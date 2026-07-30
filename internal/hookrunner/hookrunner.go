// Package hookrunner collapses the boilerplate the five `cmd/trustgate-*`
// hook entrypoints share into a single bootstrap function. Every binary
// follows the same pipeline:
//
//  1. Load layered .env files (config.LoadWithEnvFiles's godotenv.Overload
//     + config.EnvFiles, plus config.EnforceLockedEnv).
//  2. Load Config from defaults + ~/.config/.../config.json + env.
//  3. Decode the per-hook JSON payload from stdin.
//  4. Extract candidate domains (per-hook logic).
//  5. Build context, api client, cache.
//  6. Run verdict.Compose.
//  7. Write the per-event JSON verdict to stdout.
//
// Steps 1, 2, 5, 6, 7 are identical across all five binaries (modulo the
// hook event name). Step 3+4 are the per-hook variable part. Run owns the
// invariant bookkeeping; each binary supplies only an Extract function
// covering steps 3+4.
//
// Two exit paths besides the verdict cascade:
//   - Bootstrap error (config / payload decode) — emit the documented
//     fail-{open,closed} verdict per Config.FailClosed.
//   - Extract requests a short-circuit (e.g. prompt-hook verb gate
//     decides not to consult Malanta) — emit the Decision the Extract
//     callback returned without ever opening the cache or building the
//     API client.
//
// This package introduces no behavior change. It is a refactor only —
// every line of bookkeeping it owns previously lived (duplicated five
// times) in cmd/trustgate-*/main.go. The cascade, AsJSON wire shape, and
// every existing test continue to pass.
package hookrunner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/atr"
	"github.com/malanta-ai/Malanta-TrustGate/internal/audit"
	"github.com/malanta-ai/Malanta-TrustGate/internal/auditsink"
	"github.com/malanta-ai/Malanta-TrustGate/internal/cache"
	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/extract"
	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
	"github.com/malanta-ai/Malanta-TrustGate/internal/verdict"
)

// maxStdinBytes caps how much hook-payload data a single subprocess will
// even attempt to decode. Cursor's documented hook payloads are small
// (kilobytes for the largest read-file content + envelope); 256 KiB is
// two orders of magnitude above any realistic value and still bounds
// RAM / CPU exposure if Cursor — or a hostile MCP server that has
// rewritten the payload — sends a pathological blob. Exceeding the cap
// causes a decode error on the next byte read, which the bootstrap
// path turns into a fail-closed verdict.
const maxStdinBytes = 256 << 10

// utf8BOM is the 3-byte UTF-8 byte-order mark (EF BB BF). Go's encoding/json
// does NOT skip it and fails on the first byte with
// "invalid character 'ï' looking for beginning of value" (0xEF read as
// latin-1 is 'ï'). Some producers prepend it — e.g. Windows PowerShell 5.1's
// `Set-Content -Encoding UTF8` writes a BOM — so we strip a single leading
// BOM from the hook payload before decoding, defense-in-depth for every hook
// regardless of who wrote the bytes on stdin.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// stripUTF8BOM returns a reader over r with a single leading UTF-8 BOM
// removed if present. Uses bufio.Peek so no bytes are lost when there is no
// BOM (the common case).
func stripUTF8BOM(r io.Reader) io.Reader {
	br := bufio.NewReader(r)
	if b, err := br.Peek(len(utf8BOM)); err == nil && string(b) == string(utf8BOM) {
		_, _ = br.Discard(len(utf8BOM))
	}
	return br
}

// detectCursorVersion reads the running Cursor version from the hook
// payload's documented `cursor_version` base field, falling back to the
// CURSOR_VERSION environment variable. Best-effort: returns "" if neither is
// present, which makes ModeAsk degrade to a hard deny (config.CursorHonorsAsk).
func detectCursorVersion(payload []byte) string {
	var env struct {
		CursorVersion string `json:"cursor_version"`
	}
	if err := json.Unmarshal(payload, &env); err == nil && strings.TrimSpace(env.CursorVersion) != "" {
		return strings.TrimSpace(env.CursorVersion)
	}
	return strings.TrimSpace(os.Getenv("CURSOR_VERSION"))
}

// Result is the return value of Opts.Extract.
//
// Exactly one of Domains / Decision should be set for a given call:
//   - Domains = the candidate hosts to feed verdict.Compose. Empty
//     Domains is valid and Compose will return allow without any cache
//     or API access.
//   - Decision = a pre-computed verdict the runner should emit verbatim,
//     skipping the cascade. Use this for per-hook short-circuits that
//     deliberately do NOT consult Malanta — e.g. the beforeSubmitPrompt
//     verb gate that allows conversational mentions of flagged
//     indicators without spending hook budget. The HookName field is
//     overwritten by the runner so callers do not have to remember to
//     set it.
//
// If both are set, Decision wins. If neither is set, the runner treats
// it as Domains=nil and runs the cascade (which returns allow with no
// API call, matching the empty-input contract of verdict.Compose).
type Result struct {
	Domains  []string
	Decision *verdict.Decision

	// GitHub carries the typed GitHub repository / owner identities the
	// per-hook extractor found, alongside (never inside) Domains. They
	// travel as their own type all the way to the provider because they
	// are not hostnames — see verdict.Targets and reputation.Kind.
	//
	// Zero value means "this hook found none", which is also what every
	// hook that doesn't extract them yields, so the field is additive for
	// callers that ignore it.
	GitHub extract.GitHubRefs

	// ATRContent is the raw content blob the ATR (Agent Threat Rules)
	// evaluator should run against — file content for the read-file
	// hook, server+arguments for MCP, the full command line + any
	// followed-script bodies for shell. Empty disables ATR for this
	// invocation. The decision-cascade ATR behavior is fully gated on
	// content presence so the prompt hook (which has no ATR surface
	// yet) and the pre-MCP hook (used only as a stub) are unaffected.
	ATRContent string

	// ATRTargets restricts which ATR rule sub-pool to load.
	//
	//   - read-file hook: TargetSkillManifest + TargetFileContent
	//   - MCP hook:       TargetToolDescription + TargetContextExfiltration
	//   - shell hook:     TargetShell
	//
	// Empty means "do not run ATR" — the runner skips atr.LoadBundled
	// entirely, so the hot path remains identical to the pre-ATR
	// build for the hooks that opt out.
	ATRTargets []atr.Target

	// WorkspaceRoots is the hook payload's own workspace_roots field,
	// when the per-hook Extract function populates it. Used ONLY for
	// workspace/project scoping (Config.ScopeMode/ScopePaths) — see
	// checkScope. Empty means "no scope information available," which
	// checkScope treats as in-scope (never narrows enforcement based on
	// the ABSENCE of data), matching this project's general posture of
	// permissive-by-default when Cursor doesn't populate a field yet.
	WorkspaceRoots []string
}

// Opts is the per-hook configuration handed to Run.
//
// HookName is the Cursor event name (beforeShellExecution, preToolUse,
// ...). It threads through Decision.HookName so verdict.AsJSON emits
// the correct per-event wire shape — getting this wrong is a silent
// fail-open: Cursor discards a verdict it cannot parse and allows the
// action.
//
// Extract receives the loaded Config (so it can write to LogPath for
// audit-trail entries on short-circuit paths) and stdin. It is called
// exactly once per process and must close over any per-hook state.
type Opts struct {
	HookName string
	Extract  func(cfg config.Config, stdin io.Reader) (Result, error)
}

// Run is the hook subprocess main loop. It does not return; the process
// exits when the function returns (via the implicit return at the end
// of main).
func Run(opts Opts) {
	cfg, err := config.LoadWithEnvFiles()
	if err != nil {
		emitFail(opts.HookName, cfg, nil, fmt.Errorf("config: %w", err))
		return
	}
	auditStore := audit.OpenOrWarn(auditPath(cfg), os.Stderr)
	defer func() { _ = auditStore.Close() }()

	// PRIV-002: policy mode "off" means "do not inspect". Short-circuit
	// BEFORE reading/extracting stdin so no indicators are extracted from
	// the payload and none are written to the decision log — a user who set
	// mode=off expects zero inspection, not "inspect and store but allow".
	// We still emit the allow verdict and record a host-free decision so the
	// audit trail shows the hook ran while disabled.
	if cfg.Mode == config.ModeOff {
		d := verdict.Decision{
			Allow:    true,
			HookName: opts.HookName,
			Mode:     config.ModeOff,
			Reason:   "policy mode is off; no inspection performed",
		}
		verdict.RecordDecision(cfg, auditStore, &d, nil)
		writeVerdict(d.AsJSON())
		return
	}

	// Read the (BOM-stripped, size-capped) payload once so we can detect the
	// running Cursor version from it before handing the bytes to Extract.
	// The version gates ModeAsk (see config.CursorHonorsAsk) — Cursor only
	// honors permission:"ask" from a minimum version onwards.
	rawPayload, readErr := io.ReadAll(stripUTF8BOM(io.LimitReader(os.Stdin, maxStdinBytes)))
	if readErr != nil {
		emitFail(opts.HookName, cfg, auditStore, fmt.Errorf("payload: read: %w", readErr))
		return
	}
	cfg.CursorVersion = detectCursorVersion(rawPayload)

	res, err := opts.Extract(cfg, bytes.NewReader(rawPayload))
	if err != nil {
		emitFail(opts.HookName, cfg, auditStore, fmt.Errorf("payload: %w", err))
		return
	}
	targets := res.targets()
	recorded := targets.Values()
	if res.Decision != nil {
		res.Decision.HookName = opts.HookName
		applyATR(res.Decision, res, cfg)
		verdict.RecordDecision(cfg, auditStore, res.Decision, recorded)
		writeVerdict(res.Decision.AsJSON())
		dispatchAuditSink(cfg, *res.Decision, recorded)
		return
	}

	// Workspace/project scoping: out-of-scope means TrustGate doesn't
	// apply to this workspace at all, so we skip ATR too (not just the
	// reputation cascade) — see checkScope's doc comment.
	if inScope, scopeReason := checkScope(cfg, res.WorkspaceRoots); !inScope {
		// PRIV-002: TrustGate does not apply to this workspace, so we do
		// NOT persist the extracted indicators (nil hosts) — the operator
		// scoped this workspace out precisely to avoid inspection/logging
		// of its activity. Record only the host-free "out of scope"
		// decision, and don't forward anything to the audit sink.
		d := verdict.Decision{Allow: true, HookName: opts.HookName, Reason: scopeReason}
		verdict.RecordDecision(cfg, auditStore, &d, nil)
		writeVerdict(d.AsJSON())
		return
	}

	// Zero-touch defaults: an unconfigured install (no reputation
	// provider API key) must never brick a fresh install's very first
	// agent action — see config.Config.IsUnconfigured and
	// docs/admin.md. ATR still runs here (it's local/free, independent
	// of the reputation provider being configured).
	if d, ok := checkUnconfigured(cfg, recorded); ok {
		d.HookName = opts.HookName
		applyATR(&d, res, cfg)
		verdict.RecordDecision(cfg, auditStore, &d, recorded)
		writeVerdict(d.AsJSON())
		dispatchAuditSink(cfg, d, recorded)
		return
	}

	// Parent budget must cover every retry attempt: each attempt is bounded
	// by APITimeout with a fresh context, so the total is APITimeout *
	// APIMaxAttempts plus a small slack for cache + JSON work. This stays
	// under Cursor's per-hook `timeout` (20s in the standalone hooks.json,
	// 30s in the plugin manifest) for the shipped defaults (3s * 2 + 0.5s =
	// 6.5s). The retry exists so a single cold
	// API call that crosses APITimeout no longer hard-denies a legitimate
	// domain — the warm in-process connection makes attempt 2 fast.
	attempts := cfg.APIMaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	totalBudget := cfg.APITimeout*time.Duration(attempts) + 500*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), totalBudget)
	defer cancel()

	// Malanta's own in-flight-chunk default is 4; ProviderMaxConcurrency
	// overrides it (and the generic provider's own default/config-block
	// value, via the final NewFromParams argument) only when the operator
	// set it to a positive value — see Config.ProviderMaxConcurrency.
	malantaConcurrency := 4
	if cfg.ProviderMaxConcurrency > 0 {
		malantaConcurrency = cfg.ProviderMaxConcurrency
	}
	provider, err := reputation.NewFromParams(cfg.Provider, reputation.MalantaParams{
		BaseURL:        cfg.APIBaseURL,
		APIKey:         cfg.APIKey,
		AttemptTimeout: cfg.APITimeout,
		MaxAttempts:    attempts,
		MaxConcurrency: malantaConcurrency,
		BatchSize:      cfg.APIBatchSize,
	}, cfg.Generic, cfg.APITimeout, attempts, cfg.ProviderMaxConcurrency)
	if err != nil {
		// Provider construction failed (e.g. an invalid/missing generic
		// provider config, or an unknown Provider value) — this is a
		// bootstrap error like a bad config file, not a lookup failure, so
		// it follows the same emitFail fail-{open,closed} contract.
		emitFail(opts.HookName, cfg, auditStore, fmt.Errorf("reputation provider: %w", err))
		return
	}

	c := cache.OpenOrWarn(cachePath(cfg), os.Stderr)
	defer func() { _ = c.Close() }()

	d := verdict.ComposeTargets(ctx, cfg, opts.HookName, targets, c, provider, auditStore)
	// Compose has already written the decision record (JSONL + audit table)
	// reflecting the reputation cascade. ATR runs AFTER that and can only
	// TIGHTEN the verdict (allow -> deny). When it does, the already-written
	// record disagrees with what Cursor actually receives, so append an
	// immutable FINAL-decision record capturing the post-ATR truth (AUD-001).
	// (ATR never loosens a deny, so allow -> deny is the only flip possible.)
	preATRAllow := d.Allow
	applyATR(&d, res, cfg)
	if d.Allow != preATRAllow {
		verdict.RecordDecision(cfg, auditStore, &d, recorded)
	}
	writeVerdict(d.AsJSON())
	dispatchAuditSink(cfg, d, recorded)
}

// targets is the cascade input for this extraction result: hostnames stay
// hostnames, GitHub identities stay GitHub identities.
func (r Result) targets() verdict.Targets {
	return verdict.Targets{
		Hosts:  r.Domains,
		Repos:  r.GitHub.Repos,
		Owners: r.GitHub.Owners,
	}
}

// applyATR runs the ATR (Agent Threat Rules) behavioral evaluator
// against the per-hook content blob and folds the matches into the
// decision via verdict.MergeATR. ATR runs AFTER the Malanta domain
// cascade so a domain-deny verdict is never overwritten by an ATR
// allow — ATR can only tighten the deny, never loosen it.
//
// No-op when ATRContent or ATRTargets are empty (i.e. when the
// per-hook Extract did not opt in). Rule bundle load failures are
// surfaced on stderr but never fail-close the hook on their own:
// the goal is to stay invisible when ATR is misconfigured, not
// to add a new fail-closed dependency in front of the Malanta
// hot path. The decision-log audit trail records ATR matches
// when they exist; absence of matches is indistinguishable from
// "ATR did not run", which is fine because the verdict layer
// emits the same Allow / Reason in both cases.
func applyATR(d *verdict.Decision, res Result, cfg config.Config) {
	if d == nil || res.ATRContent == "" || len(res.ATRTargets) == 0 {
		return
	}
	// Kill switch. Set TRUSTGATE_ATR_DISABLE=true to skip the ATR pass
	// entirely while leaving the reputation cascade active. The
	// motivation is operator escape from a false-positive incident:
	// some upstream rules (notably
	// ATR-2026-00066 parameter-injection, ATR-2026-00113 credential-
	// theft) fire on any documentation that mentions credential
	// file paths, including the design docs in this very repo.
	// Until we curate or down-grade those rules,
	// an operator who needs to work on docs can set the env var
	// in their shell or .env and the read-file hook reverts to
	// the pre-ATR allow path. This is intentionally an env-var-
	// only escape, not a config.json setting — it should be obvious
	// to a reviewer that the operator has ATR disabled.
	if os.Getenv("TRUSTGATE_ATR_DISABLE") == "true" {
		return
	}
	rules, err := atr.LoadBundledForTargets(res.ATRTargets...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustgate: ATR bundle load failed (continuing without ATR): %v\n", err)
		return
	}
	matches := atr.Evaluate(res.ATRContent, rules)
	verdict.MergeATR(d, matches, cfg.FailClosed)
}

// writeVerdict writes the per-event JSON verdict to stdout. Surfacing a
// write failure on stderr is the best we can do — Cursor fails OPEN on
// any output it can't parse (including no output at all), so a stdout
// write that loses bytes silently turns a fail-closed verdict into an
// allow. There is no in-process recovery for that; the operator must
// see the error in Cursor's hook output panel and investigate. The
// AsJSON wire-shape unit tests remain the primary defense against
// silent fail-open, but a missing write is the second-most likely cause.
func writeVerdict(b []byte) {
	if _, err := os.Stdout.Write(b); err != nil {
		fmt.Fprintf(os.Stderr, "trustgate: stdout write failed (verdict NOT delivered to Cursor): %v\n", err)
	}
}

// cachePath is the on-disk location of the SQLite lookup cache. Kept here
// so all five binaries land at the same file (a per-binary cache would
// force every binary to re-fetch every domain after the first hook
// invocation, since each subprocess is fresh).
func cachePath(cfg config.Config) string {
	return cfg.CacheDir + "/lookups.db"
}

// auditPath is the on-disk location of the SQLite audit table — a
// separate file from the lookup cache (cachePath) so the ephemeral,
// TTL-churned reputation cache and the append-only audit trail never
// share a schema or a lock domain. See internal/audit's package doc.
func auditPath(cfg config.Config) string {
	return cfg.CacheDir + "/audit.db"
}

// checkScope reports whether the current invocation is in scope per
// Config.ScopeMode/ScopePaths, given the hook payload's own
// WorkspaceRoots (populated only by hooks whose Extract function reads
// workspace_roots from the JSON envelope). ok=false means "out of
// scope: skip the cascade and allow immediately, without consulting the
// cache or provider at all" — reason then explains why.
//
// Absent scope information (empty workspaceRoots, e.g. a hook that
// doesn't carry workspace_roots on its payload, or an older Cursor
// version) is always treated as in-scope: this feature only NARROWS
// enforcement when there's positive evidence to narrow on, it never
// narrows based on missing data.
func checkScope(cfg config.Config, workspaceRoots []string) (inScope bool, reason string) {
	mode := cfg.ScopeMode
	if mode == "" {
		mode = config.ScopeAll
	}
	if mode == config.ScopeAll || len(cfg.ScopePaths) == 0 || len(workspaceRoots) == 0 {
		return true, ""
	}
	matched := false
	for _, root := range workspaceRoots {
		if globMatchesAny(root, cfg.ScopePaths) {
			matched = true
			break
		}
	}
	switch mode {
	case config.ScopeAllowlist:
		if !matched {
			return false, fmt.Sprintf("out of scope: workspace %v is not in TRUSTGATE_SCOPE_PATHS (allowlist mode)", workspaceRoots)
		}
	case config.ScopeDenylist:
		if matched {
			return false, fmt.Sprintf("out of scope: workspace %v matches TRUSTGATE_SCOPE_PATHS (denylist mode)", workspaceRoots)
		}
	}
	return true, ""
}

// globMatchesAny reports whether path matches any of patterns.
// filepath.Match handles a plain glob (e.g. "/Users/me/work/*proj*")
// against the exact path; a pattern ending in "/*" or "/**" is ALSO
// treated as a directory-prefix match (path is that directory or
// anything under it) since filepath.Match's "*" never crosses path
// separators, and "match this workspace and everything under it" is
// almost always the intended semantics for a workspace-scoping glob.
func globMatchesAny(path string, patterns []string) bool {
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if ok, err := filepath.Match(pat, path); err == nil && ok {
			return true
		}
		if strings.HasSuffix(pat, "/**") || strings.HasSuffix(pat, "/*") {
			prefix := strings.TrimSuffix(strings.TrimSuffix(pat, "/**"), "/*")
			if path == prefix || strings.HasPrefix(path, prefix+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}

// checkUnconfigured returns a short-circuit Decision when TrustGate has
// no way to answer a reputation query yet (Config.IsUnconfigured) AND
// there's actually something to look up (domains empty means the
// cascade would trivially allow anyway, so there's nothing to short-
// circuit). ok=false means "not applicable, proceed normally."
func checkUnconfigured(cfg config.Config, domains []string) (d verdict.Decision, ok bool) {
	if !cfg.IsUnconfigured() || len(domains) == 0 {
		return verdict.Decision{}, false
	}
	if cfg.RequireConfigured {
		return verdict.Decision{
			Allow: !cfg.FailClosed,
			Reason: "trustgate is unconfigured (no reputation provider API key) and TRUSTGATE_REQUIRE_CONFIGURED=true — " +
				"this looks like a fleet provisioning failure, not a fresh individual install; contact your admin",
		}, true
	}
	noticeUnconfiguredOnce(cfg)
	return verdict.Decision{
		Allow: true,
		Reason: "trustgate is not configured yet (no reputation provider API key) — allowing by default. " +
			"Run `trustgate setup`, or set TRUSTGATE_REQUIRE_CONFIGURED=true to fail closed instead of allowing.",
	}, true
}

// noticeUnconfiguredOnce prints the "you haven't run setup yet" notice
// to stderr exactly once per install (tracked via a marker file in
// CacheDir, since every hook invocation is a fresh process with no
// other memory of prior runs) — a fresh install seeing this on every
// single agent action would be noisier than helpful.
func noticeUnconfiguredOnce(cfg config.Config) {
	if cfg.CacheDir == "" {
		return
	}
	marker := filepath.Join(cfg.CacheDir, ".unconfigured-notice-shown")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	fmt.Fprintln(os.Stderr,
		"trustgate: not configured yet (no reputation provider API key) — allowing all actions until you run `trustgate setup`. This notice won't repeat.")
	if err := os.MkdirAll(cfg.CacheDir, 0o700); err == nil {
		_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
	}
}

// dispatchAuditSink is a thin wrapper so hookrunner's three exit points
// (short-circuit, bootstrap-error, and the full cascade) all send the
// same way. Called AFTER writeVerdict, once the JSON verdict has already
// been written to stdout — the OS pipe lets Cursor's parent process start
// consuming that output while this subprocess spends up to
// auditsink's sendTimeout finishing the sink POST before exiting, which
// is as close to "off the hot path" as a fresh-process-per-invocation
// architecture allows. See internal/auditsink's package doc for the full
// trade-off against genuine async fire-and-forget.
func dispatchAuditSink(cfg config.Config, d verdict.Decision, hosts []string) {
	auditsink.Send(cfg, d, hosts)
}

// emitFail writes the bootstrap-error verdict to stdout. Allow follows
// FailClosed (true = deny on doubt, the default). HookName is set so
// AsJSON emits the correct per-event wire shape — without this, a
// fail-closed bootstrap error on the prompt hook would emit the
// {permission, user_message, agent_message} shape that Cursor uses for
// shell / read-file / MCP and silently fail-open instead. auditStore may
// be nil (e.g. when config itself failed to load, before we'd trust any
// of its paths) — verdict.RecordDecision treats a nil store as a no-op.
func emitFail(hookName string, cfg config.Config, auditStore *audit.Store, err error) {
	d := verdict.Decision{
		Allow:    !cfg.FailClosed,
		Reason:   "trustgate hook error: " + err.Error(),
		HookName: hookName,
	}
	verdict.RecordDecision(cfg, auditStore, &d, nil)
	writeVerdict(d.AsJSON())
	dispatchAuditSink(cfg, d, nil)
}
