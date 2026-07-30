// Package config loads the hook's runtime configuration from layered sources:
// built-in defaults, then ~/.config/trustgate/config.json, then environment
// variables (which always win).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/malanta-ai/Malanta-TrustGate/internal/extract"
	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

// EnvFiles returns the dotenv files each hook binary should load (in order)
// before reading the process environment. Later entries OVERRIDE earlier
// ones via godotenv.Overload, so the precedence walk is:
//
//  1. /etc/trustgate/env                 — MDM-managed, fleet-wide, the
//     production distribution channel.
//     Written by the customer's MDM
//     file-payload (mode 0640, owned by
//     root with a dedicated group that
//     contains the developer account).
//     This is the lowest-precedence
//     entry on purpose: it's the
//     default for managed endpoints.
//  2. ~/.config/trustgate/env            — per-user override. The
//     installer (scripts/install-hooks.sh)
//     still writes here for single-
//     developer setups. Overrides the
//     system file so a developer can
//     point at a staging key without
//     MDM involvement.
//  3. .env                               — dev convenience for `make e2e`
//     and ad-hoc testing from the repo
//     root. Highest precedence so
//     tests are predictable. DISABLED BY
//     DEFAULT on the hook/production path:
//     a hook's cwd is usually
//     an untrusted workspace repo, and a
//     workspace-supplied .env could
//     redirect the API base URL / host
//     allowlist / labels / threshold /
//     cache+log paths / ATR rules dir.
//     Only loaded when the developer
//     explicitly opts in via
//     TRUSTGATE_ALLOW_CWD_DOTENV=1 in the
//     AMBIENT process environment.
//
// Process env (whatever Cursor's parent shell exported) wins last because
// applyEnv runs after godotenv.Overload in every hook binary.
//
// Missing files are silently skipped: godotenv.Overload bails on the FIRST
// ENOENT it sees (returning the error without continuing to the next file),
// so we cannot simply pass all three candidate paths blindly. Doing so meant
// that on dev machines where /etc/trustgate/env doesn't exist, Overload
// would short-circuit and ~/.config/trustgate/env was never read — silently
// dropping MALANTA_API_TIMEOUT_MS and any other user overrides, and the
// operator would see fail-closed denials with dur_ms exactly at the 200ms
// default. We therefore filter to existing files here.
//
// This helper exists so all five hook binaries agree on the same lookup
// order. Drift between them would mean "works on my machine" bugs where one
// hook reads from /etc/... but another reads only from ~/.config/..., and
// the operator sees mysterious per-hook fail-closed denies.
func EnvFiles() []string {
	home, _ := os.UserHomeDir()
	candidates := []string{
		"/etc/trustgate/env",
		filepath.Join(home, ".config", "trustgate", "env"),
	}
	// The workspace-cwd .env is a DEV-ONLY convenience and is NOT loaded on
	// the hook/production path by default. A hook subprocess's cwd
	// is frequently an untrusted workspace repository; loading its .env
	// would let that repo override security-relevant settings (API base URL,
	// host allowlist, block/allow labels, min-score threshold, cache/log
	// paths, ATR rules dir) — a config- and credential-destination
	// trust-boundary collapse. It is honored ONLY when the developer has
	// explicitly opted in via TRUSTGATE_ALLOW_CWD_DOTENV in the AMBIENT
	// process environment. That gate is read here, before any .env is
	// merged, so an untrusted workspace cannot set the flag to enable itself.
	if allowCwdDotenv() {
		candidates = append(candidates, ".env")
	}
	out := make([]string, 0, len(candidates))
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// allowCwdDotenv reports whether the ambient environment has opted in to
// loading a workspace-cwd .env. Deliberately reads only
// os.Getenv (the ambient process env), never a dotenv file, so the decision
// cannot be influenced by the very .env it gates.
func allowCwdDotenv() bool {
	b, err := strconv.ParseBool(strings.TrimSpace(os.Getenv("TRUSTGATE_ALLOW_CWD_DOTENV")))
	return err == nil && b
}

// Config holds everything a hook subprocess needs to make a verdict.
//
// Every field is overridable via either the config.json file or an env var
// (see applyEnv). Env always wins. APIKey is intentionally JSON-blacklisted
// so a key cannot be persisted to the on-disk config file; it must come from
// env or ~/.config/trustgate/env.
type Config struct {
	// Provider selects which reputation backend answers lookups.
	// "malanta" (default, empty also means "malanta") uses the built-in,
	// officially-supported Malanta provider. "generic" activates the
	// config-driven REST adapter (see Generic below) and is NEVER enabled
	// implicitly — an operator must explicitly opt in. Any other value is a
	// fail-closed config error at Load.
	Provider string `json:"provider"`
	// Generic is the config-driven REST provider's configuration. Only
	// read (and only required) when Provider == "generic". Vendor CONFIGS
	// placed here (VirusTotal, etc.) are community/best-effort — see
	// docs/providers.md and SUPPORT.md; the ENGINE that interprets this
	// config is officially supported.
	Generic *reputation.GenericProviderConfig `json:"generic_provider"`
	// APIBaseURL is the Malanta REST root. Override for staging / mocks.
	// Only used when Provider is "malanta" (the default).
	APIBaseURL string `json:"api_base_url"`
	// APIKey is the Malanta API key. Sourced from MALANTA_API_KEY only;
	// never persisted to or loaded from JSON (see the `json:"-"` tag).
	APIKey string `json:"-"`
	// APITimeout is the per-HTTP-request timeout; populated from APITimeoutMs.
	APITimeout time.Duration `json:"-"`
	// APITimeoutMs bounds each batched API request. Every hook invocation
	// is a fresh process with no warm HTTP connection pool, so each lookup
	// pays a full cold DNS + TCP + TLS + round-trip to app.malanta.ai
	// (~300-700ms observed). The default is therefore 3000ms: an inner
	// timeout below ~2s trips fail-closed on essentially every live lookup
	// (it caused blanket "context deadline exceeded" denies during early
	// bring-up — see the latency notes in AGENTS.md). Cursor's
	// per-hook `timeout` (seconds, set in hooks.json) is the real ceiling;
	// this inner bound just keeps a hung endpoint from burning all of it.
	APITimeoutMs int `json:"api_timeout_ms"`
	// APIBatchSize caps how many domains the Malanta provider sends in a
	// single /v1/domains/reputation or /v1/ips/reputation request. Only
	// used when Provider is "malanta" (the default). Malanta's documented
	// per-request limit is 100 (>100 returns HTTP 400 — see
	// reputation.malantaBatchSize); Load rejects any value outside 1-100
	// via validateBatchSize. Overridable via MALANTA_API_BATCH_SIZE.
	APIBatchSize int `json:"api_batch_size"`
	// ProviderMaxConcurrency, when positive, overrides how many chunk/
	// single-mode requests the configured provider keeps in flight at
	// once — applies to BOTH the Malanta provider (which otherwise
	// hardcodes 4) and the generic provider (which otherwise uses its own
	// generic_provider.max_concurrency, default 2). Zero (the default)
	// means "no override": each provider keeps its own existing default/
	// per-config value, so leaving this unset is a pure no-op. Overridable
	// via TRUSTGATE_PROVIDER_MAX_CONCURRENCY.
	ProviderMaxConcurrency int `json:"provider_max_concurrency"`
	// APIMaxAttempts is the total number of attempts (1 = no retry) the API
	// client makes per batch before surfacing an error to the cascade. A
	// retry only fires on a TRANSIENT transport error (timeout / connection
	// failure), never on an auth error or a real HTTP status — so a genuine
	// malicious verdict still denies immediately and only a flaky network or
	// cold-call tail latency gets a second chance. Each attempt is bounded by
	// APITimeout with a FRESH context (a retry under an already-expired
	// deadline would fail instantly), and the in-process HTTP connection is
	// warm by the second attempt, so attempt 2 usually completes in well
	// under APITimeout. The hook process's total budget is sized as
	// APITimeout*APIMaxAttempts (+slack) in hookrunner and must stay under
	// Cursor's per-hook `timeout` (20s in the standalone hooks.json, 30s in
	// the plugin manifest). Default 2.
	APIMaxAttempts int `json:"api_max_attempts"`
	// BlockLabels causes a DENY when a provider verdict's name matches
	// (case-insensitive) BlockLabels, OR when its malicious score is
	// >= MinMaliciousScoreToBlock regardless of the name — the OR clause
	// is the backstop that stops a provider adding a new verdict enum
	// value from silently bypassing the block list.
	BlockLabels []string `json:"block_labels"`
	// AllowLabels short-circuits to ALLOW regardless of any block label or
	// score; this is how an explicit clean verdict beats a marginal flag.
	// Reputation is inherently a deny-list model — an unrecognized verdict
	// name is NOT denied by default (see MinMaliciousScoreToBlock), so
	// AllowLabels is an optional accelerant, not a requirement for normal
	// operation.
	AllowLabels []string `json:"allow_labels"`
	// MinMaliciousScoreToBlock is the floor that turns a verdict into an
	// actual deny (see BlockLabels doc above for the OR semantics) —
	// compared against reputation.Label.MaliciousScore, a 0..1 confidence
	// for probability-style providers (Malanta) or a raw count for
	// count-based ones (e.g. VirusTotal's malicious-engine count; tune
	// this threshold to that scale). Below this, the cascade allows but
	// logs a warning.
	//
	// JSON/env back-compat: the pre-rename name `min_probability_to_block`
	// / `TRUSTGATE_MIN_PROBABILITY` is still accepted (see Load's alias
	// handling and applyEnv) — if both the new and old name are set, the
	// new one wins.
	MinMaliciousScoreToBlock float64 `json:"min_malicious_score_to_block"`
	// FailClosed governs every error path: true means "deny on doubt".
	FailClosed bool `json:"fail_closed"`
	// PositiveTTL is how long we cache a FLAGGED verdict (in BlockLabels,
	// or whose score already crosses MinMaliciousScoreToBlock) — a longer TTL
	// is fine here since a flagged verdict rarely needs fast refresh.
	// Populated from PositiveTTLSec. (Field retained from the pre-provider-
	// abstraction schema; repurposed from "domain has any label" to
	// specifically "flagged", see cachePut in internal/verdict.)
	PositiveTTL time.Duration `json:"-"`
	// PositiveTTLSec is the disk-config-friendly form of PositiveTTL.
	PositiveTTLSec int `json:"positive_ttl_sec"`
	// NegativeTTL is how long we cache a CLEAN/UNKNOWN verdict — kept
	// shorter than PositiveTTL so a host that turns malicious after being
	// cached clean is re-checked sooner (the "shorter clean TTL for
	// high-security orgs" behavior, implemented by repurposing this
	// existing knob rather than adding new config surface). Populated from
	// NegativeTTLSec.
	NegativeTTL time.Duration `json:"-"`
	// NegativeTTLSec is the disk-config-friendly form of NegativeTTL.
	NegativeTTLSec int `json:"negative_ttl_sec"`
	// CacheDir holds the SQLite lookup cache and the decision log.
	CacheDir string `json:"cache_dir"`
	// LogPath overrides the decision log location; defaults to
	// CacheDir/decisions.log when empty.
	LogPath string `json:"log_path"`
	// RetentionDays is the local audit-data retention window in days
	// (PRIV-003). It does NOT auto-purge on the hot path (that would add
	// latency to every hook); it's the default window used by
	// `trustgate purge` when run manually or from cron. 0 (the default)
	// means "keep indefinitely" — an operator/MDM sets a positive value to
	// establish a retention policy, then schedules `trustgate purge`.
	RetentionDays int `json:"retention_days"`
	// APIHostAllowlist is the set of hostnames APIBaseURL is permitted to
	// resolve to when Provider is "malanta". The built-in default is
	// {app.malanta.ai}. Customer overrides via MALANTA_API_HOST_ALLOWLIST
	// (CSV) APPEND to this set — the built-in entry is always trusted so
	// an attacker who edits the env file cannot SUBTRACT it. Load()
	// rejects any APIBaseURL whose host is not in the resulting set,
	// fail-closed. Irrelevant when Provider is "generic" — that provider
	// validates its OWN allowed_hosts (see
	// reputation.GenericProviderConfig.Validate).
	APIHostAllowlist []string `json:"api_host_allowlist"`

	// --- Admin operability ---

	// Mode gates how much of the cascade's own decision actually takes
	// effect: ModeEnforce blocks as normal (and is fail-closed on
	// provider errors); ModeReportOnly still runs the full cascade (so
	// the audit trail shows what WOULD have happened) but never actually
	// blocks; ModeOff skips extraction and the provider entirely (fast
	// no-op allow); ModeWarn (the default) hard-denies a flagged domain
	// ONCE (with a warning message) and, if the exact same action is
	// retried, allows it and remembers that host for OverrideWindowMinutes
	// (scoped per OverrideScope), and — unlike enforce — fails OPEN on a
	// provider error/timeout (a TrustGate/provider hiccup never blocks the
	// action, matching report-only) — see finalizeDecision's warn branch,
	// failClosedOnProviderError, and docs/admin.md.
	//
	// The default is ModeWarn (not enforce) so a fresh individual install
	// educates without hard-blocking day-one work — the friction that
	// otherwise gets a security tool uninstalled. A fleet/MDM rollout is
	// expected to set (and usually lock) TRUSTGATE_MODE=enforce once the
	// team is onboarded; this default only governs installs that never set
	// a mode explicitly. See docs/admin.md §3.
	Mode string `json:"mode"`
	// PolicyAllowlist is a minimal, admin-managed, always-allow list of
	// exact indicator values (case-insensitive), checked before cache or
	// provider consultation. This is a scoped stand-in for the fuller
	// "org allowlist with owner + expiry + justification" design in the
	// project plan — see docs/admin.md for what's built vs. not.
	PolicyAllowlist []string `json:"policy_allowlist"`
	// AllowUserOverride gates whether a local, time-boxed override
	// (written by `trustgate override`, see cmd/trustgate) is honored at
	// all. Defaults to false — an operator must explicitly opt in via
	// managed config; a user cannot self-enable this flag from an
	// unmanaged env layer any more than they can self-enable
	// FailClosed=false today (both are read from the same layered
	// config, so a customer's MDM-owned env file is the intended place
	// to set it fleet-wide).
	AllowUserOverride bool `json:"allow_user_override"`
	// HelpMessage is an org-configurable line (a support URL or Slack
	// channel name) appended to every deny's user-facing message
	// alongside the decision_id — see verdict.Decision.denyMessage.
	HelpMessage string `json:"help_message"`
	// AuditSinkURL, if set, opts into best-effort async delivery of
	// every decision (allow AND deny, subject to AuditSinkVerbosity) to
	// an HTTPS collector endpoint. Empty (default) disables the sink
	// entirely — this is a genuinely opt-in feature, never on by
	// default, since it's a new network egress path. See
	// internal/auditsink and docs/admin.md.
	AuditSinkURL string `json:"audit_sink_url"`
	// AuditSinkVerbosity controls which decisions are sent when the sink
	// is enabled: "denies" (default) sends only denied decisions; "all"
	// sends every decision; "off" behaves as if AuditSinkURL were unset.
	AuditSinkVerbosity string `json:"audit_sink_verbosity"`
	// AuditSinkHostAllowlist works exactly like APIHostAllowlist: the
	// sink URL's host must be a member (additive via
	// TRUSTGATE_AUDIT_SINK_HOST_ALLOWLIST), so a hostile env file can't
	// repoint the audit sink at an exfil endpoint without also being
	// caught by this allowlist gate.
	AuditSinkHostAllowlist []string `json:"audit_sink_host_allowlist"`

	// ToolUseStrict enables the preToolUse hook's strict
	// mode: any tool_name that isn't actively inspected, isn't covered by
	// a more specific dedicated hook (beforeShellExecution,
	// beforeMCPExecution, beforeReadFile), and isn't in the hand-
	// maintained safe list or ToolUseAllowlist gets DENIED rather than
	// silently allowed. Defaults to false because Cursor's own docs
	// describe the tool-name list as illustrative, not exhaustive — an
	// operator enabling this accepts they may need to extend
	// ToolUseAllowlist when Cursor ships a new tool. See docs/admin.md.
	ToolUseStrict bool `json:"tooluse_strict"`
	// ToolUseAllowlist extends the hand-maintained known-safe tool list
	// (internal/extract.IsRecognizedTool) without a code change — the
	// escape hatch for ToolUseStrict false-denying a legitimate tool.
	ToolUseAllowlist []string `json:"tooluse_allowlist"`

	// RequireConfigured governs what happens when TrustGate is
	// UNCONFIGURED — the default Malanta provider selected but no API
	// key present (see IsUnconfigured). false (the default, right for
	// an individual/unmanaged install) means "inert allow + a one-time
	// notice": a fresh install must never brick the very first agent
	// action just because setup hasn't run yet. true (intended for an
	// enterprise MDM env file, set alongside the key) means a still-
	// missing key is treated as a fail-closed-worthy provisioning
	// error, not silent permissiveness — a managed fleet should never
	// silently degrade to allow-everything. See docs/admin.md.
	RequireConfigured bool `json:"require_configured"`

	// ScopeMode and ScopePaths implement workspace/project scoping:
	// when the hook payload's workspace_roots is available and matches
	// (or fails to match) ScopePaths per ScopeMode, the hook no-ops to
	// allow WITHOUT ever consulting the cache or provider. "all" (the
	// default) means every workspace is in scope — scoping is strictly
	// opt-in narrowing. "allowlist" means ONLY the listed path globs
	// are in scope (everything else short-circuits to allow — this
	// REDUCES enforcement coverage, so treat it as a "don't slow down
	// my personal side projects" convenience, not a security boundary).
	// "denylist" means the listed globs are OUT of scope, everything
	// else is enforced normally. Referred to as "TRUSTGATE_SCOPE" in
	// the project's design notes; implemented as two env vars
	// (TRUSTGATE_SCOPE_MODE / TRUSTGATE_SCOPE_PATHS) for the same
	// reason Mode and PolicyAllowlist are separate vars rather than one
	// packed mini-DSL string.
	ScopeMode  string   `json:"scope_mode"`
	ScopePaths []string `json:"scope_paths"`

	// OverrideScope governs how a grant (either written by `trustgate
	// override`, see internal/override, or self-promoted by
	// ModeWarn's retry-to-proceed flow) is matched against a denied
	// indicator. "domain" (the default) only flips a deny to allow
	// when the SPECIFIC flagged host was granted (`trustgate override
	// --domain <host>`, or the specific host that triggered a warn
	// deny) — tighter, since a grant only ever unblocks the host it
	// names. "time" is a blanket, domain-agnostic bypass for the
	// whole window regardless of which host triggered the deny — the
	// original, simpler behavior, kept for admins who prefer a single
	// "let me through for N minutes" escape hatch over per-host
	// grants. Changing this only affects what a NEW grant writes (`*`
	// vs an exact domain); it never invalidates a grant a user already
	// holds (internal/override.ActiveFor matches whatever is actually
	// on disk).
	OverrideScope string `json:"override_scope"`
	// OverrideWindowMinutes is how long a host stays granted once
	// promoted — either via `trustgate override --minutes` (the CLI
	// break-glass, gated on AllowUserOverride) or via ModeWarn's
	// deny-once-then-allow-on-retry flow (internal/override.
	// PromotePending), which does NOT require AllowUserOverride since
	// warn is its own admin-selected posture, not a user escape hatch.
	OverrideWindowMinutes int `json:"override_window_minutes"`
	// WarnAckMinSeconds is the minimum time that must elapse between a
	// ModeWarn first-touch deny of a host and the retry that
	// acknowledges it (internal/override.PromotePending). A retry that
	// arrives sooner re-warns instead of promoting the pending marker
	// into a grant. This is a defense against the agent auto-retrying
	// the audited-retry message on the user's behalf (sub-second) before
	// a human has actually seen and acted on the warning: Cursor gives
	// the hook no signal distinguishing a human "Try Again" from an
	// agent auto-retry, so this dwell gate is a heuristic — an agent
	// that keeps retrying past this window still eventually promotes.
	// 0 disables the gate (any retry acknowledges immediately, the
	// pre-2026-07 behavior). Only meaningful under ModeWarn.
	WarnAckMinSeconds int `json:"warn_ack_min_seconds"`
	// AskMinCursorVersion is the minimum Cursor version at which ModeAsk
	// emits permission:"ask" (Cursor's human approve/reject dialog).
	// Cursor honors "ask" for the execution hooks only from this version
	// onwards; on older builds it would silently fail OPEN, so below this
	// floor ModeAsk degrades to a hard permission:"deny" instead (safe).
	// Default "3.11.25" (the earliest build confirmed to honor it). An
	// operator can lower it via TRUSTGATE_ASK_MIN_CURSOR_VERSION once a
	// more precise first-supporting version is known.
	AskMinCursorVersion string `json:"ask_min_cursor_version"`
	// CursorVersion is the running Cursor version, detected at RUNTIME from
	// the hook payload's `cursor_version` field (or the CURSOR_VERSION env
	// var). It is NOT read from config files/env-of-config; hookrunner sets
	// it on the loaded Config before the cascade so ModeAsk can gate on it
	// (see CursorHonorsAsk). Empty when it can't be determined — in which
	// case ModeAsk degrades to deny.
	CursorVersion string `json:"-"`
}

// Recognized values for Config.ScopeMode.
const (
	ScopeAll       = "all"
	ScopeAllowlist = "allowlist"
	ScopeDenylist  = "denylist"
)

// Recognized values for Config.OverrideScope.
const (
	OverrideScopeDomain = "domain"
	OverrideScopeTime   = "time"
)

// IsUnconfigured reports whether TrustGate has no way to actually
// consult a reputation provider yet. For the default Malanta provider
// this means no API key. For a "generic" provider it means the provider
// DECLARES auth (an auth header) but its secret env var is unset — the
// same "credential missing" state, detected so TRUSTGATE_REQUIRE_CONFIGURED
// treats it identically and warn mode / beforeSubmitPrompt don't silently
// fail open on the resulting 401. A generic provider that
// declares no auth (a public API) is considered configured.
func (c Config) IsUnconfigured() bool {
	provider := strings.ToLower(strings.TrimSpace(c.Provider))
	switch provider {
	case "", "malanta":
		return c.APIKey == ""
	case "generic":
		if c.Generic == nil {
			// Defensive: Load hard-fails before this on a nil Generic
			// block, so this path is unreachable in practice.
			return true
		}
		if strings.TrimSpace(c.Generic.Auth.Header) == "" {
			return false // no auth declared → public API → configured
		}
		ev := strings.TrimSpace(c.Generic.Auth.EnvVar)
		return ev == "" || strings.TrimSpace(os.Getenv(ev)) == ""
	default:
		return false
	}
}

// Policy mode values for Config.Mode — see its doc comment.
const (
	ModeEnforce    = "enforce"
	ModeReportOnly = "report-only"
	ModeOff        = "off"
	ModeWarn       = "warn"
	// ModeAsk emits Cursor's permission:"ask" — a human approve/reject
	// dialog that pauses the action — instead of warn's deny-once-then-
	// allow-on-retry (which an agent can self-acknowledge by retrying). It
	// is the human-in-the-loop mode for INTERACTIVE use: the agent cannot
	// approve on its own, only a human clicking the dialog can. Two gates
	// apply (verdict.finalizeDecision), and ask degrades to a hard deny
	// when either fails so it never fails open or deadlocks: (1) VERSION —
	// Cursor honors "ask" only from AskMinCursorVersion onwards; (2) EVENT
	// — Cursor enforces "ask" only for beforeShellExecution and
	// beforeMCPExecution (preToolUse/beforeReadFile/subagentStart do not
	// render a dialog, so ask becomes a deny there). For AUTONOMOUS/auto-run
	// agents (where the dialog is auto-approved) prefer ModeWarn, which
	// injects the warning + audit trail into the agent loop and works on
	// every Cursor version and event. See docs/admin.md.
	ModeAsk = "ask"
)

// Defaults returns a fully-populated Config with safe defaults. Callers should
// run Load to layer in user config + env overrides on top.
//
// Zero-touch: every field here has a safe default, so a fresh install needs
// ONLY an API key (MALANTA_API_KEY) to start working — no provider,
// threshold, or allowlist configuration required.
func Defaults() Config {
	home, _ := os.UserHomeDir()
	return Config{
		Provider:               "malanta",
		APIBaseURL:             "https://app.malanta.ai/data",
		APITimeoutMs:           3000,
		APITimeout:             3000 * time.Millisecond,
		APIBatchSize:           100,
		APIMaxAttempts:         2,
		ProviderMaxConcurrency: 0, // 0 = no override; each provider keeps its own default
		// Default label set targets Malanta's reputation API
		// (schema_version 2.0.0): the only block-worthy verdict it
		// returns for a flagged domain is MALICIOUS (confirmed live;
		// the prior API's speculative "Suspicius"/SUSPICIOUS category
		// is not part of the current verdict enum). An admin can
		// still add labels back via TRUSTGATE_BLOCK_LABELS, and the
		// score-threshold backstop (MinMaliciousScoreToBlock, see its
		// doc comment) denies any high-scoring verdict regardless of
		// name, so dropping SUSPICIOUS from the default does not
		// weaken the cascade. AllowLabels is intentionally empty:
		// UNKNOWN/unrecognized verdicts already allow via the
		// deny-list model (see BlockLabels' doc comment) without
		// needing an explicit allow entry.
		BlockLabels:              []string{"MALICIOUS"},
		AllowLabels:              []string{},
		MinMaliciousScoreToBlock: 0.5,
		FailClosed:               true,
		PositiveTTLSec:           3600,
		PositiveTTL:              time.Hour,
		NegativeTTLSec:           600,
		NegativeTTL:              10 * time.Minute,
		CacheDir:                 filepath.Join(home, ".cache", "trustgate"),
		LogPath:                  filepath.Join(home, ".cache", "trustgate", "decisions.log"),
		APIHostAllowlist:         []string{"app.malanta.ai"},

		Mode:               ModeWarn,
		PolicyAllowlist:    []string{},
		AllowUserOverride:  false,
		HelpMessage:        "",
		AuditSinkURL:       "",
		AuditSinkVerbosity: "denies",
		ToolUseStrict:      false,
		ToolUseAllowlist:   []string{},
		RequireConfigured:  false,
		ScopeMode:          ScopeAll,
		ScopePaths:         []string{},

		OverrideScope:         OverrideScopeDomain,
		OverrideWindowMinutes: 15,
		WarnAckMinSeconds:     4,
		AskMinCursorVersion:   "3.11.25",
	}
}

// LoadWithEnvFiles is Load's counterpart for any entrypoint that is NOT
// one of the five `cmd/trustgate-*` hook binaries but still needs the
// SAME layered env-file precedence they get from hookrunner.Run
// (godotenv.Overload(EnvFiles()...) then EnforceLockedEnv, both BEFORE
// Load reads the environment). Today that's the trustgate admin CLI's
// `doctor` and `override` subcommands: both need to see exactly the
// config a hook process would see (e.g. whether
// ~/.config/trustgate/env has AllowUserOverride set), not just
// whatever happens to already be exported in the invoking shell.
// `setup` deliberately does NOT use this — it writes the key file
// itself and only ever reads MALANTA_API_KEY directly from process
// env as a --key fallback, so there's no config-in-effect to get
// right before the file exists.
func LoadWithEnvFiles() (Config, error) {
	_ = godotenv.Overload(EnvFiles()...)
	EnforceLockedEnv()
	return Load()
}

// Load returns the merged config from defaults, optional JSON file, and env.
// A missing file is not an error. Env always wins.
func Load() (Config, error) {
	c := Defaults()
	home, _ := os.UserHomeDir()
	cfgPath := filepath.Join(home, ".config", "trustgate", "config.json")
	if data, err := os.ReadFile(cfgPath); err == nil {
		if err := json.Unmarshal(data, &c); err != nil {
			return c, fmt.Errorf("config: parse %s: %w", cfgPath, err)
		}
		applyMinScoreAlias(data, &c)
	} else if !errors.Is(err, os.ErrNotExist) {
		return c, fmt.Errorf("config: read %s: %w", cfgPath, err)
	}
	applyEnv(&c)
	if c.APIMaxAttempts < 1 {
		c.APIMaxAttempts = 1
	}
	c.APITimeout = time.Duration(c.APITimeoutMs) * time.Millisecond
	c.PositiveTTL = time.Duration(c.PositiveTTLSec) * time.Second
	c.NegativeTTL = time.Duration(c.NegativeTTLSec) * time.Second
	if c.LogPath == "" {
		c.LogPath = filepath.Join(c.CacheDir, "decisions.log")
	}
	if err := validateProviderConfig(c); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if err := validateMinScore(c.MinMaliciousScoreToBlock); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if err := validateMode(c.Mode); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if err := validateAuditSink(c.AuditSinkURL, c.AuditSinkHostAllowlist); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if err := validateScopeMode(c.ScopeMode); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if err := validateOverrideScope(c.OverrideScope); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if err := validateWarnAckMinSeconds(c.WarnAckMinSeconds); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if err := validateBatchSize(c.APIBatchSize); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	return c, nil
}

// minScoreAliases is a shadow of ONLY the two JSON keys that can populate
// Config.MinMaliciousScoreToBlock, each as a pointer so applyMinScoreAlias
// can tell "absent" from "explicitly zero." json.Unmarshal into Config
// itself only recognizes the current tag (min_malicious_score_to_block);
// the pre-rename key (min_probability_to_block) would otherwise be
// silently ignored by that pass, breaking every existing config.json that
// still uses it.
type minScoreAliases struct {
	New *float64 `json:"min_malicious_score_to_block"`
	Old *float64 `json:"min_probability_to_block"`
}

// applyMinScoreAlias re-parses the raw config.json bytes against both the
// current and the deprecated key name for MinMaliciousScoreToBlock, and
// applies whichever is present — new wins if both are (matching the env
// precedence in applyEnv). data is the exact bytes already successfully
// unmarshaled into c by the caller, so a second parse failure here is
// unreachable in practice; if it somehow occurs, this is a no-op (c keeps
// whatever the first pass already produced).
func applyMinScoreAlias(data []byte, c *Config) {
	var aliases minScoreAliases
	if err := json.Unmarshal(data, &aliases); err != nil {
		return
	}
	switch {
	case aliases.New != nil:
		c.MinMaliciousScoreToBlock = *aliases.New
	case aliases.Old != nil:
		c.MinMaliciousScoreToBlock = *aliases.Old
	}
}

// validateOverrideScope rejects an unrecognized OverrideScope outright,
// same fail-closed-at-Load posture as validateScopeMode: a typo must
// surface as a config error, never silently fall back to either value.
func validateOverrideScope(scope string) error {
	switch scope {
	case "", OverrideScopeDomain, OverrideScopeTime:
		return nil
	default:
		return fmt.Errorf("override_scope: unknown value %q (want %q or %q)", scope, OverrideScopeDomain, OverrideScopeTime)
	}
}

// validateWarnAckMinSeconds rejects a negative dwell (a config.json
// literal typo like -1); 0 is valid and means "disable the gate". The
// env path in applyEnv already ignores negatives, so this only catches a
// config.json literal.
func validateWarnAckMinSeconds(n int) error {
	if n < 0 {
		return fmt.Errorf("warn_ack_min_seconds: must be >= 0 (0 disables the dwell gate), got %d", n)
	}
	return nil
}

// validateBatchSize rejects an APIBatchSize outside Malanta's documented
// per-request limit of 1-100 (see reputation.malantaBatchSize) — a value
// above 100 would make every batched lookup 400 at the API, and a value
// below 1 is nonsensical. Only meaningful when Provider is "malanta"; a
// generic-provider install that never touches this knob still gets the
// default of 100, which always passes.
func validateBatchSize(n int) error {
	if n < 1 || n > 100 {
		return fmt.Errorf("api_batch_size (MALANTA_API_BATCH_SIZE): must be 1-100 (Malanta's documented per-request limit), got %d", n)
	}
	return nil
}

// validateScopeMode rejects an unrecognized ScopeMode outright, same
// fail-closed-at-Load posture as validateMode.
func validateScopeMode(mode string) error {
	switch mode {
	case "", ScopeAll, ScopeAllowlist, ScopeDenylist:
		return nil
	default:
		return fmt.Errorf("scope_mode: unknown value %q (want %q, %q, or %q)", mode, ScopeAll, ScopeAllowlist, ScopeDenylist)
	}
}

// validateMode rejects an unrecognized Mode outright (fail-closed at
// Load, same posture as validateProviderConfig) — a typo like "enforced"
// or "reportonly" must never silently behave as enforce OR as off; it
// must surface as a config error the operator has to fix.
func validateMode(mode string) error {
	switch mode {
	case "", ModeEnforce, ModeReportOnly, ModeOff, ModeWarn, ModeAsk:
		return nil
	default:
		return fmt.Errorf("mode: unknown value %q (want %q, %q, %q, %q, or %q)", mode, ModeEnforce, ModeReportOnly, ModeOff, ModeWarn, ModeAsk)
	}
}

// CursorHonorsAsk reports whether the running Cursor version (CursorVersion,
// detected at runtime from the hook payload / CURSOR_VERSION) is at or above
// AskMinCursorVersion — i.e. whether it will honor permission:"ask" for the
// execution hooks. An empty or unparseable running version returns false, so
// ModeAsk degrades to a hard deny (the safe direction — never fail open).
func (c Config) CursorHonorsAsk() bool {
	if strings.TrimSpace(c.CursorVersion) == "" {
		return false
	}
	return compareDottedVersions(c.CursorVersion, c.AskMinCursorVersion) >= 0
}

// compareDottedVersions compares two dotted numeric versions (e.g. "3.11.25").
// It reads the leading numeric components (ignoring any suffix like
// " (Universal)" or "-nightly") and compares component-by-component, treating
// missing/unparseable components as 0 (so "3.11" == "3.11.0"). Returns -1, 0,
// or 1.
func compareDottedVersions(a, b string) int {
	pa := parseVersionParts(a)
	pb := parseVersionParts(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVersionParts(v string) []int {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ' '); i >= 0 { // drop " (Universal)" etc.
		v = v[:i]
	}
	var out []int
	for _, part := range strings.Split(v, ".") {
		digits := part
		for j := 0; j < len(part); j++ {
			if part[j] < '0' || part[j] > '9' {
				digits = part[:j]
				break
			}
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}

// validateMinScore rejects a non-finite block threshold.
// strconv.ParseFloat accepts "NaN", "Inf", and "-Inf", so an env override
// like TRUSTGATE_MIN_MALICIOUS_SCORE=NaN would otherwise reach the cascade,
// where `score >= NaN` is always false — silently disabling every deny. A
// non-finite threshold is never a legitimate configuration, so it is a
// fail-closed config error rather than a value we clamp or ignore. Negative
// and >1 finite values are intentionally allowed: count-based providers
// (e.g. VirusTotal engine counts) legitimately score above 1, and an
// operator may deliberately set a very low threshold.
func validateMinScore(score float64) error {
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return fmt.Errorf("min_malicious_score: must be a finite number, got %v", score)
	}
	return nil
}

// validateAuditSink applies the same HTTPS-only / non-routable-host /
// explicit-allowlist guardrails validateAPIBaseURL applies to the
// reputation API, to the audit sink URL — it's a second, admin-opted-in
// network egress path carrying decision data, and deserves the same
// scrutiny. A blank URL (the default; sink disabled) always passes.
func validateAuditSink(sinkURL string, allowlist []string) error {
	if sinkURL == "" {
		return nil
	}
	u, err := url.Parse(sinkURL)
	if err != nil {
		return fmt.Errorf("audit_sink_url: parse: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("audit_sink_url: scheme must be https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("audit_sink_url: missing host")
	}
	if extract.IsNonRoutableHost(host) {
		return fmt.Errorf("audit_sink_url: host %q is loopback / private / link-local", host)
	}
	if len(allowlist) == 0 {
		return errors.New("audit_sink_url is set but audit_sink_host_allowlist is empty — refusing to send decision data anywhere unlisted")
	}
	hostLower := strings.ToLower(host)
	for _, allowed := range allowlist {
		if strings.ToLower(strings.TrimSpace(allowed)) == hostLower {
			return nil
		}
	}
	return fmt.Errorf("audit_sink_url: host %q is not in audit_sink_host_allowlist", host)
}

// validateProviderConfig dispatches to the validation appropriate for
// whichever provider is selected. "generic" is NEVER enabled implicitly:
// an empty/"malanta" Provider always validates the Malanta API base URL,
// even if a Generic block happens to be present in config.json (a stray
// or leftover generic_provider block must never activate a provider the
// operator didn't explicitly select).
func validateProviderConfig(c Config) error {
	switch strings.ToLower(strings.TrimSpace(c.Provider)) {
	case "", "malanta":
		return validateAPIBaseURL(c.APIBaseURL, c.APIHostAllowlist)
	case "generic":
		if c.Generic == nil {
			return errors.New(`provider is "generic" but no generic_provider config block was supplied`)
		}
		// Structural validation only. A generic provider that declares
		// auth but whose secret env var is unset is NOT a hard Load error
		// (that would break `trustgate setup`, whose whole job is to store
		// that very key) — it's surfaced as "unconfigured" via
		// IsUnconfigured, exactly like a missing Malanta key.
		return c.Generic.Validate()
	default:
		return fmt.Errorf("provider: unknown value %q (want \"malanta\" or \"generic\")", c.Provider)
	}
}

// validateAPIBaseURL gates MALANTA_API_BASE_URL (and config.json's
// api_base_url) against an enterprise-grade misconfig surface, when
// Provider is "malanta" (see validateProviderConfig). The hook process
// holds the customer's Malanta API key; a hostile env file that repoints
// the base URL would silently exfiltrate that key on the next lookup.
// Rules:
//
//   - Must parse as an absolute URL with an https scheme. Plain http (or
//     any non-https scheme) is rejected so a downgrade attack cannot
//     silently lose TLS.
//   - Host must NOT resolve to a loopback / RFC1918 / link-local / CGNAT
//     literal. A bare "localhost" or "127.0.0.1" base URL is the canonical
//     local-MITM attack shape; the bare hostname check catches it before
//     DNS resolution even happens.
//   - Host MUST be in allowlist (built-in {app.malanta.ai} plus any
//     MALANTA_API_HOST_ALLOWLIST additions). Customers who genuinely need
//     a staging or air-gapped endpoint extend the list via the env var;
//     the built-in entry cannot be removed.
//
// Returns nil if the URL is acceptable. Returns a descriptive error
// otherwise — Load wraps it as a "config: ..." error which the hookrunner
// bootstrap path turns into a fail-closed verdict, so the operator sees
// the misconfig at the next hook firing rather than experiencing silent
// key exfil.
func validateAPIBaseURL(base string, allowlist []string) error {
	if base == "" {
		return errors.New("api_base_url is empty")
	}
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("api_base_url: parse: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("api_base_url: scheme must be https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("api_base_url: missing host")
	}
	if extract.IsNonRoutableHost(host) {
		return fmt.Errorf("api_base_url: host %q is loopback / private / link-local — refusing to send the API key there", host)
	}
	hostLower := strings.ToLower(host)
	for _, allowed := range allowlist {
		if strings.ToLower(strings.TrimSpace(allowed)) == hostLower {
			return nil
		}
	}
	return fmt.Errorf("api_base_url: host %q is not in MALANTA_API_HOST_ALLOWLIST (built-in: app.malanta.ai)", host)
}

// applyEnv reads environment variables in two namespaces:
//
//   - TRUSTGATE_* for tool-level settings that apply regardless of which
//     reputation provider is selected (provider choice itself, the
//     block/allow cascade, cache/log locations, fail-closed policy).
//   - MALANTA_API_* for settings specific to the built-in Malanta provider
//     (its credential, endpoint, and request tuning). These stay
//     Malanta-prefixed on purpose — they configure the Malanta VENDOR, not
//     the tool, and a future second compiled provider would get its own
//     equivalently-scoped prefix rather than sharing these.
func applyEnv(c *Config) {
	if v := os.Getenv("TRUSTGATE_PROVIDER"); v != "" {
		c.Provider = v
	}
	if v := os.Getenv("MALANTA_API_KEY"); v != "" {
		c.APIKey = v
	}
	if v := os.Getenv("MALANTA_API_BASE_URL"); v != "" {
		c.APIBaseURL = v
	}
	if v := os.Getenv("MALANTA_API_TIMEOUT_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.APITimeoutMs = n
		}
	}
	if v := os.Getenv("MALANTA_API_MAX_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			c.APIMaxAttempts = n
		}
	}
	if v := os.Getenv("MALANTA_API_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			c.APIBatchSize = n
		}
	}
	if v := os.Getenv("TRUSTGATE_PROVIDER_MAX_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			c.ProviderMaxConcurrency = n
		}
	}
	if v := os.Getenv("TRUSTGATE_FAIL_CLOSED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.FailClosed = b
		}
	}
	// TRUSTGATE_MIN_MALICIOUS_SCORE is the canonical name;
	// TRUSTGATE_MIN_PROBABILITY is the deprecated pre-rename alias, still
	// honored so an existing env file keeps working. New wins if both are
	// set (checked first, so an "else" branch never even reads the old
	// var when the new one is present).
	if v := os.Getenv("TRUSTGATE_MIN_MALICIOUS_SCORE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			c.MinMaliciousScoreToBlock = f
		}
	} else if v := os.Getenv("TRUSTGATE_MIN_PROBABILITY"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			c.MinMaliciousScoreToBlock = f
		}
	}
	if v := os.Getenv("TRUSTGATE_BLOCK_LABELS"); v != "" {
		c.BlockLabels = splitCSV(v)
	}
	if v := os.Getenv("TRUSTGATE_ALLOW_LABELS"); v != "" {
		c.AllowLabels = splitCSV(v)
	}
	if v := os.Getenv("TRUSTGATE_CACHE_DIR"); v != "" {
		c.CacheDir = v
	}
	if v := os.Getenv("TRUSTGATE_LOG_PATH"); v != "" {
		c.LogPath = v
	}
	if v := os.Getenv("TRUSTGATE_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			c.RetentionDays = n
		}
	}
	// MALANTA_API_HOST_ALLOWLIST is additive: env entries are appended to
	// the built-in allowlist rather than replacing it, so an attacker who
	// can edit the env file cannot remove "app.malanta.ai" from the
	// trusted set. The hard-default rule lives in validateAPIBaseURL,
	// invoked once from Load after all overrides are applied.
	if v := os.Getenv("MALANTA_API_HOST_ALLOWLIST"); v != "" {
		c.APIHostAllowlist = append(c.APIHostAllowlist, splitCSV(v)...)
	}

	if v := os.Getenv("TRUSTGATE_MODE"); v != "" {
		c.Mode = v
	}
	if v := os.Getenv("TRUSTGATE_POLICY_ALLOWLIST"); v != "" {
		c.PolicyAllowlist = splitCSV(v)
	}
	if v := os.Getenv("TRUSTGATE_ALLOW_USER_OVERRIDE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.AllowUserOverride = b
		}
	}
	if v := os.Getenv("TRUSTGATE_HELP_MESSAGE"); v != "" {
		c.HelpMessage = v
	}
	if v := os.Getenv("TRUSTGATE_AUDIT_SINK_URL"); v != "" {
		c.AuditSinkURL = v
	}
	if v := os.Getenv("TRUSTGATE_AUDIT_SINK_VERBOSITY"); v != "" {
		c.AuditSinkVerbosity = v
	}
	if v := os.Getenv("TRUSTGATE_AUDIT_SINK_HOST_ALLOWLIST"); v != "" {
		c.AuditSinkHostAllowlist = append(c.AuditSinkHostAllowlist, splitCSV(v)...)
	}
	if v := os.Getenv("TRUSTGATE_TOOLUSE_STRICT"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.ToolUseStrict = b
		}
	}
	if v := os.Getenv("TRUSTGATE_TOOLUSE_ALLOWLIST"); v != "" {
		c.ToolUseAllowlist = splitCSV(v)
	}
	if v := os.Getenv("TRUSTGATE_REQUIRE_CONFIGURED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.RequireConfigured = b
		}
	}
	if v := os.Getenv("TRUSTGATE_SCOPE_MODE"); v != "" {
		c.ScopeMode = v
	}
	if v := os.Getenv("TRUSTGATE_SCOPE_PATHS"); v != "" {
		c.ScopePaths = splitCSV(v)
	}
	if v := os.Getenv("TRUSTGATE_OVERRIDE_SCOPE"); v != "" {
		c.OverrideScope = v
	}
	if v := os.Getenv("TRUSTGATE_OVERRIDE_WINDOW_MIN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.OverrideWindowMinutes = n
		}
	}
	// WarnAckMinSeconds accepts 0 (explicitly disable the dwell gate), so —
	// unlike OverrideWindowMinutes above — a parsed 0 is honored rather than
	// treated as "unset, keep the default". Negative values are ignored
	// (validated separately in Validate for a config.json literal).
	if v := os.Getenv("TRUSTGATE_WARN_ACK_MIN_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			c.WarnAckMinSeconds = n
		}
	}
	if v := os.Getenv("TRUSTGATE_ASK_MIN_CURSOR_VERSION"); v != "" {
		c.AskMinCursorVersion = strings.TrimSpace(v)
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// LabelSet is a case-insensitive set of label strings.
type LabelSet map[string]struct{}

// NewLabelSet builds a case-insensitive set; pass either BlockLabels or
// AllowLabels from a Config.
func NewLabelSet(labels []string) LabelSet {
	s := make(LabelSet, len(labels))
	for _, l := range labels {
		s[strings.ToLower(strings.TrimSpace(l))] = struct{}{}
	}
	return s
}

// Has returns true if label (case-insensitively) is in the set.
func (s LabelSet) Has(label string) bool {
	_, ok := s[strings.ToLower(strings.TrimSpace(label))]
	return ok
}
