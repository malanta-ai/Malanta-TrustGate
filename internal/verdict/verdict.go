// Package verdict glues extraction, caching, and a reputation.Provider
// together into a single Compose function suitable for use from a hook
// entrypoint.
//
// Decision cascade (per indicator):
//
//  1. Verdict name in AllowLabels (case-insensitive)  -> ALLOW
//  2. Verdict name in BlockLabels OR malicious score >= MinMaliciousScoreToBlock -> DENY
//     (the OR clause is deliberate: it denies a provider verdict whose exact
//     name isn't in BlockLabels but whose score crosses the threshold, so a
//     provider adding a new verdict enum value can't silently bypass the
//     cascade)
//  3. Indicator genuinely ABSENT from the provider's response (a protocol
//     anomaly, not "no data available" — see reputation.Provider's
//     doc-comment) -> retry once for just the absent indicators, then DENY
//     if still absent and FailClosed, else ALLOW + warning
//  4. Provider error -> DENY if FailClosed, else ALLOW + warning
//  5. Event exceeds the pathological fan-out cap -> DENY if FailClosed
//     (never silently truncate-and-proceed)
//
// Any single DENY across the set of extracted indicators denies the whole
// hook invocation. We surface the offending indicator and reason in the
// JSON output.
package verdict

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/atr"
	"github.com/malanta-ai/Malanta-TrustGate/internal/audit"
	"github.com/malanta-ai/Malanta-TrustGate/internal/cache"
	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/override"
	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

// Decision is the internal verdict for a single hook invocation. It is the
// shape written to the JSON Lines decision log and the shape consumed by
// the cascade in Compose. It is NOT the shape Cursor sees on stdout - that
// conversion happens in AsJSON, which emits the per-event schema documented
// at cursor.com/docs/hooks. Keep these two shapes decoupled: the log is for
// us, stdout is Cursor's contract, and conflating them is what caused
// verdicts to silently fail-open during the first POC build.
type Decision struct {
	// DecisionID is a short, opaque, per-invocation identifier — the join
	// key between what an end user sees in a deny message and what an
	// admin can look up later via `trustgate explain <decision_id>` or in
	// the audit sink. Generated once per Decision (see NewDecisionID) and
	// never reused; a retry-once-after-absent lookup within the SAME
	// Compose call keeps the original ID rather than minting a new one.
	DecisionID string   `json:"decision_id,omitempty"`
	Allow      bool     `json:"allow"`
	Reason     string   `json:"reason,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
	// UserReason, when non-empty, is what denyMessage shows the end user
	// INSTEAD of Reason. Reason itself is unchanged and always fully
	// recorded in the decision log / audit table (so `trustgate explain`
	// still shows raw operator-only detail for troubleshooting) — this
	// exists so a provider error's raw HTTP status/JSON body (genuinely
	// useful to an operator, not to the person who just got denied) can
	// stay in the log without leaking into the Cursor UI. Set only by
	// failClosedOnProviderError; every other deny path leaves it empty,
	// so denyMessage falls back to Reason unchanged (the common case).
	UserReason string `json:"-"`
	Provider   string `json:"provider,omitempty"`
	Indicator  string `json:"indicator,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Label      string `json:"label,omitempty"`
	HookName   string `json:"hook,omitempty"`
	// Mode records which policy mode was in effect (enforce, report-only,
	// off — see internal/config.Config.Mode and Compose's mode-handling
	// step). Always populated, defaulting to "enforce".
	Mode       string `json:"mode,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
	// HelpMessage is an org-configurable line (Config.HelpMessage, e.g. a
	// support URL or "#security-help" channel name) appended to a deny's
	// user_message/agent_message in AsJSON. Empty by default — most
	// individual installs have no internal help channel to point at.
	HelpMessage string `json:"-"`
	// ATRMatches carries the ATR (Agent Threat Rules) behavioral
	// detections that fired for this hook event. ATR runs in
	// parallel with the reputation cascade — same content blob,
	// different question ("does this match a known attack shape?"
	// vs "is this host malicious?"). Matches are written to the
	// decision log on every hook invocation that produced any; the
	// per-surface deny gate decides whether any of them flips Allow
	// from true to false based on Severity (see MergeATR).
	//
	// Decision-log only — never surfaced on stdout. The AsJSON wire
	// shape Cursor sees is unchanged; ATR is an internal audit-trail
	// extension. Surfacing ATR rule IDs to the agent or end user
	// would risk advertising which detections fire (helping an
	// attacker tune around them) without giving the operator
	// anything they can't already see in the decision log.
	ATRMatches []atr.Match `json:"atr_matches,omitempty"`

	// OverrideHint is a short, user-facing instruction appended to a
	// deny message telling the operator the exact `trustgate
	// override` invocation that would unblock this specific denial
	// (see overrideHintText). Populated only when AllowUserOverride is
	// enabled and Mode is NOT "warn" (warn mode has its own, distinct
	// message — see Warned). Internal only (never logged): the
	// decision log already records Allow=false and Reason, which is
	// what matters for the audit trail; the exact wording shown to a
	// human is a UX detail, not a durable decision fact.
	OverrideHint string `json:"-"`
	// Warned, when true alongside Allow=false, means this deny is
	// Config.ModeWarn's FIRST touch of a flagged indicator: the user
	// hasn't yet retried the exact same action, so there is no pending
	// marker to promote (see finalizeDecision's warn resolution and
	// internal/override.PromotePending). Drives denyMessage's
	// warn-specific suffix ("this access is audited; re-run to
	// proceed") instead of the CLI OverrideHint. A retry of the SAME
	// action is resolved entirely within finalizeDecision (the pending
	// marker is found and promoted to a real grant, Allow flips to
	// true) — Warned is never true on that path, only on the first
	// touch. Internal only (never logged), same rationale as
	// OverrideHint.
	Warned bool `json:"-"`
	// Ask, when true alongside Allow=false, makes AsJSON emit Cursor's
	// permission:"ask" (an approve/reject dialog that pauses for the human)
	// instead of a hard permission:"deny". Set by finalizeDecision only
	// under Config.ModeAsk (experimental — see that mode's doc). Unlike
	// warn's deny-once-then-allow-on-retry (which an agent can
	// self-acknowledge by retrying), "ask" hands the decision to Cursor's
	// own human dialog, so the agent cannot approve on its own. Internal
	// only (never logged); the decision log still records Allow=false +
	// Reason. Whether Cursor actually honors "ask" for the execution hooks
	// is what this mode exists to test.
	Ask bool `json:"-"`
}

// Lookuper is the minimal surface Compose needs from a reputation provider.
// reputation.Provider satisfies this structurally, as does any fake used in
// tests.
type Lookuper interface {
	Lookup(ctx context.Context, indicators []reputation.Indicator) (map[reputation.Indicator]*reputation.Label, error)
	Name() string
}

// maxIndicatorsPerEvent caps how many candidate indicators a single hook
// event will run through the verdict cascade. Below the cap, EVERY
// indicator is looked up (the reputation provider's own batching —
// Malanta chunks at 100/request with bounded concurrency — keeps this
// affordable). Above the cap we DENY the whole event outright when
// FailClosed (rather than the old truncate-and-proceed, which let an
// attacker pad the first N entries with benign hosts to hide a malicious
// one past the truncation point) or allow-with-warning
// when FailClosed is false, matching every other "can't fully evaluate"
// path in this cascade.
//
// 500 is comfortably above any realistic legitimate event (a package.json
// with many registry-referenced deps tops out well below 50) and fits in 5
// Malanta batch chunks, which the provider issues concurrently.
const maxIndicatorsPerEvent = 500

// ownerScopeMaxTTL caps how long a GitHub OWNER verdict may be cached,
// regardless of which TTL knob the verdict would otherwise get.
//
// An owner-scope verdict is a statement about an account, and an account
// name is the least stable identity GitHub exposes: a rename frees the old
// name for immediate re-registration by anyone, so a cached "this owner is
// malicious" can outlive the account it described, and a cached "clean" can
// survive the account being taken over. Repository and host verdicts do not
// churn that way, so this cap is owner-only rather than a new config knob.
// Owner-scope indicators are rare (only a reference that names no
// repository produces one), so the extra lookups this forces are not a
// meaningful hot-path cost.
const ownerScopeMaxTTL = 5 * time.Minute

// Targets is everything one hook event contributes to the cascade. Each
// field is a different reputation.Kind and must stay in its own field all
// the way to the provider: an "owner/repo" string routed through the host
// path would be reduced as if it were a hostname (see
// reputation.MalantaProvider's eTLD+1 constraint) and answered by the wrong
// endpoint.
//
//   - Hosts are normalized hostnames / IP literals (extract.Normalize).
//   - Repos are canonical lowercased "owner/repo" (extract.GitHubFromText).
//   - Owners are canonical lowercased bare GitHub account names.
type Targets struct {
	Hosts  []string
	Repos  []string
	Owners []string
}

// Values is every indicator value in the event, hosts first. This is what
// gets recorded as the decision record's `hosts` array: the field predates
// non-host indicators and is the audit trail's record of "what this event
// referred to", which is more useful complete than type-pure. A repo or
// owner entry is unambiguous in practice (a normalized hostname never
// contains "/"), and the one indicator that actually drove the verdict is
// recorded with its exact Kind in Decision.Kind.
func (t Targets) Values() []string {
	if len(t.Repos) == 0 && len(t.Owners) == 0 {
		return t.Hosts
	}
	out := make([]string, 0, len(t.Hosts)+len(t.Repos)+len(t.Owners))
	out = append(out, t.Hosts...)
	out = append(out, t.Repos...)
	out = append(out, t.Owners...)
	return out
}

func (t Targets) isEmpty() bool {
	return len(t.Hosts) == 0 && len(t.Repos) == 0 && len(t.Owners) == 0
}

// Compose runs the full cascade over hostnames only. It is the
// host-extraction entrypoint every caller used before typed indicators
// existed; ComposeTargets is the general form.
func Compose(ctx context.Context, cfg config.Config, hookName string, hosts []string, c *cache.Cache, lookup Lookuper, auditStore *audit.Store) Decision {
	return ComposeTargets(ctx, cfg, hookName, Targets{Hosts: hosts}, c, lookup, auditStore)
}

// ComposeTargets runs the full cascade. hookName is purely cosmetic
// (recorded in the decision log). t.Hosts should already be normalized via
// extract.Normalize; ComposeTargets classifies each into a domain or IPv4
// reputation.Indicator (anything else, e.g. IPv6, is skipped with a
// warning — no provider answers it yet), and t.Repos / t.Owners into their
// GitHub Kinds.
//
// Cache and lookup are both optional: pass nil cache to disable caching,
// pass nil lookup to operate purely from cache (useful for tests).
// auditStore is also optional (nil disables the structured audit table,
// leaving the JSON-Lines decision log as the only record — see
// internal/audit's package doc for why both exist).
func ComposeTargets(ctx context.Context, cfg config.Config, hookName string, t Targets, c *cache.Cache, lookup Lookuper, auditStore *audit.Store) Decision {
	start := time.Now()
	hosts := t.Values()
	d := Decision{Allow: true, HookName: hookName, DecisionID: NewDecisionID(), Mode: effectiveMode(cfg), HelpMessage: cfg.HelpMessage}

	providerName := cfg.Provider
	if providerName == "" {
		providerName = "malanta"
	}
	if lookup != nil {
		providerName = lookup.Name()
	}
	d.Provider = providerName

	// Policy mode "off" is a fast no-op: skip extraction, cache, and the
	// provider entirely. "report-only" still runs the full cascade below
	// (so the audit trail reflects what WOULD have happened) and is
	// reconciled to an always-allow just before returning — see the
	// mode-reconciliation step at the end of this function.
	if d.Mode == config.ModeOff {
		d.DurationMs = time.Since(start).Milliseconds()
		return finalizeDecision(cfg, auditStore, d, hosts)
	}

	// Policy allowlist is applied PER HOST, not as an event-wide
	// short-circuit. An admin-allowlisted host is removed from the set
	// that goes to the cascade (it's pre-approved, never looked up), but
	// any NON-allowlisted host in the same event still runs the full
	// cascade — so a mixed event like [allowed.example, malicious.example]
	// still denies on the malicious host. Only when EVERY extracted host
	// is allowlisted (remaining is empty) do we allow the whole event
	// without consulting the provider.
	remaining := t
	if len(cfg.PolicyAllowlist) > 0 {
		var allowlisted []string
		allowlisted, remaining = partitionTargets(cfg, t)
		if len(allowlisted) > 0 {
			d.Warnings = append(d.Warnings,
				fmt.Sprintf("policy allowlist: %s explicitly allowed", strings.Join(allowlisted, ", ")))
		}
		if remaining.isEmpty() && len(allowlisted) > 0 {
			d.Reason = fmt.Sprintf("policy allowlist: %s is explicitly allowed", strings.Join(allowlisted, ", "))
			d.DurationMs = time.Since(start).Milliseconds()
			return finalizeDecision(cfg, auditStore, d, hosts)
		}
	}

	indicators, classifyWarnings := classifyTargets(remaining)
	d.Warnings = append(d.Warnings, classifyWarnings...)

	if len(indicators) == 0 {
		d.DurationMs = time.Since(start).Milliseconds()
		return finalizeDecision(cfg, auditStore, d, hosts)
	}
	if len(indicators) > maxIndicatorsPerEvent {
		reason := fmt.Sprintf("event extracted %d candidate indicators, exceeding the %d pathological-fan-out cap",
			len(indicators), maxIndicatorsPerEvent)
		if cfg.FailClosed {
			d.Allow = false
			d.Reason = reason
			d.DurationMs = time.Since(start).Milliseconds()
			return finalizeDecision(cfg, auditStore, d, hosts)
		}
		d.Warnings = append(d.Warnings, reason+"; allowing (fail_closed=false)")
		d.DurationMs = time.Since(start).Milliseconds()
		return finalizeDecision(cfg, auditStore, d, hosts)
	}

	allow := config.NewLabelSet(cfg.AllowLabels)
	block := config.NewLabelSet(cfg.BlockLabels)

	// Phase 1: consult cache for every indicator in ONE round-trip. Anything
	// not satisfied goes to the provider. Cache namespace is keyed by the
	// ACTUAL provider name (from Lookuper.Name when available) so switching
	// providers can never read another provider's cached verdicts for the
	// same host.
	resolved := make(map[reputation.Indicator]*reputation.Label, len(indicators))
	misses := make([]reputation.Indicator, 0, len(indicators))
	if c != nil {
		hits, errs := c.LookupBatch(ctx, providerName, indicators)
		for _, ind := range indicators {
			if err := errs[ind]; err != nil {
				// Treat cache errors as misses; never block on cache problems.
				d.Warnings = append(d.Warnings, fmt.Sprintf("cache lookup failed for %s: %v", ind.Value, err))
				misses = append(misses, ind)
				continue
			}
			if h, ok := hits[ind]; ok && h.Present {
				resolved[ind] = h.Label
			} else {
				misses = append(misses, ind)
			}
		}
	} else {
		misses = append(misses, indicators...)
	}

	// Phase 2: live provider for the misses.
	if len(misses) > 0 && lookup != nil {
		labels, err := lookup.Lookup(ctx, misses)
		if err != nil {
			return failClosedOnProviderError(d, cfg, auditStore, providerName, err, start, hosts)
		}
		var absent []reputation.Indicator
		for _, ind := range misses {
			if lbl, ok := labels[ind]; ok && lbl != nil {
				resolved[ind] = lbl
				cachePut(ctx, c, cfg, providerName, ind, lbl, &d)
			} else {
				absent = append(absent, ind)
			}
		}

		// Hardening C1: an indicator absent from an otherwise-successful
		// response is a protocol anomaly (see reputation.Provider's
		// doc-comment) — retry ONCE for just the absent subset before
		// deciding it's unresolvable.
		if len(absent) > 0 {
			retried, retryErr := lookup.Lookup(ctx, absent)
			if retryErr != nil {
				d.Warnings = append(d.Warnings, fmt.Sprintf("retry after partial response failed: %v", retryErr))
			} else {
				var stillAbsent []reputation.Indicator
				for _, ind := range absent {
					if lbl, ok := retried[ind]; ok && lbl != nil {
						resolved[ind] = lbl
						cachePut(ctx, c, cfg, providerName, ind, lbl, &d)
					} else {
						stillAbsent = append(stillAbsent, ind)
					}
				}
				absent = stillAbsent
			}
			for _, ind := range absent {
				reason := fmt.Sprintf("no reputation data returned for %s after retry; failing closed", ind.Value)
				if cfg.FailClosed {
					d.Allow = false
					d.Reason = reason
					d.Indicator = ind.Value
					d.Kind = ind.Kind.String()
					d.DurationMs = time.Since(start).Milliseconds()
					return finalizeDecision(cfg, auditStore, d, hosts)
				}
				d.Warnings = append(d.Warnings, reason+" (fail_closed=false; allowing)")
			}
		}
	}

	// Phase 3: apply the cascade per indicator. First DENY wins.
	for _, ind := range indicators {
		lbl, ok := resolved[ind]
		if !ok || lbl == nil {
			// Defensive: Phase 2 should have resolved or denied every miss
			// already. Only reachable if lookup was nil and the cache also
			// missed (pure-cache test mode).
			d.Warnings = append(d.Warnings, fmt.Sprintf("no verdict for %s; allowing", ind.Value))
			continue
		}
		name := strings.TrimSpace(lbl.Name)
		deny := false
		switch {
		case allow.Has(name):
			// explicit clean; always wins, regardless of score.
		case block.Has(name):
			// In the block list: deny only if confidence crosses the
			// threshold. A block-listed label at LOW confidence is a
			// deliberate "allow + warn" — some providers flag many
			// borderline cases and auto-denying every one of them would
			// make the block list unusable.
			deny = lbl.MaliciousScore >= cfg.MinMaliciousScoreToBlock
		default:
			// Not in the block list: H5 backstop. A provider verdict whose
			// exact name isn't enumerated in BlockLabels must still deny
			// if its score alone crosses the threshold — this is what
			// stops a provider adding a new verdict enum value from
			// silently bypassing the cascade. UNKNOWN/no-score verdicts
			// (MaliciousScore 0 by convention) never cross a sane
			// threshold, so this does not turn the cascade into an
			// allow-list.
			deny = lbl.MaliciousScore >= cfg.MinMaliciousScoreToBlock
		}
		if deny {
			d.Allow = false
			d.Reason = reasonText(providerName, ind, name, lbl.MaliciousScore)
			d.Provider = providerName
			d.Indicator = ind.Value
			d.Kind = ind.Kind.String()
			d.Label = name
			d.DurationMs = time.Since(start).Milliseconds()
			return finalizeDecision(cfg, auditStore, d, hosts)
		}
		// Both branches below require a non-empty name (block.Has("") and
		// a bare label check are always false for an unset verdict name),
		// so this guard is never reachable with name=="" — a score-only
		// provider's (e.g. VirusTotal) below-threshold result stays
		// silent here on purpose: without a name there is no way to
		// distinguish "flagged, but below threshold" from "provider found
		// nothing at all," and logging a warning on every single clean
		// score-only lookup would drown the decision log in noise.
		if name != "" && !allow.Has(name) {
			if lbl.ScoreMissing && block.Has(name) {
				// UNSCORED_VERDICT is a stable, grep-able prefix: the
				// provider flagged this indicator as a block-listed label
				// but returned no numeric score (nil/absent), so
				// MaliciousScore defaulted to 0 and this verdict fell
				// through to allow exactly like a genuine "scored 0"
				// clean result would. Seen live against Malanta
				// ("MALICIOUS", malicious_score: null) — see
				// reputation.Label.ScoreMissing doc. Deny/allow math is
				// unchanged here; this only makes the case loud in the
				// decision log so operators can find it and decide
				// whether unscored block-listed verdicts should fail
				// closed instead.
				d.Warnings = append(d.Warnings,
					fmt.Sprintf("UNSCORED_VERDICT: %s flagged %s as %s with no confidence score (malicious_score absent/null); allowed at malicious score 0 instead of denying",
						providerName, ind.Value, name))
			} else {
				d.Warnings = append(d.Warnings,
					fmt.Sprintf("low-confidence %s for %s (malicious score %g < %g)",
						name, ind.Value, lbl.MaliciousScore, cfg.MinMaliciousScoreToBlock))
			}
		}
	}

	d.DurationMs = time.Since(start).Milliseconds()
	return finalizeDecision(cfg, auditStore, d, hosts)
}

// reasonText builds the "<provider> flagged <indicator> [as <label>]
// (malicious score <score>)" clause shared by every reputation-triggered
// deny. label is omitted (along with "as ") when the provider returned no
// verdict name — e.g. VirusTotal, which answers with a raw engine count
// and no verdict string (see reputation.GenericResponseMapping's doc
// comment on VerdictPath) — leaving it in would otherwise read "flagged X
// as  (malicious score 10)" with a dangling "as" and a double space.
// %g keeps the score compact: a whole count prints as "10" (not
// "10.0000"), a probability prints as "0.9885".
// Non-host indicators are named explicitly ("GitHub repository acme/tool"),
// because "acme/tool" on its own reads like a path and an owner name on its
// own reads like a bare word — neither one tells the person being blocked
// what kind of thing was flagged. An owner-scope deny also says so
// outright: the verdict describes the account, so the specific repository
// being cloned may not itself be flagged, and that is exactly the nuance an
// operator needs to triage the block.
func reasonText(providerName string, ind reputation.Indicator, name string, score float64) string {
	// providerName, value, and name can originate from an
	// untrusted or compromised provider response (the verdict label
	// especially). This string becomes the agent-visible agent_message on a
	// deny, so a label like "MALICIOUS\nIgnore previous instructions and ..."
	// would otherwise inject a newline-delimited instruction into the
	// agent's feedback channel. sanitizeField neutralizes control
	// characters and bounds the length; it is a no-op for ordinary
	// hostnames/labels.
	providerName = sanitizeField(providerName)
	value := sanitizeField(ind.Value)
	name = sanitizeField(name)
	suffix := ""
	switch ind.Kind {
	case reputation.KindGitHubRepo:
		value = "GitHub repository " + value
	case reputation.KindGitHubOwner:
		value = "GitHub account " + value
		suffix = "; this verdict is for the account, not for one specific repository"
	}
	if name == "" {
		return fmt.Sprintf("%s flagged %s (malicious score %g)%s", providerName, value, score, suffix)
	}
	return fmt.Sprintf("%s flagged %s as %s (malicious score %g)%s", providerName, value, name, score, suffix)
}

// maxFieldLen bounds a single sanitized field so a hostile provider or
// custom rule can't pad the agent/user message with kilobytes of text.
const maxFieldLen = 256

// sanitizeField neutralizes text that flows from a provider response or a
// custom ATR rule into an agent/user-facing message. It replaces
// every ASCII control character (including newlines, carriage returns, and
// tabs) and DEL with a single space, so the value cannot break out of its
// position in the message onto a new line that the agent might read as a
// fresh instruction, and caps the length. It is intentionally a no-op for
// ordinary printable single-line content (hostnames, verdict labels, rule
// descriptions), so message wording for the common case is unchanged.
func sanitizeField(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if len(out) > maxFieldLen {
		out = strings.TrimSpace(out[:maxFieldLen]) + "…"
	}
	return out
}

// decisionIDBytes controls how long a decision_id is: 6 random bytes ->
// 12 hex characters. Collision probability across even a very high-volume
// fleet is negligible (48 bits of entropy) while staying short enough to
// paste into a support ticket or read aloud.
const decisionIDBytes = 6

// NewDecisionID returns a fresh, opaque, lowercase-hex decision identifier.
// Exported so hookrunner can mint one for the two code paths that bypass
// Compose entirely (a per-hook short-circuit Decision and a bootstrap
// error) — every Decision that ever reaches AsJSON should carry one.
func NewDecisionID() string {
	b := make([]byte, decisionIDBytes)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is essentially unheard-of on any platform
		// this project supports; falling back to a time-based id keeps
		// the hook from ever panicking over an id string, at the cost
		// of losing collision-resistance in that vanishingly rare case.
		return fmt.Sprintf("t%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// effectiveMode normalizes cfg.Mode to one of the three recognized values,
// defaulting to enforce (fail-closed's own default posture) for an empty
// or unrecognized string — a typo in a managed config file must never
// silently turn into "off".
func effectiveMode(cfg config.Config) string {
	switch cfg.Mode {
	case config.ModeReportOnly, config.ModeOff, config.ModeWarn, config.ModeAsk:
		return cfg.Mode
	default:
		return config.ModeEnforce
	}
}

// partitionPolicyAllowlist splits the extracted hosts into those that are
// members of the admin-managed indicator allowlist (Config.PolicyAllowlist)
// and those that are not, preserving first-seen order in each slice. The
// allowlist is a MINIMAL stand-in for the fuller "org allowlist with owner +
// expiry + justification" design in the project plan — it's an
// unconditional, non-expiring, admin-configured allowlist. Matching is
// case-insensitive and exact (no wildcards, no subdomain matching) to keep
// the semantics unambiguous to read out of a config file.
//
// Applied per host (not as an event-wide short-circuit): an allowlisted host
// is pre-approved and dropped from the cascade set, but any non-allowlisted
// host in the same event is still evaluated. Per-host is the fix for a
// single allowlisted host allowing the entire event — which let an
// attacker smuggle a malicious host past the cascade by pairing it with a
// benign, allowlisted one.
func partitionPolicyAllowlist(cfg config.Config, hosts []string) (allowlisted, rest []string) {
	if len(cfg.PolicyAllowlist) == 0 {
		return nil, hosts
	}
	set := config.NewLabelSet(cfg.PolicyAllowlist)
	for _, h := range hosts {
		if set.Has(h) {
			allowlisted = append(allowlisted, h)
		} else {
			rest = append(rest, h)
		}
	}
	return allowlisted, rest
}

// partitionTargets applies partitionPolicyAllowlist to every scope of an
// event. An allowlist entry matches an indicator VALUE exactly
// (case-insensitively), so "acme/internal-tool" allowlists that repository
// and "acme" allowlists that owner — the same literal-match semantics hosts
// already have, with no cross-scope implication in either direction
// (allowlisting an owner does NOT allowlist its repositories, because that
// would let one trusted account name pre-approve anything published under
// it).
func partitionTargets(cfg config.Config, t Targets) (allowlisted []string, rest Targets) {
	var a []string
	a, rest.Hosts = partitionPolicyAllowlist(cfg, t.Hosts)
	allowlisted = append(allowlisted, a...)
	a, rest.Repos = partitionPolicyAllowlist(cfg, t.Repos)
	allowlisted = append(allowlisted, a...)
	a, rest.Owners = partitionPolicyAllowlist(cfg, t.Owners)
	allowlisted = append(allowlisted, a...)
	return allowlisted, rest
}

// finalizeDecision is the single funnel every Compose return path routes
// through (see the package doc's cascade list). It applies, in order:
//
//  1. report-only reconciliation: a mode of "report-only" never actually
//     blocks — a would-have-denied Decision is flipped to Allow=true with
//     a warning recording what the cascade actually concluded, so the
//     audit trail shows the counterfactual without affecting the agent.
//  2. admin-gated user override (Option 5 in the project plan): applies
//     ONLY to a still-denied Decision, and only when the operator has
//     both enabled Config.AllowUserOverride (a managed-config setting,
//     never a user-writable one) AND the user has an unexpired grant
//     recorded — see checkUserOverride / internal/override.ActiveFor.
//     Every override is logged, never a silent bypass.
//  3. warn-mode resolution (resolveWarn): applies ONLY when Mode is
//     "warn" and the Decision still denies with a specific flagged
//     Indicator. See resolveWarn's doc comment for the deny-once-then-
//     allow-on-retry mechanism. Mutually exclusive in practice with
//     step 2's CLI override (an operator picks one posture or the
//     other), but nothing prevents both being configured at once —
//     step 2 runs first and, if it already flipped Allow to true,
//     resolveWarn's own `!d.Allow` guard is simply a no-op.
//  4. otherwise, if AllowUserOverride is enabled (and Mode is not
//     "warn"), the deny message grows an OverrideHint telling the
//     operator the exact `trustgate override` command that would
//     unblock this indicator.
//  5. writes the JSON-Lines log + the SQLite audit record.
//
// KNOWN LIMITATION: a deny introduced later by ATR (verdict.MergeATR,
// called from hookrunner AFTER Compose returns) does not pass back
// through this funnel, so report-only/override/warn do not apply to an
// ATR-triggered flip. The audit record written here reflects the
// pre-ATR decision; to keep the trail honest, hookrunner appends a
// separate FINAL-decision record after ATR whenever ATR flips the
// verdict (AUD-001), so the last record for a decision_id matches what
// Cursor received. This is the intended behavior for warn mode
// specifically (an ATR-only deny — a clean domain reputation verdict
// that ATR alone denies — is never eligible for the deny-once-then-
// allow-on-retry treatment, since finalizeDecision has already run and
// left Warned=false by the time ATR sees the Decision; see
// internal/hookrunner's applyATR ordering — an ATR-flagged action is
// never merely "warned about," it stays a hard, non-negotiable block).
// Unifying report-only/override for ATR-triggered denies more broadly
// is tracked as the "split hookrunner's ATR/audit/policy handling into
// their own packages" follow-up.
// hookEnforcesAsk reports whether Cursor actually ENFORCES a
// permission:"ask" verdict for the given hook event (renders the native
// approve/reject dialog and pauses the action). Per Cursor's hooks docs
// only beforeShellExecution and beforeMCPExecution do. preToolUse accepts
// "ask" but does not enforce it, beforeReadFile is allow/deny only, and
// subagentStart treats "ask" as deny — on all of those an emitted "ask"
// renders no dialog, so ModeAsk degrades to a hard deny there instead.
func hookEnforcesAsk(hookName string) bool {
	switch hookName {
	case "beforeShellExecution", "beforeMCPExecution":
		return true
	default:
		return false
	}
}

func finalizeDecision(cfg config.Config, auditStore *audit.Store, d Decision, hosts []string) Decision {
	if d.Mode == config.ModeReportOnly && !d.Allow {
		d.Warnings = append(d.Warnings, "report-only mode: would have denied: "+d.Reason)
		d.Allow = true
	}
	if !d.Allow && cfg.AllowUserOverride {
		if ok, overrideReason := checkUserOverride(cfg, d.Indicator); ok {
			d.Warnings = append(d.Warnings,
				fmt.Sprintf("user override applied (would have denied: %s): %s", d.Reason, overrideReason))
			d.Allow = true
		}
	}
	if !d.Allow && d.Mode == config.ModeWarn && d.Indicator != "" {
		d = resolveWarn(cfg, d)
	}
	// ModeAsk: a still-denied decision is emitted to Cursor as
	// permission:"ask" (a human approve/reject dialog) instead of a hard
	// deny. Unlike warn, there is no retry-to-allow path the agent can
	// self-trigger — the decision is Cursor's to render to the human. We
	// leave Allow=false (it is not an allow) and set Ask so AsJSON picks the
	// "ask" wire shape. Runs after override/warn so an explicit override or
	// an active warn grant still short-circuits to allow first.
	//
	// Two gates, both of which must pass or ask degrades to a hard deny
	// (the safe direction — never fail open, never deadlock):
	//   1. VERSION: Cursor only honors "ask" from cfg.AskMinCursorVersion
	//      onwards; older builds silently ignore it.
	//   2. EVENT: Cursor only ENFORCES "ask" for beforeShellExecution and
	//      beforeMCPExecution. For preToolUse (WebFetch/WebSearch) "ask" is
	//      accepted-but-not-enforced, beforeReadFile is allow/deny only, and
	//      subagentStart treats "ask" as deny (per Cursor's hooks docs). On
	//      those events an emitted "ask" renders no dialog — the human can
	//      never approve — so we must degrade to a real deny instead of
	//      leaving the agent waiting on a dialog that will never appear.
	if !d.Allow && d.Mode == config.ModeAsk {
		switch {
		case !cfg.CursorHonorsAsk():
			d.Warnings = append(d.Warnings, fmt.Sprintf(
				"ask mode: Cursor version %q does not meet the ask floor %q (or is unknown); degrading to a hard deny to avoid failing open",
				cfg.CursorVersion, cfg.AskMinCursorVersion))
		case !hookEnforcesAsk(d.HookName):
			d.Warnings = append(d.Warnings, fmt.Sprintf(
				"ask mode: Cursor does not enforce permission:\"ask\" for %s (only beforeShellExecution/beforeMCPExecution); degrading to a hard deny",
				d.HookName))
		default:
			d.Ask = true
		}
	}
	if !d.Allow && !d.Ask && d.Mode != config.ModeWarn && cfg.AllowUserOverride {
		d.OverrideHint = overrideHintText(cfg, d.Indicator, d.Kind)
	}
	writeLog(cfg.LogPath, auditStore, d, hosts)
	return d
}

// resolveWarn implements Config.ModeWarn's deny-once-then-allow-on-
// retry flow for a domain-reputation deny with a known indicator. This
// exists because warn must work on EVERY Cursor version and in
// autonomous/auto-run sessions where no human is present to click a
// dialog. Cursor only renders a hook's user_message on a hard `deny`,
// and its `permission:"ask"` dialog was a silently-ignored no-op for the
// execution hooks through Cursor 3.10 (Cursor staff, forum.cursor.com;
// fixed as of 3.11.25, which is what ModeAsk now targets — see
// config.ModeAsk). So warn is built from the ONE primitive that works
// everywhere: deny with a message, resolved by the user retrying the
// identical action (which re-fires this same hook). ModeAsk is the
// interactive-only alternative that uses the now-working dialog instead.
//
//  1. An active grant already covers this indicator (a previous warn
//     was already acknowledged and we're still inside the window) ->
//     allow silently, same as the CLI override's grant check.
//  2. No active grant, but a pending "warned" marker exists for this
//     indicator (this call IS the retry of an action already warned
//     about once) -> internal/override.PromotePending consumes the
//     marker and writes a real, time-boxed grant (scoped per
//     Config.OverrideScope) -> allow.
//  3. Neither -> this is the first touch. Record a pending marker
//     (internal/override.AddPending) and keep the deny, with Warned
//     set so AsJSON's denyMessage appends the audited-retry-to-proceed
//     text instead of the CLI OverrideHint.
//
// Cursor gives the hook no signal distinguishing a human deliberately
// retrying from an agent auto-retrying the same command, so step 2 can't
// tell them apart directly. Two mitigations blunt an agent
// self-acknowledging: (a) AsJSON hands the agent a DIFFERENT
// agent_message that tells it NOT to retry (see agentDenyMessage), and
// (b) the Config.WarnAckMinSeconds dwell gate below rejects a retry that
// arrives faster than a human plausibly could. Neither is a hard
// guarantee (see docs/admin.md's warn-mode section): warn is an
// audit+notify posture, not an enforcement boundary, and every step here
// (deny, promote, allow) is written to the decision log + audit sink
// regardless of who triggered the retry, so the audit requirement is met
// unconditionally.
func resolveWarn(cfg config.Config, d Decision) Decision {
	if ok, overrideReason := override.ActiveFor(cfg.CacheDir, d.Indicator); ok {
		d.Warnings = append(d.Warnings,
			fmt.Sprintf("warn-mode window active (would have denied: %s): %s", d.Reason, overrideReason))
		d.Allow = true
		return d
	}
	minAckDelay := time.Duration(cfg.WarnAckMinSeconds) * time.Second
	promoted, err := override.PromotePending(cfg.CacheDir, d.Indicator, cfg.OverrideScope, cfg.OverrideWindowMinutes, minAckDelay)
	if err != nil {
		d.Warnings = append(d.Warnings, fmt.Sprintf("warn-mode: failed to promote pending marker for %s: %v", d.Indicator, err))
	} else if promoted {
		d.Warnings = append(d.Warnings, fmt.Sprintf("warn-mode: acknowledged via retry, allowing (would have denied: %s)", d.Reason))
		d.Allow = true
		return d
	}
	// Either a first touch (no marker yet) or a retry that arrived inside
	// the dwell window (marker present but too young to count as a human
	// acknowledgment). Both re-warn; AddPending records the first touch
	// and preserves the original Created timestamp on a too-soon retry, so
	// the dwell clock keeps advancing toward the point a genuine
	// human-paced retry can promote.
	if err := override.AddPending(cfg.CacheDir, d.Indicator); err != nil {
		d.Warnings = append(d.Warnings, fmt.Sprintf("warn-mode: failed to record pending marker for %s: %v", d.Indicator, err))
	}
	d.Warned = true
	return d
}

// overrideHintText builds the user-facing instruction appended to a
// deny message when AllowUserOverride is enabled and Mode is not
// "warn" (warn mode has its own distinct message — see resolveWarn).
// Names the indicator when a specific one triggered the deny (the common
// case); omits it for a systemic denial (e.g. provider-unavailable, or the
// pathological fan-out cap) where there's no single indicator to name — an
// operator in that situation needs the blanket form.
//
// The flag must match the denied indicator's KIND. Suggesting --domain for
// a GitHub repository would hand the operator a command that appears to
// succeed (the store is keyed by value, so the grant writes fine) while
// leaving them blocked, since --domain would not canonicalize the
// reference the way the cascade did.
func overrideHintText(cfg config.Config, indicator, kind string) string {
	minutes := cfg.OverrideWindowMinutes
	if minutes <= 0 {
		minutes = 15
	}
	if indicator != "" {
		flag := "--domain"
		switch kind {
		case reputation.KindGitHubRepo.String():
			flag = "--repo"
		case reputation.KindGitHubOwner.String():
			flag = "--owner"
		}
		return fmt.Sprintf(`To allow temporarily, run: trustgate override %s %s --minutes %d --reason "<why>", then retry.`, flag, indicator, minutes)
	}
	return fmt.Sprintf(`To allow temporarily, run: trustgate override --minutes %d --reason "<why>", then retry.`, minutes)
}

// failClosedOnProviderError builds and logs the Decision for a total
// provider-lookup failure (as opposed to a partial/absent-entry response,
// which Compose handles separately via the retry-once path).
//
// Reason keeps the full, raw error detail (HTTP status, provider error
// body) — that's operator-only troubleshooting information, fully
// recorded in the decision log / audit table for `trustgate explain`.
// UserReason is a separate, deliberately terse summary with no raw
// provider internals — that's what the person who got denied actually
// sees, in the Cursor UI, via denyMessage.
func failClosedOnProviderError(d Decision, cfg config.Config, auditStore *audit.Store, providerName string, err error, start time.Time, hosts []string) Decision {
	authErr := errors.Is(err, reputation.ErrAuth)
	reason := fmt.Sprintf("%s unavailable: %v", providerName, err)
	// Two hook/mode combinations fail OPEN on a provider error instead of
	// fail-closed-denying:
	//
	//   - beforeSubmitPrompt is an advisory, soft early-warn layer
	//     (registered failClosed:false at the hook level — see hooks.json
	//     and docs/admin.md §5.3): a provider hiccup must never block a
	//     prompt from being submitted.
	//   - ModeWarn is an audit+notify posture, not an enforcement boundary
	//     (docs/admin.md §5.2). Its whole reason to exist is to NOT delay
	//     the developer's work; hard-denying every action while Malanta is
	//     slow/unreachable is exactly the friction warn is meant to avoid.
	//     So warn fails OPEN on a provider error too, matching report-only
	//     (which also never blocks). enforce keeps the fail-closed default.
	//
	// In both cases the execution hooks still gate real, resolvable
	// verdicts; failing open only affects the "we couldn't reach the
	// provider at all" path, and it's recorded as a warning in the
	// decision log so an operator can see it happened.
	failOpen := d.HookName == "beforeSubmitPrompt" || d.Mode == config.ModeWarn
	if cfg.FailClosed && !failOpen {
		d.Allow = false
		d.Reason = reason
		if authErr {
			d.Reason += " (rotate or reconfigure the provider's API key)"
			d.UserReason = fmt.Sprintf("%s: API key rejected — rotate or reconfigure it (action blocked)", providerName)
		} else {
			d.UserReason = fmt.Sprintf("%s temporarily unavailable — action blocked (fail-closed)", providerName)
		}
		d.DurationMs = time.Since(start).Milliseconds()
		return finalizeDecision(cfg, auditStore, d, hosts)
	}
	if cfg.FailClosed && d.HookName == "beforeSubmitPrompt" {
		reason += " (beforeSubmitPrompt fails open on provider error; execution hooks still enforce)"
	} else if cfg.FailClosed && d.Mode == config.ModeWarn {
		reason += " (warn mode fails open on provider error; use enforce mode to block on provider outages)"
	}
	d.Warnings = append(d.Warnings, reason)
	d.DurationMs = time.Since(start).Milliseconds()
	return finalizeDecision(cfg, auditStore, d, hosts)
}

// cachePut writes a resolved Label to the cache, choosing a TTL based on
// whether the verdict WOULD deny (score >= MinMaliciousScoreToBlock — the
// same predicate the cascade itself uses, so a cached "flagged" entry is
// exactly one that would trigger a deny on replay) or not. Flagged verdicts
// get the longer TTL (PositiveTTL) since they don't need frequent refresh;
// clean/unknown/low-confidence verdicts get the shorter TTL (NegativeTTL)
// so a newly-flagged host surfaces sooner — this is the "shorter clean TTL
// for high-security orgs" behavior, implemented by repurposing the
// two existing TTL knobs rather than adding new config surface. Cache write
// failures are recorded as warnings, never as a reason to change the
// verdict.
func cachePut(ctx context.Context, c *cache.Cache, cfg config.Config, providerName string, ind reputation.Indicator, lbl *reputation.Label, d *Decision) {
	if c == nil {
		return
	}
	if err := c.Put(ctx, providerName, ind, lbl, ttlFor(cfg, ind, lbl)); err != nil {
		d.Warnings = append(d.Warnings, fmt.Sprintf("cache write failed for %s: %v", ind.Value, err))
	}
}

// ttlFor picks the cache lifetime for one resolved verdict: the flagged
// (PositiveTTL) or clean/unknown (NegativeTTL) knob, then the owner-scope
// ceiling (see ownerScopeMaxTTL).
func ttlFor(cfg config.Config, ind reputation.Indicator, lbl *reputation.Label) time.Duration {
	ttl := cfg.NegativeTTL
	if lbl.MaliciousScore >= cfg.MinMaliciousScoreToBlock {
		ttl = cfg.PositiveTTL
	}
	if ind.Kind == reputation.KindGitHubOwner && ttl > ownerScopeMaxTTL {
		return ownerScopeMaxTTL
	}
	return ttl
}

// classifyTargets converts an event's Targets into typed reputation
// Indicators. Hosts go through classifyIndicators; repos and owners are
// already canonical, so they only need their Kind attached — critically,
// they do NOT go through the host classifier, whose net.ParseIP /
// KindDomain default would mislabel them as hostnames and route them to the
// domain endpoint.
//
// Deduplicates across all three scopes while preserving first-seen order.
func classifyTargets(t Targets) ([]reputation.Indicator, []string) {
	indicators, warnings := classifyIndicators(t.Hosts)
	if len(t.Repos) == 0 && len(t.Owners) == 0 {
		return indicators, warnings
	}
	seen := make(map[reputation.Indicator]struct{}, len(indicators)+len(t.Repos)+len(t.Owners))
	for _, ind := range indicators {
		seen[ind] = struct{}{}
	}
	add := func(kind reputation.Kind, values []string) {
		for _, v := range values {
			if v == "" {
				continue
			}
			ind := reputation.Indicator{Kind: kind, Value: v}
			if _, dup := seen[ind]; dup {
				continue
			}
			seen[ind] = struct{}{}
			indicators = append(indicators, ind)
		}
	}
	add(reputation.KindGitHubRepo, t.Repos)
	add(reputation.KindGitHubOwner, t.Owners)
	return indicators, warnings
}

// classifyIndicators converts normalized host strings into reputation
// Indicators, splitting domains from IPv4 literals. Anything that parses as
// an IP but isn't IPv4 (i.e. IPv6) is skipped with a warning: no provider
// answers IPv6 lookups yet (see reputation.Kind's doc-comment), and this is
// a permanent limitation, not a transient error, so it must not trigger
// fail-closed. Deduplicates while preserving first-seen order.
func classifyIndicators(hosts []string) ([]reputation.Indicator, []string) {
	if len(hosts) == 0 {
		return nil, nil
	}
	seen := make(map[reputation.Indicator]struct{}, len(hosts))
	out := make([]reputation.Indicator, 0, len(hosts))
	var warnings []string
	for _, h := range hosts {
		var ind reputation.Indicator
		if ip := net.ParseIP(h); ip != nil {
			if ip.To4() == nil {
				warnings = append(warnings, fmt.Sprintf("no reputation provider supports IPv6 yet; skipping %s", h))
				continue
			}
			ind = reputation.Indicator{Kind: reputation.KindIPv4, Value: h}
		} else {
			ind = reputation.Indicator{Kind: reputation.KindDomain, Value: h}
		}
		if _, ok := seen[ind]; ok {
			continue
		}
		seen[ind] = struct{}{}
		out = append(out, ind)
	}
	return out, warnings
}

// writeLog appends a single JSON Lines record to the configured log path
// AND, when auditStore is non-nil, inserts the same decision into the
// structured SQLite audit table (internal/audit) — see that package's doc
// comment for why both stores exist side by side. Logging failures must
// not change the verdict (the verdict has already been computed by the
// caller), but they must also not be silent: we surface them on stderr so
// Cursor's hook output panel shows the operator that observability is
// broken. The redaction contract is preserved here: only the extracted
// indicators and the Decision are written; raw prompts, shell command
// text, and file contents never enter either record.
func writeLog(path string, auditStore *audit.Store, d Decision, hosts []string) {
	now := time.Now()
	if auditStore != nil {
		var atrRuleIDs []string
		for _, m := range d.ATRMatches {
			atrRuleIDs = append(atrRuleIDs, m.RuleID)
		}
		rec := audit.Record{
			DecisionID: d.DecisionID,
			Timestamp:  now,
			HookName:   d.HookName,
			Provider:   d.Provider,
			Indicator:  d.Indicator,
			Kind:       d.Kind,
			Label:      d.Label,
			Allow:      d.Allow,
			Mode:       d.Mode,
			Reason:     d.Reason,
			DurationMs: d.DurationMs,
			Hosts:      hosts,
			Warnings:   d.Warnings,
			ATRRuleIDs: atrRuleIDs,
		}
		if err := auditStore.Insert(context.Background(), rec); err != nil {
			fmt.Fprintf(os.Stderr, "trustgate: audit-store insert failed: %v\n", err)
		}
	}

	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "trustgate: decision-log mkdir failed: %v\n", err)
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustgate: decision-log open failed: %v\n", err)
		return
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "trustgate: decision-log close failed: %v\n", cerr)
		}
	}()
	rec := struct {
		Timestamp string   `json:"timestamp"`
		Hosts     []string `json:"hosts"`
		Decision  Decision `json:"decision"`
	}{
		Timestamp: now.UTC().Format(time.RFC3339Nano),
		Hosts:     hosts,
		Decision:  d,
	}
	if err := json.NewEncoder(f).Encode(rec); err != nil {
		fmt.Fprintf(os.Stderr, "trustgate: decision-log encode failed: %v\n", err)
	}
}

// RecordDecision is writeLog's exported counterpart for the two hookrunner
// code paths that bypass Compose entirely — a per-hook short-circuit
// Decision and a bootstrap error. Ensures DecisionID and Mode are
// populated (so every Decision that reaches AsJSON has both, matching
// what Compose guarantees internally) before delegating to writeLog.
func RecordDecision(cfg config.Config, auditStore *audit.Store, d *Decision, hosts []string) {
	if d == nil {
		return
	}
	if d.DecisionID == "" {
		d.DecisionID = NewDecisionID()
	}
	if d.Mode == "" {
		d.Mode = effectiveMode(cfg)
	}
	if d.HelpMessage == "" {
		d.HelpMessage = cfg.HelpMessage
	}
	writeLog(cfg.LogPath, auditStore, *d, hosts)
}

// checkUserOverride reports whether indicator currently has an
// unexpired grant on disk at Config.CacheDir (written by `trustgate
// override`, or promoted from an approved prompt — see
// internal/override). Only ever consulted when the caller has already
// confirmed Config.AllowUserOverride is true (a managed-config setting)
// — the presence of a grant alone is never sufficient, so an operator
// who hasn't opted in can't be bypassed by a user simply writing the
// file by hand into a getenv-controlled path they own anyway; the real
// gate is the admin-side config flag, not file secrecy. Delegates
// entirely to internal/override.ActiveFor, which matches either an
// exact (case-insensitive) domain grant or a blanket "*" grant — see
// that package's doc comment for the on-disk schema and the legacy
// {until,reason} shape it still reads.
func checkUserOverride(cfg config.Config, indicator string) (bool, string) {
	return override.ActiveFor(cfg.CacheDir, indicator)
}

// AsJSON marshals a Decision to the wire shape Cursor expects on stdout.
// Returns the bytes followed by a newline.
//
// Cursor's hook output schema is per-event (see cursor.com/docs/hooks):
//   - beforeShellExecution / beforeMCPExecution / beforeReadFile:
//     {"continue": true, "permission": "allow"|"deny", "user_message": ...,
//     "agent_message": ...} — continue:true keeps the agent loop alive so
//     a deny surfaces Cursor's retry ("Try Again") affordance instead of
//     hard-stopping the turn (see the struct literal below for the full
//     rationale and the docs-example provenance).
//   - beforeSubmitPrompt:
//     {"continue": true|false, "user_message": ...}
//
// Cursor fails OPEN on any output it can't parse (well-formed JSON with an
// unrecognized verdict field is treated as "no decision" and the action
// proceeds). Getting this shape right is therefore security-critical; the
// internal Decision struct is intentionally decoupled from the wire format so
// that the decision log can keep its richer fields without affecting Cursor.
// denyMessage builds the user/agent-facing text for a deny: the
// reason, plus a decision_id an admin can look up later (`trustgate
// explain <decision_id>`), plus exactly one of:
//   - the warn-mode suffix, when Warned is true (this is the FIRST
//     touch of a flagged indicator under Config.ModeWarn — see
//     resolveWarn): tells the user the access was audited and that
//     retrying the identical action will proceed and be remembered
//     for a window.
//   - OverrideHint, the exact `trustgate override` command that would
//     unblock this indicator (see overrideHintText) — only when
//     AllowUserOverride is enabled and Mode is not "warn".
//
// plus an optional org-configured help line (Config.HelpMessage — a
// support URL or channel name). This is Option 1 from the project's
// admin-operability plan: turning a cryptic block into a ticket with a
// lookup key (and, now, a self-service escape hatch when the admin has
// enabled one).
func (d Decision) denyMessage() string {
	reason := d.Reason
	if d.UserReason != "" {
		reason = d.UserReason
	}
	msg := "TrustGate: " + reason
	if d.DecisionID != "" {
		msg += fmt.Sprintf(" [decision_id: %s]", d.DecisionID)
	}
	switch {
	case d.Warned && d.HookName == "beforeSubmitPrompt":
		// beforeSubmitPrompt fires on prompt submission, so the
		// acknowledgement is re-submitting the prompt, not re-running a
		// command. Keep the word "Audited" (asserted by tests and shared
		// with the generic wording below).
		msg += " Audited — re-submit this prompt to allow it briefly."
	case d.Warned:
		msg += " Audited — re-run the same action to allow it briefly."
	default:
		// Hard deny: no self-serve retry path. Name what actually
		// blocked, then — only if the admin enabled self-service
		// override — the exact command to unblock it.
		//
		// Naming the real mode matters for triage: ModeAsk reaches this
		// branch whenever it degraded to a hard deny (the event renders
		// no dialog, or the Cursor version is below the ask floor), and
		// reporting "enforce mode" there sent the operator looking at a
		// config value that was not what blocked them.
		//
		// A provider outage is called out separately because the next
		// step differs — check provider reachability, not the policy or
		// the block list. UserReason is set by exactly one path
		// (failClosedOnProviderError), which makes it the marker for
		// "this block is an outage, not a verdict."
		switch mode := d.Mode; {
		case d.UserReason != "":
			msg += " Blocked (fail-closed)."
		case mode == "":
			// Mode is always populated in production (Compose defaults
			// it); this keeps a hand-built Decision honest.
			msg += " Blocked."
		default:
			msg += fmt.Sprintf(" Blocked (%s mode).", mode)
		}
		if d.OverrideHint != "" {
			msg += " " + d.OverrideHint
		}
	}
	// Optional org-configured help line (Config.HelpMessage). This is the
	// ONLY place operator-supplied contact text is added — there is no
	// generic "contact your admin" fallback; an admin who wants one sets
	// TRUSTGATE_HELP_MESSAGE.
	if d.HelpMessage != "" {
		msg += " " + d.HelpMessage
	}
	return msg
}

// agentDenyMessage is the text fed to the AGENT (agent_message) on a
// deny, as opposed to denyMessage which is what the human sees
// (user_message). They are identical for every deny EXCEPT a warn-mode
// first touch (Warned): there, denyMessage tells the human "re-run to
// proceed" — but handing that same instruction to the agent is exactly
// what makes the agent auto-retry and silently self-acknowledge the
// warning before any human sees it. So the agent instead gets a message
// that explicitly tells it to STOP and defer to the human, with no
// retry instruction. The dwell gate in resolveWarn is the second half of
// this defense (an agent that retries anyway, ignoring this, is re-warned
// if it retries too fast); see that function's doc comment.
//
// Only ever called for the execution hooks (beforeShellExecution /
// beforeMCPExecution / beforeReadFile); beforeSubmitPrompt emits no
// agent_message in its wire shape, so its warn text stays in
// denyMessage.
func (d Decision) agentDenyMessage() string {
	if !d.Warned {
		return d.denyMessage()
	}
	msg := "TrustGate: " + d.Reason
	if d.DecisionID != "" {
		msg += fmt.Sprintf(" [decision_id: %s]", d.DecisionID)
	}
	msg += " This action was blocked pending human review (TrustGate audit+notify mode)." +
		" Do NOT retry it automatically; stop and let the user decide whether to proceed."
	if d.HelpMessage != "" {
		msg += " " + d.HelpMessage
	}
	return msg
}

// askMessage is the user_message shown in Cursor's approve/reject dialog
// under ModeAsk. It frames the flagged reason as a decision for the human,
// with the decision_id for later lookup.
func (d Decision) askMessage() string {
	reason := d.Reason
	if d.UserReason != "" {
		reason = d.UserReason
	}
	msg := "TrustGate: " + reason
	if d.DecisionID != "" {
		msg += fmt.Sprintf(" [decision_id: %s]", d.DecisionID)
	}
	msg += " Approve to allow this action, or reject to block it."
	if d.HelpMessage != "" {
		msg += " " + d.HelpMessage
	}
	return msg
}

// askAgentMessage is the agent_message under ModeAsk: tell the agent a human
// is deciding and it must NOT retry (the agent cannot approve on its own —
// only the user's dialog choice can).
func (d Decision) askAgentMessage() string {
	msg := "TrustGate: " + d.Reason
	if d.DecisionID != "" {
		msg += fmt.Sprintf(" [decision_id: %s]", d.DecisionID)
	}
	msg += " TrustGate is asking the user to approve or reject this action." +
		" Do NOT retry — wait for the human's decision."
	if d.HelpMessage != "" {
		msg += " " + d.HelpMessage
	}
	return msg
}

func (d Decision) AsJSON() []byte {
	var (
		b   []byte
		err error
	)

	if d.HookName == "beforeSubmitPrompt" {
		out := struct {
			Continue    bool   `json:"continue"`
			UserMessage string `json:"user_message,omitempty"`
		}{
			Continue: d.Allow,
		}
		if !d.Allow {
			out.UserMessage = d.denyMessage()
		}
		b, err = json.Marshal(out)
	} else {
		perm := "allow"
		if !d.Allow {
			// ModeAsk emits Cursor's approve/reject "ask" instead of a hard
			// "deny" (experimental — see Decision.Ask). Every other
			// not-allowed verdict is a "deny".
			if d.Ask {
				perm = "ask"
			} else {
				perm = "deny"
			}
		}
		// Continue is emitted true on every verdict (allow AND deny).
		// It is the Claude-Code-compat "keep the agent loop alive" flag
		// Cursor inherited: continue:false (or, empirically, an absent
		// continue on a deny) halts the whole turn, whereas continue:true
		// blocks only THIS action while leaving the flow live, so the
		// agent (or the user) can re-run the same command — which re-fires
		// this hook, exactly what warn mode's deny-once-then-allow-on-retry
		// depends on. (Re-running is a manual/agent re-issue of the command;
		// Cursor does NOT render a one-click "Try Again" button for a policy
		// deny — that affordance appears only for a Canceled/timeout hook
		// failure, established empirically.) Cursor's reference
		// schema for this event doesn't list continue, but every one of
		// Cursor's own deny EXAMPLES (docs block-git.sh, kube_guard.py)
		// emits continue:true alongside permission:"deny"; omitting it
		// hard-stopped the whole turn on a deny.
		out := struct {
			Continue     bool   `json:"continue"`
			Permission   string `json:"permission"`
			UserMessage  string `json:"user_message,omitempty"`
			AgentMessage string `json:"agent_message,omitempty"`
		}{
			Continue:   true,
			Permission: perm,
		}
		if !d.Allow {
			if d.Ask {
				// ask mode: the human is asked to approve/reject; the agent
				// is told to wait, not retry.
				out.UserMessage = d.askMessage()
				out.AgentMessage = d.askAgentMessage()
			} else {
				// user_message and agent_message diverge only on a warn-mode
				// first touch: the human is told how to proceed, the agent is
				// told to stop and not retry (see agentDenyMessage). Every
				// other deny path returns identical text from both.
				out.UserMessage = d.denyMessage()
				out.AgentMessage = d.agentDenyMessage()
			}
		}
		b, err = json.Marshal(out)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "trustgate: decision marshal failed: %v\n", err)
		if d.HookName == "beforeSubmitPrompt" {
			return []byte(`{"continue":false,"user_message":"trustgate: internal marshal error"}` + "\n")
		}
		return []byte(`{"continue":true,"permission":"deny","user_message":"trustgate: internal marshal error"}` + "\n")
	}
	return append(b, '\n')
}

// MergeATR folds a set of ATR matches into an existing Decision.
//
// Always: matches are recorded on the Decision (so the decision-log
// audit trail captures them regardless of severity).
//
// Conditionally: if failClosed is true AND at least one match is
// SeverityCritical AND the Decision is currently allow, the Decision
// is flipped to deny with a reason that names the rule ID. The
// reputation cascade may have already produced a deny — in that
// case we keep the existing deny reason and merely annotate with
// ATR matches in the log, because the operator sees both signals via
// the JSON-Lines record.
//
// Why severity-gated and not "any match denies": the false-positive
// budget targets ≤5% FP on read-file/MCP and ≤1% on shell. Holding
// the deny line at SeverityCritical leaves Medium / Low matches as
// observability-only signal that the operator can investigate
// without paying a fail-closed bill on every hit. Severity defaults
// are encoded in each rule's YAML and reviewed during the
// curation step.
//
// If failClosed is false, MergeATR still records matches but never
// flips Allow — this preserves the hook contract that fail-OPEN
// deployments observe only, never block.
func MergeATR(d *Decision, matches []atr.Match, failClosed bool) {
	if d == nil {
		return
	}
	if len(matches) == 0 {
		return
	}
	d.ATRMatches = matches
	if !failClosed {
		return
	}
	if !d.Allow {
		// Already denied by the reputation cascade. Keep that reason;
		// the ATR matches are visible in the log.
		return
	}
	if !atr.HasCriticalSeverity(matches) {
		return
	}
	for _, m := range matches {
		if m.Severity == atr.SeverityCritical {
			d.Allow = false
			// RuleID/Category/Description can come from a
			// custom (community-authored) ATR rule and end up in the
			// agent-visible deny reason; sanitize each so a rule cannot
			// inject newline-delimited instructions into agent feedback.
			d.Reason = fmt.Sprintf("ATR rule %s (%s) fired: %s",
				sanitizeField(m.RuleID), sanitizeField(string(m.Category)), sanitizeField(m.Description))
			return
		}
	}
}
