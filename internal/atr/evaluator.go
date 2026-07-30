package atr

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Match is one rule-content hit produced by Evaluate. Carries the
// minimum the decision-log audit trail and the deny gate both need:
// the rule identity (ID, category, severity), the regex description
// that fired, and a REDACTED digest of the matched substring so
// post-incident review can correlate hits without the raw content ever
// touching disk.
//
// PRIV-001: an ATR rule's matched substring is frequently the exact
// sensitive bytes the rule hunts for — a reverse-shell payload, a
// credential blob, a command line. Persisting that raw substring in the
// JSON Lines decision log would leak up to a few hundred bytes of
// secret/command content and directly contradicts the "raw content is
// never logged" disclosure. Instead we store MatchDigest (a SHA-256
// fingerprint of the matched bytes) and MatchLen (how many bytes
// matched): identical payloads produce identical digests so an operator
// can still correlate repeat hits across the log, but the content itself
// is not recoverable from the record.
type Match struct {
	RuleID      string   `json:"rule_id"`
	Category    Category `json:"category"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description,omitempty"`
	// MatchDigest is "sha256:<hex>" of the matched substring (empty when
	// nothing matched). Not the raw substring — see the type doc / PRIV-001.
	MatchDigest string `json:"match_digest,omitempty"`
	// MatchLen is the byte length of the matched substring, kept as a
	// coarse "how much fired" signal that carries no content.
	MatchLen int `json:"match_len,omitempty"`
}

// matchDigestHexLen bounds the hex digest we keep: 16 hex chars (8 bytes
// of SHA-256) is ample to distinguish distinct matches in a single
// install's log while keeping each record compact. It is deliberately a
// PREFIX of the full hash, not a truncated match — the full hash is one-
// way regardless of how many hex chars we keep.
const matchDigestHexLen = 16

// contentMaxBytes caps the content size that any one Evaluate call
// will scan. Vendored ATR rules (read-file/MCP pool) include
// ~525 regex across ~107 rules; iterating that many regex against
// the hookrunner's 256 KiB stdin cap would blow the 250ms hook
// budget on the read-file hook.
//
// 16 KiB is selected because every routine ATR target — skill
// manifests, package.json, .npmrc, Dockerfiles, lockfile headers —
// fits within it. Larger files (entire source trees, multi-megabyte
// JSON dumps) are scanned only in their first 16 KiB; the audit-log
// records a `content_truncated` annotation so the operator can see
// the cap fired. Catching attacks that occur ONLY after the 16 KiB
// mark of a tail-poisoned file is left to the shell-execution hook
// (where the eventual command runs) — same defense-in-depth
// reasoning as why we skip non-allowlisted read-file paths.
//
// Per-rule wall-clock deadlines remain enforced via evalDeadline
// below; the content cap reduces the routine cost, the deadline
// catches the pathological-regex outlier.
const contentMaxBytes = 16 << 10

// evalDeadline caps wall-clock time for a full Evaluate call.
// 60ms is well under Cursor's 250ms hook timeout and leaves
// headroom for Malanta's domain cascade in parallel; if a single
// pathological regex starts catastrophically backtracking, the
// evaluator returns whatever matches it had collected so far.
const evalDeadline = 60 * time.Millisecond

// Evaluate walks every rule and returns the set of matches against
// content. Rule order is preserved in the output, which makes the
// decision-log entries reproducible across runs even when callers
// don't sort.
//
// One Match is emitted per (rule, first-matching-pattern). For
// rules with `condition: any` the loop short-circuits at the first
// matching pattern (the typical case — 99%+ of ATR rules in the wild
// use the default any-condition). For `condition: all`, every pattern
// must match before the rule emits; the snippet comes from the LAST
// matching pattern so the operator sees the strongest signal first.
//
// Content is matched as-is; no normalization, no case folding, no
// length limits beyond what the caller already enforced upstream
// (hookrunner's 256 KiB stdin cap and readfile's 1 MiB content cap).
// ATR rules are RE2-compatible regex with their own (?i) inline
// flags where case-insensitivity is desired; the evaluator does not
// second-guess that decision.
//
// Returns nil (not an empty slice) when no rules match, so callers
// can use `if len(matches) > 0` as a cheap fast path without
// allocating.
func Evaluate(content string, rules []Rule) []Match {
	if content == "" || len(rules) == 0 {
		return nil
	}
	// Cap content size; see contentMaxBytes for the rationale.
	// Truncation happens silently here — the caller (hookrunner)
	// records the over-cap event via Diagnostics() if needed.
	if len(content) > contentMaxBytes {
		content = content[:contentMaxBytes]
	}
	deadline := time.Now().Add(evalDeadline)
	var out []Match
	for i := range rules {
		// Cheap deadline check between rules; mid-rule cancellation
		// would require running each regex on a goroutine with a
		// timer, which adds overhead that exceeds the saved time
		// for the typical fast-match case. Between-rule granularity
		// is sufficient: even the slowest rules in the bundle scan
		// the 16 KiB cap in <20ms, so the worst-case overrun beyond
		// the 60ms deadline is bounded at one rule.
		if time.Now().After(deadline) {
			break
		}
		r := &rules[i]
		m := evaluateRule(content, r)
		if m != nil {
			out = append(out, *m)
		}
	}
	return out
}

// evaluateRule applies one rule's pattern set against content and
// returns the produced Match (or nil if no match). Split out from
// Evaluate so a future per-rule benchmark or stub-substitute test
// can target a single rule's logic without iterating the whole
// bundle.
func evaluateRule(content string, r *Rule) *Match {
	if len(r.Patterns) == 0 {
		return nil
	}
	cond := r.Condition
	if cond == "" {
		cond = "any"
	}

	switch cond {
	case "all":
		// All patterns must match. We take the snippet from the
		// last matching pattern because it's the closest pattern
		// to the rule's strongest signal in ATR's wild-rule
		// authoring style (rules write the most specific check
		// last, after broad-shape preconditions).
		var lastSnippet, lastDesc string
		for _, p := range r.Patterns {
			s := p.Regex.FindString(content)
			if s == "" {
				return nil
			}
			lastSnippet = s
			lastDesc = p.Description
		}
		digest, n := redactMatch(lastSnippet)
		return &Match{
			RuleID:      r.ID,
			Category:    r.Category,
			Severity:    r.Severity,
			Description: lastDesc,
			MatchDigest: digest,
			MatchLen:    n,
		}

	default:
		// "any" (and any unknown condition; ATR's spec is permissive
		// about future operators, so we treat unknown as "any" to
		// avoid silently dropping rules that use an extension we
		// don't recognize yet). First matching pattern wins; later
		// patterns are not consulted, which is both a cheaper hot
		// path and consistent with how ATR's reference scanner
		// behaves.
		for _, p := range r.Patterns {
			s := p.Regex.FindString(content)
			if s == "" {
				continue
			}
			digest, n := redactMatch(s)
			return &Match{
				RuleID:      r.ID,
				Category:    r.Category,
				Severity:    r.Severity,
				Description: p.Description,
				MatchDigest: digest,
				MatchLen:    n,
			}
		}
	}
	return nil
}

// redactMatch turns a matched substring into a privacy-preserving
// descriptor (PRIV-001): a one-way SHA-256 fingerprint plus the byte
// length. The raw content is never returned. An empty match yields an
// empty digest and zero length. Identical inputs produce identical
// digests so an operator can still spot repeat hits across the decision
// log without the content being recoverable.
func redactMatch(s string) (digest string, n int) {
	if s == "" {
		return "", 0
	}
	sum := sha256.Sum256([]byte(s))
	full := hex.EncodeToString(sum[:])
	return "sha256:" + full[:matchDigestHexLen], len(s)
}

// HasCriticalSeverity reports whether any match in the slice has
// SeverityCritical. Used by the verdict layer to decide whether to
// flip an otherwise-allow decision to deny. Kept on this package
// (rather than verdict) so the severity threshold and the parsing
// of severity live next to each other; the verdict layer should
// never have to think about how "critical" is represented.
func HasCriticalSeverity(matches []Match) bool {
	for i := range matches {
		if matches[i].Severity == SeverityCritical {
			return true
		}
	}
	return false
}
