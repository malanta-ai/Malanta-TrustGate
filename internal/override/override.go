// Package override implements TrustGate's self-service, admin-gated
// bypass for a denied domain-reputation verdict (Config.AllowUserOverride
// — see docs/admin.md). It is the single shared implementation behind:
//
//   - `trustgate override` (cmd/trustgate/override.go), which writes a
//     grant directly — the CLI break-glass for admins running "enforce"
//     mode.
//   - internal/verdict's finalizeDecision, which reads grants to decide
//     whether a deny should be flipped to allow, AND which drives
//     Config.ModeWarn's deny-once-then-allow-on-retry flow (see
//     resolveWarn in internal/verdict/verdict.go and pending.go's doc
//     comment): a flagged action denies once with an audited-retry
//     message, and retrying the identical action (which re-fires the
//     same before-hook) is acknowledged and promoted into a real grant.
//
// Two on-disk files live under Config.CacheDir, both admin/user-owned
// (mode 0600, same posture as the rest of TrustGate's local state):
//
//   - override.json:      durable grants (see Entry).
//   - pending_asks.json:   short-TTL markers bridging ModeWarn's first
//     "warned" touch of a host to the retry that acknowledges it (see
//     pending.go).
//
// Every write is atomic (temp file + rename) so a hook process reading
// concurrently with a CLI write, or two hook processes racing, never
// observes a partially-written file. This is a JSON-file store, not
// SQLite — it matches the pre-existing override.json approach and the
// low write-concurrency of "a person occasionally runs `trustgate
// override`, or a hook occasionally resolves a ModeWarn retry." A move
// to SQLite (for stronger concurrency guarantees under heavier write
// load) is a noted hardening follow-up, not required for this feature.
package override

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const overrideFileName = "override.json"

// Entry is one durable override grant. Domain is either an exact,
// case-insensitive host (e.g. "malicious.example", matching Config.OverrideScope
// == "domain") or the literal "*" (a blanket grant, matching
// Config.OverrideScope == "time" — every denied indicator is allowed
// for the window, regardless of which host triggered the deny). Which
// shape gets written is a CLI/write-time decision (see
// cmd/trustgate/override.go); ActiveFor's matching logic is agnostic to
// the admin's configured scope and simply honors whatever is on disk —
// this means flipping TRUSTGATE_OVERRIDE_SCOPE never invalidates an
// override a user already holds.
type Entry struct {
	Domain string `json:"domain"`
	Until  string `json:"until"` // RFC3339
	Reason string `json:"reason"`
	// Source records how the entry was created: "cli" (trustgate
	// override) or "prompt" (approved via Cursor's native ask dialog,
	// promoted by an after-hook). Informational only — never gates
	// matching.
	Source string `json:"source,omitempty"`
}

// fileShape is the current on-disk shape of override.json.
type fileShape struct {
	Entries []Entry `json:"entries"`
}

// legacyShape is the pre-override-package shape written directly by an
// earlier `trustgate override` (a single blanket grant, no domain
// concept). Reading it as a Domain: "*" Entry keeps every override file
// written before this package existed — and the existing test fixtures
// that construct it by hand — working unchanged.
type legacyShape struct {
	Until  string `json:"until"`
	Reason string `json:"reason"`
}

func overridePath(cacheDir string) string {
	return filepath.Join(cacheDir, overrideFileName)
}

// readEntries loads override.json, pruning nothing (callers prune with
// pruneExpired where it matters). A missing file is not an error (no
// overrides exist yet); a corrupt file is treated the same way — an
// override store must never be a reason to fail closed on its own, so a
// read/parse error degrades to "no active overrides" rather than
// propagating.
func readEntries(cacheDir string) []Entry {
	data, err := os.ReadFile(overridePath(cacheDir))
	if err != nil {
		return nil
	}
	var fs fileShape
	if err := json.Unmarshal(data, &fs); err == nil && len(fs.Entries) > 0 {
		return fs.Entries
	}
	var legacy legacyShape
	if err := json.Unmarshal(data, &legacy); err == nil && legacy.Until != "" {
		return []Entry{{Domain: "*", Until: legacy.Until, Reason: legacy.Reason, Source: "cli"}}
	}
	return nil
}

func writeEntries(cacheDir string, entries []Entry) error {
	body, err := json.MarshalIndent(fileShape{Entries: entries}, "", "  ")
	if err != nil {
		return fmt.Errorf("override: encode: %w", err)
	}
	return atomicWrite(overridePath(cacheDir), body)
}

// pruneExpired drops any entry whose Until has passed or fails to
// parse — an unparseable timestamp is treated as already-expired
// (fail-closed posture: a corrupt grant should never be treated as
// perpetually valid).
func pruneExpired(entries []Entry) []Entry {
	now := time.Now()
	out := entries[:0:0]
	for _, e := range entries {
		until, err := time.Parse(time.RFC3339, e.Until)
		if err != nil || now.After(until) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// ActiveFor reports whether host currently has an unexpired grant —
// either an exact (case-insensitive) domain match or a blanket "*"
// entry — and, if so, a human-readable reason string suitable for a
// decision-log warning. Only ever meaningful to call once the caller
// has confirmed the admin enabled Config.AllowUserOverride; ActiveFor
// itself has no opinion on that gate (it just answers "is there a
// grant on disk," the same separation of concerns the original
// checkUserOverride had).
func ActiveFor(cacheDir, host string) (bool, string) {
	if cacheDir == "" {
		return false, ""
	}
	hostLower := strings.ToLower(strings.TrimSpace(host))
	for _, e := range pruneExpired(readEntries(cacheDir)) {
		if e.Domain != "*" && strings.ToLower(strings.TrimSpace(e.Domain)) != hostLower {
			continue
		}
		until, _ := time.Parse(time.RFC3339, e.Until) // already validated by pruneExpired
		reason := e.Reason
		if reason == "" {
			reason = "(no reason recorded)"
		}
		return true, fmt.Sprintf("%s (expires %s)", reason, until.Format(time.RFC3339))
	}
	return false, ""
}

// Grant records (or replaces, if one already exists for the same
// domain) an override for domain until the given time. domain == ""
// is normalized to "*" (blanket). Expired entries are pruned as a
// side effect so the file doesn't grow unbounded across a long-lived
// install.
func Grant(cacheDir, domain string, until time.Time, reason, source string) error {
	if cacheDir == "" {
		return fmt.Errorf("override: cache dir is empty")
	}
	if domain == "" {
		domain = "*"
	}
	entries := pruneExpired(readEntries(cacheDir))
	domainLower := strings.ToLower(domain)
	entry := Entry{Domain: domain, Until: until.Format(time.RFC3339), Reason: reason, Source: source}
	replaced := false
	for i, e := range entries {
		if strings.ToLower(e.Domain) == domainLower {
			entries[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, entry)
	}
	return writeEntries(cacheDir, entries)
}

// Clear removes the grant for domain (case-insensitive). A domain of
// "*" clears only the blanket entry, not per-host entries — use
// ClearAll to remove everything. Clearing a domain with no matching
// entry is not an error (idempotent, matching the pre-existing
// --clear-on-missing-file behavior).
func Clear(cacheDir, domain string) error {
	if cacheDir == "" {
		return nil
	}
	entries := readEntries(cacheDir)
	if len(entries) == 0 {
		return nil
	}
	domainLower := strings.ToLower(domain)
	out := entries[:0:0]
	for _, e := range entries {
		if strings.ToLower(e.Domain) != domainLower {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return ClearAll(cacheDir)
	}
	return writeEntries(cacheDir, out)
}

// ClearAll removes every override grant (the whole file). Not an error
// if no file exists yet.
func ClearAll(cacheDir string) error {
	if cacheDir == "" {
		return nil
	}
	err := os.Remove(overridePath(cacheDir))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("override: remove %s: %w", overridePath(cacheDir), err)
	}
	return nil
}

// List returns every currently-unexpired grant, for `trustgate doctor`
// / admin visibility. Never errors — an unreadable store just reports
// no entries, matching ActiveFor's fail-safe posture.
func List(cacheDir string) []Entry {
	if cacheDir == "" {
		return nil
	}
	return pruneExpired(readEntries(cacheDir))
}

// atomicWrite writes body to path via a temp file + rename in the same
// directory, so a concurrent reader (a hook process) never observes a
// partially-written file, and mode 0600 is applied before the file is
// visible at its final name.
func atomicWrite(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("override: create dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".override-tmp-*")
	if err != nil {
		return fmt.Errorf("override: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("override: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("override: close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("override: chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("override: rename into place: %w", err)
	}
	return nil
}
