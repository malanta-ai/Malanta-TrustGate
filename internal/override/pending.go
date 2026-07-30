package override

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
)

const pendingFileName = "pending_asks.json"

// pendingTTL bounds how long a pending "warned" marker survives without
// being promoted. Config.ModeWarn's deny-once-then-allow-on-retry flow
// (see docs/admin.md) expects the retry to follow within a normal
// human (or agent) response time — seconds to a couple of minutes in
// the overwhelming common case. 5 minutes comfortably covers a person
// who steps away mid-decision, while ensuring a marker never lingers
// indefinitely if the retry never comes.
const pendingTTL = 5 * time.Minute

type pendingEntry struct {
	Domain  string `json:"domain"`
	Expires string `json:"expires"` // RFC3339
	// Created is when this host was FIRST warn-denied (RFC3339). It is
	// set once by AddPending and deliberately NOT bumped when an
	// already-present marker is refreshed, so the dwell clock
	// PromotePending enforces (minAckDelay) advances in real time no
	// matter how many times an agent hammers the same retry. An empty
	// Created (a marker written before this field existed) is treated as
	// "created long ago" — always past any dwell — so the gate can never
	// wedge a legitimate promotion on a pre-upgrade marker.
	Created string `json:"created,omitempty"`
}

func pendingPath(cacheDir string) string {
	return filepath.Join(cacheDir, pendingFileName)
}

func readPending(cacheDir string) []pendingEntry {
	data, err := os.ReadFile(pendingPath(cacheDir))
	if err != nil {
		return nil
	}
	var out []pendingEntry
	if err := json.Unmarshal(data, &out); err != nil {
		// Corrupt pending file: never let it become a hot-path failure.
		// Treating it as empty means, at worst, a warn deny that was
		// about to be promoted has to warn once more — never a
		// fail-closed surprise.
		return nil
	}
	return out
}

func writePending(cacheDir string, entries []pendingEntry) error {
	body, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("override: encode pending: %w", err)
	}
	return atomicWrite(pendingPath(cacheDir), body)
}

func prunePendingExpired(entries []pendingEntry) []pendingEntry {
	now := time.Now()
	out := entries[:0:0]
	for _, e := range entries {
		expires, err := time.Parse(time.RFC3339, e.Expires)
		if err != nil || now.After(expires) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// HasPending reports whether domain currently has an unexpired
// "warned" marker (i.e. this is a RETRY of an action that was already
// warn-denied once, not a first touch). Read-only — does not consume
// the marker; call PromotePending to consume it once the caller has
// decided to allow.
func HasPending(cacheDir, domain string) bool {
	if cacheDir == "" || domain == "" {
		return false
	}
	domainLower := strings.ToLower(domain)
	for _, e := range prunePendingExpired(readPending(cacheDir)) {
		if strings.ToLower(e.Domain) == domainLower {
			return true
		}
	}
	return false
}

// AddPending records that domain has just been warn-denied once (see
// Config.ModeWarn / finalizeDecision), so that if the SAME action is
// retried, PromotePending finds this marker and allows it instead of
// warning again indefinitely.
func AddPending(cacheDir, domain string) error {
	if cacheDir == "" || domain == "" {
		return nil
	}
	entries := prunePendingExpired(readPending(cacheDir))
	domainLower := strings.ToLower(domain)
	now := time.Now()
	expires := now.Add(pendingTTL).Format(time.RFC3339)
	replaced := false
	for i, e := range entries {
		if strings.ToLower(e.Domain) == domainLower {
			// Refresh the expiry window but PRESERVE Created: repeated
			// re-warns of the same host (e.g. an agent auto-retrying
			// faster than WarnAckMinSeconds) must not keep resetting the
			// dwell clock, or the dwell gate could never be crossed. If a
			// pre-upgrade marker had no Created, stamp it now so the clock
			// starts from this touch rather than staying empty forever.
			entries[i].Expires = expires
			if entries[i].Created == "" {
				entries[i].Created = now.Format(time.RFC3339)
			}
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, pendingEntry{Domain: domain, Expires: expires, Created: now.Format(time.RFC3339)})
	}
	return writePending(cacheDir, entries)
}

// PromotePending looks for an unexpired "warned" marker for host; if
// found AND at least minAckDelay has elapsed since the marker was
// first created, it consumes the marker and grants a real override
// valid for windowMin minutes (source "warn"), returning true. The
// grant's Domain is host itself when scope is Config.OverrideScopeDomain
// (the common case — only this host stays quiet), or "*" when scope is
// Config.OverrideScopeTime (a blanket grant, matching the CLI
// override's own scope semantics — see internal/override's package
// doc). If no matching, unexpired marker exists (this wasn't a retry
// of a previously warn-denied action, or the marker already expired),
// it returns false and grants nothing — reaching this call is never by
// itself sufficient to grant anything, only doing so for a host that
// was actually warn-denied moments before.
//
// minAckDelay is the dwell gate (Config.WarnAckMinSeconds): a retry
// that arrives before minAckDelay has elapsed since the marker's
// Created time returns (false, nil) WITHOUT consuming the marker, so a
// later (human-paced) retry can still promote it. This blunts the agent
// auto-retrying the audited-retry message on the user's behalf within
// milliseconds. minAckDelay <= 0 disables the gate (any retry promotes,
// the original behavior). A marker with no/unparseable Created is
// treated as past any dwell (never wedges a legitimate promotion).
//
// windowMin <= 0 falls back to a safe default (matches the CLI's own
// --minutes default) rather than granting a zero or negative-duration
// window.
func PromotePending(cacheDir, host, scope string, windowMin int, minAckDelay time.Duration) (bool, error) {
	if cacheDir == "" || host == "" {
		return false, nil
	}
	entries := prunePendingExpired(readPending(cacheDir))
	hostLower := strings.ToLower(strings.TrimSpace(host))
	idx := -1
	for i, e := range entries {
		if strings.ToLower(e.Domain) == hostLower {
			idx = i
			break
		}
	}
	if idx == -1 {
		return false, nil
	}
	// Dwell gate: if the marker is younger than minAckDelay, this retry
	// arrived too soon to count as a human acknowledgment. Leave the
	// marker in place (do not consume, do not grant) so the caller
	// re-warns and a later retry can still promote.
	if minAckDelay > 0 {
		if created, err := time.Parse(time.RFC3339, entries[idx].Created); err == nil {
			if time.Since(created) < minAckDelay {
				return false, nil
			}
		}
	}
	remaining := append(entries[:idx:idx], entries[idx+1:]...)
	if err := writePending(cacheDir, remaining); err != nil {
		return false, err
	}
	if windowMin <= 0 {
		windowMin = 15
	}
	grantDomain := host
	if scope == config.OverrideScopeTime {
		grantDomain = "*"
	}
	until := time.Now().Add(time.Duration(windowMin) * time.Minute)
	if err := Grant(cacheDir, grantDomain, until, "acknowledged warning; re-run to proceed", "warn"); err != nil {
		return false, err
	}
	return true, nil
}
