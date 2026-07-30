package override

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
)

func TestActiveFor_NoFileMeansNoOverride(t *testing.T) {
	dir := t.TempDir()
	if ok, _ := ActiveFor(dir, "malicious.example"); ok {
		t.Error("expected no active override when no file exists")
	}
}

func TestGrant_ExactDomainOnlyMatchesThatHost(t *testing.T) {
	dir := t.TempDir()
	if err := Grant(dir, "malicious.example", time.Now().Add(10*time.Minute), "investigating", "cli"); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if ok, reason := ActiveFor(dir, "malicious.example"); !ok {
		t.Error("expected malicious.example to be active")
	} else if !containsAll(reason, "investigating", "expires") {
		t.Errorf("unexpected reason: %q", reason)
	}
	if ok, _ := ActiveFor(dir, "other.example"); ok {
		t.Error("expected a per-domain grant to NOT match an unrelated host")
	}
}

func TestGrant_ExactDomainMatchIsCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	if err := Grant(dir, "Malicious.Example", time.Now().Add(10*time.Minute), "x", "cli"); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if ok, _ := ActiveFor(dir, "malicious.example"); !ok {
		t.Error("expected case-insensitive match")
	}
}

func TestGrant_BlanketStarMatchesAnyHost(t *testing.T) {
	dir := t.TempDir()
	if err := Grant(dir, "*", time.Now().Add(10*time.Minute), "blanket window", "cli"); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if ok, _ := ActiveFor(dir, "malicious.example"); !ok {
		t.Error("expected blanket grant to match malicious.example")
	}
	if ok, _ := ActiveFor(dir, "anything.example"); !ok {
		t.Error("expected blanket grant to match any host")
	}
}

func TestGrant_EmptyDomainNormalizesToBlanket(t *testing.T) {
	dir := t.TempDir()
	if err := Grant(dir, "", time.Now().Add(10*time.Minute), "x", "cli"); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if ok, _ := ActiveFor(dir, "anything.example"); !ok {
		t.Error("expected empty domain to normalize to a blanket grant")
	}
}

func TestGrant_ReplacesExistingEntryForSameDomain(t *testing.T) {
	dir := t.TempDir()
	if err := Grant(dir, "malicious.example", time.Now().Add(5*time.Minute), "first", "cli"); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if err := Grant(dir, "malicious.example", time.Now().Add(20*time.Minute), "second", "cli"); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	entries := List(dir)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one entry after replace, got %d: %+v", len(entries), entries)
	}
	if entries[0].Reason != "second" {
		t.Errorf("expected the replaced entry to carry the newer reason, got %q", entries[0].Reason)
	}
}

func TestActiveFor_ExpiredGrantIsNotHonored(t *testing.T) {
	dir := t.TempDir()
	if err := Grant(dir, "malicious.example", time.Now().Add(-1*time.Minute), "expired", "cli"); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if ok, _ := ActiveFor(dir, "malicious.example"); ok {
		t.Error("expected an expired grant to not be honored")
	}
}

func TestActiveFor_LegacyBlanketFileShapeIsHonored(t *testing.T) {
	dir := t.TempDir()
	body, err := json.Marshal(struct {
		Until  string `json:"until"`
		Reason string `json:"reason"`
	}{Until: time.Now().Add(10 * time.Minute).Format(time.RFC3339), Reason: "legacy override"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, overrideFileName), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, reason := ActiveFor(dir, "any.host"); !ok {
		t.Error("expected the legacy {until,reason} shape to be honored as a blanket grant")
	} else if !containsAll(reason, "legacy override") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestActiveFor_LegacyExpiredFileShapeIsNotHonored(t *testing.T) {
	dir := t.TempDir()
	body, err := json.Marshal(struct {
		Until  string `json:"until"`
		Reason string `json:"reason"`
	}{Until: time.Now().Add(-1 * time.Minute).Format(time.RFC3339), Reason: "expired legacy"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, overrideFileName), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := ActiveFor(dir, "any.host"); ok {
		t.Error("expected an expired legacy grant to not be honored")
	}
}

func TestClear_RemovesOnlyMatchingDomain(t *testing.T) {
	dir := t.TempDir()
	if err := Grant(dir, "malicious.example", time.Now().Add(10*time.Minute), "a", "cli"); err != nil {
		t.Fatal(err)
	}
	if err := Grant(dir, "other.example", time.Now().Add(10*time.Minute), "b", "cli"); err != nil {
		t.Fatal(err)
	}
	if err := Clear(dir, "malicious.example"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if ok, _ := ActiveFor(dir, "malicious.example"); ok {
		t.Error("expected malicious.example override to be cleared")
	}
	if ok, _ := ActiveFor(dir, "other.example"); !ok {
		t.Error("expected other.example override to survive clearing a different domain")
	}
}

func TestClear_NonexistentEntryIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	if err := Clear(dir, "never-granted.example"); err != nil {
		t.Errorf("expected clearing a nonexistent entry to be a no-op, got: %v", err)
	}
}

func TestClearAll_RemovesEverything(t *testing.T) {
	dir := t.TempDir()
	if err := Grant(dir, "malicious.example", time.Now().Add(10*time.Minute), "a", "cli"); err != nil {
		t.Fatal(err)
	}
	if err := Grant(dir, "other.example", time.Now().Add(10*time.Minute), "b", "cli"); err != nil {
		t.Fatal(err)
	}
	if err := ClearAll(dir); err != nil {
		t.Fatalf("ClearAll: %v", err)
	}
	if entries := List(dir); len(entries) != 0 {
		t.Errorf("expected no entries after ClearAll, got %+v", entries)
	}
	if _, err := os.Stat(filepath.Join(dir, overrideFileName)); !os.IsNotExist(err) {
		t.Errorf("expected the override file itself to be removed, stat returned: %v", err)
	}
}

func TestClearAll_OnMissingFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	if err := ClearAll(dir); err != nil {
		t.Errorf("expected ClearAll on a nonexistent file to be a no-op, got: %v", err)
	}
}

func TestList_OmitsExpiredEntries(t *testing.T) {
	dir := t.TempDir()
	if err := Grant(dir, "active.example", time.Now().Add(10*time.Minute), "a", "cli"); err != nil {
		t.Fatal(err)
	}
	if err := Grant(dir, "expired.example", time.Now().Add(-10*time.Minute), "b", "cli"); err != nil {
		t.Fatal(err)
	}
	entries := List(dir)
	if len(entries) != 1 || entries[0].Domain != "active.example" {
		t.Errorf("expected only the active entry to be listed, got %+v", entries)
	}
}

func TestAddPending_ThenPromotePending_GrantsOverride(t *testing.T) {
	dir := t.TempDir()
	if err := AddPending(dir, "malicious.example"); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	promoted, err := PromotePending(dir, "malicious.example", config.OverrideScopeDomain, 15, 0)
	if err != nil {
		t.Fatalf("PromotePending: %v", err)
	}
	if !promoted {
		t.Fatal("expected PromotePending to report a promotion")
	}
	if ok, reason := ActiveFor(dir, "malicious.example"); !ok {
		t.Error("expected malicious.example to now have an active override")
	} else if !containsAll(reason, "warn") {
		t.Errorf("expected the promoted grant's reason to mention the warn origin, got %q", reason)
	}
}

func TestPromotePending_DomainScope_GrantsOnlyThatHost(t *testing.T) {
	dir := t.TempDir()
	if err := AddPending(dir, "malicious.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := PromotePending(dir, "malicious.example", config.OverrideScopeDomain, 15, 0); err != nil {
		t.Fatal(err)
	}
	if ok, _ := ActiveFor(dir, "other.example"); ok {
		t.Error("expected a domain-scoped promotion to NOT grant an unrelated host")
	}
}

func TestPromotePending_TimeScope_GrantsBlanket(t *testing.T) {
	dir := t.TempDir()
	if err := AddPending(dir, "malicious.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := PromotePending(dir, "malicious.example", config.OverrideScopeTime, 15, 0); err != nil {
		t.Fatal(err)
	}
	if ok, _ := ActiveFor(dir, "other.example"); !ok {
		t.Error("expected a time-scoped promotion to grant a blanket (*) override covering any host")
	}
	entries := List(dir)
	if len(entries) != 1 || entries[0].Domain != "*" {
		t.Errorf("expected a single blanket (*) entry, got %+v", entries)
	}
}

func TestPromotePending_WithoutAPendingMarkerGrantsNothing(t *testing.T) {
	dir := t.TempDir()
	promoted, err := PromotePending(dir, "malicious.example", config.OverrideScopeDomain, 15, 0)
	if err != nil {
		t.Fatalf("PromotePending: %v", err)
	}
	if promoted {
		t.Error("expected no promotion when nothing was pending")
	}
	if ok, _ := ActiveFor(dir, "malicious.example"); ok {
		t.Error("expected no override to be granted when nothing was pending")
	}
}

func TestPromotePending_ConsumesTheMarker(t *testing.T) {
	dir := t.TempDir()
	if err := AddPending(dir, "malicious.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := PromotePending(dir, "malicious.example", config.OverrideScopeDomain, 15, 0); err != nil {
		t.Fatal(err)
	}
	// A second promote attempt for the same host must find nothing
	// pending (the marker was consumed by the first call), even though
	// an active override now exists from the first promotion.
	promoted, err := PromotePending(dir, "malicious.example", config.OverrideScopeDomain, 15, 0)
	if err != nil {
		t.Fatalf("PromotePending (second call): %v", err)
	}
	if promoted {
		t.Error("expected the pending marker to be consumed after the first promotion")
	}
}

func TestPromotePending_DoesNotMatchADifferentHost(t *testing.T) {
	dir := t.TempDir()
	if err := AddPending(dir, "malicious.example"); err != nil {
		t.Fatal(err)
	}
	promoted, err := PromotePending(dir, "other.example", config.OverrideScopeDomain, 15, 0)
	if err != nil {
		t.Fatal(err)
	}
	if promoted {
		t.Error("expected PromotePending to not match an unrelated host's pending marker")
	}
	// The original marker should still be there for the right host.
	promoted, err = PromotePending(dir, "malicious.example", config.OverrideScopeDomain, 15, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !promoted {
		t.Error("expected the original host's pending marker to survive an unrelated promote attempt")
	}
}

func TestPromotePending_NonPositiveWindowFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	if err := AddPending(dir, "malicious.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := PromotePending(dir, "malicious.example", config.OverrideScopeDomain, 0, 0); err != nil {
		t.Fatal(err)
	}
	entries := List(dir)
	if len(entries) != 1 {
		t.Fatalf("expected one granted entry, got %+v", entries)
	}
	until, err := time.Parse(time.RFC3339, entries[0].Until)
	if err != nil {
		t.Fatal(err)
	}
	if until.Before(time.Now().Add(10 * time.Minute)) {
		t.Errorf("expected a non-positive window to fall back to a sane default (~15min), got until=%v", until)
	}
}

func TestPromotePending_WithinDwellDoesNotPromoteOrConsume(t *testing.T) {
	dir := t.TempDir()
	if err := AddPending(dir, "malicious.example"); err != nil {
		t.Fatal(err)
	}
	// A retry arriving immediately (well within a 1h dwell) must NOT
	// promote, and must NOT consume the marker.
	promoted, err := PromotePending(dir, "malicious.example", config.OverrideScopeDomain, 15, time.Hour)
	if err != nil {
		t.Fatalf("PromotePending: %v", err)
	}
	if promoted {
		t.Error("expected an inside-dwell retry to NOT promote")
	}
	if ok, _ := ActiveFor(dir, "malicious.example"); ok {
		t.Error("expected no grant to be written for an inside-dwell retry")
	}
	if !HasPending(dir, "malicious.example") {
		t.Error("expected the pending marker to survive an inside-dwell retry (not consumed)")
	}
	// The same marker, once the dwell is disabled (0), promotes — proving
	// the marker was preserved and is still usable.
	promoted, err = PromotePending(dir, "malicious.example", config.OverrideScopeDomain, 15, 0)
	if err != nil {
		t.Fatalf("PromotePending (dwell disabled): %v", err)
	}
	if !promoted {
		t.Error("expected the preserved marker to promote once the dwell gate is disabled")
	}
}

func TestPromotePending_AfterDwellPromotes(t *testing.T) {
	dir := t.TempDir()
	// Write a marker whose Created is safely in the past, so a nonzero
	// dwell has already elapsed without the test having to sleep.
	past := time.Now().Add(-30 * time.Second)
	if err := writePending(dir, []pendingEntry{{
		Domain:  "malicious.example",
		Expires: time.Now().Add(pendingTTL).Format(time.RFC3339),
		Created: past.Format(time.RFC3339),
	}}); err != nil {
		t.Fatal(err)
	}
	promoted, err := PromotePending(dir, "malicious.example", config.OverrideScopeDomain, 15, 5*time.Second)
	if err != nil {
		t.Fatalf("PromotePending: %v", err)
	}
	if !promoted {
		t.Error("expected a retry after the dwell has elapsed to promote")
	}
	if ok, _ := ActiveFor(dir, "malicious.example"); !ok {
		t.Error("expected an active grant after a past-dwell promotion")
	}
}

func TestAddPending_PreservesCreatedOnRefresh(t *testing.T) {
	dir := t.TempDir()
	// Seed a marker with a known, old Created timestamp.
	original := time.Now().Add(-30 * time.Second).Format(time.RFC3339)
	if err := writePending(dir, []pendingEntry{{
		Domain:  "malicious.example",
		Expires: time.Now().Add(time.Minute).Format(time.RFC3339),
		Created: original,
	}}); err != nil {
		t.Fatal(err)
	}
	// A re-warn of the same host must refresh Expires but keep Created,
	// so an agent hammering retries can't keep resetting the dwell clock.
	if err := AddPending(dir, "malicious.example"); err != nil {
		t.Fatal(err)
	}
	entries := readPending(dir)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one marker, got %+v", entries)
	}
	if entries[0].Created != original {
		t.Errorf("expected Created to be preserved across refresh; was %q, now %q", original, entries[0].Created)
	}
}

func TestAddPending_StampsCreatedOnNewMarker(t *testing.T) {
	dir := t.TempDir()
	if err := AddPending(dir, "malicious.example"); err != nil {
		t.Fatal(err)
	}
	entries := readPending(dir)
	if len(entries) != 1 {
		t.Fatalf("expected one marker, got %+v", entries)
	}
	if entries[0].Created == "" {
		t.Error("expected a new pending marker to carry a Created timestamp")
	}
	if _, err := time.Parse(time.RFC3339, entries[0].Created); err != nil {
		t.Errorf("expected Created to be RFC3339, got %q (%v)", entries[0].Created, err)
	}
}

func TestHasPending_ReflectsMarkerPresence(t *testing.T) {
	dir := t.TempDir()
	if HasPending(dir, "malicious.example") {
		t.Error("expected no pending marker before AddPending")
	}
	if err := AddPending(dir, "malicious.example"); err != nil {
		t.Fatal(err)
	}
	if !HasPending(dir, "malicious.example") {
		t.Error("expected a pending marker after AddPending")
	}
	if HasPending(dir, "other.example") {
		t.Error("expected HasPending to not match an unrelated host")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !containsSub(s, sub) {
			return false
		}
	}
	return true
}

func containsSub(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOfSub(s, sub) >= 0)
}

func indexOfSub(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
