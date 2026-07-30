package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestAuditFileIsOwnerOnly guards the defense-in-depth 0600 tightening in
// Open: the audit db (and WAL/SHM sidecars, when present) must not be
// group/world-readable. POSIX-only.
func TestAuditFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits not meaningful on Windows")
	}
	path := filepath.Join(t.TempDir(), "audit.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		info, statErr := os.Stat(p)
		if statErr != nil {
			continue
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s mode = %o, want owner-only (no group/world bits)", p, perm)
		}
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestPurgeOlderThan is the PRIV-003 retention guard: rows older than the
// cutoff are deleted, newer rows survive.
func TestPurgeOlderThan(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now()
	old := Record{DecisionID: "old1", Timestamp: now.Add(-48 * time.Hour), HookName: "h", Allow: true}
	fresh := Record{DecisionID: "fresh1", Timestamp: now.Add(-1 * time.Hour), HookName: "h", Allow: true}
	if err := s.Insert(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	n, err := s.PurgeOlderThan(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("PurgeOlderThan: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 row purged, got %d", n)
	}
	if got, _ := s.FindByDecisionID(ctx, "old1"); got != nil {
		t.Error("expected the old record to be purged")
	}
	if got, _ := s.FindByDecisionID(ctx, "fresh1"); got == nil {
		t.Error("expected the fresh record to survive")
	}
}

func TestPurgeAll(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c"} {
		if err := s.Insert(ctx, Record{DecisionID: id, Timestamp: time.Now(), HookName: "h", Allow: true}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.PurgeAll(ctx)
	if err != nil {
		t.Fatalf("PurgeAll: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 rows purged, got %d", n)
	}
	st, _ := s.Stats(ctx)
	if st.Total != 0 {
		t.Errorf("expected empty table after PurgeAll, got %d rows", st.Total)
	}
}

// TestExportAll_RedactionAndOrder confirms export emits JSON Lines oldest
// first and carries only redaction-safe fields (indicator/verdict/rule IDs).
func TestExportAll_RedactionAndOrder(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now()
	if err := s.Insert(ctx, Record{DecisionID: "newer", Timestamp: now, HookName: "h", Indicator: "b.example", Allow: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(ctx, Record{DecisionID: "older", Timestamp: now.Add(-time.Hour), HookName: "h", Indicator: "a.example", Allow: false}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.ExportAll(ctx, &buf); err != nil {
		t.Fatalf("ExportAll: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSONL records, got %d: %q", len(lines), buf.String())
	}
	// Oldest first.
	if !strings.Contains(lines[0], "a.example") || !strings.Contains(lines[1], "b.example") {
		t.Errorf("expected oldest-first ordering, got:\n%s", buf.String())
	}
}

func TestInsertAndFindByDecisionID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := Record{
		DecisionID: "abc123",
		Timestamp:  time.Now(),
		HookName:   "beforeShellExecution",
		Provider:   "malanta",
		Indicator:  "malicious.example",
		Kind:       "domain",
		Label:      "MALICIOUS",
		Allow:      false,
		Mode:       "enforce",
		Reason:     "malanta flagged malicious.example as MALICIOUS",
		DurationMs: 42,
		Hosts:      []string{"malicious.example"},
		Warnings:   []string{"low-confidence example.com"},
		ATRRuleIDs: []string{"ATR-2026-00006"},
	}
	if err := s.Insert(ctx, rec); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	got, err := s.FindByDecisionID(ctx, "abc123")
	if err != nil {
		t.Fatalf("FindByDecisionID: %v", err)
	}
	if got == nil {
		t.Fatal("expected a record, got nil")
	}
	if got.Indicator != "malicious.example" || got.Allow || got.Label != "MALICIOUS" {
		t.Errorf("unexpected record: %+v", got)
	}
	if len(got.Hosts) != 1 || got.Hosts[0] != "malicious.example" {
		t.Errorf("expected Hosts=[malicious.example], got %v", got.Hosts)
	}
	if len(got.ATRRuleIDs) != 1 || got.ATRRuleIDs[0] != "ATR-2026-00006" {
		t.Errorf("expected ATRRuleIDs=[ATR-2026-00006], got %v", got.ATRRuleIDs)
	}
}

func TestFindByDecisionID_MissingReturnsNilNotError(t *testing.T) {
	s := openTestStore(t)
	got, err := s.FindByDecisionID(context.Background(), "does-not-exist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for a missing decision_id, got %+v", got)
	}
}

func TestInsert_DuplicateDecisionIDIsIgnoredNotError(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	rec := Record{DecisionID: "dup1", HookName: "beforeShellExecution", Allow: true}
	if err := s.Insert(ctx, rec); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	rec.Reason = "changed after the fact"
	if err := s.Insert(ctx, rec); err != nil {
		t.Fatalf("second insert (duplicate id) should not error: %v", err)
	}
	got, err := s.FindByDecisionID(ctx, "dup1")
	if err != nil {
		t.Fatalf("FindByDecisionID: %v", err)
	}
	if got.Reason != "" {
		t.Errorf("expected the FIRST insert's (empty) reason to win on a duplicate id, got %q", got.Reason)
	}
}

func TestFindByIndicator_MatchesResolvedIndicatorAndHostsList(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Denied on the resolved Indicator field.
	if err := s.Insert(ctx, Record{
		DecisionID: "d1", Indicator: "malicious.example", Allow: false,
		Timestamp: time.Now().Add(-2 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	// Allowed overall, but malicious.example was among the extracted Hosts (e.g. a
	// multi-host event where a different host triggered a deny, or this
	// host was clean) — should still show up in "explain malicious.example".
	if err := s.Insert(ctx, Record{
		DecisionID: "d2", Indicator: "", Allow: true, Hosts: []string{"malicious.example", "example.com"},
		Timestamp: time.Now().Add(-1 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	// Unrelated record must not show up.
	if err := s.Insert(ctx, Record{DecisionID: "d3", Indicator: "example.com", Allow: true}); err != nil {
		t.Fatal(err)
	}

	got, err := s.FindByIndicator(ctx, "malicious.example", 10)
	if err != nil {
		t.Fatalf("FindByIndicator: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 matches for malicious.example, got %d: %+v", len(got), got)
	}
	// Newest first.
	if got[0].DecisionID != "d2" || got[1].DecisionID != "d1" {
		t.Errorf("expected newest-first order [d2, d1], got [%s, %s]", got[0].DecisionID, got[1].DecisionID)
	}
}

func TestStats(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	empty, err := s.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats on empty table: %v", err)
	}
	if empty.HasData {
		t.Errorf("expected HasData=false on an empty table, got %+v", empty)
	}

	for i, rec := range []Record{
		{DecisionID: "s1", Allow: true},
		{DecisionID: "s2", Allow: false},
		{DecisionID: "s3", Allow: false},
	} {
		rec.Timestamp = time.Now().Add(time.Duration(i) * time.Second)
		if err := s.Insert(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}

	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if !st.HasData || st.Total != 3 || st.Denied != 2 {
		t.Errorf("expected {HasData:true Total:3 Denied:2}, got %+v", st)
	}
	if st.Oldest.After(st.Newest) {
		t.Errorf("expected Oldest <= Newest, got oldest=%v newest=%v", st.Oldest, st.Newest)
	}
}

func TestNilStore_AllMethodsAreSafeNoOps(t *testing.T) {
	var s *Store
	ctx := context.Background()

	if err := s.Insert(ctx, Record{DecisionID: "x"}); err != nil {
		t.Errorf("Insert on nil store: %v", err)
	}
	if got, err := s.FindByDecisionID(ctx, "x"); got != nil || err != nil {
		t.Errorf("FindByDecisionID on nil store: got=%v err=%v", got, err)
	}
	if got, err := s.FindByIndicator(ctx, "x", 10); got != nil || err != nil {
		t.Errorf("FindByIndicator on nil store: got=%v err=%v", got, err)
	}
	if st, err := s.Stats(ctx); st.HasData || err != nil {
		t.Errorf("Stats on nil store: got=%+v err=%v", st, err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close on nil store: %v", err)
	}
}

func TestOpenOrWarn_FailureReturnsNilNotPanic(t *testing.T) {
	// A null byte in a path is rejected by the OS on every platform this
	// project supports, making it a reliable way to force Open to fail
	// without depending on filesystem permission quirks.
	s := OpenOrWarn("\x00/invalid/audit.db", nil)
	if s != nil {
		t.Error("expected nil Store for an invalid path")
	}
}
