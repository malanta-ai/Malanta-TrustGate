package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/audit"
)

// TestRunPurge_TimeBasedRemovesOldAuditAndLog is the PRIV-003 CLI guard: a
// time-based purge deletes audit rows and decision-log lines older than the
// window while keeping newer ones.
func TestRunPurge_TimeBasedRemovesOldAuditAndLog(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	// Ensure no ambient retention env leaks in.
	t.Setenv("TRUSTGATE_RETENTION_DAYS", "")

	cacheDir := filepath.Join(home, ".cache", "trustgate")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Seed the audit table with one old and one fresh row.
	store, err := audit.Open(filepath.Join(cacheDir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_ = store.Insert(context.Background(), audit.Record{DecisionID: "old", Timestamp: now.Add(-72 * time.Hour), HookName: "h", Allow: true})
	_ = store.Insert(context.Background(), audit.Record{DecisionID: "fresh", Timestamp: now.Add(-1 * time.Hour), HookName: "h", Allow: true})
	_ = store.Close()

	// Seed the decision log with one old and one fresh JSONL line.
	logPath := filepath.Join(cacheDir, "decisions.log")
	oldLine := `{"timestamp":"` + now.Add(-72*time.Hour).UTC().Format(time.RFC3339Nano) + `","hosts":["old.example"],"decision":{"allow":true}}`
	freshLine := `{"timestamp":"` + now.Add(-1*time.Hour).UTC().Format(time.RFC3339Nano) + `","hosts":["fresh.example"],"decision":{"allow":true}}`
	if err := os.WriteFile(logPath, []byte(oldLine+"\n"+freshLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runPurge([]string{"--days", "2", "--yes"}); err != nil {
		t.Fatalf("runPurge: %v", err)
	}

	// Audit: old gone, fresh survives.
	store2, err := audit.Open(filepath.Join(cacheDir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store2.Close() }()
	if got, _ := store2.FindByDecisionID(context.Background(), "old"); got != nil {
		t.Error("expected old audit row purged")
	}
	if got, _ := store2.FindByDecisionID(context.Background(), "fresh"); got == nil {
		t.Error("expected fresh audit row to survive")
	}

	// Log: old line gone, fresh line kept.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "old.example") {
		t.Errorf("expected old log line purged, got:\n%s", data)
	}
	if !strings.Contains(string(data), "fresh.example") {
		t.Errorf("expected fresh log line kept, got:\n%s", data)
	}
}

func TestRunPurge_NoWindowIsError(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("TRUSTGATE_RETENTION_DAYS", "")
	if err := runPurge([]string{"--yes"}); err == nil {
		t.Error("expected an error when neither --days, --all, nor TRUSTGATE_RETENTION_DAYS is set")
	}
}
