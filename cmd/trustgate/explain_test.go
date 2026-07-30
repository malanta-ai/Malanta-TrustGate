package main

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/audit"
)

func openTestAuditStore(t *testing.T) *audit.Store {
	t.Helper()
	s, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestExplainQuery_FindsByDecisionID(t *testing.T) {
	store := openTestAuditStore(t)
	ctx := context.Background()
	if err := store.Insert(ctx, audit.Record{
		DecisionID: "deadbeef", Indicator: "malicious.example", Allow: false,
		Reason: "malanta flagged malicious.example as MALICIOUS", Timestamp: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := explainQuery(ctx, &buf, store, "deadbeef", "audit.db"); err != nil {
		t.Fatalf("explainQuery: %v", err)
	}
	out := buf.String()
	if !bytesContains(out, "deadbeef") || !bytesContains(out, "malicious.example") || !bytesContains(out, "MALICIOUS") {
		t.Errorf("expected output to describe the matched record, got:\n%s", out)
	}
}

func TestExplainQuery_FallsBackToIndicatorSearch(t *testing.T) {
	store := openTestAuditStore(t)
	ctx := context.Background()
	if err := store.Insert(ctx, audit.Record{DecisionID: "d1", Indicator: "malicious.example", Allow: false}); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(ctx, audit.Record{DecisionID: "d2", Indicator: "malicious.example", Allow: true, Timestamp: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := explainQuery(ctx, &buf, store, "malicious.example", "audit.db"); err != nil {
		t.Fatalf("explainQuery: %v", err)
	}
	out := buf.String()
	if !bytesContains(out, "2 decision(s)") {
		t.Errorf("expected output to report 2 matches, got:\n%s", out)
	}
}

func TestExplainQuery_NoMatchIsFriendlyNotAnError(t *testing.T) {
	store := openTestAuditStore(t)
	var buf bytes.Buffer
	if err := explainQuery(context.Background(), &buf, store, "nope.example", "audit.db"); err != nil {
		t.Fatalf("expected no error for a query with no matches, got: %v", err)
	}
	if !bytesContains(buf.String(), "No decision found") {
		t.Errorf("expected a friendly no-match message, got:\n%s", buf.String())
	}
}

func TestRunExplain_RejectsMissingArg(t *testing.T) {
	if err := runExplain(nil); err == nil {
		t.Error("expected an error when no query argument is given")
	}
	if err := runExplain([]string{"a", "b"}); err == nil {
		t.Error("expected an error when too many arguments are given")
	}
}
