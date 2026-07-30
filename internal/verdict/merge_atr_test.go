package verdict

import (
	"testing"

	"github.com/malanta-ai/Malanta-TrustGate/internal/atr"
)

func TestMergeATRNoMatches(t *testing.T) {
	d := Decision{Allow: true}
	MergeATR(&d, nil, true)
	if !d.Allow {
		t.Error("MergeATR with nil matches must not flip Allow")
	}
	if d.ATRMatches != nil {
		t.Error("MergeATR with nil matches must not populate ATRMatches")
	}
}

func TestMergeATRMediumDoesNotDeny(t *testing.T) {
	d := Decision{Allow: true}
	matches := []atr.Match{{
		RuleID:      "TEST-MEDIUM",
		Severity:    atr.SeverityMedium,
		Category:    atr.CategoryContextExfiltration,
		Description: "medium-severity match",
	}}
	MergeATR(&d, matches, true)
	if !d.Allow {
		t.Error("MergeATR must NOT flip Allow on medium-severity match")
	}
	if len(d.ATRMatches) != 1 {
		t.Fatalf("ATRMatches not recorded; got %d", len(d.ATRMatches))
	}
}

func TestMergeATRCriticalDenies(t *testing.T) {
	d := Decision{Allow: true}
	matches := []atr.Match{{
		RuleID:      "TEST-CRITICAL",
		Severity:    atr.SeverityCritical,
		Category:    atr.CategoryPrivilegeEscalation,
		Description: "critical match",
	}}
	MergeATR(&d, matches, true)
	if d.Allow {
		t.Error("MergeATR must flip Allow=false on critical match in failClosed mode")
	}
	if d.Reason == "" {
		t.Error("MergeATR must populate Reason on critical match")
	}
	if len(d.ATRMatches) != 1 {
		t.Error("ATRMatches not recorded")
	}
}

func TestMergeATRCriticalRespectsFailOpen(t *testing.T) {
	d := Decision{Allow: true}
	matches := []atr.Match{{
		RuleID:   "TEST-CRITICAL",
		Severity: atr.SeverityCritical,
		Category: atr.CategoryPrivilegeEscalation,
	}}
	MergeATR(&d, matches, false) // fail-OPEN deployment
	if !d.Allow {
		t.Error("MergeATR in fail-OPEN mode must NOT flip Allow even on critical")
	}
	if len(d.ATRMatches) != 1 {
		t.Error("ATRMatches must still be recorded in fail-OPEN mode for audit")
	}
}

func TestMergeATRDoesNotOverwriteExistingDeny(t *testing.T) {
	d := Decision{Allow: false, Reason: "domain malicious.example.com"}
	matches := []atr.Match{{
		RuleID:   "TEST-CRITICAL",
		Severity: atr.SeverityCritical,
		Category: atr.CategoryContextExfiltration,
	}}
	MergeATR(&d, matches, true)
	if d.Allow {
		t.Error("MergeATR must not flip an existing deny to allow")
	}
	if d.Reason != "domain malicious.example.com" {
		t.Errorf("MergeATR overwrote existing deny reason: %q", d.Reason)
	}
	if len(d.ATRMatches) != 1 {
		t.Error("ATRMatches must still annotate the existing deny")
	}
}

func TestMergeATRNilDecisionIsNoOp(t *testing.T) {
	// Defensive: passing a nil Decision must not panic.
	MergeATR(nil, []atr.Match{{Severity: atr.SeverityCritical}}, true)
}
