package verdict

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

// TestCompose_DeniesAbovePathologicalFanOutCap is the regression test for
// the fan-out cap. The OLD behavior truncated to the first N hosts and
// let the cascade proceed — an attacker could pad the first N entries with
// benign hosts to hide a malicious one past the truncation point. The NEW
// behavior denies the whole event outright (under FailClosed) rather than
// silently evaluating only part of it.
func TestCompose_DeniesAbovePathologicalFanOutCap(t *testing.T) {
	const overCap = maxIndicatorsPerEvent + 50
	domains := make([]string, overCap)
	for i := range domains {
		domains[i] = fmt.Sprintf("d%03d.example", i)
	}

	var seen int
	lk := &countingLookup{
		respLabel: "UNKNOWN",
		onQuery:   func(indicators []reputation.Indicator) { seen += len(indicators) },
	}

	cfg := baseCfg(t)
	cfg.FailClosed = true
	d := Compose(context.Background(), cfg, "shell", domains, nil, lk, nil)

	if d.Allow {
		t.Errorf("expected deny above the pathological fan-out cap under fail-closed, got allow: %#v", d)
	}
	if seen != 0 {
		t.Errorf("lookup should never be consulted above the cap; saw %d indicators", seen)
	}
	if !strings.Contains(d.Reason, "pathological-fan-out") {
		t.Errorf("expected reason to mention the fan-out cap, got %q", d.Reason)
	}
}

// TestCompose_AllowsAllUnderCap_ChunksInternally verifies EVERY indicator
// under the cap is actually checked (not just a truncated prefix) — the
// provider itself is responsible for chunking (Malanta batches at 100 with
// bounded concurrency internally), so Compose only needs to pass the whole
// set through.
func TestCompose_AllowsAllUnderCap_ChunksInternally(t *testing.T) {
	const underCap = maxIndicatorsPerEvent - 1
	domains := make([]string, underCap)
	for i := range domains {
		domains[i] = fmt.Sprintf("d%03d.example", i)
	}

	var seen int
	lk := &countingLookup{
		respLabel: "UNKNOWN",
		onQuery:   func(indicators []reputation.Indicator) { seen += len(indicators) },
	}

	cfg := baseCfg(t)
	d := Compose(context.Background(), cfg, "shell", domains, nil, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow (all clean, under cap), got deny: %#v", d)
	}
	if seen != underCap {
		t.Errorf("lookup saw %d indicators, want %d (every one under the cap)", seen, underCap)
	}
}

// TestCompose_DoesNotDenyWellBelowCap is a regression guard: the cap is a
// ceiling, not a floor.
func TestCompose_DoesNotDenyWellBelowCap(t *testing.T) {
	domains := []string{"a.example", "b.example", "c.example"}

	var seen int
	lk := &countingLookup{
		respLabel: "UNKNOWN",
		onQuery:   func(indicators []reputation.Indicator) { seen += len(indicators) },
	}

	cfg := baseCfg(t)
	d := Compose(context.Background(), cfg, "shell", domains, nil, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow, got deny: %#v", d)
	}
	if seen != len(domains) {
		t.Errorf("lookup saw %d domains, want %d", seen, len(domains))
	}
}

// countingLookup records every indicator handed to it and synthesizes a
// uniform Label response. Used to assert call-count expectations without
// depending on an HTTP test server.
type countingLookup struct {
	respLabel string
	onQuery   func([]reputation.Indicator)
}

func (c *countingLookup) Lookup(_ context.Context, indicators []reputation.Indicator) (map[reputation.Indicator]*reputation.Label, error) {
	if c.onQuery != nil {
		c.onQuery(indicators)
	}
	out := make(map[reputation.Indicator]*reputation.Label, len(indicators))
	for _, ind := range indicators {
		out[ind] = &reputation.Label{Name: c.respLabel, MaliciousScore: 0}
	}
	return out, nil
}

func (c *countingLookup) Name() string { return "malanta" }
