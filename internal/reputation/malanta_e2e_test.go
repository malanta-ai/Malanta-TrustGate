//go:build e2e

// Live-API smoke test for the Malanta provider. Requires MALANTA_API_KEY in
// the environment; run via `make e2e`. Hits the real
// https://app.malanta.ai/data batch endpoints for known-labeled domains.
// Kept hermetic-test-suite-free (build-tag gated) per AGENTS.md — `go test
// ./...` must never require network or a live key.
package reputation

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestE2E_MalantaProvider_KnownDomains(t *testing.T) {
	key := os.Getenv("MALANTA_API_KEY")
	if key == "" {
		t.Skip("MALANTA_API_KEY not set")
	}
	p := NewMalanta("https://app.malanta.ai/data", key, WithMalantaRetry(3*time.Second, 2))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Any resolvable hosts work here: the assertion below is that the
	// provider answers with SOME verdict for every indicator it was asked
	// about, which is the batch contract. Whether a given host is flagged
	// is the provider's data, not this test's concern.
	indicators := []Indicator{
		{Kind: KindDomain, Value: "google.com"},
		{Kind: KindDomain, Value: "github.com"},
		{Kind: KindDomain, Value: "cloudflare.com"},
	}
	labels, err := p.Lookup(ctx, indicators)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	for _, ind := range indicators {
		lbl, ok := labels[ind]
		if !ok || lbl == nil || lbl.Name == "" {
			t.Errorf("%s: expected a non-empty verdict, got %#v (present=%v)", ind.Value, lbl, ok)
		} else {
			t.Logf("%s -> %s (score=%.4f)", ind.Value, lbl.Name, lbl.MaliciousScore)
		}
	}
}

func TestE2E_MalantaProvider_IPv4(t *testing.T) {
	key := os.Getenv("MALANTA_API_KEY")
	if key == "" {
		t.Skip("MALANTA_API_KEY not set")
	}
	p := NewMalanta("https://app.malanta.ai/data", key, WithMalantaRetry(3*time.Second, 2))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ind := Indicator{Kind: KindIPv4, Value: "8.8.8.8"}
	labels, err := p.Lookup(ctx, []Indicator{ind})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if lbl, ok := labels[ind]; !ok || lbl == nil {
		t.Errorf("8.8.8.8: expected a resolved label, got %#v (present=%v)", lbl, ok)
	} else {
		t.Logf("8.8.8.8 -> %s (score=%.4f)", lbl.Name, lbl.MaliciousScore)
	}
}
