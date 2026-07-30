package cache

import (
	"context"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

func TestLookupBatch_MixedHitsAndMisses(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()

	pos := &reputation.Label{Name: "Malicious", MaliciousScore: 0.95}
	if err := c.Put(ctx, "malanta", domainInd("bad.example"), pos, time.Hour); err != nil {
		t.Fatalf("Put pos: %v", err)
	}
	// Insert with a negative TTL so it's already expired at query time.
	if err := c.Put(ctx, "malanta", domainInd("expired.example"), pos, -time.Hour); err != nil {
		t.Fatalf("Put expired: %v", err)
	}

	hits, errs := c.LookupBatch(ctx, "malanta", []reputation.Indicator{
		domainInd("bad.example"),
		domainInd("expired.example"),
		domainInd("never-seen.example"),
	})
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}

	h, ok := hits[domainInd("bad.example")]
	if !ok || !h.Present {
		t.Errorf("bad.example missing: %#v", h)
	}
	if h.Label == nil || h.Label.Name != "Malicious" {
		t.Errorf("bad.example wrong: %#v", h)
	}

	// Expired = miss (not in hits at all)
	if _, ok := hits[domainInd("expired.example")]; ok {
		t.Errorf("expired.example should be a miss, got %#v", hits[domainInd("expired.example")])
	}

	// Never-seen = miss
	if _, ok := hits[domainInd("never-seen.example")]; ok {
		t.Errorf("never-seen.example should be a miss")
	}
}

func TestLookupBatch_EmptyAndNil(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()
	if hits, errs := c.LookupBatch(ctx, "malanta", nil); hits != nil || errs != nil {
		t.Errorf("nil input should return nil/nil, got %#v / %#v", hits, errs)
	}
	if hits, errs := c.LookupBatch(ctx, "malanta", []reputation.Indicator{}); hits != nil || errs != nil {
		t.Errorf("empty input should return nil/nil, got %#v / %#v", hits, errs)
	}
}

func TestLookupBatch_DedupesDuplicateInputs(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()
	pos := &reputation.Label{Name: "Malicious", MaliciousScore: 0.9}
	if err := c.Put(ctx, "malanta", domainInd("x.example"), pos, time.Hour); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Passing the same indicator three times must not double-count or fail.
	hits, errs := c.LookupBatch(ctx, "malanta", []reputation.Indicator{
		domainInd("x.example"), domainInd("x.example"), domainInd("x.example"),
	})
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(hits) != 1 {
		t.Errorf("expected 1 unique hit, got %d: %v", len(hits), hits)
	}
}

func TestLookupBatch_ChunksLargeInput(t *testing.T) {
	// Exercise the chunk boundary. Seed 2*maxBatchIndicators + 1 rows and
	// assert every one is reported as a hit. This is the regression test
	// for a future bump to the fan-out cap that crosses the SQLite
	// parameter limit.
	c := newCache(t)
	ctx := context.Background()
	n := 2*maxBatchIndicators + 1
	indicators := make([]reputation.Indicator, n)
	for i := 0; i < n; i++ {
		ind := domainInd(makeDomain(i))
		indicators[i] = ind
		if err := c.Put(ctx, "malanta", ind, &reputation.Label{Name: "UNKNOWN"}, time.Hour); err != nil {
			t.Fatalf("Put %s: %v", ind.Value, err)
		}
	}
	hits, errs := c.LookupBatch(ctx, "malanta", indicators)
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(hits) != n {
		t.Errorf("got %d hits, want %d", len(hits), n)
	}
}

func makeDomain(i int) string {
	return "d" + itoa(i) + ".example"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
