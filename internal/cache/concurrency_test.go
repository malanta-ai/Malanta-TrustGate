package cache

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

// TestCache_ConcurrentPutLookup is the cache's concurrency safety contract:
// concurrent access must not panic, must not corrupt data, and any Put that
// reports success must be visible to a subsequent Lookup. SQLite under the
// hood is allowed to report SQLITE_BUSY when contention exceeds the small
// busy_timeout we run with (50ms, chosen so the cache cannot eat the whole
// 250ms hook budget); the production cascade already treats Put failures as
// warnings, so they're an acceptable degraded outcome here too. The test
// therefore asserts the contract, not "zero contention." Run with `-race`
// to also catch in-process data races.
func TestCache_ConcurrentPutLookup(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()

	const (
		workers = 4
		ops     = 50
	)
	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		hardErrs    []error
		committed   = make(map[string]bool)
		busyRetries int
	)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				dom := fmt.Sprintf("d%d-%d.example", worker, i)
				ind := reputation.Indicator{Kind: reputation.KindDomain, Value: dom}
				lbl := &reputation.Label{Name: "Malicious", MaliciousScore: 0.9}
				if err := c.Put(ctx, "malanta", ind, lbl, time.Hour); err != nil {
					if strings.Contains(err.Error(), "SQLITE_BUSY") {
						mu.Lock()
						busyRetries++
						mu.Unlock()
						continue // acceptable degraded outcome
					}
					mu.Lock()
					hardErrs = append(hardErrs, fmt.Errorf("Put(%s): %w", dom, err))
					mu.Unlock()
					return
				}
				// Put reported success: contract requires the value is now visible.
				got, present, err := c.Lookup(ctx, "malanta", ind)
				if err != nil {
					if strings.Contains(err.Error(), "SQLITE_BUSY") {
						mu.Lock()
						busyRetries++
						mu.Unlock()
						continue
					}
					mu.Lock()
					hardErrs = append(hardErrs, fmt.Errorf("Lookup(%s): %w", dom, err))
					mu.Unlock()
					return
				}
				if !present || got == nil || got.Name != "Malicious" {
					mu.Lock()
					hardErrs = append(hardErrs, fmt.Errorf("Lookup(%s): committed Put not visible: present=%v got=%v", dom, present, got))
					mu.Unlock()
					return
				}
				mu.Lock()
				committed[dom] = true
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	for _, e := range hardErrs {
		t.Error(e)
	}
	if len(committed) == 0 {
		t.Errorf("no Puts committed at all (busyRetries=%d) — cache might be totally stuck", busyRetries)
	}
	t.Logf("committed=%d busy_retries=%d out of %d ops", len(committed), busyRetries, workers*ops)
}

// TestCache_NilClose verifies the fail-open contract of OpenOrWarn: calling
// Close on a nil *Cache (the value returned when the open failed) must not
// panic.
func TestCache_NilClose(t *testing.T) {
	var c *Cache
	if err := c.Close(); err != nil {
		t.Errorf("nil Close should be a no-op, got %v", err)
	}
}

// TestOpenOrWarn_BadPathDisables exercises the fail-open helper used by every
// cmd binary: an unwritable cache dir should yield nil and a warning, never
// a panic, never an error to the caller.
func TestOpenOrWarn_BadPathDisables(t *testing.T) {
	var buf bytesBuffer
	// Nest the cache under a REGULAR FILE. No OS lets a file act as a
	// parent directory, so MkdirAll fails everywhere — unlike the
	// /dev/null/... path this used to use, which is only special on Unix
	// and on Windows was a perfectly creatable relative directory, so the
	// open succeeded and the test failed there.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := OpenOrWarn(filepath.Join(blocker, "cache", "lookups.db"), &buf)
	if c != nil {
		t.Errorf("expected nil cache on bad path, got %v", c)
	}
	if buf.String() == "" {
		t.Errorf("expected a warning line on stderr, got empty")
	}
}

// bytesBuffer is a tiny io.Writer to avoid pulling in bytes for one test.
type bytesBuffer struct{ b []byte }

func (b *bytesBuffer) Write(p []byte) (int, error) { b.b = append(b.b, p...); return len(p), nil }
func (b *bytesBuffer) String() string              { return string(b.b) }
