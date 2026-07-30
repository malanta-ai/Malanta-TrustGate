package atr

import (
	"strings"
	"testing"
)

// BenchmarkEvaluateShellSubset measures the worst-case overhead of
// running the shell rule subset against a non-trivial command line.
// The performance budget requires p95 ≤ 30ms; modern hardware
// should land this benchmark in low double-digit microseconds per
// op, two to three orders of magnitude under the budget. A
// regression here (e.g. someone introduces an O(n²) pattern that
// catastrophically backtracks) is exactly the failure mode we
// want a benchmark to surface.
//
// Run with `go test -bench=. -benchmem ./internal/atr/...` and
// expect (rough numbers, M-series Apple silicon):
//
//	BenchmarkEvaluateShellSubset-10   ~100µs/op   ~20kB/op
func BenchmarkEvaluateShellSubset(b *testing.B) {
	rules, err := LoadBundledForTarget(TargetShell)
	if err != nil {
		b.Fatalf("LoadBundledForTarget(shell): %v", err)
	}
	// Representative shell command line. Includes a few dozen bytes
	// of context that shell rules WILL scan but probably not match,
	// to give an honest "scan miss" cost rather than an artificially
	// fast small-string benchmark.
	cmd := `cd /tmp && find . -name '*.go' | xargs grep -l 'TODO' && go build ./...`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Evaluate(cmd, rules)
	}
}

// BenchmarkEvaluateReadFilePool measures the read-file/MCP pool's
// scan cost against a larger blob. The pool is ~107 rules with
// roughly 4-6 patterns each; iterating that many regex against a
// 4KiB file should still be sub-millisecond.
func BenchmarkEvaluateReadFilePool(b *testing.B) {
	rules, err := LoadBundled()
	if err != nil {
		b.Fatalf("LoadBundled: %v", err)
	}
	// 4 KiB of representative skill-manifest-shaped content.
	blob := strings.Repeat("name: my-skill\ndescription: a helper for X\n"+
		"allowed_paths:\n  - ./src/**\n  - ./tests/**\n"+
		"permissions:\n  - read\n  - write\n\n", 80)
	b.ResetTimer()
	b.SetBytes(int64(len(blob)))
	for i := 0; i < b.N; i++ {
		_ = Evaluate(blob, rules)
	}
}

// BenchmarkLoadBundled measures the one-time cost paid at hook
// startup to read + compile the rule snapshot. Subsequent calls
// hit the sync.Once cache and cost nothing; the cost here only
// affects the first invocation in a process — but since every
// hook invocation IS a fresh process, this IS the cold-start
// cost on the hot path.
//
// Target: < 50ms cold. If this benchmark drifts above 100ms, the
// rule bundle is starting to dominate the 250ms hook budget and a
// pre-compilation step (rules-as-Go-source) becomes necessary.
func BenchmarkLoadBundled(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// We can't reset loadOnce; the benchmark reports the
		// sync.Once-cached cost, which is the relevant cost for
		// "second and subsequent hooks in the same process". The
		// cold-start cost is measured separately by a Makefile
		// target that exec's a fresh subprocess.
		_, _ = LoadBundled()
	}
}
