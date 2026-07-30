package atr

import (
	"sort"
	"strings"
	"testing"
	"time"
)

// TestIdentifySlowRules profiles each loaded rule against a
// representative blob and prints any that take more than 1ms to scan.
// This is the diagnostic that surfaces catastrophic backtracking in
// the bundled rule snapshot — those rules need to be either rewritten
// or filtered out at sync time.
//
// Not a strict pass/fail: prints a warning when any rule crosses the
// threshold but does not fail the build. Use the t.Log output as a
// triage list against the rule files in internal/atr/rules/.
func TestIdentifySlowRules(t *testing.T) {
	rules, err := LoadBundled()
	if err != nil {
		t.Fatalf("LoadBundled: %v", err)
	}
	blob := strings.Repeat("name: my-skill\ndescription: a helper for X\n"+
		"allowed_paths:\n  - ./src/**\n  - ./tests/**\n"+
		"permissions:\n  - read\n  - write\n\n", 80)

	type slowEntry struct {
		id  string
		dur time.Duration
	}
	var slow []slowEntry
	for i := range rules {
		r := &rules[i]
		start := time.Now()
		_ = evaluateRule(blob, r)
		d := time.Since(start)
		if d > time.Millisecond {
			slow = append(slow, slowEntry{r.ID, d})
		}
	}
	sort.Slice(slow, func(i, j int) bool { return slow[i].dur > slow[j].dur })
	if len(slow) == 0 {
		t.Log("All rules executed under 1ms on 4 KiB representative blob (good)")
		return
	}
	t.Logf("Rules exceeding 1ms on 4 KiB blob: %d", len(slow))
	limit := 15
	if len(slow) < limit {
		limit = len(slow)
	}
	for _, s := range slow[:limit] {
		t.Logf("  %s: %s", s.id, s.dur)
	}
	totalSlow := time.Duration(0)
	for _, s := range slow {
		totalSlow += s.dur
	}
	t.Logf("Total slow-rule time on this blob: %s", totalSlow)
}
