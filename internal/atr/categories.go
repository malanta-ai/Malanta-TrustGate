package atr

// FilterByCategory returns the subset of rules whose Category is in
// the given set. Used by tests and by future per-hook filtering;
// LoadBundled / LoadBundledForTarget already pre-route rules to the
// right Target pool, so this helper exists primarily for tests that
// want to assert "the bundle contains at least N skill-compromise
// rules" or "the shell pool has no prompt-injection rules".
//
// The slice is freshly allocated; modifying the returned slice does
// not affect the input.
func FilterByCategory(rules []Rule, cats ...Category) []Rule {
	if len(rules) == 0 || len(cats) == 0 {
		return nil
	}
	want := make(map[Category]struct{}, len(cats))
	for _, c := range cats {
		want[c] = struct{}{}
	}
	out := make([]Rule, 0, len(rules))
	for i := range rules {
		if _, ok := want[rules[i].Category]; ok {
			out = append(out, rules[i])
		}
	}
	return out
}

// CountByCategory returns a category -> count map for the given rule
// slice. Useful for the bundle's startup diagnostic in tests and the
// benchmark's per-surface report.
func CountByCategory(rules []Rule) map[Category]int {
	out := make(map[Category]int, 8)
	for i := range rules {
		out[rules[i].Category]++
	}
	return out
}
