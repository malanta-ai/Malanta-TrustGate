package atr

import (
	"regexp"
	"strings"
	"testing"
)

// TestEvaluate_DoesNotPersistRawMatch is the PRIV-001 guard: the Match a rule
// produces must NOT carry the raw matched substring (which is frequently the
// exact sensitive bytes the rule hunts for). It must instead carry a one-way
// SHA-256 digest and a byte length.
func TestEvaluate_DoesNotPersistRawMatch(t *testing.T) {
	// A fake secret-shaped token. Deliberately NOT an AWS-key-shaped
	// literal (that would trip scripts/check-no-secrets.sh on a tracked
	// file); the point is only that the digest doesn't echo it back.
	const secret = "FAKETOKEN-super-secret-credential-blob"
	rules := []Rule{{
		ID:       "TEST-PRIV-001",
		Category: CategoryContextExfiltration,
		Severity: SeverityCritical,
		Patterns: []Pattern{{Regex: regexp.MustCompile("FAKETOKEN[A-Za-z0-9-]+credential-blob"), Description: "test"}},
	}}
	matches := Evaluate("prefix "+secret+" suffix", rules)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0]
	if strings.Contains(m.MatchDigest, "FAKETOKEN") || strings.Contains(m.MatchDigest, "credential") {
		t.Errorf("MatchDigest leaked raw content: %q", m.MatchDigest)
	}
	if !strings.HasPrefix(m.MatchDigest, "sha256:") {
		t.Errorf("expected a sha256: digest, got %q", m.MatchDigest)
	}
	if m.MatchLen == 0 {
		t.Error("expected a non-zero MatchLen")
	}
	// Determinism: the same matched content yields the same digest.
	again := Evaluate("different prefix "+secret, rules)
	if len(again) != 1 || again[0].MatchDigest != m.MatchDigest {
		t.Errorf("expected identical digests for identical matched content, got %q vs %q", m.MatchDigest, again[0].MatchDigest)
	}
}
