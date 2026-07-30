package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/malanta-ai/Malanta-TrustGate/internal/override"
)

func cacheDirIn(home string) string { return filepath.Join(home, ".cache", "trustgate") }

// grantedValues returns the indicator values of every live grant, which is
// what actually has to match the cascade — the human-readable descriptions
// are cosmetic, the keys are load-bearing.
func grantedValues(t *testing.T, home string) []string {
	t.Helper()
	entries := override.List(cacheDirIn(home))
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Domain)
	}
	return out
}

// TestRunOverride_RepoFlagCanonicalizes is the core guarantee of --repo:
// whatever shape the operator pastes, the grant is keyed by the value the
// cascade denies on. A grant keyed to anything else is a silent no-op.
func TestRunOverride_RepoFlagCanonicalizes(t *testing.T) {
	for _, input := range []string{
		"acme/backdoor",
		"Acme/Backdoor",
		"acme/backdoor.git",
		"acme/backdoor@v1",
		"https://github.com/Acme/Backdoor",
		"https://github.com/acme/backdoor.git",
		"git@github.com:Acme/Backdoor.git",
		"https://github.com/acme/backdoor/blob/main/setup.py",
	} {
		t.Run(input, func(t *testing.T) {
			home := t.TempDir()
			setTestHome(t, home)
			if err := runOverride([]string{"--repo", input, "--minutes", "10", "--reason", "triaging"}); err != nil {
				t.Fatalf("runOverride: %v", err)
			}
			got := grantedValues(t, home)
			if len(got) != 1 || got[0] != "acme/backdoor" {
				t.Errorf("grant keyed as %v, want [acme/backdoor]", got)
			}
		})
	}
}

func TestRunOverride_OwnerFlagCanonicalizes(t *testing.T) {
	for _, input := range []string{
		"acme",
		"ACME",
		"https://github.com/Acme",
		"https://acme.github.io",
		// A repo reference resolves to its owner rather than erroring;
		// the confirmation line states the widening.
		"acme/backdoor",
	} {
		t.Run(input, func(t *testing.T) {
			home := t.TempDir()
			setTestHome(t, home)
			if err := runOverride([]string{"--owner", input, "--minutes", "10", "--reason", "triaging"}); err != nil {
				t.Fatalf("runOverride: %v", err)
			}
			got := grantedValues(t, home)
			if len(got) != 1 || got[0] != "acme" {
				t.Errorf("grant keyed as %v, want [acme]", got)
			}
		})
	}
}

// TestRunOverride_RejectsUnresolvableReference: a reference that can never
// match must fail loudly at grant time. Accepting it would hand the
// operator a grant that looks applied and changes nothing.
func TestRunOverride_RejectsUnresolvableReference(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	for _, tc := range []struct{ flag, value string }{
		{"--repo", "not a repo"},
		{"--repo", "acme"},      // owner only — belongs on --owner
		{"--repo", "-bad/repo"}, // invalid owner (leading dash)
		{"--owner", "has spaces"},
		{"--owner", strings.Repeat("a", 40)}, // over GitHub's 39-char limit
	} {
		err := runOverride([]string{tc.flag, tc.value, "--minutes", "10", "--reason", "x"})
		if err == nil {
			t.Errorf("%s %q: expected an error, got nil", tc.flag, tc.value)
		}
	}
	if got := grantedValues(t, home); len(got) != 0 {
		t.Errorf("no grant should have been written, got %v", got)
	}
}

// TestRunOverride_MixedTargetsInOneCommand covers the flat-namespace
// property: all three kinds coexist in one store with no collision,
// because a repo always contains "/", a host always contains ".", and a
// bare owner contains neither.
func TestRunOverride_MixedTargetsInOneCommand(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	if err := runOverride([]string{
		"--domain", "malicious.example",
		"--repo", "acme/backdoor",
		"--owner", "evilorg",
		"--minutes", "10", "--reason", "incident triage",
	}); err != nil {
		t.Fatalf("runOverride: %v", err)
	}
	got := grantedValues(t, home)
	want := map[string]bool{"malicious.example": true, "acme/backdoor": true, "evilorg": true}
	if len(got) != 3 {
		t.Fatalf("expected 3 grants, got %v", got)
	}
	for _, v := range got {
		if !want[v] {
			t.Errorf("unexpected grant value %q", v)
		}
	}
}

// TestRunOverride_ClearRepo confirms --clear routes through the same
// canonicalization, so an operator can clear with a different input shape
// than they granted with.
func TestRunOverride_ClearRepo(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	if err := runOverride([]string{"--repo", "acme/backdoor", "--minutes", "10", "--reason", "triaging"}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := runOverride([]string{"--clear", "--repo", "https://github.com/Acme/Backdoor.git"}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := grantedValues(t, home); len(got) != 0 {
		t.Errorf("expected no grants after clear, got %v", got)
	}
}
