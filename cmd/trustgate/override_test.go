package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/override"
)

func TestRunOverride_WritesValidOverrideFile(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	if err := runOverride([]string{"--domain", "malicious.example", "--minutes", "10", "--reason", "investigating a false positive"}); err != nil {
		t.Fatalf("runOverride: %v", err)
	}

	path := filepath.Join(home, ".cache", "trustgate", overrideFileName)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected override file to exist: %v", err)
	}
	entries := override.List(filepath.Join(home, ".cache", "trustgate"))
	if len(entries) != 1 {
		t.Fatalf("expected exactly one entry, got %+v", entries)
	}
	if entries[0].Domain != "malicious.example" {
		t.Errorf("expected Domain=malicious.example, got %q", entries[0].Domain)
	}
	if entries[0].Reason != "investigating a false positive" {
		t.Errorf("unexpected reason: %q", entries[0].Reason)
	}
	until, err := time.Parse(time.RFC3339, entries[0].Until)
	if err != nil {
		t.Fatalf("parse until: %v", err)
	}
	if until.Before(time.Now().Add(9 * time.Minute)) {
		t.Errorf("expected until to be ~10 minutes out, got %v", until)
	}
}

func TestRunOverride_RequiresDomainByDefault(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	if err := runOverride([]string{"--minutes", "10", "--reason", "x"}); err == nil {
		t.Error("expected an error when --domain is omitted under the default (domain) override scope")
	}
}

func TestRunOverride_TimeScope_DoesNotRequireDomain(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("TRUSTGATE_OVERRIDE_SCOPE", "time")
	if err := runOverride([]string{"--minutes", "10", "--reason", "blanket window"}); err != nil {
		t.Fatalf("runOverride: %v", err)
	}
	entries := override.List(filepath.Join(home, ".cache", "trustgate"))
	if len(entries) != 1 || entries[0].Domain != "*" {
		t.Errorf("expected a single blanket (*) entry, got %+v", entries)
	}
}

func TestRunOverride_MultipleDomains(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	if err := runOverride([]string{"--domain", "malicious.example", "--domain", "other.example", "--minutes", "10", "--reason", "x"}); err != nil {
		t.Fatalf("runOverride: %v", err)
	}
	entries := override.List(filepath.Join(home, ".cache", "trustgate"))
	if len(entries) != 2 {
		t.Fatalf("expected two entries, got %+v", entries)
	}
}

// TestRunOverride_RejectsWildcardUnderDomainScope is the scope-escalation
// guard: a
// literal "*" (the blanket-grant sentinel) must be refused under the default
// domain scope, so a domain-scoped policy can't be turned into a blanket
// bypass via `--domain '*'`.
func TestRunOverride_RejectsWildcardUnderDomainScope(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	for _, d := range []string{"*", "*.example", "evil.*"} {
		if err := runOverride([]string{"--domain", d, "--minutes", "10", "--reason", "x"}); err == nil {
			t.Errorf("expected --domain %q to be rejected under domain scope", d)
		}
	}
	if entries := override.List(filepath.Join(home, ".cache", "trustgate")); len(entries) != 0 {
		t.Errorf("expected no grant written for a rejected wildcard, got %+v", entries)
	}
}

func TestRunOverride_RequiresReason(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	if err := runOverride([]string{"--domain", "malicious.example", "--minutes", "5"}); err == nil {
		t.Error("expected an error when --reason is omitted")
	}
}

func TestRunOverride_RejectsNonPositiveMinutes(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	if err := runOverride([]string{"--domain", "malicious.example", "--minutes", "0", "--reason", "x"}); err == nil {
		t.Error("expected an error for --minutes 0")
	}
}

func TestRunOverride_ClearRemovesFile(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	if err := runOverride([]string{"--domain", "malicious.example", "--minutes", "10", "--reason", "x"}); err != nil {
		t.Fatalf("runOverride: %v", err)
	}
	path := filepath.Join(home, ".cache", "trustgate", overrideFileName)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected override file to exist before clearing: %v", err)
	}

	if err := runOverride([]string{"--clear"}); err != nil {
		t.Fatalf("runOverride --clear: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected override file to be removed after --clear, stat returned: %v", err)
	}
}

func TestRunOverride_ClearOneDomainLeavesOthers(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	if err := runOverride([]string{"--domain", "malicious.example", "--domain", "other.example", "--minutes", "10", "--reason", "x"}); err != nil {
		t.Fatalf("runOverride: %v", err)
	}
	if err := runOverride([]string{"--clear", "--domain", "malicious.example"}); err != nil {
		t.Fatalf("runOverride --clear --domain: %v", err)
	}
	entries := override.List(filepath.Join(home, ".cache", "trustgate"))
	if len(entries) != 1 || entries[0].Domain != "other.example" {
		t.Errorf("expected only other.example to survive, got %+v", entries)
	}
}

func TestRunOverride_ClearOnMissingFileIsNotAnError(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	if err := runOverride([]string{"--clear"}); err != nil {
		t.Errorf("expected --clear on a non-existent file to be a no-op, got: %v", err)
	}
}
