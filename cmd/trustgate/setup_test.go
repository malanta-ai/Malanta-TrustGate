package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunSetup_WritesKeyFileWithKeyFlag(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("MALANTA_API_KEY", "")

	if err := runSetup([]string{"--key", "test-key-123"}); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	path := filepath.Join(home, ".config", "trustgate", "env")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written env file: %v", err)
	}
	if got := string(data); got != "MALANTA_API_KEY=test-key-123\n" {
		t.Errorf("unexpected file contents: %q", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// POSIX-only: Windows governs access by ACL and reports 0666 for any
	// writable file. The key-file CONTENTS assertion above runs everywhere.
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("expected mode 0600, got %o", perm)
		}
	}
}

func TestRunSetup_RefusesToOverwriteWithoutReset(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	if err := runSetup([]string{"--key", "first-key"}); err != nil {
		t.Fatalf("first runSetup: %v", err)
	}
	if err := runSetup([]string{"--key", "second-key"}); err == nil {
		t.Fatal("expected an error when writing over an existing key file without --reset")
	}

	path := filepath.Join(home, ".config", "trustgate", "env")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "MALANTA_API_KEY=first-key\n" {
		t.Errorf("expected the original key to survive the refused overwrite, got %q", data)
	}
}

func TestRunSetup_ResetOverwritesExistingKeyFile(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	if err := runSetup([]string{"--key", "first-key"}); err != nil {
		t.Fatalf("first runSetup: %v", err)
	}
	if err := runSetup([]string{"--key", "second-key", "--reset"}); err != nil {
		t.Fatalf("reset runSetup: %v", err)
	}

	path := filepath.Join(home, ".config", "trustgate", "env")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "MALANTA_API_KEY=second-key\n" {
		t.Errorf("expected the reset key to win, got %q", data)
	}
}

// TestRunSetup_ResetTightensPermissiveExistingFile is the key-file-mode
// guard: a --reset over an existing, world-readable key file must end at
// mode 0600, not inherit the looser bits (os.WriteFile's mode arg applies
// only on create). POSIX-only — Windows uses ACLs, not Unix mode bits.
func TestRunSetup_ResetTightensPermissiveExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits not meaningful on Windows")
	}
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("MALANTA_API_KEY", "")

	dir := filepath.Join(home, ".config", "trustgate")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "env")
	// Pre-existing key file with permissive mode.
	if err := os.WriteFile(path, []byte("MALANTA_API_KEY=stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runSetup([]string{"--key", "fresh", "--reset"}); err != nil {
		t.Fatalf("runSetup --reset: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected --reset to tighten to 0600, got %o", perm)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "MALANTA_API_KEY=fresh\n" {
		t.Errorf("unexpected contents after reset: %q", data)
	}
}

func TestRunSetup_FallsBackToEnvVarWhenNoKeyFlag(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("MALANTA_API_KEY", "from-env-var")

	if err := runSetup(nil); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	path := filepath.Join(home, ".config", "trustgate", "env")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "MALANTA_API_KEY=from-env-var\n" {
		t.Errorf("expected the env-var key, got %q", data)
	}
}

// TestRunSetup_AutoDetectsGenericProviderEnvVar covers N1: when
// config.json selects the generic provider with an auth env var
// configured, setup stores the key under THAT env var instead of
// MALANTA_API_KEY, with no --env-var flag needed.
func TestRunSetup_AutoDetectsGenericProviderEnvVar(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	cfgDir := filepath.Join(home, ".config", "trustgate")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := `{
		"provider": "generic",
		"generic_provider": {
			"name": "virustotal",
			"base_url": "https://www.virustotal.com/api/v3",
			"mode": "single",
			"auth": {"header": "x-apikey", "env_var": "VIRUSTOTAL_API_KEY"},
			"allowed_hosts": ["www.virustotal.com"],
			"domain": {"path_template": "/domains/{domain}"}
		}
	}`
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runSetup([]string{"--key", "vt-secret"}); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	path := filepath.Join(home, ".config", "trustgate", "env")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written env file: %v", err)
	}
	if got := string(data); got != "VIRUSTOTAL_API_KEY=vt-secret\n" {
		t.Errorf("expected the auto-detected generic provider env var, got %q", got)
	}
}

// TestRunSetup_EnvVarFlagOverridesAutoDetection covers the --env-var
// escape hatch: it wins even when config.json would otherwise
// auto-detect a different (or no) provider.
func TestRunSetup_EnvVarFlagOverridesAutoDetection(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("MALANTA_API_KEY", "")

	if err := runSetup([]string{"--key", "custom-secret", "--env-var", "MY_VENDOR_API_KEY"}); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	path := filepath.Join(home, ".config", "trustgate", "env")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written env file: %v", err)
	}
	if got := string(data); got != "MY_VENDOR_API_KEY=custom-secret\n" {
		t.Errorf("expected --env-var to override auto-detection, got %q", got)
	}
}

func TestRunSetup_NoKeyAndNonInteractiveFails(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("MALANTA_API_KEY", "")

	// promptForKey reads from os.Stdin; in the test binary that's not a
	// terminal and (absent a pipe) reads produce EOF immediately, which
	// should surface as an error rather than writing an empty key.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()
	origStdin := os.Stdin
	os.Stdin = devNull
	defer func() { os.Stdin = origStdin }()

	if err := runSetup(nil); err == nil {
		t.Fatal("expected an error when no key is available and stdin is empty/non-interactive")
	}

	path := filepath.Join(home, ".config", "trustgate", "env")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected no key file to be written on failure, stat returned: %v", err)
	}
}
