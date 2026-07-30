package config

import (
	"os"
	"path/filepath"
	"testing"
)

func withSystemEnvFile(t *testing.T, contents string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "system-env")
	if contents != "" {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	orig := systemEnvPath
	systemEnvPath = path
	t.Cleanup(func() { systemEnvPath = orig })
}

func TestEnforceLockedEnv_NoSystemFileIsNoOp(t *testing.T) {
	withSystemEnvFile(t, "") // file doesn't exist
	t.Setenv("TRUSTGATE_FAIL_CLOSED", "false")
	EnforceLockedEnv()
	if os.Getenv("TRUSTGATE_FAIL_CLOSED") != "false" {
		t.Error("expected no change when the system env file doesn't exist")
	}
}

func TestEnforceLockedEnv_NoLockDeclarationIsNoOp(t *testing.T) {
	withSystemEnvFile(t, "TRUSTGATE_FAIL_CLOSED=true\n") // no TRUSTGATE_LOCKED_KEYS
	t.Setenv("TRUSTGATE_FAIL_CLOSED", "false")
	EnforceLockedEnv()
	if os.Getenv("TRUSTGATE_FAIL_CLOSED") != "false" {
		t.Error("expected the user's value to survive when the system file sets a value but doesn't declare it locked")
	}
}

func TestEnforceLockedEnv_LockedKeyOverridesUserValue(t *testing.T) {
	withSystemEnvFile(t, "TRUSTGATE_LOCKED_KEYS=TRUSTGATE_FAIL_CLOSED\nTRUSTGATE_FAIL_CLOSED=true\n")
	t.Setenv("TRUSTGATE_FAIL_CLOSED", "false") // what a user-owned layer set
	EnforceLockedEnv()
	if os.Getenv("TRUSTGATE_FAIL_CLOSED") != "true" {
		t.Errorf("expected the locked system value (true) to win, got %q", os.Getenv("TRUSTGATE_FAIL_CLOSED"))
	}
}

func TestEnforceLockedEnv_UnlockedKeysAreUntouched(t *testing.T) {
	withSystemEnvFile(t, "TRUSTGATE_LOCKED_KEYS=TRUSTGATE_FAIL_CLOSED\nTRUSTGATE_FAIL_CLOSED=true\nTRUSTGATE_MODE=off\n")
	t.Setenv("TRUSTGATE_MODE", "enforce") // TRUSTGATE_MODE is NOT in TRUSTGATE_LOCKED_KEYS
	EnforceLockedEnv()
	if os.Getenv("TRUSTGATE_MODE") != "enforce" {
		t.Errorf("expected TRUSTGATE_MODE to stay as the user set it (not locked), got %q", os.Getenv("TRUSTGATE_MODE"))
	}
}

func TestEnforceLockedEnv_KeyNotInLockableAllowlistIsIgnored(t *testing.T) {
	// PATH is obviously not a trustgate key; even if named in
	// TRUSTGATE_LOCKED_KEYS, it must never be touched.
	withSystemEnvFile(t, "TRUSTGATE_LOCKED_KEYS=PATH\nPATH=/evil/bin\n")
	origPath := os.Getenv("PATH")
	EnforceLockedEnv()
	if os.Getenv("PATH") != origPath {
		t.Error("expected PATH to be untouched — it is not in the lockableKeys allowlist")
	}
}

func TestEnforceLockedEnv_LockedKeyWithNoValueInSystemFileIsSkipped(t *testing.T) {
	// TRUSTGATE_PROVIDER is declared locked but never given a value in
	// the system file — there's nothing to lock it TO, so the user's
	// existing value must survive untouched (not unset).
	withSystemEnvFile(t, "TRUSTGATE_LOCKED_KEYS=TRUSTGATE_PROVIDER\n")
	t.Setenv("TRUSTGATE_PROVIDER", "generic")
	EnforceLockedEnv()
	if os.Getenv("TRUSTGATE_PROVIDER") != "generic" {
		t.Errorf("expected the user's TRUSTGATE_PROVIDER to survive an empty lock declaration, got %q", os.Getenv("TRUSTGATE_PROVIDER"))
	}
}

func TestEnforceLockedEnv_UserCannotSelfDeclareALock(t *testing.T) {
	// A user-owned layer setting TRUSTGATE_LOCKED_KEYS in process env
	// (simulating .env or ~/.config/trustgate/env) must have NO effect —
	// only the system file's OWN TRUSTGATE_LOCKED_KEYS is consulted.
	withSystemEnvFile(t, "") // no system file at all
	t.Setenv("TRUSTGATE_LOCKED_KEYS", "TRUSTGATE_FAIL_CLOSED")
	t.Setenv("TRUSTGATE_FAIL_CLOSED", "false")
	EnforceLockedEnv()
	if os.Getenv("TRUSTGATE_FAIL_CLOSED") != "false" {
		t.Error("expected a user-declared TRUSTGATE_LOCKED_KEYS (not from the system file) to have no effect")
	}
}

func TestLockedKeys_ReportsOnlyLockedAndValuedKeys(t *testing.T) {
	withSystemEnvFile(t, "TRUSTGATE_LOCKED_KEYS=TRUSTGATE_FAIL_CLOSED,TRUSTGATE_MODE,PATH\nTRUSTGATE_FAIL_CLOSED=true\n")
	got := LockedKeys()
	if len(got) != 1 || got[0] != "TRUSTGATE_FAIL_CLOSED" {
		t.Errorf("expected only TRUSTGATE_FAIL_CLOSED (has a value; TRUSTGATE_MODE has none, PATH isn't lockable), got %v", got)
	}
}

func TestLockedKeys_EmptyWhenNoSystemFile(t *testing.T) {
	withSystemEnvFile(t, "")
	if got := LockedKeys(); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

// --- workspace-cwd .env is off the production path by default ---

func TestEnvFiles_ExcludesCwdDotenvByDefault(t *testing.T) {
	// A hostile workspace drops a .env in cwd; without the explicit opt-in
	// it must NOT appear in the dotenv chain, so godotenv.Overload never
	// merges it into the process environment.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("MALANTA_API_BASE_URL=https://evil.example/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chdir(t, dir)
	os.Unsetenv("TRUSTGATE_ALLOW_CWD_DOTENV")
	for _, p := range EnvFiles() {
		if p == ".env" {
			t.Fatal("expected cwd .env to be excluded by default, but it was listed")
		}
	}
}

func TestEnvFiles_IncludesCwdDotenvWhenOptedIn(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("X=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chdir(t, dir)
	t.Setenv("TRUSTGATE_ALLOW_CWD_DOTENV", "1")
	found := false
	for _, p := range EnvFiles() {
		if p == ".env" {
			found = true
		}
	}
	if !found {
		t.Error("expected cwd .env to be included when TRUSTGATE_ALLOW_CWD_DOTENV=1")
	}
}

func TestEnvFiles_CwdDotenvCannotSelfEnable(t *testing.T) {
	// The opt-in must come from the AMBIENT env, never from the .env being
	// gated — a workspace .env that sets TRUSTGATE_ALLOW_CWD_DOTENV=1 must
	// not thereby enable its own loading. EnvFiles reads only os.Getenv, so
	// with the ambient var unset the file stays excluded regardless of its
	// contents.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("TRUSTGATE_ALLOW_CWD_DOTENV=1\nMALANTA_API_BASE_URL=https://evil.example/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chdir(t, dir)
	os.Unsetenv("TRUSTGATE_ALLOW_CWD_DOTENV")
	for _, p := range EnvFiles() {
		if p == ".env" {
			t.Fatal("a .env that sets the opt-in flag must not enable its own loading")
		}
	}
}

func TestLockableKeys_IncludeDestinationAndPolicyKeys(t *testing.T) {
	for _, key := range []string{
		"MALANTA_API_BASE_URL", "MALANTA_API_HOST_ALLOWLIST",
		"TRUSTGATE_BLOCK_LABELS", "TRUSTGATE_ALLOW_LABELS",
		"TRUSTGATE_CACHE_DIR", "TRUSTGATE_LOG_PATH",
		"TRUSTGATE_ATR_RULES_DIR", "TRUSTGATE_TOOLUSE_ALLOWLIST",
	} {
		if !lockableKeys[key] {
			t.Errorf("expected %s to be lockable", key)
		}
	}
}

// chdir switches into dir for the duration of the test and restores the
// prior working directory afterward.
func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}
