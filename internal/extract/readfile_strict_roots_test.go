package extract

import (
	"os"
	"path/filepath"
	"testing"
)

// These tests cover TRUSTGATE_READFILE_STRICT_WORKSPACE_ROOTS, the
// opt-in "non-permissive empty workspace_roots" behavior. Default
// (unset/false) behavior must be unchanged (empty roots = unconstrained,
// so CI harnesses and early Cursor versions that don't send
// workspace_roots still get scanned).

func TestIsContained_EmptyRoots_DefaultIsPermissive(t *testing.T) {
	if !isContained("/anywhere/requirements.txt", nil) {
		t.Error("expected empty roots to be permissive by default (strict flag unset)")
	}
}

func TestIsContained_EmptyRoots_StrictIsNonPermissive(t *testing.T) {
	t.Setenv("TRUSTGATE_READFILE_STRICT_WORKSPACE_ROOTS", "true")
	if isContained("/anywhere/requirements.txt", nil) {
		t.Error("expected empty roots to be NON-permissive when the strict flag is set")
	}
}

func TestIsContained_StrictModeDoesNotAffectNonEmptyRoots(t *testing.T) {
	t.Setenv("TRUSTGATE_READFILE_STRICT_WORKSPACE_ROOTS", "true")
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !isContained(path, []string{dir}) {
		t.Error("expected a genuinely in-workspace path to still pass containment under strict mode")
	}
	if isContained(filepath.Join(t.TempDir(), "requirements.txt"), []string{dir}) {
		t.Error("expected a genuinely out-of-workspace path to still fail containment under strict mode")
	}
}

func TestFromFileContentInRoots_EmptyRootsStrictModeSkipsExtraction(t *testing.T) {
	t.Setenv("TRUSTGATE_READFILE_STRICT_WORKSPACE_ROOTS", "true")
	got := FromFileContentInRoots("/tmp/requirements.txt", "--index-url https://malicious.example/\n", nil)
	if got != nil {
		t.Errorf("expected nil (extraction skipped) when workspace_roots is empty under strict mode, got %v", got)
	}
}

func TestIsPathInWorkspace_EmptyRootsStrictMode(t *testing.T) {
	t.Setenv("TRUSTGATE_READFILE_STRICT_WORKSPACE_ROOTS", "true")
	if IsPathInWorkspace("/tmp/anything", nil) {
		t.Error("expected IsPathInWorkspace to be non-permissive on empty roots under strict mode")
	}
}
