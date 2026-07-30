package extract

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// These tests cover the workspace-roots containment logic added to the
// read-file hook. The threat closed: a hostile
// MCP server or compromised tool input could rewrite Cursor's read-file
// payload to point at ~/.aws/credentials or /etc/passwd, and Malanta
// would be asked about whatever hostnames the regex pulled out of that
// content. Cursor sends workspace_roots on every envelope; we use that
// as the authoritative "is this path in my workspace?" check.

func TestFromFileContentInRoots_InWorkspace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(path, []byte("--index-url https://mirror.example/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := FromFileContentInRoots(path, "--index-url https://mirror.example/\n", []string{dir})
	want := []string{"mirror.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromFileContentInRoots_OutOfWorkspace(t *testing.T) {
	workspace := t.TempDir()
	other := t.TempDir()
	path := filepath.Join(other, "requirements.txt")
	if err := os.WriteFile(path, []byte("--index-url https://malicious.example/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := FromFileContentInRoots(path, "--index-url https://malicious.example/\n", []string{workspace})
	if got != nil {
		t.Errorf("got %v, want nil (out of workspace)", got)
	}
}

func TestFromFileContentInRoots_SymlinkEscape(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	// Place a real file outside the workspace and create a symlink
	// INSIDE the workspace that points at it. The hook must follow the
	// symlink and refuse to scan because the resolved target is outside
	// the workspace.
	real := filepath.Join(outside, "requirements.txt")
	if err := os.WriteFile(real, []byte("--index-url https://escape.example/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(workspace, "requirements.txt")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := FromFileContentInRoots(link, "--index-url https://escape.example/\n", []string{workspace})
	if got != nil {
		t.Errorf("got %v, want nil (symlink-escape)", got)
	}
}

func TestFromFileContentInRoots_MultiRoot(t *testing.T) {
	root1 := t.TempDir()
	root2 := t.TempDir()
	path := filepath.Join(root2, "package.json")
	if err := os.WriteFile(path, []byte(`{"registry":"https://multi.example/"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := FromFileContentInRoots(path, `{"registry":"https://multi.example/"}`, []string{root1, root2})
	want := []string{"multi.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromFileContentInRoots_EmptyRootsIsNoConstraint(t *testing.T) {
	// Test convenience: empty roots == bypass the containment check.
	// Keeps the helper friendly for unit tests that don't carry a
	// workspace and matches legacy FromFileContent behavior so the
	// hook still produces a verdict if Cursor ever drops the
	// workspace_roots field from the envelope.
	got := FromFileContentInRoots("/some/path/requirements.txt", "--index-url https://noroot.example/\n", nil)
	want := []string{"noroot.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromFileContentInRoots_NonAllowlistedPathSkippedRegardlessOfRoots(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.go")
	// Inside the workspace, but main.go is not on the allowlist — the
	// allowlist gate fires before any extraction happens.
	got := FromFileContentInRoots(path,
		"package main\nimport \"context\"\nvar _ = context.Background()\n",
		[]string{dir})
	if got != nil {
		t.Errorf("got %v, want nil (.go not on allowlist)", got)
	}
}

func TestFromFileContentInRoots_RootEqualsPath(t *testing.T) {
	// Edge case: the requested path IS the workspace root file itself
	// (in single-file workspaces, or a weird edge case where Cursor
	// passes the root). Should still be considered contained.
	dir := t.TempDir()
	root := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(root, []byte("--index-url https://equal.example/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := FromFileContentInRoots(root, "--index-url https://equal.example/\n", []string{root})
	want := []string{"equal.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}
