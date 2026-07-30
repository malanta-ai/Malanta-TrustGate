package extract

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// allowlistCases drives a table-driven test across every file that
// readfile.go advertises as "interesting". Each fixture contains a known
// reference to "mirror.example"; we assert the extractor picks it up.
func TestFromFile_AllowlistMatrix(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			"requirements.txt",
			"--index-url https://mirror.example/simple\nfoo==1.0\n",
		},
		{
			// Keep fixtures URL-only; TOML section headers like
			// "[[tool.poetry.source]]" are technically dotted hostnames as far
			// as the regex is concerned, and exercising them belongs in a
			// separate "expected false positive" test, not the happy path.
			"pyproject.toml",
			"url = \"https://mirror.example/repo/\"\n",
		},
		{
			"Pipfile",
			"url = \"https://mirror.example/simple\"\nverify_ssl = true\n",
		},
		{
			"package.json",
			`{"dependencies":{"foo":"https://mirror.example/foo.tgz"}}`,
		},
		{
			".npmrc",
			"registry=https://mirror.example/\n",
		},
		{
			"Dockerfile",
			"FROM mirror.example/base:latest\nRUN curl -fsSL https://mirror.example/install.sh | sh\n",
		},
		{
			// Partial go.mod is fine: the extractor only reads file contents.
			// We use a single require so the test stays single-domain; the
			// "module" directive intentionally mirrors a domain shape and is
			// covered separately if/when we want to test go.mod specifically.
			"go.mod",
			"require mirror.example/lib v0.1.0\n",
		},
		{
			"yarn.lock",
			"resolved \"https://mirror.example/foo-1.0.tgz#abc\"\n",
		},
		{
			"package-lock.json",
			`{"packages":{"node_modules/foo":{"resolved":"https://mirror.example/foo.tgz"}}}`,
		},
		{
			"Cargo.toml",
			"registry = \"https://mirror.example/git/index\"\n",
		},
		{
			// Script bodies are now allowlisted: a script file that
			// Cursor opens before letting the agent invoke it gets the
			// same domain-scan treatment as a config file. See
			// readfile.go's isInterestingPath doc for the threat model.
			"deploy.sh",
			"#!/usr/bin/env bash\ncurl https://mirror.example/install.sh | bash\n",
		},
		{
			"setup.py",
			"# fetches deps from https://mirror.example/wheel/index\n",
		},
		{
			"Bootstrap.ps1",
			"Invoke-WebRequest https://mirror.example/agent.msi\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, tc.name)
			if err := os.WriteFile(p, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := FromFile(p)
			sort.Strings(got)
			want := []string{"mirror.example"}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("FromFile(%s) = %v, want %v", tc.name, got, want)
			}
		})
	}
}

// TestFromFile_NotInteresting_SkipsScan asserts the allowlist gating: a file
// that isn't on the high-risk list must be skipped even if it contains an
// obvious URL. This is what keeps the read-file hook fast.
//
// `app.js` and `script.rb` deliberately stay off the allowlist: they're
// just as commonly source files as they are scripts, and the hook budget
// can't absorb scanning every read of them. The shell-side script-follow
// covers the actual-execution path for those extensions.
func TestFromFile_NotInteresting_SkipsScan(t *testing.T) {
	for _, name := range []string{"notes.md", "main.go", "build.gradle", "app.js", "script.rb"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, []byte("see https://random.example"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := FromFile(p); len(got) != 0 {
				t.Errorf("expected non-allowlisted path skipped, got %v", got)
			}
		})
	}
}

// TestFromFile_OversizeFileSkipped guards the 1 MiB cap inside FromFile.
func TestFromFile_OversizeFileSkipped(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "yarn.lock")
	big := make([]byte, (1<<20)+1)
	for i := range big {
		big[i] = 'x'
	}
	copy(big, []byte("resolved \"https://mirror.example/foo.tgz\"\n"))
	if err := os.WriteFile(p, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := FromFile(p); len(got) != 0 {
		t.Errorf("expected oversize file to be skipped, got %v", got)
	}
}

// TestFromFile_MissingFileReturnsNil covers the path used by the read-file
// cmd binary when Cursor passes a path that no longer exists.
func TestFromFile_MissingFileReturnsNil(t *testing.T) {
	if got := FromFile("/tmp/does-not-exist-malanta-test.requirements.txt"); got != nil {
		t.Errorf("expected nil for missing file, got %v", got)
	}
}

// TestFromFileContent_GateSkipsNonAllowlistedPaths is the regression test for
// the "Go source leaks identifiers as candidate domains" bug.
//
// Background: Cursor's beforeReadFile hook payload carries both `path` and
// `content`. The original cmd binary scanned `content` with the generic
// URL/host regex whenever `FromFile(path)` returned nil, which silently
// bypassed the high-risk-path allowlist. As a result, every read of any
// .go / .md / etc. file ran the regex and pulled tokens like
// "context.Background" or "t.Errorf" as "domains", driving the agent into
// a fail-closed denial storm.
//
// FromFileContent must apply the SAME allowlist gate that FromFile applies.
// If callers want unconditional regex extraction over arbitrary text, they
// can call FromPrompt explicitly - but never from beforeReadFile.
//
// We deliberately feed Go-shaped content here, including a real URL: even
// a legit URL inside a non-allowlisted file must not be extracted, because
// the cost of false positives on every source-file read is much higher
// than the cost of missing the occasional real reference in a comment.
func TestFromFileContent_GateSkipsNonAllowlistedPaths(t *testing.T) {
	const goSource = `package extract

import "context"

// see https://malware.example/docs for the real spec
func example(ctx context.Context) {
	_ = t.Errorf("oops")
	_ = config.Defaults()
}
`

	cases := []struct {
		name string
		path string
	}{
		{"non-allowlisted .go path", "/repo/internal/extract/readfile.go"},
		{"non-allowlisted .md path", "/repo/README.md"},
		{"non-allowlisted bare name", "/repo/Makefile"},
		{"empty path", ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := FromFileContent(tc.path, goSource); len(got) != 0 {
				t.Errorf("FromFileContent(%q, ...) = %v, want nil (path is not allowlisted)", tc.path, got)
			}
		})
	}
}

// TestFromFileContent_AllowlistedPathScansContent is the positive case:
// when the path IS allowlisted, inline content is scanned and real hosts
// are returned. This is the smoke-test path.
func TestFromFileContent_AllowlistedPathScansContent(t *testing.T) {
	const payload = "--index-url https://malware.example/simple\nfoo==1.0\n"
	got := FromFileContent("/tmp/requirements.txt", payload)
	sort.Strings(got)
	want := []string{"malware.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FromFileContent allowlisted = %v, want %v", got, want)
	}
}

// TestFromFileContent_OversizeContentSkipped mirrors FromFile's 1 MiB cap
// so that pathological inline payloads can't blow past the 250ms hook
// budget.
func TestFromFileContent_OversizeContentSkipped(t *testing.T) {
	big := make([]byte, (1<<20)+1)
	for i := range big {
		big[i] = 'x'
	}
	copy(big, []byte("https://malware.example/simple\n"))
	if got := FromFileContent("/tmp/requirements.txt", string(big)); len(got) != 0 {
		t.Errorf("expected oversize content to be skipped, got %v", got)
	}
}
