package extract

import (
	"reflect"
	"sort"
	"testing"
)

// TestFromShell_PercentEncodingScrub is the regression guard for the
// CTI-analyst FP report from 2026-05-28: a curl/HTTP API call with a
// URL-encoded `@` in a query parameter (`email=user%40host.tld`) had
// the bytes `40host.tld` extracted as a candidate hostname because
// the generic regex doesn't know `%40` is an encoded `@`. The
// extractor slid forward past `%` (which isn't in the userinfo
// character class), found `40` as a valid first label, and pulled
// `40host.tld` as if it were a real domain. Malanta then classified
// that synthetic host (`40mail.example` in the real report) as Malicious
// at 0.9885 and the fail-closed shell hook denied the command.
//
// The fix is a per-command scrub pass that blanks every `%XX`
// percent-encoded triple before the host regex runs. See
// percentEncodedRe doc-comment in shell.go for the full rationale,
// including the deliberate trade-off vs. URL-encoded-dot evasion
// (`evil%2Eexample%2Ecom` — which the extractor never caught
// anyway).
//
// Case names embed the encoded sequence so a failure points straight
// at which encoding class regressed.
func TestFromShell_PercentEncodingScrub(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			// The canonical report payload. Without the scrub, the
			// regex extracts `40mail.example`. With it, the only host
			// the cascade sees is the legitimate `mail.example` —
			// which is a benign domain Malanta classifies as
			// clean, so the call proceeds.
			name:    "%40 in query parameter (email-encoded)",
			command: `curl "https://api.example.com/getEmail?email=user%40mail.example"`,
			want:    []string{"api.example.com", "mail.example"},
		},
		{
			// The CTI-report shape: `dev_api "...?email=..."`
			// shell-function invocation. Before the fix the
			// extractor returned `40mail.example` (Malicious 0.9885
			// → deny). After the fix the extractor returns the
			// legitimate email-domain `mail.example` — Malanta
			// classifies it as clean and the cascade proceeds.
			// The cure isn't suppressing extraction entirely;
			// it's preventing the SYNTHETIC `40mail.example` host.
			name:    "%40 in dev_api email argument (CTI-report shape)",
			command: `dev_api "getExtendedAttributionByEmail?email=user%40mail.example"`,
			want:    []string{"mail.example"},
		},
		{
			// Lowercase hex form. The URL spec canonicalizes to
			// upper-case but real tools emit both; the regex must
			// catch both.
			name:    "%40 lowercase hex",
			command: `curl "https://api.example.com/?email=alice%40example.org"`,
			want:    []string{"api.example.com", "example.org"},
		},
		{
			// The scrub is single-pass by design: `%2540` is
			// `%40` only after a URL-decode pass, so blanking the
			// outer `%25` leaves the literal `40` remainder and
			// `40host.example` extracts. Iterating the scrub until
			// no `%XX` patterns remain would resolve it, and no
			// production report has needed that; the loop belongs in
			// shell.go::FromShellInDir step 1c if one ever does.
			// Pinned here so a change to this behavior is a
			// deliberate one.
			name:    "%2540 (double-encoded @), single-pass scrub",
			command: `curl "https://api.example.com/?email=alice%2540host.example"`,
			want:    []string{"40host.example", "api.example.com"},
		},
		{
			// Multiple encoded chars in the same URL: `%2F` (path
			// `/`), `%40` (@), `%3A` (port `:`). None should
			// produce a spurious host; the legit host stays.
			name:    "multiple encoded specials",
			command: `wget 'https://api.example.com/path%2Fto%2Fuser%40provider.example%3A8080/x'`,
			want:    []string{"api.example.com", "provider.example"},
		},
		{
			// Real %20 (space) inside a query value. No host
			// extraction collateral — just confirms the scrub
			// doesn't accidentally introduce new hits.
			name:    "%20 (encoded space) is a no-op for extraction",
			command: `curl "https://api.example.com/search?q=foo%20bar"`,
			want:    []string{"api.example.com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
			sort.Strings(got)
			sort.Strings(tc.want)
			if !reflect.DeepEqual(coerceNil(got), coerceNil(tc.want)) {
				t.Errorf("FromShell(%q) = %v, want %v",
					tc.command, got, tc.want)
			}
		})
	}
}

// TestFromShell_PercentEncodingNoFalseNegativeOnRealHosts guards the
// classes of innocuous percent-sequences that appear in shell
// commands unrelated to URL encoding (printf format specifiers, git
// pretty-format directives, awk modulo expressions). The scrub MUST
// only fire on the literal `%XX` (two-hex-digit) shape; anything
// that's `%` followed by non-hex characters stays as-is, and bare
// hosts in the same command continue to extract.
func TestFromShell_PercentEncodingNoFalseNegativeOnRealHosts(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			// `%s` is not a `%XX` hex pair (`s` is non-hex). The
			// scrub must leave it alone. (We use a `curl`
			// segment first so the URL extracts before the
			// `printf` segment — printf itself is in
			// nonNetworkBins so a printf-only segment would be
			// suppressed regardless; this test confirms the
			// scrub doesn't FALSELY catch %s elsewhere.)
			name:    "printf %s format specifier in pipeline with real URL",
			command: `curl https://api.example.com/x && printf '%s\n' "done"`,
			want:    []string{"api.example.com"},
		},
		{
			// `%H %an %ae` — `%ae` IS two hex digits (a, e). The
			// scrub blanks it. That's fine for git's
			// pretty-format string (it's not a host either way),
			// and the real URL in the same command still
			// extracts.
			name:    "git pretty-format with %ae and real URL",
			command: `git log --pretty=format:'%H %an %ae' && curl https://api.example.com/x`,
			want:    []string{"api.example.com"},
		},
		{
			// Awk modulo against a percent literal not followed by
			// two hex digits.
			name:    "awk modulo expression with real host nearby",
			command: `awk 'BEGIN{print 7%2; exit}' && curl https://api.example.com/x`,
			want:    []string{"api.example.com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
			sort.Strings(got)
			sort.Strings(tc.want)
			if !reflect.DeepEqual(coerceNil(got), coerceNil(tc.want)) {
				t.Errorf("FromShell(%q) = %v, want %v",
					tc.command, got, tc.want)
			}
		})
	}
}

// coerceNil normalizes a nil slice to an empty slice so reflect.DeepEqual
// doesn't fire on `nil != []string{}`. Local to this test file because the
// extractor is allowed to return either form (the cascade dedupes
// downstream); the readfile_script_context_test.go helper of the same
// name lives in a separate file and is not exported.
func coerceNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
