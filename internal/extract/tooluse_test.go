package extract

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// TestWebFetchMalformed pins the malformed-input boundary: a WebFetch input that can't be
// decoded / has no url / has a non-absolute url is malformed (deny under
// fail-closed/strict), while a well-formed absolute URL — even to a
// non-routable host — is NOT malformed (it just has no routable host).
func TestWebFetchMalformed(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid routable", `{"url":"https://example.com/x"}`, false},
		{"valid localhost (well-formed, non-routable)", `{"url":"http://localhost:8080/health"}`, false},
		{"missing url", `{"other":"x"}`, true},
		{"empty url", `{"url":""}`, true},
		{"relative url", `{"url":"/just/a/path"}`, true},
		{"scheme-only / no host", `{"url":"https://"}`, true},
		{"malformed JSON", `not json`, true},
		{"renamed field (schema drift)", `{"uri":"https://example.com/x"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := WebFetchMalformed(json.RawMessage(tc.input)); got != tc.want {
				t.Errorf("WebFetchMalformed(%s) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestFromToolUse_WebFetch(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{
			"happy path https URL",
			`{"url":"https://malware.example/payload.exe"}`,
			[]string{"malware.example"},
		},
		{
			"http URL with path and query",
			`{"url":"http://example.com/x?y=1"}`,
			[]string{"example.com"},
		},
		{
			"case-folded host",
			`{"url":"https://Malware.Example/Path"}`,
			[]string{"malware.example"},
		},
		{
			// URL with an IDN host: the NormalizeURL pipeline lowercases
			// and ASCII-folds via x/net/idna so the domain Malanta sees
			// matches the on-the-wire ASCII form.
			"idn host",
			`{"url":"https://xn--bcher-kva.example/"}`,
			[]string{"xn--bcher-kva.example"},
		},
		{
			"localhost is dropped by normalize",
			`{"url":"http://localhost:8080/health"}`,
			nil,
		},
		{
			"missing url field",
			`{"method":"GET"}`,
			nil,
		},
		{
			"malformed JSON",
			`{not json`,
			nil,
		},
		{
			"empty input",
			``,
			nil,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := FromToolUse("WebFetch", json.RawMessage(tc.input))
			sort.Strings(got)
			sort.Strings(tc.want)
			// Treat nil and empty-slice equivalently; the cmd binary's
			// "no domains -> allow" short-circuit doesn't distinguish.
			if (len(got) == 0) != (len(tc.want) == 0) ||
				(len(got) > 0 && !reflect.DeepEqual(got, tc.want)) {
				t.Errorf("FromToolUse(WebFetch, %s) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestFromToolUse_WebSearch(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{
			"search term containing a URL",
			`{"search_term":"how to use https://malware.example safely"}`,
			[]string{"malware.example"},
		},
		{
			"search term containing a bare host",
			`{"search_term":"reviews of malware.example vs duck.example"}`,
			[]string{"malware.example", "duck.example"},
		},
		{
			"plain English without a host",
			`{"search_term":"how does kubernetes scheduling work"}`,
			nil,
		},
		{
			"empty search_term",
			`{"search_term":""}`,
			nil,
		},
		{
			"malformed JSON",
			`{"search_term":`,
			nil,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := FromToolUse("WebSearch", json.RawMessage(tc.input))
			sort.Strings(got)
			sort.Strings(tc.want)
			if (len(got) == 0) != (len(tc.want) == 0) ||
				(len(got) > 0 && !reflect.DeepEqual(got, tc.want)) {
				t.Errorf("FromToolUse(WebSearch, %s) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestFromToolUse_NonInspectedTools is the regression guard for the
// short-circuit branch: any tool name we DON'T explicitly inspect must
// produce no candidate domains so the cmd binary will allow without
// burning the hook budget on a redundant Malanta lookup.
//
// Shell / Read / MCP-shaped tool names are covered by their own dedicated
// hook events (beforeShellExecution / beforeReadFile / beforeMCPExecution);
// Glob / Grep / Write / Edit / Task don't carry network-shaped input. All
// of them belong in the default branch here.
func TestFromToolUse_NonInspectedTools(t *testing.T) {
	skipped := []string{
		"Shell", "Read", "Write", "Edit", "Glob", "Grep",
		"Task", "TodoWrite", "AskQuestion",
		// MCP tools commonly come through as "mcp__<server>__<tool>"; we
		// treat the entire MCP family as already-covered.
		"mcp__github__create_issue",
	}
	// Use a payload that *would* contain a host if the dispatcher chose
	// to read it; the point is that for unrecognized tool names we must
	// not even try.
	payload := json.RawMessage(`{"url":"https://malware.example/x","search_term":"https://malware.example/x"}`)
	for _, name := range skipped {
		if got := FromToolUse(name, payload); len(got) != 0 {
			t.Errorf("FromToolUse(%q, ...) = %v, want nil (tool not inspected at preToolUse)", name, got)
		}
	}
}
