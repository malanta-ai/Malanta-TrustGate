package extract

// FromMCP walks an arbitrary JSON value (the decoded MCP tool arguments) and
// collects every string field that contains a URL or host-like token. We do
// not assume any particular MCP server schema; instead we apply the same
// permissive regex used for shell commands, then Normalize.
//
// Deprecated for new code: prefer FromMCPEvent so the server registration URL
// itself is also subjected to the verdict cascade. FromMCP is retained for
// callers that genuinely only have the arguments object (and for the existing
// test suite). The MCP hook entrypoint always uses FromMCPEvent.
func FromMCP(v any) []string {
	var out []string
	walkJSON(v, func(s string) {
		out = append(out, extractHosts(s)...)
	})
	return Dedup(out)
}

// FromMCPEvent extracts candidate hosts from the full beforeMCPExecution
// payload — both the registered MCP `server` URL and the tool `arguments`
// payload. The server URL is the entry point through which every subsequent
// tool call routes; if it points at a malicious endpoint, every argument we'd
// otherwise inspect is already compromised. Keeping it out of the verdict
// cascade was a real bypass class — a hostile
// MCP server registered at "https://<malicious>/" could host any tools it
// liked and the inputs argument scan would not catch the registration host.
//
// The function applies the same regex+Normalize pipeline to both surfaces and
// returns the deduplicated union.
func FromMCPEvent(server string, args any) []string {
	return FromMCPCall([]string{server}, args)
}

// FromMCPCall generalizes FromMCPEvent to the CURRENT Cursor
// beforeMCPExecution payload, which no longer carries a single `server`
// URL. Cursor now populates one of several mutually-exclusive destination
// surfaces depending on the MCP server type — `url` for a remote HTTP MCP
// server, `command` for a stdio server, plus a legacy `server` field — and
// any of them may be empty (or, per a known Cursor bug, carry the config
// key name instead of the real destination). We feed every provided
// destination through the same regex+Normalize pipeline as the tool
// arguments and return the deduplicated union, so a malicious MCP
// destination host is caught regardless of which field Cursor filled in.
// Empty destination strings contribute nothing.
func FromMCPCall(destinations []string, args any) []string {
	var out []string
	for _, d := range destinations {
		out = append(out, extractHosts(d)...)
	}
	walkJSON(args, func(s string) {
		out = append(out, extractHosts(s)...)
	})
	return Dedup(out)
}

// GitHubFromMCPEvent is the GitHub-identity counterpart of FromMCPEvent.
func GitHubFromMCPEvent(server string, args any) GitHubRefs {
	return GitHubFromMCPCall([]string{server}, args)
}

// GitHubFromMCPCall extracts GitHub repository/owner identities from every
// destination surface of a beforeMCPExecution payload plus its tool
// arguments, using the same both-surfaces reasoning as FromMCPCall: an MCP
// server that hands the agent a repository to clone is as much a delivery
// path as a shell command is.
//
// argSets is variadic so a caller holding both the current `tool_input` and
// the legacy `arguments` object can pass both and get one de-duplicated
// result, rather than merging two separately-deduplicated ones. A nil entry
// contributes nothing.
func GitHubFromMCPCall(destinations []string, argSets ...any) GitHubRefs {
	var a githubAcc
	for _, d := range destinations {
		a.scan(d)
	}
	for _, args := range argSets {
		walkJSON(args, func(s string) {
			a.scan(s)
		})
	}
	return a.refs()
}

func walkJSON(v any, onString func(string)) {
	switch t := v.(type) {
	case string:
		onString(t)
	case []any:
		for _, item := range t {
			walkJSON(item, onString)
		}
	case map[string]any:
		for _, item := range t {
			walkJSON(item, onString)
		}
	}
}
