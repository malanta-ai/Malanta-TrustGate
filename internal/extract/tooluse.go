package extract

import (
	"encoding/json"
	"net/url"
	"strings"
)

// FromToolUse dispatches by tool_name to the right extractor for Cursor's
// built-in agent tools, returning candidate domains the tool would touch.
//
// This is the gap-closer for the `preToolUse` hook event, which Cursor fires
// generically for *every* tool the agent runs (Shell, Read, Write, MCP, Task,
// WebFetch, WebSearch, ...). The four other hook binaries cover the
// already-dedicated events (`beforeShellExecution`, `beforeReadFile`,
// `beforeMCPExecution`, `beforeSubmitPrompt`); this dispatcher targets only
// the built-in tools that those events DO NOT cover and that touch the
// network on the agent's behalf - principally WebFetch and WebSearch.
//
// Design choices worth knowing about:
//
//   - Narrow allowlist by tool name. The dispatcher returns nil for any tool
//     it doesn't explicitly recognize. That means the preToolUse hook
//     binary will short-circuit-allow for Shell / Read / MCP / Glob / Grep /
//     Write / Edit / Task / ... - either because a dedicated event covers
//     them (and double-checking wastes the 250 ms hook budget), or because
//     they don't carry network-shaped inputs at all.
//
//   - `tool_input` is opaque JSON. Cursor's preToolUse payload delivers the
//     tool input as a JSON object that varies by tool (WebFetch has `url`,
//     WebSearch has `search_term`, etc.). We unmarshal into a per-tool
//     struct rather than walking a generic map so each extractor is
//     readable and type-safe.
//
//   - Errors are non-fatal. A malformed input JSON, a missing field, or a
//     URL that doesn't parse all collapse to an empty result. The cmd
//     binary then short-circuits to allow, which is the documented
//     fail-open behavior for input shapes we can't reason about. The
//     fail-closed mode in the verdict cascade still kicks in if the API
//     errors *after* we've extracted a domain.
func FromToolUse(toolName string, input json.RawMessage) []string {
	switch toolName {
	case "WebFetch":
		return fromWebFetch(input)
	case "WebSearch":
		return fromWebSearch(input)
	default:
		return nil
	}
}

// GitHubFromToolUse is the GitHub-identity counterpart of FromToolUse: it
// reads the same per-tool input schemas and returns any repository/owner
// the tool would touch. WebFetch's `url` covers the agent fetching a
// repository page or raw file directly; WebSearch's `search_term` covers
// the agent looking one up before fetching it.
func GitHubFromToolUse(toolName string, input json.RawMessage) GitHubRefs {
	var field string
	switch toolName {
	case "WebFetch":
		var p struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(input, &p); err != nil {
			return GitHubRefs{}
		}
		field = p.URL
	case "WebSearch":
		var p struct {
			SearchTerm string `json:"search_term"`
		}
		if err := json.Unmarshal(input, &p); err != nil {
			return GitHubRefs{}
		}
		field = p.SearchTerm
	default:
		return GitHubRefs{}
	}
	return GitHubFromText(field)
}

// dedicatedHookTools are tool names covered by a MORE SPECIFIC hook
// elsewhere in this project — beforeShellExecution (full command text),
// beforeMCPExecution (server + arguments), beforeReadFile (path +
// content) — each of which sees far richer context than preToolUse's
// generic tool_input ever carries. isDedicatedHookTool must return true
// for these so preToolUse's strict mode (see IsRecognizedTool) never
// re-denies a tool call its own dedicated hook already evaluated with
// better information.
func isDedicatedHookTool(toolName string) bool {
	switch toolName {
	case "Shell", "Read", "TabRead":
		return true
	}
	return strings.HasPrefix(toolName, "MCP:")
}

// knownSafeTools is a hand-maintained, BEST-EFFORT list of built-in tool
// names with no network path of their own — local file/state operations
// only. Deliberately NOT presented as exhaustive: Cursor's own hooks
// documentation describes its preToolUse matcher tool-name list as
// including examples, not enumerating every tool, and new tools can be
// added over time without this list being updated in lockstep. This is
// why IsRecognizedTool's strict mode is opt-in (Config.ToolUseStrict,
// default false) and pairs with an operator-extensible
// Config.ToolUseAllowlist — see docs/admin.md.
var knownSafeTools = map[string]bool{
	"Write":        true,
	"Delete":       true,
	"Grep":         true,
	"Glob":         true,
	"TodoWrite":    true,
	"SwitchMode":   true,
	"ReadLints":    true,
	"EditNotebook": true,
	"AskQuestion":  true,
}

// IsRecognizedTool reports whether toolName is one FromToolUse actively
// inspects, is covered by a more specific dedicated hook, is in the
// hand-maintained safe list, or is in the operator-supplied
// extraAllowlist (case-insensitive). Consulted ONLY by the preToolUse
// binary's optional strict mode: normal mode allows any unrecognized
// tool through unconditionally (this function's whole reason for
// existing is to give strict-mode operators a place to extend coverage
// without a code change when it false-denies a legitimate tool it
// doesn't know about yet).
func IsRecognizedTool(toolName string, extraAllowlist []string) bool {
	if toolName == "WebFetch" || toolName == "WebSearch" {
		return true
	}
	if isDedicatedHookTool(toolName) {
		return true
	}
	if knownSafeTools[toolName] {
		return true
	}
	for _, t := range extraAllowlist {
		if strings.EqualFold(strings.TrimSpace(t), toolName) {
			return true
		}
	}
	return false
}

// WebFetchMalformed reports whether a WebFetch tool_input is malformed or
// missing a usable destination URL. WebFetch's entire purpose is
// to hit a caller-supplied absolute URL, so an invocation whose input can't
// be decoded, has no `url`, or whose `url` is not an absolute URL with a
// host is either evasion or a Cursor schema drift (e.g. the field getting
// renamed) that would silently remove WebFetch enforcement. The preToolUse
// hook denies such input under fail-closed/strict policy rather than
// allowing it through.
//
// Crucially this returns FALSE for a well-formed absolute URL whose host is
// intentionally dropped by Normalize (loopback / RFC1918 / link-local) — a
// WebFetch to http://localhost:8080 is well-formed and must not be treated
// as malformed; it simply has no routable host to check.
func WebFetchMalformed(input json.RawMessage) bool {
	var p struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(input, &p); err != nil {
		return true
	}
	raw := strings.TrimSpace(p.URL)
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	return !u.IsAbs() || u.Hostname() == ""
}

// fromWebFetch extracts the destination host from a WebFetch tool input.
// Schema: { "url": "<absolute URL>" }. Anything else returns nil so the
// caller short-circuits to allow.
func fromWebFetch(input json.RawMessage) []string {
	var p struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(input, &p); err != nil || p.URL == "" {
		return nil
	}
	if h := NormalizeURL(p.URL); h != "" {
		return []string{h}
	}
	return nil
}

// fromWebSearch extracts any domain mentioned in a WebSearch search_term.
// Schema: { "search_term": "<free-form text>" }.
//
// Unlike WebFetch (which directly accesses the URL), WebSearch's target is
// the search engine - the search term is passed to a third party. We still
// extract here because (a) the agent is very likely to follow a search hit
// with a WebFetch on the same domain, and consulting Malanta now beats
// chasing the verdict at fetch time, and (b) the audit trail benefits from
// recording "the agent searched for $domain" alongside the eventual fetch.
//
// The shared extractHosts pipeline applies the same PSL gate and URL/host
// regex used everywhere else, so search terms like "is 777tiger.com bad?"
// produce the same candidate set the prompt hook would have produced. The
// downstream verdict cascade and label policy decide whether to block.
func fromWebSearch(input json.RawMessage) []string {
	var p struct {
		SearchTerm string `json:"search_term"`
	}
	if err := json.Unmarshal(input, &p); err != nil || p.SearchTerm == "" {
		return nil
	}
	return Dedup(extractHosts(p.SearchTerm))
}
