// trustgate-before-mcp is the Cursor beforeMCPExecution hook entrypoint.
// It decodes the MCP tool invocation (server URL + arguments) and feeds
// both surfaces through the same extractor before delegating to
// hookrunner.
package main

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/malanta-ai/Malanta-TrustGate/internal/atr"
	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/extract"
	"github.com/malanta-ai/Malanta-TrustGate/internal/hookrunner"
)

// input accepts BOTH the current Cursor beforeMCPExecution payload and the
// original POC shape. Current Cursor (verified against cursor.com/docs/hooks
// and the community payload dumps, 2026-07) sends `tool_name`, an escaped
// JSON `tool_input` string (occasionally a structured object, Claude-Code
// style), and one of `url` (remote MCP) / `command` (stdio MCP) as the
// destination. The original hook only read `tool` / `server` / `arguments`,
// so on a current client every inspected value was empty and MCP calls
// bypassed the reputation + ATR passes entirely. We decode the
// union and treat legacy fields as aliases, so the hook is correct on both
// old and new clients.
type input struct {
	// Current Cursor fields.
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	URL       string          `json:"url"`
	Command   string          `json:"command"`
	// Legacy POC aliases (retained so an older client still works).
	Tool      string `json:"tool"`
	Server    string `json:"server"`
	Arguments any    `json:"arguments"`
	// WorkspaceRoots is the standard hook-envelope field, used ONLY for
	// TRUSTGATE_SCOPE_MODE/PATHS — see docs/admin.md.
	WorkspaceRoots []string `json:"workspace_roots"`
}

// firstNonEmpty returns the first non-empty string, used to collapse a
// current field and its legacy alias to one value.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// decodeToolInput turns the `tool_input` field into a value walkJSON can
// recurse. Cursor sends it as a JSON STRING whose contents are themselves
// escaped JSON (e.g. "{\"url\":\"https://x/\"}"); some clients send a bare
// object. json.Unmarshal into `any` handles both: a JSON string decodes to a
// Go string (host regex then runs over its text), an object decodes to a
// map[string]any (walkJSON recurses). Returns nil when tool_input is absent
// or unparseable, so the caller falls back to the legacy `arguments` field.
func decodeToolInput(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Not valid JSON on its own — treat the raw bytes as an opaque
		// string so the host regex still gets a chance at it.
		return string(raw)
	}
	return v
}

func main() {
	hookrunner.Run(hookrunner.Opts{
		HookName: "beforeMCPExecution",
		Extract: func(_ config.Config, r io.Reader) (hookrunner.Result, error) {
			var in input
			if err := json.NewDecoder(r).Decode(&in); err != nil {
				return hookrunner.Result{}, err
			}

			toolName := firstNonEmpty(in.ToolName, in.Tool)
			// Destination surfaces are mutually exclusive on any given
			// event, but we pass all we have and let extraction dedupe:
			// url (remote), command (stdio), server (legacy).
			destinations := []string{in.URL, in.Command, in.Server}
			toolInput := decodeToolInput(in.ToolInput)

			// Serialize tool name + destinations + arguments for ATR. The
			// serialization is JSON because that's the on-the-wire shape
			// MCP servers produce; tool-poisoning rules in the bundle were
			// written to match against this shape. We DON'T marshal to YAML
			// or pretty-print: that would alter the byte sequence the regex
			// authors targeted and silently break upstream rule fidelity.
			var atrContent strings.Builder
			if toolName != "" {
				atrContent.WriteString(toolName)
				atrContent.WriteByte('\n')
			}
			for _, d := range destinations {
				if d != "" {
					atrContent.WriteString(d)
					atrContent.WriteByte('\n')
				}
			}
			// tool_input first (current), then legacy arguments if present.
			if len(in.ToolInput) > 0 {
				if s, ok := toolInput.(string); ok {
					atrContent.WriteString(s)
				} else if argsJSON, err := json.Marshal(toolInput); err == nil {
					atrContent.Write(argsJSON)
				}
				atrContent.WriteByte('\n')
			}
			if in.Arguments != nil {
				if argsJSON, err := json.Marshal(in.Arguments); err == nil {
					atrContent.Write(argsJSON)
				}
			}

			// Feed BOTH the current tool_input and the legacy arguments
			// through extraction (whichever is present); a client that
			// somehow sent both is covered, and Dedup collapses overlaps.
			domains := extract.FromMCPCall(destinations, toolInput)
			if in.Arguments != nil {
				domains = extract.Dedup(append(domains, extract.FromMCP(in.Arguments)...))
			}

			return hookrunner.Result{
				Domains:        domains,
				GitHub:         extract.GitHubFromMCPCall(destinations, toolInput, in.Arguments),
				ATRContent:     atrContent.String(),
				ATRTargets:     []atr.Target{atr.TargetMCP},
				WorkspaceRoots: in.WorkspaceRoots,
			}, nil
		},
	})
}
