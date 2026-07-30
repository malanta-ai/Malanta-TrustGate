// trustgate-before-tool-use is the Cursor preToolUse hook entrypoint.
//
// preToolUse fires before any tool the agent runs — Shell, Read, Write,
// Glob, MCP, Task, WebFetch, WebSearch, ... The four other hook binaries
// in this POC each cover a more-specific event (beforeShellExecution,
// beforeMCPExecution, beforeSubmitPrompt, beforeReadFile), but those
// events do NOT fire on built-in agent tools like WebFetch and WebSearch.
// Without this binary the agent could `WebFetch("https://<malicious>/x")`
// and bypass the entire Malanta verdict cascade.
//
// The binary handles the gap by:
//
//  1. Dispatching `extract.FromToolUse(tool_name, tool_input)` which only
//     extracts for the inspected tool set (currently WebFetch + WebSearch).
//  2. Short-circuiting to allow for every other tool (no domains
//     extracted → hookrunner returns the empty-domains allow without
//     building a cache or API client).
//  3. Running the same `verdict.Compose` cascade as the other four binaries
//     for the extracted domains.
//  4. Emitting the documented preToolUse wire shape
//     (`{permission, user_message, agent_message}`), which AsJSON already
//     produces for any HookName other than `beforeSubmitPrompt`.
package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/extract"
	"github.com/malanta-ai/Malanta-TrustGate/internal/hookrunner"
	"github.com/malanta-ai/Malanta-TrustGate/internal/verdict"
)

type input struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	Cwd       string          `json:"cwd"`
	// WorkspaceRoots is the standard hook-envelope field, used ONLY for
	// TRUSTGATE_SCOPE_MODE/PATHS — see docs/admin.md.
	WorkspaceRoots []string `json:"workspace_roots"`
}

func main() {
	hookrunner.Run(hookrunner.Opts{
		HookName: "preToolUse",
		Extract: func(cfg config.Config, r io.Reader) (hookrunner.Result, error) {
			var in input
			if err := json.NewDecoder(r).Decode(&in); err != nil {
				return hookrunner.Result{}, err
			}
			domains := extract.FromToolUse(in.ToolName, in.ToolInput)
			github := extract.GitHubFromToolUse(in.ToolName, in.ToolInput)
			// Explicit short-circuit (skip cache + api client build) for
			// the common "tool isn't inspected" case. verdict.Compose
			// would also return allow on empty domains, but a Decision
			// here skips the api.New / cache.OpenOrWarn calls in
			// hookrunner.Run too, which matters on cold starts.
			if len(domains) == 0 && github.IsEmpty() {
				// A recognized network tool (WebFetch) whose
				// input yields NO destination is malformed/evasive input,
				// NOT "nothing to inspect" — e.g. a missing/relative url,
				// or a Cursor schema drift that renamed the field. Silently
				// allowing it removes WebFetch enforcement entirely. Deny
				// under fail-closed (the enforce default) or strict policy,
				// respecting the project's "can't decide => deny when
				// FailClosed" rule. A well-formed absolute URL to a
				// non-routable host (localhost) is NOT malformed and is not
				// caught here (WebFetchMalformed returns false for it).
				if in.ToolName == "WebFetch" && (cfg.FailClosed || cfg.ToolUseStrict) &&
					extract.WebFetchMalformed(in.ToolInput) {
					return hookrunner.Result{Decision: &verdict.Decision{
						Allow: false,
						Reason: "preToolUse: WebFetch input is malformed or missing a valid absolute URL; " +
							"denying under fail-closed/strict policy (possible schema drift or evasion)",
					}}, nil
				}
				// Optional strict mode (off by default):
				// deny a tool_name we don't recognize at all — not
				// actively inspected, not covered by a more specific
				// dedicated hook, and not in the hand-maintained safe
				// list or the operator's own allowlist. Cursor's own
				// docs describe the tool-name catalog as illustrative,
				// not exhaustive, so this is opt-in and paired with
				// Config.ToolUseAllowlist — see docs/admin.md.
				if cfg.ToolUseStrict && !extract.IsRecognizedTool(in.ToolName, cfg.ToolUseAllowlist) {
					return hookrunner.Result{Decision: &verdict.Decision{
						Allow: false,
						Reason: fmt.Sprintf(
							"preToolUse strict mode: unrecognized tool %q has no dedicated hook coverage and is not on the known-safe or configured allowlist (TRUSTGATE_TOOLUSE_ALLOWLIST)",
							in.ToolName),
					}}, nil
				}
				return hookrunner.Result{Decision: &verdict.Decision{Allow: true}}, nil
			}
			return hookrunner.Result{Domains: domains, GitHub: github, WorkspaceRoots: in.WorkspaceRoots}, nil
		},
	})
}
