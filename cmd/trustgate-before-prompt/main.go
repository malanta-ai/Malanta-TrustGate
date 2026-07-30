// trustgate-before-prompt is the Cursor beforeSubmitPrompt hook entrypoint.
//
// It is a WARN-MODE-ONLY surface: it does anything only when
// TRUSTGATE_MODE=warn. In warn mode it scans the prompt for hosts and, if
// the prompt contains an execution-intent verb, routes to the verdict
// cascade (which warns once and allows on re-submit); conversational
// mentions without an action verb short-circuit to allow so the user can
// talk ABOUT a domain without being blocked. In every OTHER mode
// (ask, enforce, report-only, off) it allows unconditionally and stays out
// of the way — the execution hooks (beforeShellExecution /
// beforeMCPExecution / beforeReadFile / preToolUse) are the enforcement
// boundary in all modes, and hard-blocking a prompt at submission time is
// the aggressive, false-positive-prone behavior this hook was originally
// deferred for. Note ask is no exception: beforeSubmitPrompt has no
// permission:"ask" wire lever (its outputs are continue true/false only),
// so ask's human-approval dialog is emitted by the execution hooks, not
// here. See docs/admin.md §5.3 and AGENTS.md.
package main

import (
	"encoding/json"
	"io"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/extract"
	"github.com/malanta-ai/Malanta-TrustGate/internal/hookrunner"
	"github.com/malanta-ai/Malanta-TrustGate/internal/verdict"
)

type input struct {
	Prompt string `json:"prompt"`
	Text   string `json:"text"` // some Cursor versions send "text" instead of "prompt"
	// WorkspaceRoots is the standard hook-envelope field, used ONLY for
	// TRUSTGATE_SCOPE_MODE/PATHS — see docs/admin.md.
	WorkspaceRoots []string `json:"workspace_roots"`
}

func main() {
	hookrunner.Run(hookrunner.Opts{
		HookName: "beforeSubmitPrompt",
		Extract: func(cfg config.Config, r io.Reader) (hookrunner.Result, error) {
			var in input
			if err := json.NewDecoder(r).Decode(&in); err != nil {
				return hookrunner.Result{}, err
			}
			// Warn-mode-only: in ask / enforce / report-only / off the
			// prompt hook stays out of the way (allow) and leaves
			// enforcement to the execution hooks. Only warn mode uses the
			// early warn-then-allow-on-re-submit flow. See the package doc.
			if cfg.Mode != config.ModeWarn {
				return hookrunner.Result{Decision: &verdict.Decision{Allow: true}}, nil
			}
			text := in.Prompt
			if text == "" {
				text = in.Text
			}
			seen := extract.FromPrompt(text)
			github := extract.GitHubFromPrompt(text)

			// Action-verb gate. A prompt that *mentions* a flagged domain
			// without *instructing* the agent to act on it (fetch / curl /
			// install / ...) should pass through silently — blocking
			// conversation about a domain is a different (and much weaker)
			// defense than blocking access to it, and the conversational
			// false positive trains users to disable the hook. The shell
			// hook still catches real execution downstream, so we don't
			// lose the property "no hostile domain is contacted without
			// Malanta weighing in"; we just stop denying questions about
			// them.
			//
			// Audit trail: write a "gated" entry to the decision log so
			// anyone investigating later sees exactly what the prompt
			// mentioned and why no verdict was sought.
			mentioned := verdict.Targets{Hosts: seen, Repos: github.Repos, Owners: github.Owners}.Values()
			if len(mentioned) > 0 && !extract.HasActionVerb(text) {
				verdict.WriteGatedLog(cfg.LogPath, "beforeSubmitPrompt", mentioned,
					"verb-gate: prompt mentions domains without action verb (fetch/curl/install/...)")
				return hookrunner.Result{Decision: &verdict.Decision{Allow: true}}, nil
			}
			return hookrunner.Result{Domains: seen, GitHub: github, WorkspaceRoots: in.WorkspaceRoots}, nil
		},
	})
}
