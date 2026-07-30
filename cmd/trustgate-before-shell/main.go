// trustgate-before-shell is the Cursor beforeShellExecution hook entrypoint.
// It reads the JSON payload from stdin, extracts candidate domains from the
// shell command (and any local script it invokes), and emits the Cursor
// per-event JSON verdict via hookrunner.
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

type input struct {
	Command string   `json:"command"`
	Argv    []string `json:"argv"`
	// Cwd is the agent's working directory at the time of the
	// beforeShellExecution event. Used to resolve relative script paths
	// (e.g. "./scripts/foo.sh") so the extractor can follow them into the
	// file body. Cursor populates this per cursor.com/docs/hooks.
	Cwd string `json:"cwd"`
	// WorkspaceRoots is the standard hook-envelope field (see
	// docs/admin.md's workspace/project scoping section). Used ONLY for
	// TRUSTGATE_SCOPE_MODE/PATHS; absent here has no effect on domain
	// extraction or the reputation cascade.
	WorkspaceRoots []string `json:"workspace_roots"`
}

func main() {
	hookrunner.Run(hookrunner.Opts{
		HookName: "beforeShellExecution",
		Extract: func(_ config.Config, r io.Reader) (hookrunner.Result, error) {
			var in input
			if err := json.NewDecoder(r).Decode(&in); err != nil {
				return hookrunner.Result{}, err
			}
			cmd := in.Command
			if cmd == "" && len(in.Argv) > 0 {
				cmd = strings.Join(in.Argv, " ")
			}
			// ATRContent is the raw command line. The shell hook's
			// hand-curated rule subset (TRUSTGATE-SHELL-*) is tuned
			// against this surface only; rules from the broader
			// read-file/MCP pool are NOT loaded here because they
			// target tool_response / agent_output / content fields
			// and would FP on shell shape (a command line that
			// mentions `cat /etc/shadow` for tutorial purposes is
			// still a command line — but the ATR shell pool already
			// gates that as critical, and we don't want the
			// upstream rules guessing at the same surface).
			//
			// Followed-script bodies are NOT yet handed to ATR; the
			// Malanta domain cascade still inspects them via
			// extract.FromShellInDir, but the ATR pass only sees
			// the command. Adding script-body ATR coverage is a
			// tracked follow-up — the ATR shell
			// ruleset's curated subset focuses on command-line shapes
			// because that's where the canonical attack payloads
			// (curl-pipe-sh, reverse shells, credential reads)
			// land.
			return hookrunner.Result{
				Domains:        extract.FromShellInDir(cmd, in.Cwd),
				GitHub:         extract.GitHubFromShellInDir(cmd, in.Cwd),
				ATRContent:     cmd,
				ATRTargets:     []atr.Target{atr.TargetShell},
				WorkspaceRoots: in.WorkspaceRoots,
			}, nil
		},
	})
}
