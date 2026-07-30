// trustgate-before-read-file is the Cursor beforeReadFile hook entrypoint.
// It inspects high-risk paths (lockfiles, package manifests, executable
// scripts) for hostile remote references. Cursor always sends file
// contents inline (per cursor.com/docs/hooks) and the workspace_roots
// envelope field, so the hook never touches disk and enforces
// containment using Cursor's authoritative workspace boundary.
package main

import (
	"encoding/json"
	"io"

	"github.com/malanta-ai/Malanta-TrustGate/internal/atr"
	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/extract"
	"github.com/malanta-ai/Malanta-TrustGate/internal/hookrunner"
)

// input mirrors the Cursor beforeReadFile schema documented at
// cursor.com/docs/hooks: file_path is the ABSOLUTE path Cursor resolved
// before invoking the hook (no relative `../` to defeat), content is the
// inline file body, and workspace_roots is the standard envelope field
// listing the workspace's root folders. Multi-root workspaces send
// multiple entries.
//
// Legacy `path` field is preserved as a fallback so smoke fixtures and
// any pre-docs callers continue to function; production Cursor always
// populates file_path.
type input struct {
	FilePath       string   `json:"file_path"`
	Path           string   `json:"path"`
	Content        string   `json:"content"`
	WorkspaceRoots []string `json:"workspace_roots"`
}

func main() {
	hookrunner.Run(hookrunner.Opts{
		HookName: "beforeReadFile",
		Extract: func(_ config.Config, r io.Reader) (hookrunner.Result, error) {
			var in input
			if err := json.NewDecoder(r).Decode(&in); err != nil {
				return hookrunner.Result{}, err
			}
			path := in.FilePath
			if path == "" {
				path = in.Path
			}
			// Cursor always sends content inline; the on-disk fallback
			// the original POC carried was dead code in production and
			// has been removed. Without `content` there is nothing to
			// scan, and the cascade allows.
			if in.Content == "" {
				return hookrunner.Result{}, nil
			}
			res := hookrunner.Result{
				Domains:        extract.FromFileContentInRoots(path, in.Content, in.WorkspaceRoots),
				GitHub:         extract.GitHubFromFileContentInRoots(path, in.Content, in.WorkspaceRoots),
				WorkspaceRoots: in.WorkspaceRoots,
			}
			// Gate ATR on:
			//   (1) Workspace-roots containment — same boundary the
			//       domain extractor uses. An out-of-workspace
			//       file_path (Cursor's authoritative refusal-to-
			//       read boundary) must not feed ATR either, or a
			//       hostile MCP server could ship malicious-looking
			//       payload for an out-of-workspace path and have
			//       ATR fire on it (defeats §12.11).
			//   (2) The same high-risk-path allowlist the domain
			//       extractor already uses (skill manifests,
			//       lockfiles, Dockerfile, .npmrc, shell / python
			//       / PowerShell scripts). Without this gate, the
			//       upstream ATR rules (notably ATR-2026-00013,
			//       ATR-2026-00066, ATR-2026-00113) fire on
			//       arbitrary *.md / *.go / *.json content that
			//       happens to mention credential paths,
			//       mesh-internal hostnames, or skill terminology
			//       — i.e. legitimate documentation and config in
			//       this very repo's AGENTS.md and hooks.json.
			//       Aligning the ATR surface with the existing
			//       read-file scope means ATR adds zero new attack
			//       surface vs the pre-ATR baseline; it just adds
			//       behavioral coverage on the files the cascade
			//       was already inspecting.
			//
			// The proper structural fix is restoring upstream's
			// `scan_target` field in `sync-atr-rules.py` and
			// routing each rule to the right surface in
			// `bundle.go::LoadBundledForTargets`. The path-allowlist
			// gate here is the short-term mitigation shipped
			// alongside ATR.
			//
			// ATR runs on the same content the Malanta domain
			// cascade just inspected. Targets pulled here are the
			// read-file pool (skill-compromise + tool-poisoning +
			// context-exfiltration) shared between read-file and
			// MCP. We do NOT add the shell subset for this hook —
			// shell rules are tuned to command-line shape and would
			// FP on prose / package manifests.
			if extract.IsPathInWorkspace(path, in.WorkspaceRoots) &&
				extract.IsHighRiskPath(path) {
				res.ATRContent = in.Content
				res.ATRTargets = []atr.Target{atr.TargetReadFile}
			}
			return res, nil
		},
	})
}
