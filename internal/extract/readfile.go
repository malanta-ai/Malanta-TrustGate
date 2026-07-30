package extract

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FromFile scans a file's contents for URLs / hosts IF the path looks like a
// config / lockfile / dependency manifest that commonly contains remote
// references, OR is an executable script (.sh/.py/.ps1/...) whose contents
// are about to run code on the user's machine. For arbitrary user source
// files outside those two buckets we deliberately skip scanning to keep the
// hook fast and to avoid surprising blocks on files that simply mention a
// string like a hostname in a comment. The allowlist below is the
// conservative starting set; expand as we collect telemetry.
//
// Why scripts are on the allowlist: pre-execution hooks see only the
// command being authorized, not what that command will do. An invocation
// like `./scripts/foo.sh` carries no domain in the command string itself
// even though the script body may ping a malicious host. Scanning the
// script body at read-time is the second line of defense; the first is
// `extract.FromShellInDir`'s script-follow pass.
//
// Returns the de-duplicated set of normalized public hostnames found in the
// file, or nil if the file is not in the allowlist, is too large, or cannot
// be read.
func FromFile(path string) []string {
	if path == "" {
		return nil
	}
	if !isInterestingPath(path) {
		return nil
	}
	const maxSize = 1 << 20 // 1 MiB cap; lockfiles can be large
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxSize || info.IsDir() {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return Dedup(extractFromContent(path, string(data)))
}

// FromFileContent is the inline-content equivalent of FromFile: it applies the
// SAME high-risk path allowlist, but extracts from caller-provided content
// instead of reading from disk. Cursor's beforeReadFile hook payload always
// carries the file content directly (per cursor.com/docs/hooks), and we
// want to scan that without going back to disk.
//
// The path gate is non-negotiable: if the path isn't allowlisted, we return
// nil regardless of what's in content. Skipping this check is how Go source
// files end up with identifiers like "context.Background" treated as
// candidate domains - a generic URL/host regex over arbitrary text is far
// too permissive.
//
// Use FromFileContentInRoots when the caller knows the workspace boundary
// (Cursor sends it on every hook envelope as workspace_roots); this
// function intentionally does no containment check so the existing test
// suite can exercise the allowlist+regex pipeline in isolation.
func FromFileContent(path, content string) []string {
	if path == "" || content == "" {
		return nil
	}
	if !isInterestingPath(path) {
		return nil
	}
	const maxSize = 1 << 20     // mirror FromFile's cap so large inline blobs
	if len(content) > maxSize { //   don't blow past the 250ms hook budget
		return nil
	}
	return Dedup(extractFromContent(path, content))
}

// extractFromContent dispatches between the permissive and the
// URL-context-required host extractors based on the file type.
// Script extensions (.sh / .bash / .zsh / .py / .ps1 / .psm1) carry
// source code whose dotted attribute/method references vastly
// outnumber URL literals, so we require URL syntax to promote a
// regex match to a domain candidate (defeats the `logger.info`,
// `process.env`, `obj.app` FP class — see the
// extractHostsRequireURLShape doc-comment for the full
// rationale). Manifest files (package.json, requirements.txt, lock
// variants, Dockerfile, .npmrc, ...) keep the permissive extractor
// because bare registry hosts are first-class citizens in their
// syntax.
//
// Both branches pass through Dedup at the caller; this helper
// returns the raw extracted slice so callers can still wrap with
// their own pipeline.
func extractFromContent(path, content string) []string {
	if isScriptPath(path) {
		return extractHostsRequireURLShape(content)
	}
	return extractHosts(content)
}

// isScriptPath reports whether path's extension matches one of the
// source/script types where read-time extraction must require URL
// context. Kept distinct from isInterestingPath even though the
// allowlists overlap: isInterestingPath governs whether ANY read-
// time scan happens (gates the whole pipeline), while isScriptPath
// governs which extractor to use INSIDE that scan. The two
// concerns are independent and may diverge as we tune coverage.
func isScriptPath(path string) bool {
	switch strings.ToLower(filepath.Ext(filepath.Base(path))) {
	case ".sh", ".bash", ".zsh", ".py", ".ps1", ".psm1":
		return true
	}
	return false
}

// FromFileContentInRoots is the production entrypoint for the read-file
// hook. It applies the same allowlist gate as FromFileContent, AND a
// workspace-roots containment check: if path resolves (via EvalSymlinks
// where the file exists, else via Clean+Abs) to a location outside ALL of
// roots, the call returns nil and the cascade falls through to allow
// without consulting Malanta or the cache. This is the response to the
// symlink-escape / out-of-workspace read finding.
//
// The containment check is deliberately silent (no deny verdict, no
// stderr warning). The shell / preToolUse hooks are still the safety net
// for whatever the agent does WITH the read content; suppressing the
// read-file extractor only removes one branch of inspection, not the
// last line of defense.
//
// Empty roots means "no constraint": the legacy behavior of
// FromFileContent. This keeps the helper friendly for unit tests that
// pass synthetic paths without a workspace, and for early Cursor versions
// that may not yet populate workspace_roots on the read-file envelope.
//
// Symlink handling: if EvalSymlinks resolves path to a location outside
// all roots even though path's literal text was inside one, the
// containment fails and we return nil. This closes the
// "workspace-internal symlink that points at ~/.aws/credentials" attack
// shape without relying on Cursor's prior path validation.
func FromFileContentInRoots(path, content string, roots []string) []string {
	if !isContained(path, roots) {
		return nil
	}
	return FromFileContent(path, content)
}

// GitHubFromFileContentInRoots is the GitHub-identity counterpart of
// FromFileContentInRoots. It applies the SAME workspace-roots containment
// check (a path that resolves outside the workspace is silently skipped)
// and the same content size cap, but its own path allowlist — see
// gitHubScannablePath.
func GitHubFromFileContentInRoots(path, content string, roots []string) GitHubRefs {
	if path == "" || content == "" {
		return GitHubRefs{}
	}
	if !isContained(path, roots) {
		return GitHubRefs{}
	}
	if !gitHubScannablePath(path) {
		return GitHubRefs{}
	}
	const maxSize = 1 << 20 // mirror FromFileContent's cap
	if len(content) > maxSize {
		return GitHubRefs{}
	}
	return GitHubFromText(content)
}

// gitHubScannablePath is the read-file allowlist for GitHub-identity
// extraction. It diverges from isInterestingPath in both directions, and
// each divergence is deliberate.
//
// ADDED: CI workflow definitions (.github/workflows/*.yml, action.yml).
// They are not on the host allowlist because a YAML file is mostly not
// remote references and scanning every .yml read for hostnames would be a
// large FP surface. A GitHub Actions `uses:` step, though, is third-party
// executable code identified by repository — the canonical Actions
// supply-chain surface — and the GitHub recognizers only fire on
// self-identifying shapes, so the FP cost that rules out generic YAML
// host scanning does not apply.
//
// REMOVED: dependency files — both declaration manifests (package.json,
// requirements.txt, go.mod, Cargo.toml, ...) and resolved lockfiles
// (go.sum, package-lock.json, *.lock).
//
// A dependency file records which dependencies a project HAS. It is not
// the moment the project reaches out to any of them: that is the install
// or fetch command, or a workflow step (scanned above). Reading the record
// is not an action, and treating it as one costs more than it buys:
//
//   - Fan-out. A single large go.sum or composer.lock names hundreds to
//     thousands of distinct repositories. That would blow past the
//     cascade's maxIndicatorsPerEvent cap and, fail-closed, turn an
//     ordinary read of a lockfile into a hard deny — the exact
//     reliability failure the cap exists to bound.
//   - Signal quality. Every entry in that file is, by construction, an
//     ordinary transitive dependency. The interesting cases (a typosquat,
//     a hijacked transitive package) are indistinguishable from the
//     hundreds of benign ones at this layer, and are the proper job of a
//     dependency-scanning tool that inventories what you already have.
//
// These files DO stay on the host allowlist, which is not a contradiction
// but a cardinality argument: a dependency file's HOST set is tiny and
// stable (registry.npmjs.org, proxy.golang.org, github.com), so an
// unexpected host there is a strong signal of a hijacked registry or a
// redirected mirror. Its REPOSITORY set is the whole dependency tree.
// Same file, opposite signal-to-noise.
//
// The repository coverage skipped here is picked up at execution time
// instead: shell.go's manifest-follow reads the manifest an install
// command names in argv (`pip install -r reqs.txt`) and extracts
// repositories from it then — at the one moment the file stops being a
// record and becomes an action, and where the fan-out is scoped to the
// single file the operator actually invoked.
func gitHubScannablePath(path string) bool {
	if isDependencyFilePath(path) {
		return false
	}
	if isInterestingPath(path) {
		return true
	}
	return isWorkflowPath(path)
}

// isDependencyFilePath matches package-manager dependency files, whether
// hand-edited declarations or machine-generated lockfiles. See
// gitHubScannablePath for why they are excluded from GitHub-name
// extraction while remaining on the HOST allowlist.
func isDependencyFilePath(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	switch name {
	case "go.mod", "go.sum",
		"package.json", "package-lock.json", "npm-shrinkwrap.json",
		"pnpm-lock.yaml", "yarn.lock",
		"requirements.txt", "pyproject.toml", "pipfile",
		"cargo.toml", "gemfile", "composer.json":
		return true
	}
	return strings.HasSuffix(name, ".lock")
}

// isWorkflowPath matches GitHub Actions definitions: any YAML file under a
// ".github/workflows" directory, plus a top-level action.yml / action.yaml
// (a composite action, which references other actions the same way).
func isWorkflowPath(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	if name == "action.yml" || name == "action.yaml" {
		return true
	}
	dir := strings.ToLower(filepath.ToSlash(filepath.Dir(path)))
	return strings.HasSuffix(dir, ".github/workflows")
}

// IsPathInWorkspace is the public alias for isContained, exposed so
// downstream callers (the read-file hook in particular) can gate
// extra-cascade work — like ATR behavioral evaluation — on the same
// canonical workspace-containment check the domain extractor uses.
// Without this gate, an out-of-workspace file_path that Cursor would
// itself refuse to read could still be scanned by ATR if a hostile
// MCP server included payload content in the hook envelope.
//
// Returns true when path resolves under any of roots, false
// otherwise. Empty roots is treated as "no constraint" (same
// permissive default the domain extractor uses), so callers in
// CI / test harnesses that don't populate workspace_roots still see
// ATR run.
func IsPathInWorkspace(path string, roots []string) bool {
	return isContained(path, roots)
}

// isContained reports whether path resolves to a location under any of
// roots. Both sides are run through EvalSymlinks (where possible) so a
// workspace root that lives behind a system-level symlink — e.g. macOS's
// /var → /private/var — and an absolute path returned by some other API
// still compare equal. Defeats symlinks on both sides; closes the
// workspace-internal-symlink-to-sensitive-target bypass.
//
// Empty roots is treated as "no constraint" by default — see
// FromFileContentInRoots documentation for the rationale (CI/test
// harnesses and early Cursor versions that don't populate
// workspace_roots should still get scanned, not silently skipped).
// Setting TRUSTGATE_READFILE_STRICT_WORKSPACE_ROOTS=true flips this: an
// empty/missing workspace_roots is then treated as "outside every
// workspace" (containment fails, extraction and ATR are skipped for
// that read — same as a genuine symlink-escape result), rather than as
// an unconstrained pass. This is the "non-permissive empty
// workspace_roots" behavior, opt-in because
// it can suppress the extra scrutiny read-time scanning provides on any
// setup where Cursor doesn't populate workspace_roots at all. Read
// directly from the environment (not threaded as a parameter) to match
// how internal/atr's own env-gated kill switches work.
func isContained(path string, roots []string) bool {
	if len(roots) == 0 {
		strict, _ := strconv.ParseBool(os.Getenv("TRUSTGATE_READFILE_STRICT_WORKSPACE_ROOTS"))
		return !strict
	}
	if path == "" {
		return false
	}
	resolved := resolveForContainment(path)
	for _, r := range roots {
		root := resolveForContainment(r)
		if root == "" || root == "." {
			continue
		}
		// HasPrefix alone would accept "/projecta" as being under
		// "/project"; append the separator on the root side to force
		// a directory-boundary match. The resolved path == root case
		// must also match (the workspace root file itself).
		if resolved == root || strings.HasPrefix(resolved, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// resolveForContainment canonicalizes a filesystem path for use in the
// containment check. The naive approach — EvalSymlinks(path) with a
// Clean fallback on error — breaks when the file is missing but its
// ancestors are real (e.g. /tmp/requirements.txt on macOS, where /tmp
// is a symlink to /private/tmp but the file itself does not exist):
// the root would resolve to /private/tmp while the file path would
// stay as /tmp/requirements.txt, defeating the HasPrefix containment.
//
// Walk up the path until we find an ancestor EvalSymlinks can resolve,
// then re-attach the missing suffix. Yields a consistent canonical
// form regardless of whether the file itself exists, while still
// respecting any symlink in the path's real prefix.
func resolveForContainment(p string) string {
	if p == "" {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	// Walk up to the deepest existing ancestor and reattach the
	// suffix. This handles "synthetic" paths (Cursor hasn't created
	// the file yet, draft buffers, test fixtures) without losing the
	// symlink resolution that defeats the symlink-escape bypass.
	cur := p
	suffix := ""
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			break // hit filesystem root
		}
		suffix = filepath.Join(filepath.Base(cur), suffix)
		if r, err := filepath.EvalSymlinks(parent); err == nil {
			return filepath.Join(r, suffix)
		}
		cur = parent
	}
	// Nothing on the path exists. Fall back to a lexical canonical
	// form so the comparison at least operates on equal terms with
	// other lexically-canonical inputs.
	q := filepath.Clean(p)
	if !filepath.IsAbs(q) {
		if abs, err := filepath.Abs(q); err == nil {
			q = abs
		}
	}
	return q
}

// IsHighRiskPath is the public alias for isInterestingPath, exposed so
// the read-file hook can gate the ATR (Agent Threat Rules) behavioral
// pass on the same path allowlist that the domain extractor uses.
//
// Motivation: the read-file ATR pool serves three upstream rule
// categories — skill-compromise, tool-poisoning, context-exfiltration —
// authored against specific surfaces (skill manifests, tool responses,
// agent input). Running them on every `*.md` / `*.go` / `hooks.json`
// inside the workspace produces noisy fail-closed denies on legitimate
// documentation and config (ATR-2026-00013 / 00066
// / 00113 over-fired on this repo's own AGENTS.md and hooks.json
// during the 2026-05-27 install). Gating ATR on the existing high-
// risk allowlist (skill manifests, lockfiles, Dockerfile, .npmrc,
// shell / python / PowerShell scripts) aligns the ATR surface with
// the Malanta domain cascade surface — the latter has been
// production-tested for FP rate, and ATR inherits the same scope.
//
// See AGENTS.md for the broader curation context. Proper scan_target
// routing in bundle.go is the eventual structural fix; this helper is
// the short-term gate.
func IsHighRiskPath(path string) bool {
	return isInterestingPath(path)
}

// isInterestingPath returns true for file paths whose presence in a hook
// indicates the agent is about to act on remote-fetched dependencies or
// configuration.
func isInterestingPath(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	switch name {
	case "requirements.txt",
		"pyproject.toml",
		"poetry.lock",
		"pipfile",
		"pipfile.lock",
		"package.json",
		"package-lock.json",
		"pnpm-lock.yaml",
		"yarn.lock",
		"go.mod",
		"go.sum",
		"cargo.toml",
		"cargo.lock",
		"gemfile",
		"gemfile.lock",
		"dockerfile",
		".npmrc",
		".pip.conf",
		"pip.conf",
		".helmignore":
		return true
	}
	// Files with these extensions almost always carry remote refs in our
	// context. `.lock` covers extra lockfile variants beyond the named
	// entries above; the script extensions (.sh / .bash / .zsh / .py /
	// .ps1 / .psm1) cover the "malicious domain hidden inside a script
	// body" attack class (see file-level doc). We deliberately keep the
	// script list narrow - script extensions like .js / .rb / .pl are
	// also common source-file extensions and scanning every read of them
	// would meaningfully cost the 250ms hook budget. Add new extensions
	// here only with telemetry showing low read frequency.
	switch strings.ToLower(filepath.Ext(name)) {
	case ".lock",
		".sh", ".bash", ".zsh",
		".py",
		".ps1", ".psm1":
		return true
	}
	return false
}
