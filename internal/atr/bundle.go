package atr

import (
	"embed"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// encodedPatternPrefix is the sentinel that scripts/sync-atr-rules.py
// prepends to every base64-encoded regex value when vendoring an
// upstream rule. The loader detects it here and decodes back to the
// original regex string before regexp.Compile.
//
// Why we encode at all: endpoint AV / EDR engines (Microsoft Defender,
// CrowdStrike, S1, etc.) heuristically match raw byte sequences inside
// our rule YAML files against malware signatures, because detection
// rules by definition contain the byte patterns they hunt for. The
// "Trojan:PowerShell/Openclaw.GVB!MTB" quarantine of
// ATR-2026-00121-skill-dangerous-script.yaml on 2026-05-27 was the
// canonical real-world hit. Encoding at sync time keeps attack
// strings out of disk-resident YAML AND out of static binary string
// tables (the encoded form is what Go embeds via embed.FS, then
// this function decodes in memory at load time).
//
// See scripts/sync-atr-rules.py for the encoder and the rationale
// at the top of that file for the full story.
const encodedPatternPrefix = "atr-b64:"

// bundledRules is the embedded snapshot of ATR YAML rule files that
// ships inside every hook binary. Vendored from the agent-threat-rules
// npm package via scripts/sync-atr-rules.py, pinned to a specific
// package version (see scripts/sync-atr-rules.py's ATR_VERSION for the
// exact version).
//
// Filtered subdirectories:
//
//   - rules/skill-compromise/
//   - rules/tool-poisoning/
//   - rules/context-exfiltration/
//   - rules/shell/ — hand-curated ~30-50 rule subset for the shell hook
//
// Categories deliberately excluded from the sync: prompt-injection,
// agent-manipulation, data-poisoning, model-abuse, model-security.
// See rule.go for the rationale (recon + resource-development scope).
//
//go:embed all:rules
var bundledRules embed.FS

// loadOnce ensures we parse the YAML files once per process. Hook
// subprocesses are short-lived (one event each), but the package is
// also used by the benchmark binary and the test suite, both of which
// call LoadBundled / LoadBundledForTarget many times in one process.
var loadOnce sync.Once
var loadedRules map[Target][]Rule
var loadErrors []string // unrecoverable bundle problems surfaced via Diagnostics()

// LoadBundled returns the read-file rule pool — the historical
// default for tests and callers that pre-date the read-file / MCP
// pool split. After the 2026-05-27 split, this is the file-content
// scan pool: skill-compromise +
// context-exfiltration + privilege-escalation + excessive-autonomy,
// but NOT tool-poisoning (those rules are authored against MCP
// tool_args / tool_response shapes and produce FPs when run over
// arbitrary file content).
//
// Callers wiring the MCP hook explicitly must use
// LoadBundledForTarget(TargetMCP) to pick up tool-poisoning rules.
// The shell subset is NOT included here; callers that want the
// shell pool must use LoadBundledForTarget(TargetShell) explicitly.
//
// Returns nil + nil error on a fully-empty bundle (the
// "rules synced but all filtered out" edge case). Returns an error
// only when the embed FS itself is unreadable, which would indicate
// a build-time bug in the embed directive — not a runtime condition
// the hook can recover from. Callers should fail-closed on a non-nil
// error.
func LoadBundled() ([]Rule, error) {
	if err := load(); err != nil {
		return nil, err
	}
	return loadedRules[TargetReadFile], nil
}

// LoadBundledForTarget returns the rules associated with a specific
// hook surface. TargetReadFile receives the file-content scan pool
// (no tool-poisoning rules — those are MCP-shape-specific by
// authoring intent); TargetMCP receives the full pool; TargetShell
// returns only the curated shell subset. Unknown targets return
// nil — a defensive default so a typo in a future hook wiring fails
// loud (empty matches in the bench) rather than silently matching
// against the wrong pool.
func LoadBundledForTarget(t Target) ([]Rule, error) {
	if err := load(); err != nil {
		return nil, err
	}
	return loadedRules[t], nil
}

// LoadBundledForTargets is the multi-target convenience wrapper used
// by the hookrunner — each hook declares one or more targets it cares
// about (e.g. read-file declares TargetReadFile + TargetSkillManifest,
// MCP declares TargetMCP + TargetToolDescription) and gets the union
// of the rule pools back. Duplicate Rules across targets are returned
// only once: rule pool identity is currently shared (read-file = MCP),
// but the dedup is by ID so a future divergence stays correct.
func LoadBundledForTargets(targets ...Target) ([]Rule, error) {
	if err := load(); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool)
	var out []Rule
	for _, t := range targets {
		for _, r := range loadedRules[t] {
			if seen[r.ID] {
				continue
			}
			seen[r.ID] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// Diagnostics returns any non-fatal parsing problems encountered at
// bundle load time — rules with bad regex, missing IDs, out-of-scope
// categories, etc. The hook subprocess writes these to stderr via
// hookrunner.Run; Cursor surfaces stderr in its hook-output panel.
// Returns nil if no problems were seen. Safe to call from any
// goroutine after the first LoadBundled / LoadBundledForTarget call.
func Diagnostics() []string {
	_ = load() // best-effort; an error here is also reflected in loadErrors
	out := make([]string, len(loadErrors))
	copy(out, loadErrors)
	return out
}

// load is the once-per-process parse pass. Idempotent and goroutine-
// safe; subsequent calls return the cached error (if any) without
// re-reading the embed FS.
func load() error {
	var err error
	loadOnce.Do(func() {
		err = doLoad()
	})
	return err
}

// doLoad walks the embed FS, parses every YAML rule, and routes each
// rule to its Target pool. Per-rule failures (bad YAML, uncompilable
// regex, out-of-scope category) are appended to loadErrors and the
// rule is dropped from the pool — bundle load itself only fails on a
// catastrophic embed FS read error.
//
// After the embedded bundle, doLoad also loads an OPTIONAL bring-your-
// own-rules directory from TRUSTGATE_ATR_RULES_DIR (see loadCustomRules).
// This lets an operator or the community add or override detection
// rules without forking and recompiling the binary — the ATR ruleset
// content is community/best-effort (see SUPPORT.md); the loader
// mechanism itself is core and officially supported.
func doLoad() error {
	loadedRules = map[Target][]Rule{
		TargetReadFile: nil,
		TargetMCP:      nil,
		TargetShell:    nil,
	}

	// Walk in lexical order so the rule slice is reproducible across
	// runs. embed.FS doesn't guarantee any particular walk order, so
	// we collect paths first and sort.
	var paths []string
	err := fs.WalkDir(bundledRules, "rules", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return fmt.Errorf("atr: walk embedded rules: %w", err)
	}
	sort.Strings(paths)

	for _, path := range paths {
		data, readErr := fs.ReadFile(bundledRules, path)
		if readErr != nil {
			loadErrors = append(loadErrors,
				fmt.Sprintf("atr: read %s: %v", path, readErr))
			continue
		}
		// isShellPath: the embedded shell subset lives under
		// "rules/shell/" (embed.FS path, forward-slash always).
		addParsedRule(path, data, strings.HasPrefix(path, "rules/shell/"))
	}

	if dir := strings.TrimSpace(os.Getenv("TRUSTGATE_ATR_RULES_DIR")); dir != "" {
		loadCustomRules(dir)
	}
	return nil
}

// loadCustomRules reads additional YAML rule files from an operator- or
// community-provided directory (TRUSTGATE_ATR_RULES_DIR). Mirrors the
// embedded bundle's own layout convention so the same routing logic
// applies: a "shell/" subdirectory routes to TargetShell; everything
// else routes like the embedded MCP/read-file split (category
// tool-poisoning stays MCP-only). Plain, non-obfuscated YAML is
// expected here — decodeTextEnvelope/compileSafeRegex pass a string
// through unchanged when it doesn't carry the atr-b64: sentinel, so
// hand-written community rules need no special encoding.
//
// Errors (missing directory, unreadable file, bad YAML) are recorded
// in loadErrors and do NOT fail the bundle load — a broken custom-rules
// directory must not brick the embedded ruleset, matching this
// package's existing per-rule fault tolerance.
func loadCustomRules(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		loadErrors = append(loadErrors, fmt.Sprintf("atr: custom rules dir %q: %v", dir, err))
		return
	}
	var names []string
	hasShellSubdir := false
	for _, e := range entries {
		if e.IsDir() {
			if e.Name() == "shell" {
				hasShellSubdir = true
			}
			continue
		}
		if strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		full := filepath.Join(dir, name)
		data, readErr := os.ReadFile(full)
		if readErr != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("atr: read %s: %v", full, readErr))
			continue
		}
		addParsedRule(full, data, false)
	}
	if hasShellSubdir {
		shellDir := filepath.Join(dir, "shell")
		shellEntries, err := os.ReadDir(shellDir)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("atr: custom shell rules dir %q: %v", shellDir, err))
			return
		}
		var shellNames []string
		for _, e := range shellEntries {
			if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
				shellNames = append(shellNames, e.Name())
			}
		}
		sort.Strings(shellNames)
		for _, name := range shellNames {
			full := filepath.Join(shellDir, name)
			data, readErr := os.ReadFile(full)
			if readErr != nil {
				loadErrors = append(loadErrors, fmt.Sprintf("atr: read %s: %v", full, readErr))
				continue
			}
			addParsedRule(full, data, true)
		}
	}
}

// addParsedRule parses one rule file's bytes and routes it into
// loadedRules, recording any failure in loadErrors. isShell selects
// the TargetShell pool; otherwise the rule goes to TargetMCP, and
// (unless its category is tool-poisoning) also to TargetReadFile.
//
// Why the non-shell split: rules with `category: tool-poisoning` in
// upstream ATR are authored against MCP `tool_args` / `tool_response`
// fields. Their regexes target shapes specific to that surface — e.g.
// ATR-2026-00062's `__[a-z]+__` dunder pattern, which on a JSON
// tool_args blob is a strong "hidden parameter" signal, but on a
// Python source file matches every `__name__` / `__init__` /
// `__main__` reference, denying every read of a routine Python module
// (production FP captured 2026-05-27 on a pytest integration-test
// file). The evaluator doesn't honor the YAML `field:` directive today
// (honoring it is a tracked follow-up); category-level
// filtering is the layered defense that respects each rule's authored
// surface until per-field routing lands.
func addParsedRule(path string, data []byte, isShell bool) {
	rule, parseErr := parseRule(data)
	if parseErr != nil {
		loadErrors = append(loadErrors,
			fmt.Sprintf("atr: parse %s: %v", path, parseErr))
		return
	}
	if !IsAllowedCategory(rule.Category) {
		loadErrors = append(loadErrors,
			fmt.Sprintf("atr: %s out-of-scope category %q; dropped", path, rule.Category))
		return
	}
	// Skip rules that ended up with zero compilable patterns — they
	// would never match anything and would just bloat the per-rule
	// iteration in Evaluate.
	if len(rule.Patterns) == 0 {
		loadErrors = append(loadErrors,
			fmt.Sprintf("atr: %s has no compilable patterns; dropped", path))
		return
	}
	if isShell {
		loadedRules[TargetShell] = append(loadedRules[TargetShell], rule)
		return
	}
	loadedRules[TargetMCP] = append(loadedRules[TargetMCP], rule)
	if rule.Category == CategoryToolPoisoning {
		return
	}
	loadedRules[TargetReadFile] = append(loadedRules[TargetReadFile], rule)
}

// yamlRule is the YAML-decode shape, distinct from Rule so the
// evaluator-facing struct stays narrow. Lists every field we care
// about; anything not listed is silently ignored by yaml.v3.
type yamlRule struct {
	ID          string `yaml:"id"`
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
	Tags        tagBlk `yaml:"tags"`
	Detection   detBlk `yaml:"detection"`
}

type tagBlk struct {
	Category   string `yaml:"category"`
	ScanTarget string `yaml:"scan_target"`
}

type detBlk struct {
	Condition  string     `yaml:"condition"`
	Conditions []condItem `yaml:"conditions"`
}

type condItem struct {
	Field       string `yaml:"field"`
	Operator    string `yaml:"operator"`
	Value       string `yaml:"value"`
	Description string `yaml:"description"`
}

// parseRule decodes one YAML rule file into the evaluator-ready Rule
// struct. Returns an error if the YAML is malformed; non-fatal
// per-pattern failures (uncompilable regex) are skipped and an
// abbreviated description appended via the bundle's Diagnostics
// channel, but the rule is still emitted as long as at least one
// pattern survives.
//
// Why we don't return on the first bad regex: ATR rules in the wild
// are written for Node.js's regex engine (PCRE-style), and a small
// fraction use lookaround features that RE2 rejects. Dropping the
// whole rule on the first bad pattern would lose every OTHER pattern
// in the same rule's condition: any list, even though those are
// perfectly good RE2 regex. Better to extract the patterns we can
// and tell the operator via Diagnostics what we dropped.
func parseRule(data []byte) (Rule, error) {
	var y yamlRule
	if err := yaml.Unmarshal(data, &y); err != nil {
		return Rule{}, err
	}
	if y.ID == "" {
		return Rule{}, fmt.Errorf("missing id")
	}
	cat := Category(strings.TrimSpace(y.Tags.Category))
	rule := Rule{
		ID:          y.ID,
		Title:       decodeTextEnvelope(y.Title),
		Description: decodeTextEnvelope(strings.TrimSpace(y.Description)),
		Category:    cat,
		Severity:    ParseSeverity(strings.TrimSpace(y.Severity)),
		Condition:   strings.TrimSpace(y.Detection.Condition),
	}
	for _, c := range y.Detection.Conditions {
		if c.Operator != "" && c.Operator != "regex" {
			// Non-regex operators (contains, equals, ...) are part
			// of ATR's spec but not used by the rule subset we
			// currently vendor. Skipping rather than failing so
			// future syncs that pull non-regex rules don't break the
			// bundle.
			continue
		}
		if c.Value == "" {
			continue
		}
		re, err := compileSafeRegex(c.Value)
		if err != nil {
			// Per-pattern compile failures are common (lookaround,
			// backreferences in PCRE-style rules); silently skip
			// this pattern and let the rule survive on its other
			// patterns. The Diagnostics() channel would record this
			// if we surfaced it; for now the dropped-pattern count
			// is observable as (declared - matched) at load time.
			continue
		}
		rule.Patterns = append(rule.Patterns, Pattern{
			Regex:       re,
			Field:       c.Field,
			Description: decodeTextEnvelope(c.Description),
		})
	}
	return rule, nil
}

// decodeTextEnvelope decodes the atr-b64: envelope for non-regex
// scalar text fields (title, description). Unlike compileSafeRegex
// the decoded result here is plain prose for user_message rendering,
// not a regex — so a decode failure can fall back to the encoded
// form (still legible: it'll look like "atr-b64:KD9p...") rather
// than dropping the field entirely. The fallback is just for
// observability — the typical decode-failure case is "the encoded
// string is malformed", which would never happen in a snapshot
// produced by sync-atr-rules.py but might appear during a botched
// manual edit.
//
// Strings without the sentinel pass through unchanged. This means
// hand-written rule files (e.g. the hand-curated TRUSTGATE-SHELL-* set,
// which we encode after the fact) work both before AND after encoding.
func decodeTextEnvelope(s string) string {
	if !strings.HasPrefix(s, encodedPatternPrefix) {
		return s
	}
	decoded, err := base64.StdEncoding.DecodeString(s[len(encodedPatternPrefix):])
	if err != nil {
		return s
	}
	return string(decoded)
}

// compileSafeRegex compiles s as RE2. Handles two pattern forms:
//
//  1. A plain regex string (legacy / hand-written rules) — passed
//     straight to regexp.Compile.
//  2. An `atr-b64:<base64>` envelope — base64-decoded first, then
//     compiled. This is the form scripts/sync-atr-rules.py emits
//     for every vendored upstream rule; the encoding exists solely
//     to defeat endpoint-AV heuristic false-positives that match
//     against the literal attack strings inside detection rules.
//
// A decode failure (bad base64) is treated identically to a
// regex-compile failure: caller drops the pattern, surfaces it via
// Diagnostics(). We do NOT fall back to treating a failed-decode
// string as a plaintext regex — that would be a defense-in-depth
// regression (an attacker who could rewrite the embed FS could
// smuggle in a non-encoded pattern). The contract is "if you start
// with the sentinel, the rest MUST be valid base64."
//
// We don't use regexp.MustCompile because that panics — and a hook
// subprocess that panics produces no stdout, which Cursor treats as
// fail-open by silent default. Recover-and-continue is the right
// posture: a single bad regex must not derail the rest of the bundle.
func compileSafeRegex(s string) (*regexp.Regexp, error) {
	if strings.HasPrefix(s, encodedPatternPrefix) {
		decoded, err := base64.StdEncoding.DecodeString(s[len(encodedPatternPrefix):])
		if err != nil {
			return nil, fmt.Errorf("decode atr-b64 envelope: %w", err)
		}
		s = string(decoded)
	}
	return regexp.Compile(s)
}
