// Package atr is an in-process evaluator for ATR (Agent Threat Rules)
// behavioral detection rules. ATR (https://agentthreatrule.org) is an open,
// MIT-licensed YAML rule format for AI-agent threat detection — Sigma for
// SIEM, YARA for malware, ATR for AI agents.
//
// This package is the Malanta hooks' second-axis defender. The existing
// Malanta cascade in internal/verdict answers "is this host malicious?"
// from a domain-reputation API. The ATR pass answers a different question:
// "does this content match a known attack SHAPE?" The two run in parallel
// inside the same hook subprocess and feed a single Decision.
//
// Three hook surfaces consume ATR matches:
//
//   - beforeReadFile: skill-compromise + tool-poisoning +
//     context-exfiltration rules over file content (SKILL.md, .mdc rules,
//     .cursor/mcp.json, package manifests).
//   - beforeMCPExecution: same three categories over the registered MCP
//     server URL plus the JSON-serialized tool arguments.
//   - beforeShellExecution: a hand-curated ~30-50 rule subset from
//     privilege-escalation + excessive-autonomy + the shell-applicable
//     context-exfiltration rules, scoped at curation time to recon and
//     resource-development command shapes.
//
// Scrub-vs-ATR separation. The existing per-tool config-key scrub in
// internal/extract/shell.go blanks dotted config keys (user.email,
// default.region, ...) BEFORE the domain extractor runs. The ATR
// evaluator deliberately sees the ORIGINAL command bytes — rules like
// "aws configure set" / "git config user.email" need to match on the
// shapes the scrub erases. The scrub is a domain-extraction concern;
// ATR runs on the raw input.
//
// Rule sourcing. Rules in internal/atr/rules/ are vendored from the
// agent-threat-rules npm package (MIT licensed). The sync script
// scripts/sync-atr-rules.py fetches the package, filters by category,
// obfuscation-encodes the regex values, and copies rules into the
// embedded FS. The shell subset in
// internal/atr/rules/shell/ is hand-curated; the curation criteria are
// in each rule file's `# trustgate_shell_selection_rationale:` comment
// header.
package atr

import "regexp"

// Severity is a normalized rule severity for the per-surface deny gate.
// ATR ships rules with severities critical / high / medium / low /
// informational; this enum maps that domain to an ordered integer so
// comparisons against the deny threshold are unambiguous.
//
// Why we normalize instead of comparing strings: the YAML severity
// field is case-sensitive in the wild ("critical" vs "Critical" vs
// "CRITICAL" have all been observed in third-party rules even though
// the ATR spec canonicalizes to lowercase). Comparing on a parsed
// Severity value keeps the threshold gate immune to whitespace / case
// drift.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityInformational
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// ParseSeverity maps an ATR YAML severity string to the canonical
// Severity value. Unknown / blank inputs map to SeverityUnknown, which
// the deny gate treats conservatively (never auto-denies, always logs).
func ParseSeverity(s string) Severity {
	switch s {
	case "critical", "Critical", "CRITICAL":
		return SeverityCritical
	case "high", "High", "HIGH":
		return SeverityHigh
	case "medium", "Medium", "MEDIUM":
		return SeverityMedium
	case "low", "Low", "LOW":
		return SeverityLow
	case "informational", "Informational", "INFORMATIONAL", "info", "INFO":
		return SeverityInformational
	}
	return SeverityUnknown
}

// String returns the lowercase canonical form for decision-log
// serialization. SeverityUnknown stringifies as "unknown" so missing
// data is visible in audit, not silently elided.
func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	case SeverityInformational:
		return "informational"
	}
	return "unknown"
}

// Category is the rule-category enum, mirroring ATR's published
// 8-category taxonomy (https://agentthreatrule.org/en — "8 threat
// categories"). We only carry the categories this project consumes;
// adding a new category is a one-line constant addition plus an entry
// in allowedCategories.
type Category string

const (
	CategorySkillCompromise     Category = "skill-compromise"
	CategoryToolPoisoning       Category = "tool-poisoning"
	CategoryContextExfiltration Category = "context-exfiltration"
	CategoryPrivilegeEscalation Category = "privilege-escalation"
	CategoryExcessiveAutonomy   Category = "excessive-autonomy"
)

// allowedCategories is the set used by rules_test.go to assert that no
// out-of-scope rule sneaks into the bundle. The bundle intentionally
// excludes prompt-injection, agent-manipulation, data-poisoning,
// model-abuse, and model-security — those are active-attack or
// model-internal shapes, not the recon-and-resource-development pre-
// attack window this project targets. Adding a category here is a
// deliberate scope expansion and should be recorded as a follow-up in
// the project's internal design notes.
var allowedCategories = map[Category]struct{}{
	CategorySkillCompromise:     {},
	CategoryToolPoisoning:       {},
	CategoryContextExfiltration: {},
	CategoryPrivilegeEscalation: {},
	CategoryExcessiveAutonomy:   {},
}

// IsAllowedCategory reports whether the category is in the
// allowed set.
func IsAllowedCategory(c Category) bool {
	_, ok := allowedCategories[c]
	return ok
}

// Target is the hook surface a rule applies to. ATR rules in the wild
// declare a `field` (tool_response, agent_output, content, ...) but
// the regex doesn't know about field structure once it runs; we
// pre-route rules to a Target at bundle load time so each hook's
// Evaluate call only walks the rules that actually fit its surface.
//
// As of the 2026-05-27 pool split, TargetMCP receives the FULL pool (skill-compromise + tool-poisoning
// + context-exfiltration + privilege-escalation + excessive-autonomy)
// while TargetReadFile receives the same set MINUS tool-poisoning.
// Tool-poisoning rules are authored against MCP `tool_args` /
// `tool_response` fields, and their regex patterns (notably
// ATR-2026-00062's `__[a-z]+__` dunder match) produce immediate FPs
// when run over arbitrary file content. The structural fix is to
// honor each pattern's YAML `field:` directive at evaluate time
// (Option E in the §12.16 follow-up list); the category-level
// pre-route is the layered defense until that lands.
//
// TargetShell loads ONLY the hand-curated subset in
// internal/atr/rules/shell/ — loading the full pool on shell would
// produce a high FP rate on legitimate dev commands.
type Target string

const (
	TargetReadFile Target = "read_file"
	TargetMCP      Target = "mcp"
	TargetShell    Target = "shell"
)

// Rule is the parsed, evaluator-ready form of a single ATR YAML file.
// The struct is intentionally narrow: it carries only the fields the
// evaluator + deny gate consume, not every field ATR's schema defines.
// Reference / compliance / response / test_cases blocks from the
// source YAML are deliberately discarded at parse time — they cost
// memory and are not consulted on the hot path.
type Rule struct {
	ID          string
	Title       string
	Category    Category
	Severity    Severity
	Description string
	// Patterns is the compiled regex set extracted from the rule's
	// detection.conditions[]. Each entry carries its source field name
	// and description so a match can surface "which regex fired" to
	// the decision log without re-parsing the rule.
	Patterns []Pattern
	// Condition is "any" (default) or "all". "any" fires on the first
	// pattern match; "all" requires every pattern to match before the
	// rule is considered triggered. ATR's spec defaults to "any" and
	// the vast majority of rules in the wild rely on that default.
	Condition string
}

// Pattern is a single compiled regex from a rule's detection block,
// plus the field name and human-readable description for audit-trail
// logging. Regex is always non-nil in a Rule that reached the
// evaluator — bundle loading drops any rule with an uncompilable
// pattern.
type Pattern struct {
	Regex       *regexp.Regexp
	Field       string
	Description string
}
