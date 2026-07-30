package atr

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// These tests exercise loadCustomRules and addParsedRule DIRECTLY rather
// than through the public LoadBundled*/load() entrypoints. load() is
// guarded by a package-level sync.Once shared across the whole test
// binary, so driving TRUSTGATE_ATR_RULES_DIR through it would be
// order-dependent (whichever test in this package runs first "wins" the
// one real load). Testing the unexported helpers directly avoids that
// hazard and is still a faithful test of the bring-your-own-rules
// mechanism, since doLoad calls these same functions.

const testRuleYAML = `
id: %s
title: Test custom rule
description: A community-contributed test rule
tags:
  category: skill-compromise
detection:
  condition: any
  conditions:
    - field: content
      operator: regex
      value: "definitely-not-a-real-pattern-xyz-%s"
      description: test pattern
severity: high
`

func resetLoadedRules() {
	loadedRules = map[Target][]Rule{
		TargetReadFile: nil,
		TargetMCP:      nil,
		TargetShell:    nil,
	}
	loadErrors = nil
}

func TestLoadCustomRules_RootLevelGoesToMCPAndReadFile(t *testing.T) {
	resetLoadedRules()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"),
		[]byte(fmtRule("CUSTOM-ROOT-001", "root")), 0o600); err != nil {
		t.Fatal(err)
	}

	loadCustomRules(dir)

	if len(loadErrors) != 0 {
		t.Errorf("unexpected load errors: %v", loadErrors)
	}
	if !containsRuleID(loadedRules[TargetMCP], "CUSTOM-ROOT-001") {
		t.Errorf("expected CUSTOM-ROOT-001 in TargetMCP, got %v", ruleIDs(loadedRules[TargetMCP]))
	}
	if !containsRuleID(loadedRules[TargetReadFile], "CUSTOM-ROOT-001") {
		t.Errorf("expected CUSTOM-ROOT-001 in TargetReadFile, got %v", ruleIDs(loadedRules[TargetReadFile]))
	}
	if containsRuleID(loadedRules[TargetShell], "CUSTOM-ROOT-001") {
		t.Errorf("did not expect CUSTOM-ROOT-001 in TargetShell")
	}
}

func TestLoadCustomRules_ShellSubdirGoesToShellOnly(t *testing.T) {
	resetLoadedRules()
	dir := t.TempDir()
	shellDir := filepath.Join(dir, "shell")
	if err := os.MkdirAll(shellDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shellDir, "custom-shell.yaml"),
		[]byte(fmtRule("CUSTOM-SHELL-001", "shell")), 0o600); err != nil {
		t.Fatal(err)
	}

	loadCustomRules(dir)

	if len(loadErrors) != 0 {
		t.Errorf("unexpected load errors: %v", loadErrors)
	}
	if !containsRuleID(loadedRules[TargetShell], "CUSTOM-SHELL-001") {
		t.Errorf("expected CUSTOM-SHELL-001 in TargetShell, got %v", ruleIDs(loadedRules[TargetShell]))
	}
	if containsRuleID(loadedRules[TargetMCP], "CUSTOM-SHELL-001") {
		t.Errorf("did not expect CUSTOM-SHELL-001 in TargetMCP")
	}
	if containsRuleID(loadedRules[TargetReadFile], "CUSTOM-SHELL-001") {
		t.Errorf("did not expect CUSTOM-SHELL-001 in TargetReadFile")
	}
}

func TestLoadCustomRules_ToolPoisoningExcludedFromReadFile(t *testing.T) {
	resetLoadedRules()
	dir := t.TempDir()
	rule := `
id: CUSTOM-TP-001
title: Test tool-poisoning rule
tags:
  category: tool-poisoning
detection:
  condition: any
  conditions:
    - field: tool_args
      operator: regex
      value: "__[a-z]+__"
severity: high
`
	if err := os.WriteFile(filepath.Join(dir, "custom-tp.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}

	loadCustomRules(dir)

	if !containsRuleID(loadedRules[TargetMCP], "CUSTOM-TP-001") {
		t.Errorf("expected CUSTOM-TP-001 in TargetMCP, got %v", ruleIDs(loadedRules[TargetMCP]))
	}
	if containsRuleID(loadedRules[TargetReadFile], "CUSTOM-TP-001") {
		t.Errorf("tool-poisoning custom rules must not reach TargetReadFile (same FP class as upstream rules)")
	}
}

func TestLoadCustomRules_MissingDirectoryRecordsWarningNotFatal(t *testing.T) {
	resetLoadedRules()
	loadCustomRules(filepath.Join(t.TempDir(), "does-not-exist"))
	if len(loadErrors) == 0 {
		t.Error("expected a load error recorded for a missing custom rules dir")
	}
	// Must not panic and must leave the (empty) pools intact — a broken
	// custom-rules dir is a warning, never a bundle-load failure.
	for target, rules := range loadedRules {
		if len(rules) != 0 {
			t.Errorf("expected no rules for %s after a missing dir, got %d", target, len(rules))
		}
	}
}

func TestLoadCustomRules_OutOfScopeCategoryDropped(t *testing.T) {
	resetLoadedRules()
	dir := t.TempDir()
	rule := `
id: CUSTOM-OOS-001
title: Out of scope
tags:
  category: prompt-injection
detection:
  condition: any
  conditions:
    - field: content
      operator: regex
      value: "xyz"
severity: high
`
	if err := os.WriteFile(filepath.Join(dir, "oos.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	loadCustomRules(dir)
	if containsRuleID(loadedRules[TargetMCP], "CUSTOM-OOS-001") || containsRuleID(loadedRules[TargetReadFile], "CUSTOM-OOS-001") {
		t.Error("expected an out-of-scope category to be dropped, same as embedded rules")
	}
	if len(loadErrors) == 0 {
		t.Error("expected a load-error entry noting the dropped out-of-scope rule")
	}
}

// TestExampleCustomRule_Parses guards docs/examples/atr-custom-rules/
// sample-rule.yaml against schema drift: if a future change to the YAML
// shape (yamlRule, tagBlk, detBlk) breaks this shipped example, this test
// fails instead of leaving contributors with copy-pasted broken docs.
func TestExampleCustomRule_Parses(t *testing.T) {
	resetLoadedRules()
	// internal/atr -> internal -> repo root -> docs/examples/atr-custom-rules
	path := filepath.Join("..", "..", "docs", "examples", "atr-custom-rules")
	loadCustomRules(path)
	if len(loadErrors) != 0 {
		t.Fatalf("shipped example rule failed to load: %v", loadErrors)
	}
	if !containsRuleID(loadedRules[TargetMCP], "EXAMPLE-INTERNAL-TOOL-TOKEN") {
		t.Errorf("expected the shipped example rule to load into TargetMCP, got %v", ruleIDs(loadedRules[TargetMCP]))
	}
}

func fmtRule(id, salt string) string {
	return fmt.Sprintf(testRuleYAML, id, salt)
}

func containsRuleID(rules []Rule, id string) bool {
	for _, r := range rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

func ruleIDs(rules []Rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.ID
	}
	return out
}
