package extract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// These tests pin the synthetic payloads in /testdata/ to specific extractor
// outputs. The same payloads are fed to the four hook binaries in
// scripts/smoke-test.sh; pinning them here guarantees they stay aligned with
// the Go-level extractors as the suite evolves. Paths are relative to the
// package directory (Go convention for testdata).

const testdataRel = "../../testdata"

func readJSON(t *testing.T, name string, dst any) {
	t.Helper()
	p := filepath.Join(testdataRel, name)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("unmarshal %s: %v", p, err)
	}
}

func assertDomains(t *testing.T, got, want []string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestGolden_ShellPayload(t *testing.T) {
	var in struct {
		Command string `json:"command"`
	}
	readJSON(t, "shell_payload.json", &in)
	assertDomains(t, FromShell(in.Command), []string{"malicious.example"})
}

func TestGolden_ShellPayloadClean(t *testing.T) {
	var in struct {
		Command string `json:"command"`
	}
	readJSON(t, "shell_payload_clean.json", &in)
	assertDomains(t, FromShell(in.Command), []string{"example.com"})
}

func TestGolden_MCPPayload(t *testing.T) {
	var in struct {
		Arguments any `json:"arguments"`
	}
	readJSON(t, "mcp_payload.json", &in)
	assertDomains(t, FromMCP(in.Arguments), []string{"malware.example", "example.com"})
}

func TestGolden_PromptPayload(t *testing.T) {
	var in struct {
		Prompt string `json:"prompt"`
	}
	readJSON(t, "prompt_payload.json", &in)
	assertDomains(t, FromPrompt(in.Prompt), []string{"malicious.example"})
}

func TestGolden_ReadfilePayload_ContentFallback(t *testing.T) {
	// The readfile payload carries both `path` and `content`. The cmd binary
	// scans inline content when present, but - critically - still applies
	// the path allowlist via FromFileContent. We mirror that here: passing
	// the bare content to FromPrompt would *also* find malware.example, but doing
	// so would defeat the allowlist (the original bug). This test guards
	// the gated path.
	var in struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	readJSON(t, "readfile_payload.json", &in)
	assertDomains(t, FromFileContent(in.Path, in.Content), []string{"malware.example"})
}
