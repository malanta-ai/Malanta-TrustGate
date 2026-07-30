package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/cache"
	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

// seedKind is seedCache for a non-domain indicator kind. Kept separate so
// the existing host-oriented helper keeps its simple signature.
func seedKind(t *testing.T, cacheDir string, kind reputation.Kind, value, label string, score float64) {
	t.Helper()
	c, err := cache.Open(filepath.Join(cacheDir, "lookups.db"))
	if err != nil {
		t.Fatalf("seedKind open: %v", err)
	}
	defer func() { _ = c.Close() }()
	err = c.Put(context.Background(), "malanta",
		reputation.Indicator{Kind: kind, Value: value},
		&reputation.Label{Name: label, MaliciousScore: score},
		time.Hour)
	if err != nil {
		t.Fatalf("seedKind put: %v", err)
	}
}

// TestShell_DenyOnFlaggedGitHubRepo is the end-to-end wire test for GitHub
// repository reputation: a real `git clone` payload through the real shell
// binary, denied on the repository identity.
//
// github.com is seeded CLEAN on purpose. The same command also extracts
// github.com as an ordinary host, and leaving it unseeded would send it to
// the (unreachable) provider and fail closed — the test would then pass
// without ever proving the repository verdict did anything. With the host
// clean, the repository is the only thing that can produce this deny, and
// the message must name it as a repository.
func TestShell_DenyOnFlaggedGitHubRepo(t *testing.T) {
	cacheDir, logPath, env := hookEnv(t)
	seedCache(t, cacheDir, "github.com", "UNKNOWN", 0)
	seedKind(t, cacheDir, reputation.KindGitHubRepo, "acme/backdoor", "MALICIOUS", 1)

	out, stderr := runHook(t, env, "trustgate-before-shell",
		`{"command":"git clone https://github.com/Acme/Backdoor.git /tmp/x"}`)

	if got := out["permission"]; got != "deny" {
		t.Fatalf("shell/repo-deny: permission = %v, want deny; full: %v\nstderr: %s", got, out, stderr)
	}
	msg, _ := out["user_message"].(string)
	if !strings.Contains(msg, "acme/backdoor") {
		t.Errorf("user_message must name the repository, got %q", msg)
	}
	if !strings.Contains(msg, "GitHub repository") {
		t.Errorf("user_message must name the SCOPE so the block is triageable, got %q", msg)
	}

	// The decision record must carry the typed kind, which is what makes a
	// repository deny distinguishable from a hostname deny after the fact.
	rec := lastDecision(t, logPath)
	if kind := rec.Decision.Kind; kind != "github_repo" {
		t.Errorf("decision kind = %q, want github_repo", kind)
	}
	if rec.Decision.Indicator != "acme/backdoor" {
		t.Errorf("decision indicator = %q, want acme/backdoor", rec.Decision.Indicator)
	}
	if !containsValue(rec.Hosts, "acme/backdoor") {
		t.Errorf("decision record should list the repository among the inspected values, got %v", rec.Hosts)
	}
}

// TestShell_AllowOnCleanGitHubRepo is the negative control for the test
// above: identical payload shape, clean repository verdict, allow.
func TestShell_AllowOnCleanGitHubRepo(t *testing.T) {
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "github.com", "UNKNOWN", 0)
	seedKind(t, cacheDir, reputation.KindGitHubRepo, "acme/library", "UNKNOWN", 0)

	out, stderr := runHook(t, env, "trustgate-before-shell",
		`{"command":"git clone https://github.com/acme/library.git /tmp/x"}`)
	if got := out["permission"]; got != "allow" {
		t.Errorf("shell/repo-allow: permission = %v, want allow; full: %v\nstderr: %s", got, out, stderr)
	}
}

// TestShell_DenyOnFlaggedGitHubOwner covers owner-scope enforcement through
// the binary: a profile URL names no repository, so the account is what gets
// evaluated.
func TestShell_DenyOnFlaggedGitHubOwner(t *testing.T) {
	cacheDir, logPath, env := hookEnv(t)
	seedCache(t, cacheDir, "github.com", "UNKNOWN", 0)
	seedKind(t, cacheDir, reputation.KindGitHubOwner, "evilorg", "MALICIOUS", 1)

	out, stderr := runHook(t, env, "trustgate-before-shell",
		`{"command":"curl -sSL https://github.com/EvilOrg"}`)
	if got := out["permission"]; got != "deny" {
		t.Fatalf("shell/owner-deny: permission = %v, want deny; full: %v\nstderr: %s", got, out, stderr)
	}
	if rec := lastDecision(t, logPath); rec.Decision.Kind != "github_owner" {
		t.Errorf("decision kind = %q, want github_owner", rec.Decision.Kind)
	}
}

// TestReadFile_DenyOnFlaggedWorkflowAction covers the GitHub Actions
// supply-chain surface: a workflow definition is not on the HOST allowlist,
// so this can only pass if the read-file hook runs GitHub extraction under
// its own allowlist.
func TestReadFile_DenyOnFlaggedWorkflowAction(t *testing.T) {
	workspace := t.TempDir()
	cacheDir, _, env := hookEnv(t)
	seedKind(t, cacheDir, reputation.KindGitHubRepo, "acme/backdoor", "MALICIOUS", 1)

	payload := map[string]any{
		"file_path":       filepath.Join(workspace, ".github", "workflows", "ci.yml"),
		"content":         "jobs:\n  build:\n    steps:\n      - uses: acme/backdoor@v1\n",
		"workspace_roots": []string{workspace},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, stderr := runHook(t, env, "trustgate-before-read-file", string(body))
	if got := out["permission"]; got != "deny" {
		t.Errorf("readfile/workflow-deny: permission = %v, want deny; full: %v\nstderr: %s", got, out, stderr)
	}
}

// TestReadFile_DependencyFileIsCheckedForHostsOnly pins the deliberate
// scope decision documented on extract's read-file allowlist: a dependency
// file records what a project already has, so it is checked for hosts but
// not for repository names (a module path there is a naming convention, and
// the fan-out would trip the cascade's cap). Enforcement happens at the
// install command instead — see
// TestShell_DenyOnFlaggedRepoInFollowedManifest below.
func TestReadFile_DependencyFileIsCheckedForHostsOnly(t *testing.T) {
	workspace := t.TempDir()
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "github.com", "UNKNOWN", 0)
	seedKind(t, cacheDir, reputation.KindGitHubRepo, "acme/backdoor", "MALICIOUS", 1)

	payload := map[string]any{
		"file_path":       filepath.Join(workspace, "go.sum"),
		"content":         "github.com/acme/backdoor v1.0.0 h1:0000000000000000000000000000000000000000000=\n",
		"workspace_roots": []string{workspace},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, stderr := runHook(t, env, "trustgate-before-read-file", string(body))
	if got := out["permission"]; got != "allow" {
		t.Errorf("readfile/go.sum: permission = %v, want allow; full: %v\nstderr: %s", got, out, stderr)
	}
}

// TestShell_DenyOnFlaggedRepoInFollowedManifest is the other half of the
// test above, and the reason that scope decision is safe: reading the
// manifest is allowed, but the install command that CONSUMES it is denied.
//
// Nothing in the command line names the repository — only the file does —
// so this passes only if the shell hook follows the manifest path from
// argv. The filename is deliberately non-standard to show the follow keys
// off the flag, not a known-filenames list.
func TestShell_DenyOnFlaggedRepoInFollowedManifest(t *testing.T) {
	workspace := t.TempDir()
	manifest := filepath.Join(workspace, "myrequirements.txt")
	if err := os.WriteFile(manifest,
		[]byte("requests==2.31.0\ngit+https://github.com/Acme/Backdoor@main#egg=thing\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cacheDir, logPath, env := hookEnv(t)
	seedCache(t, cacheDir, "github.com", "UNKNOWN", 0)
	seedKind(t, cacheDir, reputation.KindGitHubRepo, "acme/backdoor", "MALICIOUS", 1)

	payload := map[string]any{
		"command": "pip install -r myrequirements.txt",
		"cwd":     workspace,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, stderr := runHook(t, env, "trustgate-before-shell", string(body))
	if got := out["permission"]; got != "deny" {
		t.Fatalf("shell/manifest-follow: permission = %v, want deny; full: %v\nstderr: %s", got, out, stderr)
	}
	if rec := lastDecision(t, logPath); rec.Decision.Indicator != "acme/backdoor" {
		t.Errorf("decision indicator = %q, want acme/backdoor", rec.Decision.Indicator)
	}
}

// TestToolUse_DenyOnFlaggedRepoWebFetch covers the WebFetch surface: the
// agent fetching a flagged repository page directly.
func TestToolUse_DenyOnFlaggedRepoWebFetch(t *testing.T) {
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "github.com", "UNKNOWN", 0)
	seedKind(t, cacheDir, reputation.KindGitHubRepo, "acme/backdoor", "MALICIOUS", 1)

	out, stderr := runHook(t, env, "trustgate-before-tool-use",
		`{"tool_name":"WebFetch","tool_input":{"url":"https://github.com/acme/backdoor/blob/main/run.py"}}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("tooluse/repo-deny: permission = %v, want deny; full: %v\nstderr: %s", got, out, stderr)
	}
}

// decisionRecord mirrors the JSON-Lines decision-log record shape (see
// verdict.writeLog). Only the fields these tests assert are decoded.
type decisionRecord struct {
	Hosts    []string `json:"hosts"`
	Decision struct {
		Allow     bool   `json:"allow"`
		Reason    string `json:"reason"`
		Indicator string `json:"indicator"`
		Kind      string `json:"kind"`
	} `json:"decision"`
}

// lastDecision returns the final record in the decision log.
func lastDecision(t *testing.T, logPath string) decisionRecord {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read decision log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var rec decisionRecord
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
		t.Fatalf("decode decision record: %v\nline: %s", err, lines[len(lines)-1])
	}
	return rec
}

func containsValue(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
