// Package integration spawns each of the five hook binaries as a real
// subprocess and verifies the wire contract Cursor depends on (JSON
// shape on stdout, exit-zero, no stderr noise on the happy path). Unit
// tests cover the per-package internals; this file covers the seams
// between them.
//
// These tests do NOT call the live Malanta API. Each test pre-seeds
// the SQLite cache with the verdict it wants to assert, then runs the
// binary against a stdin payload that references the seeded domain.
// verdict.Compose's Phase 1 satisfies the lookup from cache, so Phase 2
// (API call) is never reached and we don't need to redirect
// MALANTA_API_BASE_URL through the loopback gate the API-host allowlist
// now blocks.
//
// Binaries are built once into a per-test temp dir via `go build` so
// each test case is a fast `os/exec` of a static binary, not a `go run`
// (`go run` adds ~150 ms of compile time per invocation, which would
// dominate the test runtime).
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/cache"
	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

// binaries is the set of cmd packages we exercise. The test infra builds
// each one into a temp dir at TestMain time.
var binaries = []string{
	"trustgate-before-shell",
	"trustgate-before-mcp",
	"trustgate-before-prompt",
	"trustgate-before-read-file",
	"trustgate-before-tool-use",
}

var binDir string // populated by TestMain

// binPath returns the on-disk path of a built hook binary. The .exe suffix
// is required on Windows in both directions: `go build -o` takes the name
// literally (it will happily write an extension-less file), and Windows
// then refuses to execute anything without a recognized executable
// extension — which surfaced as "executable file not found in %PATH%" for
// a path that existed.
func binPath(name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(binDir, name)
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trustgate-int-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mktemp:", err)
		os.Exit(2)
	}
	defer os.RemoveAll(dir)
	binDir = dir

	for _, b := range binaries {
		out := binPath(b)
		cmd := exec.Command("go", "build", "-o", out, "./cmd/"+b)
		cmd.Dir = repoRoot()
		buf, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "build %s failed: %v\n%s\n", b, err, buf)
			os.Exit(2)
		}
	}
	os.Exit(m.Run())
}

// repoRoot resolves the repository root by walking up from this test
// file's package directory until it finds go.mod. Avoids hardcoding
// paths so `go test ./...` works regardless of cwd.
func repoRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("integration tests: could not locate go.mod")
		}
		dir = parent
	}
}

// isolatedEnviron returns os.Environ() with HOME (and, defensively,
// any MALANTA_API_KEY/TRUSTGATE_* already present) stripped and
// replaced with a fresh, empty temp directory. config.EnvFiles()
// resolves ~/.config/trustgate/env via os.UserHomeDir(), which reads
// HOME — WITHOUT this, a subprocess spawned by a test inherits the
// REAL developer's HOME, and godotenv.Overload (called by every hook
// binary via config.LoadWithEnvFiles) will silently layer in whatever
// that developer has configured for their own live TrustGate install
// (API key, AllowUserOverride, scope allowlist, ...), overriding
// exactly the env vars a test just set. This is not hypothetical: it
// broke TestReadFile_DenyOnSeededMaliciousInWorkspace,
// TestUnconfigured_InertAllowByDefault, and
// TestScope_AllowlistInScopeStillEnforcesNormally on a machine that
// had previously run `trustgate setup` / hand-written
// ~/.config/trustgate/env for its own local testing. Every env-builder
// in this file must route through this helper — see AGENTS.md's
// "tests stay hermetic by default" rule.
//
// USERPROFILE is redirected alongside HOME because os.UserHomeDir() reads
// USERPROFILE on Windows; overriding HOME alone leaves a Windows hook
// subprocess reading the real profile, which is the same leak this helper
// exists to prevent.
func isolatedEnviron(t *testing.T) []string {
	t.Helper()
	fakeHome := t.TempDir()
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "USERPROFILE=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "HOME="+fakeHome)
	if runtime.GOOS == "windows" {
		env = append(env, "USERPROFILE="+fakeHome)
	}
	return env
}

// hookEnv builds an env block scoped to a single test, pointing the
// binary at a private cache + log location so concurrent runs don't
// collide. MALANTA_API_KEY is set to a placeholder; the cache pre-seed
// ensures the API is never consulted, so the key is unused.
// setEnv replaces (or appends) a single KEY=VALUE in env, removing any
// prior occurrences of KEY first. Using this instead of a bare append
// avoids relying on duplicate-key resolution order in the child process
// (getenv returns the FIRST match on the platforms we support, so a
// naive append of a second TRUSTGATE_MODE would be silently ignored).
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if !strings.HasPrefix(kv, prefix) {
			out = append(out, kv)
		}
	}
	return append(out, prefix+value)
}

func hookEnv(t *testing.T) (cacheDir, logPath string, env []string) {
	t.Helper()
	cacheDir = t.TempDir()
	logPath = filepath.Join(cacheDir, "decisions.log")
	env = append(isolatedEnviron(t),
		"TRUSTGATE_CACHE_DIR="+cacheDir,
		"TRUSTGATE_LOG_PATH="+logPath,
		"MALANTA_API_KEY=placeholder-unused-because-cache-is-seeded",
		// Tight inner timeout: tests must not block on network.
		"MALANTA_API_TIMEOUT_MS=100",
	)
	// Pin enforce: the shipped default is now ModeWarn, but the bulk of
	// the integration tests assert enforce-mode behavior. warnEnv (and
	// the dwell test) override this to warn via setEnv. Use setEnv so an
	// ambient TRUSTGATE_MODE from the developer's shell can't leak in.
	env = setEnv(env, "TRUSTGATE_MODE", "enforce")
	return cacheDir, logPath, env
}

// hookEnvUnconfigured is hookEnv's counterpart for the zero-touch-defaults
// tests: it deliberately does NOT set MALANTA_API_KEY, and strips any
// MALANTA_API_KEY that happens to already be present in the ambient test
// environment (a developer's or CI's shell), so these tests reliably
// exercise the "no key at all" code path regardless of what's exported
// outside the test.
func hookEnvUnconfigured(t *testing.T) (cacheDir, logPath string, env []string) {
	t.Helper()
	cacheDir = t.TempDir()
	logPath = filepath.Join(cacheDir, "decisions.log")
	for _, kv := range isolatedEnviron(t) {
		if strings.HasPrefix(kv, "MALANTA_API_KEY=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		"TRUSTGATE_CACHE_DIR="+cacheDir,
		"TRUSTGATE_LOG_PATH="+logPath,
		"MALANTA_API_TIMEOUT_MS=100",
	)
	env = setEnv(env, "TRUSTGATE_MODE", "enforce")
	return cacheDir, logPath, env
}

// seedCache writes a positive label row for `domain` into the on-disk
// cache the binary will open, so verdict.Compose finds it in Phase 1
// and skips the live provider call. Keyed under the "malanta" provider
// namespace since that's the default provider every binary uses absent a
// MALANTA_PROVIDER override.
func seedCache(t *testing.T, cacheDir, domain, label string, prob float64) {
	t.Helper()
	c, err := cache.Open(filepath.Join(cacheDir, "lookups.db"))
	if err != nil {
		t.Fatalf("seedCache open: %v", err)
	}
	defer c.Close()
	ind := reputation.Indicator{Kind: reputation.KindDomain, Value: domain}
	err = c.Put(context.Background(), "malanta", ind,
		&reputation.Label{Name: label, MaliciousScore: prob},
		time.Hour)
	if err != nil {
		t.Fatalf("seedCache put: %v", err)
	}
}

// hookRunTimeout bounds a single hook invocation so a stuck binary cannot
// hang the suite. It is deliberately far above the production hook budget:
// this guards against a hang, and is not a latency assertion.
//
// Windows gets a much larger bound because the FIRST execution of a
// freshly built binary there waits on the endpoint AV's real-time scan of
// the whole executable, which ran past a 10s ceiling on CI and killed the
// process — surfacing as a bare "exit status 1" with empty stderr, since
// Windows reports a terminated process that way rather than as a signal.
var hookRunTimeout = func() time.Duration {
	if runtime.GOOS == "windows" {
		return 60 * time.Second
	}
	return 10 * time.Second
}()

// runHook invokes a single binary with the given stdin payload and
// returns parsed stdout + stderr + exit-code info.
func runHook(t *testing.T, env []string, bin, stdin string) (stdoutJSON map[string]any, stderr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), hookRunTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath(bin))
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderrBuf bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s run: %v\nstderr: %s", bin, err, stderrBuf.String())
	}
	out := stdout.Bytes()
	if len(out) == 0 {
		t.Fatalf("%s: empty stdout (Cursor would fail-open here)", bin)
	}
	if err := json.Unmarshal(out, &stdoutJSON); err != nil {
		t.Fatalf("%s: stdout is not valid JSON: %v\nstdout: %s", bin, err, out)
	}
	return stdoutJSON, stderrBuf.String()
}

func TestShell_AllowOnCleanCommand(t *testing.T) {
	_, _, env := hookEnv(t)
	out, _ := runHook(t, env, "trustgate-before-shell",
		`{"command":"echo hello"}`)
	if got := out["permission"]; got != "allow" {
		t.Errorf("shell/clean: permission = %v, want allow; full: %v", got, out)
	}
}

// TestShell_StdinWithUTF8BOM_StillParses is the regression guard for the
// Windows-installer BOM bug: a hook payload prefixed with a UTF-8 BOM
// (EF BB BF — as PowerShell 5.1's `Set-Content -Encoding UTF8` produces)
// used to fail JSON decode with "invalid character 'ï'", which fail-closes
// to a deny in enforce mode. hookrunner now strips a leading BOM, so a
// benign command parses and is allowed.
func TestShell_StdinWithUTF8BOM_StillParses(t *testing.T) {
	_, _, env := hookEnv(t) // enforce mode: a decode failure would DENY
	out, stderr := runHook(t, env, "trustgate-before-shell",
		"\xEF\xBB\xBF"+`{"command":"echo hi"}`)
	if got := out["permission"]; got != "allow" {
		t.Errorf("shell/bom: permission = %v, want allow (BOM must be stripped, not fail-closed); full: %v\nstderr: %s",
			got, out, stderr)
	}
}

// TestShell_AskMode_EmitsAskPermission is the ask-mode end-to-end guard: with
// TRUSTGATE_MODE=ask and a Cursor version (from the payload's cursor_version
// field) at/above the ask floor, a flagged host makes the real shell binary
// emit permission:"ask" (Cursor's approve/reject), not "deny".
func TestShell_AskMode_EmitsAskPermission(t *testing.T) {
	cacheDir, _, env := hookEnv(t)
	env = setEnv(env, "TRUSTGATE_MODE", "ask")
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-shell",
		`{"cursor_version":"3.11.25","command":"curl https://malicious.example/x"}`)
	if got := out["permission"]; got != "ask" {
		t.Errorf("shell/ask: permission = %v, want ask; full: %v", got, out)
	}
}

// TestShell_AskMode_DegradesToDenyBelowFloor: ask must never fail open. When
// the payload reports a Cursor version below the ask floor, the shell binary
// emits a hard permission:"deny" (older Cursor silently ignores "ask").
func TestShell_AskMode_DegradesToDenyBelowFloor(t *testing.T) {
	cacheDir, _, env := hookEnv(t)
	env = setEnv(env, "TRUSTGATE_MODE", "ask")
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-shell",
		`{"cursor_version":"3.10.0","command":"curl https://malicious.example/x"}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("shell/ask-degrade: permission = %v, want deny; full: %v", got, out)
	}
}

// TestToolUse_AskMode_DegradesToDenyEvenAboveFloor: Cursor does not enforce
// permission:"ask" for preToolUse (WebFetch/WebSearch), so ask mode must emit
// a hard deny there even on a Cursor version at/above the floor — otherwise
// the agent waits on a dialog that never renders.
func TestToolUse_AskMode_DegradesToDenyEvenAboveFloor(t *testing.T) {
	cacheDir, _, env := hookEnv(t)
	env = setEnv(env, "TRUSTGATE_MODE", "ask")
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-tool-use",
		`{"cursor_version":"3.11.25","tool_name":"WebFetch","tool_input":{"url":"https://malicious.example/x"}}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("toolUse/ask-degrade: permission = %v, want deny; full: %v", got, out)
	}
}

func TestShell_DenyOnSeededMalicious(t *testing.T) {
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-shell",
		`{"command":"curl https://malicious.example/x"}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("shell/deny: permission = %v, want deny; full: %v", got, out)
	}
	if msg, _ := out["user_message"].(string); !strings.Contains(msg, "malicious.example") {
		t.Errorf("shell/deny: user_message missing domain: %v", out)
	}
}

func TestMCP_DenyOnSeededMalicious(t *testing.T) {
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-mcp",
		`{"tool":"fetch","arguments":{"url":"https://malicious.example/api"}}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("mcp/deny: permission = %v, want deny; full: %v", got, out)
	}
}

func TestMCP_DenyOnSeededMaliciousServerField(t *testing.T) {
	// Regression test for the MCP-server-URL bypass: a malicious MCP server URL
	// must be subjected to the verdict cascade just like the arguments.
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "malicious-server.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-mcp",
		`{"tool":"fetch","server":"https://malicious-server.example/mcp","arguments":{"data":"benign"}}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("mcp/server-field: permission = %v, want deny; full: %v", got, out)
	}
}

// TestMCP_CurrentPayload_* are the regression guards: they exercise
// the CURRENT Cursor beforeMCPExecution payload (tool_name + escaped-JSON
// tool_input + url|command), which the original hook ignored entirely,
// silently allowing every MCP call on a current client.

func TestMCP_CurrentPayload_DenyOnMaliciousToolInput(t *testing.T) {
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	// tool_input is an ESCAPED JSON STRING, exactly as Cursor sends it.
	out, _ := runHook(t, env, "trustgate-before-mcp",
		`{"tool_name":"playwright_navigate","tool_input":"{\"url\":\"https://malicious.example/x\"}","command":"playwright"}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("mcp/current-tool_input: permission = %v, want deny; full: %v", got, out)
	}
}

func TestMCP_CurrentPayload_DenyOnMaliciousRemoteURL(t *testing.T) {
	// Remote MCP server: destination is carried in `url`, tool_input benign.
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "malicious-server.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-mcp",
		`{"tool_name":"search","tool_input":"{\"query\":\"main page\"}","url":"https://malicious-server.example/mcp"}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("mcp/current-url: permission = %v, want deny; full: %v", got, out)
	}
}

func TestMCP_CurrentPayload_ObjectToolInput(t *testing.T) {
	// Structured (Claude-Code-style) tool_input object, host nested inside.
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-mcp",
		`{"tool_name":"fetch","tool_input":{"endpoint":"https://malicious.example/api"}}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("mcp/current-object-input: permission = %v, want deny; full: %v", got, out)
	}
}

func TestMCP_CurrentPayload_AllowOnCleanInput(t *testing.T) {
	cacheDir, _, env := hookEnv(t)
	// Seed the destination host as benign so the cascade allows from cache
	// without a live provider call (the placeholder key + no network would
	// otherwise fail-closed to deny in enforce mode).
	seedCache(t, cacheDir, "clean-server.example", "Clean", 0.0)
	out, _ := runHook(t, env, "trustgate-before-mcp",
		`{"tool_name":"search","tool_input":"{\"query\":\"weather today\"}","url":"https://clean-server.example/mcp"}`)
	if got := out["permission"]; got != "allow" {
		t.Errorf("mcp/current-clean: permission = %v, want allow; full: %v", got, out)
	}
}

func TestPrompt_ContinueOnCleanText(t *testing.T) {
	_, _, env := hookEnv(t)
	out, _ := runHook(t, env, "trustgate-before-prompt",
		`{"prompt":"hello world, nothing to fetch"}`)
	if got, _ := out["continue"].(bool); !got {
		t.Errorf("prompt/clean: continue = %v, want true; full: %v", out["continue"], out)
	}
}

func TestPrompt_NonWarnMode_DoesNotBlockFlaggedPrompt(t *testing.T) {
	// beforeSubmitPrompt is warn-mode-only. In the default (enforce) mode
	// it must NOT hard-block a flagged action-verb prompt at submission —
	// it allows (continue:true) and leaves enforcement to the execution
	// hooks (which still deny the agent's actual shell/MCP action). The
	// warn-mode warn-then-allow flow and the verb gate are covered in
	// warn_prompt_test.go.
	cacheDir, _, env := hookEnv(t) // hookEnv pins TRUSTGATE_MODE=enforce
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-prompt",
		`{"prompt":"please fetch https://malicious.example/x"}`)
	if got, _ := out["continue"].(bool); !got {
		t.Errorf("prompt/non-warn: continue = %v, want true (warn-mode-only gate); full: %v", out["continue"], out)
	}
}

func TestReadFile_AllowOnAllowlistedClean(t *testing.T) {
	_, _, env := hookEnv(t)
	out, _ := runHook(t, env, "trustgate-before-read-file",
		`{"file_path":"/tmp/requirements.txt","content":"foo==1.0\n","workspace_roots":["/tmp"]}`)
	if got := out["permission"]; got != "allow" {
		t.Errorf("readfile/clean: permission = %v, want allow; full: %v", got, out)
	}
}

func TestReadFile_SkipsOutOfWorkspace(t *testing.T) {
	// Workspace-roots containment regression guard. Cursor sends workspace_roots; an
	// out-of-workspace path must NOT be scanned even if the basename
	// matches the high-risk allowlist and the content looks malicious.
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-read-file",
		`{"file_path":"/etc/.../requirements.txt","content":"--index-url https://malicious.example/x","workspace_roots":["/home/dev/project"]}`)
	if got := out["permission"]; got != "allow" {
		t.Errorf("readfile/out-of-workspace: permission = %v, want allow (path outside roots); full: %v", got, out)
	}
}

func TestReadFile_DenyOnSeededMaliciousInWorkspace(t *testing.T) {
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	// Use the workspace root that matches the file path so containment passes.
	out, _ := runHook(t, env, "trustgate-before-read-file",
		`{"file_path":"/tmp/requirements.txt","content":"--index-url https://malicious.example/x","workspace_roots":["/tmp"]}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("readfile/deny: permission = %v, want deny; full: %v", got, out)
	}
}

// TestOffMode_NoExtractionNoHostLog is the PRIV-002 guard: with policy mode
// "off", a flagged domain is allowed AND no extracted host is written to the
// decision log (the user opted out of inspection entirely).
func TestOffMode_NoExtractionNoHostLog(t *testing.T) {
	cacheDir, logPath, env := hookEnv(t)
	env = setEnv(env, "TRUSTGATE_MODE", "off")
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-shell",
		`{"command":"curl https://malicious.example/x"}`)
	if got := out["permission"]; got != "allow" {
		t.Fatalf("off-mode: expected allow, got %v; full: %v", got, out)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if strings.Contains(string(data), "malicious.example") {
		t.Errorf("off-mode: decision log must not contain the extracted host, got:\n%s", data)
	}
}

func TestToolUse_AllowsUninspectedTool(t *testing.T) {
	_, _, env := hookEnv(t)
	out, _ := runHook(t, env, "trustgate-before-tool-use",
		`{"tool_name":"Read","tool_input":{"file_path":"/some/file"}}`)
	if got := out["permission"]; got != "allow" {
		t.Errorf("tooluse/uninspected: permission = %v, want allow; full: %v", got, out)
	}
}

func TestToolUse_DenyOnSeededWebFetch(t *testing.T) {
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-tool-use",
		`{"tool_name":"WebFetch","tool_input":{"url":"https://malicious.example/x"}}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("tooluse/webfetch deny: permission = %v, want deny; full: %v", got, out)
	}
}

// TestToolUse_MalformedWebFetchDeniesUnderFailClosed is the fail-closed
// guard for a recognized network tool: a
// WebFetch whose input has no usable URL (schema drift / evasion) must DENY
// under the fail-closed (enforce) default, not silently allow.
func TestToolUse_MalformedWebFetchDeniesUnderFailClosed(t *testing.T) {
	_, _, env := hookEnv(t) // enforce mode => FailClosed
	// Field renamed (uri instead of url) — the enforcement-removing drift.
	out, _ := runHook(t, env, "trustgate-before-tool-use",
		`{"tool_name":"WebFetch","tool_input":{"uri":"https://malicious.example/x"}}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("tooluse/webfetch-malformed: permission = %v, want deny under fail-closed; full: %v", got, out)
	}
}

// TestToolUse_WellFormedLocalhostWebFetchAllows confirms that guard does
// NOT over-deny: a well-formed absolute URL to a non-routable host is not
// "malformed" — it simply has no routable host to check, and is allowed.
func TestToolUse_WellFormedLocalhostWebFetchAllows(t *testing.T) {
	_, _, env := hookEnv(t)
	out, _ := runHook(t, env, "trustgate-before-tool-use",
		`{"tool_name":"WebFetch","tool_input":{"url":"http://localhost:8080/health"}}`)
	if got := out["permission"]; got != "allow" {
		t.Errorf("tooluse/webfetch-localhost: permission = %v, want allow; full: %v", got, out)
	}
}

func TestToolUse_StrictMode_DeniesUnrecognizedTool(t *testing.T) {
	_, _, env := hookEnv(t)
	env = append(env, "TRUSTGATE_TOOLUSE_STRICT=true")
	out, _ := runHook(t, env, "trustgate-before-tool-use",
		`{"tool_name":"SomeBrandNewTool","tool_input":{}}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("tooluse/strict unrecognized: permission = %v, want deny; full: %v", got, out)
	}
}

func TestToolUse_StrictMode_StillAllowsDedicatedHookAndSafeTools(t *testing.T) {
	_, _, env := hookEnv(t)
	env = append(env, "TRUSTGATE_TOOLUSE_STRICT=true")
	for _, toolName := range []string{"Shell", "Read", "Write", "Glob"} {
		out, _ := runHook(t, env, "trustgate-before-tool-use",
			`{"tool_name":"`+toolName+`","tool_input":{}}`)
		if got := out["permission"]; got != "allow" {
			t.Errorf("tooluse/strict %s: permission = %v, want allow; full: %v", toolName, got, out)
		}
	}
}

func TestToolUse_StrictMode_AllowlistExtendsCoverage(t *testing.T) {
	_, _, env := hookEnv(t)
	env = append(env, "TRUSTGATE_TOOLUSE_STRICT=true", "TRUSTGATE_TOOLUSE_ALLOWLIST=MyCustomTool")
	out, _ := runHook(t, env, "trustgate-before-tool-use",
		`{"tool_name":"MyCustomTool","tool_input":{}}`)
	if got := out["permission"]; got != "allow" {
		t.Errorf("tooluse/strict allowlisted: permission = %v, want allow; full: %v", got, out)
	}
}

func TestUnconfigured_InertAllowByDefault(t *testing.T) {
	_, _, env := hookEnvUnconfigured(t)
	out, _ := runHook(t, env, "trustgate-before-shell",
		`{"command":"curl https://example.com/x"}`)
	if got := out["permission"]; got != "allow" {
		t.Errorf("unconfigured/default: permission = %v, want allow (zero-touch inert-allow); full: %v", got, out)
	}
}

func TestUnconfigured_RequireConfiguredFailsClosed(t *testing.T) {
	_, _, env := hookEnvUnconfigured(t)
	env = append(env, "TRUSTGATE_REQUIRE_CONFIGURED=true")
	out, _ := runHook(t, env, "trustgate-before-shell",
		`{"command":"curl https://example.com/x"}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("unconfigured/require-configured: permission = %v, want deny; full: %v", got, out)
	}
}

func TestUnconfigured_NoDomainsStillAllowsTrivially(t *testing.T) {
	_, _, env := hookEnvUnconfigured(t)
	env = append(env, "TRUSTGATE_REQUIRE_CONFIGURED=true") // even in the strict setting
	out, _ := runHook(t, env, "trustgate-before-shell", `{"command":"echo hi"}`)
	if got := out["permission"]; got != "allow" {
		t.Errorf("unconfigured/no-domains: permission = %v, want allow (nothing to look up); full: %v", got, out)
	}
}

func TestScope_DenylistOutOfScopeSkipsProviderEntirely(t *testing.T) {
	// Seed a MALICIOUS verdict for the domain, so if scope were NOT
	// honored, this would deny — proving the out-of-scope short-circuit
	// really does bypass cache/provider consultation, not just happen
	// to allow for an unrelated reason.
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "malicious.example", "MALICIOUS", 0.99)
	env = append(env,
		"TRUSTGATE_SCOPE_MODE=denylist",
		"TRUSTGATE_SCOPE_PATHS=/Users/me/personal/*",
	)
	out, _ := runHook(t, env, "trustgate-before-shell",
		`{"command":"curl https://malicious.example/x","workspace_roots":["/Users/me/personal/side-project"]}`)
	if got := out["permission"]; got != "allow" {
		t.Errorf("scope/denylist out-of-scope: permission = %v, want allow (scope short-circuit); full: %v", got, out)
	}
}

func TestScope_AllowlistInScopeStillEnforcesNormally(t *testing.T) {
	cacheDir, _, env := hookEnv(t)
	seedCache(t, cacheDir, "malicious.example", "MALICIOUS", 0.99)
	env = append(env,
		"TRUSTGATE_SCOPE_MODE=allowlist",
		"TRUSTGATE_SCOPE_PATHS=/Users/me/work/*",
	)
	out, _ := runHook(t, env, "trustgate-before-shell",
		`{"command":"curl https://malicious.example/x","workspace_roots":["/Users/me/work/project1"]}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("scope/allowlist in-scope: permission = %v, want deny (normal enforcement); full: %v", got, out)
	}
}

func TestAllHooks_FailClosedOnMalformedJSON(t *testing.T) {
	// Malformed payload triggers the bootstrap error path; with the
	// default FailClosed=true, every binary must emit a deny verdict
	// in its event-specific wire shape (NOT pass through silently).
	for _, b := range binaries {
		t.Run(b, func(t *testing.T) {
			_, _, env := hookEnv(t)
			out, _ := runHook(t, env, b, "not json at all")
			if b == "trustgate-before-prompt" {
				if got, _ := out["continue"].(bool); got {
					t.Errorf("%s: expected continue=false on malformed input, got %v", b, out)
				}
			} else {
				if got := out["permission"]; got != "deny" {
					t.Errorf("%s: expected permission=deny on malformed input, got %v", b, out)
				}
			}
		})
	}
}
