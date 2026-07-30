// Tests for beforeSubmitPrompt as a warn-mode surface: a flagged domain
// the user types WITH an action verb warns at prompt-submission time
// (continue:false), the re-submit is acknowledged (continue:true), and
// the grant that acknowledgement writes is honored by the execution hooks
// (prompt accept -> shell allow, via the shared override.json). A
// conversational mention WITHOUT an action verb passes the verb gate.
package integration

import (
	"strings"
	"testing"
)

func TestPrompt_Warn_FirstTouch_DeniesWithAuditedMessage(t *testing.T) {
	cacheDir, env := warnEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	out, _ := runHook(t, env, "trustgate-before-prompt",
		`{"prompt":"curl https://malicious.example/x"}`)
	if cont, _ := out["continue"].(bool); cont {
		t.Fatalf("prompt warn/first-touch: continue = true, want false; full: %v", out)
	}
	if _, ok := out["permission"]; ok {
		t.Errorf("prompt hook must emit the continue shape, not permission; full: %v", out)
	}
	msg, _ := out["user_message"].(string)
	if !strings.Contains(msg, "malicious.example") {
		t.Errorf("prompt warn/first-touch: user_message missing domain: %v", out)
	}
	if !strings.Contains(msg, "Audited") {
		t.Errorf("prompt warn/first-touch: expected the audited message, got: %v", msg)
	}
	if !strings.Contains(msg, "re-submit this prompt") {
		t.Errorf("prompt warn/first-touch: expected prompt-specific re-submit wording, got: %v", msg)
	}
}

func TestPrompt_Warn_Retry_IsAcknowledgedAndAllowed(t *testing.T) {
	cacheDir, env := warnEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)

	first, _ := runHook(t, env, "trustgate-before-prompt", `{"prompt":"curl https://malicious.example/x"}`)
	if cont, _ := first["continue"].(bool); cont {
		t.Fatalf("expected first touch to block (continue:false), got: %v", first)
	}
	// Re-submitting the identical prompt is the acknowledgement.
	retry, _ := runHook(t, env, "trustgate-before-prompt", `{"prompt":"curl https://malicious.example/x"}`)
	if cont, _ := retry["continue"].(bool); !cont {
		t.Errorf("prompt warn/retry: continue = false, want true (acknowledged); full: %v", retry)
	}
}

func TestPrompt_Warn_VerbGate_MentionWithoutVerbAllows(t *testing.T) {
	cacheDir, env := warnEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)
	// No action verb -> the verb gate short-circuits to allow, so the
	// user can talk ABOUT a flagged domain without being blocked.
	out, _ := runHook(t, env, "trustgate-before-prompt", `{"prompt":"is malicious.example malicious?"}`)
	if cont, _ := out["continue"].(bool); !cont {
		t.Errorf("prompt verb-gate: a conversational mention (no action verb) must pass (continue:true); full: %v", out)
	}
}

// TestPrompt_Warn_AcceptThenShellAllows is the key cross-hook property:
// accepting a prompt warning writes a grant (shared override.json) that
// the execution hooks honor, so the agent's downstream action on the same
// domain proceeds without re-warning. Default scope is "domain", so the
// grant covers exactly the accepted host.
func TestPrompt_Warn_AcceptThenShellAllows(t *testing.T) {
	cacheDir, env := warnEnv(t)
	seedCache(t, cacheDir, "malicious.example", "Malicious", 0.99)

	runHook(t, env, "trustgate-before-prompt", `{"prompt":"curl https://malicious.example/x"}`)           // warn
	acc, _ := runHook(t, env, "trustgate-before-prompt", `{"prompt":"curl https://malicious.example/x"}`) // accept -> grant
	if cont, _ := acc["continue"].(bool); !cont {
		t.Fatalf("expected the prompt re-submit to be allowed, got: %v", acc)
	}

	// The agent now runs the command; the shell hook must allow it via
	// the grant the prompt acceptance wrote.
	shell, _ := runHook(t, env, "trustgate-before-shell", `{"command":"curl https://malicious.example/x"}`)
	if got := shell["permission"]; got != "allow" {
		t.Errorf("cross-hook: shell permission = %v, want allow (grant from prompt accept); full: %v", got, shell)
	}
}
