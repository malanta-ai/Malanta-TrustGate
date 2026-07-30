package verdict

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAsJSON_WireShapePerHook asserts that AsJSON emits the schema Cursor
// actually expects on stdout, per cursor.com/docs/hooks:
//   - beforeShellExecution / beforeMCPExecution / beforeReadFile:
//     {"continue": true, "permission": "allow"|"deny", "user_message"?,
//     "agent_message"?} — continue:true is always present; it keeps the
//     agent loop alive so a deny surfaces the "Try Again" retry affordance
//     (matching Cursor's own deny examples in docs/hooks.md) rather than
//     hard-stopping the turn.
//   - beforeSubmitPrompt:
//     {"continue": bool, "user_message"?}
//
// This is the most security-critical contract in the POC: if it drifts,
// Cursor cannot parse a recognized verdict, silently falls back to
// fail-open, and every deny becomes an allow.
func TestAsJSON_WireShapePerHook(t *testing.T) {
	t.Parallel()

	type wire struct {
		Permission   string `json:"permission"`
		Continue     *bool  `json:"continue"`
		UserMessage  string `json:"user_message"`
		AgentMessage string `json:"agent_message"`
		// These MUST NOT appear on the wire - they belong only to the
		// internal Decision / decision log shape. If any of them ever
		// land on stdout, Cursor will not see a recognized verdict.
		Allow  *bool  `json:"allow"`
		Reason string `json:"reason"`
		Domain string `json:"domain"`
		Label  string `json:"label"`
		Hook   string `json:"hook"`
	}

	cases := []struct {
		name            string
		dec             Decision
		wantPermission  string
		wantContinue    *bool
		wantUserMsgHas  string
		wantAgentMsgHas string
	}{
		{
			name:           "shell allow",
			dec:            Decision{Allow: true, HookName: "beforeShellExecution"},
			wantPermission: "allow",
		},
		{
			name:            "shell deny carries reason on both messages",
			dec:             Decision{Allow: false, Reason: "Malanta flagged malware.example as Suspicius", HookName: "beforeShellExecution"},
			wantPermission:  "deny",
			wantUserMsgHas:  "malware.example",
			wantAgentMsgHas: "malware.example",
		},
		{
			name:           "mcp allow",
			dec:            Decision{Allow: true, HookName: "beforeMCPExecution"},
			wantPermission: "allow",
		},
		{
			name:           "mcp deny",
			dec:            Decision{Allow: false, Reason: "Malanta flagged malicious.example as Malicious", HookName: "beforeMCPExecution"},
			wantPermission: "deny",
			wantUserMsgHas: "malicious.example",
		},
		{
			name:           "read-file allow",
			dec:            Decision{Allow: true, HookName: "beforeReadFile"},
			wantPermission: "allow",
		},
		{
			name:           "read-file deny",
			dec:            Decision{Allow: false, Reason: "blocked by policy", HookName: "beforeReadFile"},
			wantPermission: "deny",
			wantUserMsgHas: "blocked by policy",
		},
		{
			name:         "prompt allow uses continue not permission",
			dec:          Decision{Allow: true, HookName: "beforeSubmitPrompt"},
			wantContinue: boolPtr(true),
		},
		{
			name:           "prompt deny uses continue=false",
			dec:            Decision{Allow: false, Reason: "prompt referenced malware.example", HookName: "beforeSubmitPrompt"},
			wantContinue:   boolPtr(false),
			wantUserMsgHas: "malware.example",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw := tc.dec.AsJSON()
			if len(raw) == 0 || raw[len(raw)-1] != '\n' {
				t.Fatalf("AsJSON output must end with a newline, got %q", raw)
			}

			var w wire
			if err := json.Unmarshal(raw, &w); err != nil {
				t.Fatalf("AsJSON output is not valid JSON: %v\nraw: %s", err, raw)
			}

			if w.Allow != nil {
				t.Errorf("wire output must not include legacy \"allow\" field: %s", raw)
			}
			if w.Reason != "" {
				t.Errorf("wire output must not include internal \"reason\" field: %s", raw)
			}
			if w.Domain != "" || w.Label != "" || w.Hook != "" {
				t.Errorf("wire output must not leak internal fields: %s", raw)
			}

			if tc.dec.HookName == "beforeSubmitPrompt" {
				if w.Permission != "" {
					t.Errorf("prompt hook must not emit \"permission\", got %q", w.Permission)
				}
				if w.Continue == nil {
					t.Fatalf("prompt hook must emit \"continue\", got %s", raw)
				}
				if tc.wantContinue != nil && *w.Continue != *tc.wantContinue {
					t.Errorf("continue=%v, want %v", *w.Continue, *tc.wantContinue)
				}
			} else {
				// Non-prompt hooks now always emit continue:true — it
				// keeps the agent loop alive so a deny surfaces Cursor's
				// "Try Again" retry affordance (matching Cursor's own deny
				// examples) instead of hard-stopping the turn.
				if w.Continue == nil {
					t.Fatalf("non-prompt hook must emit \"continue\", got %s", raw)
				}
				if !*w.Continue {
					t.Errorf("non-prompt hook must emit continue:true, got false (raw: %s)", raw)
				}
				if w.Permission != tc.wantPermission {
					t.Errorf("permission=%q, want %q (raw: %s)", w.Permission, tc.wantPermission, raw)
				}
			}

			if tc.wantUserMsgHas != "" && !strings.Contains(w.UserMessage, tc.wantUserMsgHas) {
				t.Errorf("user_message=%q, want substring %q", w.UserMessage, tc.wantUserMsgHas)
			}
			if tc.wantAgentMsgHas != "" && !strings.Contains(w.AgentMessage, tc.wantAgentMsgHas) {
				t.Errorf("agent_message=%q, want substring %q", w.AgentMessage, tc.wantAgentMsgHas)
			}
		})
	}
}

// TestAsJSON_DefaultHookFallsBackToPermissionShape guards against an empty
// HookName: in that case we cannot know which schema Cursor expects, so we
// must pick the security-conservative default (the permission shape, which
// is the one shared by the three "guard" hooks).
func TestAsJSON_DefaultHookFallsBackToPermissionShape(t *testing.T) {
	t.Parallel()
	d := Decision{Allow: false, Reason: "fallback", HookName: ""}
	raw := d.AsJSON()
	var w struct {
		Permission string `json:"permission"`
		Continue   *bool  `json:"continue"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if w.Permission != "deny" {
		t.Errorf("default hook deny: permission=%q, want \"deny\"", w.Permission)
	}
	// The empty-HookName fallback uses the shared non-prompt shape, which
	// now carries continue:true (see TestAsJSON_WireShapePerHook).
	if w.Continue == nil || !*w.Continue {
		t.Errorf("default hook must emit continue:true, got %s", raw)
	}
}

// TestAsJSON_WarnFirstTouch_AgentMessageDiffersFromUser guards the core
// of the warn-mode auto-retry fix: on a warn first touch the human is
// told how to proceed ("re-run the same action"), but the AGENT is told
// to stop and NOT retry — otherwise the agent obeys the human-facing
// instruction and silently self-acknowledges the warning.
func TestAsJSON_WarnFirstTouch_AgentMessageDiffersFromUser(t *testing.T) {
	t.Parallel()
	d := Decision{
		Allow:      false,
		Warned:     true,
		Reason:     "malanta flagged planets.website as MALICIOUS (malicious score 0.92)",
		HookName:   "beforeShellExecution",
		DecisionID: "abc123",
	}
	raw := d.AsJSON()
	var w struct {
		UserMessage  string `json:"user_message"`
		AgentMessage string `json:"agent_message"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// The human is still told how to proceed.
	if !strings.Contains(w.UserMessage, "re-run the same action") {
		t.Errorf("user_message should keep the human retry guidance, got %q", w.UserMessage)
	}

	// The agent must NOT be handed a retry instruction, and must be told
	// to stop / defer to the human.
	if strings.Contains(strings.ToLower(w.AgentMessage), "re-run") ||
		strings.Contains(strings.ToLower(w.AgentMessage), "retry to allow") {
		t.Errorf("agent_message must not instruct the agent to retry, got %q", w.AgentMessage)
	}
	if !strings.Contains(strings.ToLower(w.AgentMessage), "do not retry") {
		t.Errorf("agent_message should explicitly tell the agent not to retry, got %q", w.AgentMessage)
	}
	if w.UserMessage == w.AgentMessage {
		t.Error("expected user_message and agent_message to differ on a warn first touch")
	}
	// Both still carry the reason + decision id (so the audit key is
	// present regardless of audience).
	for _, m := range []string{w.UserMessage, w.AgentMessage} {
		if !strings.Contains(m, "planets.website") || !strings.Contains(m, "abc123") {
			t.Errorf("both messages must carry the reason and decision_id, got %q", m)
		}
	}
}

// TestAsJSON_NonWarnDeny_AgentAndUserMessagesMatch confirms the split is
// warn-first-touch-only: an ordinary (enforce) deny still sends identical
// text to both audiences.
func TestAsJSON_NonWarnDeny_AgentAndUserMessagesMatch(t *testing.T) {
	t.Parallel()
	d := Decision{
		Allow:      false,
		Reason:     "malanta flagged malicious.example as MALICIOUS (malicious score 0.99)",
		HookName:   "beforeShellExecution",
		DecisionID: "def456",
	}
	raw := d.AsJSON()
	var w struct {
		UserMessage  string `json:"user_message"`
		AgentMessage string `json:"agent_message"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if w.UserMessage != w.AgentMessage {
		t.Errorf("non-warn deny should send identical user/agent messages; user=%q agent=%q", w.UserMessage, w.AgentMessage)
	}
}

func boolPtr(b bool) *bool { return &b }
