package verdict

import (
	"errors"
	"strings"
	"testing"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
)

// TestHookError_RespectsMode guards the fix for a live customer report: a
// beforeReadFile payload that exceeded the stdin bound decoded as
// "unexpected EOF", and the bootstrap path denied it as Allow:!FailClosed
// without consulting the mode. The decision log labelled it "warn" while
// behaving like enforce, and because the bootstrap path never reached
// finalizeDecision there was no pending marker for a retry to promote —
// so warn's documented deny-once-then-allow never happened and the user
// was stuck in a loop they could not clear.
func TestHookError_RespectsMode(t *testing.T) {
	bootErr := errors.New("payload: unexpected EOF")

	tests := []struct {
		name      string
		mode      string
		hook      string
		wantAllow bool
	}{
		{"warn fails open", config.ModeWarn, "beforeReadFile", true},
		{"enforce denies", config.ModeEnforce, "beforeReadFile", false},
		{"report-only never blocks", config.ModeReportOnly, "beforeReadFile", true},
		// Unlike a provider error, an undecodable payload does NOT get
		// beforeSubmitPrompt's fail-open carve-out: malformed input is an
		// input-integrity signal, and every hook denies on it under
		// fail-closed. Guarded end to end by the integration suite's
		// TestAllHooks_FailClosedOnMalformedJSON.
		{"prompt hook still denies in enforce", config.ModeEnforce, "beforeSubmitPrompt", false},
		{"prompt hook fails open in warn, like every hook", config.ModeWarn, "beforeSubmitPrompt", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseCfg(t)
			cfg.Mode = tc.mode
			cfg.FailClosed = true

			d := HookError(cfg, nil, tc.hook, bootErr)

			if d.Allow != tc.wantAllow {
				t.Errorf("Allow = %v, want %v (reason: %s)", d.Allow, tc.wantAllow, d.Reason)
			}
			if d.HookName != tc.hook {
				t.Errorf("HookName = %q, want %q — AsJSON picks the wire shape from it", d.HookName, tc.hook)
			}
			if d.DecisionID == "" {
				t.Error("DecisionID is empty; the deny message tells users to run `trustgate explain <id>`")
			}
			if !strings.Contains(d.Reason, "unexpected EOF") {
				t.Errorf("Reason = %q, want the underlying error preserved", d.Reason)
			}
			// An allow must still be visible to an operator: a silent
			// fail-open is how a broken hook goes unnoticed for weeks.
			if d.Allow && len(d.Warnings) == 0 {
				t.Error("failed open with no warning recorded")
			}
		})
	}
}

// TestHookError_FailClosedFalseAllowsEverywhere pins the documented escape
// valve: TRUSTGATE_FAIL_CLOSED=false means "allow when we cannot decide",
// and that must hold on the bootstrap path too, including enforce mode.
func TestHookError_FailClosedFalseAllowsEverywhere(t *testing.T) {
	cfg := baseCfg(t)
	cfg.Mode = config.ModeEnforce
	cfg.FailClosed = false

	d := HookError(cfg, nil, "beforeReadFile", errors.New("payload: unexpected EOF"))
	if !d.Allow {
		t.Errorf("Allow = false with FailClosed=false; want allow (reason: %s)", d.Reason)
	}
}
