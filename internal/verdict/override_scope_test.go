package verdict

import (
	"context"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/override"
	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

func TestCompose_PerDomainOverride_FlipsOnlyTheGrantedHost(t *testing.T) {
	cfg := baseCfg(t)
	cfg.AllowUserOverride = true
	cfg.OverrideScope = config.OverrideScopeDomain
	if err := override.Grant(cfg.CacheDir, "malicious.example", time.Now().Add(10*time.Minute), "investigating", "cli"); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
		"other-bad.com":     {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}

	granted := Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)
	if !granted.Allow {
		t.Errorf("expected the granted host malicious.example to be allowed, got deny: %#v", granted)
	}

	notGranted := Compose(context.Background(), cfg, "beforeShellExecution", []string{"other-bad.com"}, nil, lk, nil)
	if notGranted.Allow {
		t.Errorf("expected an unrelated flagged host to stay denied under a per-domain grant, got allow: %#v", notGranted)
	}
}

func TestCompose_TimeScopeOverride_IsBlanket(t *testing.T) {
	cfg := baseCfg(t)
	cfg.AllowUserOverride = true
	cfg.OverrideScope = config.OverrideScopeTime
	if err := override.Grant(cfg.CacheDir, "*", time.Now().Add(10*time.Minute), "blanket window", "cli"); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
		"other-bad.com":     {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}

	for _, host := range []string{"malicious.example", "other-bad.com"} {
		d := Compose(context.Background(), cfg, "beforeShellExecution", []string{host}, nil, lk, nil)
		if !d.Allow {
			t.Errorf("expected blanket time-scope override to allow %s, got deny: %#v", host, d)
		}
	}
}

func TestCompose_DenyHint_OmittedWhenOverrideNotEnabled(t *testing.T) {
	cfg := baseCfg(t)
	cfg.AllowUserOverride = false

	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}
	d := Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)
	if d.Allow {
		t.Fatal("expected deny")
	}
	out := d.AsJSON()
	if jsonContains(out, "trustgate override") {
		t.Errorf("expected no override hint when AllowUserOverride is disabled, got %s", out)
	}
}

func TestCompose_DenyHint_ShownWhenOverrideEnabledUnderEnforce(t *testing.T) {
	cfg := baseCfg(t)
	cfg.AllowUserOverride = true

	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}
	d := Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)
	out := d.AsJSON()
	if !jsonContains(out, `"permission":"deny"`) {
		t.Errorf("expected hard deny under enforce mode, got %s", out)
	}
	if !jsonContains(out, "trustgate override --domain malicious.example") {
		t.Errorf("expected the override hint in the deny message, got %s", out)
	}
}

// --- Config.ModeWarn: deny-once-then-allow-on-retry ---

func TestCompose_Warn_FirstTouch_DeniesWithAuditedMessage(t *testing.T) {
	cfg := baseCfg(t)
	cfg.Mode = config.ModeWarn

	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}
	d := Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)
	if d.Allow {
		t.Fatalf("expected the first touch to still deny, got allow: %#v", d)
	}
	if !d.Warned {
		t.Error("expected Warned=true on the first touch under warn mode")
	}
	out := d.AsJSON()
	if !jsonContains(out, `"permission":"deny"`) {
		t.Errorf("expected a hard deny (not ask) on the wire, got %s", out)
	}
	if !jsonContains(out, "Audited") {
		t.Errorf("expected the warn-mode audited-retry message, got %s", out)
	}
	if jsonContains(out, "trustgate override") {
		t.Errorf("expected NO cli override hint under warn mode, got %s", out)
	}
}

func TestCompose_Warn_Retry_PromotesAndAllows(t *testing.T) {
	cfg := baseCfg(t)
	cfg.Mode = config.ModeWarn

	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}

	first := Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)
	if first.Allow {
		t.Fatalf("expected first touch to deny, got allow: %#v", first)
	}

	// Retry: the SAME action, re-fired (this is what Cursor's "Try
	// Again" does — it re-invokes beforeShellExecution).
	retry := Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)
	if !retry.Allow {
		t.Fatalf("expected the retry to be allowed (acknowledged), got deny: %#v", retry)
	}
	if retry.Warned {
		t.Error("expected Warned=false on the retry (it was allowed, not warned again)")
	}
}

func TestCompose_Warn_WithinWindow_SubsequentTouchesAreSilent(t *testing.T) {
	cfg := baseCfg(t)
	cfg.Mode = config.ModeWarn
	cfg.OverrideWindowMinutes = 15

	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}

	Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)          // first touch: warns
	Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)          // retry: promotes+allows
	third := Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil) // within window: should be silent allow, no re-warn
	if !third.Allow {
		t.Fatalf("expected a third touch within the window to be allowed silently, got deny: %#v", third)
	}
	if third.Warned {
		t.Error("expected Warned=false for a touch within an active window")
	}
}

func TestCompose_Warn_DomainScope_DoesNotCoverAnUnrelatedHost(t *testing.T) {
	cfg := baseCfg(t)
	cfg.Mode = config.ModeWarn
	cfg.OverrideScope = config.OverrideScopeDomain

	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
		"other-bad.com":     {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}

	Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil) // warn
	Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil) // retry -> grant for malicious.example only

	other := Compose(context.Background(), cfg, "beforeShellExecution", []string{"other-bad.com"}, nil, lk, nil)
	if other.Allow {
		t.Errorf("expected an unrelated host to still warn under domain scope, got allow: %#v", other)
	}
	if !other.Warned {
		t.Error("expected the unrelated host's first touch to be Warned=true")
	}
}

func TestCompose_Warn_TimeScope_RetryGrantsBlanketWindow(t *testing.T) {
	cfg := baseCfg(t)
	cfg.Mode = config.ModeWarn
	cfg.OverrideScope = config.OverrideScopeTime

	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
		"other-bad.com":     {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}

	Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil) // warn
	Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil) // retry -> blanket grant

	other := Compose(context.Background(), cfg, "beforeShellExecution", []string{"other-bad.com"}, nil, lk, nil)
	if !other.Allow {
		t.Errorf("expected a blanket time-scope window to also cover an unrelated host, got deny: %#v", other)
	}
}

func TestCompose_Warn_DwellGate_ImmediateRetryReWarns(t *testing.T) {
	cfg := baseCfg(t)
	cfg.Mode = config.ModeWarn
	// A large dwell means any in-process (instant) retry is "too soon" to
	// count as a human acknowledgment.
	cfg.WarnAckMinSeconds = 3600

	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}

	first := Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)
	if first.Allow || !first.Warned {
		t.Fatalf("expected first touch to warn-deny, got %#v", first)
	}
	// Immediate retry: inside the dwell, so it must re-warn, NOT promote.
	retry := Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)
	if retry.Allow {
		t.Fatalf("expected an inside-dwell retry to re-warn (deny), got allow: %#v", retry)
	}
	if !retry.Warned {
		t.Error("expected Warned=true on an inside-dwell retry (treated like another first touch)")
	}
	// The pending marker must survive so a later human-paced retry can
	// still acknowledge it.
	if !override.HasPending(cfg.CacheDir, "malicious.example") {
		t.Error("expected the pending marker to survive an inside-dwell retry")
	}
}

func TestCompose_Warn_DwellGate_RetryAfterDwellPromotes(t *testing.T) {
	cfg := baseCfg(t)
	cfg.Mode = config.ModeWarn
	cfg.WarnAckMinSeconds = 2

	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}

	first := Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)
	if first.Allow {
		t.Fatalf("expected first touch to warn-deny, got %#v", first)
	}
	// Wait past the dwell, then retry: now it should promote and allow.
	time.Sleep(2100 * time.Millisecond)
	retry := Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)
	if !retry.Allow {
		t.Fatalf("expected a retry after the dwell elapsed to be allowed, got deny: %#v", retry)
	}
}

func TestCompose_Warn_ExpiredWindow_ReWarns(t *testing.T) {
	cfg := baseCfg(t)
	cfg.Mode = config.ModeWarn

	// Simulate an already-expired grant directly (faster than sleeping
	// past a real window in a unit test).
	if err := override.Grant(cfg.CacheDir, "malicious.example", time.Now().Add(-1*time.Minute), "acknowledged warning; re-run to proceed", "warn"); err != nil {
		t.Fatal(err)
	}

	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}
	d := Compose(context.Background(), cfg, "beforeShellExecution", []string{"malicious.example"}, nil, lk, nil)
	if d.Allow {
		t.Fatalf("expected an expired warn window to deny (re-warn), got allow: %#v", d)
	}
	if !d.Warned {
		t.Error("expected Warned=true when the prior window has expired")
	}
}

func jsonContains(b []byte, sub string) bool {
	s := string(b)
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}
