package config

import (
	"strings"
	"testing"
)

// These tests cover the admin-operability config surface: policy
// mode, the audit sink's SSRF-style guardrails (mirroring
// validateAPIBaseURL's threat model — a hostile env file must not be
// able to repoint decision data at an arbitrary endpoint), and the
// related env vars.

func TestLoad_DefaultModeIsWarn(t *testing.T) {
	// The default posture is warn (educate without hard-blocking day-one
	// work); a fleet is expected to set/lock enforce explicitly. See the
	// Config.Mode doc comment and docs/admin.md §3.
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Mode != ModeWarn {
		t.Errorf("expected default Mode=%q, got %q", ModeWarn, c.Mode)
	}
}

func TestLoad_AcceptsRecognizedModes(t *testing.T) {
	for _, m := range []string{ModeEnforce, ModeReportOnly, ModeOff} {
		t.Run(m, func(t *testing.T) {
			t.Setenv("TRUSTGATE_MODE", m)
			c, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if c.Mode != m {
				t.Errorf("expected Mode=%q, got %q", m, c.Mode)
			}
		})
	}
}

func TestLoad_RejectsUnrecognizedMode(t *testing.T) {
	t.Setenv("TRUSTGATE_MODE", "enforced") // plausible typo
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error for an unrecognized mode value")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Errorf("error should mention mode: %v", err)
	}
}

func TestLoad_AuditSinkDisabledByDefault(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AuditSinkURL != "" {
		t.Errorf("expected AuditSinkURL empty by default, got %q", c.AuditSinkURL)
	}
}

func TestLoad_AuditSinkRejectsHTTP(t *testing.T) {
	t.Setenv("TRUSTGATE_AUDIT_SINK_URL", "http://collector.example.com/events")
	t.Setenv("TRUSTGATE_AUDIT_SINK_HOST_ALLOWLIST", "collector.example.com")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("expected an https-required error, got %v", err)
	}
}

func TestLoad_AuditSinkRejectsLoopback(t *testing.T) {
	t.Setenv("TRUSTGATE_AUDIT_SINK_URL", "https://127.0.0.1/events")
	t.Setenv("TRUSTGATE_AUDIT_SINK_HOST_ALLOWLIST", "127.0.0.1")
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error for a loopback audit sink URL")
	}
}

func TestLoad_AuditSinkRejectsMissingAllowlist(t *testing.T) {
	t.Setenv("TRUSTGATE_AUDIT_SINK_URL", "https://collector.example.com/events")
	// deliberately NOT setting TRUSTGATE_AUDIT_SINK_HOST_ALLOWLIST
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error when the audit sink host allowlist is empty")
	}
}

func TestLoad_AuditSinkRejectsHostNotInAllowlist(t *testing.T) {
	t.Setenv("TRUSTGATE_AUDIT_SINK_URL", "https://collector.example.com/events")
	t.Setenv("TRUSTGATE_AUDIT_SINK_HOST_ALLOWLIST", "other.example.com")
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error when the sink host isn't in its own allowlist")
	}
}

func TestLoad_AuditSinkAcceptsAllowlistedHTTPSHost(t *testing.T) {
	t.Setenv("TRUSTGATE_AUDIT_SINK_URL", "https://collector.example.com/events")
	t.Setenv("TRUSTGATE_AUDIT_SINK_HOST_ALLOWLIST", "collector.example.com")
	c, err := Load()
	if err != nil {
		t.Fatalf("expected a valid allowlisted https sink URL to pass, got: %v", err)
	}
	if c.AuditSinkURL != "https://collector.example.com/events" {
		t.Errorf("unexpected AuditSinkURL: %q", c.AuditSinkURL)
	}
}

func TestLoad_PolicyAllowlistAndOverrideEnvVars(t *testing.T) {
	t.Setenv("TRUSTGATE_POLICY_ALLOWLIST", "a.example, b.example")
	t.Setenv("TRUSTGATE_ALLOW_USER_OVERRIDE", "true")
	t.Setenv("TRUSTGATE_HELP_MESSAGE", "contact #security-help")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.PolicyAllowlist) != 2 || c.PolicyAllowlist[0] != "a.example" || c.PolicyAllowlist[1] != "b.example" {
		t.Errorf("unexpected PolicyAllowlist: %#v", c.PolicyAllowlist)
	}
	if !c.AllowUserOverride {
		t.Error("expected AllowUserOverride=true")
	}
	if c.HelpMessage != "contact #security-help" {
		t.Errorf("unexpected HelpMessage: %q", c.HelpMessage)
	}
}

func TestDefaults_AllowUserOverrideIsFalse(t *testing.T) {
	c := Defaults()
	if c.AllowUserOverride {
		t.Error("expected AllowUserOverride to default to false — this must be an explicit admin opt-in")
	}
}
