package config

import (
	"testing"

	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

func TestIsUnconfigured_TrueWhenMalantaWithNoKey(t *testing.T) {
	c := Defaults()
	c.APIKey = ""
	if !c.IsUnconfigured() {
		t.Error("expected IsUnconfigured=true for the default provider with no API key")
	}
}

func TestIsUnconfigured_FalseWhenKeyPresent(t *testing.T) {
	c := Defaults()
	c.APIKey = "some-key"
	if c.IsUnconfigured() {
		t.Error("expected IsUnconfigured=false once an API key is set")
	}
}

func TestIsUnconfigured_GenericNoAuthIsConfigured(t *testing.T) {
	c := Defaults()
	c.Provider = "generic"
	c.Generic = &reputation.GenericProviderConfig{} // no auth header declared
	if c.IsUnconfigured() {
		t.Error("expected a generic provider with no declared auth (public API) to be considered configured")
	}
}

// A generic provider that declares auth but whose secret env var is
// unset is unconfigured (parity with a missing Malanta key), and becomes
// configured once the secret is present.
func TestIsUnconfigured_GenericDeclaredAuthTracksSecretPresence(t *testing.T) {
	c := Defaults()
	c.Provider = "generic"
	c.Generic = &reputation.GenericProviderConfig{
		Auth: reputation.GenericAuth{Header: "x-apikey", EnvVar: "ZT_VENDOR_KEY"},
	}
	t.Setenv("ZT_VENDOR_KEY", "")
	if !c.IsUnconfigured() {
		t.Error("expected IsUnconfigured=true when the declared auth secret env var is unset")
	}
	t.Setenv("ZT_VENDOR_KEY", "secret")
	if c.IsUnconfigured() {
		t.Error("expected IsUnconfigured=false once the auth secret env var is set")
	}
}

func TestDefaults_RequireConfiguredIsFalse(t *testing.T) {
	c := Defaults()
	if c.RequireConfigured {
		t.Error("expected RequireConfigured to default to false (individual/unmanaged install posture)")
	}
}

func TestLoad_RequireConfiguredEnvVar(t *testing.T) {
	t.Setenv("TRUSTGATE_REQUIRE_CONFIGURED", "true")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.RequireConfigured {
		t.Error("expected TRUSTGATE_REQUIRE_CONFIGURED=true to set RequireConfigured")
	}
}

func TestLoad_DefaultScopeModeIsAll(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ScopeMode != ScopeAll {
		t.Errorf("expected default ScopeMode=%q, got %q", ScopeAll, c.ScopeMode)
	}
}

func TestLoad_ScopeModeAndPathsEnvVars(t *testing.T) {
	t.Setenv("TRUSTGATE_SCOPE_MODE", "allowlist")
	t.Setenv("TRUSTGATE_SCOPE_PATHS", "/Users/me/work/*, /Users/me/company/*")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ScopeMode != ScopeAllowlist {
		t.Errorf("expected ScopeMode=%q, got %q", ScopeAllowlist, c.ScopeMode)
	}
	if len(c.ScopePaths) != 2 || c.ScopePaths[0] != "/Users/me/work/*" || c.ScopePaths[1] != "/Users/me/company/*" {
		t.Errorf("unexpected ScopePaths: %#v", c.ScopePaths)
	}
}

func TestLoad_RejectsUnrecognizedScopeMode(t *testing.T) {
	t.Setenv("TRUSTGATE_SCOPE_MODE", "denyliist") // typo
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error for an unrecognized scope_mode value")
	}
}
