package config

import (
	"os"
	"testing"

	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

// genericAuthCfg builds a minimal, structurally-valid generic-provider
// Config that declares auth via an env var, for the auth-completeness checks.
func genericAuthCfg(envVar string) Config {
	return Config{
		Provider: "generic",
		Generic: &reputation.GenericProviderConfig{
			BaseURL:      "https://api.vendor.example",
			AllowedHosts: []string{"api.vendor.example"},
			Mode:         reputation.GenericModeSingle,
			Domain:       &reputation.GenericEndpoint{PathTemplate: "/v1/{value}"},
			Auth:         reputation.GenericAuth{Header: "x-apikey", EnvVar: envVar},
		},
	}
}

// TestIsUnconfigured_GenericAuthEnvVarPresence is the runtime guard:
// a generic provider that declares an auth header but whose secret env var is
// unset counts as UNCONFIGURED (so TRUSTGATE_REQUIRE_CONFIGURED detects it and
// warn mode / beforeSubmitPrompt don't fail open on the resulting 401), and
// counts as configured once the secret is present. It is deliberately NOT a
// hard Load error, so `trustgate setup` can still run to store the key.
func TestIsUnconfigured_GenericAuthEnvVarPresence(t *testing.T) {
	cfg := genericAuthCfg("VENDOR_KEY_AUTH_TEST")
	os.Unsetenv("VENDOR_KEY_AUTH_TEST")
	if !cfg.IsUnconfigured() {
		t.Error("expected IsUnconfigured=true when the declared auth env var is unset")
	}
	// Load must still succeed (structurally valid) so setup can run.
	if err := validateProviderConfig(cfg); err != nil {
		t.Errorf("expected validateProviderConfig to succeed structurally even with the key absent, got %v", err)
	}
	t.Setenv("VENDOR_KEY_AUTH_TEST", "a-secret-value")
	if cfg.IsUnconfigured() {
		t.Error("expected IsUnconfigured=false once the auth env var is set")
	}
}

// TestGenericValidate_AuthHeaderRequiresEnvVarName is the structural
// guard: declaring an auth header without naming the env var is a config
// error, independent of the process environment.
func TestGenericValidate_AuthHeaderRequiresEnvVarName(t *testing.T) {
	cfg := genericAuthCfg("")
	if err := cfg.Generic.Validate(); err == nil {
		t.Error("expected an error when auth.header is set but auth.env_var is empty")
	}
}
