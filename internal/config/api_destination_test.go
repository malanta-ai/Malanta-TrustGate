package config

import (
	"strings"
	"testing"
)

// These tests cover the API destination allowlist + URL validation added
// to harden against a hostile env file repointing the Malanta lookup at
// a key-harvesting endpoint. The threat model: the verdict cascade
// holds the customer's API key on every request, and we
// cannot rely on the build artifact to be the only configurable input.

func TestLoad_AcceptsBuiltInBaseURL(t *testing.T) {
	t.Setenv("MALANTA_API_BASE_URL", "https://app.malanta.ai")
	if _, err := Load(); err != nil {
		t.Fatalf("default base URL should validate, got: %v", err)
	}
}

func TestLoad_RejectsHTTPBaseURL(t *testing.T) {
	t.Setenv("MALANTA_API_BASE_URL", "http://app.malanta.ai")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error on plain-http base URL")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error should mention https requirement: %v", err)
	}
}

func TestLoad_RejectsLoopbackBaseURL(t *testing.T) {
	cases := []string{
		"https://127.0.0.1/api",
		"https://localhost/api",
		"https://[::1]/api",
	}
	for _, base := range cases {
		t.Run(base, func(t *testing.T) {
			t.Setenv("MALANTA_API_BASE_URL", base)
			_, err := Load()
			if err == nil {
				t.Fatalf("expected error on loopback base URL %q", base)
			}
		})
	}
}

func TestLoad_RejectsPrivateBaseURL(t *testing.T) {
	cases := []string{
		"https://10.0.0.1/api",
		"https://192.168.1.1/api",
		"https://172.16.0.1/api",
		"https://169.254.169.254/api", // link-local (also AWS IMDS)
		"https://100.64.0.1/api",      // CGNAT
	}
	for _, base := range cases {
		t.Run(base, func(t *testing.T) {
			t.Setenv("MALANTA_API_BASE_URL", base)
			_, err := Load()
			if err == nil {
				t.Fatalf("expected error on private-IP base URL %q", base)
			}
		})
	}
}

func TestLoad_RejectsBaseURLNotInAllowlist(t *testing.T) {
	t.Setenv("MALANTA_API_BASE_URL", "https://evil.example/")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error on out-of-allowlist host")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "allowlist") {
		t.Errorf("error should mention allowlist: %v", err)
	}
}

func TestLoad_AllowlistEnvIsAdditive(t *testing.T) {
	t.Setenv("MALANTA_API_BASE_URL", "https://staging.malanta.ai/")
	t.Setenv("MALANTA_API_HOST_ALLOWLIST", "staging.malanta.ai")
	c, err := Load()
	if err != nil {
		t.Fatalf("staging host in env-allowlist should validate, got: %v", err)
	}
	// Built-in entry must remain in the resolved allowlist; the env
	// extends, it does not replace. Operator who edits env cannot
	// remove "app.malanta.ai" from trusted hosts.
	found := false
	for _, h := range c.APIHostAllowlist {
		if h == "app.malanta.ai" {
			found = true
		}
	}
	if !found {
		t.Errorf("built-in app.malanta.ai missing from allowlist: %v", c.APIHostAllowlist)
	}
}

func TestLoad_BuiltInStillTrustedWhenEnvOverridePresent(t *testing.T) {
	// Reverse of the above: even with a custom staging entry in the
	// env, the original app.malanta.ai base URL still validates.
	t.Setenv("MALANTA_API_BASE_URL", "https://app.malanta.ai/")
	t.Setenv("MALANTA_API_HOST_ALLOWLIST", "staging.malanta.ai,other.malanta.ai")
	if _, err := Load(); err != nil {
		t.Fatalf("app.malanta.ai must validate alongside env additions, got: %v", err)
	}
}

func TestLoad_RejectsMalformedBaseURL(t *testing.T) {
	t.Setenv("MALANTA_API_BASE_URL", "::not a url::")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error on malformed base URL")
	}
}

func TestLoad_RejectsEmptyBaseURL(t *testing.T) {
	// Defaults() sets a non-empty base URL, so we have to dodge that:
	// load defaults, then call validateAPIBaseURL directly with "" to
	// exercise the empty-string branch.
	if err := validateAPIBaseURL("", []string{"app.malanta.ai"}); err == nil {
		t.Fatal("expected error on empty base URL")
	}
}
