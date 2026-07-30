package reputation

import "testing"

func TestNewFromParams_DefaultsToMalanta(t *testing.T) {
	for _, provider := range []string{"", "malanta", "MALANTA", " Malanta "} {
		p, err := NewFromParams(provider, MalantaParams{BaseURL: "https://app.malanta.ai/data", APIKey: "k"}, nil, 0, 0, 0)
		if err != nil {
			t.Fatalf("provider=%q: unexpected error: %v", provider, err)
		}
		if p.Name() != "malanta" {
			t.Errorf("provider=%q: got %q, want malanta", provider, p.Name())
		}
	}
}

func TestNewFromParams_Generic(t *testing.T) {
	cfg := &GenericProviderConfig{
		BaseURL:      "https://example.com",
		Mode:         GenericModeSingle,
		AllowedHosts: []string{"example.com"},
		Domain:       &GenericEndpoint{PathTemplate: "/lookup/{value}"},
	}
	p, err := NewFromParams("generic", MalantaParams{}, cfg, 0, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "generic" {
		t.Errorf("got %q, want generic", p.Name())
	}
}

// TestNewFromParams_GenericDisplayName guards the optional
// GenericProviderConfig.Name override (see docs/providers.md): a
// configured vendor name flows through Provider.Name() unchanged, so every
// downstream user-facing surface (deny messages, decision log, cache
// namespace) says the actual vendor instead of "generic".
func TestNewFromParams_GenericDisplayName(t *testing.T) {
	cfg := &GenericProviderConfig{
		Name:         "virustotal",
		BaseURL:      "https://example.com",
		Mode:         GenericModeSingle,
		AllowedHosts: []string{"example.com"},
		Domain:       &GenericEndpoint{PathTemplate: "/lookup/{value}"},
	}
	p, err := NewFromParams("generic", MalantaParams{}, cfg, 0, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "virustotal" {
		t.Errorf("got %q, want virustotal", p.Name())
	}
}

func TestNewFromParams_GenericWithoutConfigErrors(t *testing.T) {
	if _, err := NewFromParams("generic", MalantaParams{}, nil, 0, 0, 0); err == nil {
		t.Fatal("expected an error when provider=generic but no config was supplied")
	}
}

func TestNewFromParams_GenericWithInvalidConfigErrors(t *testing.T) {
	cfg := &GenericProviderConfig{BaseURL: "http://insecure.example"} // missing https, allowed_hosts, endpoints
	if _, err := NewFromParams("generic", MalantaParams{}, cfg, 0, 0, 0); err == nil {
		t.Fatal("expected an error for an invalid generic config (fail-closed at construction)")
	}
}

func TestNewFromParams_UnknownProviderErrors(t *testing.T) {
	if _, err := NewFromParams("not-a-real-provider", MalantaParams{}, nil, 0, 0, 0); err == nil {
		t.Fatal("expected an error for an unrecognized provider value")
	}
}
