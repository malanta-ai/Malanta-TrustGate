package reputation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// exampleConfigFile mirrors the shape an operator pastes into
// ~/.config/trustgate/config.json: the top-level provider selector plus a
// generic_provider block. Loading it via this struct (rather than
// hand-copying fields into the test) means the shipped doc example and this
// test can't silently drift apart — see docs/providers.md.
type exampleConfigFile struct {
	Provider                 string                `json:"provider"`
	GenericProvider          GenericProviderConfig `json:"generic_provider"`
	MinMaliciousScoreToBlock float64               `json:"min_malicious_score_to_block"`
}

func loadExampleConfig(t *testing.T, path string) exampleConfigFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var cfg exampleConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return cfg
}

// TestVirusTotalExampleConfig_ValidatesAndParsesRealShape guards
// docs/examples/generic-provider-configs/virustotal.json against both
// config-schema drift (Validate) and VirusTotal API v3 response-shape
// drift, by replaying VT's actual documented JSON:API response body
// (see docs.virustotal.com) through the generic engine's dot-path mapper.
func TestVirusTotalExampleConfig_ValidatesAndParsesRealShape(t *testing.T) {
	cfg := loadExampleConfig(t, "../../docs/examples/generic-provider-configs/virustotal.json")

	if cfg.Provider != "generic" {
		t.Fatalf("expected provider=generic, got %q", cfg.Provider)
	}

	// Real (trimmed) VT v3 GET /domains/{domain} response shape.
	const vtDomainResponse = `{
		"data": {
			"id": "malicious.example.com",
			"type": "domain",
			"attributes": {
				"last_analysis_stats": {
					"harmless": 70,
					"malicious": 7,
					"suspicious": 2,
					"undetected": 10,
					"timeout": 0
				}
			}
		}
	}`
	// Real (trimmed) VT v3 GET /ip_addresses/{ip} response shape.
	const vtIPResponse = `{
		"data": {
			"id": "203.0.113.5",
			"type": "ip_address",
			"attributes": {
				"last_analysis_stats": {
					"harmless": 80,
					"malicious": 0,
					"suspicious": 0,
					"undetected": 12,
					"timeout": 0
				}
			}
		}
	}`

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-apikey"); got != "vt-secret" {
			t.Errorf("missing/wrong x-apikey header: %q", got)
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/domains/"):
			w.Write([]byte(vtDomainResponse))
		case strings.HasPrefix(r.URL.Path, "/ip_addresses/"):
			w.Write([]byte(vtIPResponse))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer tlsSrv.Close()

	// Point the config's base_url/allowed_hosts at the test server; the
	// SSRF-guardrail Validate() semantics for the real www.virustotal.com
	// host are covered by the generic-provider Validate unit tests, not
	// this shape test.
	genCfg := cfg.GenericProvider
	genCfg.BaseURL = tlsSrv.URL
	genCfg.AllowedHosts = []string{strings.TrimPrefix(tlsSrv.URL, "https://")}

	p := newTestGenericProvider(genCfg, tlsSrv.Client(), "vt-secret")

	domainInd := Indicator{Kind: KindDomain, Value: "malicious.example.com"}
	ipInd := Indicator{Kind: KindIPv4, Value: "203.0.113.5"}
	got, err := p.Lookup(context.Background(), []Indicator{domainInd, ipInd})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if lbl := got[domainInd]; lbl == nil || lbl.MaliciousScore != 7 {
		t.Errorf("domain: expected score_path to resolve last_analysis_stats.malicious=7, got %+v", lbl)
	}
	if lbl := got[ipInd]; lbl == nil || lbl.MaliciousScore != 0 {
		t.Errorf("ip: expected score_path to resolve last_analysis_stats.malicious=0, got %+v", lbl)
	}

	// The example's min_malicious_score_to_block=3 is a raw AV-engine
	// COUNT, not a 0..1 probability (VerdictPath is deliberately left
	// empty — VT has no single "verdict name" field, see
	// GenericResponseMapping's doc comment on ScorePath). Confirm the
	// example documents a threshold that would actually flip these two
	// fixtures the right way: 7 >= 3 (deny), 0 >= 3 is false (allow).
	if cfg.MinMaliciousScoreToBlock <= 0 {
		t.Fatalf("expected a positive min_malicious_score_to_block tuned for VT's raw engine-count scale, got %v", cfg.MinMaliciousScoreToBlock)
	}
	if got[domainInd].MaliciousScore < cfg.MinMaliciousScoreToBlock {
		t.Errorf("expected the malicious-flagged domain fixture (%v) to cross the example's threshold (%v)",
			got[domainInd].MaliciousScore, cfg.MinMaliciousScoreToBlock)
	}
	if got[ipInd].MaliciousScore >= cfg.MinMaliciousScoreToBlock {
		t.Errorf("expected the clean IP fixture (%v) to stay under the example's threshold (%v)",
			got[ipInd].MaliciousScore, cfg.MinMaliciousScoreToBlock)
	}
	if cfg.GenericProvider.Name != "virustotal" {
		t.Errorf("expected the example config's optional display name to be set, got %q", cfg.GenericProvider.Name)
	}
}

// TestGenericExampleConfigs_AllParseAndValidateShape confirms every shipped
// example config (including skeletons not covered by a response-shape
// test) at least parses into GenericProviderConfig with a well-formed
// shape — catches JSON typos and schema drift even for the configs that
// don't warrant a full httptest fixture.
func TestGenericExampleConfigs_AllParseAndValidateShape(t *testing.T) {
	files := []string{
		"../../docs/examples/generic-provider-configs/virustotal.json",
		"../../docs/examples/generic-provider-configs/abuseipdb.json",
		"../../docs/examples/generic-provider-configs/template.json",
		"../../docs/examples/generic-provider-configs/template-batch.json",
	}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			cfg := loadExampleConfig(t, f)
			if cfg.Provider != "generic" {
				t.Errorf("expected provider=generic, got %q", cfg.Provider)
			}
			// Validate() never performs DNS resolution (see
			// extract.IsNonRoutableHost) — it only checks scheme,
			// non-loopback-ness, and allowlist membership — so even
			// the REPLACE-ME.example.com skeletons validate cleanly
			// on syntax/shape alone, without needing a live host.
			if err := cfg.GenericProvider.Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
		})
	}
}
