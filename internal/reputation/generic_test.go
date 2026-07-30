package reputation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- Validate() / SSRF guardrail tests ---

func validConfig(host string) GenericProviderConfig {
	return GenericProviderConfig{
		BaseURL:      "https://" + host,
		Mode:         GenericModeSingle,
		AllowedHosts: []string{host},
		Domain: &GenericEndpoint{
			PathTemplate: "/lookup/{value}",
			Mapping:      GenericResponseMapping{VerdictPath: "verdict", ScorePath: "score"},
		},
	}
}

func TestGenericValidate_RejectsHTTP(t *testing.T) {
	cfg := validConfig("example.com")
	cfg.BaseURL = "http://example.com"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("expected an https-required error, got %v", err)
	}
}

func TestGenericValidate_RejectsEmptyAllowedHosts(t *testing.T) {
	cfg := validConfig("example.com")
	cfg.AllowedHosts = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for empty allowed_hosts")
	}
}

func TestGenericValidate_RejectsHostNotInAllowlist(t *testing.T) {
	cfg := validConfig("example.com")
	cfg.AllowedHosts = []string{"other.example"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error when base_url host is not in allowed_hosts")
	}
}

func TestGenericValidate_RejectsLoopbackHost(t *testing.T) {
	cfg := validConfig("127.0.0.1")
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for a loopback base_url host")
	}
}

func TestGenericValidate_RejectsUnknownMode(t *testing.T) {
	cfg := validConfig("example.com")
	cfg.Mode = "bogus"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for an unrecognized mode")
	}
}

func TestGenericValidate_RejectsNoEndpoints(t *testing.T) {
	cfg := validConfig("example.com")
	cfg.Domain = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error when neither domain nor ip is configured")
	}
}

func TestGenericValidate_RejectsSingleModeMissingPlaceholder(t *testing.T) {
	cfg := validConfig("example.com")
	cfg.Domain.PathTemplate = "/lookup/static"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error when path_template has no {value}/{domain}/{ip} placeholder")
	}
}

func TestGenericValidate_RejectsBatchModeMissingFields(t *testing.T) {
	cfg := validConfig("example.com")
	cfg.Mode = GenericModeBatch
	cfg.Domain.Path = ""
	cfg.Domain.BodyField = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error when batch mode is missing path/body_field")
	}
}

func TestGenericValidate_AcceptsWellFormedConfig(t *testing.T) {
	if err := validConfig("example.com").Validate(); err != nil {
		t.Errorf("expected a well-formed config to validate, got %v", err)
	}
}

// --- Single-mode Lookup ---

// newTestGenericProvider builds a GenericProvider directly (bypassing
// NewGeneric/Validate) so the LOOKUP mechanics can be tested against a
// local httptest server. httptest servers bind to 127.0.0.1, which
// Validate correctly rejects as loopback (see TestGenericValidate_
// RejectsLoopbackHost) — that's the SSRF guard doing its job, not a test
// limitation to work around in production code. Validation and lookup
// mechanics are therefore tested separately by design.
func newTestGenericProvider(cfg GenericProviderConfig, client *http.Client, apiKey string) *GenericProvider {
	return &GenericProvider{
		cfg:         cfg,
		apiKey:      apiKey,
		maxAttempts: 1,
		http:        client,
	}
}

func TestGenericSingle_HappyPath(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-apikey"); got != "secret" {
			t.Errorf("missing/wrong auth header: %q", got)
		}
		verdict := "clean"
		score := 0.0
		if strings.Contains(r.URL.Path, "malicious.example.com") {
			verdict = "malicious"
			score = 0.9
		}
		json.NewEncoder(w).Encode(map[string]any{"verdict": verdict, "score": score})
	}))
	defer tlsSrv.Close()

	p := newTestGenericProvider(GenericProviderConfig{
		BaseURL: tlsSrv.URL,
		Mode:    GenericModeSingle,
		Auth:    GenericAuth{Header: "x-apikey"},
		Domain: &GenericEndpoint{
			PathTemplate: "/lookup/{value}",
			Mapping:      GenericResponseMapping{VerdictPath: "verdict", ScorePath: "score"},
		},
	}, tlsSrv.Client(), "secret")

	ind := Indicator{Kind: KindDomain, Value: "malicious.example.com"}
	got, err := p.Lookup(context.Background(), []Indicator{ind})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	lbl := got[ind]
	if lbl == nil || lbl.Name != "malicious" || lbl.MaliciousScore != 0.9 {
		t.Errorf("unexpected label: %#v", lbl)
	}
}

// TestGenericSingle_NullScoreMarksScoreMissing mirrors the live Malanta
// finding (verdict flagged, score field null) for the config-driven
// generic adapter: a vendor whose score field is present-but-null must
// resolve to ScoreMissing: true, not a silent Probability: 0 that looks
// identical to a genuinely-scored-clean verdict.
func TestGenericSingle_NullScoreMarksScoreMissing(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"verdict":"malicious","score":null}`)
	}))
	defer tlsSrv.Close()

	p := newTestGenericProvider(GenericProviderConfig{
		BaseURL: tlsSrv.URL,
		Mode:    GenericModeSingle,
		Domain: &GenericEndpoint{
			PathTemplate: "/lookup/{value}",
			Mapping:      GenericResponseMapping{VerdictPath: "verdict", ScorePath: "score"},
		},
	}, tlsSrv.Client(), "")

	ind := Indicator{Kind: KindDomain, Value: "malicious.example.com"}
	got, err := p.Lookup(context.Background(), []Indicator{ind})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	lbl := got[ind]
	if lbl == nil || lbl.Name != "malicious" || lbl.MaliciousScore != 0 {
		t.Fatalf("unexpected label: %#v", lbl)
	}
	if !lbl.ScoreMissing {
		t.Errorf("ScoreMissing = false, want true (score field was JSON null)")
	}
}

func TestGenericSingle_UnconfiguredKindResolvesToEmptyLabel(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("provider must not call out for a kind it has no endpoint for")
	}))
	defer tlsSrv.Close()

	p := newTestGenericProvider(GenericProviderConfig{
		BaseURL: tlsSrv.URL,
		Mode:    GenericModeSingle,
		Domain:  &GenericEndpoint{PathTemplate: "/lookup/{value}"},
		// IP intentionally nil: this provider doesn't answer IPv4.
	}, tlsSrv.Client(), "")

	ind := Indicator{Kind: KindIPv4, Value: "192.0.2.4"}
	got, err := p.Lookup(context.Background(), []Indicator{ind})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	lbl, ok := got[ind]
	if !ok {
		t.Fatal("expected the unconfigured-kind indicator to resolve to an empty Label, not be absent")
	}
	if lbl.Name != "" || lbl.MaliciousScore != 0 {
		t.Errorf("expected an empty Label, got %#v", lbl)
	}
}

func TestGenericSingle_AuthErrorNotRetried(t *testing.T) {
	var calls int
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer tlsSrv.Close()

	p := newTestGenericProvider(GenericProviderConfig{
		BaseURL: tlsSrv.URL,
		Mode:    GenericModeSingle,
		Domain:  &GenericEndpoint{PathTemplate: "/lookup/{value}"},
	}, tlsSrv.Client(), "")
	WithGenericRetry(0, 3)(p)

	_, err := p.Lookup(context.Background(), []Indicator{{Kind: KindDomain, Value: "example.com"}})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("expected ErrAuth, got %v", err)
	}
	if calls != 1 {
		t.Errorf("auth error must not be retried, got %d calls", calls)
	}
}

// --- Batch-mode Lookup ---

func TestGenericBatch_HappyPath(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string][]string
		json.NewDecoder(r.Body).Decode(&body)
		type entry struct {
			Indicator string  `json:"indicator"`
			Verdict   string  `json:"verdict"`
			Score     float64 `json:"score"`
		}
		var entries []entry
		for _, d := range body["domains"] {
			v, s := "clean", 0.0
			if d == "evil.example.com" {
				v, s = "malicious", 0.95
			}
			entries = append(entries, entry{Indicator: d, Verdict: v, Score: s})
		}
		json.NewEncoder(w).Encode(map[string]any{"results": entries})
	}))
	defer tlsSrv.Close()

	p := newTestGenericProvider(GenericProviderConfig{
		BaseURL: tlsSrv.URL,
		Mode:    GenericModeBatch,
		Domain: &GenericEndpoint{
			Path:      "/v1/batch",
			BodyField: "domains",
			Mapping: GenericResponseMapping{
				ArrayPath:          "results",
				IndicatorValuePath: "indicator",
				VerdictPath:        "verdict",
				ScorePath:          "score",
			},
		},
	}, tlsSrv.Client(), "")

	good := Indicator{Kind: KindDomain, Value: "clean.example.net"}
	bad := Indicator{Kind: KindDomain, Value: "evil.example.com"}
	got, err := p.Lookup(context.Background(), []Indicator{good, bad})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if lbl := got[bad]; lbl == nil || lbl.Name != "malicious" || lbl.MaliciousScore != 0.95 {
		t.Errorf("evil.example.com: %#v", lbl)
	}
	if lbl := got[good]; lbl == nil || lbl.Name != "clean" {
		t.Errorf("clean.example.net: %#v", lbl)
	}
}

// TestGenericBatch_NullScoreMarksScoreMissing is the batch-mode sibling of
// TestGenericSingle_NullScoreMarksScoreMissing: one entry in the array has
// an explicit JSON null score and must resolve to ScoreMissing: true while
// its sibling with a real 0.0 score does not.
func TestGenericBatch_NullScoreMarksScoreMissing(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"results":[
			{"indicator":"flagged-unscored.example.com","verdict":"malicious","score":null},
			{"indicator":"clean-scored.example.net","verdict":"clean","score":0.0}
		]}`)
	}))
	defer tlsSrv.Close()

	p := newTestGenericProvider(GenericProviderConfig{
		BaseURL: tlsSrv.URL,
		Mode:    GenericModeBatch,
		Domain: &GenericEndpoint{
			Path:      "/v1/batch",
			BodyField: "domains",
			Mapping: GenericResponseMapping{
				ArrayPath:          "results",
				IndicatorValuePath: "indicator",
				VerdictPath:        "verdict",
				ScorePath:          "score",
			},
		},
	}, tlsSrv.Client(), "")

	unscored := Indicator{Kind: KindDomain, Value: "flagged-unscored.example.com"}
	scored := Indicator{Kind: KindDomain, Value: "clean-scored.example.net"}
	got, err := p.Lookup(context.Background(), []Indicator{unscored, scored})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if lbl := got[unscored]; lbl == nil || !lbl.ScoreMissing {
		t.Errorf("flagged-unscored.example.com: %#v, want ScoreMissing=true", lbl)
	}
	if lbl := got[scored]; lbl == nil || lbl.ScoreMissing {
		t.Errorf("clean-scored.example.net: %#v, want ScoreMissing=false", lbl)
	}
}

// --- dotGet helpers ---

func TestDotGet_NestedPaths(t *testing.T) {
	tree := map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": "hello",
				"n": 3.5,
			},
		},
	}
	if s := dotGetString(tree, "a.b.c"); s != "hello" {
		t.Errorf("dotGetString = %q, want hello", s)
	}
	if f := dotGetFloat(tree, "a.b.n"); f != 3.5 {
		t.Errorf("dotGetFloat = %v, want 3.5", f)
	}
	if s := dotGetString(tree, "a.b.missing"); s != "" {
		t.Errorf("expected empty string for missing path, got %q", s)
	}
	if f := dotGetFloat(tree, "a.b.c"); f != 0 {
		t.Errorf("expected 0 for a non-numeric field, got %v", f)
	}
}

func TestDotGetFloatOK_DistinguishesMissingFromZero(t *testing.T) {
	tree := map[string]any{
		"present_zero": 0.0,
		"present_num":  3.5,
		"explicit_nil": nil,
		"non_numeric":  "not a number",
	}
	cases := []struct {
		path      string
		wantValue float64
		wantOK    bool
	}{
		{"present_zero", 0, true},
		{"present_num", 3.5, true},
		{"explicit_nil", 0, false},
		{"missing_entirely", 0, false},
		{"non_numeric", 0, false},
	}
	for _, tc := range cases {
		f, ok := dotGetFloatOK(tree, tc.path)
		if f != tc.wantValue || ok != tc.wantOK {
			t.Errorf("dotGetFloatOK(%q) = (%v, %v), want (%v, %v)", tc.path, f, ok, tc.wantValue, tc.wantOK)
		}
	}
}
