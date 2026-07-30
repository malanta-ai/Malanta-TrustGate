package reputation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestMalanta_BatchDomains_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/domains/reputation" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "k" {
			t.Errorf("missing api key header: %q", got)
		}
		var body map[string][]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		domains := body["domains"]
		resp := malantaBatchResponse{}
		for _, d := range domains {
			verdict := "UNKNOWN"
			var score *float64
			if d == "example.org" {
				verdict = "MALICIOUS"
				s := 0.9885
				score = &s
			}
			e := malantaEntry{}
			e.Indicator.Type = "domain-name"
			e.Indicator.Value = d
			e.Reputation.Verdict = verdict
			e.Reputation.MaliciousScore = score
			resp.Data = append(resp.Data, e)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	got, err := p.Lookup(context.Background(), []Indicator{
		{Kind: KindDomain, Value: "example.org"},
		{Kind: KindDomain, Value: "example.com"},
	})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if lbl := got[Indicator{Kind: KindDomain, Value: "example.org"}]; lbl == nil || lbl.Name != "MALICIOUS" || lbl.MaliciousScore != 0.9885 {
		t.Errorf("example.org: %#v", lbl)
	}
	if lbl := got[Indicator{Kind: KindDomain, Value: "example.com"}]; lbl == nil || lbl.Name != "UNKNOWN" || lbl.MaliciousScore != 0 {
		t.Errorf("example.com: %#v", lbl)
	}
	if lbl := got[Indicator{Kind: KindDomain, Value: "example.org"}]; lbl.ScoreMissing {
		t.Errorf("example.org: ScoreMissing = true, want false (a real score was present)")
	}
	if lbl := got[Indicator{Kind: KindDomain, Value: "example.com"}]; !lbl.ScoreMissing {
		t.Errorf("example.com: ScoreMissing = false, want true (malicious_score was nil)")
	}
}

// TestMalanta_ReservedTLDSkippedNotQueried verifies the RFC 2606/6761
// reserved-TLD pre-filter: a .example/.test/.invalid host is non-registrable
// (no live API can evaluate it — Malanta answers HTTP 422), so the provider
// resolves it to a clean no-data verdict WITHOUT querying, while a real-TLD
// batch-mate is still sent upstream and gets its verdict. Guards against a
// reserved-TLD host in a command failing the whole lookup closed.
func TestMalanta_ReservedTLDSkippedNotQueried(t *testing.T) {
	var queried []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string][]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		queried = append(queried, body["domains"]...)
		resp := malantaBatchResponse{}
		for _, d := range body["domains"] {
			e := malantaEntry{}
			e.Indicator.Value = d
			e.Reputation.Verdict = "MALICIOUS"
			s := 0.99
			e.Reputation.MaliciousScore = &s
			resp.Data = append(resp.Data, e)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	got, err := p.Lookup(context.Background(), []Indicator{
		{Kind: KindDomain, Value: "flagged.example"},
		{Kind: KindDomain, Value: "example.org"},
	})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	for _, d := range queried {
		if d == "flagged.example" {
			t.Errorf("reserved-TLD host was sent upstream (should be skipped): queried=%v", queried)
		}
	}
	if lbl := got[Indicator{Kind: KindDomain, Value: "flagged.example"}]; lbl == nil || lbl.Name != "UNKNOWN" || lbl.MaliciousScore != 0 {
		t.Errorf("flagged.example: got %#v, want clean no-data UNKNOWN/0", lbl)
	}
	if lbl := got[Indicator{Kind: KindDomain, Value: "example.org"}]; lbl == nil || lbl.Name != "MALICIOUS" {
		t.Errorf("example.org: got %#v, want MALICIOUS (real-TLD batch-mate must still be queried)", lbl)
	}
}

// TestMalanta_FlaggedVerdictWithNullScoreMarksScoreMissing regression-guards
// the live 2026-07-07 finding against app.malanta.ai: a domain can come
// back with a block-listed verdict ("MALICIOUS") and malicious_score:
// null. Label.Probability still defaults to 0 for the cascade's existing
// deny math, but ScoreMissing must be true so internal/verdict can log its
// distinct UNSCORED_VERDICT warning instead of silently treating this
// exactly like a genuinely-scored-clean verdict.
func TestMalanta_FlaggedVerdictWithNullScoreMarksScoreMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := malantaEntry{}
		e.Indicator.Type = "domain-name"
		e.Indicator.Value = "example.org"
		e.Reputation.Verdict = "MALICIOUS"
		e.Reputation.MaliciousScore = nil
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(malantaBatchResponse{Data: []malantaEntry{e}})
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	got, err := p.Lookup(context.Background(), []Indicator{{Kind: KindDomain, Value: "example.org"}})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	lbl := got[Indicator{Kind: KindDomain, Value: "example.org"}]
	if lbl == nil {
		t.Fatalf("example.org: no label returned")
	}
	if lbl.Name != "MALICIOUS" {
		t.Errorf("Name = %q, want MALICIOUS", lbl.Name)
	}
	if lbl.MaliciousScore != 0 {
		t.Errorf("Probability = %v, want 0 (unchanged fallback)", lbl.MaliciousScore)
	}
	if !lbl.ScoreMissing {
		t.Errorf("ScoreMissing = false, want true")
	}
}

func TestMalanta_SubdomainReducedToRegisteredDomain(t *testing.T) {
	var gotDomains []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string][]string
		json.NewDecoder(r.Body).Decode(&body)
		gotDomains = body["domains"]
		resp := malantaBatchResponse{}
		for _, d := range gotDomains {
			e := malantaEntry{}
			e.Indicator.Value = d
			e.Reputation.Verdict = "MALICIOUS"
			score := 0.9
			e.Reputation.MaliciousScore = &score
			resp.Data = append(resp.Data, e)
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	// eTLD+1 of "a.b.evil.example.com" against the public suffix list is
	// "example.com" (the label immediately before the "com" public
	// suffix, plus the suffix) — NOT "evil.example.com". This is exactly
	// the registered-domain reduction the Malanta API requires.
	sub := Indicator{Kind: KindDomain, Value: "a.b.evil.example.com"}
	got, err := p.Lookup(context.Background(), []Indicator{sub})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(gotDomains) != 1 || gotDomains[0] != "example.com" {
		t.Fatalf("expected the API to be queried with the registered domain only, got %v", gotDomains)
	}
	lbl, ok := got[sub]
	if !ok || lbl == nil || lbl.Name != "MALICIOUS" {
		t.Errorf("expected the registered-domain verdict fanned back onto the subdomain, got %#v (present=%v)", lbl, ok)
	}
}

func TestMalanta_MultipleSubdomainsCollapseToOneAPICall(t *testing.T) {
	var calls int32
	var lastDomains []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		var body map[string][]string
		json.NewDecoder(r.Body).Decode(&body)
		lastDomains = body["domains"]
		resp := malantaBatchResponse{}
		for _, d := range lastDomains {
			e := malantaEntry{}
			e.Indicator.Value = d
			e.Reputation.Verdict = "UNKNOWN"
			resp.Data = append(resp.Data, e)
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	_, err := p.Lookup(context.Background(), []Indicator{
		{Kind: KindDomain, Value: "a.example.com"},
		{Kind: KindDomain, Value: "b.example.com"},
		{Kind: KindDomain, Value: "example.com"},
	})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("expected exactly 1 API call (deduped registered domain), got %d", calls)
	}
	if len(lastDomains) != 1 || lastDomains[0] != "example.com" {
		t.Errorf("expected a single deduped registered domain, got %v", lastDomains)
	}
}

func TestMalanta_IPv4UsesIPsEndpointUnreduced(t *testing.T) {
	var gotPath string
	var gotIPs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		var body map[string][]string
		json.NewDecoder(r.Body).Decode(&body)
		gotIPs = body["ips"]
		resp := malantaBatchResponse{}
		for _, ip := range gotIPs {
			e := malantaEntry{}
			e.Indicator.Value = ip
			e.Reputation.Verdict = "MALICIOUS"
			score := 0.8
			e.Reputation.MaliciousScore = &score
			resp.Data = append(resp.Data, e)
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	ind := Indicator{Kind: KindIPv4, Value: "192.0.2.4"}
	got, err := p.Lookup(context.Background(), []Indicator{ind})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if gotPath != "/v1/ips/reputation" {
		t.Errorf("expected /v1/ips/reputation, got %s", gotPath)
	}
	if len(gotIPs) != 1 || gotIPs[0] != "192.0.2.4" {
		t.Errorf("expected the IP sent as-is, got %v", gotIPs)
	}
	if lbl := got[ind]; lbl == nil || lbl.Name != "MALICIOUS" {
		t.Errorf("unexpected label: %#v", lbl)
	}
}

func TestMalanta_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "bad-key")
	_, err := p.Lookup(context.Background(), []Indicator{{Kind: KindDomain, Value: "example.com"}})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("expected ErrAuth, got %v", err)
	}
}

func TestMalanta_NonAuthHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	_, err := p.Lookup(context.Background(), []Indicator{{Kind: KindDomain, Value: "example.com"}})
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("expected ErrProvider, got %v", err)
	}
	if errors.Is(err, ErrAuth) {
		t.Errorf("500 must not be misclassified as an auth error")
	}
}

func TestMalanta_CrossHostRedirectBlocked(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the redirect target must never be contacted (would leak the API key)")
	}))
	defer evil.Close()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/v1/domains/reputation", http.StatusFound)
	}))
	defer primary.Close()

	p := NewMalanta(primary.URL, "k")
	_, err := p.Lookup(context.Background(), []Indicator{{Kind: KindDomain, Value: "example.com"}})
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("expected a provider error from the blocked redirect, got %v", err)
	}
}

func TestMalanta_TransientErrorRetriedThenSucceeds(t *testing.T) {
	var attempt int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempt, 1) == 1 {
			// Simulate a transport-level failure on attempt 1 by hijacking
			// and closing the connection with no response — this produces
			// a genuine client-side transport error (errTransient) without
			// blocking the handler goroutine on context cancellation,
			// which can otherwise race with httptest.Server.Close() and
			// hang the test.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("ResponseWriter does not support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatalf("hijack: %v", err)
			}
			conn.Close()
			return
		}
		resp := malantaBatchResponse{Data: []malantaEntry{{}}}
		resp.Data[0].Indicator.Value = "example.com"
		resp.Data[0].Reputation.Verdict = "UNKNOWN"
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k", WithMalantaRetry(2*time.Second, 2))
	got, err := p.Lookup(context.Background(), []Indicator{{Kind: KindDomain, Value: "example.com"}})
	if err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 resolved indicator, got %d", len(got))
	}
	if atomic.LoadInt32(&attempt) != 2 {
		t.Errorf("expected exactly 2 attempts, got %d", attempt)
	}
}

func TestMalanta_NameAndAllowedHosts(t *testing.T) {
	p := NewMalanta("https://app.malanta.ai/data", "k")
	if p.Name() != "malanta" {
		t.Errorf("Name() = %q, want malanta", p.Name())
	}
	hosts := p.AllowedHosts()
	if len(hosts) != 1 || hosts[0] != "app.malanta.ai" {
		t.Errorf("AllowedHosts() = %v, want [app.malanta.ai]", hosts)
	}
}
