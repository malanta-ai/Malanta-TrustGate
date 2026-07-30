package reputation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// repoEntry builds one code-repos response entry.
func repoEntry(value, verdict string, score *float64) malantaEntry {
	e := malantaEntry{}
	e.Indicator.Value = value
	e.Indicator.Type = "code-repo"
	e.Reputation.Verdict = verdict
	e.Reputation.MaliciousScore = score
	return e
}

// TestMalanta_CodeRepos_MixedScopeBatch is the wire-contract test for
// GitHub reputation: repository AND owner indicators go to
// /v1/code-repos/reputation in ONE request under the "repos" body field,
// with their values sent verbatim — no eTLD+1 reduction, no
// re-normalization — and each verdict lands back on the right Indicator
// (right Kind included).
func TestMalanta_CodeRepos_MixedScopeBatch(t *testing.T) {
	var requests int32
	var gotPaths []string
	var gotValues []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		gotPaths = append(gotPaths, r.URL.Path)
		var body map[string][]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		values := body["repos"]
		if values == nil {
			t.Errorf("expected the request body field %q, got %v", "repos", body)
		}
		gotValues = append(gotValues, values...)
		resp := malantaBatchResponse{}
		for _, v := range values {
			switch v {
			case "acme/backdoor":
				s := 1.0
				resp.Data = append(resp.Data, repoEntry(v, "MALICIOUS", &s))
			case "evilorg":
				s := 0.9
				resp.Data = append(resp.Data, repoEntry(v, "MALICIOUS", &s))
			default:
				resp.Data = append(resp.Data, repoEntry(v, "UNKNOWN", nil))
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	repo := Indicator{Kind: KindGitHubRepo, Value: "acme/backdoor"}
	clean := Indicator{Kind: KindGitHubRepo, Value: "acme/library"}
	owner := Indicator{Kind: KindGitHubOwner, Value: "evilorg"}
	got, err := p.Lookup(context.Background(), []Indicator{repo, clean, owner})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if n := atomic.LoadInt32(&requests); n != 1 {
		t.Errorf("expected both scopes in ONE request, got %d requests", n)
	}
	for _, p := range gotPaths {
		if p != "/v1/code-repos/reputation" {
			t.Errorf("unexpected path %q", p)
		}
	}
	assertContains(t, gotValues, "acme/backdoor", "acme/library", "evilorg")

	if lbl := got[repo]; lbl == nil || lbl.Name != "MALICIOUS" || lbl.MaliciousScore != 1.0 {
		t.Errorf("repo verdict: %#v", lbl)
	}
	if lbl := got[owner]; lbl == nil || lbl.Name != "MALICIOUS" || lbl.MaliciousScore != 0.9 {
		t.Errorf("owner verdict: %#v", lbl)
	}
	if lbl := got[clean]; lbl == nil || lbl.Name != "UNKNOWN" {
		t.Errorf("clean repo verdict: %#v", lbl)
	}
	// An UNKNOWN with a null score must be flagged ScoreMissing, exactly as
	// on the domain path — the cascade uses that to tell "provider scored
	// this harmless" apart from "provider returned no score".
	if lbl := got[clean]; lbl != nil && !lbl.ScoreMissing {
		t.Errorf("clean repo: ScoreMissing = false, want true (malicious_score was null)")
	}
	// A domain indicator must never appear on this endpoint's key space.
	if _, leaked := got[Indicator{Kind: KindDomain, Value: "acme/backdoor"}]; leaked {
		t.Error("repo verdict leaked onto a KindDomain key")
	}
}

// TestMalanta_CodeRepos_NoRegistrableReduction is the regression guard for
// the wrong-endpoint failure mode: routing a repo through the domain arm
// would reduce "acme/backdoor" with EffectiveTLDPlusOne (or drop it
// outright) and query /v1/domains/reputation. The value must arrive intact.
func TestMalanta_CodeRepos_NoRegistrableReduction(t *testing.T) {
	var domainRequests int32
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/domains/reputation" {
			atomic.AddInt32(&domainRequests, 1)
		}
		var body map[string][]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		sent = append(sent, body["repos"]...)
		resp := malantaBatchResponse{}
		for _, v := range body["repos"] {
			resp.Data = append(resp.Data, repoEntry(v, "UNKNOWN", nil))
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	if _, err := p.Lookup(context.Background(), []Indicator{
		{Kind: KindGitHubRepo, Value: "acme/backdoor.io"},
	}); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if n := atomic.LoadInt32(&domainRequests); n != 0 {
		t.Errorf("a GitHub repo must never hit the domain endpoint (%d requests)", n)
	}
	assertContains(t, sent, "acme/backdoor.io")
}

// TestMalanta_CodeRepos_ReservedTLDGuardIsDomainOnly is the prerequisite-fix
// regression guard. IsReservedTLD reads the last dotted label of a value, so
// before the Kind guard a real repository named "harness.test" was resolved
// to a synthetic UNKNOWN and never queried.
func TestMalanta_CodeRepos_ReservedTLDGuardIsDomainOnly(t *testing.T) {
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string][]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		sent = append(sent, body["repos"]...)
		resp := malantaBatchResponse{}
		for _, v := range body["repos"] {
			s := 1.0
			resp.Data = append(resp.Data, repoEntry(v, "MALICIOUS", &s))
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	ind := Indicator{Kind: KindGitHubRepo, Value: "acme/harness.test"}
	got, err := p.Lookup(context.Background(), []Indicator{ind})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	assertContains(t, sent, "acme/harness.test")
	if lbl := got[ind]; lbl == nil || lbl.Name != "MALICIOUS" {
		t.Errorf("a repo whose name ends in a reserved TLD must still be queried, got %#v", lbl)
	}
}

// TestMalanta_CodeRepos_LowercasedEcho guards the case-insensitive reverse
// map. The API matches case-insensitively and echoes the LOWERCASED value,
// so keying the response on the raw echo would leave a mixed-case
// submission unmatched — and an unmatched key is an absent entry, which the
// cascade escalates to a fail-closed deny.
func TestMalanta_CodeRepos_LowercasedEcho(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string][]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		resp := malantaBatchResponse{}
		for _, v := range body["repos"] {
			s := 1.0
			// Echo lowercased, as the live endpoint does.
			resp.Data = append(resp.Data, repoEntry(lower(v), "MALICIOUS", &s))
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	ind := Indicator{Kind: KindGitHubRepo, Value: "TORVALDS/Linux"}
	got, err := p.Lookup(context.Background(), []Indicator{ind})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if lbl := got[ind]; lbl == nil || lbl.Name != "MALICIOUS" {
		t.Errorf("a lowercased echo must still resolve the submitted indicator, got %#v", lbl)
	}
}

// TestMalanta_CodeRepos_FewerEntriesThanSubmitted covers the server-side
// dedup case: two submissions that canonicalize to the same value come back
// as ONE entry. Both indicators must resolve from it, and nothing may be
// written under a zero-value Indicator key.
func TestMalanta_CodeRepos_FewerEntriesThanSubmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := malantaBatchResponse{}
		s := 1.0
		resp.Data = append(resp.Data, repoEntry("acme/backdoor", "MALICIOUS", &s))
		// An echo for a value nobody submitted must be dropped, not
		// written under the zero Indicator.
		resp.Data = append(resp.Data, repoEntry("someone/else", "MALICIOUS", &s))
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	a := Indicator{Kind: KindGitHubRepo, Value: "acme/backdoor"}
	b := Indicator{Kind: KindGitHubRepo, Value: "acme/other"}
	got, err := p.Lookup(context.Background(), []Indicator{a, b})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if lbl := got[a]; lbl == nil || lbl.Name != "MALICIOUS" {
		t.Errorf("submitted-and-answered indicator: %#v", lbl)
	}
	if _, ok := got[b]; ok {
		t.Error("an indicator with no matching entry must stay ABSENT so the cascade can retry it")
	}
	if _, ok := got[Indicator{}]; ok {
		t.Error("an unsolicited echo must be dropped, not written under a zero-value Indicator")
	}
}

// TestMalanta_CodeRepos_EnrichedPayloadDecodes confirms the response decoder
// tolerates the endpoint's richer fields (labels, context, clusters,
// timestamps, score bands). The cascade consumes only verdict +
// malicious_score for now; unknown fields must not fail the decode.
func TestMalanta_CodeRepos_EnrichedPayloadDecodes(t *testing.T) {
	const enriched = `{
	  "data": [
	    {
	      "indicator": {"type": "code-repo-owner", "value": "evilorg", "indicator_id": null},
	      "reputation": {
	        "verdict": "MALICIOUS",
	        "labels": ["IOPA", "IOC"],
	        "malicious_score": 1.0,
	        "malicious_score_band": "HIGH"
	      },
	      "apt_names": [],
	      "ioc_sources": ["urlhaus"],
	      "context": ["2 flagged repositories under this owner"],
	      "clusters": [{"cluster_id": "e66dcc98", "member_count": 2}],
	      "timestamps": {"first_observed_at": "2026-07-25T14:27:50.657Z"}
	    }
	  ],
	  "meta": {"schema_version": "2.0.0", "elapsed_ms": 812},
	  "pagination": {"has_more": false, "next_cursor": null}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(enriched))
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	owner := Indicator{Kind: KindGitHubOwner, Value: "evilorg"}
	got, err := p.Lookup(context.Background(), []Indicator{owner})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	lbl := got[owner]
	if lbl == nil || lbl.Name != "MALICIOUS" || lbl.MaliciousScore != 1.0 || lbl.ScoreMissing {
		t.Errorf("enriched owner payload: %#v", lbl)
	}
}

// TestMalanta_CodeRepos_ErrorFailsTheLookup keeps the fail-closed contract:
// an error on the repo endpoint surfaces as a Lookup error (which the
// cascade turns into a deny under fail_closed), never as a silent allow.
func TestMalanta_CodeRepos_ErrorFailsTheLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	p := NewMalanta(srv.URL, "k")
	if _, err := p.Lookup(context.Background(), []Indicator{
		{Kind: KindGitHubRepo, Value: "acme/backdoor"},
	}); err == nil {
		t.Fatal("expected an error from a 500 on the code-repos endpoint")
	}
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func assertContains(t *testing.T, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q among the submitted values %v", w, got)
		}
	}
}
