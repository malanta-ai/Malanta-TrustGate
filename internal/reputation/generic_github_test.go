package reputation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestGeneric_GitHubKindsResolveWithoutQuerying is the guard for the
// generic-adapter arm of GitHub reputation. Repository reputation is a
// Malanta-only capability, so the config-driven adapter has no endpoint for
// it — but "no endpoint" must resolve to an explicit no-data Label, not fall
// through to the domain endpoint.
//
// Two failure modes this locks out, both silent:
//   - Sending "owner/repo" to the configured DOMAIN endpoint, which answers
//     about a value that is not a hostname.
//   - Omitting the indicator from the result map, which the cascade reads as
//     a protocol anomaly and escalates to a retry and then a fail-closed
//     deny of a perfectly good action.
func TestGeneric_GitHubKindsResolveWithoutQuerying(t *testing.T) {
	var requests int32
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		t.Errorf("generic provider must not issue any request for a GitHub indicator (path %q)", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{"verdict": "malicious", "score": 1})
	}))
	defer tlsSrv.Close()

	cfg := validConfig(strings.TrimPrefix(tlsSrv.URL, "https://"))
	cfg.BaseURL = tlsSrv.URL
	p := newTestGenericProvider(cfg, tlsSrv.Client(), "secret")

	repo := Indicator{Kind: KindGitHubRepo, Value: "acme/backdoor"}
	owner := Indicator{Kind: KindGitHubOwner, Value: "acme"}
	got, err := p.Lookup(context.Background(), []Indicator{repo, owner})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if n := atomic.LoadInt32(&requests); n != 0 {
		t.Errorf("expected zero HTTP requests, got %d", n)
	}
	for _, ind := range []Indicator{repo, owner} {
		lbl, ok := got[ind]
		if !ok {
			t.Errorf("%v: absent from the result map; the cascade would fail closed on it", ind)
			continue
		}
		if lbl == nil || lbl.Name != "" || lbl.MaliciousScore != 0 {
			t.Errorf("%v: expected an empty no-data Label, got %#v", ind, lbl)
		}
	}
}

// TestGeneric_DomainStillQueriedAlongsideGitHubKinds confirms the guard is
// scoped to the new kinds: a domain in the SAME event still goes to the
// configured endpoint and gets its real verdict.
func TestGeneric_DomainStillQueriedAlongsideGitHubKinds(t *testing.T) {
	var paths []string
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{"verdict": "malicious", "score": 0.9})
	}))
	defer tlsSrv.Close()

	cfg := validConfig(strings.TrimPrefix(tlsSrv.URL, "https://"))
	cfg.BaseURL = tlsSrv.URL
	p := newTestGenericProvider(cfg, tlsSrv.Client(), "secret")

	domain := Indicator{Kind: KindDomain, Value: "malicious.example.com"}
	repo := Indicator{Kind: KindGitHubRepo, Value: "acme/backdoor"}
	got, err := p.Lookup(context.Background(), []Indicator{domain, repo})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if lbl := got[domain]; lbl == nil || lbl.Name != "malicious" {
		t.Errorf("domain verdict: %#v", lbl)
	}
	if len(paths) != 1 || !strings.Contains(paths[0], "malicious.example.com") {
		t.Errorf("expected exactly one request, for the domain; got %v", paths)
	}
}
