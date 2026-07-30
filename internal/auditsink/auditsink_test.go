package auditsink

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/verdict"
)

func TestShouldSend(t *testing.T) {
	cases := []struct {
		name      string
		sinkURL   string
		verbosity string
		allow     bool
		wantSend  bool
	}{
		{"disabled (no url)", "", "all", false, false},
		{"denies-only, allow decision", "https://x", "denies", true, false},
		{"denies-only, deny decision", "https://x", "denies", false, true},
		{"all, allow decision", "https://x", "all", true, true},
		{"all, deny decision", "https://x", "all", false, true},
		{"off", "https://x", "off", false, false},
		{"default empty verbosity behaves like denies", "https://x", "", true, false},
		{"unrecognized verbosity defaults conservative (denies)", "https://x", "bogus", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{AuditSinkURL: tc.sinkURL, AuditSinkVerbosity: tc.verbosity}
			d := verdict.Decision{Allow: tc.allow}
			if got := ShouldSend(cfg, d); got != tc.wantSend {
				t.Errorf("ShouldSend() = %v, want %v", got, tc.wantSend)
			}
		})
	}
}

func TestSend_PostsEventWhenEnabled(t *testing.T) {
	var mu sync.Mutex
	var received Event
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotAuth = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.Config{AuditSinkURL: srv.URL, AuditSinkVerbosity: "all"}
	d := verdict.Decision{
		DecisionID: "abc123",
		Allow:      false,
		Reason:     "malanta flagged malicious.example as MALICIOUS",
		Provider:   "malanta",
		Indicator:  "malicious.example",
		Kind:       "domain",
		Label:      "MALICIOUS",
		Mode:       "enforce",
		HookName:   "beforeShellExecution",
	}
	Send(cfg, d, []string{"malicious.example"})

	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "application/json" {
		t.Errorf("expected Content-Type: application/json, got %q", gotAuth)
	}
	if received.DecisionID != "abc123" || received.Indicator != "malicious.example" || received.Allow {
		t.Errorf("unexpected event received: %+v", received)
	}
}

func TestSend_NoOpWhenShouldSendIsFalse(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	cfg := config.Config{AuditSinkURL: srv.URL, AuditSinkVerbosity: "denies"}
	d := verdict.Decision{Allow: true} // allow + denies-only verbosity => should NOT send
	Send(cfg, d, nil)

	if called {
		t.Error("expected Send to skip the request entirely when ShouldSend is false")
	}
}

func TestSend_NeverPanicsOnUnreachableSink(t *testing.T) {
	cfg := config.Config{AuditSinkURL: "https://127.0.0.1:1", AuditSinkVerbosity: "all"}
	d := verdict.Decision{Allow: false}
	// Must return promptly (bounded by sendTimeout) and must not panic;
	// there's no return value to assert on beyond "did not hang or crash".
	Send(cfg, d, nil)
}
