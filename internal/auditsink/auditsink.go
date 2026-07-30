// Package auditsink implements the opt-in, outbound-only remote audit
// sink (Option 4 in the project's admin-operability plan): best-effort
// delivery of decision events to an admin-controlled HTTPS collector.
//
// Fire-and-forget in spirit, NOT in implementation. Every hook binary is
// a fresh, short-lived subprocess that exits immediately after emitting
// its verdict — there is no long-running daemon for a background
// goroutine to outlive into. A goroutine started with `go func(){...}()`
// right before main() returns would almost always be killed mid-flight
// when the process exits. Rather than pretend otherwise, Send is
// SYNCHRONOUS with a short, hard-coded deadline (sendTimeout): it runs
// AFTER the verdict has already been written to stdout, so it can only
// ever add up to sendTimeout of wall-clock time to the process's total
// lifetime, never to the time before Cursor sees an answer. This is a
// deliberate, documented simplification of "async, never delays the
// verdict" — a genuinely async sink would require the daemon
// architecture AGENTS.md explicitly defers (see its "Daemon-mediated key
// access" section) until a customer requires it.
package auditsink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/verdict"
)

// sendTimeout bounds how long Send will block. Short enough that even a
// completely unreachable sink endpoint costs a bounded, small addition to
// the hook's total runtime; long enough to complete a same-region HTTPS
// POST under normal conditions.
const sendTimeout = 800 * time.Millisecond

// maxBodyBytes caps the response body we bother reading before
// discarding it — we don't care about the collector's response beyond
// "did it accept the event," so there's no reason to buffer more.
const maxBodyBytes = 4 << 10

// Event is the wire shape posted to the sink. Deliberately narrow: no
// raw command/file/prompt content ever appears here, matching the same
// redaction contract as the local decision log and audit table (see
// internal/audit's package doc).
type Event struct {
	DecisionID string    `json:"decision_id"`
	Timestamp  time.Time `json:"timestamp"`
	HookEvent  string    `json:"hook_event"`
	Host       string    `json:"host,omitempty"`
	User       string    `json:"user,omitempty"`
	Provider   string    `json:"provider,omitempty"`
	Indicator  string    `json:"indicator,omitempty"`
	Kind       string    `json:"kind,omitempty"`
	Verdict    string    `json:"verdict,omitempty"`
	Allow      bool      `json:"allow"`
	Mode       string    `json:"mode,omitempty"`
	Reason     string    `json:"reason,omitempty"`
}

// ShouldSend reports whether d should be sent at all, given cfg's
// verbosity setting. Exported so callers (and tests) can skip building an
// Event entirely when the answer is no.
func ShouldSend(cfg config.Config, d verdict.Decision) bool {
	if cfg.AuditSinkURL == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(cfg.AuditSinkVerbosity)) {
	case "off":
		return false
	case "all":
		return true
	case "denies", "":
		return !d.Allow
	default:
		// Unrecognized verbosity: fail toward LESS data leaving the box,
		// not more — same "when in doubt, be conservative about egress"
		// posture as the rest of this package.
		return !d.Allow
	}
}

// Send posts one event derived from d to cfg.AuditSinkURL. No-op if
// ShouldSend(cfg, d) is false. Every error (network, non-2xx status, ...)
// is swallowed after a single best-effort stderr note — a flaky or
// misconfigured sink must never affect a verdict, and must not spam
// stderr with a full stack/retry story on every single hook invocation.
func Send(cfg config.Config, d verdict.Decision, hosts []string) {
	if !ShouldSend(cfg, d) {
		return
	}
	ev := Event{
		DecisionID: d.DecisionID,
		Timestamp:  time.Now().UTC(),
		HookEvent:  d.HookName,
		Host:       hostname(),
		User:       username(),
		Provider:   d.Provider,
		Indicator:  d.Indicator,
		Kind:       d.Kind,
		Verdict:    d.Label,
		Allow:      d.Allow,
		Mode:       d.Mode,
		Reason:     d.Reason,
	}
	body, err := json.Marshal(ev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustgate: audit sink: marshal event: %v\n", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.AuditSinkURL, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustgate: audit sink: build request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := sinkClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustgate: audit sink: send failed (decision still stands): %v\n", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "trustgate: audit sink: collector returned HTTP %d\n", resp.StatusCode)
	}
}

// sinkClient blocks cross-host redirects, the same SSRF-adjacent
// guardrail internal/reputation applies to provider requests — a
// compromised or misconfigured collector endpoint must not be able to
// redirect decision data somewhere the operator never allowlisted.
var sinkClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return nil
		}
		if req.URL.Hostname() != via[0].URL.Hostname() {
			return fmt.Errorf("audit sink: refusing cross-host redirect to %s", req.URL.Hostname())
		}
		return nil
	},
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

func username() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}
