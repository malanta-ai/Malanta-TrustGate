package verdict

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

// fakeLookup is a Lookuper test double. resp is keyed by indicator VALUE
// (not the full Indicator struct) for readability in tests; Lookup expands
// that into a proper map[reputation.Indicator]*reputation.Label using each
// requested indicator's own Kind, so callers don't need to specify Kind
// twice.
type fakeLookup struct {
	name string
	resp map[string]*reputation.Label
	err  error
}

func (f *fakeLookup) Lookup(_ context.Context, indicators []reputation.Indicator) (map[reputation.Indicator]*reputation.Label, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[reputation.Indicator]*reputation.Label, len(indicators))
	for _, ind := range indicators {
		if lbl, ok := f.resp[ind.Value]; ok {
			out[ind] = lbl
		}
	}
	return out, nil
}

func (f *fakeLookup) Name() string {
	if f.name == "" {
		return "malanta"
	}
	return f.name
}

func baseCfg(t *testing.T) config.Config {
	t.Helper()
	c := config.Defaults()
	dir := t.TempDir()
	c.LogPath = filepath.Join(dir, "decisions.log")
	// CacheDir must also be redirected into the test's tempdir: several
	// tests exercise features (the user-override file) that read/write
	// under CacheDir, and config.Defaults() otherwise points it at the
	// real developer's ~/.cache/trustgate.
	c.CacheDir = dir
	// Pin enforce here even though the shipped default is now ModeWarn:
	// the bulk of the verdict tests assert enforce-mode cascade behavior
	// (hard deny, override hint, provider-error fail-closed). Warn-mode
	// tests set c.Mode = config.ModeWarn explicitly, so pinning enforce
	// keeps every other test deterministic regardless of the default.
	c.Mode = config.ModeEnforce
	// Disable the warn-mode acknowledgment dwell gate by default: most
	// warn tests do an instantaneous in-process retry to exercise the
	// promote-on-retry flow, which the (nonzero) default dwell would
	// otherwise reject as "too soon". The dwell gate has its own
	// dedicated tests that set it explicitly.
	c.WarnAckMinSeconds = 0
	return c
}

func TestCompose_AllowEmptyDomains(t *testing.T) {
	d := Compose(context.Background(), baseCfg(t), "shell", nil, nil, nil, nil)
	if !d.Allow {
		t.Errorf("expected allow with no domains, got deny")
	}
}

func TestCompose_AllowLegit(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"example.com": {Name: "UNKNOWN", MaliciousScore: 0},
	}}
	d := Compose(context.Background(), cfg, "shell", []string{"example.com"}, nil, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow, got %#v", d)
	}
}

func TestCompose_DenyMalicious(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}
	d := Compose(context.Background(), cfg, "shell", []string{"malicious.example"}, nil, lk, nil)
	if d.Allow {
		t.Errorf("expected deny, got allow: %#v", d)
	}
	if d.Indicator != "malicious.example" || d.Label != "MALICIOUS" {
		t.Errorf("unexpected decision payload: %#v", d)
	}
}

// TestReasonText covers the deny-reason clause builder directly: a named
// verdict keeps the "as <label>" clause; an empty label (a score-only
// provider like VirusTotal, which has no single verdict-name field —
// see reputation.GenericResponseMapping's doc comment on VerdictPath)
// omits "as" entirely rather than leaving a dangling "as " + double
// space. Score formatting uses %g so a whole count reads as "10" (not
// "10.0000") and a probability reads as "0.9885" (not padded/truncated).
func TestReasonText(t *testing.T) {
	cases := []struct {
		name         string
		providerName string
		kind         reputation.Kind
		value        string
		label        string
		score        float64
		want         string
	}{
		{
			name:         "named verdict, probability score",
			providerName: "malanta",
			value:        "evil.example",
			label:        "MALICIOUS",
			score:        0.9885,
			want:         "malanta flagged evil.example as MALICIOUS (malicious score 0.9885)",
		},
		{
			name:         "github repo names the scope",
			providerName: "malanta",
			kind:         reputation.KindGitHubRepo,
			value:        "acme/backdoor",
			label:        "MALICIOUS",
			score:        1,
			want:         "malanta flagged GitHub repository acme/backdoor as MALICIOUS (malicious score 1)",
		},
		{
			name:         "github owner says the verdict is account-wide",
			providerName: "malanta",
			kind:         reputation.KindGitHubOwner,
			value:        "acme",
			label:        "MALICIOUS",
			score:        1,
			want: "malanta flagged GitHub account acme as MALICIOUS (malicious score 1)" +
				"; this verdict is for the account, not for one specific repository",
		},
		{
			name:         "empty label, whole-count score (VirusTotal-style)",
			providerName: "virustotal",
			value:        "evil.example",
			label:        "",
			score:        10,
			want:         "virustotal flagged evil.example (malicious score 10)",
		},
		{
			name:         "empty label, zero score",
			providerName: "virustotal",
			value:        "clean.example",
			label:        "",
			score:        0,
			want:         "virustotal flagged clean.example (malicious score 0)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reasonText(tc.providerName,
				reputation.Indicator{Kind: tc.kind, Value: tc.value}, tc.label, tc.score)
			if got != tc.want {
				t.Errorf("reasonText(%q, %q, %q, %v) = %q, want %q",
					tc.providerName, tc.value, tc.label, tc.score, got, tc.want)
			}
			if strings.Contains(got, "as  ") || strings.Contains(got, "as (") {
				t.Errorf("expected no dangling \"as\" for an empty label, got %q", got)
			}
		})
	}
}

// TestCompose_Reason_ScoreOnlyProviderEndToEnd is the Compose-level
// sibling of TestReasonText: a score-only fake provider (empty Name,
// matching VirusTotal's shape when verdict_path is unset) must still
// deny via the score backstop and produce a clean Reason with no
// dangling "as".
func TestCompose_Reason_ScoreOnlyProviderEndToEnd(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{name: "virustotal", resp: map[string]*reputation.Label{
		"evil.example": {Name: "", MaliciousScore: 10},
	}}
	d := Compose(context.Background(), cfg, "shell", []string{"evil.example"}, nil, lk, nil)
	if d.Allow {
		t.Fatalf("expected deny via the score backstop, got allow: %#v", d)
	}
	want := "virustotal flagged evil.example (malicious score 10)"
	if d.Reason != want {
		t.Errorf("Reason = %q, want %q", d.Reason, want)
	}
}

func TestCompose_DenySuspicious_CaseInsensitive(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malware.example": {Name: "suspicious", MaliciousScore: 1},
	}}
	d := Compose(context.Background(), cfg, "shell", []string{"malware.example"}, nil, lk, nil)
	if d.Allow {
		t.Errorf("expected deny on case-insensitive match, got allow")
	}
}

func TestCompose_AllowBelowThreshold(t *testing.T) {
	cfg := baseCfg(t)
	cfg.MinMaliciousScoreToBlock = 0.9
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"weak.example": {Name: "MALICIOUS", MaliciousScore: 0.5},
	}}
	d := Compose(context.Background(), cfg, "shell", []string{"weak.example"}, nil, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow (below threshold), got deny")
	}
	if len(d.Warnings) == 0 {
		t.Errorf("expected a warning for low-confidence label")
	}
}

// TestCompose_UnscoredBlockListedVerdictAllowsWithLoudWarning is a
// regression guard for the live 2026-07-07 finding: a provider can flag a
// block-listed verdict (e.g. Malanta's "MALICIOUS") while returning no
// confidence score at all (ScoreMissing: true, MaliciousScore defaulted to
// 0). Deny/allow math is unchanged — this still allows, same as any other
// verdict below MinMaliciousScoreToBlock — but the warning text must use the
// distinct, grep-able UNSCORED_VERDICT prefix rather than the generic
// "low-confidence" wording, so operators can tell "provider declined to
// score this" apart from "provider scored this as harmless" in the
// decision log.
func TestCompose_UnscoredBlockListedVerdictAllowsWithLoudWarning(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0, ScoreMissing: true},
	}}
	d := Compose(context.Background(), cfg, "shell", []string{"malicious.example"}, nil, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow (unscored verdict falls through today), got deny")
	}
	found := false
	for _, w := range d.Warnings {
		if strings.HasPrefix(w, "UNSCORED_VERDICT:") {
			found = true
		}
		if strings.HasPrefix(w, "low-confidence") {
			t.Errorf("expected UNSCORED_VERDICT wording, got generic low-confidence warning: %q", w)
		}
	}
	if !found {
		t.Errorf("expected an UNSCORED_VERDICT warning, got %v", d.Warnings)
	}
}

// TestCompose_ScoredLowConfidenceKeepsGenericWarning ensures the new
// ScoreMissing branch doesn't swallow the ordinary "real score, just below
// threshold" case: a genuinely-scored block-listed verdict below the
// threshold must still use the original "low-confidence" wording, not
// UNSCORED_VERDICT.
func TestCompose_ScoredLowConfidenceKeepsGenericWarning(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"weak.example": {Name: "MALICIOUS", MaliciousScore: 0.2, ScoreMissing: false},
	}}
	d := Compose(context.Background(), cfg, "shell", []string{"weak.example"}, nil, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow (below threshold), got deny")
	}
	found := false
	for _, w := range d.Warnings {
		if strings.HasPrefix(w, "low-confidence") {
			found = true
		}
		if strings.HasPrefix(w, "UNSCORED_VERDICT:") {
			t.Errorf("expected generic low-confidence wording, got UNSCORED_VERDICT: %q", w)
		}
	}
	if !found {
		t.Errorf("expected a low-confidence warning, got %v", d.Warnings)
	}
}

// TestCompose_UnknownLabelBelowThresholdAllows covers the ordinary "unknown
// verdict, no score" case (e.g. Malanta's UNKNOWN with a null score, or any
// provider verdict name that isn't in BlockLabels and whose score is below
// MinMaliciousScoreToBlock). Reputation is a deny-list model: an unrecognized
// label must allow, not deny, or the cascade would block most of the
// legitimate internet.
func TestCompose_UnknownLabelBelowThresholdAllows(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"mystery.example": {Name: "WeirdNewCategory", MaliciousScore: 0},
	}}
	d := Compose(context.Background(), cfg, "shell", []string{"mystery.example"}, nil, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow for unknown label below threshold, got deny")
	}
}

// TestCompose_ScoreBackstopDeniesUnmappedLabel is the regression test for
// the score backstop: a provider verdict whose NAME isn't in BlockLabels but
// whose score crosses MinMaliciousScoreToBlock must still deny. This closes
// the "new provider enum silently bypasses the block list" gap without
// requiring BlockLabels to enumerate every possible bad verdict string.
func TestCompose_ScoreBackstopDeniesUnmappedLabel(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"newthreat.example": {Name: "SOME_FUTURE_VERDICT_NOT_IN_BLOCKLIST", MaliciousScore: 0.97},
	}}
	d := Compose(context.Background(), cfg, "shell", []string{"newthreat.example"}, nil, lk, nil)
	if d.Allow {
		t.Errorf("expected deny via score backstop despite unmapped label, got allow: %#v", d)
	}
}

// TestCompose_AbsentFromResponse_RetriesOnceThenFailsClosed is the
// regression test for the absent-indicator retry path. An indicator absent from the
// provider's response (not merely a low/zero-score verdict — see
// reputation.Provider's doc-comment) is a protocol anomaly: Compose must
// retry once, and if it's still absent, DENY when FailClosed (the previous
// "allow + warn" behavior for a bare miss made a partial/broken response
// indistinguishable from "definitely clean").
func TestCompose_AbsentFromResponse_RetriesOnceThenFailsClosed(t *testing.T) {
	cfg := baseCfg(t)
	cfg.FailClosed = true
	var calls int
	lk := &countingRetryLookup{
		onLookup: func(indicators []reputation.Indicator) map[reputation.Indicator]*reputation.Label {
			calls++
			return map[reputation.Indicator]*reputation.Label{} // never answers -> stays absent
		},
	}
	d := Compose(context.Background(), cfg, "shell", []string{"ghost.example"}, nil, lk, nil)
	if d.Allow {
		t.Errorf("expected deny for an indicator absent from the response after retry, got allow: %#v", d)
	}
	if calls != 2 {
		t.Errorf("expected exactly 2 Lookup calls (initial + one retry), got %d", calls)
	}
}

func TestCompose_AbsentFromResponse_FailOpenAllowsWithWarning(t *testing.T) {
	cfg := baseCfg(t)
	cfg.FailClosed = false
	lk := &countingRetryLookup{
		onLookup: func(indicators []reputation.Indicator) map[reputation.Indicator]*reputation.Label {
			return map[reputation.Indicator]*reputation.Label{}
		},
	}
	d := Compose(context.Background(), cfg, "shell", []string{"ghost.example"}, nil, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow + warn for absent indicator under fail-open, got deny: %#v", d)
	}
	if len(d.Warnings) == 0 {
		t.Errorf("expected a warning for the absent indicator")
	}
}

// TestCompose_AbsentFromResponse_RetrySucceeds verifies the happy path of
// the retry-once policy: if the SECOND Lookup call resolves the indicator,
// the cascade proceeds normally (no denial, no leftover warning about
// absence).
func TestCompose_AbsentFromResponse_RetrySucceeds(t *testing.T) {
	cfg := baseCfg(t)
	var calls int
	lk := &countingRetryLookup{
		onLookup: func(indicators []reputation.Indicator) map[reputation.Indicator]*reputation.Label {
			calls++
			out := make(map[reputation.Indicator]*reputation.Label, len(indicators))
			if calls >= 2 {
				for _, ind := range indicators {
					out[ind] = &reputation.Label{Name: "UNKNOWN"}
				}
			}
			return out
		},
	}
	d := Compose(context.Background(), cfg, "shell", []string{"flaky.example"}, nil, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow once the retry resolves the indicator, got deny: %#v", d)
	}
}

type countingRetryLookup struct {
	onLookup func([]reputation.Indicator) map[reputation.Indicator]*reputation.Label
}

func (c *countingRetryLookup) Lookup(_ context.Context, indicators []reputation.Indicator) (map[reputation.Indicator]*reputation.Label, error) {
	return c.onLookup(indicators), nil
}
func (c *countingRetryLookup) Name() string { return "malanta" }

func TestCompose_ProviderError_FailClosed(t *testing.T) {
	cfg := baseCfg(t)
	cfg.FailClosed = true
	lk := &fakeLookup{err: reputation.ErrProvider}
	d := Compose(context.Background(), cfg, "shell", []string{"x.example"}, nil, lk, nil)
	if d.Allow {
		t.Errorf("expected deny on provider error w/ fail-closed, got allow")
	}
}

// TestCompose_ProviderError_UserMessageHidesRawDetailButLogsIt covers the
// Reason/UserReason split: the raw provider error (HTTP status, JSON body,
// etc.) must stay in Reason (what the decision log / `trustgate explain`
// show), while the message actually shown to the user (via AsJSON, which
// calls denyMessage) is a clean, vendor-agnostic summary with none of that
// raw detail.
func TestCompose_ProviderError_UserMessageHidesRawDetailButLogsIt(t *testing.T) {
	cfg := baseCfg(t)
	cfg.FailClosed = true
	rawDetail := `http 422: {"detail":"some raw vendor json body"}`
	lk := &fakeLookup{name: "virustotal", err: errors.New(rawDetail)}
	d := Compose(context.Background(), cfg, "beforeShellExecution", []string{"x.example"}, nil, lk, nil)
	if d.Allow {
		t.Fatalf("expected deny on provider error w/ fail-closed, got allow")
	}
	if !strings.Contains(d.Reason, rawDetail) {
		t.Errorf("expected Reason (decision log) to retain the raw detail, got %q", d.Reason)
	}
	out := string(d.AsJSON())
	if strings.Contains(out, rawDetail) {
		t.Errorf("expected the user-facing message to NOT leak the raw provider detail, got %s", out)
	}
	if !strings.Contains(out, "virustotal temporarily unavailable") {
		t.Errorf("expected the clean provider-unavailable summary, got %s", out)
	}
	if !strings.Contains(out, "fail-closed") {
		t.Errorf("expected the user message to explain the action was blocked fail-closed, got %s", out)
	}
}

// TestCompose_ProviderError_AuthErrorGetsCleanUserMessage covers the auth
// (401/403) sub-case: the user sees a short, actionable message, not the
// raw error the auth-detection wrapping produced.
func TestCompose_ProviderError_AuthErrorGetsCleanUserMessage(t *testing.T) {
	cfg := baseCfg(t)
	cfg.FailClosed = true
	lk := &fakeLookup{name: "malanta", err: reputation.ErrAuth}
	d := Compose(context.Background(), cfg, "beforeShellExecution", []string{"x.example"}, nil, lk, nil)
	if d.Allow {
		t.Fatalf("expected deny on auth error w/ fail-closed, got allow")
	}
	out := string(d.AsJSON())
	if !strings.Contains(out, "API key rejected") {
		t.Errorf("expected a clean auth-error user message, got %s", out)
	}
}

func TestCompose_ProviderError_FailOpen(t *testing.T) {
	cfg := baseCfg(t)
	cfg.FailClosed = false
	lk := &fakeLookup{err: reputation.ErrProvider}
	d := Compose(context.Background(), cfg, "shell", []string{"x.example"}, nil, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow on provider error w/ fail-open, got deny")
	}
}

// TestCompose_ProviderError_PromptHookFailsOpenEvenWhenFailClosed verifies
// beforeSubmitPrompt's advisory posture: a provider error (Malanta slow /
// down) fails OPEN there even under FailClosed=true, so a hiccup never
// blocks prompt submission — while an execution hook fails closed on the
// identical error. The execution hooks remain the fail-closed enforcement
// boundary (see failClosedOnProviderError).
func TestCompose_ProviderError_PromptHookFailsOpenEvenWhenFailClosed(t *testing.T) {
	cfg := baseCfg(t)
	cfg.FailClosed = true
	lk := &fakeLookup{err: reputation.ErrProvider}

	shell := Compose(context.Background(), cfg, "beforeShellExecution", []string{"x.example"}, nil, lk, nil)
	if shell.Allow {
		t.Errorf("beforeShellExecution: provider error must fail closed (deny), got allow")
	}

	prompt := Compose(context.Background(), cfg, "beforeSubmitPrompt", []string{"x.example"}, nil, lk, nil)
	if !prompt.Allow {
		t.Errorf("beforeSubmitPrompt: provider error must fail OPEN (allow), got deny; warnings: %v", prompt.Warnings)
	}
}

// TestCompose_ProviderError_WarnModeFailsOpenEvenWhenFailClosed verifies
// that warn mode is fail-OPEN on a provider error (Malanta slow / down):
// warn is an audit+notify posture and must not delay the developer's work
// when TrustGate's own provider hiccups, matching report-only. enforce on
// the identical error still fails closed (see failClosedOnProviderError).
func TestCompose_ProviderError_WarnModeFailsOpenEvenWhenFailClosed(t *testing.T) {
	cfg := baseCfg(t)
	cfg.FailClosed = true
	lk := &fakeLookup{err: reputation.ErrProvider}

	cfg.Mode = config.ModeEnforce
	enforce := Compose(context.Background(), cfg, "beforeShellExecution", []string{"x.example"}, nil, lk, nil)
	if enforce.Allow {
		t.Errorf("enforce: provider error must fail closed (deny), got allow")
	}

	cfg.Mode = config.ModeWarn
	warn := Compose(context.Background(), cfg, "beforeShellExecution", []string{"x.example"}, nil, lk, nil)
	if !warn.Allow {
		t.Errorf("warn: provider error must fail OPEN (allow), got deny; warnings: %v", warn.Warnings)
	}
}

func TestCompose_AuthError_FailClosed_HasHint(t *testing.T) {
	cfg := baseCfg(t)
	cfg.FailClosed = true
	lk := &fakeLookup{err: wrap(reputation.ErrAuth, "http 401")}
	d := Compose(context.Background(), cfg, "shell", []string{"x.example"}, nil, lk, nil)
	if d.Allow {
		t.Fatalf("expected deny on auth error w/ fail-closed, got allow")
	}
	if d.Reason == "" {
		t.Errorf("expected non-empty reason")
	}
}

func TestCompose_RespectsDeadline(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{err: reputation.ErrProvider}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	d := Compose(ctx, cfg, "shell", []string{"x.example"}, nil, lk, nil)
	if d.Allow && cfg.FailClosed {
		t.Errorf("expected deny under fail-closed, got allow")
	}
}

// TestCompose_IPv4Indicator covers the re-enabled IPv4 path end to end
// through the cascade (classification happens inside Compose).
func TestCompose_IPv4Indicator(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"192.0.2.4": {Name: "MALICIOUS", MaliciousScore: 0.9},
	}}
	d := Compose(context.Background(), cfg, "shell", []string{"192.0.2.4"}, nil, lk, nil)
	if d.Allow {
		t.Errorf("expected deny for malicious IPv4, got allow: %#v", d)
	}
	if d.Kind != "ipv4" {
		t.Errorf("expected Kind=ipv4, got %q", d.Kind)
	}
}

// TestCompose_IPv6Skipped verifies that an IPv6 literal is skipped with a
// warning rather than denied or sent to a provider that can't answer it.
func TestCompose_IPv6Skipped(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{resp: map[string]*reputation.Label{}}
	d := Compose(context.Background(), cfg, "shell", []string{"2001:4860:4860::8888"}, nil, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow (IPv6 unsupported, not an error), got deny: %#v", d)
	}
	if len(d.Warnings) == 0 {
		t.Errorf("expected a warning noting IPv6 is unsupported")
	}
}

// wrap is a tiny helper used by TestCompose_AuthError to build a wrapped error
// without depending on fmt.Errorf semantics in the test.
func wrap(sentinel error, msg string) error {
	return &wrappedErr{err: sentinel, msg: msg}
}

type wrappedErr struct {
	err error
	msg string
}

func (w *wrappedErr) Error() string { return w.msg + ": " + w.err.Error() }
func (w *wrappedErr) Unwrap() error { return w.err }
