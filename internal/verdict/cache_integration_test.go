package verdict

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/cache"
	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

func openTempCache(t *testing.T) *cache.Cache {
	t.Helper()
	c, err := cache.Open(filepath.Join(t.TempDir(), "lookups.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// recordingLookup tracks whether Lookup was called. Used to assert that a
// cache HIT short-circuits the network entirely.
type recordingLookup struct {
	called bool
	resp   map[string]*reputation.Label
	err    error
}

func (r *recordingLookup) Lookup(_ context.Context, indicators []reputation.Indicator) (map[reputation.Indicator]*reputation.Label, error) {
	r.called = true
	if r.err != nil {
		return nil, r.err
	}
	out := make(map[reputation.Indicator]*reputation.Label, len(indicators))
	for _, ind := range indicators {
		if lbl, ok := r.resp[ind.Value]; ok {
			out[ind] = lbl
		}
	}
	return out, nil
}

func (r *recordingLookup) Name() string { return "malanta" }

func domainInd(v string) reputation.Indicator {
	return reputation.Indicator{Kind: reputation.KindDomain, Value: v}
}

func TestCompose_CacheHitDeny_SkipsProvider(t *testing.T) {
	cfg := baseCfg(t)
	c := openTempCache(t)
	if err := c.Put(context.Background(), "malanta", domainInd("malicious.example"),
		&reputation.Label{Name: "MALICIOUS", MaliciousScore: 0.99},
		time.Hour); err != nil {
		t.Fatalf("cache.Put: %v", err)
	}
	lk := &recordingLookup{}
	d := Compose(context.Background(), cfg, "shell", []string{"malicious.example"}, c, lk, nil)
	if d.Allow {
		t.Fatalf("expected deny from cache hit, got allow: %#v", d)
	}
	if lk.called {
		t.Errorf("provider was called even though cache hit should have short-circuited")
	}
}

func TestCompose_CacheHitClean_AllowSkipsProvider(t *testing.T) {
	cfg := baseCfg(t)
	c := openTempCache(t)
	if err := c.Put(context.Background(), "malanta", domainInd("clean.example"),
		&reputation.Label{Name: "UNKNOWN"}, time.Hour); err != nil {
		t.Fatalf("cache.Put: %v", err)
	}
	lk := &recordingLookup{}
	d := Compose(context.Background(), cfg, "shell", []string{"clean.example"}, c, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow on clean cache hit, got deny: %#v", d)
	}
	if lk.called {
		t.Errorf("provider was called despite a clean cache hit")
	}
}

func TestCompose_CacheMissPopulatesCache(t *testing.T) {
	cfg := baseCfg(t)
	c := openTempCache(t)
	resp := map[string]*reputation.Label{
		"new.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
	}
	lk := &recordingLookup{resp: resp}
	d1 := Compose(context.Background(), cfg, "shell", []string{"new.example"}, c, lk, nil)
	if d1.Allow {
		t.Fatalf("expected deny on first call, got allow: %#v", d1)
	}
	if !lk.called {
		t.Fatalf("expected provider to be called on first lookup")
	}
	lk.called = false
	d2 := Compose(context.Background(), cfg, "shell", []string{"new.example"}, c, lk, nil)
	if d2.Allow {
		t.Fatalf("expected deny on second call (cache), got allow: %#v", d2)
	}
	if lk.called {
		t.Errorf("expected second lookup to be served from cache, but provider was called")
	}
}

// TestWriteLog_RedactionAndPermissions asserts the decision-log contract:
// only timestamp + hosts + Decision are written, the file is created with
// mode 0600, and the format is JSON Lines (one object per line, terminating
// with a newline).
func TestWriteLog_RedactionAndPermissions(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "decisions.log")
	cfg := baseCfg(t)
	cfg.LogPath = logPath
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"malicious.example": {Name: "MALICIOUS", MaliciousScore: 0.99},
	}}
	d := Compose(context.Background(), cfg, "beforeShellExecution",
		[]string{"malicious.example"}, nil, lk, nil)
	if d.Allow {
		t.Fatalf("expected deny, got allow")
	}

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Mode check is POSIX-only: Windows governs access by ACL and reports
	// 0666 for any writable file, so asserting bits there tests nothing.
	// The redaction and JSON Lines assertions below still run everywhere.
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("decision log mode = %o, want 600", mode)
		}
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 JSON line, got %d:\n%s", len(lines), raw)
	}

	var rec struct {
		Timestamp string          `json:"timestamp"`
		Hosts     []string        `json:"hosts"`
		Decision  json.RawMessage `json:"decision"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, lines[0])
	}
	if rec.Timestamp == "" {
		t.Errorf("missing timestamp")
	}
	if len(rec.Hosts) != 1 || rec.Hosts[0] != "malicious.example" {
		t.Errorf("unexpected hosts: %v", rec.Hosts)
	}

	// Redaction contract: the log must not include any field whose key
	// looks like prompt/command/payload/content/argv text. We never set
	// these in writeLog, so they should be absent from the record.
	for _, banned := range []string{"prompt", "command", "argv", "content", "payload", "text"} {
		if strings.Contains(strings.ToLower(string(raw)), `"`+banned+`"`) {
			t.Errorf("decision log contains forbidden field %q:\n%s", banned, raw)
		}
	}
}

// TestCompose_CachePutErrorIsWarningNotDeny verifies that a cache write
// failure (simulated by closing the cache before Compose runs) does NOT
// flip the verdict to deny — the verdict tracks the provider's answer.
func TestCompose_CachePutErrorIsWarningNotDeny(t *testing.T) {
	cfg := baseCfg(t)
	c := openTempCache(t)
	_ = c.Close() // every subsequent op should now fail
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"clean.example": {Name: "UNKNOWN"},
	}}
	d := Compose(context.Background(), cfg, "shell", []string{"clean.example"}, c, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow despite cache write failure, got deny: %#v", d)
	}
}

// TestCompose_CacheDenyWinsOverProviderError verifies that when one domain
// is cached and the provider would otherwise error, the cached deny still
// wins (cache hit short-circuits before the provider is ever consulted).
func TestCompose_CacheDenyWinsOverProviderError(t *testing.T) {
	cfg := baseCfg(t)
	cfg.FailClosed = false
	c := openTempCache(t)
	if err := c.Put(context.Background(), "malanta", domainInd("bad.example"),
		&reputation.Label{Name: "MALICIOUS", MaliciousScore: 0.99},
		time.Hour); err != nil {
		t.Fatalf("cache.Put: %v", err)
	}
	lk := &fakeLookup{err: reputation.ErrProvider}
	d := Compose(context.Background(), cfg, "shell",
		[]string{"bad.example"}, c, lk, nil)
	if d.Allow {
		t.Errorf("expected deny from cached label, got allow: %#v", d)
	}
}
