package cache

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

// TestCache_FileIsOwnerOnly guards the defense-in-depth 0600 tightening in
// Open: the db file (and its WAL/SHM sidecars, when present) must not be
// group/world-readable even under a permissive umask. POSIX-only — Windows
// uses ACLs, not Unix mode bits.
func TestCache_FileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "lookups.db")
	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = c.Close() }()

	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		info, statErr := os.Stat(p)
		if statErr != nil {
			continue // sidecars may not exist depending on WAL checkpoint timing
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s mode = %o, want owner-only (no group/world bits)", p, perm)
		}
	}
}

func newCache(t *testing.T) *Cache {
	t.Helper()
	dir := t.TempDir()
	return newCacheAt(t, filepath.Join(dir, "lookups.db"))
}

// newCacheAt is newCache's counterpart for tests that need to reopen the
// SAME file path later (e.g. to simulate a pre-existing on-disk schema).
func newCacheAt(t *testing.T, path string) *Cache {
	t.Helper()
	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func domainInd(v string) reputation.Indicator {
	return reputation.Indicator{Kind: reputation.KindDomain, Value: v}
}

func TestCache_PositiveHit(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()
	lbl := &reputation.Label{Name: "Malicious", MaliciousScore: 0.9}
	if err := c.Put(ctx, "malanta", domainInd("bad.example"), lbl, time.Hour); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, present, err := c.Lookup(ctx, "malanta", domainInd("bad.example"))
	if err != nil || !present || got == nil {
		t.Fatalf("Lookup: present=%v got=%v err=%v", present, got, err)
	}
	if got.Name != "Malicious" {
		t.Errorf("label: got %q want Malicious", got.Name)
	}
}

// TestCache_ScoreMissingRoundTrips covers reputation.Label.ScoreMissing:
// Put/Lookup and Put/LookupBatch must both round-trip the bit accurately,
// since a stale/misreported value would make the cascade's UNSCORED_VERDICT
// warning (internal/verdict) fire on the wrong entries after a cache hit.
func TestCache_ScoreMissingRoundTrips(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()

	scored := &reputation.Label{Name: "MALICIOUS", MaliciousScore: 0.95, ScoreMissing: false}
	unscored := &reputation.Label{Name: "MALICIOUS", MaliciousScore: 0, ScoreMissing: true}
	if err := c.Put(ctx, "malanta", domainInd("scored.example"), scored, time.Hour); err != nil {
		t.Fatalf("Put(scored): %v", err)
	}
	if err := c.Put(ctx, "malanta", domainInd("unscored.example"), unscored, time.Hour); err != nil {
		t.Fatalf("Put(unscored): %v", err)
	}

	gotScored, present, err := c.Lookup(ctx, "malanta", domainInd("scored.example"))
	if err != nil || !present {
		t.Fatalf("Lookup(scored): present=%v err=%v", present, err)
	}
	if gotScored.ScoreMissing {
		t.Errorf("scored.example: ScoreMissing = true, want false")
	}

	gotUnscored, present, err := c.Lookup(ctx, "malanta", domainInd("unscored.example"))
	if err != nil || !present {
		t.Fatalf("Lookup(unscored): present=%v err=%v", present, err)
	}
	if !gotUnscored.ScoreMissing {
		t.Errorf("unscored.example: ScoreMissing = false, want true")
	}

	// Same assertions via the batch path, which uses a separate query.
	hits, errs := c.LookupBatch(ctx, "malanta", []reputation.Indicator{
		domainInd("scored.example"), domainInd("unscored.example"),
	})
	if len(errs) != 0 {
		t.Fatalf("LookupBatch errs: %v", errs)
	}
	if hit := hits[domainInd("scored.example")]; !hit.Present || hit.Label.ScoreMissing {
		t.Errorf("batch scored.example: present=%v ScoreMissing=%v, want present=true ScoreMissing=false", hit.Present, hit.Label.ScoreMissing)
	}
	if hit := hits[domainInd("unscored.example")]; !hit.Present || !hit.Label.ScoreMissing {
		t.Errorf("batch unscored.example: present=%v ScoreMissing=%v, want present=true ScoreMissing=true", hit.Present, hit.Label.ScoreMissing)
	}
}

// TestCache_PreExistingRowsDefaultToScored simulates a database written
// before the score_missing column existed: inserting via the raw column
// list (no score_missing) must leave the migrated column at its DEFAULT 0
// (false = "had a score"), not retroactively mark old rows as unscored.
func TestCache_PreExistingRowsDefaultToScored(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()
	if _, err := c.db.ExecContext(ctx,
		`INSERT INTO lookups(provider, kind, value, label_name, malicious_score, expires_at)
		 VALUES ('malanta', 'domain', 'legacy.example', 'MALICIOUS', 0.9, ?)`,
		time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	got, present, err := c.Lookup(ctx, "malanta", domainInd("legacy.example"))
	if err != nil || !present {
		t.Fatalf("Lookup: present=%v err=%v", present, err)
	}
	if got.ScoreMissing {
		t.Errorf("pre-migration row: ScoreMissing = true, want false (backward-compat default)")
	}
}

// TestCache_LegacyProbabilityColumnIsDroppedAndRecreated regression-guards
// the probability -> malicious_score column rename: opening a database
// file that still has the OLD schema (a real "probability" column, no
// "malicious_score") must not error or leave the old column in place — it
// drops and recreates the table with the current schema, discarding any
// pre-existing rows (acceptable: this is a pure latency cache, not durable
// storage). A database that already has "malicious_score" (the common
// case after the first run) must be left untouched.
func TestCache_LegacyProbabilityColumnIsDroppedAndRecreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lookups.db")

	// Simulate a pre-rename database: open once so the file/dir exist,
	// then manually rewrite the table to the OLD shape.
	c := newCacheAt(t, path)
	if _, err := c.db.Exec(`DROP TABLE lookups`); err != nil {
		t.Fatalf("drop for legacy simulation: %v", err)
	}
	if _, err := c.db.Exec(`CREATE TABLE lookups (
		provider    TEXT NOT NULL,
		kind        TEXT NOT NULL,
		value       TEXT NOT NULL,
		label_name  TEXT NOT NULL,
		probability REAL NOT NULL,
		expires_at  INTEGER NOT NULL,
		score_missing INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (provider, kind, value)
	)`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	if _, err := c.db.Exec(
		`INSERT INTO lookups(provider, kind, value, label_name, probability, expires_at) VALUES ('malanta','domain','old.example','MALICIOUS',0.9,?)`,
		time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Re-Open must detect the legacy column, drop, and recreate — not
	// error out, and not leave the stale "old.example" row behind.
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("Open on legacy schema: %v", err)
	}
	defer reopened.Close()
	ctx := context.Background()
	if _, present, err := reopened.Lookup(ctx, "malanta", domainInd("old.example")); err != nil {
		t.Fatalf("Lookup after recreate: %v", err)
	} else if present {
		t.Errorf("expected the pre-rename row to be gone after schema recreation, got present=true")
	}
	// The recreated table must be fully usable with the current schema.
	fresh := &reputation.Label{Name: "MALICIOUS", MaliciousScore: 0.99}
	if err := reopened.Put(ctx, "malanta", domainInd("new.example"), fresh, time.Hour); err != nil {
		t.Fatalf("Put after recreate: %v", err)
	}
	got, present, err := reopened.Lookup(ctx, "malanta", domainInd("new.example"))
	if err != nil || !present || got == nil || got.MaliciousScore != 0.99 {
		t.Errorf("Lookup after recreate: got=%#v present=%v err=%v", got, present, err)
	}
}

func TestCache_PutNilLabelIsNoop(t *testing.T) {
	// There is no more "negative cache" placeholder row: Put(nil) must not
	// write anything, and a subsequent Lookup must report a plain miss.
	c := newCache(t)
	ctx := context.Background()
	if err := c.Put(ctx, "malanta", domainInd("clean.example"), nil, time.Hour); err != nil {
		t.Fatalf("Put nil: %v", err)
	}
	_, present, err := c.Lookup(ctx, "malanta", domainInd("clean.example"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if present {
		t.Errorf("expected miss after Put(nil), got present=true")
	}
}

func TestCache_Miss(t *testing.T) {
	c := newCache(t)
	_, present, err := c.Lookup(context.Background(), "malanta", domainInd("never.cached.example"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if present {
		t.Errorf("expected miss, got present=true")
	}
}

func TestCache_Expired(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()
	lbl := &reputation.Label{Name: "Malicious"}
	if err := c.Put(ctx, "malanta", domainInd("stale.example"), lbl, -time.Second); err != nil {
		t.Fatalf("Put expired: %v", err)
	}
	_, present, err := c.Lookup(ctx, "malanta", domainInd("stale.example"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if present {
		t.Errorf("expected miss for already-expired entry")
	}
}

func TestCache_PutReplaces(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()
	lbl1 := &reputation.Label{Name: "Malicious", MaliciousScore: 0.5}
	if err := c.Put(ctx, "malanta", domainInd("d.example"), lbl1, time.Hour); err != nil {
		t.Fatalf("Put #1: %v", err)
	}
	lbl2 := &reputation.Label{Name: "Suspicius", MaliciousScore: 0.9}
	if err := c.Put(ctx, "malanta", domainInd("d.example"), lbl2, time.Hour); err != nil {
		t.Fatalf("Put #2: %v", err)
	}
	got, present, err := c.Lookup(ctx, "malanta", domainInd("d.example"))
	if err != nil || !present {
		t.Fatalf("Lookup: %v present=%v", err, present)
	}
	if got.Name != "Suspicius" || got.MaliciousScore != 0.9 {
		t.Errorf("expected replacement, got %#v", got)
	}
}

// TestCache_ProviderIsolation locks down the schema-v2 property that makes
// multi-vendor support safe: the SAME indicator value under two different
// providers must not collide — a Malanta "clean" verdict for a host must
// never leak into a VirusTotal lookup for the same host, and vice versa.
func TestCache_ProviderIsolation(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()
	if err := c.Put(ctx, "malanta", domainInd("shared.example"), &reputation.Label{Name: "MALICIOUS", MaliciousScore: 0.9}, time.Hour); err != nil {
		t.Fatalf("Put malanta: %v", err)
	}
	if _, present, err := c.Lookup(ctx, "generic", domainInd("shared.example")); err != nil {
		t.Fatalf("Lookup generic: %v", err)
	} else if present {
		t.Errorf("expected miss for a different provider's cache namespace")
	}
	if got, present, err := c.Lookup(ctx, "malanta", domainInd("shared.example")); err != nil || !present || got.Name != "MALICIOUS" {
		t.Errorf("malanta entry should be unaffected: got=%#v present=%v err=%v", got, present, err)
	}
}

// TestCache_KindIsolation locks down that a domain and an IPv4 sharing the
// same literal string value (pathological, but the schema must still be
// correct) are distinct cache rows.
func TestCache_KindIsolation(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()
	domain := reputation.Indicator{Kind: reputation.KindDomain, Value: "192.0.2.4"}
	ip := reputation.Indicator{Kind: reputation.KindIPv4, Value: "192.0.2.4"}
	if err := c.Put(ctx, "malanta", domain, &reputation.Label{Name: "DOMAIN-VERDICT"}, time.Hour); err != nil {
		t.Fatalf("Put domain: %v", err)
	}
	got, present, err := c.Lookup(ctx, "malanta", ip)
	if err != nil {
		t.Fatalf("Lookup ip: %v", err)
	}
	if present {
		t.Errorf("expected the ipv4 kind to be a miss, got %#v", got)
	}
}

// TestCache_GitHubKindsRoundTrip covers the newer indicator kinds end to
// end: a repository and an owner sharing a literal value are distinct rows,
// and each round-trips through the (provider, kind, value) key — which is
// what lets a cache HIT behave identically to a live lookup for them.
func TestCache_GitHubKindsRoundTrip(t *testing.T) {
	c := newCache(t)
	ctx := context.Background()
	repo := reputation.Indicator{Kind: reputation.KindGitHubRepo, Value: "acme/backdoor"}
	owner := reputation.Indicator{Kind: reputation.KindGitHubOwner, Value: "acme"}
	// Same literal string, different scope: must not collide.
	ownerLookalike := reputation.Indicator{Kind: reputation.KindGitHubOwner, Value: "acme/backdoor"}

	if err := c.Put(ctx, "malanta", repo, &reputation.Label{Name: "MALICIOUS", MaliciousScore: 1}, time.Hour); err != nil {
		t.Fatalf("Put repo: %v", err)
	}
	if err := c.Put(ctx, "malanta", owner, &reputation.Label{Name: "UNKNOWN", ScoreMissing: true}, time.Hour); err != nil {
		t.Fatalf("Put owner: %v", err)
	}

	got, present, err := c.Lookup(ctx, "malanta", repo)
	if err != nil || !present || got.Name != "MALICIOUS" || got.MaliciousScore != 1 {
		t.Errorf("repo round-trip: got=%#v present=%v err=%v", got, present, err)
	}
	got, present, err = c.Lookup(ctx, "malanta", owner)
	if err != nil || !present || got.Name != "UNKNOWN" || !got.ScoreMissing {
		t.Errorf("owner round-trip: got=%#v present=%v err=%v", got, present, err)
	}
	if _, present, _ := c.Lookup(ctx, "malanta", ownerLookalike); present {
		t.Error("an owner-kind row must not read the repo-kind row with the same value")
	}

	hits, errs := c.LookupBatch(ctx, "malanta", []reputation.Indicator{repo, owner})
	for ind, err := range errs {
		if err != nil {
			t.Fatalf("LookupBatch %v: %v", ind, err)
		}
	}
	if h := hits[repo]; !h.Present || h.Label == nil || h.Label.Name != "MALICIOUS" {
		t.Errorf("batch repo hit: %#v", h)
	}
	if h := hits[owner]; !h.Present || h.Label == nil || h.Label.Name != "UNKNOWN" {
		t.Errorf("batch owner hit: %#v", h)
	}
}
