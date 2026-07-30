// Package cache provides a per-user SQLite-backed TTL cache for reputation
// lookups, keyed by (provider, kind, value) so entries from different
// providers or indicator kinds never collide. Cursor spawns a fresh hook
// subprocess per invocation, so an in-memory cache would be useless; we
// persist to disk and share the file across concurrent hook subprocesses
// via WAL mode.
package cache

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"

	_ "modernc.org/sqlite" // pure-Go driver, registers "sqlite"
)

// Cache wraps a single SQLite database file. Safe to use from multiple
// processes concurrently (WAL mode + busy_timeout).
type Cache struct {
	db *sql.DB
}

// schema v2: the row key is (provider, kind, value) instead of a bare
// domain string. This is required for multi-vendor support (the same host
// can carry a different verdict from a different provider) and for IPv4
// indicators (which share the value namespace loosely with domains but are
// a semantically distinct Kind). label_name is NOT NULL — there is no more
// "negative cache" placeholder row: a provider that has no data for an
// indicator must resolve it to an explicit Label (e.g. Name: "UNKNOWN",
// MaliciousScore: 0), never omit it, so every cached row is a real,
// positive resolution. See internal/reputation.Provider's doc-comment.
//
// malicious_score was named "probability" prior to the Label.Probability
// -> Label.MaliciousScore rename; see dropIfLegacySchema for how an
// existing database with the old column name is handled (drop + recreate,
// not migrate — this is a pure latency cache with no durability
// requirement, so losing cached rows across the rename costs nothing but
// a few re-fetched lookups).
const schema = `
CREATE TABLE IF NOT EXISTS lookups (
	provider        TEXT NOT NULL,
	kind            TEXT NOT NULL,
	value           TEXT NOT NULL,
	label_name      TEXT NOT NULL,
	malicious_score REAL NOT NULL,
	expires_at      INTEGER NOT NULL,
	PRIMARY KEY (provider, kind, value)
);
CREATE INDEX IF NOT EXISTS lookups_expires_at_idx ON lookups(expires_at);
`

// dropIfLegacySchema drops the lookups table if it still has the
// pre-rename "probability" column instead of "malicious_score", so the
// subsequent CREATE TABLE IF NOT EXISTS actually creates the current
// schema rather than silently keeping the stale one (which would then
// fail every query referencing the new column name). Deliberately a
// drop-and-recreate, not a data migration: the cache is a pure latency
// optimization (see OpenOrWarn's doc comment) with no durability
// requirement, so discarding old cached verdicts across a column rename
// is a safe, one-time cost — the next lookup for each host simply
// repopulates the cache. No-op (including on any query error) when the
// table doesn't exist yet — CREATE TABLE handles that case normally.
func dropIfLegacySchema(db *sql.DB) {
	rows, err := db.Query(`PRAGMA table_info(lookups)`)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	var hasOldColumn, hasNewColumn bool
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			continue
		}
		switch name {
		case "probability":
			hasOldColumn = true
		case "malicious_score":
			hasNewColumn = true
		}
	}
	if hasOldColumn && !hasNewColumn {
		_, _ = db.Exec(`DROP TABLE lookups`)
	}
}

// scoreMissingColumnMigration adds the "score_missing" column (see
// reputation.Label.ScoreMissing) to databases created before it existed.
// New rows write the real value via Put; existing pre-migration rows read
// back as 0 (false = "had a score") via the column DEFAULT, which is the
// conservative/backward-compatible choice — we don't know whether an old
// cached verdict was genuinely scored or defaulted from a nil/absent
// provider score, and defaulting to "had a score" avoids retroactively
// flagging every pre-existing cache row as UNSCORED_VERDICT noise.
// ALTER TABLE ADD COLUMN errors when the column already exists (no
// portable "IF NOT EXISTS" for columns across SQLite versions), so a
// "duplicate column" error here is expected on every run after the first
// and is swallowed.
const scoreMissingColumnMigration = `ALTER TABLE lookups ADD COLUMN score_missing INTEGER NOT NULL DEFAULT 0`

// Open returns a Cache backed by the file at path. The directory is created
// with mode 0700 if necessary, and the database file is tightened to 0600.
// The 0700 dir already blocks other unprivileged users; the explicit 0600
// on the file is defense-in-depth (a permissive umask, or a file created
// out-of-band, would otherwise leave the cache world-readable). Note this
// is not tamper-protection against the owning user (a process with the
// owner's UID can still rewrite a cached verdict) — that would require the
// deferred root-owned daemon design; see AGENTS.md.
func Open(path string) (*Cache, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("cache: mkdir: %w", err)
	}
	// _journal=wal allows concurrent readers + one writer across processes.
	// _busy_timeout caps how long we'll sleep on SQLITE_BUSY. We keep it
	// small (50ms) so contention can't eat the hook's time budget; the
	// cascade treats cache errors as misses, never as a reason to block.
	dsn := fmt.Sprintf("file:%s?_journal=wal&_busy_timeout=50&_synchronous=NORMAL", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("cache: open: %w", err)
	}
	// modernc.org/sqlite does not enforce a small connection pool by default; pin to 1
	// writer + a few readers so we don't fight ourselves on a single-process binary.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	dropIfLegacySchema(db)
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("cache: schema: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), scoreMissingColumnMigration); err != nil && !strings.Contains(err.Error(), "duplicate column") {
		_ = db.Close()
		return nil, fmt.Errorf("cache: score_missing column migration: %w", err)
	}
	// Defense-in-depth: tighten the db file and its WAL/SHM sidecars to
	// 0600 in case a permissive umask left them group/world-readable. The
	// parent dir is already 0700, so this is belt-and-suspenders; failures
	// are non-fatal (the sidecars may not exist yet, and the cache is a
	// latency optimization, never a correctness primitive).
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, statErr := os.Stat(p); statErr == nil {
			_ = os.Chmod(p, 0o600)
		}
	}
	return &Cache{db: db}, nil
}

// OpenOrWarn wraps Open with a fail-open policy intended for hook entrypoints:
// if the cache cannot be opened (permissions, disk full, corruption), it
// returns nil and writes a single warning line to w (typically os.Stderr,
// which surfaces in Cursor's hook output panel). Callers must therefore treat
// the returned *Cache as nullable; verdict.Compose handles nil caches by
// going straight to the network. This is the right policy because the cache
// is a latency optimization, not a correctness primitive.
func OpenOrWarn(path string, w io.Writer) *Cache {
	c, err := Open(path)
	if err != nil {
		if w != nil {
			fmt.Fprintf(w, "trustgate: cache disabled (%s): %v\n", path, err)
		}
		return nil
	}
	return c
}

// Close releases the database handle.
func (c *Cache) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Close()
}

// Lookup returns (label, present, err) for a single (provider, indicator)
// pair. present=false means a cache miss (or expired row); the caller
// should query the provider. present=true always carries a non-nil Label —
// there is no more "negative hit" state (see the schema doc-comment).
func (c *Cache) Lookup(ctx context.Context, provider string, ind reputation.Indicator) (*reputation.Label, bool, error) {
	now := time.Now().Unix()
	row := c.db.QueryRowContext(ctx,
		`SELECT label_name, malicious_score, score_missing FROM lookups WHERE provider = ? AND kind = ? AND value = ? AND expires_at > ?`,
		provider, ind.Kind.String(), ind.Value, now)
	var name string
	var maliciousScore float64
	var scoreMissing bool
	if err := row.Scan(&name, &maliciousScore, &scoreMissing); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("cache: lookup: %w", err)
	}
	return &reputation.Label{Name: name, MaliciousScore: maliciousScore, ScoreMissing: scoreMissing}, true, nil
}

// BatchHit is the per-indicator answer in a LookupBatch result. Present is
// true when the cache contains a non-expired row for that (provider,
// indicator) pair; Label is always non-nil when Present is true.
type BatchHit struct {
	Label   *reputation.Label
	Present bool
}

// maxBatchIndicators caps how many indicators go into a single query's OR
// chain. Each indicator contributes 2 placeholders (kind, value) plus 2
// shared ones (provider, expires_at); 200 indicators is 402 placeholders,
// comfortably under SQLite's default SQLITE_MAX_VARIABLE_NUMBER (999,
// sometimes as low as 250 depending on build). Chunking is defensive: a
// future bump to the fan-out cap shouldn't require a coordinated change
// here.
const maxBatchIndicators = 200

// LookupBatch is the bulk variant of Lookup, collapsing N round trips to
// the SQLite file into ceil(N/maxBatchIndicators) (usually 1) queries.
//
// Errors are reported per-indicator in errs (rather than a single error for
// the whole batch) so one chunk's failure doesn't take down the rest of the
// cascade. Returns a non-nil errs map only when something failed.
func (c *Cache) LookupBatch(ctx context.Context, provider string, indicators []reputation.Indicator) (hits map[reputation.Indicator]BatchHit, errs map[reputation.Indicator]error) {
	if c == nil || c.db == nil || len(indicators) == 0 {
		return nil, nil
	}
	seen := make(map[reputation.Indicator]struct{}, len(indicators))
	uniq := make([]reputation.Indicator, 0, len(indicators))
	for _, ind := range indicators {
		if _, ok := seen[ind]; ok {
			continue
		}
		seen[ind] = struct{}{}
		uniq = append(uniq, ind)
	}

	hits = make(map[reputation.Indicator]BatchHit, len(uniq))
	for i := 0; i < len(uniq); i += maxBatchIndicators {
		end := i + maxBatchIndicators
		if end > len(uniq) {
			end = len(uniq)
		}
		chunk := uniq[i:end]
		if err := c.lookupBatchChunk(ctx, provider, chunk, hits); err != nil {
			if errs == nil {
				errs = make(map[reputation.Indicator]error, len(chunk))
			}
			for _, ind := range chunk {
				errs[ind] = err
			}
		}
	}
	return hits, errs
}

// lookupBatchChunk runs a single query for up to maxBatchIndicators
// indicators. Uses an explicit (kind = ? AND value = ?) OR-chain rather
// than a composite row-value IN(...) list for maximum portability across
// SQLite driver/version combinations.
func (c *Cache) lookupBatchChunk(ctx context.Context, provider string, indicators []reputation.Indicator, hits map[reputation.Indicator]BatchHit) error {
	if len(indicators) == 0 {
		return nil
	}
	var sb strings.Builder
	sb.WriteString(`SELECT kind, value, label_name, malicious_score, score_missing FROM lookups WHERE provider = ? AND expires_at > ? AND (`)
	args := make([]any, 0, 2+len(indicators)*2)
	args = append(args, provider, time.Now().Unix())
	for i, ind := range indicators {
		if i > 0 {
			sb.WriteString(" OR ")
		}
		sb.WriteString("(kind = ? AND value = ?)")
		args = append(args, ind.Kind.String(), ind.Value)
	}
	sb.WriteString(")")

	rows, err := c.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return fmt.Errorf("cache: lookupBatch: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var kindStr, value, name string
		var maliciousScore float64
		var scoreMissing bool
		if err := rows.Scan(&kindStr, &value, &name, &maliciousScore, &scoreMissing); err != nil {
			return fmt.Errorf("cache: lookupBatch scan: %w", err)
		}
		kind, ok := reputation.ParseKind(kindStr)
		if !ok {
			continue // unrecognized kind string; treat as absent rather than error the whole chunk
		}
		hits[reputation.Indicator{Kind: kind, Value: value}] = BatchHit{
			Label:   &reputation.Label{Name: name, MaliciousScore: maliciousScore, ScoreMissing: scoreMissing},
			Present: true,
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("cache: lookupBatch iterate: %w", err)
	}
	return nil
}

// Put writes (or replaces) a cache entry for (provider, indicator). label
// must be non-nil — there is no more "negative cache" placeholder; a nil
// label is a no-op (nothing is written), since callers should only cache a
// definitively-resolved Label (see internal/reputation.Provider's
// doc-comment on why "no data available" must be an explicit Label, not an
// absent entry).
func (c *Cache) Put(ctx context.Context, provider string, ind reputation.Indicator, label *reputation.Label, ttl time.Duration) error {
	if label == nil {
		return nil
	}
	expiresAt := time.Now().Add(ttl).Unix()
	_, err := c.db.ExecContext(ctx,
		`INSERT INTO lookups(provider, kind, value, label_name, malicious_score, expires_at, score_missing)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(provider, kind, value) DO UPDATE SET
		   label_name=excluded.label_name,
		   malicious_score=excluded.malicious_score,
		   expires_at=excluded.expires_at,
		   score_missing=excluded.score_missing`,
		provider, ind.Kind.String(), ind.Value, label.Name, label.MaliciousScore, expiresAt, label.ScoreMissing,
	)
	if err != nil {
		return fmt.Errorf("cache: put: %w", err)
	}
	return nil
}
