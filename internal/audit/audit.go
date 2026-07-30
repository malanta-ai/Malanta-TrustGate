// Package audit is the structured, queryable decision store that backs
// admin operability: the `trustgate doctor`/`explain` CLI subcommands and
// the opt-in remote audit sink both read from here. It is deliberately
// separate from the JSON-Lines decision log (internal/verdict's
// writeLog): the JSONL file is the tail -F-friendly append-only stream
// operators already watch live; this SQLite table is the queryable,
// indexed store that supports "look up decision <id>" and "show me every
// decision for <indicator>" without parsing a growing text file. Both are
// written from the same call site in internal/verdict so they can never
// drift out of sync with each other.
//
// Redaction contract (matches internal/verdict.Decision's decision log):
// only the extracted indicator, the provider's verdict/score, and ATR
// rule IDENTITIES (never raw command/file/prompt bodies) are stored here.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, registers "sqlite"
)

// Store wraps a single SQLite database file. Safe for concurrent use
// across processes (WAL mode + busy_timeout), same posture as
// internal/cache.Cache.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS decisions (
	decision_id TEXT PRIMARY KEY,
	timestamp   INTEGER NOT NULL,
	hook_name   TEXT NOT NULL,
	provider    TEXT NOT NULL DEFAULT '',
	indicator   TEXT NOT NULL DEFAULT '',
	kind        TEXT NOT NULL DEFAULT '',
	label       TEXT NOT NULL DEFAULT '',
	allow       INTEGER NOT NULL,
	mode        TEXT NOT NULL DEFAULT 'enforce',
	reason      TEXT NOT NULL DEFAULT '',
	duration_ms INTEGER NOT NULL DEFAULT 0,
	hosts_json     TEXT NOT NULL DEFAULT '[]',
	warnings_json  TEXT NOT NULL DEFAULT '[]',
	atr_rules_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS decisions_timestamp_idx ON decisions(timestamp);
CREATE INDEX IF NOT EXISTS decisions_indicator_idx ON decisions(indicator);
`

// Open returns a Store backed by the file at path, creating the schema if
// necessary. Mirrors internal/cache.Open's connection settings.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: mkdir: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?_journal=wal&_busy_timeout=50&_synchronous=NORMAL", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: open: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: schema: %w", err)
	}
	// Defense-in-depth: tighten the db file and its WAL/SHM sidecars to
	// 0600 in case a permissive umask left them group/world-readable
	// (the parent dir is already 0700). Mirrors internal/cache.Open.
	// Failures are non-fatal (sidecars may not exist yet; audit storage is
	// an operability aid, never a correctness primitive).
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, statErr := os.Stat(p); statErr == nil {
			_ = os.Chmod(p, 0o600)
		}
	}
	return &Store{db: db}, nil
}

// OpenOrWarn mirrors internal/cache.OpenOrWarn's fail-open policy: audit
// storage is an operability aid, not a correctness primitive, so a
// failure to open it must never affect a verdict. Returns nil (safe to
// pass to every function in this package, all of which treat a nil
// receiver as a no-op) on failure.
func OpenOrWarn(path string, w io.Writer) *Store {
	s, err := Open(path)
	if err != nil {
		if w != nil {
			fmt.Fprintf(w, "trustgate: audit store disabled (%s): %v\n", path, err)
		}
		return nil
	}
	return s
}

// Close releases the database handle. Safe to call on a nil *Store.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Record is one row of the audit table — the structured counterpart to
// the JSON-Lines decision log entry internal/verdict.writeLog produces.
type Record struct {
	DecisionID string
	Timestamp  time.Time
	HookName   string
	Provider   string
	Indicator  string
	Kind       string
	Label      string
	Allow      bool
	Mode       string
	Reason     string
	DurationMs int64
	Hosts      []string
	Warnings   []string
	// ATRRuleIDs carries rule IDENTITIES only (e.g. "ATR-2026-00121"),
	// never the matched snippet or description — see the package doc
	// comment's redaction contract.
	ATRRuleIDs []string
}

// Insert writes one record. Safe to call on a nil *Store (no-op) so
// callers don't need to nil-check before every call, matching
// internal/cache.Cache's pattern.
func (s *Store) Insert(ctx context.Context, r Record) error {
	if s == nil || s.db == nil {
		return nil
	}
	hostsJSON, err := marshalOrEmpty(r.Hosts)
	if err != nil {
		return fmt.Errorf("audit: marshal hosts: %w", err)
	}
	warningsJSON, err := marshalOrEmpty(r.Warnings)
	if err != nil {
		return fmt.Errorf("audit: marshal warnings: %w", err)
	}
	atrJSON, err := marshalOrEmpty(r.ATRRuleIDs)
	if err != nil {
		return fmt.Errorf("audit: marshal atr rule ids: %w", err)
	}
	ts := r.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO decisions(decision_id, timestamp, hook_name, provider, indicator, kind, label, allow, mode, reason, duration_ms, hosts_json, warnings_json, atr_rules_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(decision_id) DO NOTHING`,
		r.DecisionID, ts.Unix(), r.HookName, r.Provider, r.Indicator, r.Kind, r.Label,
		boolToInt(r.Allow), nonEmptyOr(r.Mode, "enforce"), r.Reason, r.DurationMs,
		hostsJSON, warningsJSON, atrJSON,
	)
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	return nil
}

// FindByDecisionID returns the record with the given decision_id, or
// (nil, nil) if no such record exists.
func (s *Store) FindByDecisionID(ctx context.Context, id string) (*Record, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT decision_id, timestamp, hook_name, provider, indicator, kind, label, allow, mode, reason, duration_ms, hosts_json, warnings_json, atr_rules_json
		 FROM decisions WHERE decision_id = ?`, id)
	return scanRecord(row)
}

// FindByIndicator returns up to limit most-recent records mentioning
// indicator, newest first. Matches both the resolved Indicator field
// (set when the cascade reached a per-indicator verdict) and any entry
// in the original Hosts list (set even for allow-with-no-flagged-host
// decisions), so "explain example.com" finds it either way.
func (s *Store) FindByIndicator(ctx context.Context, indicator string, limit int) ([]Record, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT decision_id, timestamp, hook_name, provider, indicator, kind, label, allow, mode, reason, duration_ms, hosts_json, warnings_json, atr_rules_json
		 FROM decisions WHERE indicator = ? OR hosts_json LIKE ?
		 ORDER BY timestamp DESC LIMIT ?`,
		indicator, "%\""+indicator+"\"%", limit)
	if err != nil {
		return nil, fmt.Errorf("audit: find by indicator: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		if r != nil {
			out = append(out, *r)
		}
	}
	return out, rows.Err()
}

// Stats summarizes the audit table for `trustgate doctor`.
type Stats struct {
	Total   int
	Denied  int
	Oldest  time.Time
	Newest  time.Time
	HasData bool
}

// Stats returns aggregate counts over the whole table. Cheap (a single
// indexed query) even for a large table.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	if s == nil || s.db == nil {
		return Stats{}, nil
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(1 - allow), 0), COALESCE(MIN(timestamp), 0), COALESCE(MAX(timestamp), 0) FROM decisions`)
	var total, denied int
	var oldestUnix, newestUnix int64
	if err := row.Scan(&total, &denied, &oldestUnix, &newestUnix); err != nil {
		return Stats{}, fmt.Errorf("audit: stats: %w", err)
	}
	st := Stats{Total: total, Denied: denied, HasData: total > 0}
	if total > 0 {
		st.Oldest = time.Unix(oldestUnix, 0)
		st.Newest = time.Unix(newestUnix, 0)
	}
	return st, nil
}

// PurgeOlderThan deletes every decision recorded strictly before cutoff
// and returns the number of rows removed (PRIV-003 retention). Safe on a
// nil *Store (no-op, 0).
func (s *Store) PurgeOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM decisions WHERE timestamp < ?`, cutoff.Unix())
	if err != nil {
		return 0, fmt.Errorf("audit: purge: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// PurgeAll deletes every decision row and returns the number removed
// (PRIV-003 "delete everything" path). Safe on a nil *Store.
func (s *Store) PurgeAll(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM decisions`)
	if err != nil {
		return 0, fmt.Errorf("audit: purge all: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ExportAll streams every decision, oldest first, into out as one JSON
// object per line (JSON Lines) — the portable export format for PRIV-003's
// data-subject/export request. Safe on a nil *Store (writes nothing). The
// same redaction contract applies as everywhere else in this package: only
// indicators, verdicts, and ATR rule identities are present, never raw
// command/file/prompt bodies.
func (s *Store) ExportAll(ctx context.Context, out io.Writer) error {
	if s == nil || s.db == nil {
		return nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT decision_id, timestamp, hook_name, provider, indicator, kind, label, allow, mode, reason, duration_ms, hosts_json, warnings_json, atr_rules_json
		 FROM decisions ORDER BY timestamp ASC`)
	if err != nil {
		return fmt.Errorf("audit: export: %w", err)
	}
	defer func() { _ = rows.Close() }()
	enc := json.NewEncoder(out)
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return err
		}
		if r == nil {
			continue
		}
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("audit: export encode: %w", err)
		}
	}
	return rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRecord(row rowScanner) (*Record, error) {
	var r Record
	var ts int64
	var allowInt int
	var hostsJSON, warningsJSON, atrJSON string
	err := row.Scan(&r.DecisionID, &ts, &r.HookName, &r.Provider, &r.Indicator, &r.Kind, &r.Label,
		&allowInt, &r.Mode, &r.Reason, &r.DurationMs, &hostsJSON, &warningsJSON, &atrJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: scan: %w", err)
	}
	r.Timestamp = time.Unix(ts, 0)
	r.Allow = allowInt != 0
	r.Hosts = unmarshalOrNil(hostsJSON)
	r.Warnings = unmarshalOrNil(warningsJSON)
	r.ATRRuleIDs = unmarshalOrNil(atrJSON)
	return &r, nil
}

func marshalOrEmpty(v []string) (string, error) {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshalOrNil(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nonEmptyOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
