package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/audit"
	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
)

// runPurge implements `trustgate purge` — the PRIV-003 retention/deletion
// workflow. It removes local audit data (the SQLite audit table and,
// optionally, the JSON Lines decision log) either older than a retention
// window or in its entirety. Retention is intentionally NOT enforced on the
// hook hot path (that would add latency to every action); this command is
// what an operator runs manually or from cron to apply the policy.
func runPurge(args []string) error {
	fs := flag.NewFlagSet("purge", flag.ContinueOnError)
	days := fs.Int("days", -1, "delete audit data older than N days (default: TRUSTGATE_RETENTION_DAYS)")
	all := fs.Bool("all", false, "delete ALL local audit data (ignores --days)")
	includeLog := fs.Bool("include-log", true, "also purge the JSON Lines decision log")
	yes := fs.Bool("yes", false, "skip the interactive confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadWithEnvFiles()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	var cutoff time.Time
	if !*all {
		d := *days
		if d < 0 {
			d = cfg.RetentionDays
		}
		if d <= 0 {
			return fmt.Errorf("no retention window: pass --days N, --all, or set TRUSTGATE_RETENTION_DAYS")
		}
		cutoff = time.Now().AddDate(0, 0, -d)
	}

	if !*yes {
		target := "records older than " + cutoff.Format(time.RFC3339)
		if *all {
			target = "ALL local audit data"
		}
		fmt.Fprintf(os.Stderr, "About to purge %s under %s. Continue? [y/N]: ", target, cfg.CacheDir)
		var resp string
		_, _ = fmt.Fscanln(os.Stdin, &resp)
		if !strings.EqualFold(strings.TrimSpace(resp), "y") {
			fmt.Println("aborted")
			return nil
		}
	}

	store, err := audit.Open(filepath.Join(cfg.CacheDir, "audit.db"))
	if err != nil {
		return fmt.Errorf("open audit table: %w", err)
	}
	defer func() { _ = store.Close() }()

	var n int64
	if *all {
		n, err = store.PurgeAll(context.Background())
	} else {
		n, err = store.PurgeOlderThan(context.Background(), cutoff)
	}
	if err != nil {
		return err
	}
	fmt.Printf("Purged %d audit record(s).\n", n)

	if *includeLog {
		logPath := cfg.LogPath
		if logPath == "" {
			logPath = filepath.Join(cfg.CacheDir, "decisions.log")
		}
		removed, err := purgeDecisionLog(logPath, *all, cutoff)
		if err != nil {
			return fmt.Errorf("purge decision log: %w", err)
		}
		fmt.Printf("Removed %d decision-log line(s) from %s.\n", removed, logPath)
	}
	return nil
}

// purgeDecisionLog removes JSON Lines decision-log entries. With all=true it
// deletes the whole file. Otherwise it rewrites the file keeping only lines
// whose timestamp is at or after cutoff, via a temp file + atomic rename so
// a crash mid-purge can't corrupt or partially truncate the log. Returns the
// number of lines removed. A malformed line (unparseable timestamp) is KEPT
// (fail-safe: never silently drop a record we couldn't classify).
func purgeDecisionLog(path string, all bool, cutoff time.Time) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer func() { _ = f.Close() }()

	if all {
		// Count for reporting, then truncate.
		removed := 0
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) != "" {
				removed++
			}
		}
		_ = f.Close()
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return 0, err
		}
		return removed, nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".decisions-purge-*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }

	removed := 0
	w := bufio.NewWriter(tmp)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if purgeShouldKeep(line, cutoff) {
			if _, err := w.WriteString(line + "\n"); err != nil {
				cleanup()
				return 0, err
			}
		} else {
			removed++
		}
	}
	if err := sc.Err(); err != nil {
		cleanup()
		return 0, err
	}
	if err := w.Flush(); err != nil {
		cleanup()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return 0, err
	}
	// Release the source handle before replacing it. Windows refuses to
	// rename over a file that is still open (Go opens without
	// FILE_SHARE_DELETE), which made every `trustgate purge --days N` fail
	// there with "Access is denied"; the delete path above closes for the
	// same reason. The deferred Close stays as the error-path safety net and
	// is a harmless no-op once this succeeds.
	_ = f.Close()
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return 0, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return 0, err
	}
	return removed, nil
}

// purgeShouldKeep reports whether a decision-log line should survive a
// time-based purge. Keeps the line if its timestamp is missing/unparseable
// (fail-safe) or at/after cutoff.
func purgeShouldKeep(line string, cutoff time.Time) bool {
	var rec struct {
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.Timestamp == "" {
		return true
	}
	ts, err := time.Parse(time.RFC3339Nano, rec.Timestamp)
	if err != nil {
		return true
	}
	return !ts.Before(cutoff)
}
