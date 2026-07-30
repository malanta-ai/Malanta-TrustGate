package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/audit"
	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
)

func runExplain(args []string) error {
	if len(args) != 1 || args[0] == "" {
		return errors.New("usage: trustgate explain <decision_id|indicator>")
	}
	query := args[0]

	// LoadWithEnvFiles (not bare Load) so `explain` reads the SAME
	// CacheDir/audit.db the hook binaries write to — the env-file chain
	// (/etc/trustgate/env, ~/.config/trustgate/env) can relocate CacheDir,
	// and bare Load() would silently query the default-path DB instead,
	// reporting "not found" for decisions that are really in the
	// configured store (OPS-003). Matches doctor/override/setup.
	cfg, err := config.LoadWithEnvFiles()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	auditDBPath := filepath.Join(cfg.CacheDir, "audit.db")
	store, err := audit.Open(auditDBPath)
	if err != nil {
		return fmt.Errorf("open audit table (%s): %w", auditDBPath, err)
	}
	defer func() { _ = store.Close() }()

	return explainQuery(context.Background(), os.Stdout, store, query, auditDBPath)
}

// explainQuery is runExplain's testable core: given an already-open
// Store, look up query as a decision_id first, then fall back to an
// indicator search. Split out from runExplain so tests can pass an
// in-memory-backed Store instead of exercising config.Load/os.Stdout.
func explainQuery(ctx context.Context, w io.Writer, store *audit.Store, query, auditDBPath string) error {
	if rec, err := store.FindByDecisionID(ctx, query); err != nil {
		return fmt.Errorf("look up decision_id %q: %w", query, err)
	} else if rec != nil {
		printRecord(w, *rec)
		return nil
	}

	recs, err := store.FindByIndicator(ctx, query, 20)
	if err != nil {
		return fmt.Errorf("look up indicator %q: %w", query, err)
	}
	if len(recs) == 0 {
		fmt.Fprintf(w, "No decision found for %q in %s.\n", query, auditDBPath)
		fmt.Fprintln(w, "(the audit table only has data for hooks that ran since it was introduced — an older decision may only exist in the JSON-Lines decisions.log)")
		return nil
	}
	fmt.Fprintf(w, "%d decision(s) mentioning %q (newest first):\n\n", len(recs), query)
	for i, rec := range recs {
		if i > 0 {
			fmt.Fprintln(w, strings.Repeat("-", 40))
		}
		printRecord(w, rec)
	}
	return nil
}

func printRecord(w io.Writer, r audit.Record) {
	fmt.Fprintf(w, "decision_id:  %s\n", r.DecisionID)
	fmt.Fprintf(w, "timestamp:    %s\n", r.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(w, "hook:         %s\n", r.HookName)
	fmt.Fprintf(w, "allow:        %v\n", r.Allow)
	fmt.Fprintf(w, "mode:         %s\n", r.Mode)
	if r.Provider != "" {
		fmt.Fprintf(w, "provider:     %s\n", r.Provider)
	}
	if r.Indicator != "" {
		fmt.Fprintf(w, "indicator:    %s (%s)\n", r.Indicator, r.Kind)
	}
	if r.Label != "" {
		fmt.Fprintf(w, "label:        %s\n", r.Label)
	}
	if r.Reason != "" {
		fmt.Fprintf(w, "reason:       %s\n", r.Reason)
	}
	if len(r.Hosts) > 0 {
		fmt.Fprintf(w, "hosts:        %v\n", r.Hosts)
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintf(w, "warnings:     %v\n", r.Warnings)
	}
	if len(r.ATRRuleIDs) > 0 {
		fmt.Fprintf(w, "atr rules:    %v\n", r.ATRRuleIDs)
	}
	fmt.Fprintf(w, "duration_ms:  %d\n", r.DurationMs)
}
