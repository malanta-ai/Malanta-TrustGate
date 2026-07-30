package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/malanta-ai/Malanta-TrustGate/internal/audit"
	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
)

// runExport implements `trustgate export` — the PRIV-003 data-export
// workflow. It writes every locally-recorded decision as JSON Lines (one
// object per line), oldest first, to a file or stdout. The same redaction
// contract applies as everywhere else: only indicators, verdicts, and ATR
// rule identities are present — never raw command/file/prompt bodies.
func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	out := fs.String("out", "", "write the export to this file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadWithEnvFiles()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	store, err := audit.Open(filepath.Join(cfg.CacheDir, "audit.db"))
	if err != nil {
		return fmt.Errorf("open audit table: %w", err)
	}
	defer func() { _ = store.Close() }()

	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("open %s: %w", *out, err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := store.ExportAll(context.Background(), w); err != nil {
		return err
	}
	if *out != "" {
		fmt.Fprintf(os.Stderr, "Exported audit records to %s.\n", *out)
	}
	return nil
}
