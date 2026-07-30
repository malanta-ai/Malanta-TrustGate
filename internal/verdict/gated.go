package verdict

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WriteGatedLog appends a single JSON Lines audit entry for the case where
// the hook's caller decided to short-circuit the verdict cascade based on a
// local gate (e.g. "the prompt mentions a domain but doesn't instruct me to
// access it"). The cascade itself isn't invoked - no cache lookup, no API
// call, no Malanta consultation - but the audit trail must still record
// WHAT the hook saw and WHY it skipped the cascade, otherwise the gate is
// invisible to anyone debugging a "why didn't this get blocked?" question
// after the fact.
//
// The shape mirrors writeLog's record exactly so log consumers can stay
// schema-stable; the only difference is the embedded Decision's `reason`
// carries the gate description and a new `gated` boolean is set true.
//
// Usage from a cmd binary:
//
//	if len(seen) > 0 && !extract.HasActionVerb(text) {
//	    verdict.WriteGatedLog(cfg.LogPath, "beforeSubmitPrompt", seen,
//	        "verb-gate: prompt mentions domains without action intent")
//	    // ...then emit a default-allow Decision to stdout.
//	}
//
// Errors are surfaced on stderr (same convention as writeLog) so a broken
// log path doesn't change the verdict but also isn't silent.
func WriteGatedLog(path, hookName string, seen []string, reason string) {
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "trustgate: decision-log mkdir failed: %v\n", err)
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustgate: decision-log open failed: %v\n", err)
		return
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "trustgate: decision-log close failed: %v\n", cerr)
		}
	}()
	rec := struct {
		Timestamp string   `json:"timestamp"`
		Domains   []string `json:"domains"`
		Decision  struct {
			Allow    bool   `json:"allow"`
			Reason   string `json:"reason,omitempty"`
			HookName string `json:"hook,omitempty"`
			Gated    bool   `json:"gated"`
		} `json:"decision"`
	}{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Domains:   seen,
	}
	rec.Decision.Allow = true
	rec.Decision.Reason = reason
	rec.Decision.HookName = hookName
	rec.Decision.Gated = true

	if err := json.NewEncoder(f).Encode(rec); err != nil {
		fmt.Fprintf(os.Stderr, "trustgate: decision-log encode failed: %v\n", err)
	}
}
