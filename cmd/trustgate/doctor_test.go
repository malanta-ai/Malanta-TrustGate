package main

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/override"
	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

func TestGatherDiagnostics_ReportsConfigError(t *testing.T) {
	cfg := config.Defaults()
	d := gatherDiagnostics(cfg, errUsageForTest("config: mode: unknown value"))
	if d.ConfigError == "" {
		t.Error("expected ConfigError to be populated")
	}
}

func TestGatherDiagnostics_EnvFilesReflectFilesystem(t *testing.T) {
	dir := t.TempDir()
	setTestHome(t, dir)
	cfg := config.Defaults()
	cfg.CacheDir = dir

	d := gatherDiagnostics(cfg, nil)
	if len(d.EnvFiles) != 3 {
		t.Fatalf("expected 3 env file entries, got %d: %+v", len(d.EnvFiles), d.EnvFiles)
	}
	for _, f := range d.EnvFiles {
		if f.Exists {
			t.Errorf("expected %s to not exist in a fresh temp HOME, got Exists=true", f.Path)
		}
	}
}

func TestGatherDiagnostics_CacheAndAuditOpenSucceedInFreshDir(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.CacheDir = dir

	d := gatherDiagnostics(cfg, nil)
	if d.CacheOpenError != "" {
		t.Errorf("expected cache to open cleanly in a fresh dir, got: %s", d.CacheOpenError)
	}
	if d.AuditOpenError != "" {
		t.Errorf("expected audit table to open cleanly in a fresh dir, got: %s", d.AuditOpenError)
	}
	if d.CacheDBPath != filepath.Join(dir, "lookups.db") {
		t.Errorf("unexpected CacheDBPath: %s", d.CacheDBPath)
	}
	if d.AuditDBPath != filepath.Join(dir, "audit.db") {
		t.Errorf("unexpected AuditDBPath: %s", d.AuditDBPath)
	}
}

func TestPrintDiagnostics_DoesNotPanicAndMentionsKeyFields(t *testing.T) {
	cfg := config.Defaults()
	cfg.CacheDir = t.TempDir()
	d := gatherDiagnostics(cfg, nil)

	var buf bytes.Buffer
	printDiagnostics(&buf, d)
	out := buf.String()
	for _, want := range []string{"trustgate doctor", "provider:", "fail_closed:", "mode:", "Lookup cache:", "Audit table:", "Cursor hooks manifest:"} {
		if !bytesContains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestGatherDiagnostics_ReportsUnconfiguredState(t *testing.T) {
	cfg := config.Defaults()
	cfg.CacheDir = t.TempDir()
	cfg.APIKey = ""

	d := gatherDiagnostics(cfg, nil)
	if !d.Unconfigured {
		t.Error("expected Unconfigured=true when no API key is set")
	}

	var buf bytes.Buffer
	printDiagnostics(&buf, d)
	if !bytesContains(buf.String(), "UNCONFIGURED") {
		t.Errorf("expected the report to call out the unconfigured state, got:\n%s", buf.String())
	}
}

func TestGatherDiagnostics_ConfiguredStateHasNoWarning(t *testing.T) {
	cfg := config.Defaults()
	cfg.CacheDir = t.TempDir()
	cfg.APIKey = "some-key"

	d := gatherDiagnostics(cfg, nil)
	if d.Unconfigured {
		t.Error("expected Unconfigured=false once an API key is set")
	}
	var buf bytes.Buffer
	printDiagnostics(&buf, d)
	if bytesContains(buf.String(), "UNCONFIGURED") {
		t.Errorf("expected no unconfigured warning once an API key is set, got:\n%s", buf.String())
	}
}

func TestPrintDiagnostics_OmitsOverrideDetailWhenDisabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.CacheDir = t.TempDir()
	cfg.AllowUserOverride = false
	// The default mode is now warn, which legitimately shows override
	// detail (warn uses the same grant machinery). Pin enforce so this
	// test exercises the fully-disabled case (not warn, not allowed).
	cfg.Mode = config.ModeEnforce

	d := gatherDiagnostics(cfg, nil)
	var buf bytes.Buffer
	printDiagnostics(&buf, d)
	if bytesContains(buf.String(), "override_scope:") {
		t.Errorf("expected override detail to be omitted when AllowUserOverride is false, got:\n%s", buf.String())
	}
}

func TestPrintDiagnostics_ShowsActiveOverridesWhenEnabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.CacheDir = t.TempDir()
	cfg.AllowUserOverride = true
	if err := override.Grant(cfg.CacheDir, "malicious.example", time.Now().Add(10*time.Minute), "investigating", "cli"); err != nil {
		t.Fatal(err)
	}

	d := gatherDiagnostics(cfg, nil)
	var buf bytes.Buffer
	printDiagnostics(&buf, d)
	out := buf.String()
	for _, want := range []string{"override_scope:", "override_window_min:", "malicious.example", "investigating"} {
		if !bytesContains(out, want) {
			t.Errorf("expected doctor output to mention %q, got:\n%s", want, out)
		}
	}
}

func TestPrintDiagnostics_ShowsOverrideDetailUnderWarnModeWithoutAllowUserOverride(t *testing.T) {
	cfg := config.Defaults()
	cfg.CacheDir = t.TempDir()
	cfg.Mode = config.ModeWarn
	cfg.AllowUserOverride = false // warn mode doesn't require this

	d := gatherDiagnostics(cfg, nil)
	var buf bytes.Buffer
	printDiagnostics(&buf, d)
	out := buf.String()
	for _, want := range []string{"mode:", "warn", "override_scope:", "override_window_min:"} {
		if !bytesContains(out, want) {
			t.Errorf("expected doctor output to mention %q under warn mode, got:\n%s", want, out)
		}
	}
}

// TestIsScoreOnlyProvider covers the N2 doctor note's detection logic: a
// generic provider whose configured endpoint(s) all leave verdict_path
// empty (VirusTotal is the canonical case) is score-only; Malanta never
// is; a generic config that DOES map a verdict_path for at least one
// endpoint is not score-only either.
func TestIsScoreOnlyProvider(t *testing.T) {
	malanta := config.Defaults()
	if isScoreOnlyProvider(malanta) {
		t.Error("Malanta must never be reported as score-only")
	}

	scoreOnly := config.Defaults()
	scoreOnly.Provider = "generic"
	scoreOnly.Generic = &reputation.GenericProviderConfig{
		Domain: &reputation.GenericEndpoint{PathTemplate: "/domains/{value}"},
	}
	if !isScoreOnlyProvider(scoreOnly) {
		t.Error("expected a generic provider with no verdict_path to be reported as score-only")
	}

	named := config.Defaults()
	named.Provider = "generic"
	named.Generic = &reputation.GenericProviderConfig{
		Domain: &reputation.GenericEndpoint{
			PathTemplate: "/domains/{value}",
			Mapping:      reputation.GenericResponseMapping{VerdictPath: "verdict"},
		},
	}
	if isScoreOnlyProvider(named) {
		t.Error("expected a generic provider with a mapped verdict_path to NOT be reported as score-only")
	}
}

func TestPrintDiagnostics_ShowsScoreOnlyNoteForScoreOnlyProvider(t *testing.T) {
	cfg := config.Defaults()
	cfg.CacheDir = t.TempDir()
	cfg.Provider = "generic"
	cfg.Generic = &reputation.GenericProviderConfig{
		Name:   "virustotal",
		Domain: &reputation.GenericEndpoint{PathTemplate: "/domains/{value}"},
	}

	d := gatherDiagnostics(cfg, nil)
	if !d.ProviderIsScoreOnly {
		t.Fatal("expected ProviderIsScoreOnly=true for a verdict_path-less generic config")
	}
	var buf bytes.Buffer
	printDiagnostics(&buf, d)
	if !bytesContains(buf.String(), "score-only") {
		t.Errorf("expected the doctor report to call out the score-only provider, got:\n%s", buf.String())
	}
}

func TestPrintDiagnostics_UsesMinMaliciousScoreLabel(t *testing.T) {
	cfg := config.Defaults()
	cfg.CacheDir = t.TempDir()
	cfg.MinMaliciousScoreToBlock = 3

	d := gatherDiagnostics(cfg, nil)
	var buf bytes.Buffer
	printDiagnostics(&buf, d)
	out := buf.String()
	if !bytesContains(out, "min_malicious_score:") {
		t.Errorf("expected the min_malicious_score label, got:\n%s", out)
	}
	if bytesContains(out, "min_probability:") {
		t.Errorf("expected the old min_probability label to be gone, got:\n%s", out)
	}
}

func TestPrintDiagnostics_ShowsBatchSizeForMalantaOnly(t *testing.T) {
	malanta := config.Defaults()
	malanta.CacheDir = t.TempDir()
	var buf bytes.Buffer
	printDiagnostics(&buf, gatherDiagnostics(malanta, nil))
	if !bytesContains(buf.String(), "batch_size:") {
		t.Errorf("expected batch_size to be shown for the Malanta provider, got:\n%s", buf.String())
	}

	generic := config.Defaults()
	generic.CacheDir = t.TempDir()
	generic.Provider = "generic"
	generic.Generic = &reputation.GenericProviderConfig{
		Domain: &reputation.GenericEndpoint{PathTemplate: "/domains/{value}"},
	}
	buf.Reset()
	printDiagnostics(&buf, gatherDiagnostics(generic, nil))
	if bytesContains(buf.String(), "batch_size:") {
		t.Errorf("expected batch_size to be omitted for a non-Malanta provider, got:\n%s", buf.String())
	}
}

func TestPrintDiagnostics_ProviderMaxConcurrency(t *testing.T) {
	unset := config.Defaults()
	unset.CacheDir = t.TempDir()
	var buf bytes.Buffer
	printDiagnostics(&buf, gatherDiagnostics(unset, nil))
	if !bytesContains(buf.String(), "unset; each provider keeps its own default") {
		t.Errorf("expected the unset-override note, got:\n%s", buf.String())
	}

	override := config.Defaults()
	override.CacheDir = t.TempDir()
	override.ProviderMaxConcurrency = 8
	buf.Reset()
	printDiagnostics(&buf, gatherDiagnostics(override, nil))
	if !bytesContains(buf.String(), "provider_max_concurrency: 8 (override)") {
		t.Errorf("expected the concurrency override to be shown, got:\n%s", buf.String())
	}
}

func bytesContains(s, sub string) bool {
	return len(sub) == 0 || indexOfString(s, sub) >= 0
}

func indexOfString(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

type errUsageForTest string

func (e errUsageForTest) Error() string { return string(e) }
