package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults_Sane(t *testing.T) {
	c := Defaults()
	if c.APIBaseURL == "" {
		t.Error("missing default base URL")
	}
	if !c.FailClosed {
		t.Error("expected FailClosed default to be true")
	}
	if c.MinMaliciousScoreToBlock <= 0 || c.MinMaliciousScoreToBlock > 1 {
		t.Errorf("MinMaliciousScoreToBlock=%v out of (0,1]", c.MinMaliciousScoreToBlock)
	}
	if len(c.BlockLabels) == 0 {
		t.Error("missing default block label set")
	}
	// Malanta's current reputation API only returns MALICIOUS for a
	// flagged domain (see Defaults' doc comment) — the prior API's
	// speculative SUSPICIOUS category is no longer part of the default.
	if len(c.BlockLabels) != 1 || c.BlockLabels[0] != "MALICIOUS" {
		t.Errorf("expected default BlockLabels=[MALICIOUS], got %v", c.BlockLabels)
	}
	if c.APIBatchSize < 1 || c.APIBatchSize > 100 {
		t.Errorf("APIBatchSize=%v out of 1-100", c.APIBatchSize)
	}
	if c.ProviderMaxConcurrency != 0 {
		t.Errorf("expected default ProviderMaxConcurrency=0 (no override), got %v", c.ProviderMaxConcurrency)
	}
	// AllowLabels is intentionally empty by default: reputation is a
	// deny-list model, so an unrecognized/UNKNOWN verdict already allows
	// without needing an explicit allow entry (see BlockLabels' doc
	// comment and internal/verdict's cascade).
	if len(c.AllowLabels) != 0 {
		t.Errorf("expected empty default AllowLabels, got %v", c.AllowLabels)
	}
	if c.Provider != "malanta" {
		t.Errorf("expected default Provider=malanta, got %q", c.Provider)
	}
}

func TestLabelSet_CaseInsensitive(t *testing.T) {
	s := NewLabelSet([]string{"Malicious", "Suspicius"})
	for _, q := range []string{"malicious", "MALICIOUS", " suspicius "} {
		if !s.Has(q) {
			t.Errorf("expected match for %q", q)
		}
	}
	if s.Has("legit") {
		t.Errorf("unexpected match for legit")
	}
}

func TestLoad_EnvWins(t *testing.T) {
	t.Setenv("MALANTA_API_KEY", "from-env")
	t.Setenv("MALANTA_API_TIMEOUT_MS", "750")
	t.Setenv("TRUSTGATE_FAIL_CLOSED", "false")
	t.Setenv("TRUSTGATE_BLOCK_LABELS", "Foo, Bar")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.APIKey != "from-env" {
		t.Errorf("APIKey: got %q want from-env", c.APIKey)
	}
	if c.APITimeoutMs != 750 {
		t.Errorf("APITimeoutMs: got %d want 750", c.APITimeoutMs)
	}
	if c.FailClosed {
		t.Errorf("expected FailClosed=false from env")
	}
	if len(c.BlockLabels) != 2 || c.BlockLabels[0] != "Foo" || c.BlockLabels[1] != "Bar" {
		t.Errorf("BlockLabels: %#v", c.BlockLabels)
	}
}

func TestLoad_FileThenEnv(t *testing.T) {
	tmpHome := t.TempDir()
	setTestHome(t, tmpHome)
	cfgDir := filepath.Join(tmpHome, ".config", "trustgate")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Deliberately still uses the pre-rename JSON key (min_probability_to_block)
	// and env var (TRUSTGATE_MIN_PROBABILITY) — this test doubles as the
	// back-compat regression guard for both.
	cfg := `{"api_timeout_ms":111,"min_probability_to_block":0.7}`
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRUSTGATE_MIN_PROBABILITY", "0.42")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.APITimeoutMs != 111 {
		t.Errorf("expected file value APITimeoutMs=111, got %d", c.APITimeoutMs)
	}
	if c.MinMaliciousScoreToBlock != 0.42 {
		t.Errorf("expected env to win for MinMaliciousScoreToBlock, got %v", c.MinMaliciousScoreToBlock)
	}
}

// TestLoad_MinMaliciousScore_JSONKeyBackCompat covers config.json alone
// (no env involved): the legacy min_probability_to_block key must still
// populate MinMaliciousScoreToBlock when the new key is absent.
func TestLoad_MinMaliciousScore_JSONKeyBackCompat(t *testing.T) {
	tmpHome := t.TempDir()
	setTestHome(t, tmpHome)
	cfgDir := filepath.Join(tmpHome, ".config", "trustgate")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(`{"min_probability_to_block":0.65}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.MinMaliciousScoreToBlock != 0.65 {
		t.Errorf("expected legacy JSON key to populate MinMaliciousScoreToBlock, got %v", c.MinMaliciousScoreToBlock)
	}
}

// TestLoad_MinMaliciousScore_NewJSONKeyWinsOverOld covers a config.json
// that (unusually) sets BOTH keys: the new name must win, per the
// documented back-compat contract (Config.MinMaliciousScoreToBlock's doc
// comment).
func TestLoad_MinMaliciousScore_NewJSONKeyWinsOverOld(t *testing.T) {
	tmpHome := t.TempDir()
	setTestHome(t, tmpHome)
	cfgDir := filepath.Join(tmpHome, ".config", "trustgate")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := `{"min_probability_to_block":0.1,"min_malicious_score_to_block":0.9}`
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.MinMaliciousScoreToBlock != 0.9 {
		t.Errorf("expected the new JSON key to win when both are set, got %v", c.MinMaliciousScoreToBlock)
	}
}

// TestLoad_MinMaliciousScore_NewEnvWinsOverOldEnv covers both env vars set
// at once: TRUSTGATE_MIN_MALICIOUS_SCORE must win over the legacy
// TRUSTGATE_MIN_PROBABILITY, matching the JSON-key precedence above.
func TestLoad_MinMaliciousScore_NewEnvWinsOverOldEnv(t *testing.T) {
	t.Setenv("TRUSTGATE_MIN_PROBABILITY", "0.1")
	t.Setenv("TRUSTGATE_MIN_MALICIOUS_SCORE", "0.8")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.MinMaliciousScoreToBlock != 0.8 {
		t.Errorf("expected the new env var to win when both are set, got %v", c.MinMaliciousScoreToBlock)
	}
}

// TestLoad_BatchSize_ValidatedRange covers Config.APIBatchSize / the
// MALANTA_API_BATCH_SIZE env var: an in-range value is accepted, and a
// value outside Malanta's documented 1-100 per-request limit is a
// fail-closed config error at Load (see validateBatchSize).
func TestLoad_BatchSize_ValidatedRange(t *testing.T) {
	t.Setenv("MALANTA_API_BATCH_SIZE", "50")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.APIBatchSize != 50 {
		t.Errorf("expected APIBatchSize=50, got %d", c.APIBatchSize)
	}

	t.Setenv("MALANTA_API_BATCH_SIZE", "101")
	if _, err := Load(); err == nil {
		t.Error("expected a config error for a batch size above 100")
	}
}

// TestLoad_ProviderMaxConcurrency_EnvOverride covers
// TRUSTGATE_PROVIDER_MAX_CONCURRENCY: unset means "no override" (0, the
// default — see Defaults' doc comment); a positive value is accepted.
func TestLoad_ProviderMaxConcurrency_EnvOverride(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ProviderMaxConcurrency != 0 {
		t.Errorf("expected default ProviderMaxConcurrency=0, got %v", c.ProviderMaxConcurrency)
	}

	t.Setenv("TRUSTGATE_PROVIDER_MAX_CONCURRENCY", "8")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ProviderMaxConcurrency != 8 {
		t.Errorf("expected ProviderMaxConcurrency=8, got %v", c.ProviderMaxConcurrency)
	}
}
