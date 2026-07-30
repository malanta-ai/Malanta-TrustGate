package config

import "testing"

func TestDefaults_OverrideScopeIsDomain(t *testing.T) {
	c := Defaults()
	if c.OverrideScope != OverrideScopeDomain {
		t.Errorf("expected default OverrideScope=%q, got %q", OverrideScopeDomain, c.OverrideScope)
	}
}

func TestDefaults_OverrideWindowMinutesIsFifteen(t *testing.T) {
	c := Defaults()
	if c.OverrideWindowMinutes != 15 {
		t.Errorf("expected default OverrideWindowMinutes=15, got %d", c.OverrideWindowMinutes)
	}
}

func TestLoad_OverrideScopeEnvVar(t *testing.T) {
	t.Setenv("TRUSTGATE_OVERRIDE_SCOPE", "time")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.OverrideScope != OverrideScopeTime {
		t.Errorf("expected OverrideScope=%q, got %q", OverrideScopeTime, c.OverrideScope)
	}
}

func TestLoad_RejectsUnrecognizedOverrideScope(t *testing.T) {
	t.Setenv("TRUSTGATE_OVERRIDE_SCOPE", "domainn") // typo
	if _, err := Load(); err == nil {
		t.Fatal("expected an error for an unrecognized override_scope value")
	}
}

func TestLoad_OverrideWindowMinEnvVar(t *testing.T) {
	t.Setenv("TRUSTGATE_OVERRIDE_WINDOW_MIN", "30")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.OverrideWindowMinutes != 30 {
		t.Errorf("expected OverrideWindowMinutes=30, got %d", c.OverrideWindowMinutes)
	}
}

func TestLoad_OverrideWindowMinIgnoresNonPositive(t *testing.T) {
	t.Setenv("TRUSTGATE_OVERRIDE_WINDOW_MIN", "0")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.OverrideWindowMinutes != 15 {
		t.Errorf("expected a non-positive override to be ignored (default 15), got %d", c.OverrideWindowMinutes)
	}
}

func TestLockableKeys_IncludeNewOverrideKeys(t *testing.T) {
	for _, key := range []string{"TRUSTGATE_OVERRIDE_SCOPE", "TRUSTGATE_OVERRIDE_WINDOW_MIN", "TRUSTGATE_WARN_ACK_MIN_SECONDS"} {
		if !lockableKeys[key] {
			t.Errorf("expected %s to be lockable", key)
		}
	}
}

func TestDefaults_WarnAckMinSecondsIsFour(t *testing.T) {
	c := Defaults()
	if c.WarnAckMinSeconds != 4 {
		t.Errorf("expected default WarnAckMinSeconds=4, got %d", c.WarnAckMinSeconds)
	}
}

func TestLoad_WarnAckMinSecondsEnvVar(t *testing.T) {
	t.Setenv("TRUSTGATE_WARN_ACK_MIN_SECONDS", "10")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.WarnAckMinSeconds != 10 {
		t.Errorf("expected WarnAckMinSeconds=10, got %d", c.WarnAckMinSeconds)
	}
}

// TestLoad_RejectsNonFiniteMinScore is the finite-threshold guard:
// strconv.ParseFloat accepts NaN/Inf, and `score >= NaN` is always false,
// which would silently disable every reputation deny. Load must fail closed
// on such a value rather than adopt it.
func TestLoad_RejectsNonFiniteMinScore(t *testing.T) {
	for _, v := range []string{"NaN", "Inf", "+Inf", "-Inf"} {
		t.Setenv("TRUSTGATE_MIN_MALICIOUS_SCORE", v)
		if _, err := Load(); err == nil {
			t.Errorf("expected Load to reject TRUSTGATE_MIN_MALICIOUS_SCORE=%q, got no error", v)
		}
	}
}

func TestLoad_AcceptsFiniteMinScore(t *testing.T) {
	t.Setenv("TRUSTGATE_MIN_MALICIOUS_SCORE", "0.75")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.MinMaliciousScoreToBlock != 0.75 {
		t.Errorf("expected 0.75, got %v", c.MinMaliciousScoreToBlock)
	}
}

func TestLoad_WarnAckMinSecondsZeroDisablesGate(t *testing.T) {
	// Unlike OverrideWindowMinutes, a parsed 0 IS honored (explicit
	// disable), not treated as "unset, keep the default".
	t.Setenv("TRUSTGATE_WARN_ACK_MIN_SECONDS", "0")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.WarnAckMinSeconds != 0 {
		t.Errorf("expected an explicit 0 to be honored, got %d", c.WarnAckMinSeconds)
	}
}

func TestLoad_WarnAckMinSecondsIgnoresNegativeEnv(t *testing.T) {
	t.Setenv("TRUSTGATE_WARN_ACK_MIN_SECONDS", "-5")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.WarnAckMinSeconds != 4 {
		t.Errorf("expected a negative env value to be ignored (default 4), got %d", c.WarnAckMinSeconds)
	}
}

func TestValidateWarnAckMinSeconds(t *testing.T) {
	if err := validateWarnAckMinSeconds(0); err != nil {
		t.Errorf("expected 0 (disable) to be valid, got %v", err)
	}
	if err := validateWarnAckMinSeconds(4); err != nil {
		t.Errorf("expected a positive dwell to be valid, got %v", err)
	}
	if err := validateWarnAckMinSeconds(-1); err == nil {
		t.Error("expected a negative dwell to be rejected")
	}
}

func TestLoad_ModeWarnIsRecognized(t *testing.T) {
	t.Setenv("TRUSTGATE_MODE", "warn")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Mode != ModeWarn {
		t.Errorf("expected Mode=%q, got %q", ModeWarn, c.Mode)
	}
}
