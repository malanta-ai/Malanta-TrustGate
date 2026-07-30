package config

import "testing"

func TestCompareDottedVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"3.11.25", "3.11.25", 0},
		{"3.11.26", "3.11.25", 1},
		{"3.11.24", "3.11.25", -1},
		{"3.12.0", "3.11.25", 1},
		{"4.0.0", "3.11.25", 1},
		{"3.10.99", "3.11.0", -1},
		{"3.11", "3.11.0", 0},                 // missing trailing component == 0
		{"3.11.25 (Universal)", "3.11.25", 0}, // suffix ignored
		{"3.11.25-nightly", "3.11.25", 0},     // per-component suffix stripped
		{"", "3.11.25", -1},                   // empty parses as 0.0.0
	}
	for _, tc := range cases {
		if got := compareDottedVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareDottedVersions(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCursorHonorsAsk(t *testing.T) {
	base := Defaults()
	if base.AskMinCursorVersion != "3.11.25" {
		t.Fatalf("default AskMinCursorVersion = %q, want 3.11.25", base.AskMinCursorVersion)
	}
	cases := []struct {
		version string
		want    bool
	}{
		{"3.11.25", true},
		{"3.11.26", true},
		{"3.12.0", true},
		{"3.11.24", false},
		{"3.10.0", false},
		{"", false}, // unknown version must NOT honor ask (degrade to deny)
	}
	for _, tc := range cases {
		c := base
		c.CursorVersion = tc.version
		if got := c.CursorHonorsAsk(); got != tc.want {
			t.Errorf("CursorHonorsAsk() version=%q = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestAskMinCursorVersion_EnvOverride(t *testing.T) {
	t.Setenv("TRUSTGATE_ASK_MIN_CURSOR_VERSION", "4.0.0")
	c := Defaults()
	applyEnv(&c)
	if c.AskMinCursorVersion != "4.0.0" {
		t.Fatalf("AskMinCursorVersion = %q, want 4.0.0", c.AskMinCursorVersion)
	}
	c.CursorVersion = "3.11.25"
	if c.CursorHonorsAsk() {
		t.Errorf("with floor raised to 4.0.0, a 3.11.25 client must not honor ask")
	}
}
