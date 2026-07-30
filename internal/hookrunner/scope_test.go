package hookrunner

import (
	"os"
	"testing"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
)

func TestCheckScope_DefaultAllModeAlwaysInScope(t *testing.T) {
	cfg := config.Config{ScopeMode: config.ScopeAll, ScopePaths: []string{"/Users/me/work/*"}}
	inScope, reason := checkScope(cfg, []string{"/Users/me/personal/side-project"})
	if !inScope || reason != "" {
		t.Errorf("expected in-scope with no reason under mode=all, got inScope=%v reason=%q", inScope, reason)
	}
}

func TestCheckScope_NoScopePathsIsAlwaysInScope(t *testing.T) {
	cfg := config.Config{ScopeMode: config.ScopeAllowlist, ScopePaths: nil}
	inScope, _ := checkScope(cfg, []string{"/anywhere"})
	if !inScope {
		t.Error("expected in-scope when ScopePaths is empty regardless of mode")
	}
}

func TestCheckScope_NoWorkspaceRootsIsAlwaysInScope(t *testing.T) {
	cfg := config.Config{ScopeMode: config.ScopeAllowlist, ScopePaths: []string{"/Users/me/work/*"}}
	inScope, _ := checkScope(cfg, nil)
	if !inScope {
		t.Error("expected in-scope when the hook payload carries no workspace_roots info at all")
	}
}

func TestCheckScope_AllowlistMode(t *testing.T) {
	cfg := config.Config{ScopeMode: config.ScopeAllowlist, ScopePaths: []string{"/Users/me/work/*"}}

	inScope, _ := checkScope(cfg, []string{"/Users/me/work/project1"})
	if !inScope {
		t.Error("expected a workspace under an allowlisted glob to be in scope")
	}

	inScope, reason := checkScope(cfg, []string{"/Users/me/personal/side-project"})
	if inScope {
		t.Error("expected a workspace NOT matching the allowlist to be out of scope")
	}
	if reason == "" {
		t.Error("expected a non-empty reason for an out-of-scope decision")
	}
}

func TestCheckScope_DenylistMode(t *testing.T) {
	cfg := config.Config{ScopeMode: config.ScopeDenylist, ScopePaths: []string{"/Users/me/personal/*"}}

	inScope, _ := checkScope(cfg, []string{"/Users/me/work/project1"})
	if !inScope {
		t.Error("expected a workspace NOT matching the denylist to stay in scope")
	}

	inScope, reason := checkScope(cfg, []string{"/Users/me/personal/side-project"})
	if inScope {
		t.Error("expected a denylisted workspace to be out of scope")
	}
	if reason == "" {
		t.Error("expected a non-empty reason for an out-of-scope decision")
	}
}

func TestCheckScope_MultiRootWorkspaceMatchesIfAnyRootMatches(t *testing.T) {
	cfg := config.Config{ScopeMode: config.ScopeAllowlist, ScopePaths: []string{"/Users/me/work/*"}}
	inScope, _ := checkScope(cfg, []string{"/Users/me/personal/other", "/Users/me/work/project1"})
	if !inScope {
		t.Error("expected a multi-root workspace to be in scope if ANY root matches the allowlist")
	}
}

func TestGlobMatchesAny_ExactGlob(t *testing.T) {
	if !globMatchesAny("/Users/me/work/proj", []string{"/Users/me/work/*"}) {
		t.Error("expected filepath.Match-style glob to match a direct child")
	}
}

func TestGlobMatchesAny_DirectoryPrefixWithDoubleStarAndSubdirectory(t *testing.T) {
	// filepath.Match's "*" does not cross path separators, so a nested
	// subdirectory needs the directory-prefix special case, not plain
	// filepath.Match, to match "/Users/me/work/**".
	if !globMatchesAny("/Users/me/work/proj/sub/dir", []string{"/Users/me/work/**"}) {
		t.Error("expected a /** suffix pattern to match arbitrarily nested subdirectories")
	}
}

func TestGlobMatchesAny_SingleStarSuffixAlsoMatchesNested(t *testing.T) {
	if !globMatchesAny("/Users/me/work/proj/sub", []string{"/Users/me/work/*"}) {
		t.Error("expected a /* suffix pattern to also be treated as a directory-prefix match for nested paths")
	}
}

func TestGlobMatchesAny_NoMatch(t *testing.T) {
	if globMatchesAny("/Users/me/personal/proj", []string{"/Users/me/work/*"}) {
		t.Error("expected no match for an unrelated path")
	}
}

func TestCheckUnconfigured_NotApplicableWhenConfigured(t *testing.T) {
	cfg := config.Config{APIKey: "some-key"}
	_, ok := checkUnconfigured(cfg, []string{"malicious.example"})
	if ok {
		t.Error("expected checkUnconfigured to be inapplicable once an API key is set")
	}
}

func TestCheckUnconfigured_NotApplicableWhenNoDomains(t *testing.T) {
	cfg := config.Config{APIKey: ""}
	_, ok := checkUnconfigured(cfg, nil)
	if ok {
		t.Error("expected checkUnconfigured to be inapplicable when there's nothing to look up")
	}
}

func TestCheckUnconfigured_InertAllowByDefault(t *testing.T) {
	cfg := config.Config{APIKey: "", RequireConfigured: false, CacheDir: t.TempDir()}
	d, ok := checkUnconfigured(cfg, []string{"malicious.example"})
	if !ok {
		t.Fatal("expected checkUnconfigured to apply when unconfigured with domains present")
	}
	if !d.Allow {
		t.Error("expected an inert ALLOW by default (RequireConfigured=false)")
	}
	if d.Reason == "" {
		t.Error("expected a reason explaining the inert-allow state")
	}
}

func TestCheckUnconfigured_RequireConfiguredFailsClosed(t *testing.T) {
	cfg := config.Config{APIKey: "", RequireConfigured: true, FailClosed: true, CacheDir: t.TempDir()}
	d, ok := checkUnconfigured(cfg, []string{"malicious.example"})
	if !ok {
		t.Fatal("expected checkUnconfigured to apply")
	}
	if d.Allow {
		t.Error("expected a DENY when RequireConfigured=true and FailClosed=true")
	}
}

func TestCheckUnconfigured_RequireConfiguredRespectsFailClosedFalse(t *testing.T) {
	cfg := config.Config{APIKey: "", RequireConfigured: true, FailClosed: false, CacheDir: t.TempDir()}
	d, ok := checkUnconfigured(cfg, []string{"malicious.example"})
	if !ok {
		t.Fatal("expected checkUnconfigured to apply")
	}
	if !d.Allow {
		t.Error("expected an ALLOW when RequireConfigured=true but FailClosed=false")
	}
}

func TestNoticeUnconfiguredOnce_WritesMarkerAndDoesNotDuplicate(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{CacheDir: dir}

	noticeUnconfiguredOnce(cfg)
	markerPath := dir + "/.unconfigured-notice-shown"
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("expected a marker file to be written, stat error: %v", err)
	}

	// Second call must not error or panic; behavior (no duplicate
	// stderr notice) isn't directly observable from a unit test without
	// capturing stderr, so this just guards against a crash/regression
	// on the "already shown" path.
	noticeUnconfiguredOnce(cfg)
}
