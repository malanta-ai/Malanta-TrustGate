package verdict

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/cache"
	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/override"
	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

// TestClassifyTargets_KindsAreDistinct is the core routing guard: a
// repository or owner value must arrive at the provider under its own Kind.
// Under KindDomain the Malanta provider would apply eTLD+1 reduction and
// query the domain endpoint about a value that is not a hostname.
func TestClassifyTargets_KindsAreDistinct(t *testing.T) {
	got, warnings := classifyTargets(Targets{
		Hosts:  []string{"github.com", "192.0.2.5"},
		Repos:  []string{"acme/backdoor"},
		Owners: []string{"acme"},
	})
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	want := []reputation.Indicator{
		{Kind: reputation.KindDomain, Value: "github.com"},
		{Kind: reputation.KindIPv4, Value: "192.0.2.5"},
		{Kind: reputation.KindGitHubRepo, Value: "acme/backdoor"},
		{Kind: reputation.KindGitHubOwner, Value: "acme"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("indicator %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestClassifyTargets_SameValueDifferentScope covers the pathological but
// legal case of an owner and a repository sharing a literal string: they are
// different indicators and both must survive de-duplication.
func TestClassifyTargets_SameValueDifferentScope(t *testing.T) {
	got, _ := classifyTargets(Targets{
		Repos:  []string{"acme/backdoor"},
		Owners: []string{"acme/backdoor"},
	})
	if len(got) != 2 {
		t.Fatalf("expected both scopes to survive dedup, got %v", got)
	}
	if got[0].Kind == got[1].Kind {
		t.Errorf("expected distinct kinds, got %v", got)
	}
}

func TestClassifyTargets_DedupesWithinScope(t *testing.T) {
	got, _ := classifyTargets(Targets{
		Repos:  []string{"acme/backdoor", "acme/backdoor"},
		Owners: []string{"acme", "acme"},
	})
	if len(got) != 2 {
		t.Errorf("expected 2 deduped indicators, got %v", got)
	}
}

// TestComposeTargets_DenyOnFlaggedRepo is the end-to-end cascade assertion:
// a flagged repository denies the event, and the decision record identifies
// the flagged thing by value AND kind so an operator can tell a repository
// deny from a hostname deny.
func TestComposeTargets_DenyOnFlaggedRepo(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"github.com":    {Name: "UNKNOWN"},
		"acme/backdoor": {Name: "MALICIOUS", MaliciousScore: 1},
	}}
	d := ComposeTargets(context.Background(), cfg, "beforeShellExecution", Targets{
		Hosts: []string{"github.com"},
		Repos: []string{"acme/backdoor"},
	}, nil, lk, nil)

	if d.Allow {
		t.Fatalf("expected deny on a flagged repository, got %#v", d)
	}
	if d.Indicator != "acme/backdoor" {
		t.Errorf("Indicator = %q, want the repository", d.Indicator)
	}
	if d.Kind != "github_repo" {
		t.Errorf("Kind = %q, want github_repo", d.Kind)
	}
	if !strings.Contains(d.Reason, "GitHub repository acme/backdoor") {
		t.Errorf("reason should name the scope, got %q", d.Reason)
	}
}

// TestComposeTargets_DenyOnFlaggedOwner covers owner-scope enforcement and
// its distinct wording: the verdict is about the account, which is the
// nuance an operator needs when the repository itself isn't flagged.
func TestComposeTargets_DenyOnFlaggedOwner(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"evilorg": {Name: "MALICIOUS", MaliciousScore: 1},
	}}
	d := ComposeTargets(context.Background(), cfg, "beforeShellExecution", Targets{
		Owners: []string{"evilorg"},
	}, nil, lk, nil)

	if d.Allow {
		t.Fatalf("expected deny on a flagged owner, got %#v", d)
	}
	if d.Kind != "github_owner" {
		t.Errorf("Kind = %q, want github_owner", d.Kind)
	}
	if !strings.Contains(d.Reason, "not for one specific repository") {
		t.Errorf("owner deny should explain its scope, got %q", d.Reason)
	}
}

// TestComposeTargets_CleanRepoAllows keeps the happy path honest: an
// UNKNOWN repository verdict allows, exactly like an unflagged host.
func TestComposeTargets_CleanRepoAllows(t *testing.T) {
	cfg := baseCfg(t)
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"acme/library": {Name: "UNKNOWN"},
	}}
	d := ComposeTargets(context.Background(), cfg, "beforeShellExecution", Targets{
		Repos: []string{"acme/library"},
	}, nil, lk, nil)
	if !d.Allow {
		t.Errorf("expected allow for an UNKNOWN repository, got %#v", d)
	}
}

// TestComposeTargets_AbsentRepoFailsClosed confirms the new kinds inherit
// the fail-closed contract: a provider that answers about no repository at
// all is a protocol anomaly, not an allow.
func TestComposeTargets_AbsentRepoFailsClosed(t *testing.T) {
	cfg := baseCfg(t)
	cfg.FailClosed = true
	lk := &fakeLookup{resp: map[string]*reputation.Label{}}
	d := ComposeTargets(context.Background(), cfg, "beforeShellExecution", Targets{
		Repos: []string{"acme/backdoor"},
	}, nil, lk, nil)
	if d.Allow {
		t.Errorf("expected fail-closed deny for an unanswered repository, got %#v", d)
	}
}

// TestComposeTargets_PolicyAllowlistPerScope covers admin allowlisting of a
// repository. It also pins the deliberate non-inheritance: allowlisting an
// OWNER does not pre-approve repositories published under it.
func TestComposeTargets_PolicyAllowlistPerScope(t *testing.T) {
	t.Run("allowlisted repo skips the provider", func(t *testing.T) {
		cfg := baseCfg(t)
		cfg.PolicyAllowlist = []string{"acme/internal-tool"}
		lk := &fakeLookup{err: context.DeadlineExceeded} // would fail closed if consulted
		d := ComposeTargets(context.Background(), cfg, "shell", Targets{
			Repos: []string{"acme/internal-tool"},
		}, nil, lk, nil)
		if !d.Allow {
			t.Errorf("expected allow without a provider call, got %#v", d)
		}
	})

	t.Run("allowlisted owner does not cover its repos", func(t *testing.T) {
		cfg := baseCfg(t)
		cfg.PolicyAllowlist = []string{"acme"}
		lk := &fakeLookup{resp: map[string]*reputation.Label{
			"acme/backdoor": {Name: "MALICIOUS", MaliciousScore: 1},
		}}
		d := ComposeTargets(context.Background(), cfg, "shell", Targets{
			Repos: []string{"acme/backdoor"},
		}, nil, lk, nil)
		if d.Allow {
			t.Errorf("an owner allowlist entry must not pre-approve its repositories, got %#v", d)
		}
	})
}

// TestComposeTargets_RepoOverrideFlipsDeny is the end-to-end guarantee
// behind `trustgate override --repo`: the override store is keyed by
// indicator VALUE, so a grant written for the canonical repository must
// flip the deny for that repository — and must not leak to a different one.
func TestComposeTargets_RepoOverrideFlipsDeny(t *testing.T) {
	cfg := baseCfg(t)
	cfg.AllowUserOverride = true
	cfg.OverrideScope = config.OverrideScopeDomain
	if err := override.Grant(cfg.CacheDir, "acme/backdoor", time.Now().Add(10*time.Minute), "triaging", "cli"); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"acme/backdoor": {Name: "MALICIOUS", MaliciousScore: 1},
		"acme/other":    {Name: "MALICIOUS", MaliciousScore: 1},
	}}

	granted := ComposeTargets(context.Background(), cfg, "beforeShellExecution", Targets{
		Repos: []string{"acme/backdoor"},
	}, nil, lk, nil)
	if !granted.Allow {
		t.Errorf("expected the granted repository to be allowed, got %#v", granted)
	}

	other := ComposeTargets(context.Background(), cfg, "beforeShellExecution", Targets{
		Repos: []string{"acme/other"},
	}, nil, lk, nil)
	if other.Allow {
		t.Errorf("a per-repository grant must not cover a different repository, got %#v", other)
	}
}

// TestComposeTargets_OwnerGrantDoesNotCoverRepo pins the scope boundary in
// the store: grants match by exact value, so an owner grant does not imply
// its repositories. An operator who wants that must say so with --owner on
// a deny that was itself owner-scoped.
func TestComposeTargets_OwnerGrantDoesNotCoverRepo(t *testing.T) {
	cfg := baseCfg(t)
	cfg.AllowUserOverride = true
	cfg.OverrideScope = config.OverrideScopeDomain
	if err := override.Grant(cfg.CacheDir, "acme", time.Now().Add(10*time.Minute), "triaging", "cli"); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	lk := &fakeLookup{resp: map[string]*reputation.Label{
		"acme/backdoor": {Name: "MALICIOUS", MaliciousScore: 1},
	}}
	d := ComposeTargets(context.Background(), cfg, "beforeShellExecution", Targets{
		Repos: []string{"acme/backdoor"},
	}, nil, lk, nil)
	if d.Allow {
		t.Errorf("an owner grant must not cover a repository deny, got %#v", d)
	}
}

// TestOverrideHintText_MatchesDeniedKind: the hint is a command the
// operator will paste verbatim, so it must name the flag that actually
// canonicalizes their kind of indicator.
func TestOverrideHintText_MatchesDeniedKind(t *testing.T) {
	cfg := config.Defaults()
	for _, tc := range []struct{ kind, indicator, want string }{
		{"", "evil.example", "--domain evil.example"},
		{"domain", "evil.example", "--domain evil.example"},
		{"github_repo", "acme/backdoor", "--repo acme/backdoor"},
		{"github_owner", "evilorg", "--owner evilorg"},
	} {
		got := overrideHintText(cfg, tc.indicator, tc.kind)
		if !strings.Contains(got, tc.want) {
			t.Errorf("kind %q: hint = %q, want it to contain %q", tc.kind, got, tc.want)
		}
	}
	if got := overrideHintText(cfg, "", "github_repo"); strings.Contains(got, "--repo") {
		t.Errorf("a systemic deny names no indicator, so it must stay blanket: %q", got)
	}
}

// TestTargets_Values pins what the decision record's host array carries: all
// three scopes, hosts first, and the original slice untouched when there is
// nothing else (so the common path allocates nothing).
func TestTargets_Values(t *testing.T) {
	hosts := []string{"github.com"}
	if got := (Targets{Hosts: hosts}).Values(); len(got) != 1 || got[0] != "github.com" {
		t.Errorf("hosts-only Values() = %v", got)
	}
	got := Targets{Hosts: hosts, Repos: []string{"acme/backdoor"}, Owners: []string{"evilorg"}}.Values()
	want := []string{"github.com", "acme/backdoor", "evilorg"}
	if len(got) != len(want) {
		t.Fatalf("Values() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Values() = %v, want %v", got, want)
		}
	}
	if len(hosts) != 1 {
		t.Errorf("Values() must not mutate the caller's Hosts slice: %v", hosts)
	}
}

// TestTTLFor_OwnerScopeIsCapped is the staleness guard. A GitHub account
// name can be renamed and re-registered by someone else, so an owner-scope
// verdict must not inherit the long flagged-verdict TTL — while repository
// and host verdicts, which don't churn that way, keep it.
func TestTTLFor_OwnerScopeIsCapped(t *testing.T) {
	cfg := baseCfg(t)
	cfg.PositiveTTL = 24 * time.Hour
	cfg.NegativeTTL = time.Hour

	flagged := &reputation.Label{Name: "MALICIOUS", MaliciousScore: 1}
	clean := &reputation.Label{Name: "UNKNOWN"}

	cases := []struct {
		name string
		ind  reputation.Indicator
		lbl  *reputation.Label
		want time.Duration
	}{
		{
			name: "flagged owner is capped",
			ind:  reputation.Indicator{Kind: reputation.KindGitHubOwner, Value: "evilorg"},
			lbl:  flagged,
			want: ownerScopeMaxTTL,
		},
		{
			name: "clean owner is capped too",
			ind:  reputation.Indicator{Kind: reputation.KindGitHubOwner, Value: "acme"},
			lbl:  clean,
			want: ownerScopeMaxTTL,
		},
		{
			name: "flagged repo keeps the positive TTL",
			ind:  reputation.Indicator{Kind: reputation.KindGitHubRepo, Value: "evilorg/tool"},
			lbl:  flagged,
			want: cfg.PositiveTTL,
		},
		{
			name: "flagged host keeps the positive TTL",
			ind:  reputation.Indicator{Kind: reputation.KindDomain, Value: "evil.example"},
			lbl:  flagged,
			want: cfg.PositiveTTL,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ttlFor(cfg, tc.ind, tc.lbl); got != tc.want {
				t.Errorf("ttlFor = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCachePut_OwnerScopeVerdictIsCached confirms the capped TTL still
// produces a usable cache entry (the cap shortens the lifetime, it does not
// disable caching for owner scope).
func TestCachePut_OwnerScopeVerdictIsCached(t *testing.T) {
	cfg := baseCfg(t)
	c, err := cache.Open(filepath.Join(t.TempDir(), "lookups.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	defer func() { _ = c.Close() }()

	owner := reputation.Indicator{Kind: reputation.KindGitHubOwner, Value: "evilorg"}
	d := Decision{}
	cachePut(context.Background(), c, cfg, "malanta", owner,
		&reputation.Label{Name: "MALICIOUS", MaliciousScore: 1}, &d)

	got, present, err := c.Lookup(context.Background(), "malanta", owner)
	if err != nil || !present || got.Name != "MALICIOUS" {
		t.Errorf("owner verdict should be cached: got=%#v present=%v err=%v", got, present, err)
	}
	if len(d.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", d.Warnings)
	}
}
