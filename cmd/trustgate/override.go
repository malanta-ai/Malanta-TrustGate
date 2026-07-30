package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/extract"
	"github.com/malanta-ai/Malanta-TrustGate/internal/override"
)

// overrideFileName matches internal/override's on-disk file name —
// kept here purely so this package's own tests can assert against the
// exact path without reaching into the internal/override package.
const overrideFileName = "override.json"

// stringSliceFlag collects a repeatable string flag (--domain can be
// passed more than once to grant/clear several hosts in one command).
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// overrideTarget is one resolved override subject: the exact indicator
// value the grant is keyed by (which must match what the cascade denied
// on, byte for byte after case-folding), plus how to describe it to the
// operator so the confirmation line is unambiguous about scope.
type overrideTarget struct {
	value string
	desc  string
}

// overrideTargets resolves the three target flags into one flat list.
//
// Hosts pass through as typed (they are already lowercased by
// extract.Normalize on the enforcement side, and ActiveFor case-folds).
// GitHub references are canonicalized through internal/extract so that
// pasting the URL from a deny message, or the owner/repo from the log,
// both land on the value the cascade used. An unresolvable reference is a
// hard error rather than a pass-through: a grant keyed to something the
// cascade will never produce is a silent no-op, and the operator would
// discover it only by hitting the same block again.
func overrideTargets(domains, repos, owners stringSliceFlag) ([]overrideTarget, error) {
	var out []overrideTarget
	for _, d := range domains {
		if strings.TrimSpace(d) == "" {
			return nil, fmt.Errorf("--domain must be a non-empty host")
		}
		d = strings.TrimSpace(d)
		out = append(out, overrideTarget{value: d, desc: "host " + d})
	}
	for _, r := range repos {
		repo, ok := extract.CanonicalGitHubRepo(r)
		if !ok {
			return nil, fmt.Errorf("--repo %q: not a GitHub repository reference; pass owner/repo (e.g. acme/backdoor) or a GitHub URL naming one", r)
		}
		out = append(out, overrideTarget{value: repo, desc: "GitHub repository " + repo})
	}
	for _, o := range owners {
		owner, ok := extract.CanonicalGitHubOwner(o)
		if !ok {
			return nil, fmt.Errorf("--owner %q: not a GitHub owner reference; pass the bare account name (e.g. acme) or a GitHub URL naming one", o)
		}
		out = append(out, overrideTarget{value: owner, desc: "GitHub owner " + owner})
	}
	return out, nil
}

// describeTargets renders targets for a confirmation line, naming the
// scope of each so an operator can see at a glance that (say) an owner
// grant is broader than the repository they were denied on.
func describeTargets(targets []overrideTarget) string {
	descs := make([]string, 0, len(targets))
	for _, t := range targets {
		descs = append(descs, t.desc)
	}
	return strings.Join(descs, ", ")
}

func runOverride(args []string) error {
	fs := flag.NewFlagSet("override", flag.ContinueOnError)
	minutes := fs.Int("minutes", 15, "how many minutes the override stays active")
	reason := fs.String("reason", "", "why you're overriding a deny (required, gets logged)")
	clear := fs.Bool("clear", false, "remove an override immediately, ignoring --minutes/--reason")
	var domains, repos, owners stringSliceFlag
	fs.Var(&domains, "domain", "flagged host to grant/clear (repeatable). Required when TRUSTGATE_OVERRIDE_SCOPE=domain (the default); ignored (writes a blanket grant) when TRUSTGATE_OVERRIDE_SCOPE=time")
	fs.Var(&repos, "repo", "flagged GitHub repository to grant/clear (repeatable). Accepts owner/repo or any GitHub URL naming it")
	fs.Var(&owners, "owner", "flagged GitHub owner (user or organization) to grant/clear (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Resolve GitHub references to the exact canonical value the cascade
	// denies on, then treat all three flags as one flat list of targets.
	// The override store is keyed by indicator VALUE, not by kind, and the
	// three namespaces cannot collide: a canonical repo always contains
	// "/", a hostname never does (extract.Normalize drops bare hostnames,
	// so every host carries a dot), and a bare owner has neither.
	targets, err := overrideTargets(domains, repos, owners)
	if err != nil {
		return err
	}

	// LoadWithEnvFiles (not plain config.Load) so this reflects EXACTLY
	// what the hook binaries themselves will see — including
	// TRUSTGATE_ALLOW_USER_OVERRIDE / TRUSTGATE_OVERRIDE_SCOPE set in
	// ~/.config/trustgate/env or /etc/trustgate/env, which a hook
	// process picks up via config.LoadWithEnvFiles but a plain
	// config.Load (process env only) would miss. Getting this wrong
	// previously meant this command could print a false "will have NO
	// EFFECT" warning even when the hooks would, in fact, honor the
	// grant.
	cfg, err := config.LoadWithEnvFiles()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if *clear {
		if len(targets) == 0 {
			if err := override.ClearAll(cfg.CacheDir); err != nil {
				return err
			}
			fmt.Println("All overrides cleared.")
			return nil
		}
		for _, t := range targets {
			if err := override.Clear(cfg.CacheDir, t.value); err != nil {
				return fmt.Errorf("clear %s: %w", t.value, err)
			}
		}
		fmt.Printf("Cleared override(s) for: %s\n", describeTargets(targets))
		return nil
	}

	if *reason == "" {
		return fmt.Errorf("--reason is required (it gets written to the audit trail — see docs/admin.md)")
	}
	if *minutes <= 0 {
		return fmt.Errorf("--minutes must be positive, got %d", *minutes)
	}

	scope := cfg.OverrideScope
	if scope == "" {
		scope = config.OverrideScopeDomain
	}
	var grantTargets []overrideTarget
	switch scope {
	case config.OverrideScopeTime:
		if len(targets) > 0 {
			fmt.Println("note: TRUSTGATE_OVERRIDE_SCOPE=time is a blanket override; --domain/--repo/--owner are ignored (every flagged indicator is allowed for the window, not just the ones named).")
		}
		grantTargets = []overrideTarget{{value: "*", desc: "blanket"}}
	default: // config.OverrideScopeDomain, and any empty/unrecognized value defensively treated the same
		if len(targets) == 0 {
			return fmt.Errorf("name what to override when TRUSTGATE_OVERRIDE_SCOPE=domain (the default): --domain malicious.example, --repo acme/backdoor, or --owner acme. Use TRUSTGATE_OVERRIDE_SCOPE=time for a blanket override instead")
		}
		// Reject a wildcard under domain scope. "*" is the
		// reserved blanket-grant sentinel (internal/override.ActiveFor
		// treats it as "allow every flagged host"), which is exactly what
		// TRUSTGATE_OVERRIDE_SCOPE=time is for. Accepting `--domain '*'`
		// here would let a user quietly convert a domain-scoped policy
		// into a blanket bypass. Any wildcard-bearing value is refused;
		// the operator must either name exact hosts or switch to time
		// scope deliberately.
		for _, t := range targets {
			if strings.Contains(t.value, "*") {
				return fmt.Errorf("%s: wildcard grants are not allowed under TRUSTGATE_OVERRIDE_SCOPE=domain; name the exact flagged indicator(s), or set TRUSTGATE_OVERRIDE_SCOPE=time for a deliberate blanket override", t.desc)
			}
		}
		grantTargets = targets
	}

	until := time.Now().Add(time.Duration(*minutes) * time.Minute)
	for _, t := range grantTargets {
		if err := override.Grant(cfg.CacheDir, t.value, until, *reason, "cli"); err != nil {
			return fmt.Errorf("grant %s: %w", t.value, err)
		}
	}

	if grantTargets[0].value == "*" {
		fmt.Printf("Blanket override granted, expires %s.\n", until.Format(time.RFC3339))
	} else {
		fmt.Printf("Override granted for %s, expires %s.\n", describeTargets(grantTargets), until.Format(time.RFC3339))
	}
	if !cfg.AllowUserOverride {
		fmt.Println()
		fmt.Println("WARNING: this override will have NO EFFECT. An admin must set")
		fmt.Println("TRUSTGATE_ALLOW_USER_OVERRIDE=true in managed config (e.g.")
		fmt.Println("/etc/trustgate/env) before any override is honored — see")
		fmt.Println("docs/admin.md. Writing a grant alone is never sufficient.")
	}
	return nil
}
