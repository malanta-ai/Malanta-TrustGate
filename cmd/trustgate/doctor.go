package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/audit"
	"github.com/malanta-ai/Malanta-TrustGate/internal/cache"
	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"github.com/malanta-ai/Malanta-TrustGate/internal/override"
	"github.com/malanta-ai/Malanta-TrustGate/internal/reputation"
)

// dialTimeout bounds the reachability check's TCP dial. Short enough
// that `trustgate doctor` stays snappy on an unreachable host, long
// enough to not false-negative on a normal cross-region round trip.
const dialTimeout = 3 * time.Second

// envFileStatus is one entry in the layered dotenv precedence chain (see
// config.EnvFiles). Reported for visibility, not because doctor cares
// which file actually supplied a given value.
type envFileStatus struct {
	Path   string
	Exists bool
}

// reachabilityResult is one TCP-dial probe against a provider's
// allowed host on port 443. This is NOT an authenticated API call — it
// only confirms basic network reachability, since doing an authenticated
// call risks tripping the provider's own rate limits every time an
// operator runs doctor.
type reachabilityResult struct {
	Host      string
	Reachable bool
	Latency   time.Duration
	Err       string
}

// diagnostics is doctor's full report. Split from the printing logic so
// the gathering step is independently testable.
type diagnostics struct {
	ConfigError string

	Provider               string
	ProviderKnown          bool
	ProviderIsScoreOnly    bool
	APIKeyConfigured       bool
	Unconfigured           bool
	RequireConfigured      bool
	FailClosed             bool
	Mode                   string
	BlockLabels            []string
	AllowLabels            []string
	MinMaliciousScore      float64
	BatchSize              int
	ProviderMaxConcurrency int
	PolicyAllowlist        []string
	AllowUserOverride      bool
	OverrideScope          string
	OverrideWindowMinutes  int
	ActiveOverrides        []override.Entry
	AuditSinkEnabled       bool
	ScopeMode              string
	ScopePaths             []string
	LockedKeys             []string

	EnvFiles []envFileStatus

	CacheDBPath    string
	CacheOpenError string

	AuditDBPath    string
	AuditStats     audit.Stats
	AuditOpenError string

	ProviderConstructError string
	Reachability           []reachabilityResult

	HooksManifestPath      string
	HooksManifestFound     bool
	HooksManifestMentions  bool
	HooksManifestReadError string
}

// isScoreOnlyProvider reports whether the configured provider can never
// return a verdict NAME, only a numeric score — true for a generic
// provider whose configured endpoint(s) all leave mapping.verdict_path
// empty (VirusTotal is the canonical example: last_analysis_stats has no
// single "verdict" field — see docs/providers.md). block_labels /
// allow_labels never match anything for such a provider; only
// min_malicious_score drives denies. False for Malanta (always names a
// verdict) and for a generic config where at least one configured
// endpoint DOES map a verdict_path.
func isScoreOnlyProvider(cfg config.Config) bool {
	if cfg.Provider != "generic" || cfg.Generic == nil {
		return false
	}
	endpoints := []*reputation.GenericEndpoint{cfg.Generic.Domain, cfg.Generic.IP}
	sawEndpoint := false
	for _, ep := range endpoints {
		if ep == nil {
			continue
		}
		sawEndpoint = true
		if ep.Mapping.VerdictPath != "" {
			return false
		}
	}
	return sawEndpoint
}

func runDoctor(_ []string) error {
	cfg, cfgErr := config.LoadWithEnvFiles()
	d := gatherDiagnostics(cfg, cfgErr)
	printDiagnostics(os.Stdout, d)
	return nil
}

func gatherDiagnostics(cfg config.Config, cfgErr error) diagnostics {
	d := diagnostics{
		Provider:               cfg.Provider,
		ProviderKnown:          cfg.Provider == "" || cfg.Provider == "malanta" || cfg.Provider == "generic",
		ProviderIsScoreOnly:    isScoreOnlyProvider(cfg),
		APIKeyConfigured:       cfg.APIKey != "",
		Unconfigured:           cfg.IsUnconfigured(),
		RequireConfigured:      cfg.RequireConfigured,
		FailClosed:             cfg.FailClosed,
		Mode:                   cfg.Mode,
		BlockLabels:            cfg.BlockLabels,
		AllowLabels:            cfg.AllowLabels,
		MinMaliciousScore:      cfg.MinMaliciousScoreToBlock,
		BatchSize:              cfg.APIBatchSize,
		ProviderMaxConcurrency: cfg.ProviderMaxConcurrency,
		PolicyAllowlist:        cfg.PolicyAllowlist,
		AllowUserOverride:      cfg.AllowUserOverride,
		OverrideScope:          cfg.OverrideScope,
		OverrideWindowMinutes:  cfg.OverrideWindowMinutes,
		ActiveOverrides:        override.List(cfg.CacheDir),
		AuditSinkEnabled:       cfg.AuditSinkURL != "",
		ScopeMode:              cfg.ScopeMode,
		ScopePaths:             cfg.ScopePaths,
		LockedKeys:             config.LockedKeys(),
		CacheDBPath:            filepath.Join(cfg.CacheDir, "lookups.db"),
		AuditDBPath:            filepath.Join(cfg.CacheDir, "audit.db"),
	}
	if cfgErr != nil {
		d.ConfigError = cfgErr.Error()
	}

	home, _ := os.UserHomeDir()
	for _, p := range []string{
		"/etc/trustgate/env",
		filepath.Join(home, ".config", "trustgate", "env"),
		".env",
	} {
		_, err := os.Stat(p)
		d.EnvFiles = append(d.EnvFiles, envFileStatus{Path: p, Exists: err == nil})
	}

	if c, err := cache.Open(d.CacheDBPath); err != nil {
		d.CacheOpenError = err.Error()
	} else {
		_ = c.Close()
	}

	if a, err := audit.Open(d.AuditDBPath); err != nil {
		d.AuditOpenError = err.Error()
	} else {
		defer func() { _ = a.Close() }()
		if st, err := a.Stats(context.Background()); err != nil {
			d.AuditOpenError = err.Error()
		} else {
			d.AuditStats = st
		}
	}

	if cfgErr == nil {
		malantaConcurrency := 4
		if cfg.ProviderMaxConcurrency > 0 {
			malantaConcurrency = cfg.ProviderMaxConcurrency
		}
		provider, err := reputation.NewFromParams(cfg.Provider, reputation.MalantaParams{
			BaseURL:        cfg.APIBaseURL,
			APIKey:         cfg.APIKey,
			AttemptTimeout: cfg.APITimeout,
			MaxAttempts:    cfg.APIMaxAttempts,
			MaxConcurrency: malantaConcurrency,
			BatchSize:      cfg.APIBatchSize,
		}, cfg.Generic, cfg.APITimeout, cfg.APIMaxAttempts, cfg.ProviderMaxConcurrency)
		if err != nil {
			d.ProviderConstructError = err.Error()
		} else {
			for _, host := range provider.AllowedHosts() {
				d.Reachability = append(d.Reachability, checkReachability(host))
			}
		}
	}

	d.HooksManifestPath = filepath.Join(home, ".cursor", "hooks.json")
	data, err := os.ReadFile(d.HooksManifestPath)
	if err != nil {
		if !os.IsNotExist(err) {
			d.HooksManifestReadError = err.Error()
		}
	} else {
		d.HooksManifestFound = true
		d.HooksManifestMentions = containsBytes(data, "trustgate-before-shell")
	}

	return d
}

func checkReachability(host string) reachabilityResult {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "443"), dialTimeout)
	r := reachabilityResult{Host: host, Latency: time.Since(start)}
	if err != nil {
		r.Err = err.Error()
		return r
	}
	_ = conn.Close()
	r.Reachable = true
	return r
}

func containsBytes(haystack []byte, needle string) bool {
	return len(needle) == 0 || indexOfBytes(haystack, []byte(needle)) >= 0
}

func indexOfBytes(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func printDiagnostics(w io.Writer, d diagnostics) {
	fmt.Fprintln(w, "trustgate doctor")
	fmt.Fprintln(w, "================")
	if d.ConfigError != "" {
		fmt.Fprintf(w, "\nCONFIG ERROR: %s\n", d.ConfigError)
		fmt.Fprintln(w, "(the fields below reflect defaults layered with whatever DID parse; fix the error above first)")
	}

	fmt.Fprintln(w, "\nProvider & policy:")
	provider := d.Provider
	if provider == "" {
		provider = "malanta (default)"
	}
	fmt.Fprintf(w, "  provider:              %s\n", provider)
	if !d.ProviderKnown {
		fmt.Fprintf(w, "  WARNING: %q is not a recognized provider (want \"malanta\" or \"generic\")\n", d.Provider)
	}
	fmt.Fprintf(w, "  api key configured:    %s\n", yesNo(d.APIKeyConfigured))
	if provider == "malanta" || provider == "malanta (default)" {
		fmt.Fprintf(w, "  batch_size:            %d (max 100; Malanta's documented per-request limit)\n", d.BatchSize)
	}
	if d.ProviderMaxConcurrency > 0 {
		fmt.Fprintf(w, "  provider_max_concurrency: %d (override)\n", d.ProviderMaxConcurrency)
	} else {
		fmt.Fprintln(w, "  provider_max_concurrency: (unset; each provider keeps its own default)")
	}
	if d.Unconfigured {
		if d.RequireConfigured {
			fmt.Fprintln(w, "  ** UNCONFIGURED: no API key, and TRUSTGATE_REQUIRE_CONFIGURED=true -> every lookup will DENY. Run `trustgate setup` or provision the key. **")
		} else {
			fmt.Fprintln(w, "  ** UNCONFIGURED: no API key -> zero-touch default is INERT ALLOW (see docs/admin.md). Run `trustgate setup` to fix. **")
		}
	}
	fmt.Fprintf(w, "  require_configured:    %v\n", d.RequireConfigured)
	fmt.Fprintf(w, "  fail_closed:           %v\n", d.FailClosed)
	// The shipped config default is "warn" (config.Defaults), so a normally
	// loaded config prints "warn" here. The "enforce" fallback is
	// deliberately NOT "warn": it only shows when d.Mode is empty, which
	// happens on a config-LOAD error — and an empty mode is resolved to
	// enforce (fail-closed) by verdict.effectiveMode at runtime, so the
	// fallback label matches what the hooks would actually do, not the
	// permissive-looking shipped default.
	fmt.Fprintf(w, "  mode:                  %s\n", nonEmpty(d.Mode, config.ModeEnforce))
	fmt.Fprintf(w, "  block_labels:          %v\n", d.BlockLabels)
	fmt.Fprintf(w, "  allow_labels:          %v\n", d.AllowLabels)
	if d.ProviderIsScoreOnly {
		fmt.Fprintln(w, "  note: this provider never returns a verdict name (score-only,")
		fmt.Fprintln(w, "        e.g. VirusTotal's engine count) — block_labels/allow_labels")
		fmt.Fprintln(w, "        never match anything; only min_malicious_score drives denies.")
	}
	fmt.Fprintf(w, "  min_malicious_score:   %g\n", d.MinMaliciousScore)
	if len(d.PolicyAllowlist) > 0 {
		fmt.Fprintf(w, "  policy_allowlist:      %v\n", d.PolicyAllowlist)
	}
	fmt.Fprintf(w, "  allow_user_override:   %v\n", d.AllowUserOverride)
	// Override scope/window/active-grants are relevant whenever EITHER
	// the CLI break-glass is enabled (AllowUserOverride) OR ModeWarn is
	// active — both write grants through the same internal/override
	// store, and warn mode does not require AllowUserOverride (it is
	// its own admin-selected posture, not a user escape hatch).
	if d.AllowUserOverride || d.Mode == "warn" {
		fmt.Fprintf(w, "  override_scope:        %s\n", nonEmpty(d.OverrideScope, "domain"))
		fmt.Fprintf(w, "  override_window_min:   %d\n", d.OverrideWindowMinutes)
		if len(d.ActiveOverrides) == 0 {
			fmt.Fprintln(w, "  active overrides:      none")
		} else {
			fmt.Fprintln(w, "  active overrides:")
			for _, e := range d.ActiveOverrides {
				fmt.Fprintf(w, "    - %s (expires %s, source=%s): %s\n", e.Domain, e.Until, nonEmpty(e.Source, "cli"), e.Reason)
			}
		}
	}
	fmt.Fprintf(w, "  audit sink enabled:    %s\n", yesNo(d.AuditSinkEnabled))
	fmt.Fprintf(w, "  scope_mode:            %s\n", nonEmpty(d.ScopeMode, "all"))
	if len(d.ScopePaths) > 0 {
		fmt.Fprintf(w, "  scope_paths:           %v\n", d.ScopePaths)
	}
	if len(d.LockedKeys) > 0 {
		fmt.Fprintf(w, "  locked by /etc/trustgate/env: %v\n", d.LockedKeys)
	}

	fmt.Fprintln(w, "\nEnv files (precedence order, later overrides earlier):")
	for _, f := range d.EnvFiles {
		mark := " "
		if f.Exists {
			mark = "x"
		}
		fmt.Fprintf(w, "  [%s] %s\n", mark, f.Path)
	}

	fmt.Fprintf(w, "\nLookup cache: %s\n", d.CacheDBPath)
	if d.CacheOpenError != "" {
		fmt.Fprintf(w, "  ERROR: %s\n", d.CacheOpenError)
	} else {
		fmt.Fprintln(w, "  status: OK (opened successfully)")
	}

	fmt.Fprintf(w, "\nAudit table: %s\n", d.AuditDBPath)
	if d.AuditOpenError != "" {
		fmt.Fprintf(w, "  ERROR: %s\n", d.AuditOpenError)
	} else if !d.AuditStats.HasData {
		fmt.Fprintln(w, "  no decisions recorded yet")
	} else {
		fmt.Fprintf(w, "  total decisions: %d (denied: %d)\n", d.AuditStats.Total, d.AuditStats.Denied)
		fmt.Fprintf(w, "  oldest: %s\n", d.AuditStats.Oldest.Format(time.RFC3339))
		fmt.Fprintf(w, "  newest: %s\n", d.AuditStats.Newest.Format(time.RFC3339))
	}

	fmt.Fprintln(w, "\nProvider reachability (TCP dial only, not an authenticated call):")
	if d.ProviderConstructError != "" {
		fmt.Fprintf(w, "  could not construct the configured provider: %s\n", d.ProviderConstructError)
	} else if len(d.Reachability) == 0 {
		fmt.Fprintln(w, "  (no hosts to check)")
	}
	for _, r := range d.Reachability {
		if r.Reachable {
			fmt.Fprintf(w, "  %s:443 — reachable (%s)\n", r.Host, r.Latency.Round(time.Millisecond))
		} else {
			fmt.Fprintf(w, "  %s:443 — UNREACHABLE: %s\n", r.Host, r.Err)
		}
	}

	fmt.Fprintf(w, "\nCursor hooks manifest: %s\n", d.HooksManifestPath)
	switch {
	case d.HooksManifestReadError != "":
		fmt.Fprintf(w, "  ERROR reading manifest: %s\n", d.HooksManifestReadError)
	case !d.HooksManifestFound:
		fmt.Fprintln(w, "  not found — hooks are not installed for this user (run the installer or install the plugin)")
	case !d.HooksManifestMentions:
		fmt.Fprintln(w, "  found, but does not reference trustgate-before-shell — hooks may be installed under a different mechanism (e.g. the marketplace plugin) or not at all")
	default:
		fmt.Fprintln(w, "  found and references trustgate-before-shell")
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
