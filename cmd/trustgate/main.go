// trustgate is the TrustGate admin/setup CLI. Unlike the five
// trustgate-before-* hook binaries, this is NOT invoked on Cursor's hot
// path (no 250ms budget, no stdin/stdout JSON verdict contract) — it's run
// interactively by a person, so it's free to import things (terminal
// libraries, etc.) the hook binaries deliberately avoid.
//
// Its subcommands: "setup" (the individual/single-developer half of the
// key-distribution story documented in docs/architecture.md and the root
// README — an enterprise MDM writes /etc/trustgate/env directly, but a
// single developer needs something to run once), "doctor" (config-in-effect
// + provider-reachability diagnostics), "explain" (decision-log lookup by
// decision_id or indicator), "override" (admin-gated break-glass grants),
// and "purge"/"export" (PRIV-003 local audit-data retention + export).
// See docs/admin.md for the full write-up of doctor/explain/override.
package main

import (
	"fmt"
	"os"
)

var version = "dev" // overridden at build time via -ldflags "-X main.version=..."

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "setup":
		if err := runSetup(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "trustgate setup: %v\n", err)
			os.Exit(1)
		}
	case "doctor":
		if err := runDoctor(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "trustgate doctor: %v\n", err)
			os.Exit(1)
		}
	case "explain":
		if err := runExplain(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "trustgate explain: %v\n", err)
			os.Exit(1)
		}
	case "override":
		if err := runOverride(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "trustgate override: %v\n", err)
			os.Exit(1)
		}
	case "purge":
		if err := runPurge(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "trustgate purge: %v\n", err)
			os.Exit(1)
		}
	case "export":
		if err := runExport(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "trustgate export: %v\n", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Println("trustgate " + version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "trustgate: unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `trustgate - Malanta TrustGate admin CLI

Usage:
  trustgate setup [--key <api-key>] [--env-var <NAME>] [--reset]
      Store a reputation-provider API key for this user at
      ~/.config/trustgate/env (mode 0600). Prompts for the key (hidden
      input) if not supplied via --key or the target env var. Refuses to
      overwrite an existing key file unless --reset is passed.

      Which env var it stores is provider-aware: with the default
      Malanta provider, that's MALANTA_API_KEY. With provider: "generic"
      configured in config.json, it auto-detects and stores under that
      vendor's generic_provider.auth.env_var instead (e.g.
      VIRUSTOTAL_API_KEY) — see docs/providers.md. Pass --env-var to
      override the detected name (e.g. for a vendor config you haven't
      finished writing yet).

  trustgate doctor
      Print a diagnostic report: config-in-effect, which env files are
      present, lookup-cache and audit-table health, provider
      reachability, and whether Cursor's hooks.json references these
      hooks. Start here when a hook seems to be misbehaving.

  trustgate explain <decision_id|indicator>
      Look up one decision by its decision_id (the value shown in a
      deny's user_message), or list recent decisions mentioning a given
      indicator (domain or IP). Reads from the local SQLite audit table
      — see docs/admin.md.

  trustgate override [--domain <host>] [--repo <owner/repo>] [--owner <owner>] --minutes <n> --reason "<why>"
      Grant a time-boxed override for one or more specific flagged
      indicators (TRUSTGATE_OVERRIDE_SCOPE=domain, the default) that lets
      a denied action for them through for the next <n> minutes. Each
      flag is repeatable and they can be mixed in one command; use the
      flag matching what was blocked — a deny's message names it.
      --repo/--owner accept a GitHub URL as well as the bare form, and
      canonicalize it to the value the cascade denied on. Note --owner is
      broader than --repo: it allows EVERY repository under that account.
      Only takes effect if an admin has set
      TRUSTGATE_ALLOW_USER_OVERRIDE=true in managed config — writing a
      grant yourself does nothing otherwise. Every override use is
      logged, never a silent bypass. See docs/admin.md.

  trustgate override --minutes <n> --reason "<why>"
      With TRUSTGATE_OVERRIDE_SCOPE=time, no target flag is required (and
      any passed is ignored): grants a single blanket override that lets
      ANY denied indicator through for the window, regardless of which
      one triggered the deny.

  trustgate override --clear [--domain <host>] [--repo <owner/repo>] [--owner <owner>]
      Remove an override immediately. With a target flag, clears only the
      named indicator(s); without one, clears every grant.

  trustgate purge [--days <n>] [--all] [--include-log] [--yes]
      Apply the local audit-data retention policy: delete audit-table
      rows (and, by default, decision-log lines) older than <n> days, or
      everything with --all. Defaults --days to TRUSTGATE_RETENTION_DAYS.
      Run manually or from cron — retention is NOT enforced on the hook
      hot path. See docs/admin.md (PRIV-003).

  trustgate export [--out <file>]
      Export every locally-recorded decision as JSON Lines (oldest
      first) to <file> or stdout. Only indicators, verdicts, and ATR
      rule identities are included — never raw command/file/prompt text.

  trustgate version
      Print the CLI version.

  trustgate help
      Show this message.
`)
}
