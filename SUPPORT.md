# Support

Malanta TrustGate ships a pluggable reputation-provider architecture: one
compiled, officially-supported provider (Malanta) plus a generic
config-driven REST adapter that lets anyone point the hooks at another
vendor without writing Go code. That flexibility comes with a deliberate,
declared support-tier policy so the maintainer burden stays bounded as more
vendors get used in the wild.

## Support tiers

| Component | Tier | What that means |
| --- | --- | --- |
| Core (`internal/verdict`, `internal/extract`, `internal/cache`, `internal/config`, `internal/hookrunner`, the five `cmd/trustgate-before-*` binaries) | **Officially supported** | Maintainers use reasonable efforts to triage and address functional and security defects on a normal open-source cadence. |
| Malanta provider (`internal/reputation` Malanta client) | **Officially supported** | Same as core - it is the default, compiled-in provider and is maintained alongside it. Open-source integration support does not modify any separate Malanta service support terms. |
| Generic provider **engine** (`internal/reputation` generic adapter: request/response mapping, SSRF guardrails, batch/single modes) | **Officially supported** | Bugs in the generic adapter itself are triaged like core on a reasonable-efforts basis. |
| Specific vendor **configs** placed under the generic adapter (VirusTotal example, any other `generic_provider` config you write or find in `docs/providers.md`) | **Best-effort / community** | These are data, not code we compile or test against a live vendor API on every change. If a vendor changes its response shape, a config may stop working, and fixing it is on the config author/maintainer. We accept PRs but there is no SLA. |
| The vendored Agent Threat Rules (ATR) ruleset content | **Best-effort / community** | We integrate and curate a subset of ATR; rule-content bugs (false positives/negatives in a specific rule) should go to the upstream ATR project when they're upstream rules, or to us when they're in our hand-curated subset. |

## What this means in practice

- **Filing an issue against core or the Malanta provider**: maintainers
  will use reasonable efforts to triage and address the issue on a normal
  open-source cadence. Use the `provider:malanta` label if you know the
  issue is in that layer.
- **Filing an issue against a generic-adapter vendor config**: use the
  `provider:third-party` label. We'll try to help, but if the fix requires
  vendor-specific expertise we don't have, the fastest path is a PR from
  someone who uses that vendor.
- **Promoting a community config to compiled/built-in status**: this
  requires (a) tests against a realistic fixture of the vendor's API shape,
  (b) a named maintainer willing to keep it working, and (c) maintainer
  sign-off that the support burden is worth taking on permanently. Until
  then, it stays a config example.

## Getting help

- **Bug reports and feature requests**: open a GitHub issue.
- **Security vulnerabilities**: do **not** open a public issue — see
  [SECURITY.md](SECURITY.md).
- **"How do I configure vendor X?"**: check [`docs/providers.md`](docs/providers.md)
  first; if your vendor isn't there, open an issue with the `provider:third-party`
  label and, ideally, a draft config.
