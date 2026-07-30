# Bring your own reputation vendor

TrustGate answers one question before Cursor lets an agent talk to a domain,
IP address, or GitHub repository: *is this destination trustworthy?* That
answer comes from a **reputation provider** — a pluggable backend behind the
`internal/reputation.Provider` interface. Two implementations ship today:

| Provider | `provider` value | Support tier | Notes |
| --- | --- | --- | --- |
| Malanta | `malanta` (default) | Officially supported | Compiled in; batch API against `/v1/domains/reputation` + `/v1/ips/reputation` + `/v1/code-repos/reputation`. GitHub repository reputation is Malanta-only. |
| Generic (config-driven) | `generic` | Engine: officially supported. Vendor configs: **community/best-effort** | Point it at any REST reputation API via JSON config — no Go code required. |

This doc is about the generic provider: how to configure it for a vendor
you already have an account with, the guardrails it enforces, and what
support to expect. See [`SUPPORT.md`](../SUPPORT.md) for the full tier
policy — the short version is: **we maintain the engine that interprets
your config; you (or the community) maintain the config itself.**

## What the generic provider gives you

Point TrustGate at whatever reputation API your organization already trusts
— Malanta, VirusTotal, AbuseIPDB, or an internal threat-intel service — with
nothing but JSON config. Concretely, you get:

- **Any REST vendor, no Go and no fork.** Describe the vendor's API in
  `config.json` — its endpoint(s), how auth works, and where the
  verdict/score live in the response. You never touch or recompile
  TrustGate.
- **Changes take effect immediately.** Every hook invocation reloads config,
  so a new or edited config applies on the next agent action — no rebuild,
  no redeploy, no waiting on a maintainer.
- **The hard parts are handled for you.** The engine makes the HTTPS calls,
  enforces the SSRF guardrails (host allowlist, no internal-range
  destinations, redirect blocking), batches and retries, and pulls the
  verdict/score out of the JSON. Your config only describes the response
  shape.
- **Mix, match, and switch freely.** Configure a domain vendor and an IP
  vendor independently, swap vendors by editing one file, or fall back to
  the built-in Malanta provider at any time.

## Quick start

1. Pick (or write) a config for your vendor — see the worked examples
   below, or copy [`docs/examples/generic-provider-configs/template.json`](examples/generic-provider-configs/template.json).
2. Merge the `provider` and `generic_provider` keys into
   `~/.config/trustgate/config.json` (create the file if it doesn't exist).
3. Put the vendor's API key in an env var (the name is whatever you put in
   `generic_provider.auth.env_var`) — in `.env`, `~/.config/trustgate/env`,
   or `/etc/trustgate/env` for a fleet-wide install. **Never** put the key
   value itself in `config.json`.
4. Restart Cursor (or just re-run the hook — each invocation is a fresh
   process that reloads config).

## Config schema

```jsonc
{
  "provider": "generic",
  "generic_provider": {
    "name": "myvendor",                              // optional display name — see below
    "base_url": "https://vendor.example.com/api",  // https only
    "mode": "single",                                // "single" or "batch"
    "method": "GET",                                 // default: GET (single) / POST (batch)
    "auth": {
      "header": "x-api-key",                         // header name the vendor expects
      "env_var": "MY_VENDOR_API_KEY",                 // where the secret VALUE comes from
      "scheme": "Bearer "                             // optional prefix, e.g. for Authorization headers
    },
    "allowed_hosts": ["vendor.example.com"],          // REQUIRED — the SSRF guardrail
    "max_concurrency": 2,                             // in-flight requests; default 2 (see
                                                       // TRUSTGATE_PROVIDER_MAX_CONCURRENCY below to override)
    "domain": { /* GenericEndpoint, see below */ },
    "ip":     { /* GenericEndpoint, see below */ }
  },
  "block_labels": ["malicious"],
  "min_malicious_score_to_block": 0.5
}
```

`domain` and `ip` are independent and both optional — set only the ones your
vendor answers. An indicator whose kind has no configured endpoint resolves
to a neutral "no data" label (never flagged, never fail-closed) rather than
an error.

There is no GitHub endpoint in this schema. Repository reputation is
Malanta-only today; under a generic provider those indicators resolve to a
neutral no-data label and never block.

`name` is optional and purely cosmetic, but worth setting: without it,
every user-facing surface (a deny's message, the decision log's `provider`
field, `trustgate doctor`, and the cache's namespace) calls your vendor
"generic". Set it to the vendor's name (e.g. `"virustotal"`) and those
surfaces say that instead — see `GenericProvider.Name`'s doc comment for
exactly what it affects.

### Single mode (`GenericEndpoint`)

```jsonc
{
  "path_template": "/v1/domain/{domain}/reputation",  // {value}/{domain}/{ip} are synonyms
  "mapping": {
    "verdict_path": "verdict",   // dot-path to a string verdict field (optional)
    "score_path": "score"        // dot-path to a numeric field (optional)
  }
}
```

The indicator value is URL-escaped before being substituted into
`path_template`, so it can never alter the request's host or path structure
— an attacker-controlled domain string cannot redirect the request
elsewhere. `path_template` can include a literal query string after the
placeholder (e.g. `/check?ipAddress={ip}&maxAgeInDays=90}`) for vendors that
take the indicator as a query parameter instead of a path segment — see the
AbuseIPDB example below.

### Batch mode (`GenericEndpoint`)

```jsonc
{
  "path": "/v1/domains/reputation",
  "body_field": "domains",              // JSON body: {"domains": ["a.com", "b.com"]}
  "mapping": {
    "array_path": "results",            // dot-path to the response array (empty = response root)
    "indicator_value_path": "domain",   // per-entry field that echoes back the queried value
    "verdict_path": "verdict",
    "score_path": "score"
  }
}
```

TrustGate sends every indicator of that kind in **one** request (no
chunking yet — see the batch template's caveat below) and matches each
response entry back to its original indicator via
`indicator_value_path`. If your vendor caps request size, keep event fan-out
under that cap or use single mode instead.

### Mapping is field paths only (no computation)

`verdict_path`/`score_path`/`array_path`/`indicator_value_path` are plain
dot-separated field paths — no array indexing, no expressions, no
computation. So if your vendor's "maliciousness" requires combining two
fields (VirusTotal's `last_analysis_stats` is the classic case — see
below), pick the single field that's the best proxy and tune
`min_malicious_score_to_block` to that field's actual scale.

## Worked example: VirusTotal

VirusTotal's [API v3](https://docs.virustotal.com/reference/domains) doesn't
return a single "is this malicious" verdict — it returns
`last_analysis_stats`, a per-engine vote breakdown:

```json
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "harmless": 70, "malicious": 7, "suspicious": 2, "undetected": 10, "timeout": 0
      }
    }
  }
}
```

Since the mapping engine can't compute `malicious / total`, the pragmatic
config maps `score_path` straight to the raw **engine count**
(`data.attributes.last_analysis_stats.malicious`) and leaves `verdict_path`
empty (VT has no single string verdict field; the cascade is fine running
on a score alone — see `GenericResponseMapping`'s doc comment). Because the
score here is a raw count (typically 0–90, not a 0..1 probability),
`min_malicious_score_to_block` is tuned to that scale, not to `0.5`. The
config also sets `"name": "virustotal"` so deny messages, the decision
log, and `trustgate doctor` say "virustotal" instead of "generic".

Full config, auth header, and both domain/IP endpoints:
[`docs/examples/generic-provider-configs/virustotal.json`](examples/generic-provider-configs/virustotal.json)
— validated against VirusTotal's actual documented response shape by
`internal/reputation/example_configs_test.go`
(`TestVirusTotalExampleConfig_ValidatesAndParsesRealShape`).

```bash
export VIRUSTOTAL_API_KEY=...
```

## Worked example: AbuseIPDB (IP-only skeleton)

[AbuseIPDB](https://docs.abuseipdb.com/) answers IP reputation only — there's
no domain endpoint, so the config omits `domain` entirely (domain lookups
will resolve to "no data" and never be flagged; pair this with a
domain-capable provider, or accept that domain checks are effectively
disabled). It also takes the IP as a query parameter rather than a path
segment, and its `abuseConfidenceScore` is a 0–100 integer:

[`docs/examples/generic-provider-configs/abuseipdb.json`](examples/generic-provider-configs/abuseipdb.json)

```bash
export ABUSEIPDB_API_KEY=...
```

This one is a **skeleton**: it parses and validates (see
`TestGenericExampleConfigs_AllParseAndValidateShape`), but unlike the
VirusTotal example it isn't tested against a captured real response body.
If you use it in production and hit a mapping bug, please open a PR with a
fix and a fixture — see [`SUPPORT.md`](../SUPPORT.md)'s tier policy for why
that's the fastest path.

## Templates

- [`template.json`](examples/generic-provider-configs/template.json) — single
  mode starting point with placeholder auth/paths.
- [`template-batch.json`](examples/generic-provider-configs/template-batch.json)
  — batch mode starting point.

## Tuning request concurrency

`generic_provider.max_concurrency` (default 2) bounds in-flight requests
per event for this vendor. `TRUSTGATE_PROVIDER_MAX_CONCURRENCY` (env) /
`provider_max_concurrency` (top-level `config.json` key) is a separate,
provider-agnostic override: when set to a positive value it takes
precedence over `max_concurrency` here (and, for the built-in Malanta
provider, over its own hardcoded default of 4). Leave it unset (the
default) to use each provider's own value/default unchanged — see
`docs/admin.md`'s env var reference.

## SSRF guardrails (read this before shipping a config)

The generic provider holds your vendor's API key and makes outbound
requests on the hot path, so `Validate()` enforces:

- **HTTPS only.** Plain `http://` is rejected outright.
- **`allowed_hosts` is required and non-empty**, and `base_url`'s own host
  must be a member. This is the primary SSRF guardrail for a config-driven
  destination — it's how a hostile or buggy config can't be pointed at an
  internal service.
- **No loopback / RFC1918 / link-local / CGNAT hosts.** A `base_url`
  resolving to `127.0.0.1` or a private range is rejected before any
  request is made.
- **Cross-host redirects are blocked** at the HTTP client level — a
  compromised or misconfigured vendor endpoint can't 302 your API key
  somewhere else.

**Known limitation:** `Validate()` checks the *configured* hostname, not
what it resolves to at request time — there's no DNS-rebinding or
IP-pinning defense. Treat `allowed_hosts` as "hostnames I trust the
operator's DNS for," not an IP-level guarantee.

## Contributing a new vendor config

PRs adding a new example under `docs/examples/generic-provider-configs/`
are welcome. To make it a first-class example (not just a skeleton):

1. Add a fixture-based test in `internal/reputation` that replays the
   vendor's actual documented response shape (see
   `TestVirusTotalExampleConfig_ValidatesAndParsesRealShape` as the
   template) — redact/synthesize the response body, don't use real account
   data.
2. Document the field-mapping trade-off if the vendor doesn't expose a
   clean 0..1 probability (most don't — see the VirusTotal write-up above).
3. Add the file to both this doc and
   `TestGenericExampleConfigs_AllParseAndValidateShape`'s file list.

Remember this stays **community/best-effort** support even after merging
(see [`SUPPORT.md`](../SUPPORT.md)) — promoting a config to a compiled,
officially-supported provider (like Malanta) is a separate, higher bar.
