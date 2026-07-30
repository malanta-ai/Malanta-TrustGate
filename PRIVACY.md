# Privacy & Data Use

_Publisher: **Malantai Ltd.** · Contact: **hello@malanta.ai** · Security:
**security@malanta.ai**_

This document describes what data TrustGate handles, the paths on which
data may leave your machine, the plugin's local storage and retention, and
the controls you have. It also states our binding no-model-training
commitment and the cost/availability of the plugin and the services it can
use.

## No-model-training commitment (binding)

**Malantai Ltd. does not use any data submitted through TrustGate — the
domains, IP addresses, and GitHub repository/owner names sent in a
reputation lookup, or any decision metadata — to train, fine-tune, or otherwise improve any machine-learning
or AI model, and does not sell, rent, or share that data for that
purpose.** Reputation lookups are used solely to answer the reputation
query for that request. This commitment applies to the Malanta reputation
service operated by Malantai Ltd.

Third-party reputation providers you may configure instead of Malanta
(e.g. VirusTotal) are governed by **their own** privacy terms; TrustGate
sends them only the indicators described below, but their handling of that
data is outside Malantai Ltd.'s control — review their policy before
enabling them.

## What TrustGate handles, and where it goes

Everything TrustGate inspects (shell command text, MCP tool input, file
contents, prompt text) is processed **locally, in memory**, only to extract
candidate destinations and run the behavioral (ATR) pass. Raw command
lines, file contents, and prompt bodies are **never** transmitted off the
device and are **never** written to disk by TrustGate.

The data paths from your machine are:

| Egress path | What is sent | When | To whom |
| --- | --- | --- | --- |
| Reputation lookup | The extracted **domains / eTLD+1 / IPv4 addresses / GitHub repository/owner names (`owner/repo` or bare `owner`)** only (never the raw command/file/prompt) | On every inspected action with a cache miss | The configured reputation provider (Malanta by default, unless another provider is configured) |
| Audit sink (optional) | Decision **metadata** (decision id, timestamp, hook, indicator, verdict/score, mode, ATR rule identities, and machine hostname/username for attribution) — never raw content | Only when `TRUSTGATE_AUDIT_SINK_URL` is configured | The collector URL configured by the operator |

The extracted indicators are transmitted **solely for the purpose of
obtaining a reputation verdict required to perform the requested security
check** — never for any other purpose.

A GitHub reference is reduced to the repository name (`owner/repo`) — or
just the owner name when no repository is named — before transmission.
Branch names, file paths, query strings, and any tokens embedded in a URL
are discarded locally and never sent.

Nothing else is transmitted. There is no telemetry, no analytics, no
"phone home." If you run in mode `off`, TrustGate does not inspect actions
or transmit data.

## Local storage & retention

TrustGate keeps two local stores under `~/.cache/trustgate/` (or your
configured `TRUSTGATE_CACHE_DIR`):

- **Reputation cache** (`lookups.db`) — a TTL cache of provider verdicts,
  keyed by (provider, kind, value). Entries expire on their TTL.
- **Decision log + audit table** (`decisions.log`, `audit.db`) — the
  local audit trail. **Redaction contract:** only the extracted
  indicators, the provider verdict/score, the decision metadata, and ATR
  rule *identities* are stored. An ATR match is recorded as a one-way
  SHA-256 fingerprint + byte length, never the matched substring. Raw
  command/file/prompt bodies are never stored.

**File access:** the API key file is restricted to your account on every
platform — owner-only permissions (`0600`) on macOS and Linux, and an
explicit current-user-only ACL on Windows, where `trustgate setup` refuses
to store the key at all if that ACL cannot be applied. The cache, decision
log, and audit database get the same owner-only permissions on macOS and
Linux; on Windows, which does not implement Unix permission bits, they
inherit your user profile's ACL, which by default excludes other
non-administrator users. On every platform, a process running as you — and
any administrator or root user — can read these files. They are private to
your account, not sealed against it. See
[`docs/admin.md`](docs/admin.md#11-on-disk-protection-of-local-state) for
the operator-facing detail.

**Retention & deletion controls:**

- `TRUSTGATE_RETENTION_DAYS` — sets the retention window (default `0` =
  keep indefinitely; an operator/MDM sets a policy).
- `trustgate purge [--days N | --all]` — deletes audit rows and
  decision-log entries older than the window, or everything. Run manually
  or from cron (retention is not enforced on the hook hot path, to avoid
  latency).
- `trustgate export [--out FILE]` — exports every recorded decision as
  redaction-safe JSON Lines for review or export of locally recorded
  decisions.

If you enable the audit sink, retention and deletion of data **at the
collector** are the responsibility of whoever operates that collector —
TrustGate only sends the metadata; it does not manage the remote store.

## Your controls

- **Provider choice** — Malanta (default) or any configured provider; or
  none (the plugin allows by default when unconfigured unless
  `TRUSTGATE_REQUIRE_CONFIGURED=true`).
- **Mode** — `off` (no inspection at all), `report-only`, `warn`, or
  `enforce`.
- **Scope** — restrict which workspaces TrustGate applies to
  (`TRUSTGATE_SCOPE_MODE`/`TRUSTGATE_SCOPE_PATHS`); out-of-scope
  workspaces are not inspected or logged.
- **Behavioral pass** — `TRUSTGATE_ATR_DISABLE=true` turns off the ATR
  pass.
- **Audit sink** — off by default; you choose whether to enable it and
  where it points.
- **Deletion/export** — `trustgate purge` / `trustgate export` as above.

## Cost & availability disclosure

- **The plugin is free and open source (MIT).** Malantai Ltd. does not
  charge for TrustGate itself, and installing/using the plugin costs
  nothing.
- **TrustGate requires an external reputation service to make verdicts.**
  It ships with two built-in provider integrations; the service behind
  each has its own pricing and terms, independent of this free plugin:
  - **Malanta** (default) — a commercial pre-attack-prevention service by
    Malantai Ltd. It requires an API key; access/pricing is arranged with
    Malanta separately (see https://malanta.ai). Without a key, TrustGate
    is inert-allow by default (or fail-closed if you set
    `TRUSTGATE_REQUIRE_CONFIGURED=true`).
  - **VirusTotal** (community/best-effort config) — a third-party service
    with both a free tier (rate-limited) and paid plans, governed by
    VirusTotal's own terms and privacy policy. You supply your own key.
- You may also configure **any** other REST reputation vendor via the
  generic adapter; its cost and terms are between you and that vendor.

The plugin never transmits payment information and has no in-plugin
purchases. The only external dependency with a potential cost is the
reputation service you choose to point it at.

## Changes

Material changes to this document will be noted in `CHANGELOG.md`.
Questions: **hello@malanta.ai**.
