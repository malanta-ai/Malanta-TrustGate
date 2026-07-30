# Architecture

This document describes how TrustGate is put together: the hook lifecycle,
the reputation abstraction, the cache, the verdict cascade, and the
behavioral (ATR) layer that runs alongside it. For "how do I point this at
vendor X," see [`providers.md`](providers.md). For contribution mechanics,
see [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

## The problem

Cursor's enterprise hooks let a trusted subprocess veto an agent action
before it happens: a shell command, an MCP tool call, a file read, a
built-in tool call (`WebFetch`/`WebSearch`), or a submitted prompt. TrustGate
is that subprocess for one specific question: **is the external
domain/IP this action is about to contact trustworthy?**

## One binary per hook event

```text
cmd/trustgate-before-shell/      beforeShellExecution
cmd/trustgate-before-mcp/        beforeMCPExecution
cmd/trustgate-before-read-file/  beforeReadFile
cmd/trustgate-before-tool-use/   preToolUse   (WebFetch / WebSearch)
cmd/trustgate-before-prompt/     beforeSubmitPrompt (warn-mode-only — see below)
```

Each `main.go` is ~30 lines: decode the hook-specific JSON payload, extract
candidate hosts from it, and hand off to `internal/hookrunner.Run`, which
owns everything every binary needs in common. Cursor spawns a **fresh
process for every single hook invocation** — there is no warm connection
pool, no persistent state between calls except what's on disk (the SQLite
cache and the decision log).

`beforeSubmitPrompt` is wired, but as a **warn-mode-only** early surface: it
does anything only when `TRUSTGATE_MODE=warn`, and in every other mode it
allows the prompt through and leaves enforcement to the execution hooks. Two
guards keep it from being noisy. First, an **action-verb gate**: a prompt
that merely *mentions* a domain ("is x.com malicious?") passes silently,
while one that *instructs* the agent to act on it ("fetch x.com") is what
reaches the cascade — the false-positive cost of denying the former trains
users to disable the hook. Second, it is registered `failClosed:false` (the
only hook that is) and fails open on provider errors, so a TrustGate hiccup
can never block prompt submission. Under warn mode a flagged action-verb
prompt warns once and is allowed on re-submit (the acknowledgement writes an
`internal/override` grant the execution hooks honor). The shell/MCP/read-file
hooks catch the actual action one step later regardless — they are the
enforcement boundary in all modes, and they see domains the agent generates
itself that never appear in the prompt.

## Bootstrap pipeline (`internal/hookrunner`)

Every hook binary runs the same eight steps:

1. Load layered `.env` files (see `internal/config.EnvFiles` below) and
   process env.
2. Load `Config` from built-in defaults + `~/.config/trustgate/config.json`
   + env overrides.
3. Decode the per-hook JSON payload from stdin (capped at 256 KiB).
4. Extract candidate domains/IPs — the one part that's genuinely different
   per hook (see `internal/extract`).
5. Open the SQLite cache and construct the configured reputation provider.
6. Run `verdict.Compose` — the cascade described below.
7. Run the ATR behavioral pass and merge its result into the same
   `Decision` (see "Behavioral detection" below).
8. Write the per-event JSON verdict Cursor expects to stdout.

A bootstrap error (bad config, undecodable payload) short-circuits to the
documented fail-{open,closed} verdict per `Config.FailClosed` without ever
reaching steps 4–7.

## Extraction (`internal/extract`)

Turns raw hook input (a shell command line, MCP tool args, file content, a
prompt) into a list of candidate hostnames/IPs. All extractors funnel
through **one** normalization function
(`extract.Normalize`/`extract.NormalizeURL`) before a candidate is
considered real — this is a hard rule (see `AGENTS.md`) because domain
normalization bugs are exactly the kind of thing that silently breaks
verdicts without any test noticing.

Normalize drops: empty strings, non-routable IP literals (loopback /
RFC1918 / link-local / CGNAT), bare `localhost`, and anything that fails
IDN processing. It punycode-encodes internationalized labels, strips a
`:port` suffix, and lowercases. Public IPv4 (and IPv6, though no provider
answers IPv6 yet — see below) literals pass through as-is.

The shell extractor is the most elaborate: a minimal tokenizer, per-tool
flag extractors (git/npm/kubectl/aws/gcloud config-key scrubbing so dotted
config keys like `user.email` aren't mistaken for hostnames),
local-script-body following (`./foo.sh`, `python foo.py`), and
dependency-manifest following (the file an install command names in its own
arguments, as in `pip install -r reqs.txt`).

**GitHub repository/owner names** (`internal/extract/repo.go`) are
extracted alongside hostnames, on a separate path with its own
normalization: a reference is canonicalized to a lowercased `owner/repo`,
with refs, branches, paths, and query strings discarded. When no repository
is nameable — a bare profile URL, an `owner.github.io` Pages host — it
falls back to the bare `owner`, which the provider answers at account
scope. Reference forms recognized: web, `raw`, API, and `codeload` URLs,
SSH remotes, the `github:owner/repo` shorthand package managers accept,
and GitHub Actions `uses:` steps (the supply-chain surface where a
compromised third-party action runs in your CI).

Extraction targets the surfaces where an action is about to happen: the
shell command, MCP arguments, built-in tool input, script and Dockerfile
bodies, CI workflow definitions, and the prompt. A per-payload cap bounds how many references
one event can produce, so a pathological file can't exhaust the hook's time
budget or the cascade's per-event indicator cap.

## Reputation providers (`internal/reputation`)

```go
type Kind int // KindDomain | KindIPv4 | KindGitHubRepo | KindGitHubOwner

type Indicator struct {
    Kind  Kind
    Value string
}

type Label struct {
    Name           string  // vendor's verdict/category name, "" if unavailable
    MaliciousScore float64 // 0..1 confidence, or a vendor-specific score scale
    ScoreMissing   bool    // vendor flagged a verdict but returned no numeric score
}

type Provider interface {
    Lookup(ctx context.Context, indicators []Indicator) (map[Indicator]*Label, error)
    Name() string
    AllowedHosts() []string
}
```

This is the seam the whole "bring your own vendor" story hangs off. Two
implementations exist:

- **Malanta** (`internal/reputation/malanta.go`) — the default, compiled-in
  provider. Speaks Malanta's batch REST API (`POST
  /v1/domains/reputation`, `POST /v1/ips/reputation`, `POST
  /v1/code-repos/reputation`), reduces domains to
  their registered eTLD+1 (both endpoints 422 on subdomains) and fans the
  verdict back onto every original hostname, batches at up to 100
  indicators per request (configurable down via `MALANTA_API_BATCH_SIZE` /
  `api_batch_size`, capped at Malanta's own 100-per-request limit) with
  bounded concurrency (also overridable, alongside the generic provider's,
  via `TRUSTGATE_PROVIDER_MAX_CONCURRENCY`), and retries once on a
  transient transport error. GitHub repo/owner indicators go to the
  `code-repos` endpoint **verbatim** — the eTLD+1 reduction is
  domain-only, and applying it to a repository name would be nonsense.
- **Generic** (`internal/reputation/generic.go`) — a config-driven REST
  adapter for any other vendor. See [`providers.md`](providers.md) for the
  full schema and worked examples (VirusTotal, AbuseIPDB). Never activated
  unless `provider: "generic"` is explicitly configured. GitHub repo/owner
  indicators resolve to a neutral no-data label here: repository reputation
  is Malanta-only today, and the explicit guard exists so a
  generic-provider user never fail-closes on a kind their vendor was never
  asked about.

Both share `internal/reputation/httpshared.go`: a cross-host redirect
blocker (`http.Client.CheckRedirect`), a response-size cap, and a
snippet-sanitizer for error messages so an error body can't leak into logs
verbatim.

`internal/reputation/factory.go`'s `NewFromParams` is the single
construction point `hookrunner` calls — it reads `Config.Provider` and
returns the right `Provider` implementation or a fail-closed config error.

**IPv4 vs IPv6:** IPv4 literals are first-class indicators today; IPv6 is
extracted and normalized but has no provider support yet, so `verdict.Compose`
skips IPv6 indicators with a warning rather than denying or crashing.

## Cache (`internal/cache`)

A persistent SQLite (pure-Go `modernc.org/sqlite`, WAL mode) TTL cache
keyed by `(provider, kind, value)`. Keying on the provider name means
switching providers can never accidentally serve a cached verdict computed
by a different vendor for the same host. There is no "negative cache"
placeholder concept — every cached row is a real, positive resolution
(a provider that has no opinion resolves to an explicit empty/`UNKNOWN`
`Label`, never an absent row). Flagged verdicts get a longer TTL
(`PositiveTTL`, default 1h) than clean/low-confidence ones
(`NegativeTTL`, default 10m), so a host that turns malicious after being
cached clean is re-checked sooner.

**Owner-scope verdicts are capped at a much shorter TTL** (5m) regardless
of verdict. A GitHub account is mutable in ways a hostname is not — it can
be renamed, transferred, or taken over — so an account-scope answer is
treated as a short-lived observation rather than a stable fact.

## The verdict cascade (`internal/verdict.Compose`)

Per hook invocation, for the set of extracted indicators:

1. **Cache lookup**, one round-trip for the whole batch. Hits skip the
   provider entirely.
2. **Provider lookup** for cache misses.
3. **Absent-entry retry**: an indicator genuinely missing from an otherwise
   successful response (not "no data," a protocol anomaly) gets retried
   once before being treated as unresolvable — under `fail_closed`, still
   unresolvable after retry means deny.
4. **Per-indicator cascade**, first deny wins across the whole set:
   - Verdict name in `allow_labels` (case-insensitive) → allow, unconditionally.
   - Verdict name in `block_labels` → deny **only if** its score crosses
     `min_malicious_score_to_block` (a block-listed label at low confidence is
     a deliberate allow + warn, not an auto-deny). A block-listed verdict
     the vendor returned with **no** numeric score (`Label.ScoreMissing`)
     currently allows-with-warning, logged with a distinct
     `UNSCORED_VERDICT` marker so the case is greppable in the decision log
     (see `AGENTS.md` §5).
   - Verdict name **not** in `block_labels` → the score-threshold check
     still applies (a deliberate backstop): a provider adding a new verdict
     enum value can't silently bypass the block list just because nobody
     added its name to the config.
5. **Pathological fan-out**: an event that extracts more than 500 candidate
   indicators denies outright under `fail_closed` rather than silently
   truncating — truncating would let an attacker pad the front of a
   command with benign hosts to push a malicious one past the cutoff.
6. **Provider error** (total failure, not partial/absent) → deny under
   `fail_closed`, allow + warn otherwise — EXCEPT `warn` mode and the
   `beforeSubmitPrompt` hook, which fail **open** (allow + warn) on a
   provider error even when `fail_closed` is true (warn is audit+notify,
   not enforcement; see `failClosedOnProviderError` and `docs/admin.md`
   §5.2). Only `enforce` blocks on a provider outage.

Every invocation writes one JSON-Lines record to the decision log
(`~/.cache/trustgate/decisions.log` by default) regardless of outcome —
this is the audit trail an admin/`doctor` tool would read.

### Wire shape (Cursor's contract, not ours)

Cursor's hook output schema is per-event and Cursor **fails open on any
output it can't parse** — a well-formed-but-unrecognized JSON shape is
treated as "no decision," and the action proceeds silently. Getting
`Decision.AsJSON()`'s shape exactly right is therefore a security property,
not a formatting nicety:

```jsonc
// beforeShellExecution / beforeMCPExecution
{ "continue": true, "permission": "allow" | "deny" | "ask", "user_message": "...", "agent_message": "..." }

// beforeReadFile / preToolUse
{ "continue": true, "permission": "allow" | "deny", "user_message": "...", "agent_message": "..." }

// beforeSubmitPrompt
{ "continue": true | false, "user_message": "..." }
```

`continue: true` on the permission-shaped events keeps the agent loop alive
(matching Cursor's own hook examples); a `deny` blocks the single action
without halting the turn. `permission: "ask"` (Cursor's native
approve/reject dialog, emitted only under `TRUSTGATE_MODE=ask`) is enforced
by Cursor **only** for `beforeShellExecution`/`beforeMCPExecution`; on
`beforeReadFile`/`preToolUse` it isn't honored, so `ask` mode degrades to a
hard `deny` there (see [`admin.md`](admin.md) §5.2.1). `Decision.AsJSON`
emits the right shape per `HookName` — getting it wrong is a silent
fail-open, so it's covered by the wire-contract integration tests.

## Behavioral detection (`internal/atr`)

The reputation cascade answers "is this host malicious?" ATR (Agent Threat
Rules, an open MIT-licensed YAML detection format) answers a different
question against the same content blob: "does this match a known attack
*shape*?" — reverse-shell one-liners, SSH key exfiltration, MCP
tool-poisoning patterns, skill-compromise instructions, and so on. The two
run in the same hook subprocess and feed a single `Decision`
(`verdict.MergeATR`); a critical-severity ATR match can flip an
otherwise-allowed decision to deny, but never overrides an existing
reputation-cascade deny.

- An embedded snapshot (vendored from the upstream `agent-threat-rules`
  package, `scripts/sync-atr-rules.py` — maintainer-only, see
  [`CONTRIBUTING.md`](../CONTRIBUTING.md)) ships inside every binary.
- `TRUSTGATE_ATR_RULES_DIR` lets anyone add or override rules with plain
  YAML, no rebuild required — see
  [`docs/examples/atr-custom-rules/README.md`](examples/atr-custom-rules/README.md).
- `TRUSTGATE_ATR_DISABLE=true` is the kill switch: skips the ATR pass
  entirely while leaving the reputation cascade active, for when a rule
  false-positives on legitimate work and you need an immediate escape
  valve.

## Configuration (`internal/config`)

Layered, later wins: built-in defaults → `~/.config/trustgate/config.json`
→ environment variables. `EnvFiles()` defines the `.env`-style file
precedence hook binaries load before process env:

1. `/etc/trustgate/env` — MDM-managed, fleet-wide (lowest precedence:
   the default for managed endpoints).
2. `~/.config/trustgate/env` — per-user override.
3. `.env` in the working directory — dev convenience.

Two env-var namespaces exist on purpose: `TRUSTGATE_*` for tool-level
settings that apply no matter which provider is active (`TRUSTGATE_PROVIDER`,
`TRUSTGATE_FAIL_CLOSED`, `TRUSTGATE_BLOCK_LABELS`/`ALLOW_LABELS`,
`TRUSTGATE_MIN_MALICIOUS_SCORE`, `TRUSTGATE_CACHE_DIR`/`LOG_PATH`,
`TRUSTGATE_ATR_DISABLE`/`ATR_RULES_DIR`), and `MALANTA_API_*` for settings
specific to the Malanta provider (its key, base URL, timeout, host
allowlist) — those stay Malanta-prefixed because they configure the
vendor, not the tool.

`Config.APIKey` is JSON-blacklisted (`json:"-"`) so it can never be
persisted into `config.json` even by accident; it only ever comes from an
env var or one of the three env files above.

## Fail-closed by default (in `enforce` mode)

Every error path that affects a verdict respects `Config.FailClosed`
(default `true`): if TrustGate can't get a confident answer — provider
down, auth error, cache broken, config invalid — the fail-closed posture
is deny, not allow. This is the single most important design decision in
the codebase; changes to `internal/verdict`, `internal/reputation`, or
`internal/config.EnvFiles` get extra review scrutiny for exactly this
reason (see `CONTRIBUTING.md`).

**Mode interacts with this.** `FailClosed` governs what a *deny-eligible*
error does, but the default `TRUSTGATE_MODE` is `warn`, not `enforce`
(see [`docs/admin.md`](admin.md) §3): warn is an audit+notify posture, so
it softens a flagged-domain deny to block-once-then-proceed AND fails
**open** on a provider error/timeout (matching `report-only`) rather than
denying. Fail-closed-on-everything is the `enforce`-mode behavior — the
posture a fleet moves to once onboarded. So "fail-closed by default" is
precise about the `FailClosed` flag and about `enforce` mode; the shipped
*default mode* trades that hard floor for lower day-one friction on
individual installs, on purpose.

## Admin operability

See [`docs/admin.md`](admin.md) for the full write-up. Short version: a
`decision_id` on every Decision, a `trustgate` admin CLI
(`doctor`/`explain`/`override`), a scoped-down central policy (`mode` +
a flat allowlist, not the fuller owner/expiry-per-entry design), an
opt-in HTTPS audit sink (synchronous with a short deadline, not
literally async — every hook is a fresh short-lived subprocess with no
daemon for a background goroutine to outlive), zero-touch defaults
(`TRUSTGATE_REQUIRE_CONFIGURED`), a managed-config policy lock
(`/etc/trustgate/env`'s `TRUSTGATE_LOCKED_KEYS`), and workspace/project
scoping (`TRUSTGATE_SCOPE_MODE`/`SCOPE_PATHS`).

Cursor Marketplace packaging (`.cursor-plugin/plugin.json`,
`hooks/hooks.json`, a wrapper-script binary resolver with checksum +
best-effort cosign verification) is also built — see
[`docs/plugin.md`](plugin.md).

## What's not built yet

- The fuller org-allowlist design (per-entry owner, expiry, justification,
  fleet/group scoping) — what ships is a flat, non-expiring, exact-match
  list instead.
- Syslog/file audit sink modes (HTTP/HTTPS only today).
- OS keystore integration for the API key (Keychain / DPAPI / Secret
  Service) — still env-file-only.
- A verified Windows path for the marketplace plugin (the standalone
  `.ps1` installer is the recommended Windows path today).

See the project's plan/issue tracker for current status on these.
