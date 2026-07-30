# Malanta TrustGate

TrustGate is a set of [Cursor enterprise hooks](https://cursor.com/docs/hooks)
that check the domains, IP addresses, and GitHub repositories an AI coding
agent is about to contact — before it contacts them — against a pluggable
reputation provider. Malanta is the default, officially-supported provider; a
config-driven generic adapter lets you point TrustGate at any other REST
reputation API (VirusTotal, AbuseIPDB, an internal threat-intel service)
with no code changes. See [`docs/providers.md`](docs/providers.md) for the
"bring your own vendor" guide, [`docs/architecture.md`](docs/architecture.md)
for how the whole system fits together, [`docs/plugin.md`](docs/plugin.md)
for the Cursor Marketplace plugin packaging, and
[`docs/admin.md`](docs/admin.md) for team/enterprise operability
(diagnostics, policy modes, an opt-in audit sink, admin-gated overrides).

TrustGate is a free, open-source plugin published by **Malantai Ltd.** and
licensed under the [MIT License](LICENSE). The plugin itself contains no
in-plugin purchases and collects no payment information; the reputation
service it checks against (Malanta by default, or a provider you configure)
has its own terms and pricing — see [Privacy & cost](#privacy--cost) and
[Disclaimer](#disclaimer).

| Cursor hook | Binary | What it inspects | Status |
| --- | --- | --- | --- |
| `beforeShellExecution` | `trustgate-before-shell` | The shell command Cursor is about to run | **active** |
| `beforeMCPExecution` | `trustgate-before-mcp` | The registered MCP server URL + tool arguments | **active** |
| `beforeReadFile` | `trustgate-before-read-file` | Paths + content of high-risk files (lockfiles, manifests, scripts, CI workflows) Cursor is about to read | **active** |
| `preToolUse` | `trustgate-before-tool-use` | Built-in agent tools (`WebFetch`, `WebSearch`) not covered by a dedicated event | **active** |
| `beforeSubmitPrompt` | `trustgate-before-prompt` | The user prompt about to be sent to the model | **warn-mode only** — see below |

Each hook spawns a small Go binary (no CGO, designed for a fast cold
start), extracts candidate destinations from its payload — hostnames, IP
addresses, and GitHub repository/owner names — resolves each one to a
reputation label (via a SQLite-backed TTL cache first, then the configured
provider), and writes a single-line JSON verdict to stdout. End-to-end hook
latency is dominated by the ATR ruleset load, cache lookup, and — on a cache
miss — the provider round-trip, not by process startup; measure on your
target machine rather than relying on a fixed number.

Alongside those binaries, the plugin also delivers two agent-facing
components to the installing user:

| Component | File | What it does |
| --- | --- | --- |
| `trustgate` agent skill | `skills/trustgate/SKILL.md` | On-demand operating guide the agent loads when it hits a verdict — how to read it, diagnose a block, use overrides, and configure TrustGate |
| `trustgate-modes` rule | `rules/trustgate-modes.mdc` | Always-on rule for interpreting a verdict per policy mode (so an `allow` is never mistaken for a clean reputation result) |

The Marketplace plugin delivers both automatically; the standalone
installer installs the skill by default and prints how to add the rule
(see [Install](#install-the-hooks-into-cursor) and
[`docs/plugin.md`](docs/plugin.md)).

**The default mode is `warn`** (audit + notify): a flagged destination is
blocked once with an explanation, and re-running the same action proceeds —
so TrustGate educates without hard-blocking day-one work, the friction that
otherwise gets a security tool uninstalled. Flip to `enforce`
(`TRUSTGATE_MODE=enforce`) for a hard, **fail-closed** posture where a
flagged destination — or any error, timeout, or misconfiguration — denies
the action outright; a fleet rollout typically sets and locks that once the
team is onboarded. For interactive desktop use there is also `ask`
(`TRUSTGATE_MODE=ask`, Cursor 3.11.25+), which shows a native
approve/reject dialog and pauses a flagged **shell or MCP** action for a
human decision (it degrades to a hard deny on older Cursor builds, and on
events Cursor doesn't enforce `ask` for — `WebFetch`/`WebSearch`, file
reads — so it never fails open). See
[`docs/admin.md`](docs/admin.md#3-policy-mode-and-a-minimal-allowlist)
for all modes.

An [Agent Threat Rules](https://agentthreatrule.org) (ATR) behavioral pass
runs alongside the reputation cascade in the same subprocess, matching
content against known attack *shapes* (reverse shells, credential
exfiltration, MCP tool-poisoning) independent of domain reputation — see
[`docs/architecture.md`](docs/architecture.md#behavioral-detection-internalatr).

> **`beforeSubmitPrompt` is a warn-mode-only early warning.** It acts only
> when `TRUSTGATE_MODE=warn` (the default mode); in `ask`, `enforce`,
> `report-only`, or `off` it lets the prompt through untouched. (`ask` is
> not an exception here: the prompt hook has no `permission:"ask"` lever —
> its only outputs are allow/block — so `ask` enforcement, like
> `enforce`'s, lives entirely at the execution hooks.) Even under warn it
> stays quiet for ordinary questions and never blocks prompt submission on
> a TrustGate error — it's a nicer, earlier heads-up for destinations you
> type, not an enforcement point. The shell/MCP/read-file hooks are the real
> enforcement boundary in all modes (and catch destinations the agent
> generates itself, which never appear in your prompt). See
> [`docs/admin.md`](docs/admin.md#53-prompt-layer-warn-beforesubmitprompt)
> for the full behavior.

## Security: never let your API key touch anything but the sanctioned paths

The reputation provider's API key must only ever live in a process
environment variable or one of the three on-disk env files described
under [Configuration](#configuration) below. It must never appear in
`config.json`, source, a commit, or a chat/ticket/screenshot. If a key is
ever exposed that way, rotate it immediately in the provider's dashboard —
see [`SECURITY.md`](SECURITY.md) for the full disclosure policy if you
think you've found a way the *code itself* could leak one.

**Reporting a vulnerability:** do **not** open a public GitHub issue for a
security vulnerability. Email **security@malanta.ai** and review
[`SECURITY.md`](SECURITY.md) for the coordinated-disclosure process.

## Privacy & cost

TrustGate is local-first: it processes everything on your machine and the
only data that ever leaves the device is the extracted domains, IPs, and
GitHub repository/owner names sent to your configured reputation provider
(and, if you opt in, decision metadata
to your own audit-sink URL). Raw commands, file contents, and prompts are
never transmitted or stored. Malantai Ltd. does not use TrustGate data to
train any model. The plugin itself is free (MIT) with no in-plugin
purchases and no payment collection. Malanta is a **separate commercial
service** operated by Malantai Ltd. that requires an API key (access,
pricing, terms, and privacy at [malanta.ai](https://malanta.ai)); any
third-party provider you configure instead is governed by **its own**
terms and pricing. If no provider is configured, TrustGate allows actions
by default unless `TRUSTGATE_REQUIRE_CONFIGURED=true`. Full details,
retention controls, and the no-training commitment are in
[`PRIVACY.md`](PRIVACY.md).

## Supported platforms

| OS | Status | Installer |
| --- | --- | --- |
| **macOS** (arm64, x86_64) | Primary target. Daily-driven on Darwin 25 / macOS 26 "Tahoe". | `scripts/install-hooks.sh` |
| **Linux** (glibc, arm64 or x86_64) | Supported. Same install flow as macOS; not as heavily exercised. | `scripts/install-hooks.sh` |
| **Windows 10 / 11** (PowerShell 5.1 or 7+) | Supported — same Go binaries (`.exe`), parallel PowerShell installer; install verified end to end with a live Cursor agent. Exercised less than macOS. | `scripts\install-hooks.ps1` |

The hook binaries are 100% pure Go (no CGO) and build cleanly for all three
platforms with no source changes. The only platform-specific bits are the
installer script, the binary extension, and ACLs vs. `chmod` for the
on-disk env file.

## Requirements

- **Go 1.25+** (`go version`) — for a source build. `go.mod` sets a `1.25.0`
  language floor and pins the build toolchain to `1.26.5` (fetched
  automatically with the default `GOTOOLCHAIN=auto`); CI builds on `1.26.x`.
  On macOS 26 / Darwin 25 a current toolchain also avoids a linker/`LC_UUID`
  incompatibility with older Go — see `AGENTS.md`.
  **No Go toolchain?** Run the installer with `--prebuilt` (`-Prebuilt` on
  Windows) to download verified prebuilt binaries instead of building — see
  below.
- An API key for whichever reputation provider you're using (Malanta by
  default; see [`docs/providers.md`](docs/providers.md) for others).
- One of the supported platforms above.

## Layout

```text
Malanta-TrustGate/
├── cmd/
│   ├── trustgate-before-shell/main.go
│   ├── trustgate-before-mcp/main.go
│   ├── trustgate-before-prompt/main.go      (beforeSubmitPrompt, warn-mode only — see above)
│   ├── trustgate-before-read-file/main.go
│   ├── trustgate-before-tool-use/main.go
│   └── trustgate/                           admin CLI (`setup`/`doctor`/`explain`/`override`/`purge`/`export`)
├── .cursor-plugin/plugin.json                Cursor Marketplace plugin manifest
├── hooks/                                    plugin hook config + wrapper scripts
├── skills/trustgate/SKILL.md                 plugin-bundled agent skill (operating guide; delivered to installers)
├── rules/trustgate-modes.mdc                 plugin-bundled always-on rule (verdict interpretation per mode)
├── assets/logo.svg                           marketplace icon
├── internal/
│   ├── reputation/  Provider interface + Malanta batch client + generic REST adapter
│   ├── cache/       SQLite TTL cache, keyed by (provider, kind, value)
│   ├── config/      layered defaults < config.json < env (see Configuration)
│   ├── extract/     per-surface domain/IP extractors + normalization,
│   │                plus GitHub repository/owner name canonicalization
│   ├── verdict/     extract -> cache -> provider -> JSON verdict cascade
│   ├── atr/         behavioral (Agent Threat Rules) detection pass
│   ├── override/    self-service override grants + warn-mode's pending-marker store
│   └── hookrunner/  shared bootstrap all five cmd/ binaries call into
├── docs/
│   ├── architecture.md   how the system fits together
│   ├── providers.md      bring-your-own-vendor guide
│   └── examples/         worked provider configs + ATR custom-rule example
├── scripts/
│   ├── install-hooks.sh    macOS / Linux installer (bash)
│   ├── install-hooks.ps1   Windows installer (PowerShell)
│   ├── smoke-test.sh       Live-API smoke test (shell, MCP, read-file, tool-use binaries) (bash)
│   └── sync-atr-rules.py   maintainer-only: refresh the vendored ATR snapshot
├── testdata/               Sample payloads for each hook
├── hooks.json              Cursor hook manifest template
├── go.mod
├── Makefile
└── .env.example
```

## Build

```bash
git clone https://github.com/malanta-ai/Malanta-TrustGate.git
cd Malanta-TrustGate
make tidy     # download dependencies
make test     # unit tests (hermetic, no network, no API key)
make build    # produces dist/trustgate-before-*
```

PowerShell users can run the underlying commands directly:

```powershell
go mod tidy
go test ./...
go build -o dist/ ./cmd/...
```

## Install the hooks into Cursor

There are two ways to get these hooks into Cursor. Both build from this
same source and ship the same binaries — pick whichever fits your setup:

- **Standalone installer** (below): works on macOS, Linux, and Windows.
  Use this today; it's the most field-tested path.
- **Cursor Marketplace plugin**: install via Cursor's plugin system
  instead of running a script. The plugin bundles the hooks **plus the
  `trustgate` agent skill (`skills/trustgate/SKILL.md`) and the
  `trustgate-modes` rule (`rules/trustgate-modes.mdc`)**, and delivers both
  to the installing user's agent automatically. Currently macOS/Linux only
  (or Windows with Git Bash/WSL) — see [`docs/plugin.md`](docs/plugin.md)
  for local testing, submission, and team/enterprise import instructions.

### Standalone installer

The installer writes four things, on all platforms:

1. The five hook binaries plus the `trustgate` admin CLI to `~/.local/bin/`
   (Windows: `%USERPROFILE%\.local\bin\`). `trustgate-before-prompt` is
   installed and wired, but only acts under `TRUSTGATE_MODE=warn` — see the
   note above.
2. Cursor's hook manifest to `~/.cursor/hooks.json`.
3. The provider API key to `~/.config/trustgate/env`
   (Windows: `%USERPROFILE%\.config\trustgate\env`), file-permission
   restricted to the current user.
4. The TrustGate agent skill to `~/.cursor/skills/trustgate/` so the agent
   interprets verdicts correctly (an `allow` is not a clean reputation
   result — see [Privacy & cost](#privacy--cost) and the skill itself).
   Skip with `--no-agent-guidance` (`-NoAgentGuidance` on Windows); the
   enforcement hooks are unaffected either way.

### macOS / Linux

```bash
export MALANTA_API_KEY=...   # or just run the script and you'll be prompted
./scripts/install-hooks.sh   # --reset-key to overwrite a key; --prebuilt to skip building (no Go)
```

No Go toolchain? `./scripts/install-hooks.sh --prebuilt` downloads the
matching prebuilt binaries for your OS/arch from the internal binaries repo
(`malanta-ai/Malanta-TrustGate-Binaries`), verifies their SHA-256, and
installs those — everything else (hooks.json, skill, key setup) is identical.
Requires access to that private repo.

Key storage itself is handled by `trustgate setup` (installed alongside
the hook binaries) — you can re-run it anytime without re-running the
whole installer: `~/.local/bin/trustgate setup --reset`. It's
provider-aware: with the default Malanta provider it stores
`MALANTA_API_KEY`; if `config.json` selects `provider: "generic"`, it
auto-detects and stores under that vendor's own auth env var instead
(`--env-var` overrides the detected name) — see
[Using a different reputation provider](#using-a-different-reputation-provider).

### Windows (PowerShell)

```powershell
$env:MALANTA_API_KEY = "..."   # or omit and the script prompts securely
pwsh -File scripts\install-hooks.ps1   # -ResetKey to overwrite a key; -Prebuilt to skip building (no Go)
```

On Windows PowerShell 5.1, use `powershell` instead of `pwsh`. If script
execution is disabled, either run with `-ExecutionPolicy Bypass` once, or
set `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` per user.

### After install (all platforms)

**Restart Cursor** so it picks up the new hook manifest.

The installer also installs the `trustgate` agent skill (above). There's a
companion always-on rule (`rules/trustgate-modes.mdc`) that can't be
installed as a global file — Cursor has no user-global rule file path — so
the installer prints how to enable it: paste it into
Cursor → Settings → Customize → Rules (User Rules), or copy it into a
project's `.cursor/rules/`. This is optional; the skill already carries the
key guidance. (The Marketplace plugin delivers both automatically.)

> **Install order matters.** Cursor reads `hooks.json` fresh on every tool
> call. A fail-closed hook whose target binary doesn't exist locks every
> agent tool with `exit 127` until an operator fixes the manifest from
> outside the session. The installer scripts always build → install
> binaries → write `hooks.json`, in that order, for this reason — don't
> hand-edit `hooks.json` ahead of the binaries.

## Using a different reputation provider

By default TrustGate uses the built-in Malanta provider. To use another
vendor (or your own internal API), set `TRUSTGATE_PROVIDER=generic` and
add a `generic_provider` config block — see
[`docs/providers.md`](docs/providers.md) for the schema, worked examples
(VirusTotal, AbuseIPDB), and the SSRF guardrails the engine enforces.
Vendor configs are community/best-effort support; the engine itself and
the Malanta provider are officially supported — see
[`SUPPORT.md`](SUPPORT.md).

Once `config.json` selects `generic`, `trustgate setup` picks that up
automatically: `trustgate setup --reset` prompts for and stores the
vendor's key under the env var named in `generic_provider.auth.env_var`
(e.g. `VIRUSTOTAL_API_KEY`), not `MALANTA_API_KEY`.

## UAT (manual acceptance steps)

After restarting Cursor with the hook manifest in place. Note the default
mode is `warn`, so a flagged destination is blocked **once** and then
proceeds on a re-run — steps 2-5 below describe that first-touch block. To
exercise the hard, fail-closed behavior (step 6), set
`TRUSTGATE_MODE=enforce` first.

1. **Allow path**: ask Cursor to fetch `https://example.com/robots.txt`.
   Expected: the action proceeds; the decision log shows
   `permission: allow` for `beforeShellExecution`.
2. **Warn path — shell**: ask Cursor to fetch and run a script from a
   domain your provider flags as malicious. Expected (default `warn`): the
   command is blocked on the first touch with the verdict name and an
   "Audited — re-run…" message; re-running the identical command proceeds.
   Under `enforce` it stays blocked with a `trustgate override` hint.
3. **Warn path — MCP** (if you have an MCP server that takes a URL):
   invoke a tool with a flagged URL in its arguments. Expected: the call
   is blocked on first touch (same warn/enforce distinction as above).
4. **Warn path — WebFetch/WebSearch**: ask Cursor to fetch a flagged URL.
   Expected: the built-in tool is blocked by `preToolUse` on first touch.
5. **Warn path — GitHub repository**: ask Cursor to clone a repository your
   provider flags as malicious. Expected: the block names the **GitHub
   repository** (`owner/repo`), not `github.com` — the host itself is clean,
   so naming it would mean the repository check didn't run. The deny hint
   uses `trustgate override --repo`.
6. **Fail-closed sanity (enforce only)**: set `TRUSTGATE_MODE=enforce`,
   then unset the API key and repeat any of the above. Expected: every
   action is denied with a reason naming the provider as unavailable.
   (Under the default `warn`, a provider error/unconfigured state instead
   fails **open** — allow with a logged warning — by design; see
   [`docs/admin.md`](docs/admin.md#3-policy-mode-and-a-minimal-allowlist).)

### Tailing the decision log

```bash
tail -F ~/.cache/trustgate/decisions.log | jq .
```

```powershell
Get-Content -Wait "$env:USERPROFILE\.cache\trustgate\decisions.log"
```

### Fast scripted variant (macOS/Linux, requires `python3`)

```bash
export MALANTA_API_KEY=$(grep ^MALANTA_API_KEY ~/.config/trustgate/env | cut -d= -f2-)
./scripts/smoke-test.sh
```

This checks the allow path on every surface. To exercise the deny path too,
set `TRUSTGATE_SMOKE_DENY_HOST` to a host your provider currently flags —
the script skips those cases when it is unset, rather than depending on a
hardcoded host whose verdict can change.

## Configuration

All knobs have safe defaults; a fresh install needs only an API key. Two
env-var namespaces exist on purpose: `TRUSTGATE_*` for tool-level settings
that apply no matter which provider is active, and `MALANTA_API_*` for
settings specific to the Malanta provider (they configure the vendor, not
the tool). Override via env vars (preferred) or
`~/.config/trustgate/config.json`.

Dotenv files load in this precedence (later overrides earlier), on every
platform — see `internal/config.EnvFiles`:

1. `/etc/trustgate/env` — fleet-managed installs (MDM payload); lowest
   precedence, the default for managed endpoints.
2. `~/.config/trustgate/env` — the file the installer writes.
3. `.env` in the working directory — dev convenience.

Process environment always wins last.

#### Core (`TRUSTGATE_*` — apply no matter which provider is active)

| Env var | JSON key | Default | Purpose |
| --- | --- | --- | --- |
| `TRUSTGATE_PROVIDER` | `provider` | `malanta` | `malanta` (default) or `generic` — see [`docs/providers.md`](docs/providers.md) |
| `TRUSTGATE_FAIL_CLOSED` | `fail_closed` | `true` | Deny on error/timeout/misconfiguration |
| `TRUSTGATE_MIN_MALICIOUS_SCORE` | `min_malicious_score_to_block` | `0.5` | Minimum malicious score (0..1 probability for Malanta, or a vendor-specific raw scale, e.g. VirusTotal's engine count) to turn a flagged verdict into a deny |
| `TRUSTGATE_BLOCK_LABELS` | `block_labels` | `MALICIOUS` | Case-insensitive deny list |
| `TRUSTGATE_ALLOW_LABELS` | `allow_labels` | _(empty)_ | Case-insensitive allow list (wins over block, regardless of score) |
| `TRUSTGATE_PROVIDER_MAX_CONCURRENCY` | `provider_max_concurrency` | _(unset)_ | Overrides in-flight-request concurrency for the CONFIGURED provider (Malanta's hardcoded 4, or the generic provider's own `max_concurrency`); unset leaves each provider's own value/default unchanged |
| `TRUSTGATE_CACHE_DIR` | `cache_dir` | `~/.cache/trustgate` | SQLite cache + decision log location |
| `TRUSTGATE_LOG_PATH` | `log_path` | `<cache_dir>/decisions.log` | JSON-Lines decision log path |
| _(none)_ | `positive_ttl_sec` | `3600` | Cache TTL for flagged verdicts |
| _(none)_ | `negative_ttl_sec` | `600` | Cache TTL for clean/low-confidence verdicts |
| `TRUSTGATE_ATR_DISABLE` | (env only) | `false` | Skip the ATR behavioral pass while leaving the reputation cascade active |
| `TRUSTGATE_ATR_RULES_DIR` | (env only) | _(unset)_ | Bring-your-own ATR rules directory — see [`docs/examples/atr-custom-rules/`](docs/examples/atr-custom-rules/README.md) |

#### Admin / policy (see [`docs/admin.md`](docs/admin.md) for the full write-up)

| Env var | JSON key | Default | Purpose |
| --- | --- | --- | --- |
| `TRUSTGATE_MODE` | `mode` | `warn` | `enforce` \| `report-only` \| `off` \| `warn` (default) \| `ask` — see [`docs/admin.md`](docs/admin.md) |
| `TRUSTGATE_POLICY_ALLOWLIST` | `policy_allowlist` | _(empty)_ | CSV of always-allowed indicator values (matched per scope — listing an owner does not pre-approve repositories under it) |
| `TRUSTGATE_ALLOW_USER_OVERRIDE` | `allow_user_override` | `false` | Admin opt-in for `trustgate override` to take effect |
| `TRUSTGATE_HELP_MESSAGE` | `help_message` | _(empty)_ | Appended to deny messages alongside the `decision_id` |
| `TRUSTGATE_AUDIT_SINK_URL` | `audit_sink_url` | _(empty)_ | Opt-in HTTPS collector for every decision |
| `TRUSTGATE_REQUIRE_CONFIGURED` | `require_configured` | `false` | Fail closed instead of inert-allow when unconfigured (no API key) |
| `TRUSTGATE_SCOPE_MODE` / `TRUSTGATE_SCOPE_PATHS` | `scope_mode` / `scope_paths` | `all` / _(empty)_ | Workspace/project scoping |
| `TRUSTGATE_WARN_ACK_MIN_SECONDS` | `warn_ack_min_seconds` | `4` | `warn` mode only — minimum seconds before a retry acknowledges a warn (a faster auto-retry re-warns); `0` disables |
| `TRUSTGATE_ASK_MIN_CURSOR_VERSION` | `ask_min_cursor_version` | `3.11.25` | `ask` mode only — minimum Cursor version that honors `permission:"ask"`; below it `ask` degrades to a hard deny |

See `docs/admin.md`'s own env var reference for further admin-only knobs
(`TRUSTGATE_TOOLUSE_STRICT`, `TRUSTGATE_OVERRIDE_SCOPE`,
`TRUSTGATE_LOCKED_KEYS`, and more) not repeated here.

#### Malanta provider (`MALANTA_API_*` — only read when `TRUSTGATE_PROVIDER=malanta`, the default)

| Env var | JSON key | Default | Purpose |
| --- | --- | --- | --- |
| `MALANTA_API_KEY` | (env only) | _required_ | Malanta API key |
| `MALANTA_API_BASE_URL` | `api_base_url` | `https://app.malanta.ai/data` | Malanta API base URL (override for staging) |
| `MALANTA_API_TIMEOUT_MS` | `api_timeout_ms` | `3000` | Per-request HTTP timeout — each hook is a fresh process with no warm connection pool, so a cold HTTPS round-trip regularly takes 300–700ms |
| `MALANTA_API_MAX_ATTEMPTS` | `api_max_attempts` | `2` | Retries once on a transient transport error, never on an auth error or real HTTP status |
| `MALANTA_API_HOST_ALLOWLIST` | `api_host_allowlist` | `app.malanta.ai` | Additive allowlist for `api_base_url`'s host |
| `MALANTA_API_BATCH_SIZE` | `api_batch_size` | `100` | Indicators per Malanta batch request; must be 1-100 (the API's own hard limit) |

#### Generic provider (any other vendor — only read when `TRUSTGATE_PROVIDER=generic`)

| Env var | JSON key | Default | Purpose |
| --- | --- | --- | --- |
| _(vendor's own, e.g. `VIRUSTOTAL_API_KEY`)_ | `generic_provider.auth.env_var` names it | _required_ | Vendor API key — see [`docs/providers.md`](docs/providers.md) |
| _(none)_ | `generic_provider` | _(unset)_ | Full config block (base URL, auth, endpoint mapping, allowed hosts) — see [`docs/providers.md`](docs/providers.md) |

## Decision log

Every verdict is appended to `~/.cache/trustgate/decisions.log` as one
JSON object per line:

```json
{"timestamp":"2026-07-06T15:55:00.123Z","hosts":["malicious.example"],"decision":{"decision_id":"a1b2c3d4e5f6","allow":false,"reason":"malanta flagged malicious.example as MALICIOUS (malicious score 0.9885)","provider":"malanta","indicator":"malicious.example","kind":"domain","label":"MALICIOUS","hook":"beforeShellExecution","mode":"enforce","duration_ms":54}}
```

The `hosts` array carries every inspected destination, including GitHub
`owner/repo` and bare-owner names; `kind` distinguishes them (`domain`,
`ipv4`, `github_repo`, `github_owner`).

The same decision is also written to a queryable SQLite audit table
(`~/.cache/trustgate/audit.db`) — see [`docs/admin.md`](docs/admin.md) for
`trustgate doctor`/`explain`, which read from it.

## Live API test

```bash
MALANTA_API_KEY=... make e2e   # gated behind //go:build e2e, not part of `make test`
```

Checks that a known-malicious domain, a known-benign domain, and (for a
provider with IP support) an IP each return a sensible label.

## Known limitations

- **Shell parsing is best-effort**: a minimal tokenizer + per-tool flag
  extractors + a permissive host regex. POSIX-quoting edge cases will be
  missed.
- **`beforeReadFile`** only scans an allowlist of high-risk paths
  (lockfiles, manifests, Dockerfiles, shell/Python/PowerShell scripts).
  Arbitrary source files are skipped to keep the hook fast.
- **No central fleet reporting beyond the opt-in audit sink**: decisions
  stay local in the JSON-Lines log and SQLite audit table by default;
  `TRUSTGATE_AUDIT_SINK_URL` (see [`docs/admin.md`](docs/admin.md)) forwards
  them to an HTTPS collector, but there's no built-in aggregation/dashboard
  on the receiving end — that's on the operator standing up the collector.
- **Key on disk**: the API key sits in an env file with mode `0600`
  (POSIX) / current-user-only ACL (Windows). Native OS keystore
  integration is a possible future upgrade, not built.
- **Windows (standalone installer) is verified** end to end with a live
  Cursor agent, but is exercised less than macOS; the Marketplace **plugin**
  path on Windows (which needs Git Bash/WSL) remains unverified — see
  [`docs/plugin.md`](docs/plugin.md).
- **Generic-adapter vendor configs are community/best-effort support**,
  not officially maintained — see [`SUPPORT.md`](SUPPORT.md).

## Support

Support differs across TrustGate's core components, the Malanta
integration, the generic-provider engine, provider-specific configs, and
the upstream ATR rules — the full support-tier policy is in
[`SUPPORT.md`](SUPPORT.md). For bugs and feature requests, open a GitHub
issue; for security vulnerabilities, use the private channel in
[`SECURITY.md`](SECURITY.md) instead.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the dev workflow and PR
expectations, [`SUPPORT.md`](SUPPORT.md) for the support-tier policy
(core vs. community-contributed vendor configs), and
[`SECURITY.md`](SECURITY.md) to report a vulnerability privately.

If you are an AI agent picking up this project, start with
[`AGENTS.md`](AGENTS.md) — it explains conventions and hard rules that
aren't obvious from the code alone.

## Disclaimer

TrustGate is a security tool, but no security tool can identify or prevent
every threat. You remain responsible for reviewing your configuration,
selecting an appropriate operating mode, protecting your provider
credentials, validating reputation-provider results, and maintaining
appropriate security controls.

TrustGate is a third-party plugin. **Publication on the Cursor Marketplace
does not constitute endorsement or certification by Anysphere.**

TrustGate is provided under the MIT License on an "as is" basis, without
warranties of any kind, whether express or implied, including warranties
of merchantability, fitness for a particular purpose, and non-infringement.
To the maximum extent permitted by applicable law, Malantai Ltd. and the
TrustGate authors and contributors will not be liable for any claim,
damages, or other liability arising from or relating to the software or its
use — including any security decision, reputation verdict, configuration,
failure to detect a threat, or action taken or not taken in reliance on
TrustGate.

Any separate Malanta reputation service is governed by the applicable
service terms and privacy information made available for that service.
Third-party reputation providers are governed by their own terms and
privacy notices, and Malantai Ltd. does not control their independent
services, pricing, availability, results, or data handling.

## License & notices

TrustGate's original code and documentation are licensed under the
[MIT License](LICENSE). Third-party software, data, and rules linked into
or bundled with the binaries remain subject to their own licenses and
notices — see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). The
vendored [Agent Threat Rules](https://agentthreatrule.org) snapshot under
`internal/atr/rules/` is separately MIT-licensed by its upstream project.

**Malantai**, **Malanta**, **TrustGate**, and their associated logos and
branding are trademarks of Malantai Ltd., addressed in
[`TRADEMARKS.md`](TRADEMARKS.md) — the MIT license covers the code, not the
marks.
