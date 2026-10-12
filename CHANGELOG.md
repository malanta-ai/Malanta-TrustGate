# Changelog

All notable changes to Malanta TrustGate are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] — 2026-10-12

### Security

- **Bumped `golang.org/x/net` to `v0.60.0` and the build toolchain to
  `go1.26.9`,** clearing six advisories `govulncheck` reports as
  reachable through `internal/auditsink`'s HTTP client. Five are HTTP/2
  issues in `golang.org/x/net` (GO-2026-6617 HPACK encoder race,
  GO-2026-6612 double flow-control refund, GO-2026-6611 CPU consumption
  from repeated window changes, GO-2026-6610 malformed framing headers);
  two are standard-library issues fixed in `go1.26.9` (GO-2026-6613 /
  CVE-2026-94439 HTTP/1 connection desynchronization after a 2xx
  CONNECT, and GO-2026-6608 / CVE-2026-94440 memory-limit bypass parsing
  MIME headers). All are server- and transport-side exposure on the
  optional audit-sink path rather than the hook verdict path, and
  `govulncheck` now reports no findings.

### Fixed

- **A file larger than 256 KiB no longer blocks its own read.** Cursor
  sends file contents inline, and the hook runner's stdin bound truncated
  any larger payload mid-JSON; the resulting decode error surfaced as
  `payload: unexpected EOF` and denied the read. Large lockfiles — the
  files this hook most wants to inspect — were the common casualty. The
  read-file hook now carries its own 2 MiB bound, clearing the
  extractor's existing 1 MiB content cap with room for JSON escaping, so
  content in that range is scanned and content above it takes the
  extractor's documented skip-and-allow path. Every other hook keeps the
  256 KiB default. A payload that still exceeds the bound now names the
  size in the logged reason instead of only `unexpected EOF`.
- **Hook errors respect the policy mode.** The bootstrap path (config
  load, payload decode, cache open) decided allow/deny from
  `fail_closed` alone, without consulting the mode, so an error
  hard-denied in `warn` while the decision log labelled it `warn`. It
  also bypassed the stage that records warn's pending marker, so the
  documented deny-once-then-allow-on-retry never happened — retrying
  reproduced the identical error and left no way to clear the block.
  These failures now apply the same mode policy as a provider error:
  `warn` fails open with the error recorded as a warning, `report-only`
  never blocks, and `enforce` keeps the fail-closed deny. Malformed
  input remains a deny under `fail_closed` on every hook, including
  `beforeSubmitPrompt`.

## [0.1.3] — 2026-09-09

No change to hook behavior. This release rebuilds the binaries on a Go
toolchain carrying the standard library fixes below; the `0.1.2` binaries
were built on `go1.26.5` and predate them.

### Added

- **Documented the team-marketplace rollout path** in `docs/plugin.md`, for
  organizations that want TrustGate on their developers' machines without
  waiting on a public marketplace listing.

### Security

- **Bumped the build toolchain to `go1.26.8`.** Clears four Go standard
  library advisories, all fixed in `1.26.6`, that `govulncheck` reports as
  reachable from TrustGate's code: quadratic `resolvePath` in `net/url`
  (CVE-2026-56860), unbounded post-handshake messages in `crypto/tls`
  (CVE-2026-56862), unbounded recursion depth in `encoding/asn1`
  (CVE-2026-33818), and punycode label handling in `net/http`'s vendored
  `x/net/idna` (CVE-2026-39821). All four are denial-of-service class. The
  direct `golang.org/x/net` dependency was already at `v0.57.0`, past the
  idna fix, so domain normalization was never affected — only the older
  copy vendored into the standard library.

## [0.1.2] — 2026-07-31

No change to hook behavior — the binaries are functionally identical to
`0.1.1`, differing only in the version they report; nothing under `cmd/`,
`internal/`, or `go.mod` changed. This release exists so the plugin's binary
resolver, which downloads from the release tag named by the manifest version,
ships against a tag whose source matches it.

### Added

- **`TRUSTGATE_PLUGIN_REQUIRE_SIGNATURE=true` makes cosign verification
  mandatory** for plugin binary downloads (default off). A missing cosign,
  an unsigned release, or a failed verification becomes a refusal instead
  of a warning, closing the same-origin gap where an actor who can serve a
  malicious binary can serve a matching `checksums.txt`. Off by default
  because requiring it would turn a one-click install into "first install
  Sigstore"; on, it is the fleet-wide guarantee an enterprise wants. The
  wrapper reads it from `/etc/trustgate/env` and `~/.config/trustgate/env`
  as well as the process environment, since it applies before any Go
  binary exists to read config — and any layer that asks for signatures
  wins, so a per-user file cannot downgrade an MDM-set requirement.
  `TRUSTGATE_COSIGN_BIN` points at a cosign kept outside the standard
  locations.

### Changed

- **cosign is found where it is actually installed.** The plugin resolver
  looked for the CLI on `PATH` only. Hooks are spawned by a GUI
  application, which on macOS inherits launchd's minimal `PATH` rather
  than the user's shell `PATH`, so a cosign in `/opt/homebrew/bin` or
  `~/go/bin` was invisible and every download silently degraded to
  checksum-only verification — penalizing exactly the users who installed
  cosign. It now probes the standard locations before giving up.
- **The session-start warm-up no longer loses downloads.** It resolved
  every binary inside a hook Cursor kills at its timeout, so some were
  left unresolved and the first MCP call or file read paid an inline
  download inside a fail-closed hook. The work is now detached and
  outlives the timeout, which `sessionStart` permits because it is
  fire-and-forget.
- **Configuring an API key no longer needs a Go toolchain.** The warm-up
  resolves the `trustgate` CLI alongside the hook binaries, so
  `trustgate setup` is available from the plugin's own cache. When no key
  is configured, the warm-up now returns an `additional_context` notice
  saying so: an unconfigured TrustGate allows every action, and that was
  previously silent.

## [0.1.1] — 2026-07-31

No change to hook behavior — the binaries are functionally identical to
`0.1.0`. This release exists so the packaging fixes below ship against a
tag whose source matches them exactly.

### Added

- **The plugin registers `beforeSubmitPrompt`.** It wired only the four
  execution hooks, so a plugin user in `warn` mode — the default — silently
  lost the prompt-layer early warning the README documents. Registered
  `failClosed: false`, because a prompt-layer miss must never stop you from
  submitting a prompt, and the `sessionStart` warm-up now pre-resolves its
  binary too.

### Changed

- **`--prebuilt` / `-Prebuilt` install from this repository's signed
  release.** Both installers previously cloned a separate private binaries
  repo, which was unreachable for anyone outside the org. They now download
  the same artifacts the plugin resolver uses, verifying each binary against
  the release's `checksums.txt` and, when the `cosign` CLI is present, the
  signature over that file.

### Fixed

- **The Marketplace listing's logo now renders.** The manifest declared it
  under `icon`, but Cursor's plugin schema reads `logo`.

## [0.1.0] — 2026-07-30

First public release. TrustGate checks where an AI coding agent is about to
send bytes — before it sends them — against a reputation provider, and blocks
the action when the destination is flagged.

### Added

- **Five Cursor hook binaries**, one per event: `beforeShellExecution`,
  `beforeMCPExecution`, `beforeReadFile`, `preToolUse` (`WebFetch` /
  `WebSearch`), and `beforeSubmitPrompt`. Each is a short-lived Go process
  that reads a JSON payload on stdin and writes a single-line verdict to
  stdout. Fail-closed by default on the four execution hooks; the prompt hook
  fails open so a hiccup can never stop you from typing.
- **Destination extraction** for domains, IP addresses, and GitHub
  repository/owner names, from shell commands (including the body of a script
  or dependency manifest the command names in its own arguments), MCP server
  URLs and tool arguments, built-in tool input, high-risk file contents, and
  prompt text.
- **Pluggable reputation providers.** Malanta is the compiled-in default; any
  REST vendor can be wired in with a JSON config, no code, via the generic
  adapter. See [`docs/providers.md`](docs/providers.md).
- **Four operating modes** — `warn`, `ask`, `enforce`, `report-only` (plus
  `off`) — so a team can roll out from observation to enforcement without
  changing binaries. See [`docs/admin.md`](docs/admin.md).
- **Agent Threat Rules (ATR)**, a behavioral detection pass over shell, MCP,
  and file-read surfaces, with a vendored ruleset and a bring-your-own rules
  directory.
- **Self-service overrides.** `trustgate override` grants a time-boxed,
  audited bypass by `--domain`, `--repo`, or `--owner`, so a false positive
  costs a developer seconds rather than a support ticket.
- **Local-only storage**: a SQLite TTL verdict cache and a JSON Lines
  decision log, both under the user's home directory. `trustgate export`
  dumps recorded decisions; `trustgate status` and `trustgate doctor` report
  configuration and health.
- **Installers** for macOS/Linux (`scripts/install-hooks.sh`) and Windows
  (`scripts/install-hooks.ps1`), which build the binaries, wire
  `hooks.json`, and install the agent skill and rule that teach an agent how
  to behave when TrustGate blocks something.
