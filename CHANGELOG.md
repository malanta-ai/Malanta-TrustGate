# Changelog

All notable changes to Malanta TrustGate are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
