# The Cursor Marketplace plugin

This repository ships as **one repo, two distribution artifacts**:

1. The standalone installer (`scripts/install-hooks.sh`/`.ps1`) — build
   from source, install binaries to `~/.local/bin`, write
   `~/.cursor/hooks.json` directly. Works everywhere, including Windows.
2. A Cursor Marketplace **plugin** (`.cursor-plugin/plugin.json` +
   `hooks/`) — install via Cursor's plugin system instead of a shell
   script. **Currently macOS/Linux only** — see "Platform support" below.

Both distribute the exact same hook binaries built from the exact same
source; they differ only in how the binaries get onto your machine and
how Cursor discovers the hook manifest.

## Bundled agent guidance (plugin only)

The Marketplace plugin also bundles two agent-facing components, auto-
discovered at the plugin root and **delivered to the installing user**:

- `skills/trustgate/SKILL.md` — an operating guide the agent loads on
  demand when it hits a TrustGate verdict (how to read a verdict, diagnose
  a block, use overrides, configure, and recognize known false positives).
- `rules/trustgate-modes.mdc` — an always-on rule covering how to
  interpret a verdict per policy mode (an `allow` is not a clean
  reputation result — e.g. warn mode allows on acknowledged retry).

The Marketplace plugin delivers **both** automatically. The **standalone
installer** (`scripts/install-hooks.sh`/`.ps1`) now also installs the
**skill** by default — it copies `skills/trustgate/SKILL.md` to the
user-global `~/.cursor/skills/trustgate/` (skip with `--no-agent-guidance`
/ `-NoAgentGuidance`). The **rule** can't be auto-installed standalone:
Cursor has no user-global rule *file* path (file rules are project-scoped;
global rules live only in Settings → Customize → Rules), so the installer
prints instructions to paste it into User Rules or copy it into a project's
`.cursor/rules/`. The skill already carries the key verdict-interpretation
guidance, so this is optional. (`AGENTS.md` in the repo root is separate
again: it's guidance for agents working on this source, delivered by
neither install path.)

## How the plugin resolves its binaries

A plugin's `hooks/hooks.json` commands must be portable — they can't
reference `~/.local/bin/...` (nothing guarantees those binaries exist for
a marketplace install) or ship a raw compiled binary directly (Cursor
plugins are git repos, not binary bundles). So each event's `command`
points at a small wrapper script (`hooks/scripts/hook-*.sh`) that
resolves a working binary on demand, in this order:

1. **Cached**: `~/.cache/trustgate/plugin/<version>/<binary-name>`, if
   already resolved this session/version.
2. **Download + verify**: fetch the matching GitHub Release asset for
   your OS/arch, verify its SHA256 against the release's published
   `checksums.txt`, and — if the `cosign` CLI happens to be installed —
   verify a keyless cosign signature over `checksums.txt` too (see
   "Supply chain" below for why this is best-effort, not required).
3. **Build from source**: `go build` straight from this same checked-out
   repo (the plugin *is* the repo) if a Go toolchain is on `PATH`.

If all three fail, the wrapper script exits non-zero and Cursor's
`failClosed: true` on every enforcement event denies the action — the
library never fabricates a fake "allow" verdict on a resolution failure.
The one exception is `beforeSubmitPrompt`, registered `failClosed: false`
for the reason described in the README: a prompt-layer miss must never stop
you from submitting a prompt, and the execution hooks remain the
enforcement boundary regardless.

A `sessionStart` hook (`hooks/scripts/warmup.sh`) pre-resolves every hook
binary (shell, MCP, read-file, tool-use, prompt) plus the `trustgate`
admin CLI once per session, so the odds of the *first real* enforcement
call hitting the slow (download/build) path are low. The downloads run
detached (`hooks/scripts/warmup-worker.sh`) because resolving six binaries
can outlast this hook's timeout, and a warm-up killed halfway leaves
exactly the inline download it exists to prevent; Cursor treats
`sessionStart` as fire-and-forget, so returning early costs nothing.
The warm-up is explicitly `failClosed: false` and always exits 0 — a
warm-up miss just means the next real hook call resolves the binary
itself.

The same hook is where an unconfigured install announces itself. If the
CLI is already cached and reports no API key, the warm-up returns an
`additional_context` string telling the agent that TrustGate is inert and
what command fixes it. Without that, a user who never ran `setup` gets a
plugin that silently allows everything — the one failure mode a security
tool must not have.

## Supply chain

- **SHA256 checksum verification is always performed** for a downloaded
  binary, against the release's published `checksums.txt`. A mismatch is
  refused outright (never installed), with the wrapper falling back to
  building from source instead.
- **Cosign keyless signature verification is best-effort.** If the
  `cosign` CLI is present, the wrapper downloads the release's
  `checksums.txt.sigstore.json` bundle (cosign v3's combined
  certificate+signature format) and verifies it against
  `checksums.txt`, scoped to this repo's GitHub Actions OIDC identity —
  see [`.goreleaser.yaml`](../.goreleaser.yaml) and
  [`.github/workflows/release.yml`](../.github/workflows/release.yml) for
  how releases are signed. The CLI is looked up on `PATH` and in the
  standard install locations (`/opt/homebrew/bin`, `/usr/local/bin`,
  `~/go/bin`, `~/.local/bin`), because hooks are spawned by a GUI
  application and do not inherit your shell's `PATH`; set
  `TRUSTGATE_COSIGN_BIN` for anywhere else. If `cosign` is **not** found,
  the wrapper proceeds on checksum-only verification and prints a warning
  to stderr. This is a deliberate trade-off: requiring `cosign` as a hard
  dependency would break the "just works" install story for the common
  case where it isn't already on a developer's machine. **Known gap:** a
  network attacker who can both serve a malicious binary AND forge (or
  omit) `checksums.txt` in the same request, on a machine without
  `cosign` installed, is not caught by this scheme — HTTPS-to-github.com
  is the remaining defense in that scenario. Installing `cosign` closes
  this gap.
- **`TRUSTGATE_PLUGIN_REQUIRE_SIGNATURE=true` makes the signature
  mandatory** (default: unset, i.e. best-effort as above). With it set, a
  missing `cosign`, a release with no signature bundle, and a failed
  verification are all refusals rather than warnings — closing the gap
  described above at the cost of requiring `cosign` on every machine.
  Unlike TrustGate's other settings, this one is read straight from the
  env files by the wrapper script (`/etc/trustgate/env` and
  `~/.config/trustgate/env`) as well as the process environment, since it
  takes effect before any Go binary exists to read them; an MDM writing
  the system file turns it on fleet-wide. Also unlike the others, **any**
  layer that asks for signatures wins, so a per-user file cannot downgrade
  a system-wide requirement. A refusal still falls through to
  building from source, which needs no signature because it compiles the
  reviewed repository itself.
- **No silent auto-update — with a caveat.** The wrapper always resolves to
  the version pinned in `.cursor-plugin/plugin.json`; bumping that version (a
  normal plugin update via Cursor) is the only way the resolver targets a
  *different* asset. Note this pins the version, **not** asset immutability:
  GitHub allows a release's assets to be re-uploaded under the same tag, and
  the `checksums.txt` used to verify a download is served from the *same
  origin* as the asset, so an actor who controls that origin could serve a
  matching malicious pair. A committed-hash + mandatory-signature delivery
  model would close this; until that lands, prefer the build-from-source
  fallback for high-assurance installs.
- **Cached binaries are origin-checked.** A binary already in the
  per-version cache is re-used only if it is a plain regular file (not a
  symlink) owned by the current user, and the cache directory is
  user-private (mode 0700); anything else is treated as a tampered/pre-seeded
  cache entry and replaced by a fresh, verified download or build. This stops
  a different local user from planting an executable at the cache path.
- **Tested end to end against a local fake release**, not just reviewed:
  `make test-plugin-wrapper` (`scripts/test-ensure-binary.sh`) spins up a
  throwaway local HTTP server serving a fake binary + `checksums.txt` and
  exercises the happy path plus two negative cases (checksum mismatch,
  missing `checksums.txt`) with the `go` toolchain hidden from `PATH` so
  the build-from-source fallback can't mask a broken download-refusal
  path. Runs in CI on every PR (Linux/macOS).

## Local testing

There's no "Add Local Plugin" panel; the workflow is a filesystem copy or
symlink:

```bash
mkdir -p ~/.cursor/plugins/local
ln -s /path/to/Malanta-TrustGate ~/.cursor/plugins/local/malanta-trustgate
```

Then run **Developer: Reload Window** in Cursor and confirm the hooks
fire (ask it to fetch a URL; check `~/.cache/trustgate/decisions.log`).

## Submitting to the Marketplace

1. Make sure the repo is public (Marketplace plugins must be open source).
2. Submit at [cursor.com/marketplace/publish](https://cursor.com/marketplace/publish).
   Submissions are manually reviewed by Cursor.
3. If you have the `create-plugin` plugin installed, its
   `review-plugin-submission` skill is a useful final self-check before
   submitting (manifest validity, component discoverability, relative
   paths only, README quality).

## Team / Enterprise import

Cursor Dashboard → Plugins → **Import from Repo**, pointing at this
repository. Enable **Auto Refresh** (requires the Cursor GitHub App
to be installed on the repo) so a new tagged release rolls out without
each developer re-importing manually.

## Onboarding and the API key

The plugin artifact is **key-free** — the reputation provider's API key
is never committed, embedded in the plugin, or placed in any
Cursor-managed field. You store it yourself with `trustgate setup`, which
writes `~/.config/trustgate/env`, the same file the plugin's
wrapper-resolved hook binaries read.

The CLI that runs `setup` comes with the plugin: the session-start
warm-up resolves it alongside the hook binaries, so after your first
session it is at

```bash
~/.cache/trustgate/plugin/<version>/trustgate setup
```

with `<version>` matching the manifest. Until a key is stored, the
warm-up reminds the agent at the start of every session that TrustGate is
inert, and names that path.

Two other routes to the same CLI, if you'd rather not use a cache path:
`go install github.com/malanta-ai/Malanta-TrustGate/cmd/trustgate@latest`
(needs a Go toolchain), or the standalone installer, which puts it on
`PATH` at `~/.local/bin/trustgate`.

Enterprises: an MDM profile that writes `/etc/trustgate/env` (see the
root README's Configuration section) works identically regardless of
which distribution artifact developers use — the env-file precedence
chain doesn't care how the binary got onto the machine.

## Platform support

The plugin's wrapper scripts (`hooks/scripts/*.sh`) are POSIX shell.
**macOS and Linux are fully supported.** Windows works if Git Bash or
WSL provides a `bash` on `PATH` that Cursor's plugin host can invoke;
this is **not yet verified**. Until it is, Windows users should prefer
the standalone installer (`scripts/install-hooks.ps1`), which is
native PowerShell and has no such dependency. If you get the plugin
working on stock Windows (no Git Bash/WSL), please open a PR — see
[`CONTRIBUTING.md`](../CONTRIBUTING.md).
