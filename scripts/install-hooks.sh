#!/usr/bin/env bash
# install-hooks.sh
#
# Build the five TrustGate hook binaries (shell, mcp, prompt, read-file,
# tool-use) plus the trustgate admin CLI, drop them under ~/.local/bin,
# install a hooks.json into ~/.cursor/, install the TrustGate agent skill
# into ~/.cursor/skills/ (so the agent interprets verdicts correctly), and
# store MALANTA_API_KEY securely at ~/.config/trustgate/env (mode 0600).
#
# This script is idempotent: re-running it overwrites the binaries,
# hooks.json, and the agent skill, but preserves any existing API key file
# unless --reset-key.
#
# Usage:
#   ./scripts/install-hooks.sh [--reset-key] [--no-agent-guidance]
#
#   --reset-key          Overwrite an existing ~/.config/trustgate/env
#                        API key file instead of leaving it in place.
#   --no-agent-guidance  Skip installing the TrustGate agent skill (and the
#                        rule note). The enforcement hooks are unaffected;
#                        this only omits the in-agent guidance that helps
#                        the agent read verdicts correctly.
#   --prebuilt           Don't build from source (no Go toolchain needed).
#                        Instead download the matching prebuilt binaries
#                        for this OS/arch from the internal binaries repo
#                        (malanta-ai/Malanta-TrustGate-Binaries), verify
#                        their SHA-256, and install those. Requires access
#                        to that private repo.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bin_dir="$HOME/.local/bin"
cfg_dir="$HOME/.config/trustgate"
cursor_dir="$HOME/.cursor"
key_file="$cfg_dir/env"

# Internal prebuilt-binaries repo (used only by --prebuilt).
binaries_repo_url="https://github.com/malanta-ai/Malanta-TrustGate-Binaries.git"

# Parse flags up front: --reset-key (key-file handling) is needed
# before the steps below run, not just at the end.
reset_key=0
install_guidance=1
prebuilt=0
for arg in "$@"; do
  case "$arg" in
    --reset-key) reset_key=1 ;;
    --no-agent-guidance) install_guidance=0 ;;
    --prebuilt) prebuilt=1 ;;
  esac
done

mkdir -p "$bin_dir" "$cfg_dir" "$cursor_dir"
chmod 700 "$cfg_dir"

# fetch_prebuilt downloads the matching prebuilt archive from the internal
# binaries repo, verifies every archive's SHA-256 against the repo's
# SHA256SUMS, and extracts this platform's executables into dist/ (so the
# install step below is identical to the build path). Used for --prebuilt
# so a developer without a Go toolchain can still install.
fetch_prebuilt() {
  local version os arch archive tmp rel
  version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' .cursor-plugin/plugin.json | head -1)"
  [ -n "$version" ] || { echo "error: could not read plugin version from .cursor-plugin/plugin.json" >&2; exit 1; }
  case "$(uname -s)" in
    Darwin) os=darwin ;;
    Linux)  os=linux ;;
    *) echo "error: --prebuilt supports macOS/Linux here; on Windows use install-hooks.ps1 -Prebuilt" >&2; exit 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64)  arch=amd64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) echo "error: unsupported arch $(uname -m)" >&2; exit 1 ;;
  esac
  archive="trustgate_${version}_${os}_${arch}.tar.gz"
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  echo "==> Fetching prebuilt binaries ($archive) from $binaries_repo_url"
  if ! git clone --depth 1 "$binaries_repo_url" "$tmp/bin" >/dev/null 2>&1; then
    echo "error: could not clone $binaries_repo_url — do you have access to that private repo?" >&2
    exit 1
  fi
  rel="$tmp/bin/v${version}"
  [ -f "$rel/$archive" ] || { echo "error: $archive not found in the binaries repo (v${version})" >&2; exit 1; }
  echo "==> Verifying SHA-256 checksums"
  if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$rel" && sha256sum -c SHA256SUMS >/dev/null ) || { echo "error: checksum verification failed" >&2; exit 1; }
  elif command -v shasum >/dev/null 2>&1; then
    ( cd "$rel" && shasum -a 256 -c SHA256SUMS >/dev/null ) || { echo "error: checksum verification failed" >&2; exit 1; }
  else
    echo "error: no sha256sum/shasum available to verify the download; refusing" >&2
    exit 1
  fi
  mkdir -p dist
  tar -xzf "$rel/$archive" -C dist/
}

if [[ $prebuilt -eq 1 ]]; then
  fetch_prebuilt
else
  if ! command -v go >/dev/null 2>&1; then
    godev_url="https://go"
    godev_url="${godev_url}.dev/dl/"
    echo "error: go toolchain not found on PATH. Install Go 1.25+ from ${godev_url} and retry, or re-run with --prebuilt to download prebuilt binaries instead." >&2
    exit 1
  fi
  echo "==> Building binaries"
  mkdir -p dist
  go build -o dist/ ./cmd/...
fi

binaries=(
  trustgate-before-prompt
  trustgate-before-shell
  trustgate-before-mcp
  trustgate-before-read-file
  trustgate-before-tool-use
  trustgate
)

echo "==> Installing binaries to $bin_dir"
for bin in "${binaries[@]}"; do
  install -m 0755 "dist/$bin" "$bin_dir/$bin"
done

echo "==> Writing hooks.json to $cursor_dir/hooks.json"
# The manifest template carries two substitution tokens:
#   HOME_PLACEHOLDER -> $HOME (cross-platform installer convention)
#   EXT_PLACEHOLDER  -> "" on macOS/Linux (".exe" on Windows; see install-hooks.ps1)
# Substitution is via bash parameter expansion (not sed) for consistency
# with install-hooks.ps1's equivalent -replace chain.
hooks_json="$(cat hooks.json)"
hooks_json="${hooks_json//HOME_PLACEHOLDER/$HOME}"
hooks_json="${hooks_json//EXT_PLACEHOLDER/}"
printf '%s\n' "$hooks_json" > "$cursor_dir/hooks.json"
chmod 600 "$cursor_dir/hooks.json"

# Install the TrustGate agent skill into the user-global skills dir so the
# agent loads it (on demand) whenever it hits a TrustGate verdict and reads
# it correctly — see docs/plugin.md's "Bundled agent guidance". This is the
# standalone counterpart to what the Marketplace plugin delivers
# automatically. ~/.cursor/skills/<name>/SKILL.md is the documented
# user-global skill path (the folder name must match the skill's frontmatter
# `name`, "trustgate"). The always-on RULE has no user-global file path in
# Cursor (file rules are project-scoped; global rules live only in
# Settings -> Customize -> Rules), so we can't drop it here — we point at it
# in the "Next steps" note instead.
skill_src="$repo_root/skills/trustgate/SKILL.md"
skill_dst_dir="$cursor_dir/skills/trustgate"
if [[ $install_guidance -eq 1 && -f "$skill_src" ]]; then
  echo "==> Installing agent skill to $skill_dst_dir"
  mkdir -p "$skill_dst_dir"
  install -m 0644 "$skill_src" "$skill_dst_dir/SKILL.md"
fi

# API key handling delegates to the trustgate CLI's own "setup"
# subcommand (cmd/trustgate/setup.go) rather than duplicating the
# prompt/write/chmod logic here -- one implementation, one set of tests.
# The existence check stays here (rather than always invoking `setup` and
# inspecting its exit code) so re-running this installer with an existing
# key file is a silent no-op, matching this script's documented
# idempotent behavior, instead of `set -e` aborting the whole install on
# setup's "already exists, pass --reset" refusal.
if [[ -f "$key_file" && $reset_key -eq 0 ]]; then
  echo "==> $key_file already exists; leaving in place (pass --reset-key to overwrite)"
elif [[ $reset_key -eq 1 ]]; then
  # Avoid `"${arr[@]}"` on an empty array: macOS ships bash 3.2 by
  # default (GPLv3 licensing), which treats that expansion as an
  # unbound variable under `set -u` even though bash 4.4+ doesn't.
  "$bin_dir/trustgate" setup --reset
else
  "$bin_dir/trustgate" setup
fi

cat <<EOF

Installed. Next steps:
  1. Restart Cursor so it picks up the new hooks.
  2. Try a benign action (open a project, ask a normal question).
  3. Tail the decision log to watch verdicts:
       tail -F $HOME/.cache/trustgate/decisions.log
  4. Run the smoke test against the live API:
       MALANTA_API_KEY=\$(grep -h ^MALANTA_API_KEY $key_file | cut -d= -f2-) \\
         ./scripts/smoke-test.sh
EOF

if [[ $install_guidance -eq 1 && -f "$repo_root/rules/trustgate-modes.mdc" ]]; then
  cat <<EOF

Agent guidance:
  - Installed the TrustGate skill at $skill_dst_dir/SKILL.md (loads on demand
    when the agent hits a verdict).
  - The always-on verdict-interpretation rule can't be installed as a global
    file (Cursor has no user-global rule file path). To make it always-on:
      * paste $repo_root/rules/trustgate-modes.mdc into
        Cursor -> Settings -> Customize -> Rules (User Rules), OR
      * copy it into a project's .cursor/rules/ for per-project scope.
    (Skipping this is fine — the skill already carries the key guidance.)
EOF
fi
