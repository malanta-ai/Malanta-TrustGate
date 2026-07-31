#!/usr/bin/env bash
# ensure-binary.sh — shared logic for the plugin's per-event hook wrapper
# scripts (hooks/scripts/hook-*.sh). Sourced, never executed directly.
#
# ensure_binary <binary-name> resolves (downloading or building as needed)
# a working copy of one of this repo's cmd/<binary-name> binaries and
# prints its absolute path to stdout. Callers should `exec` that path so
# stdin/stdout/exit-code pass through to Cursor unchanged.
#
# Resolution order, each step verified before use:
#   1. Already-cached binary at ~/.cache/trustgate/plugin/<version>/<name>.
#   2. Download the matching GitHub Release asset for this OS/arch +
#      verify its SHA256 against the release's published checksums.txt,
#      then (best-effort, only if the `cosign` CLI is present) verify a
#      cosign keyless signature over checksums.txt. Missing cosign is a
#      warning, not a hard failure — see docs/plugin.md's Supply Chain
#      section for the trade-off this accepts (checksum-only fallback
#      rather than requiring a new hard dependency for the "just works"
#      install story). Set TRUSTGATE_PLUGIN_REQUIRE_SIGNATURE=true to
#      invert that trade-off and refuse anything unsigned.
#   3. `go build` from this same checked-out repo (the plugin IS the
#      repo — see docs/plugin.md) if a Go toolchain is on PATH.
#
# On total failure, prints nothing to stdout and returns non-zero; the
# calling wrapper script exits non-zero, and Cursor's failClosed: true on
# every event in hooks.json denies the action — this library never
# emits a hook JSON verdict itself, it only resolves a binary.
set -uo pipefail

_trustgate_plugin_root() {
  if [[ -n "${CURSOR_PLUGIN_ROOT:-}" ]]; then
    printf '%s\n' "${CURSOR_PLUGIN_ROOT%/}"
    return 0
  fi
  # Fallback for local testing outside Cursor (see docs/plugin.md's
  # "Local testing" section): lib/ -> scripts/ -> hooks/ -> plugin root.
  ( cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd )
}

_trustgate_plugin_version() {
  local manifest="$1/.cursor-plugin/plugin.json"
  local v
  v="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" 2>/dev/null | head -1)"
  printf '%s\n' "${v:-0.0.0-unknown}"
}

_trustgate_os() {
  case "$(uname -s)" in
    Darwin) echo darwin ;;
    Linux)  echo linux ;;
    *)      echo unknown ;;
  esac
}

_trustgate_arch() {
  case "$(uname -m)" in
    x86_64|amd64)   echo amd64 ;;
    arm64|aarch64)  echo arm64 ;;
    *)              echo unknown ;;
  esac
}

# _trustgate_sha256 <file> — prints the hex digest, using whichever tool
# is available (macOS ships shasum, most Linux distros ship sha256sum).
_trustgate_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    return 1
  fi
}

# _trustgate_find_cosign — prints an invocable cosign path, or returns 1.
#
# PATH alone is not enough here. Hooks are spawned by a GUI application,
# which on macOS inherits launchd's minimal PATH rather than the user's
# shell PATH, so a perfectly good cosign in /opt/homebrew/bin or ~/go/bin
# is invisible and every download silently degrades to checksum-only —
# the weaker path, taken by the users who did the right thing and
# installed cosign. Probing the standard locations costs one stat each.
#
# TRUSTGATE_COSIGN_BIN overrides the search entirely, for a cosign kept
# somewhere non-standard (and for tests, which use it to simulate absence).
_trustgate_find_cosign() {
  if [[ -n "${TRUSTGATE_COSIGN_BIN:-}" ]]; then
    [[ -x "${TRUSTGATE_COSIGN_BIN}" ]] || return 1
    printf '%s\n' "${TRUSTGATE_COSIGN_BIN}"
    return 0
  fi
  if command -v cosign >/dev/null 2>&1; then
    command -v cosign
    return 0
  fi
  local candidate
  for candidate in \
      /opt/homebrew/bin/cosign \
      /usr/local/bin/cosign \
      "$HOME/go/bin/cosign" \
      "$HOME/.local/bin/cosign" \
      /home/linuxbrew/.linuxbrew/bin/cosign; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

# _trustgate_require_signature — true when a downloaded binary must carry a
# verified cosign signature, so a missing cosign CLI or signature bundle is
# a refusal instead of the default warning.
#
# Default OFF: requiring it would turn a one-click plugin install into
# "first install Sigstore." An operator who wants the strong guarantee
# fleet-wide sets TRUSTGATE_PLUGIN_REQUIRE_SIGNATURE=true.
#
# Read from the process environment AND the env files the Go binaries
# already read, because this resolver runs before any of them and an MDM
# writing /etc/trustgate/env is the whole point. Deliberately NOT the usual
# last-layer-wins precedence: any layer asking for signatures wins, so a
# per-user file cannot quietly downgrade a system-wide requirement. Only
# this one key is read — the files also hold the API key, which has no
# business in this process.
_trustgate_require_signature() {
  local v file
  for v in "${TRUSTGATE_PLUGIN_REQUIRE_SIGNATURE:-}" \
           "$(_trustgate_env_file_value "$HOME/.config/trustgate/env")" \
           "$(_trustgate_env_file_value /etc/trustgate/env)"; do
    case "$v" in
      [Tt][Rr][Uu][Ee]|1|[Yy][Ee][Ss]) return 0 ;;
    esac
  done
  return 1
}

# _trustgate_env_file_value <file> — prints the last value assigned to
# TRUSTGATE_PLUGIN_REQUIRE_SIGNATURE in a dotenv-style file, ignoring
# comments and surrounding quotes. Never sources the file.
_trustgate_env_file_value() {
  local file="$1"
  [[ -r "$file" ]] || return 0
  sed -n 's/^[[:space:]]*TRUSTGATE_PLUGIN_REQUIRE_SIGNATURE[[:space:]]*=[[:space:]]*//p' "$file" \
    | tail -1 | tr -d '"'"'" | awk '{print $1}'
}

# _trustgate_owned_by_me <path> — true if path is owned by the current uid.
# Best-effort: if neither stat flavor is available, returns true (don't
# block on a missing tool). Used to reject a cache entry a DIFFERENT local
# user pre-seeded.
_trustgate_owned_by_me() {
  local p="$1" owner
  if owner="$(stat -f '%u' "$p" 2>/dev/null)"; then :         # BSD / macOS
  elif owner="$(stat -c '%u' "$p" 2>/dev/null)"; then :       # GNU / Linux
  else return 0; fi
  [[ "$owner" == "$(id -u)" ]]
}

# _trustgate_cached_binary_trustworthy <cache_dir> <bin_path> — true only if
# the cached binary is safe to exec WITHOUT re-verification: it
# must be a regular file (not a symlink an attacker pointed at their own
# payload), executable, and both it and its containing version dir must be
# owned by the current user. Anything else means the cache was tampered
# with or pre-seeded by another user, so we fall through to a fresh,
# verified download / build instead of trusting it.
_trustgate_cached_binary_trustworthy() {
  local cache_dir="$1" bin_path="$2"
  [[ -f "$bin_path" && ! -L "$bin_path" && -x "$bin_path" ]] || return 1
  _trustgate_owned_by_me "$cache_dir" || return 1
  _trustgate_owned_by_me "$bin_path" || return 1
  return 0
}

# _trustgate_download_verified <name> <version> <os> <arch> <out-path>
# Downloads the release asset + checksums.txt, verifies the SHA256, and
# (best-effort) a cosign signature. Moves the verified binary to <out-path>
# and chmod +x's it on success. Returns non-zero on ANY verification
# failure — never installs an unverified or mismatched binary.
_trustgate_download_verified() {
  local name="$1" version="$2" os="$3" arch="$4" out="$5"
  command -v curl >/dev/null 2>&1 || return 1

  local asset="${name}_${os}_${arch}"
  # TRUSTGATE_PLUGIN_RELEASE_BASE_URL is a TEST-ONLY override (see
  # scripts/test-ensure-binary.sh / CI) that lets the download+verify
  # path be exercised end-to-end against a local fake release server
  # instead of the real GitHub Releases URL. Unset in every real install.
  local base_url="${TRUSTGATE_PLUGIN_RELEASE_BASE_URL:-https://github.com/malanta-ai/Malanta-TrustGate/releases/download/v${version}}"
  local tmp_dir
  tmp_dir="$(mktemp -d)" || return 1
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp_dir'" RETURN

  if ! curl -fsSL --max-time 20 -o "$tmp_dir/$asset" "$base_url/$asset" 2>/dev/null; then
    return 1
  fi
  if ! curl -fsSL --max-time 20 -o "$tmp_dir/checksums.txt" "$base_url/checksums.txt" 2>/dev/null; then
    echo "trustgate plugin: downloaded $asset but checksums.txt is unavailable; refusing to trust an unverified binary" >&2
    return 1
  fi

  local expected actual
  expected="$(grep " ${asset}\$" "$tmp_dir/checksums.txt" | awk '{print $1}')"
  if [[ -z "$expected" ]]; then
    echo "trustgate plugin: $asset is not listed in the release's checksums.txt; refusing" >&2
    return 1
  fi
  actual="$(_trustgate_sha256 "$tmp_dir/$asset")" || {
    echo "trustgate plugin: no sha256sum/shasum available to verify the download; refusing" >&2
    return 1
  }
  if [[ "$expected" != "$actual" ]]; then
    echo "trustgate plugin: checksum mismatch for $asset (expected $expected, got $actual) — possible tampering; refusing" >&2
    return 1
  fi

  # Best-effort cosign keyless verification, using cosign v3's bundle
  # format (a single .sigstore.json combining the certificate and
  # signature — see .goreleaser.yaml). See the file header comment for
  # why a missing `cosign` CLI degrades to a warning rather than a hard
  # failure.
  local cosign_bin require_sig=1
  _trustgate_require_signature && require_sig=0
  if cosign_bin="$(_trustgate_find_cosign)"; then
    if curl -fsSL --max-time 20 -o "$tmp_dir/checksums.txt.sigstore.json" "$base_url/checksums.txt.sigstore.json" 2>/dev/null; then
      if ! "$cosign_bin" verify-blob \
          --bundle "$tmp_dir/checksums.txt.sigstore.json" \
          --certificate-identity-regexp '^https://github\.com/malanta-ai/Malanta-TrustGate/' \
          --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
          "$tmp_dir/checksums.txt" >/dev/null 2>"$tmp_dir/cosign.err"; then
        echo "trustgate plugin: cosign signature verification FAILED for checksums.txt — refusing (see $(cat "$tmp_dir/cosign.err" 2>/dev/null))" >&2
        return 1
      fi
    elif [[ $require_sig -eq 0 ]]; then
      echo "trustgate plugin: TRUSTGATE_PLUGIN_REQUIRE_SIGNATURE is set but this release has no signature bundle for $asset; refusing" >&2
      return 1
    else
      echo "trustgate plugin: cosign is installed but this release has no signature bundle; proceeding on SHA256-only verification" >&2
    fi
  elif [[ $require_sig -eq 0 ]]; then
    echo "trustgate plugin: TRUSTGATE_PLUGIN_REQUIRE_SIGNATURE is set but no cosign CLI was found (PATH, standard locations, or TRUSTGATE_COSIGN_BIN); refusing to install $asset on checksum-only verification" >&2
    return 1
  else
    # Say so when the download was verified by same-origin checksum only
    # (no independent signature). Install cosign, or use the
    # build-from-source fallback, for a stronger guarantee. See
    # docs/plugin.md's Supply Chain section.
    echo "trustgate plugin: cosign not found on PATH or in the standard install locations — $asset verified by SHA256 against same-origin checksums.txt only (no signature check). See docs/plugin.md." >&2
  fi

  mv "$tmp_dir/$asset" "$out" || return 1
  chmod +x "$out"
  return 0
}

# trustgate_cached_binary <name> — prints the path to an already-cached,
# trustworthy copy of <name>, or returns 1. Never downloads and never
# builds, so a caller that only wants a binary IF it is already free can
# ask without paying for one.
trustgate_cached_binary() {
  local name="$1" plugin_root version cache_dir bin_path
  plugin_root="$(_trustgate_plugin_root)"
  version="$(_trustgate_plugin_version "$plugin_root")"
  cache_dir="${TRUSTGATE_PLUGIN_CACHE_DIR:-$HOME/.cache/trustgate/plugin/$version}"
  bin_path="$cache_dir/$name"
  _trustgate_cached_binary_trustworthy "$cache_dir" "$bin_path" || return 1
  printf '%s\n' "$bin_path"
}

# ensure_binary <name> — see file header.
ensure_binary() {
  local name="$1"
  local plugin_root version os arch cache_dir bin_path
  plugin_root="$(_trustgate_plugin_root)"
  version="$(_trustgate_plugin_version "$plugin_root")"
  os="$(_trustgate_os)"
  arch="$(_trustgate_arch)"
  cache_dir="${TRUSTGATE_PLUGIN_CACHE_DIR:-$HOME/.cache/trustgate/plugin/$version}"
  bin_path="$cache_dir/$name"

  mkdir -p "$cache_dir" 2>/dev/null
  # Keep the version cache dir user-private so another local user
  # can't drop a payload into it between resolution runs.
  chmod 700 "$cache_dir" 2>/dev/null || true

  # Only trust a cached binary that we own and that is a plain
  # regular file — never a symlink or another user's file pre-seeded at
  # this path. An untrustworthy cache entry falls through to a fresh,
  # verified download / build below (which overwrites it).
  if _trustgate_cached_binary_trustworthy "$cache_dir" "$bin_path"; then
    printf '%s\n' "$bin_path"
    return 0
  fi

  if [[ "$os" != unknown && "$arch" != unknown ]] \
      && _trustgate_download_verified "$name" "$version" "$os" "$arch" "$bin_path"; then
    printf '%s\n' "$bin_path"
    return 0
  fi

  if command -v go >/dev/null 2>&1; then
    if go build -o "$bin_path" "$plugin_root/cmd/$name" 2>>"$cache_dir/build.log"; then
      chmod +x "$bin_path"
      printf '%s\n' "$bin_path"
      return 0
    fi
    echo "trustgate plugin: go build fallback failed for $name; see $cache_dir/build.log" >&2
  else
    echo "trustgate plugin: no cached or downloadable binary for $name, and no Go toolchain on PATH to build from source" >&2
  fi
  return 1
}
