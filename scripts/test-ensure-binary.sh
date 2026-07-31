#!/usr/bin/env bash
# test-ensure-binary.sh
#
# Exercises hooks/scripts/lib/ensure-binary.sh's download-and-verify path
# end to end against a local fake release server, since no real GitHub
# release exists to test against otherwise (see docs/plugin.md's Supply
# Chain section). Covers:
#   1. Happy path: correct binary + correct checksums.txt -> accepted.
#   2. Checksum-mismatch: corrupted checksums.txt -> REFUSED (never
#      installs an unverified/mismatched binary).
#   3. Missing checksums.txt -> REFUSED (never trusts an unverified
#      download even if the binary itself downloaded fine).
#
# Run via `make test-plugin-wrapper` or directly. Requires python3 (for a
# throwaway static file server) and a POSIX shell with sha256sum/shasum.

set -euo pipefail
set +m # disable job-control "Terminated" notices for the background test servers

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=lib/ensure-binary.sh
source "$repo_root/hooks/scripts/lib/ensure-binary.sh"

fail_count=0
work_dir="$(mktemp -d)"
trap 'kill "${server_pid:-0}" 2>/dev/null || true; rm -rf "$work_dir"' EXIT

release_dir="$work_dir/release"
mkdir -p "$release_dir"

os="$(_trustgate_os)"
arch="$(_trustgate_arch)"
if [[ "$os" == unknown || "$arch" == unknown ]]; then
  echo "test-ensure-binary: unsupported OS/arch for this test ($(uname -s)/$(uname -m)); skipping" >&2
  exit 0
fi

fake_binary_name="fake-trustgate-tool_${os}_${arch}"
cat > "$release_dir/$fake_binary_name" <<'EOF'
#!/bin/sh
echo '{"permission":"allow"}'
EOF
chmod +x "$release_dir/$fake_binary_name"

sha256() { _trustgate_sha256 "$1"; }
real_hash="$(sha256 "$release_dir/$fake_binary_name")"
echo "$real_hash  $fake_binary_name" > "$release_dir/checksums.txt"

# wait_for_server <url>: polls until url responds or ~5s elapse. Avoids
# depending on http.server's startup banner, which some Python versions
# (observed: 3.14) don't print at all when stdout is redirected — a
# fixed/known port + readiness poll is far more portable than screen-
# scraping a log line for an ephemeral port number.
wait_for_server() {
  local url="$1"
  for _ in $(seq 1 50); do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# A random-ish high port per run reduces (but doesn't eliminate) the odds
# of colliding with something else already listening; the readiness poll
# below tolerates a slow-starting server either way.
port=$(( (RANDOM % 10000) + 20000 ))
base_url="http://127.0.0.1:${port}"

echo "==> Starting local fake release server on port $port"
python3 -m http.server "$port" --directory "$release_dir" --bind 127.0.0.1 \
  > "$work_dir/server.log" 2>&1 &
server_pid=$!
if ! wait_for_server "$base_url/checksums.txt"; then
  echo "test-ensure-binary: fake release server never became ready" >&2
  cat "$work_dir/server.log" >&2 || true
  exit 1
fi
echo "==> Fake release server at $base_url"

assert_success() {
  local desc="$1" cache_dir="$2"
  local out
  mkdir -p "$cache_dir"
  if out="$(TRUSTGATE_PLUGIN_RELEASE_BASE_URL="$base_url" TRUSTGATE_PLUGIN_CACHE_DIR="$cache_dir" \
      ensure_binary fake-trustgate-tool 2>"$cache_dir/stderr.log")"; then
    if [[ -x "$out" ]]; then
      echo "PASS: $desc"
    else
      echo "FAIL: $desc — ensure_binary reported success but $out is not executable"
      fail_count=$((fail_count + 1))
    fi
  else
    echo "FAIL: $desc — ensure_binary failed (see $cache_dir/stderr.log)"
    cat "$cache_dir/stderr.log" >&2
    fail_count=$((fail_count + 1))
  fi
}

assert_refused() {
  local desc="$1" cache_dir="$2"
  mkdir -p "$cache_dir"
  # Hide `go` from PATH for this assertion so a refused download can't be
  # silently masked by the build-from-source fallback — we want to prove
  # the DOWNLOAD path itself refused, not just that ensure_binary overall
  # eventually succeeded via a different route.
  local stripped_path
  stripped_path="$(printf '%s' "$PATH" | tr ':' '\n' | grep -v -E '/go(/bin)?$' | paste -sd: -)"
  if out="$(PATH="$stripped_path" TRUSTGATE_PLUGIN_RELEASE_BASE_URL="$base_url" TRUSTGATE_PLUGIN_CACHE_DIR="$cache_dir" \
      ensure_binary fake-trustgate-tool 2>"$cache_dir/stderr.log")"; then
    echo "FAIL: $desc — expected ensure_binary to refuse, but it succeeded with $out"
    fail_count=$((fail_count + 1))
  else
    echo "PASS: $desc (refused as expected: $(tail -1 "$cache_dir/stderr.log"))"
  fi
}

echo "=== 1. Happy path ==="
assert_success "correct binary + correct checksums.txt is accepted" "$work_dir/cache-happy"

echo "=== 2. Checksum mismatch ==="
mismatch_dir="$work_dir/release-mismatch"
mkdir -p "$mismatch_dir"
cp "$release_dir/$fake_binary_name" "$mismatch_dir/"
echo "0000000000000000000000000000000000000000000000000000000000000000  $fake_binary_name" > "$mismatch_dir/checksums.txt"
port2=$(( (RANDOM % 10000) + 30000 ))
base_url="http://127.0.0.1:${port2}"
python3 -m http.server "$port2" --directory "$mismatch_dir" --bind 127.0.0.1 > "$work_dir/server2.log" 2>&1 &
server2_pid=$!
if ! wait_for_server "$base_url/checksums.txt"; then
  echo "test-ensure-binary: mismatch server never became ready" >&2
  exit 1
fi
assert_refused "a checksum mismatch is refused" "$work_dir/cache-mismatch"
kill "$server2_pid" 2>/dev/null || true

echo "=== 3. Missing checksums.txt ==="
nockcheck_dir="$work_dir/release-nocheck"
mkdir -p "$nockcheck_dir"
cp "$release_dir/$fake_binary_name" "$nockcheck_dir/"
port3=$(( (RANDOM % 10000) + 40000 ))
base_url="http://127.0.0.1:${port3}"
python3 -m http.server "$port3" --directory "$nockcheck_dir" --bind 127.0.0.1 > "$work_dir/server3.log" 2>&1 &
server3_pid=$!
if ! wait_for_server "$base_url/$fake_binary_name"; then
  echo "test-ensure-binary: nocheck server never became ready" >&2
  exit 1
fi
assert_refused "a missing checksums.txt is refused" "$work_dir/cache-nocheck"
kill "$server3_pid" 2>/dev/null || true

echo "=== 4. TRUSTGATE_PLUGIN_REQUIRE_SIGNATURE with no cosign ==="
# Point the cosign lookup at a path that cannot exist, so the assertion is
# about the flag rather than about whatever the test machine happens to
# have installed. The fake release serves no signature bundle either way.
base_url="http://127.0.0.1:${port}"
require_cache="$work_dir/cache-require-sig"
mkdir -p "$require_cache"
stripped_path="$(printf '%s' "$PATH" | tr ':' '\n' | grep -v -E '/go(/bin)?$' | paste -sd: -)"
if out="$(PATH="$stripped_path" \
    TRUSTGATE_COSIGN_BIN="$work_dir/no-such-cosign" \
    TRUSTGATE_PLUGIN_REQUIRE_SIGNATURE=true \
    TRUSTGATE_PLUGIN_RELEASE_BASE_URL="$base_url" \
    TRUSTGATE_PLUGIN_CACHE_DIR="$require_cache" \
    ensure_binary fake-trustgate-tool 2>"$require_cache/stderr.log")"; then
  echo "FAIL: require-signature should refuse a checksum-only install, but it succeeded with $out"
  fail_count=$((fail_count + 1))
else
  echo "PASS: require-signature refuses when cosign is unavailable (refused as expected: $(tail -1 "$require_cache/stderr.log"))"
fi

echo "=== 5. Same conditions, flag unset ==="
# Guards the default: the flag must be what refuses above, not the missing
# cosign, which on its own is only a warning.
assert_success "checksum-only install is accepted when the flag is unset" "$work_dir/cache-default-sig"

if [[ $fail_count -ne 0 ]]; then
  echo "test-ensure-binary: $fail_count assertion(s) failed" >&2
  exit 1
fi
echo "test-ensure-binary: all assertions passed"
