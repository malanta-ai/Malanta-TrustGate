#!/usr/bin/env bash
# sessionStart warm-up: pre-resolves (downloads or builds) all four hook
# binaries once per session so the FIRST real enforcement call doesn't
# pay the download/build latency inline. Deliberately non-blocking of
# the session and NEVER fail-closed (see hooks.json: failClosed: false
# on this entry) — a warm-up miss just means the next real hook call
# resolves the binary itself (slower, but correct). Always exits 0.
set -uo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/ensure-binary.sh
source "$script_dir/lib/ensure-binary.sh"

for name in trustgate-before-shell trustgate-before-mcp trustgate-before-read-file trustgate-before-tool-use; do
  ensure_binary "$name" >/dev/null 2>&1 &
done
wait

exit 0
