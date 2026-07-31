#!/usr/bin/env bash
# Background half of the sessionStart warm-up (see warmup.sh).
#
# Split into its own script so warmup.sh can spawn it detached: the parent
# returns immediately and Cursor's hook timeout kills nothing that matters.
# Resolution failures are absorbed — a warm-up miss only means the next real
# hook call resolves that binary itself.
#
# The admin CLI is resolved alongside the hook binaries because it is how a
# plugin user configures their API key; see warmup.sh for that flow.
set -uo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/ensure-binary.sh
source "$script_dir/lib/ensure-binary.sh"

for name in trustgate-before-shell trustgate-before-mcp trustgate-before-read-file \
            trustgate-before-tool-use trustgate-before-prompt trustgate; do
  ensure_binary "$name" >/dev/null 2>&1 &
done
wait

exit 0
