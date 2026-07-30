#!/usr/bin/env bash
# Plugin wrapper for the preToolUse event (WebFetch/WebSearch). See
# hook-shell.sh for how resolution and exec work.
set -uo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/ensure-binary.sh
source "$script_dir/lib/ensure-binary.sh"

bin_path="$(ensure_binary trustgate-before-tool-use)" || exit 2
exec "$bin_path"
