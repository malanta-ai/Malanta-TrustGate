#!/usr/bin/env bash
# Plugin wrapper for the beforeShellExecution event. Resolves (downloads
# or builds) trustgate-before-shell, then execs it so stdin/stdout/exit
# code pass straight through — see lib/ensure-binary.sh for how
# resolution works and hooks.json for how Cursor invokes this script.
set -uo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/ensure-binary.sh
source "$script_dir/lib/ensure-binary.sh"

bin_path="$(ensure_binary trustgate-before-shell)" || exit 2
exec "$bin_path"
