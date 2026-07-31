#!/usr/bin/env bash
# Plugin wrapper for the beforeSubmitPrompt event. See hook-shell.sh for how
# resolution and exec work.
#
# Registered failClosed:false (hooks.json), unlike the four execution hooks:
# a prompt-layer miss must never stop the user from submitting a prompt. That
# also covers the `|| exit 2` below — if the binary cannot be resolved at all,
# Cursor treats the non-zero exit as a hook failure and, being fail-open here,
# lets the prompt through.
set -uo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/ensure-binary.sh
source "$script_dir/lib/ensure-binary.sh"

bin_path="$(ensure_binary trustgate-before-prompt)" || exit 2
exec "$bin_path"
