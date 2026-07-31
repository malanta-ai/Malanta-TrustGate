#!/usr/bin/env bash
# sessionStart warm-up. Two jobs, neither of which may delay the session:
#
#   1. Pre-resolve every hook binary (plus the admin CLI) so the FIRST real
#      enforcement call doesn't pay download/build latency inline. The work
#      runs DETACHED, in warmup-worker.sh: resolving six binaries can exceed
#      this hook's timeout, and a killed warm-up used to leave some binaries
#      unresolved — which is exactly the inline download it exists to avoid.
#      Cursor treats sessionStart as fire-and-forget, so returning early
#      costs nothing.
#
#   2. Tell the agent when TrustGate is installed but has no API key, via
#      the `additional_context` field sessionStart supports. Unconfigured
#      TrustGate is INERT — it allows everything — and the failure mode is
#      silent, so a user can believe they are protected when they are not.
#      Only checked when the CLI is already cached (never downloaded here),
#      so a first session stays fast and a later one carries the notice.
#
# NEVER fail-closed (hooks.json sets failClosed:false on this entry) and
# always exits 0.
set -uo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/ensure-binary.sh
source "$script_dir/lib/ensure-binary.sh"

# nohup + disown so the worker survives this hook's timeout. Neither is a
# guarantee if the whole process group is killed, but both are portable —
# macOS ships no setsid.
nohup bash "$script_dir/warmup-worker.sh" >/dev/null 2>&1 &
disown 2>/dev/null || true

# Capture and match, rather than piping into `grep -q`: the library sets
# pipefail, and grep -q exits on first match, so the producer takes SIGPIPE
# and the pipeline reports 141 — making the notice fire only when doctor
# happened to finish writing first.
if cli="$(trustgate_cached_binary trustgate)"; then
  doctor_out="$("$cli" doctor 2>/dev/null)" || doctor_out=""
  case "$doctor_out" in
    *UNCONFIGURED*)
      printf '{"additional_context":"Malanta TrustGate is installed but has no reputation API key configured, so it is currently INERT: it inspects nothing and allows every action. Open your FIRST reply in this conversation by telling the user this in one sentence, and give them the exact fix: run `%s setup` in a terminal. Do not run that command yourself — it prompts interactively for a secret. Say it once; do not repeat it in later replies."}\n' "$cli"
      ;;
  esac
fi

exit 0
