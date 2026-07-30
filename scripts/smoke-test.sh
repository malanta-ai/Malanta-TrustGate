#!/usr/bin/env bash
# smoke-test.sh
#
# Exercise each of the four built hook binaries against synthetic payloads.
# Verifies basic plumbing (stdin in, JSON out) and that a clean host
# (google.com) is allowed on every surface.
#
# The deny half needs a host the configured provider actually flags, and
# which one that is depends on the provider's current data — so it is not
# hardcoded here. Set TRUSTGATE_SMOKE_DENY_HOST to a host you know is
# flagged and the deny cases run too; leave it unset and they are skipped
# with a notice. This keeps the script useful to anyone with a key, and
# stops the suite from failing the day a hardcoded host gets delisted.
#
# Requires MALANTA_API_KEY in the environment.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ -z "${MALANTA_API_KEY:-}" ]]; then
  echo "error: MALANTA_API_KEY must be set in the environment" >&2
  exit 1
fi

if [[ ! -x dist/trustgate-before-shell ]]; then
  echo "==> Building binaries (dist/ missing)"
  go build -o dist/ ./cmd/...
fi

export MALANTA_API_KEY

run_case() {
  local label="$1" bin="$2" payload="$3" want_allow="$4"
  local out
  out="$(printf '%s' "$payload" | "./dist/$bin")"
  echo "[$label] $out"
  # Cursor's hook output schema is per-event:
  #   - beforeShellExecution / beforeMCPExecution / beforeReadFile: {"permission":"allow"|"deny", ...}
  #   - beforeSubmitPrompt:                                          {"continue": true|false, ...}
  # Normalize both into a single allow-ish boolean for assertion purposes.
  local allow
  allow="$(printf '%s' "$out" | python3 -c '
import json, sys
v = json.load(sys.stdin)
if "permission" in v:
    print("True" if v["permission"] == "allow" else "False")
elif "continue" in v:
    print("True" if v["continue"] else "False")
else:
    print("UNKNOWN")
' 2>/dev/null || true)"
  if [[ "$allow" != "$want_allow" ]]; then
    echo "  FAIL: expected allow=$want_allow, got allow=$allow" >&2
    return 1
  fi
}

failures=0
deny_host="${TRUSTGATE_SMOKE_DENY_HOST:-}"

run_case "shell/google allow"     trustgate-before-shell     '{"command":"curl https://google.com/robots.txt"}' True  || failures=$((failures+1))
run_case "tooluse/webfetch allow" trustgate-before-tool-use  '{"tool_name":"WebFetch","tool_input":{"url":"https://google.com/"}}' True || failures=$((failures+1))
# Read-file: path must match the high-risk allowlist (literal "requirements.txt"
# basename), otherwise inline content is intentionally skipped to keep the hook
# from false-positiving on arbitrary source files.
run_case "readfile/clean allow"    trustgate-before-read-file '{"path":"/tmp/requirements.txt","content":"--index-url https://google.com/simple\nfoo==1.0\n"}' True  || failures=$((failures+1))

if [[ -n "$deny_host" ]]; then
  run_case "shell/flagged deny"       trustgate-before-shell     "{\"command\":\"curl https://$deny_host/x\"}"  False || failures=$((failures+1))
  run_case "shell/flagged deny (wget)" trustgate-before-shell    "{\"command\":\"wget https://$deny_host/y\"}"  False || failures=$((failures+1))
  run_case "mcp/flagged deny"         trustgate-before-mcp       "{\"tool\":\"fetch\",\"arguments\":{\"url\":\"https://$deny_host/api\"}}" False || failures=$((failures+1))
  run_case "mcp/current-payload deny" trustgate-before-mcp       "{\"tool_name\":\"fetch\",\"tool_input\":\"{\\\"url\\\":\\\"https://$deny_host/api\\\"}\",\"command\":\"fetch\"}" False || failures=$((failures+1))
  run_case "tooluse/webfetch deny"    trustgate-before-tool-use  "{\"tool_name\":\"WebFetch\",\"tool_input\":{\"url\":\"https://$deny_host/x\"}}" False || failures=$((failures+1))
  run_case "readfile/flagged deny"    trustgate-before-read-file "{\"path\":\"/tmp/requirements.txt\",\"content\":\"--index-url https://$deny_host/simple\\nfoo==1.0\\n\"}" False || failures=$((failures+1))
else
  echo "note: TRUSTGATE_SMOKE_DENY_HOST unset — skipping the 6 deny cases."
  echo "      Set it to a host your provider flags to exercise the deny path."
fi
# Negative test: a non-allowlisted path with content that LOOKS like it has hosts
# must NOT be scanned (this is the Go-source-as-domain bug we just fixed).
run_case "readfile/source skipped" trustgate-before-read-file '{"path":"/repo/main.go","content":"package main\nimport \"context\"\nvar _ = context.Background()\n"}' True || failures=$((failures+1))

if [[ $failures -ne 0 ]]; then
  echo "smoke test: $failures case(s) failed" >&2
  exit 1
fi
echo "smoke test: all cases passed"
