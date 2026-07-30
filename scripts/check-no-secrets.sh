#!/usr/bin/env bash
# check-no-secrets.sh
#
# Guards against the exact failure mode documented in AGENTS.md's history:
# a real API key pasted into a tracked file. Scans every git-tracked file
# (not the working tree — a file that's merely present but gitignored,
# like .env, is out of scope and correctly so) for:
#
#   1. An assigned value for MALANTA_API_KEY / any *_API_KEY env var that
#      looks like a real secret (not just the bare env var name, which
#      legitimately appears throughout docs/code, and not an empty or
#      placeholder assignment like ".env.example"'s `MALANTA_API_KEY=`).
#   2. Common third-party secret shapes (AWS access key IDs, PEM private
#      key headers, GitHub tokens) as a general safety net.
#
# Run locally before a commit that touches config/docs, or via CI (see
# .github/workflows/ci.yml). Exits non-zero and prints the offending
# file:line on any hit.
#
# False positives: if this ever flags a legitimate non-secret value,
# tighten the pattern rather than removing the check — see CONTRIBUTING.md.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail=0

# Pattern 1: an assigned, non-trivial value for a *_API_KEY-shaped env var
# in a TRACKED file. The value must immediately follow '=' (no space — a
# real shell assignment, not prose like "KEY= /path/to/file" or
# "KEY= <see above>") and excludes '/' so file-path-shaped text after a
# bare "KEY=" (seen in doc commands like `grep KEY= /etc/.../env`) doesn't
# false-positive. Requires 12+ chars so "MALANTA_API_KEY=" (the
# .env.example placeholder) doesn't trip it. Lines with the literal
# placeholder text "..."/"your-"/"replace-me"/"example"/"placeholder" are
# excluded by content rather than by path, so real docs still get scanned
# for an accidentally-pasted real value.
# Redaction: this scanner's own output would otherwise ECHO the very
# secret it just found into stdout / the CI log (a second copy of the
# leak, in a system that retains build logs). We keep the locating
# context (file:line and the env-var name) but mask the assigned value
# before printing.
matches="$(git grep -nIE '[A-Z_]*_API_KEY=["'"'"']?[A-Za-z0-9_.+-]{12,}["'"'"']?([[:space:]]|$)' 2>/dev/null \
    | grep -viE '\.\.\.|your[_-]|replace[_-]me|example|placeholder' || true)"
if [[ -n "$matches" ]]; then
  printf '%s\n' "$matches" | sed -E 's/(_API_KEY=)(["'"'"']?)[A-Za-z0-9_.+-]{12,}/\1\2***REDACTED***/g' >&2
  echo "::error::possible API key value committed (see above, value redacted) — rotate immediately if real, then fix the file" >&2
  fail=1
fi

# Pattern 2: common third-party secret shapes, anywhere in tracked files.
patterns=(
  'AKIA[0-9A-Z]{16}'                          # AWS access key ID
  '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'  # PEM private key
  'ghp_[A-Za-z0-9]{36}'                        # GitHub personal access token
  'malanta_[A-Za-z0-9]{15,}'                   # Malanta key shape (case-sensitive prefix)
)
for p in "${patterns[@]}"; do
  matches="$(git grep -nIE "$p" 2>/dev/null || true)"
  if [[ -n "$matches" ]]; then
    # Same redaction rationale as pattern 1: mask the matched secret
    # shape in the printed line so the scanner never re-emits the value.
    printf '%s\n' "$matches" | sed -E "s#$p#***REDACTED***#g" >&2
    echo "::error::matched secret-shaped pattern '$p' (see above, value redacted) — rotate immediately if real, then fix the file" >&2
    fail=1
  fi
done

if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "check-no-secrets: clean"
