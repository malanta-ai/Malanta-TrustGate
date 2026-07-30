#!/usr/bin/env python3
"""
sync-atr-rules.py — pull the agent-threat-rules npm package, encode
each rule's regex values, write only the encoded YAML to
internal/atr/rules/<category>/.

WHY encoding is necessary
=========================

ATR detection-rule files contain literal byte sequences that MATCH
real-world malware patterns (PowerShell IEX cradles, reverse-shell
shapes, encoded-command payloads, etc.). When those bytes land on
disk verbatim — even inside a YAML file — endpoint AV / EDR engines
heuristically flag them as the malware they're trained to detect.

This is the well-known "anti-virus engine flags signature-shipping
tool" false-positive class: YARA rules, Sigma rules, Snort/Suricata
signatures, and PEAS / LinPEAS all routinely trip it.

In our case Microsoft Defender quarantined the upstream rule file
`ATR-2026-00121-skill-dangerous-script.yaml` as
`Trojan:PowerShell/Openclaw.GVB!MTB` — exactly because the YAML
contained a base-pattern that Openclaw's signature looks for.

The fix: replace each `value: "<regex>"` field in a rule's
`detection.conditions[].value` block with `value: "atr-b64:<base64>"`
at sync time. The on-disk file then contains only opaque base64,
which no AV signature can pattern-match. The bundle loader
(internal/atr/bundle.go::parseRule) detects the `atr-b64:` sentinel
prefix and decodes back to the original regex string before
compiling.

Operationally
=============

- This script is the SOLE entry point that touches network. It
  fetches the npm tarball via the registry's documented `dist.tarball`
  URL — no shelling out to `npm`, so no risk of the npm cache
  retaining a plaintext copy on disk.
- Plaintext rule bytes exist only in memory inside this script's
  process. The decoded form on disk is the encoded form — there is
  NO intermediate "extracted but unencoded" tarball directory.
- The script is idempotent: re-running it overwrites the encoded
  category directories. It does NOT touch internal/atr/rules/shell/
  (those are hand-curated; encode them via the same encoder run
  with `--encode-only <file>` instead).
- Sync mode requires PyYAML (`pip install pyyaml`) to parse and
  minimize upstream rules safely (a real parser, not line-based
  regex — see minimize_and_encode_upstream). The `--encode-only`
  path for the hand-curated shell rules stays stdlib-only.

Usage
=====

    # Sync from upstream npm registry, encode, vendor:
    python3 scripts/sync-atr-rules.py

    # Encode an already-on-disk file in place (e.g. the hand-
    # curated shell rules):
    python3 scripts/sync-atr-rules.py --encode-only \\
        internal/atr/rules/shell/*.yaml

    # Bump pinned version:
    ATR_VERSION=2.3.0 python3 scripts/sync-atr-rules.py
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

# Sentinel prefix on encoded regex values. Picked to be:
#   1. Distinctive enough not to clash with any natural ATR regex
#      (no real rule starts with "atr-b64:").
#   2. Short, so the bundle.go decode loop runs in trivial time.
#   3. Self-documenting on inspection — anyone reading a rule file
#      sees "atr-b64:" and understands why the value is opaque.
SENTINEL = "atr-b64:"

# Allowed categories: matches internal/atr/rule.go::allowedCategories.
# Any rule whose `tags.category` is outside this set is dropped at
# sync time so the vendored snapshot stays in scope.
ALLOWED_CATEGORIES = {"skill-compromise", "tool-poisoning", "context-exfiltration"}

ATR_VERSION = os.environ.get("ATR_VERSION", "3.5.7")
REGISTRY_URL = f"https://registry.npmjs.org/agent-threat-rules/{ATR_VERSION}"

# Supply-chain hardening bounds for the (maintainer-only) sync path.
# The whole tarball is pulled into memory and every member is read into
# memory, so cap both so a compromised or malformed upstream can't exhaust
# memory (CWE-400). The real corpus is far under these.
MAX_TARBALL_BYTES = 50 * 1024 * 1024        # 50 MiB
MAX_MEMBER_BYTES = 1 * 1024 * 1024          # 1 MiB per rule file
MAX_REGISTRY_META_BYTES = 25 * 1024 * 1024  # npm metadata JSON
# Refuse to commit a suspiciously small corpus: a truncated download or a
# mostly-unparseable upstream should not silently erase the vendored
# ruleset. Floor, not an exact count; lower it if the upstream in-scope set
# legitimately shrinks below this.
MIN_TOTAL_RULES = 50


# --------------------------------------------------------------------
# YAML helpers
# --------------------------------------------------------------------
#
# TWO encoders live here, on purpose:
#
#   - The SYNC path (upstream tarball -> vendored) uses PyYAML via
#     minimize_and_encode_upstream: a real-parser BUILD-UP transform
#     that reconstructs each rule from only the keys the Go loader
#     reads. This is the correct, robust encoder. It replaced an
#     earlier line-based minimizer that leaked plaintext attack
#     payloads on the 3.x schema — upstream `evasion_tests:` /
#     `test_cases:` sequence items sit at the SAME indentation as
#     their parent key, so an indentation-based subtree-skip left the
#     `- input: "..."` example lines orphaned on disk (Defender would
#     then quarantine the binary that embeds them). A build-up parse
#     can't leak an unknown block because it only ever emits fields it
#     explicitly extracts.
#
#   - The --encode-only / --reencode path (the hand-curated
#     TRUSTGATE-SHELL-* rules) keeps the stdlib line-based encoder
#     below (encode_yaml_bytes). Those files are already minimal and
#     hand-formatted; a line-based scalar-only rewrite preserves their
#     formatting instead of reserializing them, and they don't contain
#     the top-level sequence blocks that broke the line-based approach
#     upstream. This path stays stdlib-only (no PyYAML needed).


# Fields whose single-line scalar values we encode. Any one of these
# can carry text that an AV signature would match — value is the
# regex itself, description and title are human-readable explanations
# that name the attack shape ("Bash reverse shell (>& /dev/tcp/...)"
# is exactly the byte pattern Defender's Openclaw signature hunts
# for). Encoding all three keeps the on-disk YAML AND the embedded
# binary's string table free of attack signatures.
#
# We deliberately do NOT encode:
#   - id: identifiers are stable opaque tokens (TRUSTGATE-SHELL-006,
#     ATR-2026-00010) with no attack content.
#   - severity, category, scan_target: enum-shaped tokens.
#   - field, operator, condition: schema scaffolding.
ENCODED_FIELDS = ("value", "description", "title")

# Top-level YAML keys the Go loader (internal/atr/bundle.go::yamlRule)
# actually reads. Any other top-level key — references, test_cases,
# examples, metadata, author, schema_version, etc. — is dropped
# entirely when minimizing a rule file. Two motivations:
#
#  1. Defense against AV signature FPs: upstream test_cases routinely
#     contain literal attack payloads (`bash -i >& /dev/tcp/...`,
#     `cat ~/.ssh/id_rsa | base64 | curl ...`). These are pedagogical
#     fixtures, not the runtime rule — but they end up embedded in
#     the binary via embed.FS and trip Defender's Openclaw
#     signature exactly as the original detection-rule patterns did.
#  2. Binary size: a minimized rule is ~20% the size of the upstream
#     pretty-printed YAML. Across the 100-rule snapshot this saves
#     several hundred KiB in the embedded blob.
KEEP_TOP_KEYS = {"id", "title", "description", "severity", "tags", "detection"}

# Sub-keys that should be dropped wherever they appear in the YAML
# tree. The Go loader looks at:
#   - top: id, title, description, severity
#   - tags.category
#   - detection.condition, detection.conditions[].{field,operator,value,description}
#
# Everything else nested inside `tags:` or `detection:` or any deeper
# context is unused at runtime but still ends up in the embed.FS
# bytes. Listed explicitly so the strip is observable in code review —
# a future schema upgrade that wants to ship a new sub-field has to
# either land it in the Go loader (cause an unused field to start
# being kept) or rationalize WHY it must survive the minimization.
DROP_KEYS_ANYWHERE = {
    # detection-block siblings/children
    "false_positives", "negatives", "true_positives", "test_cases",
    "examples", "input", "tool_response", "expected",
    "confidence", "rationale", "notes",
    # tags-block siblings/children that the loader doesn't read
    "subcategory", "scan_target", "owasp_llm", "owasp_agentic",
    "mitre_atlas", "mitre_attack", "cve",
    # top-level metadata the loader ignores
    "references", "rule_version", "schema_version", "author",
    "date", "status", "detection_tier", "maturity",
}

# Match `<field>: "<string>"` or `<field>: '<string>'` on its own
# line, where <field> is one of ENCODED_FIELDS. Quotes are required:
# every ATR rule we've inspected emits these fields as quoted single-
# line scalars when their content needs encoding. Block-scalar forms
# (|- and >-) are skipped — see _BLOCK_FIELD_LINE_RE below.
ENCODED_FIELDS_PAT = "|".join(re.escape(f) for f in ENCODED_FIELDS)
VALUE_LINE_RE = re.compile(
    rf"""^(\s*(?:{ENCODED_FIELDS_PAT}):\s*)   # 1: leading indent + field-key
        (['"])                                 # 2: opening quote
        (.+)                                   # 3: the scalar payload
        \2                                     # closing quote (same as opening)
        \s*$                                   # optional trailing whitespace
    """,
    re.VERBOSE,
)

# Match a block-scalar header like `description: |` or `description: >`
# (optionally with chomp indicator `|-`, `|+`, etc.). When we see one,
# we collapse the block into a single line, encode it, and emit the
# encoded form as a quoted scalar. Loses formatting fidelity for
# human inspection, but the description goes through Decision.Reason
# either way and the formatting collapse just normalizes whitespace.
_BLOCK_FIELD_LINE_RE = re.compile(
    rf"""^(\s*)({ENCODED_FIELDS_PAT}):\s*([|>][-+]?)\s*$
    """,
    re.VERBOSE,
)

# Match a YAML comment line (full-line `#` or trailing `   # ...`).
# Used to strip comments from emitted files: comments live in the
# embed.FS bytes verbatim, so an attack-shape rationale paragraph
# inside a comment would still trip AV heuristics in the binary.
# Note: we only strip FULL-LINE comments and trailing comments after
# whitespace. We do NOT strip `#` inside quoted strings — those are
# valid YAML scalars.
_FULL_LINE_COMMENT_RE = re.compile(r"^\s*#.*$")


# YAML double-quoted-string escape interpretation table. We need to
# apply this BEFORE base64-encoding the value, because the Go YAML
# loader (yaml.v3) interprets these escapes when reading a plaintext
# rule file — the regex compiler expects the post-escape string,
# not the on-disk literal bytes.
#
# Reference: YAML 1.2 §5.7 (Escaped Characters). We cover the subset
# observed in ATR rule files; if upstream ever adds a new escape we
# don't cover, the regex will simply contain the literal `\X` and
# regex.Compile will either reject it or treat it as a regex escape.
# The regression test (TestEvaluateMatchesKnownPositive) catches a
# broken round-trip.
_YAML_ESCAPES = {
    "\\": "\\",
    '"': '"',
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "/": "/",
}


def yaml_unescape_double_quoted(s: str) -> str:
    """Apply YAML 1.2 double-quoted-string escape interpretation.

    Handles the canonical escapes (\\\\, \\", \\n, \\t, \\r, \\0, \\b,
    \\f, \\v, \\a, \\/) plus the numeric forms (\\xHH, \\uHHHH,
    \\UHHHHHHHH). Unknown escapes pass through unchanged so a future
    upstream rule with an exotic escape we don't recognize doesn't
    silently corrupt the regex.
    """
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        nxt = s[i + 1]
        if nxt in _YAML_ESCAPES:
            out.append(_YAML_ESCAPES[nxt])
            i += 2
            continue
        if nxt == "x" and i + 3 < n:
            try:
                out.append(chr(int(s[i + 2 : i + 4], 16)))
                i += 4
                continue
            except ValueError:
                pass
        if nxt == "u" and i + 5 < n:
            try:
                out.append(chr(int(s[i + 2 : i + 6], 16)))
                i += 6
                continue
            except ValueError:
                pass
        if nxt == "U" and i + 9 < n:
            try:
                out.append(chr(int(s[i + 2 : i + 10], 16)))
                i += 10
                continue
            except ValueError:
                pass
        # Unrecognized escape: pass through verbatim. The Go regex
        # engine then decides whether `\X` is a valid regex escape.
        out.append(c)
        i += 1
    return "".join(out)


def _encode_one_scalar(text: str) -> str:
    """Apply yaml-unescape (when needed) + base64-encode, return the
    encoded line content (without trailing newline)."""
    m = VALUE_LINE_RE.match(text)
    if not m:
        return text
    prefix, quote, val = m.group(1), m.group(2), m.group(3)
    if val.startswith(SENTINEL):
        return text  # already encoded
    if quote == '"':
        val = yaml_unescape_double_quoted(val)
    encoded = base64.b64encode(val.encode("utf-8")).decode("ascii")
    return f'{prefix}"{SENTINEL}{encoded}"'


# Match an unquoted single-line scalar on one of the ENCODED_FIELDS.
# Bare scalars in YAML are everything from `:` up to end-of-line that
# isn't quoted and isn't a block-scalar header. We deliberately limit
# this to the encodable fields (title, description, value) so we
# don't accidentally rewrite enums (`severity: critical`) or numeric
# fields. Empty values are skipped — they're not encodable.
_BARE_FIELD_LINE_RE = re.compile(
    rf"""^(\s*(?:{ENCODED_FIELDS_PAT}):\s+)   # 1: indent + field + sep
        (?!\s*$)                              # not an empty value
        (?!["'|>])                            # not quoted or block header
        ([^#\n][^\n]*?)                       # 2: bare scalar (must not start with #)
        \s*(?:\#.*)?$                         # optional trailing comment
    """,
    re.VERBOSE,
)


def _is_top_level_key(line: str, key_name: str | None = None) -> tuple[bool, str | None]:
    """Return (is_top_key, key_name). A top-level key is a line with
    zero indentation that matches `name:` or `name: value`."""
    if not line or line[0] == " ":
        return False, None
    m = re.match(r"^([A-Za-z_][A-Za-z_0-9]*)\s*:", line)
    if not m:
        return False, None
    return True, m.group(1)


def encode_yaml_bytes(raw: bytes) -> bytes:
    """Return raw minimized + encoded.

    Pipeline:
      1. Drop any top-level YAML key NOT in KEEP_TOP_KEYS together
         with its entire indented subtree. This removes references,
         test_cases, examples, metadata, etc. — sub-blocks that the
         Go loader doesn't read but which routinely carry attack-
         shape literals that trip endpoint AV.
      2. Strip full-line YAML comments.
      3. Encode single-line quoted scalars on ENCODED_FIELDS
         (yaml-unescape then base64).
      4. Encode block scalars on ENCODED_FIELDS (collapse to single
         line, then base64).
      5. Encode bare (unquoted) single-line scalars on
         ENCODED_FIELDS (no escape interpretation needed for bare
         strings).

    Each scalar carries the `atr-b64:` sentinel after encoding; the
    Go loader (internal/atr/bundle.go) decodes both regex `value`
    fields and prose `description`/`title` fields.
    """
    lines = raw.decode("utf-8", errors="replace").splitlines()
    out: list[str] = []
    i, n = 0, len(lines)

    def block_indent(s: str) -> int:
        return len(s) - len(s.lstrip(" "))

    def skip_subtree(start: int, base_col: int) -> int:
        """Return the index of the first line that ends the subtree
        whose root sits at column base_col. A subtree ends when we
        see another non-blank/non-comment line at indentation
        <= base_col (or hit EOF)."""
        j = start + 1
        while j < n:
            cur = lines[j]
            if not cur.strip() or cur.lstrip().startswith("#"):
                j += 1
                continue
            cur_col = block_indent(cur)
            if cur_col <= base_col:
                return j
            j += 1
        return j

    while i < n:
        line = lines[i]

        # Strip full-line comments and blank lines.
        if not line.strip() or _FULL_LINE_COMMENT_RE.match(line):
            i += 1
            continue

        # Top-level key?
        is_top, key = _is_top_level_key(line)
        if is_top and key not in KEEP_TOP_KEYS:
            i = skip_subtree(i, 0)
            continue

        # Drop-anywhere key (e.g. `false_positives:` nested under
        # `detection:`)? Detect by extracting the bare key from the
        # current line and checking against DROP_KEYS_ANYWHERE.
        nested_match = re.match(r"^(\s*)([A-Za-z_][A-Za-z_0-9]*)\s*:", line)
        if nested_match:
            indent_str, nested_key = nested_match.group(1), nested_match.group(2)
            if nested_key in DROP_KEYS_ANYWHERE:
                i = skip_subtree(i, len(indent_str))
                continue

        # Block scalar on an encodable field?
        bm = _BLOCK_FIELD_LINE_RE.match(line)
        if bm:
            base_indent, field = bm.group(1), bm.group(2)
            base_col = len(base_indent)
            j = i + 1
            block_lines: list[str] = []
            child_indent: int | None = None
            while j < n:
                cur = lines[j]
                if cur.strip() == "":
                    block_lines.append("")
                    j += 1
                    continue
                cur_indent = block_indent(cur)
                if cur_indent <= base_col:
                    break  # block ended
                if child_indent is None:
                    child_indent = cur_indent
                strip = min(cur_indent, child_indent or cur_indent)
                block_lines.append(cur[strip:])
                j += 1
            collapsed = " ".join(s.strip() for s in block_lines if s.strip())
            encoded = base64.b64encode(collapsed.encode("utf-8")).decode("ascii")
            out.append(f'{base_indent}{field}: "{SENTINEL}{encoded}"')
            i = j
            continue

        # Single-line quoted scalar on an encodable field?
        if VALUE_LINE_RE.match(line):
            out.append(_encode_one_scalar(line))
            i += 1
            continue

        # Bare single-line scalar on an encodable field?
        nm = _BARE_FIELD_LINE_RE.match(line)
        if nm:
            prefix, val = nm.group(1), nm.group(2).strip()
            if not val.startswith(SENTINEL) and val:
                encoded = base64.b64encode(val.encode("utf-8")).decode("ascii")
                out.append(f'{prefix}"{SENTINEL}{encoded}"')
                i += 1
                continue

        # Default: keep verbatim.
        out.append(line)
        i += 1

    encoded_text = "\n".join(out)
    if not encoded_text.endswith("\n"):
        encoded_text += "\n"
    return encoded_text.encode("utf-8")


def _b64_scalar(value: object) -> str:
    """Return the atr-b64 sentinel-encoded form of a scalar, or pass it
    through unchanged if it is already encoded. The build-up encoder works
    on Python values already unescaped by the YAML parser, so no manual
    yaml-unescape step is needed (unlike the line-based encoder, which
    reads raw on-disk quoted bytes)."""
    s = "" if value is None else str(value)
    if s.startswith(SENTINEL):
        return s
    return SENTINEL + base64.b64encode(s.encode("utf-8")).decode("ascii")


def minimize_and_encode_upstream(raw: bytes) -> bytes:
    """Parse one upstream ATR rule with a real YAML parser, keep ONLY the
    keys the Go loader (internal/atr/bundle.go::yamlRule) actually reads,
    base64-encode the attack-bearing scalars, and emit a fresh minimal
    YAML document.

    This is a BUILD-UP transform, not a tear-down one: instead of trying
    to delete unwanted blocks from the upstream file (the old line-based
    encoder's approach, which leaked plaintext because YAML sequence items
    like `evasion_tests:`'s `- input:` sit at the SAME indent as their
    parent key and slipped past the indentation-based subtree skip), we
    reconstruct the file from only the fields we extract. Anything not
    named here — test_cases, evasion_tests, false_positives, response,
    references, compliance, agent_source, and any future block — can never
    reach disk, so upstream pedagogical attack payloads (`cat ~/.ssh/id_rsa
    | curl ...`) are structurally excluded rather than pattern-stripped.

    Requires PyYAML (sync path only; the hand-curated `--encode-only`
    path keeps the stdlib line-based encoder). Raises on unparseable YAML;
    the caller counts and skips those.
    """
    try:
        import yaml  # PyYAML
    except ImportError as e:  # pragma: no cover - environment guard
        raise RuntimeError(
            "sync mode needs PyYAML to safely minimize upstream rules "
            "(build-up encode). Install it with `pip install pyyaml` (or run "
            "in a venv). The --encode-only path for the hand-curated shell "
            "rules does not need it."
        ) from e

    doc = yaml.safe_load(raw)
    if not isinstance(doc, dict):
        raise ValueError("rule YAML is not a mapping")

    out: dict[str, Any] = {}
    if doc.get("id") is not None:
        out["id"] = str(doc["id"])
    if doc.get("title") is not None:
        out["title"] = _b64_scalar(doc["title"])
    if doc.get("description") is not None:
        out["description"] = _b64_scalar(str(doc["description"]).strip())
    if doc.get("severity") is not None:
        out["severity"] = str(doc["severity"])

    tags = doc.get("tags")
    if isinstance(tags, dict):
        keep_tags: dict[str, Any] = {}
        # Only tags.category and tags.scan_target are read by the Go
        # loader (tagBlk); everything else (subcategory, confidence,
        # owasp_*, mitre_*, ...) is dropped by omission.
        if tags.get("category") is not None:
            keep_tags["category"] = str(tags["category"])
        if tags.get("scan_target") is not None:
            keep_tags["scan_target"] = str(tags["scan_target"])
        if keep_tags:
            out["tags"] = keep_tags

    det = doc.get("detection")
    if isinstance(det, dict):
        keep_det: dict[str, Any] = {}
        conds = det.get("conditions")
        new_conds: list[dict[str, Any]] = []
        if isinstance(conds, list):
            for c in conds:
                if not isinstance(c, dict):
                    continue
                nc: dict[str, Any] = {}
                if c.get("field") is not None:
                    nc["field"] = str(c["field"])
                if c.get("operator") is not None:
                    nc["operator"] = str(c["operator"])
                if c.get("value") is not None:
                    nc["value"] = _b64_scalar(c["value"])
                if c.get("description") is not None:
                    nc["description"] = _b64_scalar(c["description"])
                if nc:
                    new_conds.append(nc)
        if new_conds:
            keep_det["conditions"] = new_conds
        if det.get("condition") is not None:
            keep_det["condition"] = str(det["condition"])
        if keep_det:
            out["detection"] = keep_det

    import yaml as _yaml  # already imported above; alias for dump
    dumped = _yaml.safe_dump(
        out,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=10 ** 9,  # never line-wrap a long base64/regex scalar
    )
    if not dumped.endswith("\n"):
        dumped += "\n"
    return dumped.encode("utf-8")


def parse_category(raw: bytes) -> str | None:
    """Return the rule's tags.category (best-effort, line-based)."""
    in_tags = False
    for line in raw.splitlines():
        text = line.decode("utf-8", errors="replace").rstrip()
        if text.startswith("tags:"):
            in_tags = True
            continue
        if in_tags:
            # A top-level key at indentation level 0 closes the
            # tags block.
            if text and not text.startswith(" "):
                in_tags = False
                continue
            m = re.match(r"\s+category:\s*[\"']?([^\"'\s]+)[\"']?", text)
            if m:
                return m.group(1).strip()
    return None


# --------------------------------------------------------------------
# Upstream fetch
# --------------------------------------------------------------------


def _fetch_https_bytes(url: str, timeout: int, max_bytes: int) -> bytes:
    """Fetch url and return body bytes, capped at max_bytes. Tries urllib
    first; falls back to `curl` if urllib's SSL context can't validate the
    chain.

    the response is read with a hard byte cap so a compromised or
    misbehaving endpoint can't stream an unbounded body into memory. A body
    that exceeds the cap is a hard error, not a silent truncation.

    Why the curl fallback exists: macOS Python framework installs
    (python.org installer) ship without root certs unless the user
    has run `Install Certificates.command`. urllib then fails with
    `CERTIFICATE_VERIFY_FAILED`. macOS `curl` always uses the
    system trust store via Secure Transport, so a single
    subprocess call is the most portable bridge — and it keeps the
    sync script stdlib-only (no `pip install certifi`).
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read(max_bytes + 1)
    except urllib.error.URLError as e:
        msg = str(e)
        if "CERTIFICATE_VERIFY_FAILED" not in msg:
            raise
        # SSL chain validation failed in Python. Fall back to curl;
        # macOS Secure Transport will trust the system roots even
        # when Python's bundled cert store can't.
        print(f"==> urllib SSL verify failed; falling back to curl for {url}")
        import subprocess
        result = subprocess.run(
            ["curl", "-fsSL", "--max-time", str(timeout),
             "--max-filesize", str(max_bytes), url],
            check=True,
            capture_output=True,
        )
        data = result.stdout
    if len(data) > max_bytes:
        raise RuntimeError(
            f"response from {url} exceeds the {max_bytes}-byte cap; refusing"
        )
    return data


def _verify_integrity(tar_bytes: bytes, integrity: str) -> None:
    """Verify tar_bytes against an npm `dist.integrity` string.

    npm publishes Subresource-Integrity-style digests, e.g.
    "sha512-<base64>". We recompute the named hash over the downloaded
    bytes and compare in constant time. A missing/unsupported/mismatched
    integrity value is a hard error — we never vendor an unverified
    tarball. (npm also still ships a legacy hex `dist.shasum` (SHA-1); we
    require the stronger `dist.integrity` and ignore shasum.)
    """
    if not integrity or "-" not in integrity:
        raise RuntimeError(
            "npm registry response has no usable dist.integrity; refusing to "
            "vendor an unverified tarball"
        )
    algo, _, b64 = integrity.partition("-")
    algo = algo.strip().lower()
    if algo not in hashlib.algorithms_available:
        raise RuntimeError(f"unsupported dist.integrity algorithm {algo!r}")
    try:
        expected = base64.b64decode(b64, validate=True)
    except Exception as e:
        raise RuntimeError(f"malformed dist.integrity base64: {e}") from e
    actual = hashlib.new(algo, tar_bytes).digest()
    if not hmac.compare_digest(expected, actual):
        raise RuntimeError(
            f"tarball {algo} digest does not match dist.integrity — possible "
            "tampering; refusing"
        )
    print(f"==> Verified tarball {algo} against npm dist.integrity")


def fetch_tarball_bytes(version: str) -> bytes:
    """Download the agent-threat-rules npm tarball into memory, verifying it
    against the registry's published dist.integrity."""
    print(f"==> Resolving registry metadata for agent-threat-rules@{version}")
    meta_bytes = _fetch_https_bytes(
        REGISTRY_URL, timeout=60, max_bytes=MAX_REGISTRY_META_BYTES)
    meta: dict[str, Any] = json.loads(meta_bytes)
    dist = meta.get("dist", {})
    tarball_url = dist.get("tarball")
    if not tarball_url:
        raise RuntimeError(
            f"npm registry response missing dist.tarball for version {version}"
        )
    print(f"==> Downloading {tarball_url}")
    tar_bytes = _fetch_https_bytes(
        tarball_url, timeout=120, max_bytes=MAX_TARBALL_BYTES)
    _verify_integrity(tar_bytes, dist.get("integrity", ""))
    return tar_bytes


def write_encoded_rules_from_tarball(
    tar_bytes: bytes, dest_root: Path
) -> dict[str, int]:
    """Iterate the tarball; encode + write only in-scope rules into
    dest_root (a STAGING directory — the caller performs the atomic swap
    into the live rules tree, so this function can always write).

    Returns a per-category count of how many rules were written.
    """
    counts: dict[str, int] = {c: 0 for c in ALLOWED_CATEGORIES}
    skipped_out_of_scope = 0
    skipped_unparseable = 0
    skipped_unsafe = 0
    skipped_oversize = 0

    dest_root_real = os.path.realpath(dest_root)

    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isreg():
                continue
            name = member.name
            # npm tarballs prefix every entry with "package/".
            if not name.startswith("package/rules/"):
                continue
            if not (name.endswith(".yaml") or name.endswith(".yml")):
                continue
            # Strip "package/rules/" to get "<category>/<file>"
            rel = name[len("package/rules/"):]
            parts = rel.split("/", 1)
            if len(parts) != 2:
                continue
            category, filename = parts
            if category not in ALLOWED_CATEGORIES:
                skipped_out_of_scope += 1
                continue
            # Path-traversal guard: filename must be a plain basename
            # within the category dir — never a nested path, "..", a hidden
            # dotfile, or anything that resolves outside dest_root/<category>.
            # A malicious tarball member like
            # "package/rules/skill-compromise/../../../../etc/cron.d/x.yaml"
            # would otherwise escape the rules tree.
            out_dir = (dest_root / category)
            out_path = out_dir / filename
            if (
                "/" in filename
                or filename in ("", ".", "..")
                or filename.startswith(".")
                or os.path.commonpath(
                    [dest_root_real, os.path.realpath(out_path)]
                ) != dest_root_real
            ):
                print(f"    skipped unsafe member name {name!r}", file=sys.stderr)
                skipped_unsafe += 1
                continue
            # Size cap: reject an oversize member before reading it
            # into memory (the header size is authoritative for a regular
            # file; the bounded read below is defense in depth).
            if member.size > MAX_MEMBER_BYTES:
                print(f"    skipped oversize member {name!r} ({member.size} bytes)",
                      file=sys.stderr)
                skipped_oversize += 1
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            raw = f.read(MAX_MEMBER_BYTES + 1)
            if len(raw) > MAX_MEMBER_BYTES:
                print(f"    skipped oversize member {name!r} (stream exceeded cap)",
                      file=sys.stderr)
                skipped_oversize += 1
                continue
            # Sanity gate: the file must declare a category in its
            # YAML body that matches the directory it came from.
            declared = parse_category(raw)
            if declared and declared != category and declared in ALLOWED_CATEGORIES:
                # ATR ships some rules whose tags.category does not
                # match the directory (e.g. an over-permissioned-skill
                # rule lives in skill-compromise/ but is tagged as
                # privilege-escalation). The Go loader trusts the
                # YAML tag — so we route by directory but accept the
                # mismatch silently.
                pass
            if declared and declared not in ALLOWED_CATEGORIES and declared != "":
                # YAML self-declared an out-of-scope category despite
                # living in an in-scope directory. Drop it.
                skipped_out_of_scope += 1
                continue
            try:
                encoded = minimize_and_encode_upstream(raw)
            except Exception as e:  # unparseable/odd-shaped upstream rule
                print(f"    skipped unparseable {category}/{filename}: {e}",
                      file=sys.stderr)
                skipped_unparseable += 1
                continue
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(encoded)
            counts[category] += 1

    if skipped_out_of_scope:
        print(f"    skipped {skipped_out_of_scope} out-of-scope rules")
    if skipped_unparseable:
        print(f"    skipped {skipped_unparseable} unparseable rules")
    if skipped_unsafe:
        print(f"    skipped {skipped_unsafe} unsafe-named rules")
    if skipped_oversize:
        print(f"    skipped {skipped_oversize} oversize rules")
    return counts


# --------------------------------------------------------------------
# Standalone encode mode (for the hand-curated shell pack)
# --------------------------------------------------------------------


def encode_in_place(files: list[Path]) -> None:
    """Encode each YAML file in place, atomically."""
    for p in files:
        if not p.is_file():
            print(f"warn: {p} not a regular file; skipped", file=sys.stderr)
            continue
        raw = p.read_bytes()
        encoded = encode_yaml_bytes(raw)
        if encoded == raw:
            print(f"    {p}: already encoded (no change)")
            continue
        # Atomic rename.
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_bytes(encoded)
        os.replace(tmp, p)
        print(f"    encoded {p}")


# Match a value line that already carries the SENTINEL — used by the
# --reencode mode to migrate older encoded files after an encoder bug
# fix.
ENCODED_VALUE_LINE_RE = re.compile(
    r"""^(\s*value:\s*)
        (['"])
        (atr-b64:[A-Za-z0-9+/=]+)
        \2
        \s*$
    """,
    re.VERBOSE,
)


def reencode_in_place(files: list[Path]) -> None:
    """Decode each existing `atr-b64:` value, re-apply yaml-unescape
    semantics, re-encode. Used once when the encoder is corrected so
    on-disk files match the new round-trip expectation.

    Idempotent across multiple runs: a file whose decoded value
    already matches the post-unescape form re-encodes to the same
    base64 and the rewrite is a no-op modulo encoding identity.
    """
    for p in files:
        if not p.is_file():
            print(f"warn: {p} not a regular file; skipped", file=sys.stderr)
            continue
        raw = p.read_bytes()
        out_lines: list[bytes] = []
        changed = False
        for line in raw.splitlines(keepends=True):
            text = line.decode("utf-8", errors="replace")
            m = ENCODED_VALUE_LINE_RE.match(text)
            if not m:
                out_lines.append(line)
                continue
            prefix, _q, sentinel_val = m.group(1), m.group(2), m.group(3)
            b64 = sentinel_val[len(SENTINEL):]
            try:
                decoded = base64.b64decode(b64).decode("utf-8")
            except Exception as e:
                print(f"warn: {p}: bad base64 in line: {e}", file=sys.stderr)
                out_lines.append(line)
                continue
            fixed = yaml_unescape_double_quoted(decoded)
            new_b64 = base64.b64encode(fixed.encode("utf-8")).decode("ascii")
            if new_b64 == b64:
                out_lines.append(line)
                continue
            out_lines.append(f'{prefix}"{SENTINEL}{new_b64}"\n'.encode("utf-8"))
            changed = True
        if not changed:
            print(f"    {p}: already migrated")
            continue
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_bytes(b"".join(out_lines))
        os.replace(tmp, p)
        print(f"    reencoded {p}")


# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--encode-only",
        nargs="+",
        type=Path,
        help="Encode the listed YAML files in place; skip the upstream fetch.",
    )
    parser.add_argument(
        "--reencode",
        nargs="+",
        type=Path,
        help="Decode + yaml-unescape + re-encode an already-encoded YAML file. "
             "Use after encoder bug fixes to migrate on-disk snapshots.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without touching disk (sync mode only).",
    )
    parser.add_argument(
        "--rules-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "internal" / "atr" / "rules",
        help="Destination root for vendored rules (default: internal/atr/rules).",
    )
    args = parser.parse_args()

    if args.encode_only:
        encode_in_place(args.encode_only)
        return 0

    if args.reencode:
        reencode_in_place(args.reencode)
        return 0

    # PyYAML preflight: minimize_and_encode_upstream needs PyYAML.
    # Check it up front so a missing dependency fails loudly BEFORE we touch
    # anything on disk, instead of silently skipping every rule as
    # "unparseable" and producing an empty corpus.
    try:
        import yaml  # noqa: F401  (import-for-side-effect preflight)
    except ImportError:
        print("sync mode needs PyYAML (pip install pyyaml); refusing to run "
              "without it to avoid vendoring an empty ruleset.", file=sys.stderr)
        return 1

    # Sync mode: fetch upstream (integrity-verified), encode in memory into a
    # STAGING dir, then atomically swap each category into place. Nothing in
    # the live rules tree is touched until the full encoded corpus is staged
    # and validated — so a failed/partial run (or --dry-run) never erases or
    # partially replaces the vendored snapshot.
    tarball = fetch_tarball_bytes(ATR_VERSION)
    print(f"==> Tarball size: {len(tarball)} bytes")

    staging = args.rules_root / f".sync-staging-{os.getpid()}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)
    try:
        counts = write_encoded_rules_from_tarball(tarball, staging)
        print("==> Encoded rules (staged):")
        total = 0
        for cat in sorted(counts):
            print(f"    {cat}: {counts[cat]}")
            total += counts[cat]
        print(f"==> Total: {total}")

        # Refuse to commit a suspiciously small corpus — a truncated download
        # or a mostly-unparseable upstream must not silently gut the snapshot.
        if total < MIN_TOTAL_RULES:
            print(f"==> Refusing to commit: only {total} rules staged "
                  f"(floor is {MIN_TOTAL_RULES}); leaving the existing snapshot "
                  f"untouched.", file=sys.stderr)
            return 1

        if args.dry_run:
            print("==> Dry run: staged corpus validated; leaving the live "
                  "rules tree untouched.")
            return 0

        # Atomic-ish swap per category: the expensive work (fetch + encode)
        # is already done in staging, so each swap is a local rmtree+rename
        # with a microsecond window, not a network-bound file-by-file write
        # over a freshly-wiped directory. The shell/ subdir is never touched.
        for cat in ALLOWED_CATEGORIES:
            staged_cat = staging / cat
            live_cat = args.rules_root / cat
            if not staged_cat.exists():
                continue
            if live_cat.exists():
                shutil.rmtree(live_cat)
            os.rename(staged_cat, live_cat)
        print("==> Swapped staged corpus into place.")
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return 0


if __name__ == "__main__":
    sys.exit(main())
