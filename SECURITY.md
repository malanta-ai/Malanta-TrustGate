# Security Policy

Malanta TrustGate runs as a trusted pre-execution hook inside Cursor: it
inspects shell commands, MCP tool calls, file reads, and (optionally) prompts
before they execute, and it holds a reputation-provider API credential in its
process environment on every invocation. Vulnerabilities here have an
unusually direct blast radius — a bypass can let a malicious command or
domain through silently, and a credential-handling bug can exfiltrate the
provider API key. We take reports in this area seriously and ask that you do
too.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Email **security@malanta.ai** with:

- A description of the vulnerability and its impact (e.g. "extraction bypass
  lets a malicious domain through," "SSRF via the generic provider config,"
  "the API key is written where an unprivileged user can read it").
- Steps to reproduce, or a minimal proof-of-concept payload.
- The affected version/commit.
- Your assessment of severity, if you have one.

We will acknowledge your report within **3 business days** and aim to provide
an initial assessment (confirmed / not applicable / need more info) within
**10 business days**. We ask that you give us a reasonable window to ship a
fix before any public disclosure — coordinated disclosure protects users who
haven't upgraded yet.

If you believe you have found a **live, exploited** issue affecting a real
deployment (not just this repository), please say so explicitly in your first
message so we can prioritize accordingly.

## Scope

In scope:

- The hook binaries (`cmd/trustgate-before-*`) and everything they import
  under `internal/`.
- The domain/IP extraction logic (`internal/extract`) — false negatives that
  let a malicious indicator bypass extraction are a real class of bug here,
  not just crashes or memory-safety issues.
- The reputation provider clients (`internal/reputation`), including the
  generic config-driven adapter's SSRF guardrails.
- The verdict cascade (`internal/verdict`) and its fail-closed/fail-open
  semantics.
- Credential handling: how the reputation API key is sourced, stored on
  disk, and whether it can leak via logs, redirects, or error messages.
- The installer scripts (`scripts/install-hooks.sh`/`.ps1`) and their file
  permission choices.

Out of scope:

- Vulnerabilities in a third-party reputation provider's own API or service
  (report those to the vendor).
- Findings that require an attacker to already have arbitrary code execution
  on the machine running the hook (at that point the hook is not a
  meaningful trust boundary).
- The upstream Agent Threat Rules (ATR) ruleset content itself — report
  issues with specific rules to the upstream project; report only "our
  integration of ATR is broken/bypassable" here.

## What "vulnerability" means for this project

Beyond the usual categories (RCE, injection, credential exfiltration,
privilege escalation), please also report:

- **Extraction bypass**: a shell command, MCP call, file, or prompt that
  contains a malicious domain/IP but is not submitted to the reputation
  provider (a false negative in `internal/extract`).
- **SSRF**: any way to make the generic provider (or the Malanta provider)
  contact a host outside its configured/validated allowlist, including via
  redirects, DNS tricks, or path-template injection.
- **Fail-open regressions**: any code path where an error, timeout, or
  malformed input results in `allow` when the documented behavior (given
  `fail_closed`) is `deny`.
- **Wire-shape drift**: any change that causes Cursor to fail to parse a
  deny verdict (Cursor fails OPEN on unparseable hook output — see
  `internal/verdict/verdict.go`'s `AsJSON`).

## Marketplace incident notification (Anysphere / Cursor)

Because TrustGate is distributed as a Cursor Marketplace plugin, an
incident affecting plugin users may trigger an external notification
obligation beyond the coordinated-disclosure process above. If Malantai
becomes aware of a security vulnerability, data breach, or other security
incident that affects or may reasonably affect the published Marketplace
plugin or Plugin Data, the publisher will promptly notify Anysphere. Any
user notice will be provided where required by law or otherwise
appropriate to protect users. The initial notice to Anysphere may be
preliminary and may be supplemented as the investigation progresses.

- Notify Anysphere (Cursor) at **legal@cursor.com** promptly after
  becoming aware of the issue, per the Cursor Publisher Terms'
  incident-notice requirement, including the information then reasonably
  available, such as a summary of the issue, affected or potentially
  affected versions, the known or potential user impact, and the
  remediation/timeline.
- Coordinate the public-disclosure timing with both the reporter and
  Anysphere so the Marketplace listing and any advisory stay consistent.
- Publish a fixed version and, where warranted, a security advisory on the
  repository.

This procedure is the publisher's responsibility; a reporter does not need
to contact Anysphere themselves. Email **security@malanta.ai** as above
and we will handle the Marketplace-side notification.

## Supported versions

This project is pre-1.0 and moves quickly. Security fixes are made against
the `main` branch; we do not maintain long-lived release branches yet. Once
tagged releases exist, this section will be updated with a support matrix.
