# Bring-your-own ATR rules

TrustGate ships an embedded set of [Agent Threat Rules](https://agentthreatrule.org)
(ATR) — an open, MIT-licensed YAML format for AI-agent threat detection —
covering skill-compromise, tool-poisoning, context-exfiltration,
privilege-escalation, and excessive-autonomy shapes. That embedded set is
**community/best-effort** support (see [`SUPPORT.md`](../../../SUPPORT.md)):
we curate it, but we can't chase every organization's specific false-positive
or false-negative case.

If you need a rule the embedded set doesn't have — or need to suppress one
that doesn't fit your environment — you don't have to fork and recompile.
Point `TRUSTGATE_ATR_RULES_DIR` at a directory of your own YAML rule files
and TrustGate loads them alongside the embedded bundle on every hook
invocation.

## Setup

```bash
export TRUSTGATE_ATR_RULES_DIR=/path/to/your/custom-rules
```

(Or set it in `~/.config/trustgate/env` / `/etc/trustgate/env` for a
persistent, per-user or fleet-wide configuration — see the env-file
precedence in `internal/config.EnvFiles`.)

## Directory layout

```text
custom-rules/
├── my-rule.yaml          # routed like the embedded MCP/read-file pool
├── another-rule.yaml
└── shell/                # optional: routed to the shell hook ONLY
    └── my-shell-rule.yaml
```

- Files directly in the directory are routed the same way the embedded
  bundle routes non-shell rules: they're available to `beforeMCPExecution`,
  and also to `beforeReadFile` **unless** their `tags.category` is
  `tool-poisoning` (those rules are authored against MCP `tool_args` /
  `tool_response` shapes and produce false positives on ordinary file
  content — see `internal/atr/bundle.go`'s `addParsedRule` doc-comment).
- Files under a `shell/` subdirectory are routed to `beforeShellExecution`
  only.

## Rule format

Plain, un-obfuscated YAML — no base64 encoding required (that's an
internal defense against AV false-positives on the *vendored* rule
snapshot; your own rules don't need it). See
[`sample-rule.yaml`](sample-rule.yaml) for a minimal working example, and
`internal/atr/rule.go`'s `allowedCategories` for the full set of
categories TrustGate will accept — anything else is silently dropped
(recorded in the decision-log-adjacent `Diagnostics()` output, never a
hard failure).

## Severity

`severity: critical` auto-denies (under `fail_closed`); everything else
is logged for audit but does not block. Start new rules at `high` or
`medium` until you've validated they don't false-positive on your own
team's normal workflow.

## Testing your rule

There's no built-in CLI for this yet (tracked as a future `doctor`/`explain`
admin-tooling improvement). For now, the fastest way to validate a rule is
to run the unit-test-style check directly:

```bash
TRUSTGATE_ATR_RULES_DIR=/path/to/your/custom-rules \
  echo '{"command":"your test command here"}' | trustgate-before-shell
```

and confirm the `permission` field in the output matches what you expect.
