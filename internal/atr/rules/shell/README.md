# Shell ATR rule subset

Hand-curated rule pack for `beforeShellExecution`. These rules are NOT
synced from the agent-threat-rules npm package — most upstream rules
target `tool_response` / `agent_output` / `content` fields, which is the
wrong surface for a shell command line. Instead, each rule here is a
shell-shape-distinctive pattern selected by hand to catch recon and
resource-development command shapes without firing on common developer
commands.

## Provenance and license

Unlike the vendored `ATR-2026-XXXXX` rules elsewhere in this bundle
(synced from the upstream MIT-licensed `agent-threat-rules` package),
the `TRUSTGATE-SHELL-*` rules in this directory were originally
authored from scratch by Malanta for this project (initially under the
`MALANTA-SHELL-*` id prefix, renamed for the open-source release). They
are original content, not third-party code, and are released under
this repository's [MIT license](../../../../LICENSE) like everything
else here — there is no separate license or usage restriction on this
directory.

## Selection rationale (mandatory)

Every rule file must carry a `# trustgate_shell_selection_rationale:`
comment block in its YAML header explaining:

1. What attack shape this rule catches on a shell command line.
2. Why this regex is distinctive enough not to fire on dev commands.
3. Upstream ATR rule ID lineage (if directly inspired by one).
4. Known FP risks and the mitigation chosen (severity downgrade,
   tighter regex, etc.).

## Severity gate

The verdict layer auto-denies on `severity: critical`. `high`,
`medium`, `low` are decision-log only.

The split below targets ≤ 1% FP rate on a real-developer shell
corpus:

- `critical` is reserved for shapes that have NO legitimate dev
  use case (private key file reads, exfil POST shape with sensitive
  file capture, setuid bit assignment, kernel-device destruction,
  authorized_keys writes, reverse-shell shapes).
- `medium` covers shapes that are usually-malicious-but-occasionally-
  legitimate (curl-pipe-sh, env|grep token, crontab edit). Logged
  but not auto-denied.

## Categories used

Per `internal/atr/rule.go::allowedCategories`, shell rules may only
use:

- `privilege-escalation`
- `excessive-autonomy`
- `context-exfiltration`

Adding any other category requires expanding the test in
`rules_test.go::TestShellSubsetLoad` and is a deliberate scope
change.
