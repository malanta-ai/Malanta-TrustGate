---
name: trustgate
description: Operate and troubleshoot Malanta TrustGate — the Cursor security hooks that check domains/IPs (reputation) and behavioral attack patterns (ATR) before shell, MCP, file-read, and WebFetch/WebSearch actions. Use when a TrustGate hook blocks, warns, or asks for human approval on an action, when interpreting or explaining a verdict, when a domain or command was denied/allowed/paused for approval, or when configuring TrustGate's mode, scope, overrides, retention, or provider.
---

# Malanta TrustGate

TrustGate is a set of Cursor enterprise hooks. Before an agent action runs,
the matching hook extracts candidate domains/IPs, asks a reputation provider
(Malanta by default) whether to block, runs a behavioral (ATR) pass over the
content, and returns a verdict. Everything is local except the reputation
lookup (domains/IPs only) and an opt-in audit sink.

Hooks: `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`,
`preToolUse` (WebFetch/WebSearch), and `beforeSubmitPrompt` (warn-mode-only).

## First rule: read the verdict, don't infer it

**Whether an action ran depends on the policy mode, not just reputation.**
An `allow` does NOT mean a host is clean — see the `trustgate-modes` rule
for per-mode behavior (warn mode allows on acknowledged retry, ask mode
pauses for a human approve/reject dialog, report-only never blocks, off
does nothing). Before stating anything about a host's
reputation, read the real verdict:

```bash
trustgate explain <decision_id>     # decision_id is printed in deny messages
tail -n 20 ~/.cache/trustgate/decisions.log   # JSON Lines, one verdict/line
```

Each log line carries `allow`, `label`, `reason`, `mode`, `hook`, and any
`warnings` (e.g. `warn-mode: acknowledged via retry`, `report-only mode:
would have denied`, or `ask mode: Cursor version ... degrading to a hard
deny` when `ask` ran on a Cursor build below the version floor). That is
the source of truth. **Exception: in `ask` mode do NOT investigate — see
the next section; hand the decision straight to the user.**

## If an action is paused for approval (ask mode) — STOP, ask the user

When a hook returns `permission:"ask"`, Cursor shows the user a native
**Approve / Reject dialog** and pauses the action *for the human to
decide*. (The dialog only appears for **shell** and **MCP** actions;
Cursor doesn't enforce `ask` for `WebFetch`/`WebSearch` or file reads, so
those are cleanly **denied** in ask mode, not paused — handle a deny
normally.) Your only job on an actual ask dialog is to get out of the way
and let the human decide:

- **Ask the user, plainly, whether to continue — then stop.** One or two
  sentences, e.g.: *"TrustGate flagged `<host>` as `<LABEL>` and is asking
  you to approve or reject this action. Approve in the dialog to continue,
  or reject to cancel."* Then wait for the human.
- **Do NOT troubleshoot or investigate.** Don't run `trustgate explain` /
  `doctor`, don't tail the decision log, don't analyze the score or rule.
  The reason (host, label, score, `decision_id`) is already in the message
  TrustGate returned — you have everything you need; looking things up is
  noise.
- **Do NOT offer workarounds or a menu of options.** Don't suggest a
  sandboxed/isolated fetch, `TRUSTGATE_ALLOW_USER_OVERRIDE`, disabling the
  hook, rewording, retrying, or any other bypass. Presenting escape
  hatches pressures the user past the exact safety control that just
  fired. If they want an override, they'll ask.
- **Do NOT retry, reword, split, or re-route the action** to get around
  the pause — that is trying to defeat a pending human decision.
- Only if the user *explicitly* asks "why was this flagged?" should you
  explain the reason; only if they *explicitly* ask to proceed anyway
  should you discuss an override (and only if an admin enabled it).

This is deliberately different from `enforce`/`warn`, where the outcome is
already decided and a `decision_id` explanation is useful. In `ask` the
human is mid-decision — help by being brief and stepping back, not by
working the problem.

## Diagnose a block

Use this when an action was **hard-denied** (enforce/warn) and the user
wants to understand or resolve it — NOT for an `ask` pause (see above,
just ask the user) and only investigate unprompted when a block is
actually blocking the user's work.

1. Get the `decision_id` from the deny message shown in the UI/agent.
2. `trustgate explain <decision_id>` — shows label, score, reason, hook.
3. Classify the deny by its `reason`:
   - `... flagged <host> as <LABEL> (malicious score ...)` → **reputation**
     deny. The host is on the block list / over threshold.
   - `ATR rule <ID> (<category>) fired: ...` → **behavioral (ATR)** deny.
     Independent of domain reputation; matched an attack shape.
   - `... unconfigured ...` → no provider API key and
     `TRUSTGATE_REQUIRE_CONFIGURED=true`. Run `trustgate setup`.
   - `<provider> unavailable: ...` → provider error under fail-closed.
   - `policy allowlist ...` / `out of scope ...` → allowed, not a block.
4. `trustgate doctor` — shows the mode, provider, scope, and config in
   effect (start here when behavior is surprising).

## Overrides and the warn flow

- **warn mode**: a flagged host denies once, then the SAME action proceeds
  on retry (a time-boxed grant is written). Do NOT auto-retry to bypass a
  warn — that self-acknowledges before a human decides. Stop and surface it.
- **ask mode** (Cursor 3.11.25+): a flagged **shell or MCP** action is
  emitted as `permission:"ask"` — Cursor shows a native approve/reject
  dialog and pauses for the human. Handle it exactly as in **"If an action
  is paused for approval"** above: ask the user plainly whether to
  continue, then stop — do not investigate the verdict or offer bypasses.
  `ask` degrades to a hard `deny` (never fails open) below the version
  floor (`TRUSTGATE_ASK_MIN_CURSOR_VERSION`) AND on events Cursor doesn't
  enforce `ask` for (`WebFetch`/`WebSearch`, file reads) — a deny there is
  expected, not a bug.
- **Manual override** (only if an admin set `TRUSTGATE_ALLOW_USER_OVERRIDE=true`):

```bash
trustgate override --domain <host> --minutes 15 --reason "why"        # per-host
trustgate override --repo <owner/repo> --minutes 15 --reason "why"    # per-repository
trustgate override --owner <owner> --minutes 15 --reason "why"        # per-account (broad)
trustgate override --clear [--domain <host> | --repo <owner/repo> | --owner <owner>]
```

  Use the flag the deny message names. `--owner` allows every repository
  under that account, so prefer `--repo` unless the deny was itself
  owner-scoped.

  Wildcards (`--domain '*'`) are rejected under domain scope; use
  `TRUSTGATE_OVERRIDE_SCOPE=time` for a deliberate blanket window.

## Configuration

Env-file precedence (later wins), all read fresh per hook invocation:
`/etc/trustgate/env` (MDM) < `~/.config/trustgate/env` (per-user) <
workspace `.env` (**only if `TRUSTGATE_ALLOW_CWD_DOTENV=1`** — off by
default) < process env. A managed `/etc/trustgate/env` can pin keys via
`TRUSTGATE_LOCKED_KEYS` (those always win).

Common settings:

| Var | Effect |
| --- | --- |
| `TRUSTGATE_MODE` | `off` / `report-only` / `warn` (default) / `ask` / `enforce` |
| `TRUSTGATE_ASK_MIN_CURSOR_VERSION` | Min Cursor version for `ask` mode (default `3.11.25`; below it `ask` → hard deny) |
| `TRUSTGATE_REQUIRE_CONFIGURED` | Fail closed instead of inert-allow when no key |
| `TRUSTGATE_SCOPE_MODE` / `_PATHS` | Restrict which workspaces are inspected |
| `TRUSTGATE_ATR_DISABLE` | Skip the behavioral pass (keep reputation) |
| `TRUSTGATE_ATR_RULES_DIR` | Bring-your-own ATR rules |
| `TRUSTGATE_MIN_MALICIOUS_SCORE` | Block threshold (finite number) |
| `TRUSTGATE_BLOCK_LABELS` / `_ALLOW_LABELS` | Verdict labels that deny/allow |
| `TRUSTGATE_ALLOW_USER_OVERRIDE` | Enable `trustgate override` |
| `TRUSTGATE_RETENTION_DAYS` | Local audit retention window |
| `MALANTA_API_KEY` | Provider credential (env or env file only, never config.json) |

The API key must live only in process env or one of the env files above —
never in `config.json`, source, or a commit.

## Retention and data

Local stores under `~/.cache/trustgate/`: a reputation TTL cache and the
decision log + audit DB. Only indicators, verdicts, and ATR rule
*identities* are stored (ATR matches are a SHA-256 digest, never the raw
matched bytes); raw commands/files/prompts are never stored or transmitted.

```bash
trustgate purge --days 90        # or --all; deletes audit rows + log lines
trustgate export --out audit.jsonl
```

Retention is applied by `trustgate purge` (manual/cron), not on the hot
path. See `PRIVACY.md` for the full disclosure.

## Known false positives and workarounds

- **Docs mentioning credential paths** (e.g. `~/.ssh/id_rsa`, `~/.aws/...`)
  can trip an ATR read-file rule. Escape hatch: `TRUSTGATE_ATR_DISABLE=true`
  in an env file (leaves the reputation cascade active).
- **Batched CTI/threat-intel work** that puts a flagged domain literally in
  a shell command line will (correctly) deny — the hook sees bytes, not
  intent. Move domain-bearing calls into a helper that reads the domain
  list from disk, so the flagged host never appears in argv.
- **Dotted config keys** (`git config user.email ...`) are scrubbed for
  common tools; an untooled one may false-positive on its TLD-shaped
  suffix.

For deployment/distribution details see the repository's `docs/` (admin,
architecture, providers).
