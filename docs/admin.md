# Admin operability

TrustGate's default posture is **warn**: a flagged domain is blocked
once with an explanation, and re-running the same action proceeds — an
audit + notify posture that educates without hard-blocking day-one work
(the friction that otherwise gets a security tool uninstalled). It is
deliberately NOT `enforce` by default; a fleet/enterprise rollout is
expected to move to (and usually lock) `enforce` once the team is
onboarded. For a team or enterprise rollout, an admin usually needs more:
a way to diagnose why something got blocked, a way to tune policy without
shipping a new binary, a way to see decisions across a fleet, and a way
to unblock a specific false positive without weakening the control for
everyone else. This doc covers what's built for that, and — just as
importantly — what isn't.

## 1. Every decision has a `decision_id`

Every verdict (allow or deny, cascade-produced or a bootstrap error)
carries a short, opaque `decision_id` (12 hex characters, e.g.
`a1b2c3d4e5f6`). A deny's `user_message`/`agent_message` includes it:

```text
malanta flagged malicious.example as MALICIOUS (malicious score 0.9885) [decision_id: a1b2c3d4e5f6]
```

If you've set `TRUSTGATE_HELP_MESSAGE` (e.g. a support URL or Slack
channel), it's appended too. This turns "the agent got blocked" into a
support ticket with a lookup key — see `trustgate explain` below.

## 2. `trustgate doctor` and `trustgate explain`

`trustgate doctor` prints a diagnostic report: config-in-effect, which
of the three env files exist, lookup-cache and audit-table health, a
TCP-reachability check against the configured provider's host(s), and
whether `~/.cursor/hooks.json` references these hooks at all. Start here
when a hook seems to be misbehaving — most "why did this get blocked"
investigations start with confirming the config TrustGate is actually
running with matches what you think it's running with.

`trustgate explain <decision_id|indicator>` looks up a specific decision
by its ID, or lists recent decisions mentioning a given indicator
(domain or IP), reading from the local SQLite audit table
(`~/.cache/trustgate/audit.db`).

Both read **only** the structured fields already in the decision log —
indicator, provider, verdict, score, ATR rule IDs. Raw command lines,
file contents, and prompts are never captured anywhere in this pipeline
(see `internal/audit`'s package doc for the redaction contract) — there
is nothing more sensitive for these commands to accidentally expose. An
ATR match is recorded as a one-way SHA-256 fingerprint of the matched
substring plus its byte length (not the substring itself), so even the
bytes a behavioral rule matched never land on disk.

## 3. Policy: `mode` and a minimal allowlist

`TRUSTGATE_MODE` (or `mode` in `config.json`) is one of:

- `warn` (**default**) — audit + notify without hard-blocking: a flagged
  action denies **once**, with a message explaining why and telling the
  user to retry to proceed; retrying the identical action is acknowledged
  and allowed, then stays quiet for a window. Provider errors/timeouts
  **fail open** here (a TrustGate/provider hiccup never blocks the action
  — matching `report-only`), so warn never delays a developer's work on
  infrastructure trouble. See §5.2 for the full mechanism, why it exists,
  and its trade-offs — it's the right default for onboarding and for an
  org that wants visibility into agents touching disreputable
  infrastructure without a hard-enforcement posture.
- `ask` — human-in-the-loop for **interactive** use (Cursor 3.11.25+): a
  flagged action is emitted as `permission:"ask"`, so Cursor renders a
  native approve/reject dialog and **pauses** until a human decides — the
  agent has no retry-to-allow path it can self-trigger (unlike `warn`). It
  is **version-gated so it never fails open**: on Cursor builds below the
  ask floor (default `3.11.25`, `TRUSTGATE_ASK_MIN_CURSOR_VERSION`) it
  degrades to a hard `deny`. Best for a developer actively driving an
  interactive session; for **autonomous/auto-run** agents prefer `warn`,
  because with no human present the dialog is auto-approved. See §5.2.1.
- `enforce` — block as normal, **fail-closed**: a flagged domain, and any
  provider error/timeout/misconfiguration, denies outright. This is the
  hard-enforcement posture; a fleet typically sets and locks it once the
  team is past onboarding.
- `report-only` — run the full cascade so the audit trail shows what
  *would* have happened, but never actually block. Useful for rolling
  out TrustGate to a team without any friction at all (not even warn's
  block-once), or for validating a new provider/threshold before
  committing to enforcement.
- `off` — skip extraction and the provider entirely; a fast no-op allow.

Why `warn` and not `enforce` as the default: a fresh individual install
that hard-blocked on day one — before the developer understands what
TrustGate is or how to override — is the fastest path to an uninstall.
warn keeps them moving (block-once-then-proceed, and never blocked by a
provider hiccup) while still surfacing every flagged domain. The stronger
guarantee lives in `enforce`, which a security team turns on (and locks
via `TRUSTGATE_LOCKED_KEYS`, §9) once the fleet is onboarded.

**Choosing a mode (the intended tiering):** `warn` is the universal
default — consistent and safe-degrading on every Cursor version and in
both interactive and autonomous sessions. `ask` is an **interactive**
per-developer upgrade on 3.11.25+ (a real human gate the agent can't
self-clear); it is deliberately *not* the default because its dialog is
auto-approved in an autonomous/auto-run session — its weakest behavior
would land exactly where the risk is highest, and Cursor gives the hook
no signal to tell the two apart. `enforce` (locked) is the actual
security floor for a managed fleet: the only mode that *guarantees* a
flagged action is blocked regardless of who is at the keyboard.

`TRUSTGATE_POLICY_ALLOWLIST` (CSV of exact indicator values,
case-insensitive) always allows a matching host before cache or provider
consultation — useful for a known-good internal domain your reputation
provider doesn't recognize.

**What this is not**: the allowlist is an unconditional, non-expiring,
flat list. It has no per-entry owner, expiry, or justification metadata
and no fleet/group scoping of its own — simpler to reason about, and you
can still scope it per-machine via the normal env-file layering
(`/etc/trustgate/env` for fleet-wide, `~/.config/trustgate/env` for
per-user). If you need per-entry expiry, track it externally (e.g. a
comment in your MDM config's change history).

## 4. Opt-in audit sink

Setting `TRUSTGATE_AUDIT_SINK_URL` (plus
`TRUSTGATE_AUDIT_SINK_HOST_ALLOWLIST`, required) turns on best-effort
delivery of decisions to an HTTPS collector you control:

```bash
export TRUSTGATE_AUDIT_SINK_URL=https://collector.example.com/trustgate-events
export TRUSTGATE_AUDIT_SINK_HOST_ALLOWLIST=collector.example.com
export TRUSTGATE_AUDIT_SINK_VERBOSITY=denies  # denies (default) | all | off
```

Same HTTPS-only / non-routable-host / explicit-allowlist guardrails as
the reputation provider's own base URL — this is a second network egress
path carrying decision data, and gets the same scrutiny. Cross-host
redirects are blocked at the HTTP client level.

**Known trade-off, read before enabling**: the sink call is not
async/fire-and-forget. Every hook binary is a fresh, short-lived
subprocess that exits immediately after emitting its verdict — there's
no daemon for a background goroutine to outlive into. A goroutine
started right before the process exits would almost always be killed
mid-flight. Rather than pretend otherwise, the sink call is
**synchronous with an 800ms deadline**, issued *after* the verdict JSON
has already been written to stdout (so the OS pipe lets Cursor start
consuming the answer while the sink call finishes). In practice this adds
up to 800ms to the hook subprocess's total lifetime when the sink is
enabled — bounded and opt-in, but not literally zero-cost. A genuinely
async sink would require a long-running daemon, which this build does
not include.

**Not built**: syslog and file sink modes (HTTP/HTTPS only today);
per-event batching (each decision is its own POST).

## 5. Admin-gated user override, and `warn` mode

Two related but distinct mechanisms, both built on a shared grant store
(`internal/override`, `~/.cache/trustgate/override.json`):

- **The CLI break-glass** (`trustgate override`, this section) — for
  orgs running `enforce` mode who still want a deliberate, logged,
  per-domain exception path for a developer hitting a false positive.
- **`warn` mode** (§5.2) — a whole different *posture*, for orgs that
  don't want to hard-block at all, but do want every touch of
  disreputable infrastructure audited and the user notified.

### 5.1 CLI break-glass override (`enforce` mode)

Disabled by default. An admin sets `TRUSTGATE_ALLOW_USER_OVERRIDE=true`
in **managed** config (e.g. `/etc/trustgate/env`, an MDM-owned file a
regular user can't edit) to allow it at all. `TRUSTGATE_OVERRIDE_SCOPE`
controls whether a grant is per-domain or blanket:

- `domain` (default) — a grant only unblocks the **specific host** it
  names. Tighter: overriding a false positive on
  `internal-tool.example` never also unblocks an unrelated flagged
  domain that happens to come up in the same session.
- `time` — a single blanket grant that unblocks **any** denied host
  for the window. Simpler "let me through for N minutes" behavior.

```bash
# domain scope (default) — grant one or more specific hosts
trustgate override --domain internal-tool.example --minutes 15 \
  --reason "investigating a false positive"
trustgate override --domain a.example --domain b.example --minutes 15 --reason "..."

# a flagged GitHub repository (accepts a URL too — it's canonicalized to
# the owner/repo the deny named)
trustgate override --repo acme/backdoor --minutes 15 --reason "..."

# a flagged GitHub owner. BROADER than --repo: this allows every
# repository under that account for the window.
trustgate override --owner acme --minutes 15 --reason "..."

# flags are repeatable and mixable in one command
trustgate override --domain a.example --repo acme/backdoor --minutes 15 --reason "..."

# time scope — no target flag needed (and ignored if passed)
export TRUSTGATE_OVERRIDE_SCOPE=time
trustgate override --minutes 15 --reason "..."
```

Use the flag matching what was blocked — the deny message names it.
Grants match by exact value, so an `--owner` grant does not cover a
repository deny, and vice versa.

This writes a time-boxed grant to `~/.cache/trustgate/override.json`;
every hook invocation checks it and, if unexpired and matching (exact
host, or a blanket `*` grant), flips a would-be deny to allow **with a
warning recorded in both the JSON-Lines log and the audit table** —
never a silent bypass. `trustgate override --clear` removes every
grant; `trustgate override --clear --domain internal-tool.example` (or
`--repo` / `--owner`) removes just one. Changing `TRUSTGATE_OVERRIDE_SCOPE` only affects what
a *new* grant writes — it never invalidates a grant you already hold.

If `TRUSTGATE_ALLOW_USER_OVERRIDE` is not set, writing a grant yourself
does nothing — the CLI warns you about this at write time. The
admin-side flag is the real gate, not a grant's existence or secrecy.

The deny message for an `enforce`-mode denial includes the exact
command to run, then retry:

```text
malanta flagged malicious.example as MALICIOUS (malicious score 0.9200) [decision_id: ...]
To allow temporarily: trustgate override --domain malicious.example --minutes 15 --reason "<why>", then retry.
```

The flag matches the kind that was denied, so a repository denial reads:

```text
malanta flagged GitHub repository acme/backdoor as MALICIOUS (malicious score 1.0000) [decision_id: ...]
To allow temporarily: trustgate override --repo acme/backdoor --minutes 15 --reason "<why>", then retry.
```

### 5.2 `warn` mode: audit + notify, without hard-blocking

`TRUSTGATE_MODE=warn` is a distinct admin-selected **posture** (not a
user escape hatch — it does not require `TRUSTGATE_ALLOW_USER_OVERRIDE`).
It's for an org that wants agents' contact with disreputable
infrastructure fully audited and the user notified, but does not want
to hard-block outright.

**`warn` vs `ask`: pick by audience.** `warn` (this section) is the
audit+notify posture that works on **every** Cursor version and in
**autonomous / auto-run** sessions: it injects the warning + audit trail
into the agent loop itself and never depends on a human being present.
`ask` (§5.2.1) is the **interactive** human-in-the-loop posture on Cursor
3.11.25+: it renders a native approve/reject dialog for shell/MCP actions
and pauses for a human. Choose `warn` for fleets and autonomous agents
(where an `ask` dialog would be auto-approved with no human to click it,
or on older Cursor builds); choose `ask` for a developer actively driving
an interactive session. `ask` is version-gated so it never fails open —
below the floor it degrades to a hard `deny` (see §5.2.1).

**How `warn` resolves a flagged action.** `warn` is built on `deny` +
`user_message` — the message Cursor renders on a block — and treats the
identical retry as acknowledgement:

1. **First touch** of a flagged domain: hard-deny, with a message
   explaining the flag and telling the user this access is audited and
   that retrying the identical action will proceed:

   ```text
   malanta flagged malicious.example as MALICIOUS (malicious score 0.9200) [decision_id: ...]
   Audited — re-run the same action to allow it briefly.
   ```

2. **Retry** — re-issuing the identical action re-fires
   `beforeShellExecution`/`beforeMCPExecution`, and TrustGate treats
   that as acknowledgment: the action is allowed, and the host is
   granted for `TRUSTGATE_OVERRIDE_WINDOW_MIN` minutes (default 15),
   scoped per `TRUSTGATE_OVERRIDE_SCOPE` exactly like the CLI
   break-glass above. Note: there is **no** one-click "Try Again" button
   in Cursor's UI for a policy block, so "retry" means re-running the
   identical command — the agent re-attempting on its own, or you
   re-sending it.
3. **Within the window**, the same host (or, under `time` scope, any
   host) is allowed silently — no re-warning.
4. **After the window expires**, the next touch warns again.

The whole mechanism lives in the existing before-hooks — the retry
re-fires the same event, so there's nothing extra to install or wire.

**Provider errors fail OPEN under warn.** The block-once flow above is
only for a domain the provider actually flagged. If the provider itself
errors or times out (Malanta slow, down, or a cold-start stall), warn
mode **allows** the action with a warning in the decision log — it does
NOT block. This matches `report-only` and is deliberate: warn's whole
point is to not delay a developer's work, and hard-denying every action
while TrustGate's own backend is having a bad moment is exactly the
friction that gets the tool uninstalled. `enforce` is the opposite here —
a provider error fails **closed** (deny). So the choice between warn and
enforce is also a choice about what happens when TrustGate can't reach
its provider: warn keeps you moving, enforce stops you. (ATR behavioral
denies are unaffected by this — they never depend on the provider.)

**Two guards keep the agent from silently acknowledging the warning
for you.** Because the retry is what proceeds, an unguarded warn would
let the agent auto-retry the audited-retry message it just received and
self-clear the block before a human ever sees it. Both mitigations are
on by default:

- **The agent is told NOT to retry.** On a warn first touch the human's
  `user_message` says "re-run the same action to allow it briefly," but
  the agent's separate `agent_message` says the opposite: the action is
  blocked pending human review, do **not** retry it automatically, stop
  and let the user decide. (The four execution hooks send distinct
  user/agent messages; every non-warn deny still sends identical text
  to both.)
- **A retry that arrives too fast doesn't count.**
  `TRUSTGATE_WARN_ACK_MIN_SECONDS` (default `4`) is a minimum dwell
  between the first-touch warn and the retry that acknowledges it. A
  retry sooner than that — an agent auto-retry is typically sub-second —
  re-warns instead of promoting, while a human who reads the message and
  re-runs (seconds later) is acknowledged normally. Set it to `0` to
  disable the dwell gate (any retry acknowledges immediately, the
  original behavior). The pending marker survives a too-soon retry, and
  an agent hammering retries cannot reset the dwell clock (the marker's
  creation time is preserved), so the window is measured from the first
  warn, not the last retry.

**Read this before enabling.** Even with both guards, `warn` cannot
*guarantee* a human is in the loop: Cursor gives the hook no signal
distinguishing a human "Try Again" from an agent auto-retry, so the
guards are defense-in-depth (the agent could ignore the "do not retry"
instruction, and an agent that keeps retrying past
`TRUSTGATE_WARN_ACK_MIN_SECONDS` still eventually acknowledges). `warn`
is an **audit + notify** posture, not an enforcement boundary, and the
audit requirement is met unconditionally regardless of who/what
triggered the retry — every step (the warn-deny, the promotion, the
windowed allows) is written to both the JSON-Lines decision log and the
SQLite audit table. If you need a hard guarantee that a human reviewed
the action before it proceeds, use `enforce` mode instead (with or
without the CLI break-glass) — `warn` is deliberately weaker than that,
by design, in exchange for not blocking legitimate automated workflows
outright.

**ATR (behavioral detection) is never softened by `warn`.** See the
known-limitation note below — an ATR-triggered deny is a hard,
non-negotiable block under every mode, `warn` included; only a
domain-reputation deny (from the Malanta/generic-provider cascade
itself) is ever eligible for the deny-once-then-allow-on-retry
treatment.

### 5.2.1 `ask` mode: native human approve/reject (Cursor 3.11.25+)

`TRUSTGATE_MODE=ask` emits Cursor's `permission:"ask"` on a flagged
action instead of `warn`'s deny-once-then-allow-on-retry. Cursor renders
its own approve/reject dialog (carrying TrustGate's `user_message`) and
**pauses** the action until a human clicks — the agent has no
retry-to-allow path it can self-trigger. This is the mode to use when a
human is actually sitting at the session and you want them to make the
call on every flagged host, without the `warn` caveat that an agent
could self-acknowledge the retry.

**It is version-gated so it never fails open.** Cursor only honors `ask`
for the execution hooks from **3.11.25** onward; older builds accept the
verdict and silently ignore it (the action proceeds). TrustGate detects
the running Cursor version from the hook payload's `cursor_version`
field (falling back to the `CURSOR_VERSION` env var) and:

- **at or above the floor** → emits `permission:"ask"` (the dialog);
- **below the floor, or version unknown** → degrades to a hard
  `permission:"deny"` and records a
  `ask mode: Cursor version ... does not meet the ask floor ...;
  degrading to a hard deny` line in the decision log.

The floor defaults to `3.11.25` and is overridable (and lockable by MDM)
via `TRUSTGATE_ASK_MIN_CURSOR_VERSION` once a more precise
first-supporting version is confirmed for a given fleet.

**The dialog only appears for shell and MCP actions.** Cursor enforces
`permission:"ask"` for **`beforeShellExecution`** and
**`beforeMCPExecution`** only. Per Cursor's hooks docs, `ask` is
*accepted-but-not-enforced* for `preToolUse` (the `WebFetch` / `WebSearch`
surface), `beforeReadFile` is `allow`/`deny` only, and `subagentStart`
treats `ask` as `deny`. On those events an emitted `ask` would render no
dialog — the human could never approve — so TrustGate **degrades `ask` to
a hard `deny`** there (logging `ask mode: Cursor does not enforce
permission:"ask" for <hook>; degrading to a hard deny`). Practical effect:
in `ask` mode a flagged shell command or MCP tool call pops the
approve/reject dialog, but a flagged `WebFetch`/`WebSearch` or a flagged
read is cleanly **blocked** (with the reason + override hint), not paused
for approval. This is a Cursor platform limitation, not a policy choice;
it will lift automatically for those events if/when Cursor starts
enforcing `ask` for them.

**`ask` vs `warn` for autonomous agents.** In a non-interactive /
auto-run session there is no human to click the dialog, so an `ask`
verdict is auto-approved and the flagged action proceeds — `ask`'s
guarantee is only as strong as "a human is present." For fleets running
autonomous agents, prefer `warn` (which injects the audited
do-not-retry `agent_message` into the loop and works on every version)
or `enforce` (hard block). `ask` is the interactive-desktop mode.

Everything else is unchanged from a normal deny: a clean host is a plain
allow, ATR behavioral denies are still hard blocks, and every step is
written to the decision log + SQLite audit table.

### 5.3 Prompt-layer warn (`beforeSubmitPrompt`)

`beforeSubmitPrompt` is wired as an *early* warn surface, and it is
**active only when `TRUSTGATE_MODE=warn`**. In `ask`, `enforce`,
`report-only`, or `off` the prompt hook allows unconditionally
(`continue:true`) and stays out of the way — the execution hooks enforce
in every mode, and hard-blocking a prompt at submission time is exactly
the aggressive, false-positive-prone behavior this hook was originally
deferred for. `ask` is no exception: `beforeSubmitPrompt` has no
`permission:"ask"` lever (its outputs are `continue` true/false only), so
`ask`'s approve/reject dialog is rendered by the execution hooks, not
here. So the rest of this section applies only under `warn`.

When you type a prompt that both names a flagged domain AND uses an action
verb (`curl`, `fetch`, `ping`, `install`, `clone`, `visit`, ...), the
warning surfaces at submission time instead of waiting for the agent to
run the command:

- **Mention without an action verb** ("is `suspicious.example` malicious?")
  passes silently — the action-verb gate keeps conversational questions
  from being blocked.
- **Action-verb prompt** ("curl `suspicious.example`") warns once
  (`continue:false` with the audited message). Re-submitting the same
  prompt is the acknowledgement (`continue:true`); it writes an override
  grant, scoped per `TRUSTGATE_OVERRIDE_SCOPE` exactly like the
  execution-hook warn flow above.
- **Acceptance propagates.** Because all hooks share one `override.json`,
  the grant written when you accept the prompt is honored by the
  execution hooks: the agent's subsequent `curl suspicious.example` (shell
  hook), MCP call, etc. proceed without re-warning. Under `domain` scope
  that covers exactly the accepted host; under `time` scope it's the
  usual blanket window.

Two deliberate properties:

- **Fails soft — a TrustGate hiccup never blocks a prompt.** The hook is
  registered `failClosed: false` (the other four stay `true`), so a
  prompt-hook crash/timeout lets the prompt through. And a provider error
  (Malanta slow or unavailable) also **fails open** at this hook — unlike
  the execution hooks, a Malanta hiccup never blocks you from submitting a
  prompt (`internal/verdict.failClosedOnProviderError` special-cases
  `beforeSubmitPrompt`). The prompt layer is a soft early warn; the
  execution hooks remain the fail-closed enforcement boundary and still
  gate the actual action with a real verdict, so a prompt-layer miss just
  means the earlier warning didn't fire that once.
- **It only sees what you typed.** Domains the agent generates itself
  (or gets from an MCP response) never appear in your prompt, so they're
  caught at the execution hooks, not here. This surface is an *earlier,
  nicer touch* for user-typed domains, never a replacement for the
  execution hooks.

As with every warn deny, there is no one-click "Accept" button in
Cursor's UI; accepting means re-submitting the identical prompt.

## Known limitation: ATR-triggered denies bypass this funnel

The reputation cascade (`internal/verdict.Compose`) and everything above
(mode, allowlist, override, warn, decision_id) are all one funnel
(`finalizeDecision`). ATR (behavioral detection) runs **after** `Compose`
returns and can flip an otherwise-allowed decision to deny on its own.
That flip does **not** pass back through the mode/override funnel — so
`report-only`/`off` mode, the CLI override, and `warn`'s retry-to-proceed
mechanism all do NOT apply to an ATR-triggered deny: it never becomes
eligible for a prompt, override, or acknowledged retry — it just stays
denied. (The audit trail stays correct regardless: when ATR flips the
decision, a final post-ATR record is written to the audit table and the
decision log, so what's recorded matches what Cursor received.) In short:
an ATR behavioral deny is a hard block that the softer modes and the
override paths cannot loosen.

## 6. `preToolUse` strict mode

`preToolUse` fires for *every* tool the agent runs (per Cursor's own
docs), but this project only actively inspects `WebFetch`/`WebSearch` and
otherwise allows unconditionally — `Shell`/`Read`/MCP tool calls have
their own, richer dedicated hooks, and Cursor's tool catalog isn't fully
enumerable from the outside (its docs explicitly describe the
`preToolUse` matcher's tool-name list as illustrative, not exhaustive).

Setting `TRUSTGATE_TOOLUSE_STRICT=true` flips the default for any tool
name that is: (a) not `WebFetch`/`WebSearch`, (b) not covered by a
dedicated hook (`Shell`, `Read`, `TabRead`, `MCP:*`), and (c) not in the
hand-maintained safe list (`Write`, `Delete`, `Grep`, `Glob`,
`TodoWrite`, `SwitchMode`, `ReadLints`, `EditNotebook`, `AskQuestion`) —
such a tool call is **denied** rather than silently allowed. Extend the
safe list per-install with `TRUSTGATE_TOOLUSE_ALLOWLIST` (CSV).

**Read this before enabling**: because the safe list isn't guaranteed
exhaustive, strict mode can false-deny a legitimate Cursor tool it
doesn't recognize — including a new tool a future Cursor release adds.
`preToolUse` only supports `allow`/`deny` (the `ask` permission isn't
enforced for this event, per Cursor's own docs), so there's no
"prompt the user instead" middle ground here. Turn this on only if
you've validated your team's actual tool usage against the safe list
first (`trustgate doctor` can help, though it doesn't enumerate tool
usage today — that's a manual check for now).

## 7. Non-permissive empty `workspace_roots` (opt-in)

The read-file hook's workspace-containment check treats an
empty/missing `workspace_roots` as "no constraint" by default — this
keeps CI harnesses and any Cursor version that doesn't yet populate the
field working. Setting
`TRUSTGATE_READFILE_STRICT_WORKSPACE_ROOTS=true` flips that: an
empty `workspace_roots` is treated as "outside every workspace," so
domain extraction and ATR are skipped for that read (the read itself is
still allowed — this only removes one branch of inspection, matching
how a genuine symlink-escape result is already handled). Enable this if
you'd rather lose read-time scanning coverage on an edge case than ever
treat "we don't know the workspace" as equivalent to "trust this path."

## 8. Zero-touch defaults

A fresh, unconfigured install (the default Malanta provider, no API key
yet) must never brick the very first agent action. When TrustGate has
nothing to check a domain against, it defaults to **inert allow**: the
action proceeds, and a one-time notice goes to stderr the first time this
happens (tracked via a marker file so it doesn't repeat on every
invocation):

```text
trustgate: not configured yet (no reputation provider API key) — allowing
all actions until you run `trustgate setup`. This notice won't repeat.
```

`trustgate doctor` also calls this out explicitly. This only applies when
there's actually something to look up — an event with no extracted hosts
allows trivially either way, configured or not.

For a **fleet**, silent inert-allow is the wrong default: a provisioning
failure (the MDM profile didn't land the key) should be loud, not
invisible. Set `TRUSTGATE_REQUIRE_CONFIGURED=true` in the MDM-managed env
file (alongside the key itself) to flip this: an unconfigured state then
fails per `TRUSTGATE_FAIL_CLOSED` (deny by default) instead of allowing.
Individual/unmanaged installs should leave this unset (default `false`).

## 9. Managed-config policy lock

`/etc/trustgate/env` (the MDM-managed system file) can declare a set of
env vars as **locked**, so a user-owned layer (`~/.config/trustgate/env`,
`.env`, or ambient process env) can never weaken them:

```bash
# in /etc/trustgate/env
TRUSTGATE_FAIL_CLOSED=true
TRUSTGATE_MODE=enforce
TRUSTGATE_LOCKED_KEYS=TRUSTGATE_FAIL_CLOSED,TRUSTGATE_MODE
```

With this in place, even if a developer's own `.env` sets
`TRUSTGATE_FAIL_CLOSED=false` or `TRUSTGATE_MODE=off`, the system file's
values win. Only a fixed set of security-relevant keys can be locked
(`TRUSTGATE_MODE`, `TRUSTGATE_FAIL_CLOSED`, `TRUSTGATE_REQUIRE_CONFIGURED`,
`TRUSTGATE_PROVIDER`, `TRUSTGATE_POLICY_ALLOWLIST`,
`TRUSTGATE_ALLOW_USER_OVERRIDE`, `TRUSTGATE_AUDIT_SINK_URL`,
`TRUSTGATE_AUDIT_SINK_VERBOSITY`, `TRUSTGATE_AUDIT_SINK_HOST_ALLOWLIST`,
`TRUSTGATE_ATR_DISABLE`, `TRUSTGATE_SCOPE_MODE`, `TRUSTGATE_SCOPE_PATHS`,
`TRUSTGATE_TOOLUSE_STRICT`, `TRUSTGATE_READFILE_STRICT_WORKSPACE_ROOTS`,
`TRUSTGATE_OVERRIDE_SCOPE`, `TRUSTGATE_OVERRIDE_WINDOW_MIN`)
— naming anything else in `TRUSTGATE_LOCKED_KEYS` is silently ignored.
`TRUSTGATE_LOCKED_KEYS` itself can **only** ever be read from
`/etc/trustgate/env`; a user-owned layer setting it has no effect, so a
developer can't grant themselves the ability to lock keys. A key named
as locked but given no value in the system file is left alone (there's
nothing to lock it *to*) rather than being erased. `trustgate doctor`
shows which keys are currently locked.

## 10. Workspace/project scoping

`TRUSTGATE_SCOPE_MODE` (`all` default / `allowlist` / `denylist`) plus
`TRUSTGATE_SCOPE_PATHS` (CSV of path globs) let an operator narrow which
workspaces TrustGate actually enforces on, evaluated against the hook
payload's own `workspace_roots`:

```bash
# Only enforce inside two work trees; every other workspace (personal
# side projects, scratch dirs, ...) allows immediately, without ever
# consulting the cache or the reputation provider.
export TRUSTGATE_SCOPE_MODE=allowlist
export TRUSTGATE_SCOPE_PATHS=/Users/me/work/*,/Users/me/company/*
```

A glob ending in `/*` or `/**` also matches everything nested under that
directory (plain `filepath.Match` globs don't cross path separators, so
this directory-prefix special case is what makes `/Users/me/work/*`
cover `/Users/me/work/proj/sub/dir`, not just direct children).

**Read this before enabling `allowlist` mode**: it's an opt-in
convenience for "don't slow down my personal projects," not a security
boundary — anything outside the allowlist skips enforcement entirely.
`denylist` mode is the more conservative choice for most orgs: enforce
everywhere except a short list of known-exempt paths. Absent
`workspace_roots` information (a hook payload that doesn't carry it) is
always treated as in-scope — this feature only narrows enforcement when
there's positive evidence to narrow on. `ScopeMode`/`ScopePaths` are
policy-lockable (see above) so a user can't widen their own scope past
what an admin intends.

Implemented as `TRUSTGATE_SCOPE_MODE`/`TRUSTGATE_SCOPE_PATHS` (two env
vars) rather than a single packed `TRUSTGATE_SCOPE` value, matching how
`TRUSTGATE_MODE` and `TRUSTGATE_POLICY_ALLOWLIST` are already separate.

## 11. On-disk protection of local state

The API key file is restricted to the running user on every platform:
mode `0600` on macOS and Linux, and an explicit current-user-only ACL on
Windows (`icacls /inheritance:r /grant:r <user>:F`), applied by
`trustgate setup`, which refuses to store the key if the ACL cannot be set.

The cache (`lookups.db`), decision log (`decisions.log`), and audit
database (`audit.db`) are created `0600` inside a `0700` directory on macOS
and Linux. On Windows those mode bits have no effect — access is governed
by the ACL inherited from the user profile, which by default excludes other
non-administrator users but is not tightened by TrustGate itself.

None of this defends against the account's own processes. A verdict in the
cache can be rewritten by anything running as that user, and root or an
administrator can read or modify all of it. Treat the local stores as
private to the account, not as tamper-proof evidence; if you need an
authoritative record, forward decisions to a collector you control with
`TRUSTGATE_AUDIT_SINK_URL` (§4).

## Env var reference (admin operability)

| Env var | Default | Purpose |
| --- | --- | --- |
| `TRUSTGATE_MODE` | `warn` | `enforce` \| `report-only` \| `off` \| `warn` (default) \| `ask` — warn/report-only fail OPEN on provider errors; enforce/ask fail closed; `ask` (Cursor 3.11.25+) emits the native approve/reject dialog, degrading to a hard deny below the floor |
| `TRUSTGATE_ASK_MIN_CURSOR_VERSION` | `3.11.25` | `ask` mode only — minimum Cursor version that honors `permission:"ask"`; below it `ask` degrades to a hard deny (never fails open) |
| `TRUSTGATE_POLICY_ALLOWLIST` | _(empty)_ | CSV of always-allowed exact indicator values |
| `TRUSTGATE_ALLOW_USER_OVERRIDE` | `false` | Admin opt-in for `trustgate override` to have any effect |
| `TRUSTGATE_HELP_MESSAGE` | _(empty)_ | Appended to deny messages alongside the decision_id |
| `TRUSTGATE_AUDIT_SINK_URL` | _(empty)_ | HTTPS collector endpoint; unset disables the sink entirely |
| `TRUSTGATE_AUDIT_SINK_VERBOSITY` | `denies` | `denies` \| `all` \| `off` |
| `TRUSTGATE_AUDIT_SINK_HOST_ALLOWLIST` | _(empty)_ | Required (non-empty) once `TRUSTGATE_AUDIT_SINK_URL` is set |
| `TRUSTGATE_TOOLUSE_STRICT` | `false` | Deny unrecognized `preToolUse` tool names instead of allowing them |
| `TRUSTGATE_TOOLUSE_ALLOWLIST` | _(empty)_ | CSV of extra tool names strict mode should treat as safe |
| `TRUSTGATE_READFILE_STRICT_WORKSPACE_ROOTS` | `false` | Treat empty `workspace_roots` as "outside workspace" instead of "unconstrained" |
| `TRUSTGATE_REQUIRE_CONFIGURED` | `false` | Fail closed (instead of inert-allow) when unconfigured — set `true` for managed/fleet installs |
| `TRUSTGATE_SCOPE_MODE` | `all` | `all` \| `allowlist` \| `denylist` — workspace/project scoping |
| `TRUSTGATE_SCOPE_PATHS` | _(empty)_ | CSV of path globs evaluated against the hook payload's `workspace_roots` |
| `TRUSTGATE_OVERRIDE_SCOPE` | `domain` | `domain` \| `time` — per-host grant vs. blanket window (used by both the CLI break-glass and `warn` mode) |
| `TRUSTGATE_OVERRIDE_WINDOW_MIN` | `15` | Minutes a host stays granted once promoted (`warn` mode's retry, or the CLI `--minutes` default) |
| `TRUSTGATE_WARN_ACK_MIN_SECONDS` | `4` | `warn` mode only — minimum seconds between a first-touch warn and the retry that acknowledges it; a faster retry (e.g. an agent auto-retry) re-warns instead of promoting. `0` disables the gate |
| `TRUSTGATE_LOCKED_KEYS` | _(empty)_ | **`/etc/trustgate/env` only** — CSV of keys the system file locks against user override |
