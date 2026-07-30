# Contributing to Malanta TrustGate

Thanks for considering a contribution. This project is a set of Cursor
enterprise hooks (Go binaries) that check domains/IPs an agent is about to
contact against a reputation provider before allowing the action. It runs on
a security-sensitive hot path — please read [AGENTS.md](AGENTS.md) before
making non-trivial changes; it documents the hard rules (fail-closed
defaults, single normalization site, no CGO, secret handling) that keep this
tool trustworthy.

## Getting set up

```bash
go version   # need 1.24+ (1.26+ recommended on macOS 26/"Tahoe")
make tidy    # resolve module dependencies
make test    # unit tests, hermetic, no network, no API key required
make build   # build all hook binaries into dist/
```

`make test` must pass on a clean checkout with no network and no API key. If
it doesn't, that's a bug — please open an issue before building on top of a
red tree.

Live-API tests are gated behind the `e2e` build tag and are **not** part of
`make test`:

```bash
MALANTA_API_KEY=... make e2e     # hits the real Malanta reputation API
MALANTA_API_KEY=... make smoke   # exercises the built binaries end to end
```

## Before you open a PR

1. **Add tests.** Every new feature, extractor rule, or bug fix needs a
   corresponding test. Look at the existing table-driven tests in
   `internal/extract`, `internal/reputation`, and `internal/verdict` for the
   house style.
2. **Run the full suite, including race detection:**
   ```bash
   go test -race ./...
   go vet ./...
   gofmt -l .   # should print nothing for files you touched
   ```
3. **Don't touch the four areas below without discussion first** (open an
   issue or draft PR to talk it through): the verdict cascade in
   `internal/verdict`, the provider contract in `internal/reputation`, the
   domain/IP normalization rules in `internal/extract`, and the env-file
   precedence in `internal/config.EnvFiles`. These four are the parts most
   likely to break verdicts silently, and changes here get extra scrutiny.
4. **Never commit secrets.** No API keys, tokens, or credentials in code,
   tests, fixtures, or commit messages — see [SECURITY.md](SECURITY.md) if
   you think one has leaked.

## Adding a reputation provider config

You don't need to write Go code to point TrustGate at a new reputation
vendor — the generic config-driven adapter (`internal/reputation` generic
provider) can usually express a REST API via config alone. See
[`docs/providers.md`](docs/providers.md) for the schema and a worked
example.

Vendor configs are **community/best-effort** by default (see
[SUPPORT.md](SUPPORT.md)) — we welcome PRs adding example configs to
`docs/providers.md`, but promoting one to a compiled, officially-supported
provider is a separate, higher bar: it needs tests against a realistic
fixture of the vendor's response shape and a maintainer willing to own it
long-term.

## Adding an ATR detection rule

Same story for behavioral detection rules (the ATR pass that runs alongside
the reputation cascade). You don't need to fork this repo to add or
override a rule — point `TRUSTGATE_ATR_RULES_DIR` at your own directory of
plain YAML rule files; see
[`docs/examples/atr-custom-rules/README.md`](docs/examples/atr-custom-rules/README.md).
The embedded/vendored rule snapshot (`internal/atr/rules/`,
`scripts/sync-atr-rules.py`) is a maintainer-only tool for refreshing that
snapshot from upstream — most contributions to detection coverage should go
through the bring-your-own-rules mechanism instead.

## Commit and PR style

- Keep commits scoped to one logical change; write commit messages that
  explain *why*, not just *what*.
- PR descriptions should say what you tested and how (unit tests, `make
  e2e`, manual smoke test against a live provider, etc.).
- Small, focused PRs get reviewed faster than large ones. If your change
  naturally splits into "refactor" + "new feature," consider two PRs.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you're expected to uphold it.

## Questions

Open a GitHub issue, or see [SUPPORT.md](SUPPORT.md) for how support tiers
work across core vs. community-contributed vendor configs.
