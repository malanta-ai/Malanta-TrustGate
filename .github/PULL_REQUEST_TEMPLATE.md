## What does this PR do?

<!-- One or two sentences. -->

## Why?

<!-- What bug/gap does this close? Link an issue if there is one. -->

## Testing

- [ ] `go test -race ./...` passes
- [ ] `go vet ./...` and `gofmt -l .` are clean for changed files
- [ ] Added/updated tests covering the change
- [ ] If this touches `internal/verdict`, `internal/reputation`, `internal/extract`, or `internal/config.EnvFiles`: explain the reasoning below (see CONTRIBUTING.md — these get extra scrutiny)

<!-- Manual testing (make e2e / make smoke / live provider), if applicable -->

## Checklist

- [ ] No secrets (API keys, tokens) in code, tests, fixtures, or commit messages
- [ ] If this adds/changes a third-party provider config example, it's documented in `docs/providers.md` and labeled as community/best-effort per SUPPORT.md
