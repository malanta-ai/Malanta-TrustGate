.PHONY: build test e2e smoke install clean tidy atr-sync atr-bench check-secrets test-plugin-wrapper

# Build all hook binaries + the trustgate admin CLI into dist/
build:
	go build -o dist/ ./cmd/...

# Unit tests only (hermetic)
test:
	go test ./...

# Guard against a committed API key value (see AGENTS.md's history for why
# this exists). Safe to run before any commit that touches config/docs.
check-secrets:
	./scripts/check-no-secrets.sh

# Exercise the Cursor Marketplace plugin's binary-resolution wrapper
# (hooks/scripts/lib/ensure-binary.sh) against a local fake release
# server, since no real GitHub release exists to test the download path
# against otherwise. See docs/plugin.md's Supply Chain section.
test-plugin-wrapper:
	./scripts/test-ensure-binary.sh

# Live API tests; requires MALANTA_API_KEY in environment
e2e:
	go test -tags=e2e -count=1 ./internal/reputation/...

# Build then exercise binaries with synthetic payloads
smoke: build
	./scripts/smoke-test.sh

# Build, install binaries to ~/.local/bin, wire up hooks.json
install:
	./scripts/install-hooks.sh

# Resolve and download module dependencies
tidy:
	go mod tidy

clean:
	rm -rf dist/

# Re-vendor the ATR (Agent Threat Rules) snapshot from the upstream
# npm package. Safe to run repeatedly; preserves internal/atr/rules/
# shell/, which holds our hand-curated shell subset. Bump
# ATR_VERSION (env var) before invoking when upstream publishes a
# new rev. Writes obfuscated (atr-b64:) YAML directly — see
# scripts/sync-atr-rules.py's module docstring for why.
atr-sync:
	python3 ./scripts/sync-atr-rules.py

# Benchmark the ATR evaluator. Use to confirm that any rule subset
# change keeps the read-file/MCP pool under the 60ms evalDeadline
# and the shell subset under 1ms. Output reads in `ns/op`; the
# hot-path budget is 250ms total per hook so ATR should comfortably
# stay one order of magnitude under that.
atr-bench:
	go test -bench=. -benchmem -run=^$$ ./internal/atr/...
