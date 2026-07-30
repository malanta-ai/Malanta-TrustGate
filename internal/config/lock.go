package config

import (
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// systemEnvPath is the MDM-managed, fleet-wide env file — the same path
// EnvFiles() lists first (lowest normal precedence). It is the ONLY
// source EnforceLockedEnv trusts to declare a lock: a user-owned layer
// (~/.config/trustgate/env, .env, or ambient process env) can never grant
// itself the ability to lock a key, because TRUSTGATE_LOCKED_KEYS is only
// ever read from this one file.
//
// A package-level var (not a const) purely so tests in this package can
// point it at a temp file instead of the real /etc/trustgate/env, which
// a test process can't write to without root.
var systemEnvPath = "/etc/trustgate/env"

// lockableKeys is the fixed set of security-relevant env vars
// TRUSTGATE_LOCKED_KEYS is allowed to name. Restricting to an explicit
// allowlist (rather than "lock anything you name") means a typo or an
// overly broad value in the system file can't accidentally lock an
// unrelated var — matches the project plan's own enumeration (mode,
// fail_closed, require_configured, provider, allowlist, audit sink,
// ATR-disable, scope) plus the other security-relevant toggles added
// since.
var lockableKeys = map[string]bool{
	"TRUSTGATE_MODE":                            true,
	"TRUSTGATE_FAIL_CLOSED":                     true,
	"TRUSTGATE_REQUIRE_CONFIGURED":              true,
	"TRUSTGATE_PROVIDER":                        true,
	"TRUSTGATE_POLICY_ALLOWLIST":                true,
	"TRUSTGATE_ALLOW_USER_OVERRIDE":             true,
	"TRUSTGATE_AUDIT_SINK_URL":                  true,
	"TRUSTGATE_AUDIT_SINK_VERBOSITY":            true,
	"TRUSTGATE_AUDIT_SINK_HOST_ALLOWLIST":       true,
	"TRUSTGATE_ATR_DISABLE":                     true,
	"TRUSTGATE_SCOPE_MODE":                      true,
	"TRUSTGATE_SCOPE_PATHS":                     true,
	"TRUSTGATE_TOOLUSE_STRICT":                  true,
	"TRUSTGATE_READFILE_STRICT_WORKSPACE_ROOTS": true,
	"TRUSTGATE_OVERRIDE_SCOPE":                  true,
	"TRUSTGATE_OVERRIDE_WINDOW_MIN":             true,
	"TRUSTGATE_WARN_ACK_MIN_SECONDS":            true,
	"TRUSTGATE_MIN_MALICIOUS_SCORE":             true,
	"TRUSTGATE_MIN_PROBABILITY":                 true,
	"TRUSTGATE_PROVIDER_MAX_CONCURRENCY":        true,
	// Destination / policy surfaces: an MDM fleet must be
	// able to pin where lookups + the credential go (API base URL, host
	// allowlist), the block/allow cascade, the block threshold's own
	// override name, where audit + decision data is written (cache/log),
	// the behavioral ruleset source, and the network-tool allowlist —
	// otherwise a user-owned env layer could weaken any of these even
	// though the workspace .env is already off by default.
	"MALANTA_API_BASE_URL":             true,
	"MALANTA_API_HOST_ALLOWLIST":       true,
	"TRUSTGATE_BLOCK_LABELS":           true,
	"TRUSTGATE_ALLOW_LABELS":           true,
	"TRUSTGATE_CACHE_DIR":              true,
	"TRUSTGATE_LOG_PATH":               true,
	"TRUSTGATE_ATR_RULES_DIR":          true,
	"TRUSTGATE_TOOLUSE_ALLOWLIST":      true,
	"TRUSTGATE_RETENTION_DAYS":         true,
	"TRUSTGATE_ASK_MIN_CURSOR_VERSION": true,
}

// EnforceLockedEnv re-applies any env vars /etc/trustgate/env has
// declared LOCKED via its own TRUSTGATE_LOCKED_KEYS entry, overwriting
// whatever a user-owned layer (~/.config/trustgate/env, .env, or ambient
// process env) set for those specific keys. MUST be called after
// godotenv.Overload(EnvFiles()...) has already merged all three env
// files into the process environment, and before config.Load (or any
// other os.Getenv-based reader — e.g. the ATR kill switch or the
// read-file strict-workspace-roots flag) consults it, so the system
// file's value always wins for a locked key.
//
// No-op if /etc/trustgate/env doesn't exist, can't be parsed, or doesn't
// declare TRUSTGATE_LOCKED_KEYS — an individual/unmanaged install is
// never restricted by this mechanism. A key named in TRUSTGATE_LOCKED_KEYS
// but without its own value in the SAME file is skipped (there's nothing
// to lock it TO) rather than being unset — a lock declaration without an
// accompanying value is treated as an incomplete/no-op declaration, never
// as "erase whatever the user configured."
func EnforceLockedEnv() {
	sysVals, err := godotenv.Read(systemEnvPath)
	if err != nil {
		return
	}
	lockedCSV := strings.TrimSpace(sysVals["TRUSTGATE_LOCKED_KEYS"])
	if lockedCSV == "" {
		return
	}
	for _, key := range splitCSV(lockedCSV) {
		if !lockableKeys[key] {
			continue
		}
		if v, present := sysVals[key]; present {
			_ = os.Setenv(key, v)
		}
	}
}

// LockedKeys returns the set of keys /etc/trustgate/env currently locks
// (empty if unmanaged or no lock is declared) — exposed for `trustgate
// doctor` so an admin/user can see what's locked without reading the
// system file's raw contents by hand.
func LockedKeys() []string {
	sysVals, err := godotenv.Read(systemEnvPath)
	if err != nil {
		return nil
	}
	lockedCSV := strings.TrimSpace(sysVals["TRUSTGATE_LOCKED_KEYS"])
	if lockedCSV == "" {
		return nil
	}
	var out []string
	for _, key := range splitCSV(lockedCSV) {
		if lockableKeys[key] {
			if _, present := sysVals[key]; present {
				out = append(out, key)
			}
		}
	}
	return out
}
