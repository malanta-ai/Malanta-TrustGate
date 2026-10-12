package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// lockfileOfSize builds lockfile-shaped JSON text of roughly n bytes. The
// shape matters: the read-file extractor only scans allowlisted paths, and
// a lockfile is both the realistic large input and the one this hook most
// wants to inspect.
func lockfileOfSize(n int) string {
	var b strings.Builder
	b.WriteString("{\n  \"name\": \"app\",\n  \"lockfileVersion\": 3,\n  \"packages\": {\n")
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, `    "node_modules/pkg-%d": {"version": "1.2.3", "resolved": "https://registry.npmjs.org/pkg-%d/-/pkg-%d-1.2.3.tgz"},`+"\n", i, i, i)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func readFilePayload(t *testing.T, path, content string, roots []string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"file_path":       path,
		"content":         content,
		"workspace_roots": roots,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return string(body)
}

// TestReadFile_LargeFileIsNotADecodeError is the regression guard for a
// live customer report: reading a JSON file over the runner's old 256 KiB
// stdin bound truncated the payload mid-structure, surfaced as
// "payload: unexpected EOF", and blocked the read. Large lockfiles are
// routine, and they are exactly what this hook exists to scan, so this
// must behave like any other clean read.
//
// Enforce mode is deliberate: it is the strictest posture, so an allow
// here proves the payload genuinely decoded rather than being softened by
// a lenient mode.
func TestReadFile_LargeFileIsNotADecodeError(t *testing.T) {
	cacheDir, logPath, env := hookEnv(t) // enforce
	// The lockfile's only host must resolve from cache, or this asserts
	// network reachability instead of payload handling.
	seedCache(t, cacheDir, "registry.npmjs.org", "CLEAN", 0.0)

	// Comfortably past the old 256 KiB bound and under the extractor's
	// 1 MiB content cap, i.e. the range that must actually be scanned.
	content := lockfileOfSize(400 << 10)
	payload := readFilePayload(t, "/tmp/package-lock.json", content, []string{"/tmp"})

	out, stderr := runHook(t, env, "trustgate-before-read-file", payload)
	if got := out["permission"]; got != "allow" {
		t.Errorf("large clean lockfile: permission = %v, want allow; stderr: %s; full: %v", got, stderr, out)
	}
	if msg, _ := out["user_message"].(string); strings.Contains(msg, "unexpected EOF") {
		t.Errorf("large lockfile still reported as a decode error: %q", msg)
	}
	// Decoding is necessary but not sufficient: the file must actually
	// have been scanned, which the extracted host proves.
	if rec := lastDecision(t, logPath); !containsValue(rec.Hosts, "registry.npmjs.org") {
		t.Errorf("large lockfile decoded but was not scanned; hosts = %v", rec.Hosts)
	}
}

// TestReadFile_OverCapFailsOpenInWarn pins the other half of the fix. A
// payload beyond even the raised bound still truncates — that bound is a
// real defense and is meant to be hit by pathological input — but the
// resulting hook error must respect the mode. It previously denied in
// every mode while the log claimed "warn", and since no pending marker
// was written there was nothing for a retry to promote, leaving the user
// in a loop they could not clear.
func TestReadFile_OverCapFailsOpenInWarn(t *testing.T) {
	_, _, env := hookEnv(t)
	env = setEnv(env, "TRUSTGATE_MODE", "warn")

	// Past the read-file hook's 2 MiB bound, so the payload truncates.
	content := lockfileOfSize(3 << 20)
	payload := readFilePayload(t, "/tmp/package-lock.json", content, []string{"/tmp"})

	out, stderr := runHook(t, env, "trustgate-before-read-file", payload)
	if got := out["permission"]; got != "allow" {
		t.Errorf("over-cap payload in warn: permission = %v, want allow (warn must not hard-block on a hook error); stderr: %s; full: %v", got, stderr, out)
	}
}

// TestReadFile_OverCapDeniesInEnforce is the counterweight: failing open
// in warn must not quietly become failing open everywhere. An oversized
// payload is still a hostile-input signal, and enforce keeps denying it.
func TestReadFile_OverCapDeniesInEnforce(t *testing.T) {
	_, logPath, env := hookEnv(t) // enforce

	content := lockfileOfSize(3 << 20)
	payload := readFilePayload(t, "/tmp/package-lock.json", content, []string{"/tmp"})

	out, stderr := runHook(t, env, "trustgate-before-read-file", payload)
	if got := out["permission"]; got != "deny" {
		t.Errorf("over-cap payload in enforce: permission = %v, want deny; stderr: %s; full: %v", got, stderr, out)
	}
	// The logged reason must name the size. Bare "unexpected EOF" is what
	// sent the original report chasing a broken client instead of a large
	// file. It stays out of the user-facing message for the same reason a
	// provider error's detail does — the message carries the decision_id,
	// and `trustgate explain` resolves the rest.
	rec := lastDecision(t, logPath)
	if !strings.Contains(rec.Decision.Reason, "stdin bound") {
		t.Errorf("over-cap deny does not explain the size in the log; reason = %q; stderr: %s", rec.Decision.Reason, stderr)
	}
}
