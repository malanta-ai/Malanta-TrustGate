package hookrunner

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// TestStripUTF8BOM covers the Windows-installer BOM class: a UTF-8 BOM
// (EF BB BF) prepended to the hook payload made Go's encoding/json fail with
// "invalid character 'ï'". stripUTF8BOM must remove exactly one leading BOM
// and leave everything else — including a valid JSON body — intact.
func TestStripUTF8BOM(t *testing.T) {
	const payload = `{"command":"echo hi"}`

	t.Run("leading BOM is stripped and JSON decodes", func(t *testing.T) {
		withBOM := "\xEF\xBB\xBF" + payload
		got, err := io.ReadAll(stripUTF8BOM(strings.NewReader(withBOM)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got) != payload {
			t.Errorf("expected BOM stripped, got %q", got)
		}
		var out map[string]any
		if err := json.Unmarshal(got, &out); err != nil {
			t.Errorf("stripped payload should be valid JSON, got: %v", err)
		}
	})

	t.Run("no BOM is unchanged", func(t *testing.T) {
		got, err := io.ReadAll(stripUTF8BOM(strings.NewReader(payload)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got) != payload {
			t.Errorf("expected unchanged payload, got %q", got)
		}
	})

	t.Run("only the leading BOM is removed", func(t *testing.T) {
		// A BOM-looking sequence later in the body must survive.
		body := payload + "\xEF\xBB\xBF"
		got, err := io.ReadAll(stripUTF8BOM(strings.NewReader(body)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got) != body {
			t.Errorf("expected only a leading BOM to be stripped, got %q", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		got, err := io.ReadAll(stripUTF8BOM(strings.NewReader("")))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

// TestStdinCap_PreventsUnboundedReads guards the stdin input-size bound.
// Cursor's documented hook payloads are at most a few KiB; this test
// asserts that the LimitReader cap actually fires by reading from a
// reader that would otherwise return many megabytes.
//
// The runner itself is hard to test in-process because it consults
// os.Stdin and the live config. We exercise the LimitReader behavior
// directly to confirm the cap value is correct and the wrapper truncates.
func TestStdinCap_LimitsReadBytes(t *testing.T) {
	// 10 MiB of zero bytes — a hostile MCP server could realistically
	// stuff this into a tool-input string.
	const totalBytes = 10 << 20
	r := io.LimitReader(strings.NewReader(strings.Repeat("a", totalBytes)), maxStdinBytes)

	buf, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(buf) != maxStdinBytes {
		t.Errorf("ReadAll returned %d bytes, want %d (the cap)", len(buf), maxStdinBytes)
	}
}

// TestStdinCap_ConstantIsReasonable is a documentation guard. If
// somebody flips this constant to 1 MiB or 1 KiB by accident the
// other tests would still pass — none of them depends on the exact
// value. Pin it here so the choice is reviewed deliberately.
func TestStdinCap_ConstantIsReasonable(t *testing.T) {
	if maxStdinBytes < 16<<10 {
		t.Errorf("maxStdinBytes=%d is too small; would reject realistic Cursor payloads", maxStdinBytes)
	}
	if maxStdinBytes > 4<<20 {
		t.Errorf("maxStdinBytes=%d is too large; defeats the DoS bound", maxStdinBytes)
	}
}
