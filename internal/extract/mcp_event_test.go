package extract

import (
	"reflect"
	"testing"
)

// These tests guard the MCP-server-URL fix: the MCP server
// registration URL itself must be in the verdict cascade, not just the
// tool arguments. Before the fix, a malicious MCP server could register
// at https://<malicious>/ and host tools whose arguments looked
// completely benign; the hook would inspect only the arguments and pass
// the registration host through unweighted. FromMCPEvent now feeds the
// server URL through the same regex+Normalize pipeline as the args.

func TestFromMCPCall_DestinationSurfaces(t *testing.T) {
	// url (remote), command (stdio), and legacy server are all destination
	// surfaces; any non-empty one must be extracted. Empty strings are
	// ignored. Covers the current-payload shape.
	got := FromMCPCall(
		[]string{"https://remote.example/mcp", "", "https://legacy.example/"},
		map[string]any{"endpoint": "https://arg.example/x"})
	want := []string{"remote.example", "legacy.example", "arg.example"}
	if !reflect.DeepEqual(sorted(got), sorted(want)) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromMCPCall_EmptyDestinations(t *testing.T) {
	if got := FromMCPCall([]string{"", "", ""}, nil); len(got) != 0 {
		t.Errorf("expected no hosts for all-empty input, got %v", got)
	}
}

func TestFromMCPEvent_ServerOnly(t *testing.T) {
	got := FromMCPEvent("https://malicious.example/mcp", nil)
	want := []string{"malicious.example"}
	if !reflect.DeepEqual(sorted(got), sorted(want)) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromMCPEvent_ServerAndArgs(t *testing.T) {
	args := map[string]any{
		"target": "https://target.example/api",
	}
	got := FromMCPEvent("https://server.example/", args)
	want := []string{"server.example", "target.example"}
	if !reflect.DeepEqual(sorted(got), sorted(want)) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromMCPEvent_DedupAcrossSurfaces(t *testing.T) {
	// Same host on both surfaces should appear once.
	got := FromMCPEvent("https://shared.example/", map[string]any{"echo": "https://shared.example/x"})
	want := []string{"shared.example"}
	if !reflect.DeepEqual(sorted(got), sorted(want)) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromMCPEvent_EmptyServer(t *testing.T) {
	// MCP events for in-process / stdio MCP servers carry an empty `server`
	// string. The extractor must not panic and must still scan the args.
	args := map[string]any{"url": "https://only-in-args.example"}
	got := FromMCPEvent("", args)
	want := []string{"only-in-args.example"}
	if !reflect.DeepEqual(sorted(got), sorted(want)) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromMCPEvent_EmptyArgs(t *testing.T) {
	if got := FromMCPEvent("", nil); len(got) != 0 {
		t.Errorf("got %v want no hosts", got)
	}
}

// TestFromMCP_BackwardCompatibility makes sure the original FromMCP entry
// point still works for callers that genuinely only have the arguments
// object — primarily the existing test fixtures and any out-of-tree code
// pinned to the older signature.
func TestFromMCP_BackwardCompatibility(t *testing.T) {
	args := map[string]any{"endpoint": "https://compat.example/v1"}
	got := FromMCP(args)
	want := []string{"compat.example"}
	if !reflect.DeepEqual(sorted(got), sorted(want)) {
		t.Errorf("got %v want %v", got, want)
	}
}
