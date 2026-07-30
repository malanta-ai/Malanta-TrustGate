package extract

import "testing"

func TestIsRecognizedTool_InspectedTools(t *testing.T) {
	for _, tool := range []string{"WebFetch", "WebSearch"} {
		if !IsRecognizedTool(tool, nil) {
			t.Errorf("expected %q to be recognized (actively inspected)", tool)
		}
	}
}

func TestIsRecognizedTool_DedicatedHookTools(t *testing.T) {
	for _, tool := range []string{"Shell", "Read", "TabRead", "MCP:some-server-tool"} {
		if !IsRecognizedTool(tool, nil) {
			t.Errorf("expected %q to be recognized (covered by a dedicated hook)", tool)
		}
	}
}

func TestIsRecognizedTool_KnownSafeTools(t *testing.T) {
	for _, tool := range []string{"Write", "Delete", "Grep", "Glob", "TodoWrite"} {
		if !IsRecognizedTool(tool, nil) {
			t.Errorf("expected %q to be recognized (hand-maintained safe list)", tool)
		}
	}
}

func TestIsRecognizedTool_UnknownToolIsNotRecognizedByDefault(t *testing.T) {
	if IsRecognizedTool("SomeBrandNewTool", nil) {
		t.Error("expected an unrecognized tool to NOT be recognized without an explicit allowlist entry")
	}
}

func TestIsRecognizedTool_OperatorAllowlistExtendsCoverage(t *testing.T) {
	if !IsRecognizedTool("MyCustomTool", []string{"OtherTool", "MyCustomTool"}) {
		t.Error("expected the operator allowlist to recognize MyCustomTool")
	}
	if !IsRecognizedTool("mycustomtool", []string{"MyCustomTool"}) {
		t.Error("expected the operator allowlist match to be case-insensitive")
	}
}
