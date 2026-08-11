package hook

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadInputParsesBashCommand(t *testing.T) {
	raw := `{
		"tool_name": "Bash",
		"tool_input": {"command": "git status"},
		"cwd": "/tmp",
		"hook_event_name": "PreToolUse"
	}`
	in, err := ReadInput(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadInput error: %v", err)
	}
	if in.ToolName != "Bash" {
		t.Errorf("ToolName = %q, want Bash", in.ToolName)
	}
	if in.ToolInput.Command != "git status" {
		t.Errorf("Command = %q, want %q", in.ToolInput.Command, "git status")
	}
}

func TestWriteDecisionEmptyIsSilent(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteDecision(&buf, "", "irrelevant"); err != nil {
		t.Fatalf("WriteDecision error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output for empty decision, got %q", buf.String())
	}
}

func TestWriteDecisionDeny(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteDecision(&buf, DecisionDeny, "too dangerous"); err != nil {
		t.Fatalf("WriteDecision error: %v", err)
	}
	got := buf.String()
	for _, want := range []string{`"permissionDecision":"deny"`, `"permissionDecisionReason":"too dangerous"`, `"hookEventName":"PreToolUse"`} {
		if !strings.Contains(got, want) {
			t.Errorf("output %q missing %q", got, want)
		}
	}
}
