package configs

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestClaudeExampleIsValidJSONAndSelectsSupportedTools(t *testing.T) {
	data, err := os.ReadFile("claude-code.settings.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("invalid Claude settings JSON: %v", err)
	}
	text := string(data)
	for _, required := range []string{`"PreToolUse"`, `"matcher": "Bash"`, `"matcher": "PowerShell"`, `"matcher": "Read"`, `"matcher": "Write"`, `"matcher": "Edit"`, `"type": "command"`, `--host claude`} {
		if !strings.Contains(text, required) {
			t.Errorf("Claude example is missing %q", required)
		}
	}
}

func TestCodexExampleContainsCanonicalHookShape(t *testing.T) {
	data, err := os.ReadFile("codex-config.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{"[[hooks.PreToolUse]]", `matcher = "^Bash$"`, "[[hooks.PreToolUse.hooks]]", `type = "command"`, `--host codex`} {
		if !strings.Contains(text, required) {
			t.Errorf("Codex example is missing %q", required)
		}
	}
	if strings.Contains(text, "codex_hooks.PreToolUse") {
		t.Fatal("Codex example uses the deprecated codex_hooks key")
	}
}
