package main

import (
	"encoding/json"
	"strings"
	"testing"
)

var testProgramNames = []string{"policygate", "policygate.exe"}

func TestNamesPolicygateRecognizesRegistrations(t *testing.T) {
	matching := []string{
		"/usr/local/bin/policygate --host claude",
		"/opt/homebrew/bin/policygate --host codex",
		`C:\Users\x\.policygate\bin\policygate.exe --host claude`,
		// The documented way to give each host its own policy hides the binary
		// behind env, so the first token is not the program.
		"/usr/bin/env POLICYGATE_CONFIG=/home/x/.policygate/claude.yaml /usr/local/bin/policygate --host claude",
		// quoteHookPath quotes a path containing spaces.
		"'/Users/a b/.policygate/bin/policygate' --host claude",
		`"C:\Program Files\policygate.exe" --host claude`,
		// A case-insensitive filesystem runs the same binary either way.
		"/usr/local/bin/POLICYGATE --host claude",
	}
	for _, cmd := range matching {
		if !namesPolicygate(cmd, testProgramNames) {
			t.Errorf("namesPolicygate(%q) = false, want true", cmd)
		}
	}

	other := []string{
		"/usr/local/bin/other-tool",
		"/usr/local/bin/policygate-wrapper --host claude",
		"",
		// A flag or an assignment that merely mentions the name is not the
		// program being run.
		"/usr/local/bin/audit --tool=policygate",
		"/usr/local/bin/audit --exclude policygate-old",
	}
	for _, cmd := range other {
		if namesPolicygate(cmd, testProgramNames) {
			t.Errorf("namesPolicygate(%q) = true, want false", cmd)
		}
	}
}

// A renamed binary must still recognize what it wrote, or a second install
// appends a duplicate registration instead of replacing the first.
func TestHookProgramNamesIncludesARenamedBinary(t *testing.T) {
	names := hookProgramNames("/tmp/pg-check")
	if !namesPolicygate("/tmp/pg-check --host claude", names) {
		t.Error("a renamed binary did not recognize its own registration")
	}
	if !namesPolicygate("/usr/local/bin/policygate --host claude", names) {
		t.Error("a renamed binary stopped recognizing the canonical name")
	}

	canonical := hookProgramNames("/usr/local/bin/policygate")
	if len(canonical) != 2 {
		t.Errorf("hookProgramNames() = %v, want no duplicate of the canonical name", canonical)
	}
}

func TestQuoteHookPathOnlyQuotesWhenNeeded(t *testing.T) {
	if got := quoteHookPath("/usr/local/bin/policygate"); got != "/usr/local/bin/policygate" {
		t.Errorf("quoteHookPath() = %q, want the path unquoted", got)
	}
	if got := quoteHookPath("/Users/a b/policygate"); !strings.Contains(got, "a b") || got[0] == '/' {
		t.Errorf("quoteHookPath() = %q, want a quoted path", got)
	}
}

func TestRewriteClaudeSettingsCreatesRegistration(t *testing.T) {
	out, err := rewriteClaudeSettings(nil, "/bin/policygate --host claude", testProgramNames, true)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Hooks struct {
			PreToolUse []claudeMatcherGroup `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	groups := parsed.Hooks.PreToolUse
	if len(groups) != 1 || groups[0].Matcher != "Bash" || len(groups[0].Hooks) != 1 {
		t.Fatalf("unexpected registration: %s", out)
	}
	if groups[0].Hooks[0].Command != "/bin/policygate --host claude" {
		t.Errorf("command = %q", groups[0].Hooks[0].Command)
	}
}

// Rewriting one key must not reorder or drop the rest of a file the user
// maintains by hand.
func TestRewriteClaudeSettingsPreservesUnrelatedKeysAndOrder(t *testing.T) {
	original := []byte(`{"model":"opus","hooks":{"PostToolUse":[]},"permissions":{"allow":["Read"]}}`)

	out, err := rewriteClaudeSettings(original, "/bin/policygate --host claude", testProgramNames, true)
	if err != nil {
		t.Fatal(err)
	}
	modelAt := strings.Index(string(out), `"model"`)
	hooksAt := strings.Index(string(out), `"hooks"`)
	permsAt := strings.Index(string(out), `"permissions"`)
	if modelAt < 0 || hooksAt < 0 || permsAt < 0 {
		t.Fatalf("a key was dropped: %s", out)
	}
	if modelAt > hooksAt || hooksAt > permsAt {
		t.Errorf("keys were reordered: %s", out)
	}
	if !strings.Contains(string(out), "PostToolUse") {
		t.Errorf("an unrelated hook event was dropped: %s", out)
	}
}

func TestRewriteClaudeSettingsIsIdempotent(t *testing.T) {
	const command = "/bin/policygate --host claude"
	once, err := rewriteClaudeSettings(nil, command, testProgramNames, true)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := rewriteClaudeSettings(once, command, testProgramNames, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Errorf("a second install changed the file:\n%s\n---\n%s", once, twice)
	}
}

// An upgrade that moves the binary must replace the old registration rather
// than leave two gates registered.
func TestRewriteClaudeSettingsReplacesAMovedBinary(t *testing.T) {
	original := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/policygate --host claude"}]}]}}`)

	out, err := rewriteClaudeSettings(original, "/opt/homebrew/bin/policygate --host claude", testProgramNames, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "/usr/local/bin/policygate") {
		t.Errorf("the old registration survived: %s", out)
	}
	if strings.Count(string(out), "--host claude") != 1 {
		t.Errorf("expected exactly one registration: %s", out)
	}
}

func TestRewriteClaudeSettingsKeepsOtherHooksOnUninstall(t *testing.T) {
	original := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/other-tool"},{"type":"command","command":"/bin/policygate --host claude"}]}]}}`)

	out, err := rewriteClaudeSettings(original, "/bin/policygate --host claude", testProgramNames, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "policygate") {
		t.Errorf("the registration survived uninstall: %s", out)
	}
	if !strings.Contains(string(out), "other-tool") {
		t.Errorf("an unrelated hook was removed: %s", out)
	}
}

// Removing the last hook should leave no empty scaffolding behind.
func TestRewriteClaudeSettingsDropsEmptyScaffolding(t *testing.T) {
	original := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/bin/policygate --host claude"}]}]}}`)

	out, err := rewriteClaudeSettings(original, "/bin/policygate --host claude", testProgramNames, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hooks") {
		t.Errorf("an empty hooks object was left behind: %s", out)
	}
}

func TestRewriteClaudeSettingsRejectsMalformedJSON(t *testing.T) {
	if _, err := rewriteClaudeSettings([]byte("{not json"), "/bin/policygate --host claude", testProgramNames, true); err == nil {
		t.Error("expected an error rather than a silently rewritten file")
	}
}

func TestRewriteCodexConfigAppendsAndReplaces(t *testing.T) {
	original := []byte("model = \"gpt-5\"\n")

	out, err := rewriteCodexConfig(original, "/bin/policygate --host codex", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `model = "gpt-5"`) {
		t.Errorf("existing configuration was lost: %s", out)
	}
	if !strings.Contains(string(out), codexBlockStart) || !strings.Contains(string(out), codexBlockEnd) {
		t.Errorf("the managed block is not delimited: %s", out)
	}

	again, err := rewriteCodexConfig(out, "/bin/policygate --host codex", true)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(out) {
		t.Errorf("a second install changed the file:\n%s\n---\n%s", out, again)
	}

	// A moved binary replaces the block rather than appending another.
	moved, err := rewriteCodexConfig(out, "/opt/pg/policygate --host codex", true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(moved), codexBlockStart) != 1 {
		t.Errorf("expected exactly one managed block: %s", moved)
	}
	if strings.Contains(string(moved), `command = "/bin/policygate --host codex"`) {
		t.Errorf("the old command survived: %s", moved)
	}

	removed, err := rewriteCodexConfig(moved, "/opt/homebrew/bin/policygate --host codex", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(removed), "policygate") {
		t.Errorf("the block survived uninstall: %s", removed)
	}
	if !strings.Contains(string(removed), `model = "gpt-5"`) {
		t.Errorf("uninstall removed unrelated configuration: %s", removed)
	}
}

// A half-deleted block would otherwise be silently appended to, leaving two
// partial registrations.
func TestRewriteCodexConfigRejectsAnUnterminatedBlock(t *testing.T) {
	original := []byte(codexBlockStart + "\n[[hooks.PreToolUse]]\n")
	if _, err := rewriteCodexConfig(original, "/bin/policygate --host codex", true); err == nil {
		t.Error("expected an error for a block without its terminator")
	}
}

func TestTomlStringEscapes(t *testing.T) {
	if got := tomlString(`C:\bin\policygate.exe --host codex`); got != `"C:\\bin\\policygate.exe --host codex"` {
		t.Errorf("tomlString() = %s", got)
	}
	if got := tomlString(`say "hi"`); got != `"say \"hi\""` {
		t.Errorf("tomlString() = %s", got)
	}
}

// A Windows path does not survive being written as os.Executable spells it:
// "D:\bin\policygate.exe" reads \b as a backspace inside a JSON string, and a
// host that runs the command through a shell drops each backslash as an escape.
// Reported from a real Windows registration, where only the forward-slash form
// worked.
func TestHookCommandWritesForwardSlashes(t *testing.T) {
	got := hookCommand(`D:\bin\policygate.exe`, "claude")
	if strings.Contains(got, `\`) {
		t.Errorf("hookCommand() = %q, want no backslash", got)
	}
	if got != "D:/bin/policygate.exe --host claude" {
		t.Errorf("hookCommand() = %q", got)
	}
}

// The forward-slash form has to round-trip: a registration this command wrote
// must still be recognized, or install stops being idempotent on Windows.
func TestWindowsRegistrationRoundTrips(t *testing.T) {
	const exe = `D:\bin\policygate.exe`
	command := hookCommand(exe, "claude")
	names := hookProgramNames(exe)

	if !namesPolicygate(command, names) {
		t.Fatalf("namesPolicygate(%q) = false, want true", command)
	}

	once, err := rewriteClaudeSettings(nil, command, names, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(once), `\\`) {
		t.Errorf("settings carry an escaped backslash: %s", once)
	}
	twice, err := rewriteClaudeSettings(once, command, names, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Errorf("a second install on Windows changed the file:\n%s\n---\n%s", once, twice)
	}

	toml, err := rewriteCodexConfig(nil, hookCommand(exe, "codex"), true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(toml), `\`) {
		t.Errorf("codex block carries a backslash: %s", toml)
	}
}

// A backslash is a legal character in a Unix filename, so only a path spelled
// the Windows way may be rewritten.
func TestHookPathSeparatorsLeavesUnixPathsAlone(t *testing.T) {
	cases := []struct{ in, want string }{
		{`D:\bin\policygate.exe`, "D:/bin/policygate.exe"},
		{`c:\Program Files\policygate.exe`, "c:/Program Files/policygate.exe"},
		{`\\server\share\policygate.exe`, "//server/share/policygate.exe"},
		{"/usr/local/bin/policygate", "/usr/local/bin/policygate"},
		{`/home/user/we\ird/policygate`, `/home/user/we\ird/policygate`},
		{"relative/policygate", "relative/policygate"},
	}
	for _, tc := range cases {
		if got := hookPathSeparators(tc.in); got != tc.want {
			t.Errorf("hookPathSeparators(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
