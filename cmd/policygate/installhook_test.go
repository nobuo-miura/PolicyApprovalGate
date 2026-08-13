package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
		// The name alone is not a registration. Another tool taking a path to
		// policygate as an argument must not be mistaken for one, or uninstall
		// deletes somebody else's hook.
		"/usr/local/bin/audit-tool --exclude /tmp/policygate",
		"/usr/local/bin/watch /opt/homebrew/bin/policygate",
		"/usr/local/bin/policygate",
		"/usr/local/bin/policygate --version",
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
			PreToolUse []struct {
				Matcher string `json:"matcher"`
				Hooks   []struct {
					Type    string `json:"type"`
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	// Claude Code on Windows carries commands through a PowerShell tool as
	// well as a Bash one, and a matcher of "Bash" alone leaves that traffic
	// unexamined. Each tool gets its own group rather than an alternation,
	// so a matcher compared literally still matches.
	groups := parsed.Hooks.PreToolUse
	registered := map[string]string{}
	for _, group := range groups {
		if len(group.Hooks) != 1 {
			t.Fatalf("unexpected registration: %s", out)
		}
		registered[group.Matcher] = group.Hooks[0].Command
	}
	for _, matcher := range claudeMatchers {
		if got := registered[matcher]; got != "/bin/policygate --host claude" {
			t.Errorf("matcher %q registered %q", matcher, got)
		}
	}
	if len(registered) != len(claudeMatchers) {
		t.Errorf("registered %d matchers, want %d: %s", len(registered), len(claudeMatchers), out)
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
	if got := strings.Count(string(out), "--host claude"); got != len(claudeMatchers) {
		t.Errorf("registered %d times, want one per matcher (%d): %s", got, len(claudeMatchers), out)
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
	got := hookCommand(`D:\bin\policygate.exe`, "claude", "")
	if strings.Contains(got, `\`) {
		t.Errorf("hookCommand() = %q, want no backslash", got)
	}
	if got != "D:/bin/policygate.exe --host claude" {
		t.Errorf("hookCommand() = %q", got)
	}
}

// Naming the policy file through the environment needs /usr/bin/env, which
// Windows does not have: Codex fails to start the command and - measured on
// Windows 11 - runs the guarded command anyway, with no sign the gate never
// ran. --config removes the wrapper, so the registration works everywhere.
func TestHookCommandCarriesAConfigPath(t *testing.T) {
	got := hookCommand(`D:\bin\policygate.exe`, "codex", `C:\Users\x\.policygate\codex.yaml`)
	want := "D:/bin/policygate.exe --host codex --config C:/Users/x/.policygate/codex.yaml"
	if got != want {
		t.Errorf("hookCommand() = %q, want %q", got, want)
	}
	if strings.Contains(got, "/usr/bin/env") {
		t.Errorf("hookCommand() = %q, want no wrapper", got)
	}

	// A registration naming a policy file must still be recognized, or a second
	// install appends a duplicate.
	if !namesPolicygate(got, hookProgramNames(`D:\bin\policygate.exe`)) {
		t.Errorf("namesPolicygate(%q) = false, want true", got)
	}

	// A path with a space is quoted, and the flag survives the quoting.
	spaced := hookCommand("/usr/local/bin/policygate", "claude", "/Users/a b/policy.yaml")
	if !strings.Contains(spaced, "--config '/Users/a b/policy.yaml'") {
		t.Errorf("hookCommand() = %q, want the policy path quoted", spaced)
	}
}

// The forward-slash form has to round-trip: a registration this command wrote
// must still be recognized, or install stops being idempotent on Windows.
func TestWindowsRegistrationRoundTrips(t *testing.T) {
	const exe = `D:\bin\policygate.exe`
	command := hookCommand(exe, "claude", "")
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

	toml, err := rewriteCodexConfig(nil, hookCommand(exe, "codex", ""), true)
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

// Rules and registration are upgraded by separate commands, and only the rules
// announce themselves. A settings file written before the PowerShell matcher
// existed keeps working and reports nothing while every PowerShell command goes
// past unexamined - found on a machine whose rules were already current, which
// listed ~/.ssh without a prompt.
func TestInspectClaudeRegistrationFindsAStaleMatcherSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	// What install-hook wrote before PowerShell was added.
	const stale = `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/bin/policygate --host claude"}]}]}}`
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := inspectClaudeRegistration(path, testProgramNames)
	if !reg.exists {
		t.Fatal("the settings file was not read")
	}
	if len(reg.matchers) != 1 || reg.matchers[0] != "Bash" {
		t.Fatalf("matchers = %v, want just Bash", reg.matchers)
	}
	missing := reg.missing()
	if len(missing) != 1 || missing[0] != "PowerShell" {
		t.Errorf("missing() = %v, want PowerShell", missing)
	}
}

func TestInspectClaudeRegistrationIsQuietWhenCurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	current, err := rewriteClaudeSettings(nil, "/bin/policygate --host claude", testProgramNames, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, current, 0o600); err != nil {
		t.Fatal(err)
	}

	if missing := inspectClaudeRegistration(path, testProgramNames).missing(); len(missing) != 0 {
		t.Errorf("missing() = %v, want none for a registration just written", missing)
	}
}

// A file that registers other hooks but not policygate is a host this user has
// not set up. Reporting it as incomplete would be noise.
func TestInspectClaudeRegistrationIgnoresUnrelatedHooks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	const other = `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/other-tool"}]}]}}`
	if err := os.WriteFile(path, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := inspectClaudeRegistration(path, testProgramNames)
	if len(reg.matchers) != 0 || len(reg.missing()) != 0 {
		t.Errorf("matchers = %v, missing = %v, want both empty", reg.matchers, reg.missing())
	}
}

// A hook may carry fields this program knows nothing about - a timeout, args,
// an async flag. Decoding a group into a struct and re-encoding it drops every
// one of them, which would mean installing policygate beside another tool
// quietly broke that tool's configuration.
func TestRewriteClaudeSettingsPreservesUnknownFieldsOnOtherHooks(t *testing.T) {
	original := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","description":"team hooks","hooks":[` +
		`{"type":"command","command":"/usr/local/bin/other-tool","timeout":30,"async":true,"args":["--strict"]}` +
		`]}]}}`)

	// Installing beside it appends to the same group, which re-encodes it;
	// uninstalling removes policygate from that group and re-encodes it again.
	installed, err := rewriteClaudeSettings(original, "/bin/policygate --host claude", testProgramNames, true)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := rewriteClaudeSettings(installed, "/bin/policygate --host claude", testProgramNames, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []struct {
		name string
		out  []byte
	}{{"install", installed}, {"uninstall", removed}} {
		neighbour := findHookEntry(t, stage.out, "/usr/local/bin/other-tool")
		for field, want := range map[string]any{
			"timeout": float64(30),
			"async":   true,
		} {
			if got := neighbour[field]; got != want {
				t.Errorf("%s: neighbouring hook lost %q: got %v, want %v", stage.name, field, got, want)
			}
		}
		args, _ := neighbour["args"].([]any)
		if len(args) != 1 || args[0] != "--strict" {
			t.Errorf("%s: neighbouring hook lost its args: %v", stage.name, neighbour["args"])
		}
		// A field on the group itself has to survive too.
		if !strings.Contains(string(stage.out), "team hooks") {
			t.Errorf("%s: the group lost its description: %s", stage.name, stage.out)
		}
	}
	if strings.Contains(string(removed), "policygate") {
		t.Errorf("the registration survived uninstall: %s", removed)
	}
}

// findHookEntry returns the PreToolUse hook whose command is want.
func findHookEntry(t *testing.T, settings []byte, want string) map[string]any {
	t.Helper()
	var parsed struct {
		Hooks struct {
			PreToolUse []struct {
				Hooks []map[string]any `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(settings, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, settings)
	}
	for _, group := range parsed.Hooks.PreToolUse {
		for _, entry := range group.Hooks {
			if entry["command"] == want {
				return entry
			}
		}
	}
	t.Fatalf("no hook with command %q in %s", want, settings)
	return nil
}

// The project settings file is shared and committed, and the registration
// carries this machine's absolute path to the binary. Writing there publishes a
// local path and hands teammates a hook pointing at a binary they do not have.
func TestHookConfigPathDefaultsToTheLocalSettingsFile(t *testing.T) {
	got, err := hookConfigPath("claude", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "settings.local.json" {
		t.Errorf("hookConfigPath(claude) = %q, want the local settings file", got)
	}

	// --user names the user-level file, which is not shared.
	got, err = hookConfigPath("claude", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "settings.json" {
		t.Errorf("hookConfigPath(claude, user) = %q, want ~/.claude/settings.json", got)
	}
}
