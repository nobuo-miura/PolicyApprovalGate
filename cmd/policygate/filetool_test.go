package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nobuo-miura/policyapprovalgate/internal/hook"
	"github.com/nobuo-miura/policyapprovalgate/internal/pathpolicy"
	"github.com/nobuo-miura/policyapprovalgate/internal/rules"
)

// The gap this closes was not a missing feature but a disagreement: the same
// file, reached with the same intent, was answered one way through the shell
// and another way through a tool that names it directly. Asserting that the
// two agree - rather than pinning each to a value - keeps them together when
// the bundled policy changes.
func TestFileToolsReachTheSameDecisionAsTheShell(t *testing.T) {
	cfg, err := rules.Default()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	key := filepath.Join(root, ".ssh", "id_rsa")
	env := filepath.Join(root, ".env")

	for _, tc := range []struct {
		name    string
		tool    string
		op      pathpolicy.Op
		path    string
		command string
	}{
		{"read a private key", "Read", pathpolicy.OpRead, key, "cat " + key},
		{"write a private key", "Write", pathpolicy.OpWrite, key, "echo x > " + key},
		{"edit an environment file", "Edit", pathpolicy.OpWrite, env, "echo x > " + env},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := hook.Input{CWD: root}

			shellDecision, shellReason, _, _ := evaluatePOSIX(cfg, in, tc.command)
			fileDecision, fileReason, _, _ := evaluateFileTool(cfg, in, tc.path, tc.op)

			// A shared "" would satisfy the comparison while protecting
			// nothing, so the shell answer has to be a real one first.
			if shellDecision == "" {
				t.Fatalf("%q was not caught through the shell either; the case no longer tests anything", tc.command)
			}
			if fileDecision != shellDecision {
				t.Errorf("%s %s = %q (%s), shell = %q (%s)",
					tc.tool, tc.path, fileDecision, fileReason, shellDecision, shellReason)
			}
		})
	}
}

// Reads are what an agent does constantly, so the cost of getting this wrong is
// a prompt on nearly every step rather than an occasional false positive.
func TestFileToolsLeaveOrdinaryWorkAlone(t *testing.T) {
	cfg, err := rules.Default()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	outside := t.TempDir()

	for _, tc := range []struct {
		name string
		op   pathpolicy.Op
		path string
	}{
		{"read inside the project", pathpolicy.OpRead, filepath.Join(root, "README.md")},
		{"read outside the project", pathpolicy.OpRead, filepath.Join(outside, "notes.md")},
		{"write inside the project", pathpolicy.OpWrite, filepath.Join(root, "main.go")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision, reason, _, _ := evaluateFileTool(cfg, hook.Input{CWD: root}, tc.path, tc.op)
			if decision != "" {
				t.Errorf("%s = %q (%s), want the host's own approval flow", tc.path, decision, reason)
			}
		})
	}
}

// Only the path policies apply to a tool that was handed a path. The command
// rules and the unknown fallback are written about commands, and letting them
// see a filename would both match the wrong things and, with a strict fallback,
// stop every file the agent touches.
const fileToolCommandRulesYAML = `
config_version: 1
deny:
  - pattern: 'secret'
    reason: "Command mentions a secret"
ask:
  - pattern: 'notes'
    reason: "Command mentions notes"
unknown:
  action: deny
path_scope:
  enabled: false
sensitive_paths:
  enabled: false
protected_paths:
  enabled: false
audit:
  enabled: false
`

func TestFileToolsSkipCommandRulesAndTheUnknownFallback(t *testing.T) {
	cfg := mustConfig(t, fileToolCommandRulesYAML)
	root := t.TempDir()

	for _, name := range []string{"secret.txt", "notes.md", "ordinary.go"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name)
			decision, reason, source, _ := evaluateFileTool(cfg, hook.Input{CWD: root}, path, pathpolicy.OpWrite)
			if decision != "" {
				t.Errorf("%s = %q (%s) from %s, want the host's own approval flow", path, decision, reason, source)
			}
		})
	}

	// The same words in a command still reach the command rules.
	if decision, _, _, _ := evaluatePOSIX(cfg, hook.Input{CWD: root}, "echo secret"); decision != hook.DecisionDeny {
		t.Errorf("deny rule through the shell = %q, want deny; the rules under test are not being applied at all", decision)
	}
}

func TestFileToolOpNamesOnlyTheToolsThatCarryAPath(t *testing.T) {
	for _, tc := range []struct {
		tool string
		want pathpolicy.Op
		ok   bool
	}{
		{"Read", pathpolicy.OpRead, true},
		{"Write", pathpolicy.OpWrite, true},
		{"Edit", pathpolicy.OpWrite, true},
		// Host tool names are matched the way every other name in this program
		// is, so a differently-cased spelling cannot slip past.
		{"write", pathpolicy.OpWrite, true},
		{"EDIT", pathpolicy.OpWrite, true},
		// Not yet measured, and guessing its field name would register a
		// matcher that silently never fires.
		{"NotebookEdit", "", false},
		{"Bash", "", false},
		{"Glob", "", false},
		{"", "", false},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			op, ok := fileToolOp(tc.tool)
			if ok != tc.ok || op != tc.want {
				t.Errorf("fileToolOp(%q) = (%q, %v), want (%q, %v)", tc.tool, op, ok, tc.want, tc.ok)
			}
		})
	}
}

// isolateHome redirects the paths policygate derives from the home directory,
// so a test that runs the whole hook path writes its audit records into the
// test's own directory instead of appending to the audit log of whoever ran it.
func isolateHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)        // Unix
	t.Setenv("USERPROFILE", home) // Windows
}

func TestRunHookDecidesOnAFileToolPayload(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	config := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(config, rules.DefaultYAML(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICYGATE_CONFIG", config)
	withArgs(t, "--host", "claude")

	key := filepath.Join(root, ".ssh", "id_rsa")
	input := fmt.Sprintf(`{"cwd":%q,"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":%q}}`, root, key)

	var output bytes.Buffer
	if code := runHook(strings.NewReader(input), &output, false); code != 0 {
		t.Fatalf("runHook() = %d, want successful hook processing", code)
	}
	if !strings.Contains(output.String(), `"permissionDecision":"ask"`) {
		t.Errorf("output = %s, want an ask decision", output.String())
	}
}

// A payload is read as whatever its tool name says it is. Choosing by which
// field happens to be populated would let a caller present both and take
// whichever analysis it preferred.
func TestRunHookLetsTheToolNameDecideWhichFieldIsRead(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	config := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(config, rules.DefaultYAML(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICYGATE_CONFIG", config)
	withArgs(t, "--host", "claude")

	// The command is harmless and the path is not: a Bash payload must be
	// judged on its command, and so must defer.
	input := fmt.Sprintf(
		`{"cwd":%q,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hello","file_path":%q}}`,
		root, filepath.Join(root, ".ssh", "id_rsa"))

	var output bytes.Buffer
	if code := runHook(strings.NewReader(input), &output, false); code != 0 {
		t.Fatalf("runHook() = %d", code)
	}
	if output.Len() != 0 {
		t.Errorf("output = %s, want no decision: a Bash payload must be read as its command", output.String())
	}
}

// Hook mode must never refuse a call because of the terminal check: a host
// delivers the payload through a pipe or a file, and both have to keep working.
func TestStdinIsTerminalOnlyRejectsCharacterDevices(t *testing.T) {
	regular, err := os.CreateTemp(t.TempDir(), "payload")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = regular.Close() })
	if stdinIsTerminal(regular) {
		t.Error("a regular file was treated as a terminal, so a host redirecting a file would be refused")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	t.Cleanup(func() { _ = w.Close() })
	if stdinIsTerminal(r) {
		t.Error("a pipe was treated as a terminal, so every piped hook call would be refused")
	}
}

// Claude Code reads a project file and a user file, and install-hook writes one
// of them. A registration left in the other scope keeps running unseen, and if
// it predates a matcher it examines less while reporting nothing - which is how
// a stale user-level registration sat alongside a fresh project one until a
// doctor run happened to surface it.
func TestOtherClaudeScopeNotesFindsAStaleRegistrationInTheOtherScope(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	project := t.TempDir()
	t.Chdir(project)

	userSettings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(userSettings), 0o700); err != nil {
		t.Fatal(err)
	}
	// What install-hook --user wrote before Read, Write and Edit were added.
	const stale = `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/old/bin/policygate --host claude"}]}]}}`
	if err := os.WriteFile(userSettings, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	projectTarget := filepath.Join(project, ".claude", "settings.local.json")
	notes := strings.Join(otherClaudeScopeNotes("install-hook", projectTarget, "", testProgramNames), "\n")

	if !strings.Contains(notes, userSettings) {
		t.Fatalf("the user-level registration was not reported:\n%s", notes)
	}
	for _, tool := range []string{"Read", "Write", "Edit"} {
		if !strings.Contains(notes, tool) {
			t.Errorf("%s is missing there but was not named:\n%s", tool, notes)
		}
	}
	// The flag has to reach the other file, not the one just written.
	if !strings.Contains(notes, "--host claude --user") {
		t.Errorf("the advice does not point at the user scope:\n%s", notes)
	}

	// Nothing to say when the other scope holds no registration.
	if err := os.Remove(userSettings); err != nil {
		t.Fatal(err)
	}
	if notes := otherClaudeScopeNotes("install-hook", projectTarget, "", testProgramNames); len(notes) != 0 {
		t.Errorf("reported something with no other registration: %v", notes)
	}

	// An explicit --path means the caller named the file outright.
	if err := os.WriteFile(userSettings, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	if notes := otherClaudeScopeNotes("install-hook", projectTarget, "/some/explicit/path.json", testProgramNames); len(notes) != 0 {
		t.Errorf("reported a scope for an explicit --path: %v", notes)
	}
}

// The example settings file is what someone registering by hand copies, and it
// lives in a package that cannot import this one - so its matcher list is
// written out by hand and nothing here notices when the two drift. Adding a
// tool to claudeMatchers without updating the example would hand every manual
// registration a gate that examines less than the installer's does.
func TestExampleSettingsCoverEveryMatcher(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "claude-code.settings.example.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Hooks struct {
			PreToolUse []struct {
				Matcher string `json:"matcher"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("%s is not valid JSON: %v", path, err)
	}
	var got []string
	for _, group := range parsed.Hooks.PreToolUse {
		got = append(got, group.Matcher)
	}
	if !slices.Equal(got, claudeMatchers) {
		t.Errorf("%s registers %v, want %v", path, got, claudeMatchers)
	}
}

// Codex edits files with apply_patch rather than with a tool of its own, and
// the patch arrives as a shell command. The gate saw the command and stopped
// there: no path came out of it, so a write to .env was answered one way when
// spelled as a redirect and another way when spelled as a patch.
func TestApplyPatchReachesTheSameDecisionAsTheShell(t *testing.T) {
	cfg, err := rules.Default()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	in := hook.Input{CWD: root}

	for _, tc := range []struct {
		name  string
		shell string
		patch string
	}{
		{
			name:  "write a secrets file",
			shell: "echo x > .env",
			patch: "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: .env\n+X=1\n*** End Patch\nPATCH",
		},
		{
			name:  "create a file under .ssh",
			shell: "echo x > .ssh/config",
			patch: "apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: .ssh/config\n+Host x\n*** End Patch\nPATCH",
		},
		{
			name:  "delete a secrets file",
			shell: "rm .env",
			patch: "apply_patch <<'PATCH'\n*** Begin Patch\n*** Delete File: .env\n*** End Patch\nPATCH",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shellDecision, shellReason, _, _ := evaluatePOSIX(cfg, in, tc.shell)
			patchDecision, patchReason, _, _ := evaluatePOSIX(cfg, in, tc.patch)

			if shellDecision == "" {
				t.Fatalf("%q was not caught through the shell either; the case no longer tests anything", tc.shell)
			}
			if patchDecision != shellDecision {
				t.Errorf("patch = %q (%s), shell = %q (%s)",
					patchDecision, patchReason, shellDecision, shellReason)
			}
		})
	}

	// An ordinary source edit still goes to the host, or every patch would prompt.
	ordinary := "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: main.go\n+// x\n*** End Patch\nPATCH"
	if decision, reason, _, _ := evaluatePOSIX(cfg, in, ordinary); decision != "" {
		t.Errorf("an ordinary patch = %q (%s), want the host's own approval flow", decision, reason)
	}
}
