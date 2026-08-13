package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nobuo-miura/policyapprovalgate/internal/paths"
)

// Registering the hook by hand means reading the binary's absolute path out of
// an install script and pasting it into JSON or TOML, with a ~ that only
// expands when the host happens to run the command through a shell. Resolving
// the path here removes that whole class of mistake, and it is the only way to
// stay correct across install locations: Homebrew's prefix differs by platform,
// and ~/.policygate/bin differs again.

const (
	// codexBlockStart and codexBlockEnd delimit the registration this command
	// manages. Owning a marked region keeps install idempotent and uninstall
	// exact without parsing the user's TOML, which would mean pulling in a
	// dependency and re-emitting a file written by hand.
	codexBlockStart = "# >>> policygate hook (managed by `policygate install-hook`) >>>"
	codexBlockEnd   = "# <<< policygate hook <<<"
)

func runInstallHook(args []string) int { return runHookRegistration(args, true) }

func runUninstallHook(args []string) int { return runHookRegistration(args, false) }

func runHookRegistration(args []string, install bool) int {
	name := "uninstall-hook"
	if install {
		name = "install-hook"
	}

	var host, override, policy string
	dryRun, user := false, false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		value := func() (string, bool) {
			if i+1 >= len(args) {
				return "", false
			}
			i++
			return args[i], true
		}
		var ok bool
		switch {
		case arg == "--host":
			if host, ok = value(); !ok {
				return usageErrorf(name, "--host requires a value")
			}
		case strings.HasPrefix(arg, "--host="):
			host = strings.TrimPrefix(arg, "--host=")
		case arg == "--path":
			if override, ok = value(); !ok {
				return usageErrorf(name, "--path requires a value")
			}
		case strings.HasPrefix(arg, "--path="):
			override = strings.TrimPrefix(arg, "--path=")
		case arg == "--config":
			if policy, ok = value(); !ok {
				return usageErrorf(name, "--config requires a value")
			}
		case strings.HasPrefix(arg, "--config="):
			policy = strings.TrimPrefix(arg, "--config=")
		case arg == "--dry-run":
			dryRun = true
		case arg == "--user":
			user = true
		default:
			return usageErrorf(name, "unknown argument %q", arg)
		}
	}

	host = strings.ToLower(host)
	if host != "claude" && host != "codex" {
		return usageErrorf(name, "--host must be claude or codex")
	}
	if user && host != "claude" {
		return usageErrorf(name, "--user applies to --host claude only")
	}

	target, err := hookConfigPath(host, user, override)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policygate %s: %v\n", name, err)
		return 1
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "policygate %s: resolve own path: %v\n", name, err)
		return 1
	}
	command := hookCommand(exe, host, policy)
	programNames := hookProgramNames(exe)

	original, err := os.ReadFile(target)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		original = nil
		if !install {
			fmt.Printf("policygate %s: %s does not exist, nothing to remove\n", name, target)
			return 0
		}
	default:
		fmt.Fprintf(os.Stderr, "policygate %s: read %s: %v\n", name, target, err)
		return 1
	}

	var updated []byte
	if host == "claude" {
		updated, err = rewriteClaudeSettings(original, command, programNames, install)
	} else {
		updated, err = rewriteCodexConfig(original, command, install)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "policygate %s: %s: %v\n", name, target, err)
		return 1
	}

	if bytes.Equal(original, updated) {
		fmt.Printf("policygate %s: %s is already up to date\n", name, target)
		return 0
	}
	if dryRun {
		fmt.Printf("policygate %s: would write %s:\n\n%s", name, target, updated)
		return 0
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "policygate %s: create directory: %v\n", name, err)
		return 1
	}
	if original != nil {
		backup, err := writeConfigBackup(target, original)
		if err != nil {
			fmt.Fprintf(os.Stderr, "policygate %s: write backup: %v\n", name, err)
			return 1
		}
		fmt.Printf("policygate %s: backed up %s to %s\n", name, target, backup)
	}
	if err := writeHookConfig(target, updated); err != nil {
		fmt.Fprintf(os.Stderr, "policygate %s: write %s: %v\n", name, target, err)
		return 1
	}

	if install {
		fmt.Printf("policygate install-hook: registered %s in %s\n", command, target)
		if host == "codex" {
			fmt.Println("policygate install-hook: run /hooks in Codex and trust the definition, or the hook is skipped")
		}
	} else {
		fmt.Printf("policygate uninstall-hook: removed the policygate hook from %s\n", target)
	}
	return 0
}

func usageErrorf(name, format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "policygate %s: %s\n", name, fmt.Sprintf(format, a...))
	usage(os.Stderr)
	return 2
}

// hookConfigPath resolves the file a host reads its hook registrations from.
func hookConfigPath(host string, user bool, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	home := paths.Home()
	if home == "" {
		return "", fmt.Errorf("resolve home dir")
	}
	switch {
	case host == "codex":
		return filepath.Join(home, ".codex", "config.toml"), nil
	case user:
		return filepath.Join(home, ".claude", "settings.json"), nil
	default:
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve working directory: %w", err)
		}
		return filepath.Join(cwd, ".claude", "settings.json"), nil
	}
}

// hookCommand builds the command a host runs. The path is quoted only when it
// has to be, because hosts display this string for the user to approve and an
// unnecessarily quoted path reads as suspicious.
//
// A Windows path is rewritten with forward slashes, because it does not survive
// the trip to the host as os.Executable spells it: inside a JSON string
// "D:\bin\policygate.exe" reads \b as a backspace, and a host that hands the
// command to a shell sees each backslash as an escape and drops it. Windows
// accepts forward slashes as separators, so the rewritten path still runs.
// A policy file is named with --config rather than through the environment.
// The documented alternative wraps the binary in /usr/bin/env, which Windows
// does not have: Codex spawns the command directly, fails to start it, and -
// measured on Windows 11 - runs the command anyway with nothing to show that
// the gate never ran.
func hookCommand(exe, host, policy string) string {
	command := quoteHookPath(hookPathSeparators(exe)) + " --host " + host
	if policy != "" {
		command += " --config " + quoteHookPath(hookPathSeparators(policy))
	}
	return command
}

// hookPathSeparators normalizes the separators of a Windows path.
//
// It keys off how the path is spelled rather than the host OS, for two reasons:
// a backslash is a legal character in a Unix filename and must survive, and
// deciding by spelling keeps the Windows behaviour reachable from a test on any
// platform.
func hookPathSeparators(p string) string {
	if !isWindowsPath(p) {
		return p
	}
	return strings.ReplaceAll(p, `\`, "/")
}

func isWindowsPath(p string) bool {
	if strings.HasPrefix(p, `\\`) {
		return true // UNC
	}
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	c := p[0] | 0x20 // fold to lower case
	return c >= 'a' && c <= 'z'
}

func quoteHookPath(p string) string {
	if !strings.ContainsAny(p, " \t") {
		return p
	}
	if runtime.GOOS == "windows" {
		return `"` + p + `"`
	}
	return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
}

// namesPolicygate reports whether a registered command runs this program,
// whatever path it was installed to. Matching the program name rather than the
// current executable keeps install idempotent after an upgrade moves the
// binary, and lets uninstall clean up a registration an older version wrote.
//
// Every token is examined rather than just the first, because the documented
// way to give each host its own policy puts the binary behind env:
//
//	/usr/bin/env POLICYGATE_CONFIG=/path/claude.yaml /path/policygate --host claude
//
// Flags and assignments are skipped so an unrelated hook that merely mentions
// the name in an argument is left alone.
func namesPolicygate(command string, programNames []string) bool {
	// Quotes become separators: a quoted path containing spaces still yields a
	// token ending in the program name.
	unquoted := strings.NewReplacer("'", " ", `"`, " ").Replace(command)
	for _, token := range strings.Fields(unquoted) {
		if token == "" || strings.HasPrefix(token, "-") || strings.Contains(token, "=") {
			continue
		}
		base := programBase(token)
		for _, name := range programNames {
			if base == name {
				return true
			}
		}
	}
	return false
}

// programBase returns the last element of a path token, honouring both
// separators whatever the local one is. A project's .claude/settings.json is
// often committed and shared, so a registration written on Windows has to be
// recognized on a machine whose filepath package treats a backslash as an
// ordinary character.
func programBase(token string) string {
	if i := strings.LastIndexAny(token, `/\`); i >= 0 {
		token = token[i+1:]
	}
	return strings.ToLower(token)
}

// hookProgramNames lists the basenames that identify a policygate registration.
//
// The canonical names come first so a registration written by a differently
// named copy is still recognized, and the running binary's own name is added so
// install stays idempotent when the binary has been renamed - otherwise a
// second run appends a duplicate instead of replacing what it wrote.
func hookProgramNames(exe string) []string {
	names := []string{"policygate", "policygate.exe"}
	base := programBase(exe)
	if base != "" && base != "." && base != names[0] && base != names[1] {
		names = append(names, base)
	}
	return names
}

// writeHookConfig replaces target atomically, keeping the mode of a file that
// already exists. A project's .claude/settings.json is often committed, so its
// permissions belong to the user rather than to this command.
func writeHookConfig(target string, data []byte) error {
	mode := os.FileMode(0o600)
	if info, err := os.Stat(target); err == nil {
		mode = info.Mode().Perm()
	}
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".policygate-hook-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, target)
}

// --- Claude Code: JSON ---

type claudeHookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type claudeMatcherGroup struct {
	Matcher string            `json:"matcher"`
	Hooks   []claudeHookEntry `json:"hooks"`
}

// rewriteClaudeSettings adds or removes the policygate PreToolUse hook. Every
// key it does not own is carried through as raw JSON, so unrelated settings
// keep their formatting and their order.
func rewriteClaudeSettings(original []byte, command string, programNames []string, install bool) ([]byte, error) {
	top := newOrderedObject()
	if len(bytes.TrimSpace(original)) > 0 {
		var err error
		if top, err = parseOrderedObject(original); err != nil {
			return nil, fmt.Errorf("parse settings: %w", err)
		}
	}

	hooks := newOrderedObject()
	if raw, ok := top.get("hooks"); ok {
		var err error
		if hooks, err = parseOrderedObject(raw); err != nil {
			return nil, fmt.Errorf("parse settings: hooks: %w", err)
		}
	}

	var groups []json.RawMessage
	if raw, ok := hooks.get("PreToolUse"); ok {
		if err := json.Unmarshal(raw, &groups); err != nil {
			return nil, fmt.Errorf("parse settings: hooks.PreToolUse: %w", err)
		}
	}

	// Removing first makes install idempotent and shares one code path with
	// uninstall.
	kept, err := withoutPolicygateHooks(groups, programNames)
	if err != nil {
		return nil, err
	}
	if install {
		if kept, err = withPolicygateHook(kept, command); err != nil {
			return nil, err
		}
	}

	switch {
	case len(kept) > 0:
		encoded, err := json.Marshal(kept)
		if err != nil {
			return nil, err
		}
		hooks.set("PreToolUse", encoded)
	default:
		hooks.remove("PreToolUse")
	}
	if hooks.empty() {
		top.remove("hooks")
	} else {
		encoded, err := hooks.MarshalJSON()
		if err != nil {
			return nil, err
		}
		top.set("hooks", encoded)
	}

	encoded, err := top.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, encoded, "", "  "); err != nil {
		return nil, err
	}
	pretty.WriteByte('\n')
	return pretty.Bytes(), nil
}

// withoutPolicygateHooks drops every policygate entry, and any matcher group
// left with no hooks. Groups it does not touch are returned unchanged.
func withoutPolicygateHooks(groups []json.RawMessage, programNames []string) ([]json.RawMessage, error) {
	var kept []json.RawMessage
	for _, raw := range groups {
		var group claudeMatcherGroup
		if err := json.Unmarshal(raw, &group); err != nil {
			// A group shaped differently is not ours; leave it alone.
			kept = append(kept, raw)
			continue
		}
		remaining := make([]claudeHookEntry, 0, len(group.Hooks))
		for _, entry := range group.Hooks {
			if !namesPolicygate(entry.Command, programNames) {
				remaining = append(remaining, entry)
			}
		}
		if len(remaining) == len(group.Hooks) {
			kept = append(kept, raw)
			continue
		}
		if len(remaining) == 0 {
			continue
		}
		group.Hooks = remaining
		encoded, err := json.Marshal(group)
		if err != nil {
			return nil, err
		}
		kept = append(kept, encoded)
	}
	return kept, nil
}

// withPolicygateHook appends the hook to an existing Bash matcher group when
// there is one, so a user who already registered other Bash hooks keeps a
// single group.
// claudeMatchers are the tools that carry a shell command to evaluate.
//
// PowerShell is listed separately rather than as an alternation such as
// "Bash|PowerShell". A matcher that turns out to be compared literally rather
// than as a regular expression would then match neither tool and disable the
// hook outright, which is the one failure this must not risk. Two plain names
// work under either reading.
var claudeMatchers = []string{"Bash", "PowerShell"}

func withPolicygateHook(groups []json.RawMessage, command string) ([]json.RawMessage, error) {
	entry := claudeHookEntry{Type: "command", Command: command}
	for _, matcher := range claudeMatchers {
		var err error
		if groups, err = withMatcherGroup(groups, matcher, entry); err != nil {
			return nil, err
		}
	}
	return groups, nil
}

// withMatcherGroup appends the hook to an existing group for matcher when there
// is one, so a user who already registered other hooks for that tool keeps a
// single group.
func withMatcherGroup(groups []json.RawMessage, matcher string, entry claudeHookEntry) ([]json.RawMessage, error) {
	for i, raw := range groups {
		var group claudeMatcherGroup
		if err := json.Unmarshal(raw, &group); err != nil || group.Matcher != matcher {
			continue
		}
		group.Hooks = append(group.Hooks, entry)
		encoded, err := json.Marshal(group)
		if err != nil {
			return nil, err
		}
		groups[i] = encoded
		return groups, nil
	}
	encoded, err := json.Marshal(claudeMatcherGroup{Matcher: matcher, Hooks: []claudeHookEntry{entry}})
	if err != nil {
		return nil, err
	}
	return append(groups, encoded), nil
}

// --- Codex CLI: TOML ---

// rewriteCodexConfig replaces the marked block, or appends one. TOML arrays of
// tables may repeat, so appending at the end of the file is valid whatever the
// user already has.
func rewriteCodexConfig(original []byte, command string, install bool) ([]byte, error) {
	body := string(original)
	start := strings.Index(body, codexBlockStart)
	if start >= 0 {
		end := strings.Index(body[start:], codexBlockEnd)
		if end < 0 {
			return nil, fmt.Errorf("found %q without its closing %q; fix the file by hand", codexBlockStart, codexBlockEnd)
		}
		end += start + len(codexBlockEnd)
		if end < len(body) && body[end] == '\n' {
			end++
		}
		body = body[:start] + body[end:]
	}
	body = strings.TrimRight(body, "\n")

	if !install {
		if body == "" {
			return nil, nil
		}
		return []byte(body + "\n"), nil
	}

	var b strings.Builder
	if body != "" {
		b.WriteString(body)
		b.WriteString("\n\n")
	}
	b.WriteString(codexBlockStart)
	b.WriteString("\n[[hooks.PreToolUse]]\nmatcher = \"^Bash$\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = ")
	b.WriteString(tomlString(command))
	b.WriteString("\n")
	b.WriteString(codexBlockEnd)
	b.WriteString("\n")
	return []byte(b.String()), nil
}

func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// --- ordered JSON object ---

// orderedObject keeps the key order of a JSON object. Rewriting one key in a
// file the user maintains by hand should not reshuffle the rest of it, which is
// what decoding into a map and re-encoding would do.
type orderedObject struct {
	keys   []string
	values map[string]json.RawMessage
}

func newOrderedObject() *orderedObject {
	return &orderedObject{values: map[string]json.RawMessage{}}
}

func parseOrderedObject(data []byte) (*orderedObject, error) {
	obj := newOrderedObject()
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("expected a JSON object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("expected an object key")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		obj.set(key, value)
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return obj, nil
}

func (o *orderedObject) get(key string) (json.RawMessage, bool) {
	v, ok := o.values[key]
	return v, ok
}

func (o *orderedObject) set(key string, value json.RawMessage) {
	if _, exists := o.values[key]; !exists {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func (o *orderedObject) remove(key string) {
	if _, exists := o.values[key]; !exists {
		return
	}
	delete(o.values, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *orderedObject) empty() bool { return len(o.keys) == 0 }

func (o *orderedObject) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, key := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		b.Write(encodedKey)
		b.WriteByte(':')
		b.Write(o.values[key])
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// hookRegistration is what a host's configuration currently registers.
type hookRegistration struct {
	path     string
	exists   bool
	matchers []string
}

// missing reports the matchers a registration lacks. Only a file that already
// registers policygate is worth reporting on: one that registers nothing is a
// host this user has not set up, not a broken setup.
func (r hookRegistration) missing() []string {
	if len(r.matchers) == 0 {
		return nil
	}
	have := make(map[string]bool, len(r.matchers))
	for _, m := range r.matchers {
		have[m] = true
	}
	var absent []string
	for _, want := range claudeMatchers {
		if !have[want] {
			absent = append(absent, want)
		}
	}
	return absent
}

// inspectClaudeRegistration reports which matchers a settings file registers
// policygate under.
//
// A registration written before a matcher was added stays as it was: nothing
// rewrites it, and the gate reports no problem while a whole tool goes past it
// unexamined. That happened - a Claude Code registered before the PowerShell
// matcher existed listed ~/.ssh without a word, on a machine whose rules were
// already up to date. Rules and registration are upgraded separately, so both
// have to be checked.
func inspectClaudeRegistration(path string, programNames []string) hookRegistration {
	reg := hookRegistration{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return reg
	}
	reg.exists = true

	var parsed struct {
		Hooks struct {
			PreToolUse []claudeMatcherGroup `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return reg
	}
	for _, group := range parsed.Hooks.PreToolUse {
		for _, entry := range group.Hooks {
			if namesPolicygate(entry.Command, programNames) {
				reg.matchers = append(reg.matchers, group.Matcher)
				break
			}
		}
	}
	return reg
}

// claudeRegistrations reports the settings files a Claude Code hook can live in.
func claudeRegistrations(programNames []string) []hookRegistration {
	var out []hookRegistration
	for _, user := range []bool{false, true} {
		path, err := hookConfigPath("claude", user, "")
		if err != nil {
			continue
		}
		out = append(out, inspectClaudeRegistration(path, programNames))
	}
	return out
}
