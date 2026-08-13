// Command policygate implements a deterministic PreToolUse hook for Claude
// Code and Codex CLI. It evaluates commands with local policy and delegates
// unmatched or internally failed checks to the host approval flow.
package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nobuo-miura/policyapprovalgate/internal/audit"
	"github.com/nobuo-miura/policyapprovalgate/internal/dialect"
	"github.com/nobuo-miura/policyapprovalgate/internal/gitpush"
	"github.com/nobuo-miura/policyapprovalgate/internal/hook"
	"github.com/nobuo-miura/policyapprovalgate/internal/pathpolicy"
	"github.com/nobuo-miura/policyapprovalgate/internal/paths"
	"github.com/nobuo-miura/policyapprovalgate/internal/rules"
	"github.com/nobuo-miura/policyapprovalgate/internal/shellparse"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init":
			os.Exit(runInit())
		case "install-hook":
			os.Exit(runInstallHook(os.Args[2:]))
		case "uninstall-hook":
			os.Exit(runUninstallHook(os.Args[2:]))
		case "check-config":
			os.Exit(runCheckConfig(os.Args[2:]))
		case "doctor":
			os.Exit(runDoctor(os.Args[2:]))
		case "evaluate":
			os.Exit(runEvaluate(os.Args[2:]))
		case "observe":
			os.Exit(runHookMode(os.Args[2:], true))
		case "version":
			fmt.Println(version)
			return
		case "help", "-h", "--help":
			usage(os.Stdout)
			return
		}
	}
	os.Exit(runHookMode(os.Args[1:], false))
}

// usage describes every subcommand. Hook mode is the default, so an unknown
// argument must be reported rather than silently treated as a hook call.
func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `policygate applies a deterministic policy to PreToolUse hook calls.

Usage:
  policygate [--host claude|codex] [--config PATH]
                                             Evaluate one PreToolUse payload from stdin
  policygate observe [--host claude|codex] [--config PATH]
                                             Record a decision without enforcing it
  policygate init [--upgrade]                Create or upgrade the user configuration
  policygate install-hook --host claude|codex [--user] [--path PATH] [--config PATH] [--dry-run]
                                             Register this binary as a PreToolUse hook
  policygate uninstall-hook --host claude|codex [--user] [--path PATH] [--dry-run]
                                             Remove the registration
  policygate check-config [--config PATH]    Validate a configuration file
  policygate doctor                          Print version, host, and configuration status
  policygate evaluate --command CMD [--cwd DIR] [--host claude|codex] [--tool NAME]
                                             Evaluate a command without executing it
  policygate version                         Print the version
  policygate help                            Print this message

Environment:
  POLICYGATE_CONFIG  Configuration file path (default ~/.policygate/config.yaml).
                     A --config flag takes precedence.
  POLICYGATE_HOST    Host behavior applied when --host is omitted
  POLICYGATE_SHELL   Shell dialect (posix or powershell); overrides detection
`)
}

// runHookMode processes one hook call after rejecting arguments hook mode does
// not accept, so a mistyped subcommand cannot silently wait on stdin.
func runHookMode(args []string, observeOverride bool) int {
	if err := checkHookArgs(args); err != nil {
		fmt.Fprintf(os.Stderr, "policygate: %v\n", err)
		usage(os.Stderr)
		return 2
	}
	return run(observeOverride)
}

// checkHookArgs accepts only the flags hook mode understands, so a mistyped
// subcommand is reported instead of being treated as a hook call.
func checkHookArgs(args []string) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--host", arg == "--config":
			if i+1 >= len(args) {
				return fmt.Errorf("%s requires a value", arg)
			}
			i++
		case strings.HasPrefix(arg, "--host="), strings.HasPrefix(arg, "--config="):
		default:
			return fmt.Errorf("unknown argument %q", arg)
		}
	}
	return nil
}

// runInit creates or upgrades the user configuration.
func runInit() int {
	upgrade := false
	for _, arg := range os.Args[2:] {
		if arg != "--upgrade" {
			fmt.Fprintf(os.Stderr, "policygate init: unknown argument %q\n", arg)
			usage(os.Stderr)
			return 2
		}
		upgrade = true
	}
	path, err := paths.ConfigTarget()
	if err != nil {
		fmt.Fprintf(os.Stderr, "policygate init: resolve home dir: %v\n", err)
		return 1
	}

	if _, err := os.Stat(path); err == nil {
		if !upgrade {
			fmt.Printf("policygate init: %s already exists, leaving it alone\n", path)
			return 0
		}
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "policygate init: inspect %s: %v\n", path, err)
		return 1
	}

	// The directory may also contain audit logs with sensitive command data.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "policygate init: create directory: %v\n", err)
		return 1
	}
	data := rules.DefaultYAML()
	if upgrade {
		old, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "policygate init --upgrade: read %s: %v\n", path, err)
			return 1
		}
		var warnings []string
		data, warnings, err = rules.Upgrade(old)
		if err != nil {
			fmt.Fprintf(os.Stderr, "policygate init --upgrade: %v\n", err)
			return 1
		}
		for _, warning := range warnings {
			fmt.Printf("policygate init --upgrade: %s\n", warning)
		}
		backup, err := writeConfigBackup(path, old)
		if err != nil {
			fmt.Fprintf(os.Stderr, "policygate init --upgrade: write backup: %v\n", err)
			return 1
		}
		fmt.Printf("policygate init --upgrade: backed up existing policy to %s\n", backup)
	}
	if err := writeConfigAtomically(path, data); err != nil {
		fmt.Fprintf(os.Stderr, "policygate init: write %s: %v\n", path, err)
		return 1
	}
	fmt.Printf("policygate init: wrote policy schema v%d to %s\n", rules.CurrentConfigVersion, path)
	return 0
}

// run processes one hook call. Policy denials are emitted as hook output;
// nonzero exit codes are reserved for failures to process the call itself.
func run(observeOverride bool) int {
	return runHook(os.Stdin, os.Stdout, observeOverride)
}

func runHook(stdin io.Reader, stdout io.Writer, observeOverride bool) int {
	cfg, _, configErr := loadConfig()
	host := resolveHost()

	in, err := hook.ReadInput(stdin)
	if err != nil {
		warnf("read hook input: %v (deferring)", err)
		return 0
	}

	cmd := strings.TrimSpace(in.ToolInput.Command)
	if !carriesShellCommand(in.ToolName) || cmd == "" {
		return 0
	}
	in.CWD = resolveCWD(in.CWD)
	shell := resolveDialect(host, in.ToolName)
	warnOnDialectMismatch(shell, cmd)
	if configErr != nil {
		reason := "policy configuration could not be loaded: " + configErr.Error()
		warnf("%s", reason)
		if !observeOverride {
			if err := hook.WriteDecision(stdout, hook.DecisionDeny, reason); err != nil {
				warnf("write configuration-error decision: %v", err)
			}
		}
		return 0
	}

	decision, reason, source, matchedBy := evaluate(cfg, in, cmd, shell)
	decision, reason = finalizeForHost(host, decision, reason)
	predictedDecision := decision
	observe := observeOverride || cfg.Mode == "observe"
	if observe {
		decision = ""
	}

	if err := hook.WriteDecision(stdout, decision, reason); err != nil {
		warnf("write decision: %v", err)
	}

	if cfg.Audit.Enabled {
		loggedCmd := auditCommand(cfg.Audit.CommandMode, cmd)
		rec := audit.Record{
			Time:      time.Now(),
			ToolName:  in.ToolName,
			CWD:       in.CWD,
			Command:   loggedCmd,
			Source:    source,
			Decision:  string(predictedDecision),
			Reason:    reason,
			MatchedBy: matchedBy,
			Dialect:   string(shell),
		}
		if observe {
			rec.Source = "observe:" + rec.Source
		}
		if err := audit.Append(auditPath(cfg), rec, audit.Options{MaxBytes: cfg.Audit.MaxBytes, MaxFiles: cfg.Audit.MaxFiles}); err != nil {
			warnf("write audit log: %v", err)
		}
	}

	return 0
}

// evaluate returns the host decision and audit metadata. Explicit denials take
// priority and unmatched commands delegate to host approval.
func evaluate(cfg *rules.Config, in hook.Input, cmd string, shell dialect.Dialect) (decision hook.Decision, reason, source, matchedBy string) {
	// Match the whole command with quoted and escaped text masked out, so a
	// separator inside an argument cannot pose as the start of a command.
	if r := cfg.MatchDeny(maskQuotedText(cmd)); r != nil {
		return hook.DecisionDeny, r.Reason, "deny_rule", r.Pattern
	}

	subcmds, parseErr := shellparse.Parse(cmd)
	if parseErr != nil {
		// Do not guess when invalid syntax prevents structural analysis.
		warnf("parse command for analysis: %v", parseErr)
		d, r := actionDecision(cfg.ParseError, shell, "could not analyze command structure: "+parseErr.Error())
		return d, r, "parse_error", ""
	}

	// Quoting and escaping hide a program name from the raw text, as in
	// m'k'fs.ext4 or \rm, so deny rules also see each command's resolved form.
	for _, sc := range expandNestedScripts(subcmds, 0) {
		if r := cfg.MatchDeny(resolvedText(sc)); r != nil {
			return hook.DecisionDeny, r.Reason, "deny_rule", r.Pattern
		}
	}

	if blocked, reason := checkCriticalDeletes(subcmds, in.CWD); blocked {
		return hook.DecisionDeny, reason, "critical_delete", "rm recursive+force"
	}

	// A literal sh -c or eval script runs real commands, so every check below
	// also inspects the scripts reachable from this command.
	nested := nestedScriptGroups(subcmds, in.CWD, 0)

	if v := checkProtectedBranches(cfg, subcmds, in.CWD); v.Blocked {
		return hook.DecisionDeny, v.Reason, "protected_branch", ""
	}
	for _, group := range nested {
		if v := checkProtectedBranches(cfg, group.commands, group.cwd); v.Blocked {
			return hook.DecisionDeny, v.Reason, "protected_branch", ""
		}
	}

	// Ask rules request confirmation for specific commands without denying
	// them outright, checked the same way deny rules are: against the whole
	// masked command, then each subcommand's resolved form.
	if r := cfg.MatchAsk(maskQuotedText(cmd)); r != nil {
		return hook.DecisionAsk, r.Reason, "ask_rule", r.Pattern
	}
	for _, sc := range expandNestedScripts(subcmds, 0) {
		if r := cfg.MatchAsk(resolvedText(sc)); r != nil {
			return hook.DecisionAsk, r.Reason, "ask_rule", r.Pattern
		}
	}

	if d, r, src, matched := strictestPathAccess(cfg, subcmds, cmd, in.CWD, nested, shell); d != "" {
		switch d {
		case "deny":
			return hook.DecisionDeny, r, src, matched
		case "ask":
			return hook.DecisionAsk, r, src, matched
		}
	}

	// Match every simple command separately so a safe prefix cannot classify an
	// unsafe suffix. Allow classification never bypasses host approval.
	if patterns, ok := allSubcommandsAllowed(cfg, subcmds); ok {
		reason := "matches an allow rule"
		source := "allow_rule"
		if len(subcmds) > 1 {
			reason = "every command in the chain matches an allow rule"
			source = "allow_rule_chain"
		}
		return "", reason + " (host approval is never bypassed)", source, strings.Join(patterns, " | ")
	}

	// Delegate to the configured unknown-command fallback.
	d, r := actionDecision(cfg.Unknown, shell, unmatchedReason(shell))
	return d, r, "unknown", ""
}

// maxNestedShellDepth bounds how far literal sh -c and eval scripts are
// followed. Reaching it fails closed rather than leaving a script uninspected.
const maxNestedShellDepth = 8

// resolvedText renders a command with its wrappers removed and its program
// name unquoted, so a deny pattern matches the program that will actually run.
//
// Only the program name is normalized. Arguments keep the quoting they were
// written with, because an argument's contents must never be re-read as
// command syntax: echo 'sudo rm -rf /' deletes nothing.
func resolvedText(cmd shellparse.Command) string {
	unwrapped := shellparse.Unwrap(cmd)
	if len(unwrapped.Argv) == 0 {
		return ""
	}
	args := unwrapped.Argv[1:]
	if len(unwrapped.ArgvRaw) == len(unwrapped.Argv) {
		// Prefer the written form so quoting is visible; a re-parsed env -S
		// string has no raw form and falls back to its resolved arguments.
		args = unwrapped.ArgvRaw[1:]
	}
	parts := []string{unwrapped.Argv[0]}
	for _, a := range args {
		parts = append(parts, maskQuotedText(a))
	}
	for _, r := range unwrapped.Redirects {
		parts = append(parts, r.Op, r.Target)
	}
	return strings.Join(parts, " ")
}

// maskFiller replaces a neutralized metacharacter. It is a word character so
// that word boundaries around it behave the same as around ordinary text.
const maskFiller = 'x'

// shellMetacharacters separate or redirect commands.
const shellMetacharacters = ";&|<>"

// maskQuotedText neutralizes the shell metacharacters inside quoted spans and
// after a backslash, so a separator that is really part of an argument cannot
// anchor a rule: `git commit -m '; reboot'` runs nothing but git.
//
// Only metacharacters are replaced. Rules that deliberately inspect argument
// contents, such as the one for an interpreter writing to a hook configuration
// file, still see the text they need.
//
// This runs on unparseable input too, so deny rules keep applying when shell
// syntax is invalid.
func maskQuotedText(s string) string {
	out := []byte(s)
	inSingle, inDouble := false, false
	mask := func(i int) {
		if strings.IndexByte(shellMetacharacters, out[i]) >= 0 {
			out[i] = maskFiller
		}
	}
	for i := 0; i < len(out); i++ {
		switch c := out[i]; {
		case c == '\\' && !inSingle:
			if i+1 < len(out) {
				i++
				mask(i)
			}
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case inSingle || inDouble:
			mask(i)
		}
	}
	return string(out)
}

// expandNestedScripts returns subcmds together with the commands of every
// literal sh -c or eval script they carry. It ignores working directories
// because callers use it for text matching only.
func expandNestedScripts(subcmds []shellparse.Command, depth int) []shellparse.Command {
	if depth >= maxNestedShellDepth {
		return subcmds
	}
	out := make([]shellparse.Command, 0, len(subcmds))
	for _, sc := range subcmds {
		out = append(out, sc)
		nested, ok := parseNestedScript(sc)
		if !ok {
			continue
		}
		out = append(out, expandNestedScripts(nested, depth+1)...)
	}
	return out
}

// nestedScriptGroup is a literal script found inside a command, paired with the
// working directory it runs from.
type nestedScriptGroup struct {
	commands []shellparse.Command
	cwd      string
}

// nestedScriptGroups returns the literal scripts reachable from subcmds. A
// script whose working directory cannot be resolved is skipped, because the
// checks that consume these groups depend on that directory.
func nestedScriptGroups(subcmds []shellparse.Command, startCWD string, depth int) []nestedScriptGroup {
	if depth >= maxNestedShellDepth {
		return nil
	}
	home := paths.Home()
	states, _ := pathpolicy.TrackCWD(subcmds, startCWD, home)
	var out []nestedScriptGroup
	for i, sc := range subcmds {
		if states[i].Indeterminate {
			continue
		}
		nested, ok := parseNestedScript(sc)
		if !ok {
			continue
		}
		out = append(out, nestedScriptGroup{commands: nested, cwd: states[i].Path})
		out = append(out, nestedScriptGroups(nested, states[i].Path, depth+1)...)
	}
	return out
}

// parseNestedScript parses the script carried by a literal sh -c or eval.
func parseNestedScript(cmd shellparse.Command) ([]shellparse.Command, bool) {
	unwrapped := shellparse.Unwrap(cmd)
	script, ok := literalNestedShellScript(path.Base(unwrapped.Name()), unwrapped.Argv)
	if !ok {
		return nil, false
	}
	nested, err := shellparse.Parse(script)
	if err != nil {
		return nil, false
	}
	return nested, true
}

// strictestPathAccess returns the strictest path decision across the command
// itself and every literal script it reaches.
func strictestPathAccess(cfg *rules.Config, subcmds []shellparse.Command, cmd, cwd string, nested []nestedScriptGroup, shell dialect.Dialect) (decision, reason, source, matchedBy string) {
	home := paths.Home()
	if shell == dialect.PowerShell {
		// The nested groups are POSIX constructs, recovered from a literal
		// sh -c; there is nothing equivalent to walk into here.
		return checkPathAccess(cfg, powerShellAccesses(cmd, cwd), cwd)
	}
	best := 0
	consider := func(d, r, s, m string) {
		if rank := decisionRank(d); rank > best {
			best, decision, reason, source, matchedBy = rank, d, r, s, m
		}
	}
	consider(checkPathAccess(cfg, posixAccesses(subcmds, cwd, home), cwd))
	for _, group := range nested {
		consider(checkPathAccess(cfg, posixAccesses(group.commands, group.cwd, home), group.cwd))
	}
	return decision, reason, source, matchedBy
}

// checkCriticalDeletes enforces a non-configurable baseline against recursively
// force-deleting the filesystem root or the current user's home directory.
func checkCriticalDeletes(subcmds []shellparse.Command, startCWD string) (bool, string) {
	return checkCriticalDeletesContext(subcmds, startCWD, 0, false)
}

func checkCriticalDeletesDepth(subcmds []shellparse.Command, startCWD string, depth int) (bool, string) {
	return checkCriticalDeletesContext(subcmds, startCWD, depth, false)
}

func checkCriticalDeletesContext(subcmds []shellparse.Command, startCWD string, depth int, xargsInput bool) (bool, string) {
	if depth >= maxNestedShellDepth {
		return true, "nested shell analysis depth exceeded while checking critical deletion"
	}
	home := paths.Home()
	states, _ := pathpolicy.TrackCWD(subcmds, startCWD, home)
	for i, original := range subcmds {
		cmd := shellparse.Unwrap(original)
		name := path.Base(cmd.Name())
		throughXargs := xargsInput || passesThroughXargs(original.Argv)
		if script, ok := literalNestedShellScript(name, cmd.Argv); ok && !states[i].Indeterminate {
			if nested, err := shellparse.Parse(script); err == nil {
				if blocked, reason := checkCriticalDeletesContext(nested, states[i].Path, depth+1, throughXargs); blocked {
					return true, reason
				}
			}
		}
		if name != "rm" || len(cmd.Argv) < 2 {
			continue
		}
		// xargs builds the argument list from stdin, so its targets may never
		// appear as positional arguments. Only a simple here-string is fully
		// knowable without executing xargs' own input parser.
		stdinTargets, stdinKnown := xargsInputTargets(original)
		recursive, force := false, false
		var targets []string
		optionsDone := false
		for _, arg := range cmd.Argv[1:] {
			switch {
			case !optionsDone && arg == "--":
				optionsDone = true
			case !optionsDone && arg == "--recursive":
				recursive = true
			case !optionsDone && arg == "--force":
				force = true
			case !optionsDone && strings.HasPrefix(arg, "--"):
				// Unknown long options cannot imply short -r/-f flags.
			case !optionsDone && strings.HasPrefix(arg, "-") && arg != "-":
				flags := strings.TrimPrefix(arg, "-")
				recursive = recursive || strings.ContainsAny(flags, "rR")
				force = force || strings.Contains(flags, "f")
			default:
				targets = append(targets, arg)
			}
		}
		if !recursive || !force {
			continue
		}
		if throughXargs && !stdinKnown {
			return true, "recursive force-delete target supplied to xargs through unresolved standard input"
		}
		targets = append(targets, stdinTargets...)
		if throughXargs {
			for _, target := range targets {
				if strings.ContainsAny(target, "$`") {
					return true, "recursive force-delete target supplied through unresolved xargs arguments"
				}
			}
		}
		state := states[i]
		if state.Indeterminate {
			continue
		}
		for _, target := range targets {
			// $HOME never resolves during analysis, so it is matched literally
			// instead of being dismissed as an unresolved expansion.
			if home != "" && isHomeExpansion(target) {
				return true, "recursive force-delete of current user's home directory"
			}
			resolved := pathpolicy.ResolvePhysical(pathpolicy.Resolve(state.Path, home, target))
			if resolved == "/" {
				return true, "recursive force-delete of filesystem root"
			}
			if home != "" && resolved == pathpolicy.ResolvePhysical(home) {
				return true, "recursive force-delete of current user's home directory"
			}
		}
	}
	return false, ""
}

// xargsInputTargets returns the paths supplied through a simple here-string.
// A pipe, file, heredoc, or quoted xargs input needs runtime parsing and is
// therefore reported as unknown.
func xargsInputTargets(cmd shellparse.Command) ([]string, bool) {
	if !passesThroughXargs(cmd.Argv) {
		return nil, true
	}
	var targets []string
	found := false
	for _, r := range cmd.Redirects {
		switch r.Op {
		case "<<<":
			if found || strings.ContainsAny(r.Target, `"'\`) {
				return nil, false
			}
			found = true
			targets = append(targets, strings.Fields(r.Target)...)
		case "<", "<<", "<<-":
			return nil, false
		}
	}
	return targets, found
}

// passesThroughXargs reports whether argv runs its tail through xargs.
func passesThroughXargs(argv []string) bool {
	for _, a := range argv {
		if path.Base(strings.TrimPrefix(a, `\`)) == "xargs" {
			return true
		}
	}
	return false
}

// isHomeExpansion reports whether target is a plain reference to $HOME. A
// quoted expansion keeps its quotes, because the parser cannot resolve it.
func isHomeExpansion(target string) bool {
	target = strings.Trim(target, `"'`)
	switch strings.TrimSuffix(target, "/") {
	case "$HOME", "${HOME}":
		return true
	default:
		return false
	}
}

func literalNestedShellScript(name string, argv []string) (string, bool) {
	switch name {
	case "sh", "bash", "dash", "ksh", "zsh":
		for i := 1; i+1 < len(argv); i++ {
			arg := argv[i]
			if arg == "-c" || (strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(strings.TrimPrefix(arg, "-"), "c")) {
				return argv[i+1], true
			}
		}
	case "eval":
		if len(argv) > 1 {
			return strings.Join(argv[1:], " "), true
		}
	}
	return "", false
}

// actionDecision maps a configured fallback action to a host decision.
// unmatchedReason says why nothing matched, because the two cases mean opposite
// things and the user reading the prompt has to be able to tell them apart.
func unmatchedReason(shell dialect.Dialect) string {
	if shell.Analyzable() {
		return "no rule matched"
	}
	return fmt.Sprintf("no rule matched, and %s commands are matched as text only: policygate could not examine this one", shell)
}

func actionDecision(a rules.ActionConfig, shell dialect.Dialect, reason string) (hook.Decision, string) {
	switch a.For(shell.Analyzable()) {
	case "ask":
		return hook.DecisionAsk, reason
	case "deny":
		return hook.DecisionDeny, reason
	default:
		return "", reason
	}
}

// allSubcommandsAllowed reports whether every simple command matches an audit
// classification rule. An empty command list never matches.
func allSubcommandsAllowed(cfg *rules.Config, subcmds []shellparse.Command) ([]string, bool) {
	if len(subcmds) == 0 {
		return nil, false
	}
	patterns := make([]string, 0, len(subcmds))
	for _, sc := range subcmds {
		r := cfg.MatchAllow(sc.Raw)
		if r == nil {
			return nil, false
		}
		patterns = append(patterns, r.Pattern)
	}
	return patterns, true
}

func checkProtectedBranches(cfg *rules.Config, subcmds []shellparse.Command, cwd string) gitpush.Verdict {
	pb := cfg.ProtectedBranches
	gpCfg := gitpush.Config{
		Names:           pb.Names,
		BlockForcePush:  pb.BlockForcePush,
		BlockDelete:     pb.BlockDelete,
		BlockDirectPush: pb.BlockDirectPush,
	}
	for _, sc := range subcmds {
		if v := gitpush.Check(sc, cwd, gpCfg); v.Blocked {
			return v
		}
	}
	return gitpush.Verdict{}
}

// trackedAccess is one path access together with what is known about the
// working directory it is resolved against.
type trackedAccess struct {
	access pathpolicy.Access
	state  pathpolicy.CWDState
	links  []pathpolicy.Symlink
}

// trackedAccesses collects the path accesses of a command in whichever dialect
// it is written.
//
// The POSIX path is the parsed one, with the working directory followed through
// the chain and symbolic links resolved. PowerShell has no parse to work from,
// so its accesses come from ClassifyPowerShell and carry only the working
// directory the hook reported: a cd there is reported by marking the paths that
// follow it indeterminate rather than by computing where it landed.
func posixAccesses(subcmds []shellparse.Command, cwd, home string) []trackedAccess {
	cwdStates, linksBefore := pathpolicy.TrackCWD(subcmds, cwd, home)
	var out []trackedAccess
	for i, sc := range subcmds {
		for _, acc := range pathpolicy.Classify(sc) {
			out = append(out, trackedAccess{access: acc, state: cwdStates[i], links: linksBefore[i]})
		}
	}
	return out
}

// powerShellAccesses reads the paths straight out of the command text.
//
// There is no parse to follow the working directory through, so every access
// resolves against the directory the hook reported. ClassifyPowerShell reports
// a directory change by marking the relative paths after it indeterminate,
// which is the honest answer: the analysis cannot say where they landed.
func powerShellAccesses(cmd, cwd string) []trackedAccess {
	state := pathpolicy.CWDState{Path: cwd}
	var out []trackedAccess
	for _, acc := range pathpolicy.ClassifyPowerShell(cmd) {
		out = append(out, trackedAccess{access: acc, state: state})
	}
	return out
}

// checkPathAccess returns the strictest path-scope, sensitive-path, or
// protected-path result across all simple commands. It tracks CWD changes and
// both existing and pending symbolic links.
func checkPathAccess(cfg *rules.Config, accesses []trackedAccess, cwd string) (decision, reason, source, matchedBy string) {
	// Self-protection is structural and has no configuration to disable, so it
	// keeps this function alive even when every configured path check is off.
	self := selfPaths()
	if !cfg.PathScope.Enabled && !cfg.SensitivePaths.Enabled && !cfg.ProtectedPaths.Enabled && len(self) == 0 {
		return "", "", "", ""
	}

	home := paths.Home()
	root := cwd
	if cfg.PathScope.ProjectRoot != "" && cfg.PathScope.ProjectRoot != "cwd" {
		root = cfg.PathScope.ProjectRoot
	}
	root = pathpolicy.ResolvePhysical(filepath.Clean(root))
	// Without an absolute root, nothing can be shown to be inside the project.
	rootLabel := fmt.Sprintf("outside project root (%s)", root)
	if !filepath.IsAbs(root) {
		rootLabel = "outside the project root, which could not be determined"
	}

	best := 0 // 0 none, 1 ask, 2 deny
	for _, tracked := range accesses {
		acc, state, links := tracked.access, tracked.state, tracked.links
		{
			indeterminate := acc.Indeterminate || state.Indeterminate

			// Always resolved: self-protection needs the candidates even when
			// every configured path check is disabled.
			pathCandidates := []string{acc.Path}
			// An unresolved path is only ever matched as written, so the
			// spelling Win32 will actually open has to be offered too.
			if trimmed := pathpolicy.TrimHostNameDecorations(acc.Path); trimmed != acc.Path {
				pathCandidates = append(pathCandidates, trimmed)
			}
			if !indeterminate {
				rewritten := pathpolicy.RewriteThroughPending(pathpolicy.Resolve(state.Path, home, acc.Path), links)
				pathCandidates = append(pathCandidates, pathpolicy.ResolvePhysical(rewritten))
			}

			if acc.Op == pathpolicy.OpWrite || acc.Op == pathpolicy.OpDelete {
				if guarded := matchesSelf(self, pathCandidates); guarded != "" {
					if rank := decisionRank("deny"); rank > best {
						best = rank
						decision, source = "deny", "self_protection"
						reason = fmt.Sprintf("policygate's own executable (%s): %s", acc.Op, acc.Path)
						matchedBy = guarded
					}
				}
			}

			if cfg.SensitivePaths.Enabled {
				if rule := matchAny(cfg.MatchSensitive, pathCandidates); rule != nil {
					d := cfg.SensitivePaths.Policy.For(string(acc.Op))
					if rank := decisionRank(d); rank > best {
						best = rank
						decision, source, matchedBy = d, "path_policy", rule.Pattern
						reason = fmt.Sprintf("%s (%s): %s", rule.Reason, acc.Op, acc.Path)
					}
				}
			}

			if cfg.ProtectedPaths.Enabled && (acc.Op == pathpolicy.OpWrite || acc.Op == pathpolicy.OpDelete) {
				if rule := matchAny(cfg.MatchProtected, pathCandidates); rule != nil {
					if rank := decisionRank("deny"); rank > best {
						best = rank
						decision, source, matchedBy = "deny", "path_policy", rule.Pattern
						reason = fmt.Sprintf("protected path (%s): %s", acc.Op, acc.Path)
					}
				}
			}

			if !cfg.PathScope.Enabled {
				continue
			}
			// Never assume an unresolved path remains inside the project.
			outside := indeterminate
			if !indeterminate {
				rewritten := pathpolicy.RewriteThroughPending(pathpolicy.Resolve(state.Path, home, acc.Path), links)
				resolved := pathpolicy.ResolvePhysical(rewritten)
				outside = pathpolicy.IsOutside(root, resolved)
			}
			if outside && (!indeterminate || acc.Op != pathpolicy.OpRead) {
				d := cfg.PathScope.OutsideProject.For(string(acc.Op))
				if rank := decisionRank(d); rank > best {
					reasonSuffix := fmt.Sprintf("%s: %s", rootLabel, acc.Path)
					switch {
					case acc.Indeterminate:
						reasonSuffix = "path contains an unresolved expansion, treated as " + reasonSuffix
					case state.Indeterminate:
						reasonSuffix = "working directory could not be resolved, treated as " + reasonSuffix
					}
					best = rank
					decision, source, matchedBy = d, "path_policy", ""
					reason = fmt.Sprintf("%s %s", acc.Op, reasonSuffix)
				}
			}
		}
	}
	if best == 0 {
		return "", "", "", ""
	}
	return decision, reason, source, matchedBy
}

func matchAny(match func(string) *rules.Rule, candidates []string) *rules.Rule {
	for _, c := range candidates {
		if r := match(c); r != nil {
			return r
		}
	}
	return nil
}

func decisionRank(d string) int {
	switch d {
	case "deny":
		return 2
	case "ask":
		return 1
	default:
		return 0
	}
}

// loadConfig loads the user policy. A missing user policy selects the embedded
// defaults, while an explicit but invalid policy is returned as an error.
func loadConfig() (*rules.Config, string, error) {
	path := configPath()
	if path != "" {
		if cfg, warnings, err := rules.LoadWithWarnings(path); err == nil {
			for _, warning := range warnings {
				warnf("config %s: %s", path, warning)
			}
			return cfg, path, nil
		} else {
			return nil, path, fmt.Errorf("load config %s: %w", path, err)
		}
	}
	cfg, err := rules.Default()
	if err != nil {
		return nil, "built-in (broken)", fmt.Errorf("parse embedded default config: %w", err)
	}
	return cfg, "built-in default", nil
}

// configPath reports the configuration to load, or "" when the embedded
// defaults apply. paths.ConfigSource documents why an explicitly selected file
// skips the existence check.
//
// A --config on the command line wins over POLICYGATE_CONFIG: it is the more
// specific of the two, and the only one a host can be made to deliver on every
// platform.
func configPath() string {
	if p := resolveConfigFlag(); p != "" {
		return p
	}
	p, _ := paths.ConfigSource()
	return p
}

func auditPath(cfg *rules.Config) string {
	p := cfg.Audit.Path
	if p == "" {
		p = paths.DefaultAuditLog
	}
	return paths.Expand(p)
}

// resolveDialect reports the shell language a payload carries, honouring an
// explicit POLICYGATE_SHELL over the host contract.
//
// The override exists because the contract is measured behaviour, not a
// promise: it has to be correctable in the field without waiting for a release.
func resolveDialect(host, toolName string) dialect.Dialect {
	if v := os.Getenv(dialect.EnvShell); v != "" {
		if d, err := dialect.Parse(v); err == nil {
			return d
		} else {
			warnf("%s: %v (falling back to detection)", dialect.EnvShell, err)
		}
	}
	return dialect.Detect(host, toolName, runtime.GOOS)
}

// carriesShellCommand reports whether a tool hands policygate a shell command
// to evaluate.
//
// Claude Code on Windows carries commands through a PowerShell tool as well as
// a Bash one, and measuring a session found 12 PowerShell calls against 10 Bash
// ones with none of the PowerShell reaching the audit log: matching only "Bash"
// left more than half the commands unexamined. Anything else - a file edit, a
// web fetch - carries no command and is not this hook's business.
func carriesShellCommand(toolName string) bool {
	switch strings.ToLower(toolName) {
	case "bash", "powershell":
		return true
	}
	return false
}

// warnOnDialectMismatch reports text that reads as PowerShell where the host
// contract says POSIX.
//
// The text is never allowed to decide - it can be shaped at will, and letting
// it choose would hand an attacker the analysis it prefers to face. But a host
// that quietly changes what it sends would otherwise leave PowerShell being
// read as POSIX with nothing to show for it, so the disagreement is surfaced.
func warnOnDialectMismatch(shell dialect.Dialect, cmd string) {
	if shell != dialect.POSIX {
		return
	}
	if dialect.LooksLikePowerShell(maskQuotedText(cmd)) {
		warnf("command reads as PowerShell but the host contract says posix; set %s=powershell if this host has changed", dialect.EnvShell)
	}
}

// resolveConfigFlag reads a --config given on the hook command line.
//
// It exists because naming the configuration through the environment is not
// portable. The documented way to give each host its own policy wraps the
// binary in /usr/bin/env, and Windows has no such program: Codex spawns the
// command directly, fails to start it, and - measured on Windows 11 - runs the
// command anyway without a word. A gate that is registered, trusted, and
// completely inert is the worst failure this can have, so the configuration has
// to be nameable without a wrapper.
func resolveConfigFlag() string {
	for i, a := range os.Args {
		if a == "--config" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "--config="); ok {
			return v
		}
	}
	return ""
}

// resolveHost uses --host before POLICYGATE_HOST and never infers a host from payload data.
func resolveHost() string {
	for i, a := range os.Args {
		if a == "--host" && i+1 < len(os.Args) {
			return strings.ToLower(os.Args[i+1])
		}
		if v, ok := strings.CutPrefix(a, "--host="); ok {
			return strings.ToLower(v)
		}
	}
	return strings.ToLower(os.Getenv("POLICYGATE_HOST"))
}

func finalizeForHost(host string, decision hook.Decision, reason string) (hook.Decision, string) {
	if decision != hook.DecisionAsk || host == "claude" {
		return decision, reason
	}
	// The note differs by whether the host was actually named. A correctly
	// configured Codex hook converts ask to deny by design, and telling its
	// user to "pass --host claude" on every such command reads as a
	// misconfiguration report for a setup that is right. Only a host nobody
	// declared is worth suggesting a flag for.
	if host == "" {
		return hook.DecisionDeny, reason + " (no host was declared, so ask is converted to deny; pass --host claude if this hook only runs under Claude Code)"
	}
	return hook.DecisionDeny, reason + " (this host does not support a standalone ask, so it is enforced as deny)"
}

// resolveCWD falls back to the process working directory when the host omits
// the hook's working directory, so path checks keep an absolute project root.
func resolveCWD(cwd string) string {
	if cwd != "" {
		return cwd
	}
	wd, err := os.Getwd()
	if err != nil {
		warnf("hook input has no cwd and the working directory is unavailable: %v", err)
		return cwd
	}
	warnf("hook input has no cwd; using the process working directory %s", wd)
	return wd
}

func auditCommand(mode, command string) string {
	switch mode {
	case "full":
		return command
	case "hash":
		return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(command)))
	case "none":
		return ""
	default:
		return audit.Redact(command)
	}
}

func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "policygate: "+format+"\n", args...)
}
