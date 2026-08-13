package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nobuo-miura/policyapprovalgate/internal/dialect"
	"github.com/nobuo-miura/policyapprovalgate/internal/hook"
	"github.com/nobuo-miura/policyapprovalgate/internal/rules"
)

// version is replaced by release builds through -ldflags.
var version = "dev"

type evaluationOutput struct {
	Decision  hook.Decision `json:"decision,omitempty"`
	Reason    string        `json:"reason"`
	Source    string        `json:"source"`
	MatchedBy string        `json:"matched_by,omitempty"`
	// Dialect names the analysis that ran, so a result can be read knowing
	// whether the command was structurally examined or only matched as text.
	Dialect string `json:"dialect,omitempty"`
}

func runEvaluate(args []string) int {
	fs := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	command := fs.String("command", "", "shell command to evaluate")
	cwd := fs.String("cwd", "", "working directory used for path checks")
	host := fs.String("host", "codex", "host behavior to apply (codex or claude)")
	tool := fs.String("tool", "Bash", "tool name the host would report, which affects dialect detection")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *command == "" {
		fmt.Fprintln(os.Stderr, "policygate evaluate: --command is required")
		return 2
	}
	if *cwd == "" {
		var err error
		*cwd, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "policygate evaluate: resolve cwd: %v\n", err)
			return 1
		}
	}
	cfg, _, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "policygate evaluate: %v\n", err)
		return 1
	}
	in := hook.Input{ToolName: *tool, CWD: *cwd, ToolInput: hook.ToolInput{Command: *command}}
	shell := resolveDialect(*host, *tool)
	warnOnDialectMismatch(shell, *command)
	decision, reason, source, matchedBy := evaluate(cfg, in, *command, shell)
	decision, reason = finalizeForHost(*host, decision, reason)
	out := evaluationOutput{decision, reason, source, matchedBy, string(shell)}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "policygate evaluate: encode result: %v\n", err)
		return 1
	}
	return 0
}

func runCheckConfig(args []string) int {
	fs := flag.NewFlagSet("check-config", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := fs.String("config", configPath(), "configuration file to validate")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(os.Stderr, "policygate check-config: no configuration file found")
		return 1
	}
	cfg, warnings, err := rules.LoadWithWarnings(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policygate check-config: %v\n", err)
		return 1
	}
	for _, warning := range warnings {
		fmt.Printf("warning: %s\n", warning)
	}
	if warning := fallbackAskWarning(cfg); warning != "" {
		fmt.Printf("warning: %s\n", warning)
	}
	if warning := unanalyzedAskWarning(cfg); warning != "" {
		fmt.Printf("warning: %s\n", warning)
	}
	if warning := staleRulesWarning(cfg); warning != "" {
		fmt.Printf("warning: %s\n", warning)
	}
	fmt.Printf("ok: %s (schema v%d, mode %s)\n", *path, cfg.Version, cfg.Mode)
	return 0
}

// fallbackAskWarning reports fallback actions set to ask, which only Claude
// Code enforces. Every other host converts ask to deny, so such a fallback
// rejects each command that reaches it instead of asking for confirmation.
//
// The warning is deliberately host-neutral: neither check-config nor doctor
// accepts --host, so neither can tell which host the registered hook runs
// under, and a host-specific verdict would misreport a correct setup.
func fallbackAskWarning(cfg *rules.Config) string {
	var sections []string
	if cfg.Unknown.Action == "ask" {
		sections = append(sections, "unknown.action")
	}
	if cfg.ParseError.Action == "ask" {
		sections = append(sections, "parse_error.action")
	}
	if len(sections) == 0 {
		return ""
	}
	return fmt.Sprintf("%s: ask is preserved only when the resolved host is Claude (--host claude or POLICYGATE_HOST=claude); every other host converts it to deny and rejects each command that reaches the fallback",
		strings.Join(sections, " and "))
}

// staleRulesWarning reports built-in rules the configuration no longer carries.
//
// A user configuration replaces a rule list wholesale, so one written before a
// release never receives the rules that release added. Nothing else says so:
// the gate loads, reports no error, and enforces less than the documentation
// describes. Silence there is the failure this whole project exists to avoid.
func staleRulesWarning(cfg *rules.Config) string {
	missing, err := cfg.MissingDefaultRules()
	if err != nil || len(missing) == 0 {
		return ""
	}
	sections := make([]string, 0, len(missing))
	for _, name := range []string{"deny", "sensitive_paths.patterns", "protected_paths.patterns"} {
		if count, ok := missing[name]; ok {
			sections = append(sections, fmt.Sprintf("%s (%d)", name, count))
		}
	}
	return fmt.Sprintf("this configuration is missing built-in rules added since it was written: %s; run `policygate init --upgrade` to merge them, then review the warnings it prints",
		strings.Join(sections, ", "))
}

// unanalyzedAskWarning reports the shipped default, which is safe on Claude
// Code and unusable on Codex under Windows.
//
// Both are legitimate settings, so this describes the consequence rather than
// prescribing a value. It stays host-neutral for the same reason
// fallbackAskWarning does: neither check-config nor doctor accepts --host, so
// neither can tell which host the registered hook runs under.
func unanalyzedAskWarning(cfg *rules.Config) string {
	var sections []string
	if cfg.Unknown.UnanalyzedAction == "ask" {
		sections = append(sections, "unknown.unanalyzed_action")
	}
	if cfg.ParseError.UnanalyzedAction == "ask" {
		sections = append(sections, "parse_error.unanalyzed_action")
	}
	if len(sections) == 0 {
		return ""
	}
	return fmt.Sprintf("%s: Codex sends PowerShell for every command on Windows and converts ask to deny, which would reject ordinary work there; give Codex its own file through POLICYGATE_CONFIG with unanalyzed_action: defer, understanding that PowerShell is then matched as text only",
		strings.Join(sections, " and "))
}

func runDoctor(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: policygate doctor")
		return 2
	}
	failures := 0
	fmt.Printf("policygate %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	path := configPath()
	if path == "" {
		fmt.Println("config: built-in default")
	} else if cfg, warnings, err := rules.LoadWithWarnings(path); err != nil {
		fmt.Printf("config: error: %v\n", err)
		failures++
	} else {
		fmt.Printf("config: ok (%s, schema v%d, mode %s)\n", path, cfg.Version, cfg.Mode)
		for _, warning := range warnings {
			fmt.Printf("config warning: %s\n", warning)
		}
		if warning := fallbackAskWarning(cfg); warning != "" {
			fmt.Printf("config warning: %s\n", warning)
		}
		if warning := unanalyzedAskWarning(cfg); warning != "" {
			fmt.Printf("config warning: %s\n", warning)
		}
		if warning := staleRulesWarning(cfg); warning != "" {
			fmt.Printf("config warning: %s\n", warning)
		}
	}
	if exe, err := os.Executable(); err == nil {
		fmt.Printf("binary: %s\n", exe)
	}
	// Self-protection depends on resolving this process's own path, so report
	// what it actually guards rather than leaving it to be assumed.
	if guarded := selfPaths(); len(guarded) == 0 {
		fmt.Println("self-protection: inactive (own path could not be resolved)")
	} else {
		fmt.Printf("self-protection: %s\n", strings.Join(guarded, ", "))
	}
	host := resolveHost()
	fmt.Printf("host: %s\n", host)
	// The dialect follows from the host and the platform, so a misconfigured
	// --host silently changes which analysis runs. Show the result.
	shell := resolveDialect(host, "Bash")
	fmt.Printf("shell dialect: %s (structural analysis: %t)\n", shell, shell.Analyzable())
	if shell != dialect.POSIX {
		fmt.Println("shell warning: this host sends a dialect policygate cannot analyze structurally; only text rules apply")
	}
	if failures != 0 {
		return 1
	}
	return 0
}

func writeConfigAtomically(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".policygate-config-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
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
	return os.Rename(tmpPath, path)
}

func writeConfigBackup(path string, data []byte) (string, error) {
	backup, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".bak.*")
	if err != nil {
		return "", err
	}
	backupPath := backup.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(backupPath)
		}
	}()
	if err := backup.Chmod(0o600); err != nil {
		_ = backup.Close()
		return "", err
	}
	if _, err := backup.Write(data); err != nil {
		_ = backup.Close()
		return "", err
	}
	if err := backup.Sync(); err != nil {
		_ = backup.Close()
		return "", err
	}
	if err := backup.Close(); err != nil {
		return "", err
	}
	keep = true
	return backupPath, nil
}
