package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

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
}

func runEvaluate(args []string) int {
	fs := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	command := fs.String("command", "", "shell command to evaluate")
	cwd := fs.String("cwd", "", "working directory used for path checks")
	host := fs.String("host", "codex", "host behavior to apply (codex or claude)")
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
	in := hook.Input{ToolName: "Bash", CWD: *cwd, ToolInput: hook.ToolInput{Command: *command}}
	decision, reason, source, matchedBy := evaluate(cfg, in, *command)
	decision, reason = finalizeForHost(*host, decision, reason)
	if err := json.NewEncoder(os.Stdout).Encode(evaluationOutput{decision, reason, source, matchedBy}); err != nil {
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
	}
	if exe, err := os.Executable(); err == nil {
		fmt.Printf("binary: %s\n", exe)
	}
	fmt.Printf("host: %s\n", resolveHost())
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
