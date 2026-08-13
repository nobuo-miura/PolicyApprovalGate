package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nobuo-miura/policyapprovalgate/internal/hook"
)

// everyPathCheckOffYAML disables every configurable path check, so anything
// still denied under it is structural.
const everyPathCheckOffYAML = `
deny: []
ask: []
allow: []
path_scope:
  enabled: false
sensitive_paths:
  enabled: false
protected_paths:
  enabled: false
audit:
  enabled: false
`

// guardSelf points self-protection at a fixture instead of the test binary, so
// the tests never name a path they might really write to.
func guardSelf(t *testing.T, guarded ...string) {
	t.Helper()
	previous := selfPaths
	selfPaths = func() []string { return guarded }
	t.Cleanup(func() { selfPaths = previous })
}

// The gate must not be disarmed by editing the policy it reads, so protecting
// the binary cannot depend on a configuration switch.
func TestSelfProtectionSurvivesEveryPathCheckBeingDisabled(t *testing.T) {
	cfg := mustConfig(t, everyPathCheckOffYAML)
	guardSelf(t, "/opt/homebrew/bin/policygate")
	in := hook.Input{ToolName: "Bash", CWD: t.TempDir()}

	cases := []string{
		"rm -f /opt/homebrew/bin/policygate",
		"echo x > /opt/homebrew/bin/policygate",
		"cp evil /opt/homebrew/bin/policygate",
		"install -m 0755 evil /opt/homebrew/bin/policygate",
		`sh -c "rm -f /opt/homebrew/bin/policygate"`,
		"env rm -f /opt/homebrew/bin/policygate",
	}
	for _, cmd := range cases {
		decision, reason, source, _ := evaluatePOSIX(cfg, in, cmd)
		if decision != hook.DecisionDeny || source != "self_protection" {
			t.Errorf("evaluate(%q) = %q/%q (%s), want deny/self_protection", cmd, decision, source, reason)
		}
	}
}

// Naming the binary relative to an earlier cd only resolves when the directory
// really exists, so this case needs a real one. Hard-coding an install path
// made it pass on a Mac with Homebrew and fail everywhere else.
func TestSelfProtectionFollowsAnEarlierCd(t *testing.T) {
	cfg := mustConfig(t, everyPathCheckOffYAML)

	dir := t.TempDir()
	// Guard both spellings, as resolveSelfPaths does: on macOS the temp
	// directory is reached through a symlink, and only the resolved form
	// matches a path the analyzer has resolved.
	physical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	name := "policygate"
	if runtime.GOOS == "windows" {
		name = "policygate.exe"
	}
	logical := filepath.ToSlash(dir) + "/" + name
	guardSelf(t, logical, filepath.ToSlash(physical)+"/"+name)

	in := hook.Input{ToolName: "Bash", CWD: t.TempDir()}
	cmd := fmt.Sprintf("cd %s && rm -f %s", filepath.ToSlash(dir), name)
	if decision, reason, source, _ := evaluatePOSIX(cfg, in, cmd); decision != hook.DecisionDeny || source != "self_protection" {
		t.Errorf("evaluate(%q) = %q/%q (%s), want deny/self_protection", cmd, decision, source, reason)
	}
}

// Replacing the symlink a hook registration names redirects the gate just as
// effectively as overwriting the file behind it, so both are guarded.
func TestSelfProtectionCoversInvocationPathAndTarget(t *testing.T) {
	cfg := mustConfig(t, everyPathCheckOffYAML)
	guardSelf(t, "/opt/homebrew/bin/policygate", "/opt/homebrew/Cellar/policygate/1.0.0/bin/policygate")
	in := hook.Input{ToolName: "Bash", CWD: t.TempDir()}

	for _, cmd := range []string{
		"rm -f /opt/homebrew/bin/policygate",
		"rm -f /opt/homebrew/Cellar/policygate/1.0.0/bin/policygate",
	} {
		if decision, _, source, _ := evaluatePOSIX(cfg, in, cmd); decision != hook.DecisionDeny || source != "self_protection" {
			t.Errorf("evaluate(%q) = %q/%q, want deny/self_protection", cmd, decision, source)
		}
	}
}

// A filesystem that ignores case opens the same binary for a different
// spelling, so the guard has to recognize it.
func TestSelfProtectionIgnoresCase(t *testing.T) {
	cfg := mustConfig(t, everyPathCheckOffYAML)
	guardSelf(t, "/opt/homebrew/bin/policygate")
	in := hook.Input{ToolName: "Bash", CWD: t.TempDir()}

	if decision, _, source, _ := evaluatePOSIX(cfg, in, "rm -f /opt/Homebrew/bin/POLICYGATE"); decision != hook.DecisionDeny || source != "self_protection" {
		t.Errorf("decision=%q source=%q, want deny/self_protection", decision, source)
	}
}

// Reading the binary discloses nothing the user cannot already read, and
// denying it would break ordinary inspection such as checksum verification.
func TestSelfProtectionAllowsReads(t *testing.T) {
	cfg := mustConfig(t, everyPathCheckOffYAML)
	guardSelf(t, "/opt/homebrew/bin/policygate")
	in := hook.Input{ToolName: "Bash", CWD: t.TempDir()}

	for _, cmd := range []string{
		"cat /opt/homebrew/bin/policygate",
		"shasum -a 256 /opt/homebrew/bin/policygate",
	} {
		if decision, _, source, _ := evaluatePOSIX(cfg, in, cmd); decision == hook.DecisionDeny {
			t.Errorf("evaluate(%q) = deny (%s), want the read to pass", cmd, source)
		}
	}
}

// Neighbours in the same directory are not the binary.
func TestSelfProtectionDoesNotOverreach(t *testing.T) {
	cfg := mustConfig(t, everyPathCheckOffYAML)
	guardSelf(t, "/opt/homebrew/bin/policygate")
	in := hook.Input{ToolName: "Bash", CWD: t.TempDir()}

	for _, cmd := range []string{
		"rm -f /opt/homebrew/bin/policygate-old",
		"rm -f /opt/homebrew/bin/other",
		"rm -f /opt/homebrew/bin",
	} {
		if decision, _, source, _ := evaluatePOSIX(cfg, in, cmd); source == "self_protection" {
			t.Errorf("evaluate(%q) = %q/self_protection, want no self-protection match", cmd, decision)
		}
	}
}

// Failing to resolve the executable disables the guard rather than the gate.
func TestSelfProtectionInactiveWithoutAResolvedPath(t *testing.T) {
	cfg := mustConfig(t, everyPathCheckOffYAML)
	guardSelf(t)
	in := hook.Input{ToolName: "Bash", CWD: t.TempDir()}

	if decision, _, source, _ := evaluatePOSIX(cfg, in, "rm -f /opt/homebrew/bin/policygate"); source == "self_protection" {
		t.Errorf("decision=%q source=%q, want no self-protection without a resolved path", decision, source)
	}
}

// The configured path rules must keep working alongside the structural guard.
func TestSelfProtectionLeavesConfiguredRulesIntact(t *testing.T) {
	cfg := mustConfig(t, protectedPathsYAML)
	guardSelf(t, "/opt/homebrew/bin/policygate")
	dir := t.TempDir()
	in := hook.Input{ToolName: "Bash", CWD: dir}

	if decision, _, source, _ := evaluatePOSIX(cfg, in, "rm -f .claude/settings.json"); decision != hook.DecisionDeny || source != "path_policy" {
		t.Errorf("decision=%q source=%q, want deny/path_policy", decision, source)
	}
}

func TestResolveSelfPathsReportsCleanForwardSlashForm(t *testing.T) {
	got := normalizeSelfPath(filepath.Join("/opt", "homebrew", "bin", "..", "bin", "policygate"))
	if got != "/opt/homebrew/bin/policygate" {
		t.Errorf("normalizeSelfPath() = %q, want %q", got, "/opt/homebrew/bin/policygate")
	}
}
