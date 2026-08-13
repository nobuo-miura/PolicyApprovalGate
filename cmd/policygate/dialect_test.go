package main

import (
	"runtime"
	"testing"

	"github.com/nobuo-miura/policyapprovalgate/internal/dialect"
	"github.com/nobuo-miura/policyapprovalgate/internal/hook"
	"github.com/nobuo-miura/policyapprovalgate/internal/rules"
)

func TestResolveDialectFollowsTheHostContract(t *testing.T) {
	t.Setenv(dialect.EnvShell, "")

	// The contract is platform-dependent, so assert against what this platform
	// is expected to produce rather than pinning a single answer.
	want := dialect.POSIX
	if runtime.GOOS == "windows" {
		want = dialect.PowerShell
	}
	if got := resolveDialect("codex", "Bash"); got != want {
		t.Errorf("resolveDialect(codex, Bash) = %q, want %q on %s", got, want, runtime.GOOS)
	}
	if got := resolveDialect("claude", "Bash"); got != dialect.POSIX {
		t.Errorf("resolveDialect(claude, Bash) = %q, want posix", got)
	}
	// A tool named for the language settles it on any platform.
	if got := resolveDialect("claude", "PowerShell"); got != dialect.PowerShell {
		t.Errorf("resolveDialect(claude, PowerShell) = %q, want powershell", got)
	}
}

// The contract is measured behaviour rather than a promise, so it has to be
// correctable without waiting for a release.
func TestResolveDialectHonoursTheOverride(t *testing.T) {
	t.Setenv(dialect.EnvShell, "powershell")
	if got := resolveDialect("claude", "Bash"); got != dialect.PowerShell {
		t.Errorf("resolveDialect() = %q, want the override to win", got)
	}

	t.Setenv(dialect.EnvShell, "posix")
	if got := resolveDialect("claude", "PowerShell"); got != dialect.POSIX {
		t.Errorf("resolveDialect() = %q, want the override to win", got)
	}
}

// A typo must not silently select a dialect; detection stays in charge.
func TestResolveDialectIgnoresAnInvalidOverride(t *testing.T) {
	t.Setenv(dialect.EnvShell, "fish")
	if got := resolveDialect("claude", "Bash"); got != dialect.POSIX {
		t.Errorf("resolveDialect() = %q, want detection to stand", got)
	}
}

// The measured Windows payloads are the reason dialect detection exists, so
// they are the cases worth pinning.
func TestResolveDialectOnTheMeasuredWindowsPayloads(t *testing.T) {
	t.Setenv(dialect.EnvShell, "")

	cases := []struct {
		name     string
		host     string
		toolName string
		want     dialect.Dialect
	}{
		// Codex reports Bash and sends PowerShell; this is the case that made
		// tool_name unusable as a signal on its own.
		{"codex windows", "codex", "Bash", dialect.PowerShell},
		{"claude windows bash tool", "claude", "Bash", dialect.POSIX},
		{"claude windows powershell tool", "claude", "PowerShell", dialect.PowerShell},
		{"no host on windows is ambiguous", "", "Bash", dialect.Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dialect.Detect(tc.host, tc.toolName, "windows"); got != tc.want {
				t.Errorf("Detect(%q, %q, windows) = %q, want %q", tc.host, tc.toolName, got, tc.want)
			}
		})
	}
}

// evaluatePOSIX runs evaluate for the POSIX dialect, which is the language
// every command in the surrounding tests is written in. Cases that exercise
// another dialect call evaluate directly and say so.
func evaluatePOSIX(cfg *rules.Config, in hook.Input, cmd string) (hook.Decision, string, string, string) {
	return evaluate(cfg, in, cmd, dialect.POSIX)
}
