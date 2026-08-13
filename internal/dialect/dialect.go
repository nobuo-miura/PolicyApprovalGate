// Package dialect identifies the shell language a hook payload carries.
//
// The command text alone does not say which language it is written in, and
// neither does the tool that carried it: Codex on Windows reports tool_name
// "Bash" and sends PowerShell. Getting this wrong is not a cosmetic problem.
// PowerShell mostly parses as POSIX rather than failing, so an unrecognized
// cmdlet reaches the unknown fallback and is deferred as if it had been
// examined and found ordinary.
package dialect

import (
	"fmt"
	"regexp"
	"strings"
)

// Dialect is the shell language a command is written in.
type Dialect string

const (
	// POSIX is the language mvdan.cc/sh parses and internal/pathpolicy
	// classifies.
	POSIX Dialect = "posix"

	// PowerShell carries cmdlets that the POSIX analysis cannot classify.
	PowerShell Dialect = "powershell"

	// Unknown means the payload gave no reliable signal. Callers treat it the
	// way they treat PowerShell: analyzable only as text.
	Unknown Dialect = "unknown"
)

// Analyzable reports whether the POSIX structural analysis understands this
// dialect well enough for a non-match to mean anything.
//
// A non-POSIX command is still worth analyzing - `git push --force origin main`
// and `cat ~/.ssh/id_rsa` read the same in both languages, and the existing
// checks catch them. What changes is the meaning of silence: for POSIX, no
// match means the command was examined and nothing applied; for anything else,
// it means the command may simply not have been understood.
func (d Dialect) Analyzable() bool { return d == POSIX }

// EnvShell overrides the detected dialect.
const EnvShell = "POLICYGATE_SHELL"

// Parse reads an explicit dialect selection.
func Parse(s string) (Dialect, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(POSIX), "bash", "sh":
		return POSIX, nil
	case string(PowerShell), "pwsh", "ps":
		return PowerShell, nil
	default:
		return "", fmt.Errorf("unknown shell %q: use posix or powershell", s)
	}
}

// Detect reports the dialect a payload carries.
//
// The rules come from measuring both hosts on Windows 11 (2026-08-13); see
// cmd/policygate/testdata/*-windows*.json for the payloads they are drawn from.
//
//	host    tool_name     GOOS      dialect
//	claude  PowerShell    windows   powershell   (a tool of its own)
//	claude  Bash          any       posix        (routed through Git Bash)
//	codex   Bash          windows   powershell   (reports Bash, sends PowerShell)
//	codex   Bash          other     posix
//	(none)  Bash          windows   unknown      (either of the two above)
//
// Because this table tracks host behaviour rather than anything guaranteed, an
// explicit POLICYGATE_SHELL has to be able to override it.
func Detect(host, toolName, goos string) Dialect {
	// A tool named for the language settles it on any platform.
	if strings.EqualFold(toolName, "PowerShell") {
		return PowerShell
	}
	if !strings.EqualFold(goos, "windows") {
		// No host runs PowerShell as its shell tool off Windows, and one that
		// did would have to name the tool for it.
		return POSIX
	}
	switch strings.ToLower(host) {
	case "claude":
		return POSIX
	case "codex":
		return PowerShell
	}
	// On Windows the host decides, so without one the payload is ambiguous.
	return Unknown
}

// cmdletAtCommandPosition matches a Verb-Noun cmdlet where a command may start:
// the beginning of the text, or just after a separator or a pipe. Anchoring it
// keeps a hyphenated word in an argument or a message - a Content-Type header,
// or "add Select-Object examples" in a commit message - from reading as
// PowerShell.
var cmdletAtCommandPosition = regexp.MustCompile(`(?:^|[;&|(])\s*[A-Z][a-zA-Z]+-[A-Z][a-zA-Z]+\b`)

// powerShellOnlySyntax lists constructs with no POSIX reading and no plausible
// appearance in ordinary prose. Cmdlet names are deliberately absent: they are
// matched only at a command position, above.
var powerShellOnlySyntax = regexp.MustCompile(`\$env:|\$PSVersionTable\b`)

// LooksLikePowerShell reports whether the text carries PowerShell syntax.
//
// This is a cross-check, never the decision. Detect keys off the host contract,
// which is reliable; text can be made to look like anything, so believing it
// would hand an attacker the choice of which analysis to face. Callers use a
// disagreement to warn that the host contract may have moved.
//
// A warning that fires on ordinary POSIX teaches people to ignore it, so the
// patterns are anchored to a command position. Callers should pass text with
// quoted content masked, the same way deny rules are matched, so a separator
// inside a message cannot create a command position that is not there.
func LooksLikePowerShell(command string) bool {
	return cmdletAtCommandPosition.MatchString(command) || powerShellOnlySyntax.MatchString(command)
}
