package pathpolicy

import (
	"strings"
)

// PowerShell path extraction.
//
// The POSIX analysis in this package cannot be reused here: there is no
// PowerShell parser to hand it a command from, and a cmdlet names its paths
// through parameters rather than by position alone. Without extraction the path
// rules have nothing to match against - sensitive_paths never sees the .ssh in
// `Get-Content -LiteralPath $HOME\.ssh\id_rsa`, and the command passes as
// though it had been examined.
//
// What follows is a tokenizer and a parameter walk, not a parser. Anything it
// cannot account for is reported as indeterminate so the caller can treat it as
// unexamined rather than as safe.

// psRead lists cmdlets whose paths are read, with the aliases Windows
// PowerShell defines for them. The alias tables were read off a Windows 11 host
// with Get-Alias; PowerShell Core on Unix deliberately omits the ones that
// would shadow native commands, so they cannot be checked there.
var psRead = map[string]bool{
	"get-content": true, "gc": true, "cat": true, "type": true,
	"get-childitem": true, "gci": true, "ls": true, "dir": true,
	"get-item": true, "gi": true,
	"import-csv": true, "select-string": true, "sls": true,
	"get-filehash": true, "resolve-path": true, "test-path": true,
}

// psWrite lists cmdlets whose paths are created or modified.
var psWrite = map[string]bool{
	"set-content": true, "sc": true,
	"add-content": true, "ac": true,
	"out-file": true, "new-item": true, "ni": true,
	"copy-item": true, "cpi": true, "copy": true, "cp": true,
	"move-item": true, "mi": true, "move": true, "mv": true,
	"rename-item": true, "rni": true, "ren": true,
	"set-itemproperty": true, "new-itemproperty": true,
	"export-csv": true, "set-acl": true,
}

// psDelete lists cmdlets whose paths are deleted. Every alias here was
// confirmed against Get-Alias -Definition Remove-Item.
var psDelete = map[string]bool{
	"remove-item": true, "ri": true, "rm": true,
	"del": true, "erase": true, "rd": true, "rmdir": true,
	"clear-content": true, "clc": true,
	"remove-itemproperty": true,
}

// psPathParameters names the parameters that carry a path.
//
// Matching is by prefix rather than by exact name, because PowerShell accepts
// any unambiguous abbreviation: -LiteralPath answers to -l, and a rule written
// for the full spelling would be one keystroke from useless. Over-matching a
// parameter that merely starts the same way costs a path that is examined
// unnecessarily, which is the harmless direction.
var psPathParameters = []string{
	"path", "literalpath", "destination", "outfile", "filepath",
	"newname", "target", "outputfile", "append",
}

// psSetLocation lists the cmdlets that change the working directory. Their
// presence makes every later path indeterminate, since resolving against a
// directory this analysis cannot compute would be a guess.
var psSetLocation = map[string]bool{
	"set-location": true, "sl": true, "cd": true, "chdir": true,
	"push-location": true, "pushd": true,
	"pop-location": true, "popd": true,
}

// ClassifyPowerShell extracts the path accesses of a PowerShell command.
//
// Paths are returned as written. Resolving them against a working directory is
// the caller's job, exactly as it is for the POSIX classifier.
func ClassifyPowerShell(command string) []Access {
	var out []Access
	directoryChanged := false

	for _, segment := range splitPowerShellSegments(command) {
		tokens := tokenizePowerShell(segment)
		if len(tokens) == 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(tokens[0].text, ".exe"))
		if psSetLocation[name] {
			// A later relative path would have to be resolved against a
			// directory this analysis cannot compute.
			directoryChanged = true
			continue
		}

		op, ok := powerShellOp(name)
		if !ok {
			continue
		}
		for _, access := range powerShellPaths(tokens[1:], op) {
			if directoryChanged && !isPowerShellAbsPath(access.Path) {
				access.Indeterminate = true
			}
			out = append(out, access)
		}
	}
	return out
}

// NormalizeWindowsPath rewrites a Windows path into the form the rest of this
// package works in: forward slashes, with the user profile written as ~.
//
// Without it the path rules cannot match. Their patterns are written with
// forward slashes - `(^|/)\.ssh(/|$)` - so `$HOME\.ssh` matches nothing at all,
// and the command reads as though it touched no sensitive path. filepath.ToSlash
// is no help because it converts nothing on a Unix host, and this analysis runs
// on Linux and macOS as well as on Windows.
func NormalizeWindowsPath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = stripExtendedLengthPrefix(p)
	// Rewrite the roots spelled as variables into the ~ form Resolve already
	// expands, rather than teaching it several more spellings.
	for _, prefix := range []string{"$env:userprofile", "$home", "%userprofile%", "%homepath%"} {
		if len(p) >= len(prefix) && strings.EqualFold(p[:len(prefix)], prefix) {
			p = "~" + p[len(prefix):]
			break
		}
	}
	// C:name refers to that name under the working directory Windows keeps for
	// drive C. Where it lands is unknowable here - ClassifyPowerShell marks it
	// indeterminate for that reason - but the name it opens is plain, and the
	// path rules match on the name. Leaving the prefix on would hide `.env`
	// behind a `C:` that no pattern anchored to a separator can see past.
	if isDriveRelative(p) {
		p = p[2:]
	}
	return trimWindowsNameDecorations(p)
}

// stripExtendedLengthPrefix removes the \\?\ form, which names the same file
// while defeating a comparison against the plain spelling.
func stripExtendedLengthPrefix(p string) string {
	const unc = "//?/UNC/"
	if len(p) >= len(unc) && strings.EqualFold(p[:len(unc)], unc) {
		return "//" + p[len(unc):]
	}
	if strings.HasPrefix(p, "//?/") {
		return p[len("//?/"):]
	}
	return p
}

// trimWindowsNameDecorations removes what Win32 ignores when it opens a file.
//
// A trailing dot or space is dropped on the way to the filesystem, so `.env.`
// and `.env ` both open `.env` while matching no rule written for it - one
// character is enough to walk a secret past sensitive_paths. An alternate data
// stream suffix is cut for the same reason: `.env:hidden` names a stream of the
// very file the rules guard, and the guarded name has to be what is matched.
func trimWindowsNameDecorations(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		// A relative marker is a name in its own right and must survive.
		if part == "." || part == ".." || part == "" {
			continue
		}
		if i == len(parts)-1 {
			part = stripDataStream(part, i == 0)
		}
		trimmed := strings.TrimRight(part, ". ")
		// Trimming must not erase a component entirely.
		if trimmed != "" {
			part = trimmed
		}
		parts[i] = part
	}
	// A trailing separator names the same directory and would otherwise leave
	// an empty component that no pattern anchored to $ can match.
	for len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, "/")
}

// stripDataStream cuts a file:stream suffix, leaving a drive specification
// alone: the colon in C:/x separates a drive, not a stream.
func stripDataStream(component string, first bool) string {
	colon := strings.Index(component, ":")
	if colon < 0 {
		return component
	}
	if first && colon == 1 {
		// A leading drive letter. Anything after a second colon is a stream.
		if next := strings.Index(component[2:], ":"); next >= 0 {
			return component[:2+next]
		}
		return component
	}
	return component[:colon]
}

// isDriveRelative reports the C:name form, which resolves against the working
// directory Windows keeps per drive.
//
// That directory is not the one the hook reported and cannot be computed here,
// so the path is unresolvable rather than relative to anything known - and
// left unmarked it would read as the harmless-looking name after the colon.
func isDriveRelative(p string) bool {
	if len(p) < 3 || p[1] != ':' {
		return false
	}
	c := p[0] | 0x20 // fold to lower case
	if c < 'a' || c > 'z' {
		return false
	}
	return p[2] != '/' && p[2] != '\\'
}

// isPowerShellAbsPath decides by how a path is spelled rather than by the
// host's rules. filepath.IsAbs answers for the platform this process runs on,
// which would make a Windows path look relative when the analysis runs anywhere
// else - and this classifier is exercised from a Mac and a Linux CI runner as
// well as from Windows.
func isPowerShellAbsPath(p string) bool {
	if isAbsPath(p) {
		return true
	}
	if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//") {
		return true // UNC
	}
	// The two roots PowerShell writes as variables expand to absolute paths.
	lower := strings.ToLower(p)
	if strings.HasPrefix(lower, "$home") || strings.HasPrefix(lower, "$env:userprofile") {
		return true
	}
	if len(p) >= 2 && p[1] == ':' {
		c := p[0] | 0x20 // fold to lower case
		return c >= 'a' && c <= 'z'
	}
	return false
}

func powerShellOp(name string) (Op, bool) {
	switch {
	case psDelete[name]:
		return OpDelete, true
	case psWrite[name]:
		return OpWrite, true
	case psRead[name]:
		return OpRead, true
	}
	return "", false
}

// powerShellPaths walks a cmdlet's arguments, taking the value of any
// path-carrying parameter and, failing that, the first positional argument.
// Nearly every cmdlet here binds its first position to -Path.
func powerShellPaths(args []psToken, op Op) []Access {
	var out []Access
	positionalTaken := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !arg.quoted && strings.HasPrefix(arg.text, "-") {
			if !isPowerShellPathParameter(arg.text) {
				continue
			}
			// A switch at the end of the command has no value to take.
			if i+1 >= len(args) {
				continue
			}
			i++
			out = append(out, powerShellValues(args[i], op)...)
			positionalTaken = true
			continue
		}
		if positionalTaken {
			continue
		}
		out = append(out, powerShellValues(arg, op)...)
		positionalTaken = true
	}
	return out
}

func isPowerShellPathParameter(arg string) bool {
	name := strings.ToLower(strings.TrimLeft(arg, "-"))
	if name == "" {
		return false
	}
	// A parameter binds to any full name it is an unambiguous prefix of.
	for _, full := range psPathParameters {
		if strings.HasPrefix(full, name) {
			return true
		}
	}
	return false
}

// powerShellValues splits a comma-separated list, which PowerShell reads as an
// array, and reports whether each element can be pinned down.
func powerShellValues(token psToken, op Op) []Access {
	var out []Access
	for _, value := range strings.Split(token.text, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, Access{
			Path: NormalizeWindowsPath(value),
			Op:   op,
			// A value built from a variable or a subexpression is not a path
			// this analysis can resolve. $HOME and $env:USERPROFILE are the
			// exceptions the caller expands, so they stay determinate.
			Indeterminate: powerShellValueIsIndeterminate(value),
		})
	}
	return out
}

func powerShellValueIsIndeterminate(value string) bool {
	if strings.Contains(value, "$(") || strings.Contains(value, "`") {
		return true
	}
	if isDriveRelative(value) {
		return true
	}
	lower := strings.ToLower(value)
	for _, known := range []string{"$home", "$env:userprofile", "$pwd"} {
		lower = strings.ReplaceAll(lower, known, "")
	}
	return strings.Contains(lower, "$")
}

// psToken is one argument, with whether it arrived quoted. A quoted token that
// begins with a dash is a value, not a parameter.
type psToken struct {
	text   string
	quoted bool
}

// splitPowerShellSegments breaks a command at statement and pipeline
// separators, so each cmdlet is examined with only its own arguments.
//
// A pipeline boundary matters for a second reason: a cmdlet reading its input
// from the pipe has no path argument to find, and the paths belong to whatever
// produced that input.
func splitPowerShellSegments(command string) []string {
	var segments []string
	var current strings.Builder
	var quote rune

	flush := func() {
		if s := strings.TrimSpace(current.String()); s != "" {
			segments = append(segments, s)
		}
		current.Reset()
	}
	for _, r := range command {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
			current.WriteRune(r)
		case r == '\'' || r == '"':
			quote = r
			current.WriteRune(r)
		case r == ';' || r == '|' || r == '&' || r == '(' || r == ')' || r == '{' || r == '}' || r == '\n':
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return segments
}

// tokenizePowerShell splits a segment into arguments, honouring quotes. It is
// not a PowerShell parser and does not try to be; it recovers the shape a
// cmdlet invocation has in practice.
func tokenizePowerShell(segment string) []psToken {
	var tokens []psToken
	var current strings.Builder
	var quote rune
	quoted := false

	flush := func() {
		if current.Len() > 0 || quoted {
			tokens = append(tokens, psToken{text: current.String(), quoted: quoted})
		}
		current.Reset()
		quoted = false
	}
	for _, r := range segment {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			current.WriteRune(r)
		case r == '\'' || r == '"':
			quote = r
			quoted = true
		case r == ' ' || r == '\t' || r == '=':
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return tokens
}
