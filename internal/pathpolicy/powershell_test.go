package pathpolicy

import "testing"

func accessesOf(t *testing.T, command string) []Access {
	t.Helper()
	return ClassifyPowerShell(command)
}

// The cases that started this: measured on Windows, every one of them passed
// through policygate untouched because no path was extracted.
func TestClassifyPowerShellExtractsTheMeasuredCases(t *testing.T) {
	cases := []struct {
		command string
		path    string
		op      Op
	}{
		{`Get-ChildItem $HOME\.ssh`, `~/.ssh`, OpRead},
		{`Get-Content -LiteralPath $HOME\.ssh\id_rsa`, `~/.ssh/id_rsa`, OpRead},
		{`Get-Content -LiteralPath .\.env`, `./.env`, OpRead},
		{`Remove-Item -LiteralPath $HOME\.ssh -Recurse -Force`, `~/.ssh`, OpDelete},
		{`Remove-Item -Recurse -Force C:\temp\x`, `C:/temp/x`, OpDelete},
		{`Set-Content -Path .\.env -Value x`, `./.env`, OpWrite},
	}
	for _, tc := range cases {
		got := accessesOf(t, tc.command)
		if len(got) != 1 {
			t.Errorf("ClassifyPowerShell(%q) = %+v, want one access", tc.command, got)
			continue
		}
		if got[0].Path != tc.path || got[0].Op != tc.op {
			t.Errorf("ClassifyPowerShell(%q) = %+v, want %q/%s", tc.command, got[0], tc.path, tc.op)
		}
		if got[0].Indeterminate {
			t.Errorf("ClassifyPowerShell(%q) reported an indeterminate path", tc.command)
		}
	}
}

// PowerShell binds a parameter to any full name it is an unambiguous prefix of,
// so -l reaches -LiteralPath. A rule written for the full spelling would be one
// keystroke from useless.
func TestClassifyPowerShellFollowsAbbreviatedParameters(t *testing.T) {
	for _, cmd := range []string{
		`Get-Content -LiteralPath $HOME\.ssh\id_rsa`,
		`Get-Content -Literal $HOME\.ssh\id_rsa`,
		`Get-Content -lit $HOME\.ssh\id_rsa`,
		`Get-Content -l $HOME\.ssh\id_rsa`,
		`Get-Content -Path $HOME\.ssh\id_rsa`,
		`Get-Content -pa $HOME\.ssh\id_rsa`,
	} {
		got := accessesOf(t, cmd)
		if len(got) != 1 || got[0].Path != `~/.ssh/id_rsa` {
			t.Errorf("ClassifyPowerShell(%q) = %+v", cmd, got)
		}
	}
}

func TestClassifyPowerShellHandlesAliasesAndCase(t *testing.T) {
	cases := []struct {
		command string
		op      Op
	}{
		{`gc .env`, OpRead},
		{`cat .env`, OpRead},
		{`type .env`, OpRead},
		{`ls .ssh`, OpRead},
		{`dir .ssh`, OpRead},
		{`gci .ssh`, OpRead},
		{`rm .env`, OpDelete},
		{`del .env`, OpDelete},
		{`ri .env`, OpDelete},
		{`REMOVE-ITEM .env`, OpDelete},
		{`Get-CONTENT .env`, OpRead},
	}
	for _, tc := range cases {
		got := accessesOf(t, tc.command)
		if len(got) != 1 || got[0].Op != tc.op {
			t.Errorf("ClassifyPowerShell(%q) = %+v, want one %s", tc.command, got, tc.op)
		}
	}
}

func TestClassifyPowerShellHandlesQuotingAndArrays(t *testing.T) {
	got := accessesOf(t, `Remove-Item -LiteralPath 'C:\Program Files\app'`)
	if len(got) != 1 || got[0].Path != `C:/Program Files/app` {
		t.Errorf("quoted path = %+v", got)
	}
	// A quoted value beginning with a dash is a value, not a parameter.
	got = accessesOf(t, `Get-Content -Path "-weird-name.txt"`)
	if len(got) != 1 || got[0].Path != "-weird-name.txt" {
		t.Errorf("quoted dashed value = %+v", got)
	}
	// PowerShell reads a comma-separated value as an array.
	got = accessesOf(t, `Remove-Item a.txt,b.txt`)
	if len(got) != 2 || got[0].Path != "a.txt" || got[1].Path != "b.txt" {
		t.Errorf("array value = %+v", got)
	}
}

// Every cmdlet in a chain is examined, and each with only its own arguments.
func TestClassifyPowerShellSplitsStatements(t *testing.T) {
	got := accessesOf(t, `Get-Content readme.txt; Remove-Item .env; Set-Content out.txt -Value x`)
	if len(got) != 3 {
		t.Fatalf("ClassifyPowerShell() = %+v, want three accesses", got)
	}
	want := []struct {
		path string
		op   Op
	}{{"readme.txt", OpRead}, {".env", OpDelete}, {"out.txt", OpWrite}}
	for i, w := range want {
		if got[i].Path != w.path || got[i].Op != w.op {
			t.Errorf("access %d = %+v, want %q/%s", i, got[i], w.path, w.op)
		}
	}
}

// A value this analysis cannot pin down must say so, rather than being reported
// as a path that was checked.
func TestClassifyPowerShellMarksUnresolvableValues(t *testing.T) {
	for _, cmd := range []string{
		`Remove-Item -LiteralPath $target`,
		`Remove-Item -LiteralPath $(Get-Location)`,
		`Get-Content -LiteralPath (Join-Path $dir 'x')`,
	} {
		got := accessesOf(t, cmd)
		for _, access := range got {
			if !access.Indeterminate {
				t.Errorf("ClassifyPowerShell(%q) = %+v, want the value marked indeterminate", cmd, access)
			}
		}
	}

	// A directory change makes every later relative path unresolvable, but an
	// absolute one still stands.
	got := accessesOf(t, `Set-Location C:\elsewhere; Remove-Item .env`)
	if len(got) != 1 || !got[0].Indeterminate {
		t.Errorf("after Set-Location = %+v, want indeterminate", got)
	}
	got = accessesOf(t, `Set-Location C:\elsewhere; Remove-Item C:\fixed\.env`)
	if len(got) != 1 || got[0].Indeterminate {
		t.Errorf("absolute path after Set-Location = %+v, want determinate", got)
	}
}

// Cmdlets that carry no path, and text that is not a cmdlet invocation, must
// not invent one.
func TestClassifyPowerShellIgnoresCommandsWithoutPaths(t *testing.T) {
	for _, cmd := range []string{
		`Get-Date`,
		`Write-Output "hello"`,
		`go build ./...`,
		`git status`,
		`$items = 1`,
	} {
		if got := accessesOf(t, cmd); len(got) != 0 {
			t.Errorf("ClassifyPowerShell(%q) = %+v, want no access", cmd, got)
		}
	}
}

// A cmdlet reading from the pipe has no path of its own; the paths belong to
// whatever produced the input.
func TestClassifyPowerShellSeparatesPipelineStages(t *testing.T) {
	got := accessesOf(t, `Get-ChildItem C:\project | Remove-Item`)
	if len(got) != 1 || got[0].Path != `C:/project` || got[0].Op != OpRead {
		t.Errorf("ClassifyPowerShell() = %+v, want only the Get-ChildItem read", got)
	}
}

// The path rules are written with forward slashes, so a Windows path has to be
// rewritten into that form or it matches nothing at all.
func TestNormalizeWindowsPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{`$HOME\.ssh`, "~/.ssh"},
		{`$env:USERPROFILE\.aws\credentials`, "~/.aws/credentials"},
		{`$Env:UserProfile\.ssh`, "~/.ssh"},
		{`C:\temp\x`, "C:/temp/x"},
		{`.\.env`, "./.env"},
		{`\\server\share\secret`, "//server/share/secret"},
		{"already/posix", "already/posix"},
		{"~/.ssh", "~/.ssh"},
	}
	for _, tc := range cases {
		if got := NormalizeWindowsPath(tc.in); got != tc.want {
			t.Errorf("NormalizeWindowsPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Win32 ignores these decorations when it opens a file, so a rule written for
// the plain name has to match them too. Each one is a single character away
// from walking a secret past sensitive_paths.
func TestNormalizeWindowsPathStripsWhatWin32Ignores(t *testing.T) {
	cases := []struct{ in, want, why string }{
		{`.env.`, ".env", "a trailing dot is dropped on the way to the filesystem"},
		{`.env...`, ".env", "so is a run of them"},
		{`.env `, ".env", "and a trailing space"},
		{`C:\Users\x\.ssh\`, "C:/Users/x/.ssh", "a trailing separator leaves an empty component"},
		{`.env:hidden`, ".env", "an alternate data stream names a stream of the guarded file"},
		{`C:\x\.env:hidden`, "C:/x/.env", "even with a drive in front"},
		{`\\?\C:\Users\x\.ssh\id_rsa`, "C:/Users/x/.ssh/id_rsa", "the extended-length form names the same file"},
		{`\\?\UNC\server\share\secret`, "//server/share/secret", "and so does its UNC variant"},
		{`%USERPROFILE%\.ssh`, "~/.ssh", "cmd spells the profile this way"},
		// A drive specification is not a stream, and the relative markers are
		// names in their own right.
		{`C:`, "C:", "a bare drive is left alone"},
		{`C:.env`, ".env", "a drive-relative path still names a plain file"},
		{`C:project\.env`, "project/.env", "and keeps the rest of the name"},
		{`./x`, "./x", "a relative marker must survive trimming"},
		{`../x`, "../x", "and so must its parent form"},
	}
	for _, tc := range cases {
		if got := NormalizeWindowsPath(tc.in); got != tc.want {
			t.Errorf("NormalizeWindowsPath(%q) = %q, want %q (%s)", tc.in, got, tc.want, tc.why)
		}
	}
}

// C:name resolves against the working directory Windows keeps per drive, which
// is not the one the hook reported and cannot be computed here.
func TestClassifyPowerShellMarksDriveRelativePaths(t *testing.T) {
	got := accessesOf(t, `Get-Content C:.env`)
	if len(got) != 1 || !got[0].Indeterminate {
		t.Errorf("ClassifyPowerShell() = %+v, want the drive-relative path marked indeterminate", got)
	}
	// A rooted path on the same drive is perfectly resolvable.
	got = accessesOf(t, `Get-Content C:\project\.env`)
	if len(got) != 1 || got[0].Indeterminate {
		t.Errorf("ClassifyPowerShell() = %+v, want a rooted path to stay determinate", got)
	}
}
