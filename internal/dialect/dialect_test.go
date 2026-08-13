package dialect

import "testing"

// The table is drawn from measuring both hosts on Windows 11; the payloads live
// in cmd/policygate/testdata/*-windows*.json.
func TestDetectFollowsTheMeasuredHostContract(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		toolName string
		goos     string
		want     Dialect
	}{
		{"claude bash on windows goes through git bash", "claude", "Bash", "windows", POSIX},
		{"claude bash on macos", "claude", "Bash", "darwin", POSIX},
		{"claude has a powershell tool of its own", "claude", "PowerShell", "windows", PowerShell},
		// The one that matters: Codex reports Bash and sends PowerShell.
		{"codex on windows reports bash and sends powershell", "codex", "Bash", "windows", PowerShell},
		{"codex on linux", "codex", "Bash", "linux", POSIX},
		{"codex on macos", "codex", "Bash", "darwin", POSIX},
		// Without a host, a Windows payload could be either of the two above.
		{"windows without a host is ambiguous", "", "Bash", "windows", Unknown},
		{"an unrecognized host on windows is ambiguous", "someshell", "Bash", "windows", Unknown},
		// Off Windows there is no ambiguity to resolve.
		{"no host off windows", "", "Bash", "linux", POSIX},
		// A tool named for the language settles it anywhere.
		{"a powershell tool off windows", "", "PowerShell", "linux", PowerShell},
		{"tool names are matched without regard to case", "claude", "powershell", "windows", PowerShell},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Detect(tc.host, tc.toolName, tc.goos); got != tc.want {
				t.Errorf("Detect(%q, %q, %q) = %q, want %q", tc.host, tc.toolName, tc.goos, got, tc.want)
			}
		})
	}
}

// Only POSIX carries the guarantee that a non-match means the command was
// understood; everything else has to be treated as possibly unexamined.
func TestOnlyPOSIXIsAnalyzable(t *testing.T) {
	if !POSIX.Analyzable() {
		t.Error("POSIX must be analyzable")
	}
	for _, d := range []Dialect{PowerShell, Unknown} {
		if d.Analyzable() {
			t.Errorf("%q must not be treated as analyzable", d)
		}
	}
}

func TestParse(t *testing.T) {
	for _, in := range []string{"posix", "POSIX", "bash", "sh", " posix "} {
		if got, err := Parse(in); err != nil || got != POSIX {
			t.Errorf("Parse(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"powershell", "PowerShell", "pwsh", "ps"} {
		if got, err := Parse(in); err != nil || got != PowerShell {
			t.Errorf("Parse(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "cmd", "fish", "unknown"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted an unsupported value", in)
		}
	}
}

func TestLooksLikePowerShell(t *testing.T) {
	// Drawn from what Codex actually generated on Windows.
	powershell := []string{
		`Get-ChildItem -Force | Select-Object -ExpandProperty Name`,
		`$items = Get-ChildItem -Force; 'FILES:'; $items | ForEach-Object { $_.Name }`,
		`Get-Content -LiteralPath $HOME\.ssh\id_rsa`,
		`Remove-Item -LiteralPath $HOME\.ssh -Recurse -Force`,
		`(Get-ChildItem -LiteralPath sub -File | Measure-Object).Count`,
		`echo $env:PATH`,
	}
	for _, cmd := range powershell {
		if !LooksLikePowerShell(cmd) {
			t.Errorf("LooksLikePowerShell(%q) = false, want true", cmd)
		}
	}

	// A warning that fires on ordinary POSIX would train people to ignore it.
	posix := []string{
		"ls -la",
		"cat ~/.ssh/id_rsa",
		"git push --force origin main",
		"rm -rf /tmp/x",
		`curl -H "Content-Type: application/json" https://example.com`,
		"go build ./...",
		"grep -r Get-Content ./docs",
		`git commit -m "add Select-Object examples"`,
	}
	for _, cmd := range posix {
		if LooksLikePowerShell(cmd) {
			t.Errorf("LooksLikePowerShell(%q) = true, want false", cmd)
		}
	}
}
