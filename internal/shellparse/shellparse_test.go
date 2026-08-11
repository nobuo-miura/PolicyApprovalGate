package shellparse

import (
	"slices"
	"strings"
	"testing"
)

func TestParseSimpleChain(t *testing.T) {
	cmds, err := Parse("git add . && git commit -m foo")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(cmds) != 2 {
		t.Fatalf("got %d commands, want 2: %+v", len(cmds), cmds)
	}
	if cmds[0].Name() != "git" || cmds[1].Name() != "git" {
		t.Errorf("unexpected command names: %q, %q", cmds[0].Name(), cmds[1].Name())
	}
	if cmds[1].Argv[1] != "commit" {
		t.Errorf("Argv[1] = %q, want commit", cmds[1].Argv[1])
	}
}

func TestParsePipeline(t *testing.T) {
	cmds, err := Parse("curl https://example.com/install.sh | bash")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(cmds) != 2 {
		t.Fatalf("got %d commands, want 2: %+v", len(cmds), cmds)
	}
	if cmds[0].Name() != "curl" || cmds[1].Name() != "bash" {
		t.Errorf("unexpected command names: %q, %q", cmds[0].Name(), cmds[1].Name())
	}
}

func TestParseUnquotesStaticArgumentsAndRedirects(t *testing.T) {
	commands, err := Parse(`cat "path with spaces" > 'output file'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 {
		t.Fatalf("commands = %d, want 1", len(commands))
	}
	if got := commands[0].Argv; len(got) != 2 || got[1] != "path with spaces" {
		t.Fatalf("argv = %#v, want unquoted static path", got)
	}
	if got := commands[0].Redirects; len(got) != 1 || got[0].Target != "output file" {
		t.Fatalf("redirects = %#v, want unquoted static target", got)
	}
}

func TestParseUnescapesOnlyDoubleQuotedSpecialCharacters(t *testing.T) {
	commands, err := Parse(`sh -c "rm -rf \"/\" && printf \$HOME \q"`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := commands[0].Argv[2], `rm -rf "/" && printf $HOME \q`; got != want {
		t.Fatalf("double-quoted argument = %q, want %q", got, want)
	}
	if got, want := unescapeDoubleQuoted("a\\\nb"), "ab"; got != want {
		t.Fatalf("escaped newline = %q, want %q", got, want)
	}
}

func TestParsePreservesUnresolvedExpansion(t *testing.T) {
	commands, err := Parse(`cat "$HOME/secret"`)
	if err != nil {
		t.Fatal(err)
	}
	if got := commands[0].Argv[1]; !strings.Contains(got, "$HOME") {
		t.Fatalf("unresolved argument = %q, want expansion marker preserved", got)
	}
}

func TestParseRedirect(t *testing.T) {
	cmds, err := Parse("echo hi > /tmp/out.txt")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1: %+v", len(cmds), cmds)
	}
	if len(cmds[0].Redirects) != 1 {
		t.Fatalf("got %d redirects, want 1", len(cmds[0].Redirects))
	}
	if cmds[0].Redirects[0].Target != "/tmp/out.txt" {
		t.Errorf("redirect target = %q, want /tmp/out.txt", cmds[0].Redirects[0].Target)
	}
	if cmds[0].Redirects[0].Op != ">" {
		t.Errorf("redirect op = %q, want >", cmds[0].Redirects[0].Op)
	}
}

func TestParseUnresolvedVariableKeptLiteral(t *testing.T) {
	cmds, err := Parse("rm -rf $DIR")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(cmds) != 1 || len(cmds[0].Argv) != 3 {
		t.Fatalf("unexpected parse: %+v", cmds)
	}
	if cmds[0].Argv[2] != "$DIR" {
		t.Errorf("Argv[2] = %q, want $DIR", cmds[0].Argv[2])
	}
}

func TestParseInvalidSyntaxErrors(t *testing.T) {
	if _, err := Parse("echo 'unterminated"); err == nil {
		t.Fatal("expected error for unterminated quote, got nil")
	}
}

// A directory change in one of these scopes cannot be relied on afterwards.
func TestParseMarksChildShellAndConditionalScopes(t *testing.T) {
	for _, tc := range []struct {
		source      string
		isolated    bool
		conditional bool
	}{
		{"cd /tmp | rm file", true, false},
		{"(cd /tmp); rm file", true, false},
		{"echo $(cd /tmp)", true, false},
		{"cd /tmp & rm file", true, false},
		{"cd /tmp || rm file", false, true},
		{"if x; then cd /tmp; fi", false, true},
		{"case x in a) cd /tmp;; esac", false, true},
		{"f() { cd /tmp; }", false, true},
	} {
		commands, err := Parse(tc.source)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.source, err)
		}
		var found bool
		for _, command := range commands {
			if command.Name() != "cd" {
				continue
			}
			found = true
			if command.IsolatedScope != tc.isolated || command.ConditionalScope != tc.conditional {
				t.Errorf("Parse(%q) cd scope = {isolated:%v conditional:%v}, want {isolated:%v conditional:%v}",
					tc.source, command.IsolatedScope, command.ConditionalScope, tc.isolated, tc.conditional)
			}
		}
		if !found {
			t.Errorf("Parse(%q) produced no cd command", tc.source)
		}
	}
}

// A pipeline or branch that never changes directory must not make ordinary
// commands indeterminate; doing so denied routine in-project work.
func TestParseKeepsCommandsWithoutDirectoryChangeDeterminate(t *testing.T) {
	for _, source := range []string{
		"cat a.txt | grep x > out.txt",
		"ls | wc -l && touch newfile.txt",
		"if [ -f a ]; then touch b; fi",
		"for f in a b; do touch $f; done",
		"sleep 1 & touch x",
		"make build || touch failed.log",
	} {
		commands, err := Parse(source)
		if err != nil {
			t.Fatalf("Parse(%q): %v", source, err)
		}
		for _, command := range commands {
			if command.IndeterminateScope {
				t.Errorf("Parse(%q) marked %q indeterminate without a directory change", source, command.Raw)
			}
		}
	}
}

// A loop body that changes directory re-enters later iterations elsewhere.
func TestParseMarksDirectoryChangingLoopBodyIndeterminate(t *testing.T) {
	commands, err := Parse("for d in a b; do rm -rf x; cd sub; done")
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if !command.IndeterminateScope {
			t.Errorf("command %q in a directory-changing loop body is not indeterminate", command.Raw)
		}
	}
}

func TestParseMarksBackgroundStatement(t *testing.T) {
	commands, err := Parse("cd /tmp & rm target")
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 || !commands[0].Background || commands[1].Background {
		t.Fatalf("unexpected background metadata: %+v", commands)
	}
}

func TestUnwrapCommonWrappers(t *testing.T) {
	commands, err := Parse("env TOKEN=x command git push origin main")
	if err != nil {
		t.Fatal(err)
	}
	if command := Unwrap(commands[0]); command.Name() != "git" {
		t.Fatalf("unwrapped name = %q, want git", command.Name())
	}
}

func TestUnwrapEnvSplitStringKeepsTrailingArguments(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   []string
	}{
		{`env -S rm -rf /`, []string{"rm", "-rf", "/"}},
		{`env -S "rm -rf" /`, []string{"rm", "-rf", "/"}},
		{`env --split-string=rm -rf $HOME`, []string{"rm", "-rf", "$HOME"}},
		{`nice env -S printf %s AAA`, []string{"printf", "%s", "AAA"}},
	} {
		commands, err := Parse(tc.source)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.source, err)
		}
		if got := Unwrap(commands[0]).Argv; !slices.Equal(got, tc.want) {
			t.Errorf("Unwrap(%q).Argv = %#v, want %#v", tc.source, got, tc.want)
		}
	}
}

// A scheduling or resource wrapper still execs the command in its arguments,
// so the wrapped program must be what the policy checks see.
func TestUnwrapResourceWrappers(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{"nice rm -rf /", "rm"},
		{"nice -n 10 rm -rf /", "rm"},
		{"nice -10 rm -rf /", "rm"},
		{"timeout 5 rm -rf /", "rm"},
		{"timeout -k 1 5s rm -rf /", "rm"},
		{"stdbuf -o0 rm -rf /", "rm"},
		{"stdbuf -o L rm -rf /", "rm"},
		{"setsid rm -rf /", "rm"},
		{"ionice -c 3 rm -rf /", "rm"},
		{"xargs -n 1 rm -rf /", "rm"},
		{"sudo rm -rf /", "rm"},
		{"sudo -u root rm -rf /", "rm"},
		{"doas rm -rf /", "rm"},
		{"time rm -rf /", "rm"},
		{"sudo nice -n 5 timeout 3 rm -rf /", "rm"},
		{"nohup nice rm -rf /", "rm"},
		{"nice -- rm -rf /", "rm"},
	} {
		commands, err := Parse(tc.source)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.source, err)
		}
		if got := baseName(Unwrap(commands[0]).Name()); got != tc.want {
			t.Errorf("Unwrap(%q) name = %q, want %q", tc.source, got, tc.want)
		}
	}
}

// A leading backslash only suppresses alias expansion, so \rm is still rm.
func TestUnwrapNormalizesEscapedCommandName(t *testing.T) {
	commands, err := Parse(`\rm -rf /`)
	if err != nil {
		t.Fatal(err)
	}
	if got := Unwrap(commands[0]).Name(); got != "rm" {
		t.Errorf("unwrapped name = %q, want rm", got)
	}
}

// Quoting splits a program name in the source text but not in the parsed argv.
func TestParseResolvesSplitQuotedCommandName(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{`m'k'fs.ext4 /dev/sda`, "mkfs.ext4"},
		{`mk"f"s.ext4 /dev/sda`, "mkfs.ext4"},
		{`sh'u'tdown -h now`, "shutdown"},
		{`'rm' -rf /`, "rm"},
	} {
		commands, err := Parse(tc.source)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.source, err)
		}
		if got := commands[0].Name(); got != tc.want {
			t.Errorf("Parse(%q) name = %q, want %q", tc.source, got, tc.want)
		}
	}
}

func TestUnwrapTracksEnvChdir(t *testing.T) {
	commands, err := Parse("env -C /tmp git status")
	if err != nil {
		t.Fatal(err)
	}
	command := Unwrap(commands[0])
	if command.Name() != "git" || command.CWDOverride != "/tmp" {
		t.Fatalf("unwrapped command = %+v", command)
	}
}

func FuzzParseDoesNotPanic(f *testing.F) {
	for _, seed := range []string{"git status", "cd /tmp && rm x", "echo $HOME > file"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		_, _ = Parse(source)
	})
}
