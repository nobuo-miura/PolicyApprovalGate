package pathpolicy

import (
	"testing"

	"github.com/nobuo-miura/policyapprovalgate/internal/paths"
	"github.com/nobuo-miura/policyapprovalgate/internal/shellparse"
)

func classify(t *testing.T, cmd string) []Access {
	t.Helper()
	cmds, err := shellparse.Parse(cmd)
	if err != nil {
		t.Fatalf("shellparse.Parse(%q): %v", cmd, err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	return Classify(cmds[0])
}

func TestClassifyRm(t *testing.T) {
	accesses := classify(t, "rm -rf /tmp/foo")
	mustAccess(t, accesses, "/tmp/foo", OpDelete)
}

func TestClassifyCatIsRead(t *testing.T) {
	accesses := classify(t, "cat /etc/hosts")
	mustAccess(t, accesses, "/etc/hosts", OpRead)
}

func TestClassifyRedirectIsWrite(t *testing.T) {
	accesses := classify(t, "echo hi >> /var/log/app.log")
	mustAccess(t, accesses, "/var/log/app.log", OpWrite)
}

func TestClassifyMvSourceIsReadAndDeleteDestIsWrite(t *testing.T) {
	accesses := classify(t, "mv a.txt /tmp/b.txt")
	mustAccess(t, accesses, "a.txt", OpRead)
	mustAccess(t, accesses, "a.txt", OpDelete)
	mustAccess(t, accesses, "/tmp/b.txt", OpWrite)
}

func TestClassifyCpDestOnlyIsWrite(t *testing.T) {
	accesses := classify(t, "cp a.txt /tmp/b.txt")
	mustAccess(t, accesses, "a.txt", OpRead)
	mustAccess(t, accesses, "/tmp/b.txt", OpWrite)
}

func TestClassifyCopyTargetDirectoryOptions(t *testing.T) {
	for _, command := range []string{
		"cp -t /outside file.txt",
		"cp --target-directory=/outside file.txt",
		"install -t /outside app",
		"env cp -t /outside file.txt",
	} {
		mustAccess(t, classify(t, command), "/outside", OpWrite)
	}
}

func TestClassifyInstallDirectoryMode(t *testing.T) {
	mustAccess(t, classify(t, "install -d -m 0700 /outside/private"), "/outside/private", OpWrite)
}

func TestClassifyFindGlobalSymlinkOption(t *testing.T) {
	mustAccess(t, classify(t, "find -H -O3 /outside -name '*.go'"), "/outside", OpRead)
}

func TestClassifyCopyFlagWithoutValueDoesNotConsumeSource(t *testing.T) {
	mustAccess(t, classify(t, "cp --preserve-context /outside/source target"), "/outside/source", OpRead)
}

func TestClassifySedInPlaceIsWrite(t *testing.T) {
	accesses := classify(t, "sed -i 's/a/b/' config.yaml")
	mustAccess(t, accesses, "config.yaml", OpWrite)
}

func TestClassifySedWithoutInPlaceIsRead(t *testing.T) {
	accesses := classify(t, "sed 's/a/b/' config.yaml")
	mustAccess(t, accesses, "config.yaml", OpRead)
}

func TestClassifyUnknownCommandProducesNothing(t *testing.T) {
	accesses := classify(t, "go build ./...")
	if len(accesses) != 0 {
		t.Errorf("expected no accesses for unrecognized command, got %+v", accesses)
	}
}

func TestClassifyIndeterminateVariable(t *testing.T) {
	accesses := classify(t, "rm -rf $DIR")
	found := false
	for _, a := range accesses {
		if a.Path == "$DIR" {
			found = true
			if !a.Indeterminate {
				t.Errorf("expected $DIR to be marked indeterminate")
			}
		}
	}
	if !found {
		t.Fatalf("expected an access for $DIR, got %+v", accesses)
	}
}

func TestResolveAndIsOutside(t *testing.T) {
	root := "/home/user/project"
	inside := Resolve("/home/user/project", "/home/user", "sub/file.txt")
	if IsOutside(root, inside) {
		t.Errorf("expected %q to be inside %q", inside, root)
	}

	outside := Resolve("/home/user/project", "/home/user", "../secrets.txt")
	if !IsOutside(root, outside) {
		t.Errorf("expected %q to be outside %q", outside, root)
	}

	outsideAbs := Resolve("/home/user/project", "/home/user", "/etc/passwd")
	if !IsOutside(root, outsideAbs) {
		t.Errorf("expected %q to be outside %q", outsideAbs, root)
	}

	// A sibling sharing a string prefix is still outside the root.
	sibling := Resolve("/home/user/project", "/home/user", "/home/user/project-evil/x")
	if !IsOutside(root, sibling) {
		t.Errorf("expected prefix-sharing sibling %q to be outside %q", sibling, root)
	}
}

func mustAccess(t *testing.T, accesses []Access, path string, op Op) {
	t.Helper()
	for _, a := range accesses {
		if a.Path == path && a.Op == op {
			return
		}
	}
	t.Errorf("expected access {%q, %q} in %+v", path, op, accesses)
}

func FuzzClassifyDoesNotPanic(f *testing.F) {
	for _, seed := range []string{"cp -t /tmp a", "sed -i s/a/b/ file", "env rm -rf target"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		commands, err := shellparse.Parse(source)
		if err != nil {
			return
		}
		for _, command := range commands {
			_ = Classify(command)
		}
	})
}

// Containment on a root that cannot be probed - one that does not exist -
// falls back to the platform default. The behaviour on a real filesystem is
// covered by TestIsOutsideFollowsTheProjectFilesystem.
func TestIsOutsideOnAnUnprobeableRoot(t *testing.T) {
	const root = "/Users/user/Project"

	if IsOutside(root, root) {
		t.Errorf("the root is not outside itself")
	}
	if IsOutside(root, root+"/src/main.go") {
		t.Errorf("an exact-case child was reported outside %q", root)
	}

	mixed := "/users/user/project/src/main.go"
	if got := IsOutside(root, mixed); got == paths.FSIgnoresCase {
		t.Errorf("IsOutside(%q, %q) = %v, want the platform fallback to apply",
			root, mixed, got)
	}

	// Folding case must not turn a prefix-sharing sibling into a child.
	if !IsOutside(root, "/users/user/project-evil/x") {
		t.Errorf("prefix-sharing sibling was reported inside %q", root)
	}
	// Nor may it swallow an unrelated tree of the same length.
	if !IsOutside(root, "/Users/user/Другое/x") {
		t.Errorf("unrelated path was reported inside %q", root)
	}
}

// A POSIX command on Windows can still reach Win32, which drops a trailing dot
// or space and reads a name:stream suffix as a stream of that same file. The
// host's answer is passed in rather than read from runtime.GOOS so that both
// branches are covered wherever the suite runs; a Windows-only assertion would
// be silently vacuous on the Mac and Linux runners.
func TestResolveDropsWin32NameDecorations(t *testing.T) {
	const cwd = "/home/user/project"
	const home = "/home/user"

	cases := []struct {
		name    string
		path    string
		windows string
		posix   string
	}{
		{"trailing dot", ".env.", cwd + "/.env", cwd + "/.env."},
		{"several trailing dots", ".env...", cwd + "/.env", cwd + "/.env..."},
		{"trailing space", ".env ", cwd + "/.env", cwd + "/.env "},
		{"dot and space", ".env. ", cwd + "/.env", cwd + "/.env. "},
		{"explicitly relative", "./.env.", cwd + "/.env", cwd + "/.env."},
		{"alternate data stream", ".env:hidden", cwd + "/.env", cwd + "/.env:hidden"},
		{"default stream", ".env::$DATA", cwd + "/.env", cwd + "/.env::$DATA"},
		{"under the home directory", "~/.ssh/id_rsa.", home + "/.ssh/id_rsa", home + "/.ssh/id_rsa."},
		{"absolute", "/etc/passwd.", "/etc/passwd", "/etc/passwd."},
		{"decorated parent", "sub./file", cwd + "/sub/file", cwd + "/sub./file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolve(cwd, home, tc.path, true); got != tc.windows {
				t.Errorf("resolve(%q, windows) = %q, want %q", tc.path, got, tc.windows)
			}
			if got := resolve(cwd, home, tc.path, false); got != tc.posix {
				t.Errorf("resolve(%q, posix) = %q, want %q", tc.path, got, tc.posix)
			}
		})
	}
}

// Trimming must not consume a name outright, and the relative markers are names
// of their own: turning `..` into an empty component would resolve a path to
// somewhere the command never named.
func TestResolveKeepsPathsThatAreOnlyDecoration(t *testing.T) {
	const cwd = "/home/user/project"

	cases := []struct{ path, want string }{
		{"..", "/home/user"},
		{"../.env", "/home/user/.env"},
		{".", cwd},
		{"...", cwd + "/..."},
		{" ", cwd + "/ "},
		{"", ""},
		// The critical-delete check recognizes `rm -rf /` by comparing the
		// resolved path against "/", so a root that trims to "" disarms it.
		{"/", "/"},
		{"/tmp/..", "/"},
		{"../../../..", "/"},
	}
	for _, tc := range cases {
		if got := resolve(cwd, "/home/user", tc.path, true); got != tc.want {
			t.Errorf("resolve(%q, windows) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// A path holding an unexpanded variable is never resolved, so the undecorated
// spelling has to be reachable on its own.
func TestTrimHostNameDecorations(t *testing.T) {
	const decorated = "$DIR/.env."

	if got := trimHostNameDecorations(decorated, true); got != "$DIR/.env" {
		t.Errorf("trimHostNameDecorations(%q, windows) = %q, want %q", decorated, got, "$DIR/.env")
	}
	if got := trimHostNameDecorations(decorated, false); got != decorated {
		t.Errorf("trimHostNameDecorations(%q, posix) = %q, want it unchanged", decorated, got)
	}
	if got := trimHostNameDecorations("", true); got != "" {
		t.Errorf("trimHostNameDecorations(%q, windows) = %q, want it unchanged", "", got)
	}
}

// The exported entry points must agree with the platform they were built for,
// or the branch the suite exercises would not be the one that runs.
func TestResolveMatchesThisPlatform(t *testing.T) {
	got := Resolve("/home/user/project", "/home/user", ".env.")
	want := "/home/user/project/.env."
	if paths.FSDropsNameDecorations {
		want = "/home/user/project/.env"
	}
	if got != want {
		t.Errorf("Resolve(%q) = %q, want %q", ".env.", got, want)
	}
	if got := TrimHostNameDecorations("$DIR/.env."); (got == "$DIR/.env") != paths.FSDropsNameDecorations {
		t.Errorf("TrimHostNameDecorations(%q) = %q, which disagrees with FSDropsNameDecorations=%v",
			"$DIR/.env.", got, paths.FSDropsNameDecorations)
	}
}
