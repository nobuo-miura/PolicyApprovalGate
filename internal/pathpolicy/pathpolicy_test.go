package pathpolicy

import (
	"testing"

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
