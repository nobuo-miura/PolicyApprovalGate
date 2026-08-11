package gitpush

import (
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nobuo-miura/policyapprovalgate/internal/shellparse"
)

// Short options cluster, so -fu is --force plus --set-upstream.
func TestCheckDetectsClusteredShortOptions(t *testing.T) {
	cfg := Config{Names: []string{"main"}, BlockForcePush: true, BlockDelete: true}
	for _, tc := range []struct{ command, want string }{
		{"git push -fu origin main", "force-pushes"},
		{"git push -uf origin main", "force-pushes"},
		{"git push -df origin main", "deletes"},
		{"git push -fd origin main", "deletes"},
		{"git push -qf origin main", "force-pushes"},
	} {
		v := Check(parseOne(t, tc.command), "/repo", cfg)
		if !v.Blocked {
			t.Errorf("Check(%q) was not blocked", tc.command)
			continue
		}
		if !strings.HasPrefix(v.Reason, tc.want) {
			t.Errorf("Check(%q) reason = %q, want it to start with %q", tc.command, v.Reason, tc.want)
		}
	}
}

// git documents --branches as a synonym for --all.
func TestCheckTreatsBranchesAsAll(t *testing.T) {
	forceCfg := Config{Names: []string{"main"}, BlockForcePush: true}
	if v := Check(parseOne(t, "git push --force --branches origin"), t.TempDir(), forceCfg); !v.Blocked {
		t.Error("git push --force --branches was not blocked")
	}
	directCfg := Config{Names: []string{"main"}, BlockDirectPush: true}
	if v := Check(parseOne(t, "git push --branches origin"), t.TempDir(), directCfg); !v.Blocked {
		t.Error("git push --branches was not blocked with BlockDirectPush")
	}
	// Without force or direct-push blocking, --branches is a plain push.
	if v := Check(parseOne(t, "git push --branches origin"), t.TempDir(), forceCfg); v.Blocked {
		t.Errorf("plain --branches was blocked: %s", v.Reason)
	}
}

// A destination decided at run time may well be a protected branch.
func TestCheckBlocksUnresolvedDestination(t *testing.T) {
	cfg := Config{Names: []string{"main"}, BlockForcePush: true, BlockDelete: true}
	for _, command := range []string{
		`git push --force origin "$branch"`,
		`git push --delete origin "$b"`,
		`git push --force origin ${BR}`,
	} {
		if v := Check(parseOne(t, command), t.TempDir(), cfg); !v.Blocked {
			t.Errorf("Check(%q) was not blocked", command)
		}
	}
	// A plain push stays deferred when direct pushes are allowed.
	if v := Check(parseOne(t, `git push origin "$branch"`), t.TempDir(), cfg); v.Blocked {
		t.Errorf("plain push with an unresolved destination was blocked: %s", v.Reason)
	}
}

func TestCheckBlocksDangerousPushWithUnresolvedGitC(t *testing.T) {
	cfg := Config{Names: []string{"main"}, BlockForcePush: true, BlockDelete: true}
	for _, command := range []string{
		`git -C "$REPO" push --force`,
		`git -C${REPO} push --force`,
		`git -c protocol.version=2 -C "$REPO" push --force`,
		`env -C "$REPO" git push --force`,
	} {
		if v := Check(parseOne(t, command), t.TempDir(), cfg); !v.Blocked {
			t.Errorf("Check(%q) was not blocked", command)
		}
	}

	for _, command := range []string{
		`git -C "$REPO" status`,
		`git -C "$REPO" push origin feature`,
	} {
		if v := Check(parseOne(t, command), t.TempDir(), cfg); v.Blocked {
			t.Errorf("Check(%q) was unexpectedly blocked: %s", command, v.Reason)
		}
	}
}

// A wildcard refspec expands on the remote and can land on a protected branch.
func TestCheckDetectsWildcardRefspec(t *testing.T) {
	cfg := Config{Names: []string{"main"}, BlockForcePush: true, BlockDelete: true, BlockDirectPush: true}
	for _, command := range []string{
		"git push origin 'refs/heads/*:refs/heads/*'",
		"git push -f origin 'refs/heads/*'",
		"git push --delete origin 'refs/heads/ma*'",
		"git push origin 'ma?n'",
	} {
		if v := Check(parseOne(t, command), "/repo", cfg); !v.Blocked {
			t.Errorf("Check(%q) was not blocked", command)
		}
	}
	// A pattern that cannot reach a protected branch stays allowed.
	if v := Check(parseOne(t, "git push origin 'refs/heads/feature/*'"), "/repo", cfg); v.Blocked {
		t.Errorf("unrelated wildcard was blocked: %s", v.Reason)
	}
}

// The branch lookup runs before the host approves the command, so the command
// being inspected must not be able to steer policygate's own git subprocess.
func TestNormalizeGitForwardsOnlyRepositoryLocatingOptions(t *testing.T) {
	argv := []string{
		"git", "-c", "core.pager=evil", "--exec-path", "/tmp/evil", "--config-env=AUTH=X",
		"--exec-path=/tmp/evil", "--git-dir", "/repo/.git", "--work-tree=/repo",
		"push", "origin", "main",
	}
	rest, _, options := normalizeGit(argv, "/start")

	if len(rest) == 0 || rest[0] != "push" {
		t.Fatalf("rest = %v, want the push subcommand first", rest)
	}
	want := []string{"--git-dir", "/repo/.git", "--work-tree=/repo"}
	if !slices.Equal(options, want) {
		t.Errorf("forwarded options = %v, want %v", options, want)
	}
}

func parseOne(t *testing.T, cmd string) shellparse.Command {
	t.Helper()
	cmds, err := shellparse.Parse(cmd)
	if err != nil {
		t.Fatalf("Parse(%q): %v", cmd, err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	return cmds[0]
}

func defaultConfig() Config {
	return Config{
		Names:           []string{"main", "master"},
		BlockForcePush:  true,
		BlockDelete:     true,
		BlockDirectPush: false,
	}
}

func TestForcePushToMainWithExplicitBranch(t *testing.T) {
	v := Check(parseOne(t, "git push --force origin main"), t.TempDir(), defaultConfig())
	if !v.Blocked {
		t.Fatal("expected force-push to main to be blocked")
	}
}

func TestForcePushViaRefspec(t *testing.T) {
	v := Check(parseOne(t, "git push origin feature:main"), t.TempDir(), Config{
		Names: []string{"main"}, BlockForcePush: true, BlockDirectPush: true,
	})
	if !v.Blocked {
		t.Fatal("expected refspec-based push to main to be blocked (BlockDirectPush)")
	}
}

func TestRepoOptionDoesNotConsumeFirstRefspec(t *testing.T) {
	for _, command := range []string{
		"git push --repo=origin --force feature:main",
		"git push --repo origin +feature:main",
	} {
		if v := Check(parseOne(t, command), t.TempDir(), defaultConfig()); !v.Blocked {
			t.Errorf("expected %q to inspect the first positional as a refspec", command)
		}
	}
}

func TestForcePlusRefspecPrefix(t *testing.T) {
	v := Check(parseOne(t, "git push origin +feature:main"), t.TempDir(), defaultConfig())
	if !v.Blocked {
		t.Fatal("expected +refspec force push to main to be blocked")
	}
}

func TestDeleteRefspecForm(t *testing.T) {
	v := Check(parseOne(t, "git push origin :main"), t.TempDir(), defaultConfig())
	if !v.Blocked {
		t.Fatal("expected :main delete-refspec to be blocked")
	}
}

func TestDeleteFlagForm(t *testing.T) {
	v := Check(parseOne(t, "git push origin --delete main"), t.TempDir(), defaultConfig())
	if !v.Blocked {
		t.Fatal("expected --delete main to be blocked")
	}
}

func TestNonForcePushToFeatureBranchAllowed(t *testing.T) {
	v := Check(parseOne(t, "git push origin feature-x"), t.TempDir(), defaultConfig())
	if v.Blocked {
		t.Fatalf("did not expect feature branch push to be blocked: %+v", v)
	}
}

func TestNonForcePushToMainAllowedByDefault(t *testing.T) {
	// Plain pushes are allowed by default.
	v := Check(parseOne(t, "git push origin main"), t.TempDir(), defaultConfig())
	if v.Blocked {
		t.Fatalf("did not expect plain push to main to be blocked with BlockDirectPush=false: %+v", v)
	}
}

func TestFullRefForm(t *testing.T) {
	v := Check(parseOne(t, "git push --force origin refs/heads/feature:refs/heads/main"), t.TempDir(), defaultConfig())
	if !v.Blocked {
		t.Fatal("expected full refs/heads/ form to be blocked")
	}
}

func TestMirrorPushBlockedWithoutExplicitForceFlag(t *testing.T) {
	// --mirror forces updates and deletions even without -f.
	v := Check(parseOne(t, "git push --mirror origin"), t.TempDir(), defaultConfig())
	if !v.Blocked {
		t.Fatal("expected git push --mirror to be blocked without an explicit --force flag")
	}
}

func TestPrunePushBlockedWhenProtectedBranchDeletionIsBlocked(t *testing.T) {
	v := Check(parseOne(t, "git push --prune origin"), t.TempDir(), defaultConfig())
	if !v.Blocked {
		t.Fatal("expected git push --prune to be blocked because it can delete a protected branch")
	}
}

func TestMirrorPushAllowedWhenBothProtectionsOff(t *testing.T) {
	v := Check(parseOne(t, "git push --mirror origin"), t.TempDir(), Config{
		Names: []string{"main"}, BlockForcePush: false, BlockDelete: false,
	})
	if v.Blocked {
		t.Fatalf("did not expect --mirror to be blocked with force/delete protection off: %+v", v)
	}
}

func TestAllPushNotBlockedByDefault(t *testing.T) {
	// --all is a plain direct push when BlockDirectPush is disabled.
	v := Check(parseOne(t, "git push --all origin"), t.TempDir(), defaultConfig())
	if v.Blocked {
		t.Fatalf("did not expect plain --all to be blocked with BlockDirectPush=false: %+v", v)
	}
}

func TestAllPushBlockedWithForce(t *testing.T) {
	v := Check(parseOne(t, "git push --all --force origin"), t.TempDir(), defaultConfig())
	if !v.Blocked {
		t.Fatal("expected --all --force to be blocked")
	}
}

func TestNonGitPushCommandIsNoop(t *testing.T) {
	v := Check(parseOne(t, "git status"), t.TempDir(), defaultConfig())
	if v.Blocked {
		t.Fatalf("did not expect git status to be blocked: %+v", v)
	}
}

func TestWrappedForcePushesAreBlocked(t *testing.T) {
	for _, command := range []string{
		"env git push --force origin main",
		"command git push --force origin main",
		"git -C ../repo push --force origin main",
		"git --git-dir=.git push --force origin main",
	} {
		if v := Check(parseOne(t, command), t.TempDir(), defaultConfig()); !v.Blocked {
			t.Errorf("expected %q to be blocked", command)
		}
	}
}

func TestBareForcePushUsesCAndGitDirContext(t *testing.T) {
	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	cmd := exec.Command("git", "init", "-b", "main", repo)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	for _, command := range []string{
		"git -C repo push --force",
		"git --git-dir=repo/.git push --force",
		"env -C repo git push --force",
	} {
		if v := Check(parseOne(t, command), parent, defaultConfig()); !v.Blocked {
			t.Errorf("expected bare push context to resolve main for %q", command)
		}
	}
}

func TestForcePushSymbolicSourceWithoutDestinationUsesCurrentBranch(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "repo")
	cmd := exec.Command("git", "init", "-b", "main", repo)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	for _, source := range []string{"HEAD", "@"} {
		command := "git push --force origin " + source
		if v := Check(parseOne(t, command), repo, defaultConfig()); !v.Blocked {
			t.Errorf("expected %q to resolve the symbolic source to protected branch main", command)
		}
	}
}

func FuzzCheckDoesNotPanic(f *testing.F) {
	for _, seed := range []string{"git push --force origin main", "env git push origin :main", "git -C . push --mirror"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		commands, err := shellparse.Parse(source)
		if err != nil {
			return
		}
		for _, command := range commands {
			_ = Check(command, ".", defaultConfig())
		}
	})
}
