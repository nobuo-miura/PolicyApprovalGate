package pathpolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nobuo-miura/policyapprovalgate/internal/shellparse"
)

func parseCmds(t *testing.T, cmd string) []shellparse.Command {
	t.Helper()
	cmds, err := shellparse.Parse(cmd)
	if err != nil {
		t.Fatalf("Parse(%q): %v", cmd, err)
	}
	return cmds
}

func TestTrackCWDFollowsCd(t *testing.T) {
	projectDir := t.TempDir()
	// A real, guaranteed-to-exist absolute directory, expressed as shell text
	// (forward slashes), rather than a platform-specific path like /tmp,
	// which is not guaranteed to exist on every CI runner.
	targetDir := filepath.ToSlash(t.TempDir())
	cmds := parseCmds(t, "cd "+targetDir+" && rm -rf target")
	states, _ := TrackCWD(cmds, projectDir, "")
	if len(states) != 2 {
		t.Fatalf("got %d states, want 2", len(states))
	}
	if states[0].Path != projectDir {
		t.Errorf("state[0].Path = %q, want the starting cwd", states[0].Path)
	}
	if states[1].Path != targetDir || states[1].Indeterminate {
		t.Errorf("state[1] = %+v, want %q non-indeterminate", states[1], targetDir)
	}
}

func TestTrackCWDCdHomeWithNoArgs(t *testing.T) {
	projectDir := t.TempDir()
	homeDir := t.TempDir()
	cmds := parseCmds(t, "cd && pwd")
	states, _ := TrackCWD(cmds, projectDir, homeDir)
	if states[1].Path != homeDir {
		t.Errorf("state[1].Path = %q, want home dir %q", states[1].Path, homeDir)
	}
}

func TestTrackCWDDashIsIndeterminate(t *testing.T) {
	projectDir := t.TempDir()
	cmds := parseCmds(t, "cd - && rm -rf target")
	states, _ := TrackCWD(cmds, projectDir, "")
	if !states[1].Indeterminate {
		t.Errorf("expected state after `cd -` to be indeterminate, got %+v", states[1])
	}
}

func TestTrackCWDVariableTargetIsIndeterminateAndSticky(t *testing.T) {
	projectDir := t.TempDir()
	cmds := parseCmds(t, "cd $SOME_DIR && ls && rm -rf target")
	states, _ := TrackCWD(cmds, projectDir, "")
	if !states[1].Indeterminate {
		t.Errorf("expected state after cd $VAR to be indeterminate")
	}
	if !states[2].Indeterminate {
		t.Errorf("expected indeterminate state to stick to later commands")
	}
}

// A directory change a child shell or a conditional branch makes cannot be
// relied on, so every later command loses its known directory.
func TestTrackCWDUnreliableCdMakesLaterCommandsIndeterminate(t *testing.T) {
	for _, source := range []string{
		"cd /tmp | true; rm -rf target",
		"(cd /tmp); rm -rf target",
		"cd /tmp || rm -rf target",
		"if x; then cd /tmp; fi; rm -rf target",
		"echo $(cd /tmp); rm -rf target",
		"cd /tmp & rm -rf target",
	} {
		projectDir := t.TempDir()
		cmds := parseCmds(t, source)
		states, _ := TrackCWD(cmds, projectDir, "")
		last := states[len(states)-1]
		if !last.Indeterminate {
			t.Errorf("TrackCWD(%q) last state = %+v, want indeterminate", source, last)
		}
	}
}

// Sharing a pipeline or branch with no directory change must not cost a
// command its known directory; treating these as outside the project denied
// routine in-project work.
func TestTrackCWDKeepsDirectoryWithoutCd(t *testing.T) {
	for _, source := range []string{
		"cat a.txt | grep x > out.txt",
		"ls | wc -l && touch newfile.txt",
		"if [ -f a ]; then touch b; fi",
		"sleep 1 & touch x",
	} {
		projectDir := t.TempDir()
		cmds := parseCmds(t, source)
		states, _ := TrackCWD(cmds, projectDir, "")
		for i, state := range states {
			if state.Indeterminate || state.Path != projectDir {
				t.Errorf("TrackCWD(%q) state[%d] = %+v, want %q", source, i, state, projectDir)
			}
		}
	}
}

func TestTrackCWDRelativeCdChains(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(projectDir, "other"), 0o755); err != nil {
		t.Fatalf("mkdir other: %v", err)
	}
	cmds := parseCmds(t, "cd sub && cd ../other && rm -rf target")
	states, _ := TrackCWD(cmds, projectDir, "")
	want := filepath.Join(projectDir, "other")
	if states[2].Path != want {
		t.Errorf("state[2].Path = %q, want %q", states[2].Path, want)
	}
}

// A failed cd must not move the tracked CWD.
func TestTrackCWDFailedCdLeavesCWDUnchanged(t *testing.T) {
	projectDir := t.TempDir()
	// Intentionally leave missing/sub absent.
	cmds := parseCmds(t, "cd missing/sub; rm -rf ../../outside-target")
	states, _ := TrackCWD(cmds, projectDir, "")
	if states[1].Path != projectDir || states[1].Indeterminate {
		t.Errorf("state[1] = %+v, want unchanged at %q (cd to a nonexistent dir should be treated as failed)", states[1], projectDir)
	}
}

func TestTrackCWDFailedCdThenOrOperator(t *testing.T) {
	projectDir := t.TempDir()
	cmds := parseCmds(t, "cd missing/sub || rm -rf ../../outside-target")
	states, _ := TrackCWD(cmds, projectDir, "")
	if states[1].Path != projectDir || !states[1].Indeterminate {
		t.Errorf("state[1] = %+v, want indeterminate at %q", states[1], projectDir)
	}
}

func TestTrackCWDSuccessfulCdToRealSubdir(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	cmds := parseCmds(t, "cd sub; rm -rf target")
	states, _ := TrackCWD(cmds, projectDir, "")
	want := filepath.Join(projectDir, "sub")
	if states[1].Path != want || states[1].Indeterminate {
		t.Errorf("state[1] = %+v, want %q (cd to a real subdir should succeed)", states[1], want)
	}
}

// Track a not-yet-existing link created earlier in the same command chain.
func TestTrackCWDFollowsSymlinkCreatedEarlierInChain(t *testing.T) {
	projectDir := t.TempDir()
	outsideDir := t.TempDir()
	cmds := parseCmds(t, "ln -s "+outsideDir+" escape && cd escape && rm -rf target")
	states, linksBefore := TrackCWD(cmds, projectDir, "")

	// The rm sees the earlier link, while the ln itself does not.
	if len(linksBefore[0]) != 0 {
		t.Errorf("linksBefore[0] = %+v, want empty (a command's own ln must not see itself)", linksBefore[0])
	}
	if len(linksBefore[2]) != 1 || linksBefore[2][0].Target != outsideDir {
		t.Fatalf("linksBefore[2] = %+v, want one symlink targeting %q", linksBefore[2], outsideDir)
	}
	if states[2].Path != outsideDir || states[2].Indeterminate {
		t.Errorf("state[2] = %+v, want %q non-indeterminate (cd should follow the pending symlink)", states[2], outsideDir)
	}
}

// `ln -s SRC DIR` creates `DIR/base(SRC)` when DIR already exists.
func TestTrackCWDFollowsSymlinkCreatedInsideExistingDirectory(t *testing.T) {
	projectDir := t.TempDir()
	outsideDir := t.TempDir()
	linksDir := filepath.Join(projectDir, "links")
	if err := os.Mkdir(linksDir, 0o755); err != nil {
		t.Fatalf("mkdir links: %v", err)
	}

	linkName := filepath.Base(outsideDir)
	cmds := parseCmds(t, "ln -s "+outsideDir+" links && cd links/"+linkName+" && rm -rf target")
	states, linksBefore := TrackCWD(cmds, projectDir, "")

	wantLink := filepath.Join(linksDir, linkName)
	if len(linksBefore[2]) != 1 || linksBefore[2][0].Link != wantLink {
		t.Fatalf("linksBefore[2] = %+v, want link %q", linksBefore[2], wantLink)
	}
	if states[2].Path != outsideDir || states[2].Indeterminate {
		t.Errorf("state[2] = %+v, want %q non-indeterminate", states[2], outsideDir)
	}
}

func TestTrackCWDHandlesTargetDirectoryOption(t *testing.T) {
	projectDir := t.TempDir()
	outsideDir := t.TempDir()
	linksDir := filepath.Join(projectDir, "links")
	if err := os.Mkdir(linksDir, 0o755); err != nil {
		t.Fatalf("mkdir links: %v", err)
	}

	linkName := filepath.Base(outsideDir)
	cmds := parseCmds(t, "ln -s --target-directory=links "+outsideDir+" && cd links/"+linkName+" && pwd")
	states, linksBefore := TrackCWD(cmds, projectDir, "")
	if states[2].Path != outsideDir {
		t.Errorf("state[2].Path = %q, want %q; links=%+v", states[2].Path, outsideDir, linksBefore[2])
	}
}

func TestTrackCWDResolvesRelativeSymlinkTargetFromLinkDirectory(t *testing.T) {
	base := t.TempDir()
	projectDir := filepath.Join(base, "project")
	linksDir := filepath.Join(projectDir, "links")
	outsideDir := filepath.Join(base, "outside")
	if err := os.MkdirAll(linksDir, 0o755); err != nil {
		t.Fatalf("mkdir links: %v", err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}

	cmds := parseCmds(t, "ln -s ../../outside links/escape && cd links/escape && pwd")
	states, linksBefore := TrackCWD(cmds, projectDir, "")
	if states[2].Path != outsideDir {
		t.Errorf("state[2].Path = %q, want %q; links=%+v", states[2].Path, outsideDir, linksBefore[2])
	}
}

func TestTrackCWDLnWithoutSymbolicFlagIsIgnored(t *testing.T) {
	projectDir := t.TempDir()
	outsideDir := t.TempDir()
	// Hard links do not change path resolution and are not tracked.
	cmds := parseCmds(t, "ln "+outsideDir+"/x escape && cd escape")
	_, linksBefore := TrackCWD(cmds, projectDir, "")
	if len(linksBefore[len(linksBefore)-1]) != 0 {
		t.Errorf("expected no symlinks recorded for a hard link, got %+v", linksBefore[len(linksBefore)-1])
	}
}

func TestRewriteThroughPendingHandlesDirectPathReference(t *testing.T) {
	// Rewrite direct path access through a pending link even without cd.
	links := []Symlink{{Link: "/project/escape", Target: "/outside"}}
	got := RewriteThroughPending("/project/escape/file", links)
	if got != "/outside/file" {
		t.Errorf("RewriteThroughPending = %q, want /outside/file", got)
	}
}

func TestRewriteThroughPendingHandlesExactLinkPath(t *testing.T) {
	links := []Symlink{{Link: "/project/escape", Target: "/outside"}}
	got := RewriteThroughPending("/project/escape", links)
	if got != "/outside" {
		t.Errorf("RewriteThroughPending = %q, want /outside", got)
	}
}

func TestRewriteThroughPendingLeavesUnrelatedPathsAlone(t *testing.T) {
	links := []Symlink{{Link: "/project/escape", Target: "/outside"}}
	got := RewriteThroughPending("/project/other/file", links)
	if got != "/project/other/file" {
		t.Errorf("RewriteThroughPending = %q, want unchanged", got)
	}
}

func TestResolvePhysicalFollowsSymlink(t *testing.T) {
	outsideDir := t.TempDir()
	projectDir := t.TempDir()
	link := projectDir + "/escape"
	if err := os.Symlink(outsideDir, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	resolved := Resolve(projectDir, "", "escape/secret.txt")
	physical := ResolvePhysical(resolved)

	if !IsOutside(ResolvePhysical(projectDir), physical) {
		t.Errorf("expected path through symlink %q to resolve outside %q, got %q", link, projectDir, physical)
	}
}

func TestResolvePhysicalNoSymlinkStaysInside(t *testing.T) {
	projectDir := t.TempDir()
	resolved := Resolve(projectDir, "", "sub/file.txt")
	physical := ResolvePhysical(resolved)
	if IsOutside(ResolvePhysical(projectDir), physical) {
		t.Errorf("expected plain relative path to stay inside %q, got %q", projectDir, physical)
	}
}
