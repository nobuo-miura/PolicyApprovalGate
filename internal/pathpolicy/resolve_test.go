package pathpolicy

import (
	"os"
	"path/filepath"
	"testing"
)

func physicalTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(dir)
}

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
}

// A write through a link whose target does not exist yet creates the target,
// so the target - not the link - is where the path resolves.
func TestResolvePhysicalCheckedFollowsDanglingLinks(t *testing.T) {
	base := physicalTempDir(t)
	outside := base + "/outside"
	project := base + "/project"
	for _, dir := range []string{outside, project} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	symlinkOrSkip(t, outside+"/new.txt", project+"/abs")
	symlinkOrSkip(t, "../outside/missing-dir", project+"/rel")
	symlinkOrSkip(t, "abs", project+"/chain")

	for path, want := range map[string]string{
		project + "/abs":            outside + "/new.txt",
		project + "/rel/file.txt":   outside + "/missing-dir/file.txt",
		project + "/chain":          outside + "/new.txt",
		project + "/plain/file.txt": project + "/plain/file.txt",
	} {
		got, ok := ResolvePhysicalChecked(path)
		if !ok || got != want {
			t.Errorf("ResolvePhysicalChecked(%q) = %q, %v; want %q, true", path, got, ok, want)
		}
	}
}

func TestResolvePhysicalCheckedReportsLinkLoops(t *testing.T) {
	dir := physicalTempDir(t)
	symlinkOrSkip(t, dir+"/b", dir+"/a")
	symlinkOrSkip(t, dir+"/a", dir+"/b")

	if got, ok := ResolvePhysicalChecked(dir + "/a/file.txt"); ok {
		t.Errorf("ResolvePhysicalChecked through a link loop = %q, true; want ok=false", got)
	}
}
