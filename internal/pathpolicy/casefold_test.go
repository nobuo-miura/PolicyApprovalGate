package pathpolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nobuo-miura/policyapprovalgate/internal/paths"
)

// The probe has to agree with the filesystem the test is actually running on,
// whichever that is, so it is checked against a directory created for the
// purpose rather than against a hard-coded expectation.
func TestRootIgnoresCaseMatchesTheRealFilesystem(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Project")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := os.Stat(filepath.Join(dir, "project"))
	actuallyIgnoresCase := err == nil

	if got := rootIgnoresCase(filepath.ToSlash(root)); got != actuallyIgnoresCase {
		t.Errorf("rootIgnoresCase() = %v, but the filesystem says %v", got, actuallyIgnoresCase)
	}
}

// A probe that cannot be answered must not invent one.
func TestRootIgnoresCaseFallsBackWhenUnanswerable(t *testing.T) {
	// A root that does not exist cannot be probed.
	missing := filepath.ToSlash(filepath.Join(t.TempDir(), "absent"))
	if got := rootIgnoresCase(missing); got != paths.FSIgnoresCase {
		t.Errorf("rootIgnoresCase(missing) = %v, want the platform default %v", got, paths.FSIgnoresCase)
	}

	// A last element with no letters carries no information either.
	dir := t.TempDir()
	numeric := filepath.Join(dir, "2024")
	if err := os.Mkdir(numeric, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := rootIgnoresCase(filepath.ToSlash(numeric)); got != paths.FSIgnoresCase {
		t.Errorf("rootIgnoresCase(numeric) = %v, want the platform default %v", got, paths.FSIgnoresCase)
	}

	if got := rootIgnoresCase(""); got != paths.FSIgnoresCase {
		t.Errorf("rootIgnoresCase(\"\") = %v, want the platform default", got)
	}
}

func TestFlipLastElementCase(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		flipped bool
	}{
		{filepath.Join("a", "Project"), filepath.Join("a", "pROJECT"), true},
		{filepath.Join("a", "project"), filepath.Join("a", "PROJECT"), true},
		{filepath.Join("a", "2024"), "", false},
		{filepath.Join("Mixed", "x9y"), filepath.Join("Mixed", "X9Y"), true},
	}
	for _, tc := range cases {
		got, ok := flipLastElementCase(tc.in)
		if ok != tc.flipped || (tc.flipped && got != tc.want) {
			t.Errorf("flipLastElementCase(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.flipped)
		}
	}
}

// Containment must follow the filesystem the project sits on. Folding case
// where it should not places a separate directory inside the project.
func TestIsOutsideFollowsTheProjectFilesystem(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Project")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := os.Stat(filepath.Join(dir, "project"))
	ignoresCase := err == nil

	slashRoot := filepath.ToSlash(root)
	if IsOutside(slashRoot, slashRoot+"/src/main.go") {
		t.Error("an exact-case child was reported outside the project")
	}
	lowered := filepath.ToSlash(filepath.Join(dir, "project")) + "/src/main.go"
	if got := IsOutside(slashRoot, lowered); got == ignoresCase {
		t.Errorf("IsOutside(%q) = %v, but this filesystem ignores case: %v", lowered, got, ignoresCase)
	}
	// Folding case must never turn a prefix-sharing sibling into a child.
	if !IsOutside(slashRoot, filepath.ToSlash(filepath.Join(dir, "Project-evil"))+"/x") {
		t.Error("a prefix-sharing sibling was reported inside the project")
	}
}
