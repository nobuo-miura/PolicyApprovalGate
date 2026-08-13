package pathpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nobuo-miura/policyapprovalgate/internal/paths"
)

// Case sensitivity of the filesystem holding a project.
//
// Whether the containment check may ignore case has to be answered from the
// filesystem rather than from the operating system, and the direction of the
// risk is the opposite of the one the rule matcher faces. Rule matching folds
// case unconditionally because over-matching costs a false positive while
// under-matching is a bypass. Here folding is the dangerous direction: treating
// /Users/u/project as inside /Users/u/Project puts a separate directory inside
// the project and relaxes every path_scope decision about it.
//
// The OS is not a reliable answer either way. macOS ships case-insensitive APFS
// but the recommended way to work case-sensitively is a separate volume, which
// is exactly where a cross-platform project lives; Linux is case-sensitive
// until an ext4 casefold directory, an exFAT mount, or a network share says
// otherwise.

// caseFoldCache remembers the answer per root. IsOutside runs once per path
// access, and a command can carry many.
var caseFoldCache sync.Map // string -> bool

// rootIgnoresCase reports whether the filesystem holding root resolves names
// without regard to case.
//
// The probe flips the case of the root's own last element and asks whether the
// result is the same file. Comparing identity rather than mere existence
// matters: on a case-sensitive filesystem a differently-cased sibling may
// happen to exist, and taking that as proof would fold case exactly where it
// must not be folded.
//
// An unanswerable probe falls back to the platform default, which is the best
// remaining guess.
func rootIgnoresCase(root string) bool {
	if root == "" {
		return paths.FSIgnoresCase
	}
	if cached, ok := caseFoldCache.Load(root); ok {
		ignoreCase, _ := cached.(bool)
		return ignoreCase
	}
	result := probeIgnoresCase(root)
	caseFoldCache.Store(root, result)
	return result
}

func probeIgnoresCase(root string) bool {
	native := filepath.FromSlash(root)
	info, err := os.Stat(native)
	if err != nil {
		return paths.FSIgnoresCase
	}
	flipped, ok := flipLastElementCase(native)
	if !ok {
		// Nothing to flip: a root such as /srv/2024 carries no letter in its
		// last element, so this tells us nothing about the filesystem.
		return paths.FSIgnoresCase
	}
	other, err := os.Stat(flipped)
	if err != nil {
		return false // The flipped name does not resolve: case matters here.
	}
	return os.SameFile(info, other)
}

// flipLastElementCase inverts the case of every letter in the final path
// element, reporting whether there was one to invert.
func flipLastElementCase(p string) (string, bool) {
	dir, base := filepath.Split(p)
	var b strings.Builder
	flipped := false
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32)
			flipped = true
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
			flipped = true
		default:
			b.WriteRune(r)
		}
	}
	if !flipped {
		return "", false
	}
	return dir + b.String(), true
}
