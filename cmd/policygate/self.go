package main

import (
	"os"
	"path/filepath"
	"strings"
)

// selfPaths reports every path that names this executable.
//
// Guarding the binary is what makes the install location a matter of
// convenience rather than of security. Homebrew chowns its prefix to the
// installing user, so a brew-installed binary carries no protection from the OS
// at all, and the same is true under ~/.policygate. Denying writes to whatever
// path this process was started from gives every install location the same
// footing.
//
// Both the invocation path and its target are guarded. The hook registration
// names the invocation path, so replacing a symlink redirects the gate just as
// effectively as overwriting the file it points at - and Homebrew installs
// exactly that way, linking bin/policygate into a versioned Cellar directory.
//
// It is a variable so tests can stand in a fixture instead of writing to the
// location of the real binary.
var selfPaths = resolveSelfPaths

func resolveSelfPaths() []string {
	exe, err := os.Executable()
	if err != nil {
		// Nothing can be guarded structurally without a path of this process's
		// own. Configured protected_paths rules still cover the default
		// install directory.
		warnf("resolve own executable path, self-protection is inactive: %v", err)
		return nil
	}
	out := []string{normalizeSelfPath(exe)}
	// os.Executable resolves symlinks on some platforms and not others, so ask
	// for the target explicitly rather than relying on which one this is.
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		if p := normalizeSelfPath(real); p != out[0] {
			out = append(out, p)
		}
	}
	return out
}

// normalizeSelfPath produces the clean forward-slash form that pathpolicy
// resolves command arguments into.
func normalizeSelfPath(p string) string {
	return filepath.ToSlash(filepath.Clean(p))
}

// matchesSelf returns the guarded path a candidate names, or "" for none.
//
// The comparison ignores case for the same reason rule matching does: a
// filesystem that ignores case opens the same file for POLICYGATE, and
// over-matching a distinct file differing only by case costs a false positive
// rather than a bypass.
func matchesSelf(self, candidates []string) string {
	for _, s := range self {
		for _, c := range candidates {
			if strings.EqualFold(s, c) {
				return s
			}
		}
	}
	return ""
}
