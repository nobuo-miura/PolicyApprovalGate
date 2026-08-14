package pathpolicy

import "strings"

// Codex has no Read, Write or Edit tool. It edits files with apply_patch, which
// it delivers as a shell command - Codex parses the shell itself to find the
// call, which is why its errors mention a bash grammar and a heredoc body.
//
// So the command does reach the gate, and then stops there: apply_patch is not
// a command this package knows, no path comes out of it, and the patch body
// naming the files is read by nobody. Measured against Codex CLI 0.147.0, a
// shell write to .env was denied while the same change through apply_patch went
// unexamined.
//
// The paths are in the patch itself, in these markers.
const (
	patchAddFile    = "*** Add File:"
	patchUpdateFile = "*** Update File:"
	patchDeleteFile = "*** Delete File:"
	patchMoveTo     = "*** Move to:"
)

// applyPatchNames are the spellings that invoke the tool. Codex rejects
// applypatch and apply-patch outright, so only the one name reaches it.
var applyPatchNames = map[string]bool{"apply_patch": true}

// isApplyPatch reports whether a command name invokes apply_patch.
func isApplyPatch(name string) bool {
	return applyPatchNames[strings.ToLower(name)]
}

// classifyApplyPatch reports the files a patch changes.
//
// The whole command text is scanned rather than one argument, because the patch
// arrives two ways - as an argument, and through a heredoc whose body is not an
// argument at all - and both keep the body in the text as written.
//
// A marker is only read at column zero, and leading whitespace is deliberately
// not trimmed first. Inside a hunk every line is prefixed with +, - or a single
// space, so trimming would turn a context line reading "*** Update File: .env"
// into a marker - letting the contents of the file being edited choose which
// paths the gate inspects. The format puts markers at column zero, so nothing
// legitimate is lost by insisting on it.
func classifyApplyPatch(text string) []Access {
	var out []Access
	// Index of the most recent Update File, which a Move to would rename.
	pendingUpdate := -1

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, patchUpdateFile):
			out = append(out, patchAccess(line[len(patchUpdateFile):], OpWrite))
			pendingUpdate = len(out) - 1
		case strings.HasPrefix(line, patchAddFile):
			out = append(out, patchAccess(line[len(patchAddFile):], OpWrite))
			pendingUpdate = -1
		case strings.HasPrefix(line, patchDeleteFile):
			out = append(out, patchAccess(line[len(patchDeleteFile):], OpDelete))
			pendingUpdate = -1
		case strings.HasPrefix(line, patchMoveTo):
			out = append(out, patchAccess(line[len(patchMoveTo):], OpWrite))
			// A rename leaves nothing at the old path, so the file named by the
			// Update File above this is being removed, not written. Delete is
			// also the stricter reading of the two, which is the right way to
			// be wrong about a file that is going away.
			if pendingUpdate >= 0 {
				out[pendingUpdate].Op = OpDelete
				pendingUpdate = -1
			}
		}
	}
	return out
}

// patchAccess builds the access for one marker's path.
func patchAccess(rest string, op Op) Access {
	path := strings.TrimSpace(rest)
	path = strings.Trim(path, `"'`)
	access := Access{Path: path, Op: op}
	// An unquoted heredoc and a double-quoted argument expand before
	// apply_patch sees them, so a path carrying an expansion is not the path
	// that will be written. A quoted heredoc does not expand, and its $ is
	// simply part of the name. The command text retains that distinction, but
	// this classifier deliberately does not model the quoting context around
	// every patch-delivery form. Reporting both as unresolved errs toward
	// examining a literal $ too closely rather than checking the wrong path.
	if path == "" || strings.ContainsAny(path, "$`") {
		access.Indeterminate = true
	}
	return access
}
