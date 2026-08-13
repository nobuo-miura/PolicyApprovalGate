//go:build windows

package paths

// FSDropsNameDecorations is true here because Win32 normalizes a path before
// the filesystem ever sees it: a trailing dot or space is dropped, so `.env.`
// and `.env ` open `.env`, and a `name:stream` suffix names a stream of that
// same file. A rule written for `.env` therefore has to be matched against the
// undecorated spelling, or one extra character walks the file past it.
//
// This is a property of the API rather than of the shell in front of it. Git
// Bash's own `cat` rejects `.env.`, but anything it launches - cmd, python, a
// Go binary - goes straight to Win32 and opens the file.
const FSDropsNameDecorations = true
