//go:build !windows

package paths

// FSDropsNameDecorations is false here because `.env.` and `.env ` are names in
// their own right on Linux and macOS, distinct from `.env`. Trimming them would
// report a file the command never opened, and the same applies to a colon,
// which is an ordinary character in a POSIX filename rather than a stream
// separator.
const FSDropsNameDecorations = false
