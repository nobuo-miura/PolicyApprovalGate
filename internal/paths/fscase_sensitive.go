//go:build !windows && !darwin

package paths

// FSIgnoresCase is false here because .env and .ENV are distinct files on a
// typical Linux filesystem, and folding case would make the path rules match
// files the command never touched.
const FSIgnoresCase = false
