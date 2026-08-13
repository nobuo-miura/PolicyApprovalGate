// Package paths resolves the per-user locations policygate owns. Every lookup
// lives here so that the hook, the operational commands, and the installer all
// agree on one directory layout; a disagreement between them would leave the
// gate reading one policy while protecting another.
//
// It also carries FSIgnoresCase, the one piece of platform path semantics that
// both the rule matcher and the path classifier need to agree on.
package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// EnvConfig overrides the configuration file location.
const EnvConfig = "POLICYGATE_CONFIG"

// dirName is the per-user directory policygate owns. The built-in
// protected_paths rule denies writes and deletes anywhere under it, so
// everything placed inside inherits that protection.
const dirName = ".policygate"

// DefaultAuditLog is the audit log written into a fresh configuration. It stays
// in ~ form because it is a configuration value that users read and edit, not a
// resolved filesystem path. Expand turns it into one.
const DefaultAuditLog = "~/" + dirName + "/log/audit.log"

// Home returns the user's home directory, or an empty string when it cannot be
// resolved. Path analysis treats an empty home as "leave ~ unexpanded" rather
// than failing the evaluation, because a command that merely mentions ~ should
// not become unanalyzable just because the home directory is unknown.
func Home() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// BaseDir returns ~/.policygate.
func BaseDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, dirName), nil
}

// BinDir returns ~/.policygate/bin, the location the installer writes the
// binary to. It sits under BaseDir so that protected_paths covers the binary
// itself without any additional configuration.
func BinDir() (string, error) {
	base, err := BaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "bin"), nil
}

// DefaultConfig returns ~/.policygate/config.yaml whether or not it exists.
func DefaultConfig() (string, error) {
	base, err := BaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "config.yaml"), nil
}

// ConfigTarget returns the configuration path to create or upgrade: an explicit
// POLICYGATE_CONFIG when set, otherwise the default path regardless of whether
// it already exists.
func ConfigTarget() (string, error) {
	if p := os.Getenv(EnvConfig); p != "" {
		return p, nil
	}
	return DefaultConfig()
}

// ConfigSource reports which configuration to load, and whether the caller
// selected it explicitly.
//
// An explicit POLICYGATE_CONFIG is returned as written and is never checked for
// existence, so an unreadable or invalid explicit policy surfaces as a load
// error instead of silently falling back to the embedded defaults. Without it,
// the default path is returned only when it already exists; an empty result
// selects the embedded defaults.
func ConfigSource() (path string, explicit bool) {
	if p := os.Getenv(EnvConfig); p != "" {
		return p, true
	}
	p, err := DefaultConfig()
	if err != nil {
		return "", false
	}
	if _, err := os.Stat(p); err != nil {
		return "", false
	}
	return p, false
}

// Expand replaces a leading ~/ with the user's home directory. The path is
// returned unchanged when it carries no ~ prefix or when the home directory
// cannot be resolved.
func Expand(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home := Home()
	if home == "" {
		return p
	}
	return filepath.Join(home, p[2:])
}
