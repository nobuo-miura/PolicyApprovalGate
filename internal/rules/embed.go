package rules

import _ "embed"

//go:embed default.yaml
var defaultYAML []byte

// Default returns the built-in policy used when no user configuration exists.
func Default() (*Config, error) {
	return parseExact(defaultYAML)
}

// DefaultYAML returns a copy of the embedded policy YAML.
func DefaultYAML() []byte {
	out := make([]byte, len(defaultYAML))
	copy(out, defaultYAML)
	return out
}
