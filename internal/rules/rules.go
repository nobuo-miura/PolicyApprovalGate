// Package rules loads policygate YAML configuration and matches commands and paths.
package rules

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// CurrentConfigVersion is the newest configuration schema understood by this build.
const CurrentConfigVersion = 1

// Rule is one regular-expression rule with a human-readable reason.
type Rule struct {
	Pattern string `yaml:"pattern"`
	Reason  string `yaml:"reason"`

	compiled *regexp.Regexp
}

// AccessPolicy defines decisions for each path-access operation.
type AccessPolicy struct {
	Read   string `yaml:"read"` // "allow" | "ask" | "deny"
	Write  string `yaml:"write"`
	Delete string `yaml:"delete"`
}

// For returns the decision for op. Unknown or omitted operations default to ask.
func (p AccessPolicy) For(op string) string {
	var v string
	switch op {
	case "read":
		v = p.Read
	case "write":
		v = p.Write
	case "delete":
		v = p.Delete
	}
	if v == "" {
		return "ask"
	}
	return v
}

// PathScopeConfig controls access outside the project root.
type PathScopeConfig struct {
	Enabled bool `yaml:"enabled"`
	// ProjectRoot is either "cwd" or a fixed absolute path.
	ProjectRoot    string       `yaml:"project_root"`
	OutsideProject AccessPolicy `yaml:"outside_project"`
}

// SensitivePathsConfig detects sensitive paths inside or outside the project.
type SensitivePathsConfig struct {
	Enabled  bool         `yaml:"enabled"`
	Patterns []Rule       `yaml:"patterns"`
	Policy   AccessPolicy `yaml:"policy"`
}

// ProtectedPathsConfig always rejects writes and deletions to matching paths.
// It is a soft guard against disabling policygate through monitored Bash calls.
type ProtectedPathsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Patterns []Rule `yaml:"patterns"`
}

// ProtectedBranchesConfig controls pushes to protected Git branches.
type ProtectedBranchesConfig struct {
	Names           []string `yaml:"names"`
	BlockForcePush  bool     `yaml:"block_force_push"`
	BlockDelete     bool     `yaml:"block_delete"`
	BlockDirectPush bool     `yaml:"block_direct_push"`
}

// ActionConfig defines the fallback for unmatched or unparseable commands.
type ActionConfig struct {
	Action string `yaml:"action"` // "defer" | "deny"
}

// AuditConfig controls JSON Lines audit logging.
type AuditConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Path        string `yaml:"path"`
	CommandMode string `yaml:"command_mode"`
	MaxBytes    int64  `yaml:"max_bytes"`
	MaxFiles    int    `yaml:"max_files"`
}

// Config is the complete policygate configuration.
type Config struct {
	Version           int                     `yaml:"config_version"`
	Mode              string                  `yaml:"mode"`
	Deny              []Rule                  `yaml:"deny"`
	Ask               []Rule                  `yaml:"ask"`
	Allow             []Rule                  `yaml:"allow"`
	PathScope         PathScopeConfig         `yaml:"path_scope"`
	SensitivePaths    SensitivePathsConfig    `yaml:"sensitive_paths"`
	ProtectedPaths    ProtectedPathsConfig    `yaml:"protected_paths"`
	ProtectedBranches ProtectedBranchesConfig `yaml:"protected_branches"`
	// Unknown is used when no rule matches.
	Unknown ActionConfig `yaml:"unknown"`
	// ParseError is used when shell syntax cannot be parsed.
	ParseError ActionConfig `yaml:"parse_error"`
	Audit      AuditConfig  `yaml:"audit"`
}

// Load reads and compiles a YAML configuration from path.
func Load(path string) (*Config, error) {
	cfg, _, err := LoadWithWarnings(path)
	return cfg, err
}

// LoadWithWarnings loads a configuration and reports applied migrations.
func LoadWithWarnings(path string) (*Config, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return ParseWithWarnings(data)
}

// Parse merges YAML data over the built-in defaults, compiles its expressions,
// and rejects unknown fields or invalid values.
func Parse(data []byte) (*Config, error) {
	cfg, _, err := ParseWithWarnings(data)
	return cfg, err
}

// ParseWithWarnings overlays a user configuration onto the built-in defaults.
// This preserves newly added protections when a legacy or partial file is loaded.
func ParseWithWarnings(data []byte) (*Config, []string, error) {
	var defaults map[string]any
	if err := yaml.Unmarshal(defaultYAML, &defaults); err != nil {
		return nil, nil, fmt.Errorf("parse embedded defaults: %w", err)
	}
	var user map[string]any
	if err := yaml.Unmarshal(data, &user); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}
	if user == nil {
		user = map[string]any{}
	}
	var warnings []string
	if versionValue, ok := user["config_version"]; !ok {
		warnings = append(warnings, "legacy configuration has no config_version; defaults for schema version 1 were merged")
	} else if versionNumber, ok := versionValue.(int); !ok {
		return nil, nil, fmt.Errorf("config_version must be an integer")
	} else if versionNumber > CurrentConfigVersion {
		return nil, nil, fmt.Errorf("config_version %d is newer than supported version %d", versionNumber, CurrentConfigVersion)
	} else if versionNumber < CurrentConfigVersion {
		warnings = append(warnings, fmt.Sprintf("configuration schema v%d was upgraded to v%d", versionNumber, CurrentConfigVersion))
	}
	if value, ok := user["explicit_allow"]; ok {
		warnings = append(warnings, fmt.Sprintf("explicit_allow=%v was removed and is ignored; allow rules never bypass host approval", value))
		delete(user, "explicit_allow")
	}
	if value, ok := user["audit"].(map[string]any); ok {
		if disable, exists := value["disable_redact"]; exists {
			if enabled, _ := disable.(bool); enabled {
				value["command_mode"] = "full"
			}
			delete(value, "disable_redact")
			warnings = append(warnings, "audit.disable_redact was migrated to audit.command_mode")
		}
	}
	merged := mergeMaps(defaults, user)
	merged["config_version"] = CurrentConfigVersion
	encoded, err := yaml.Marshal(merged)
	if err != nil {
		return nil, nil, fmt.Errorf("encode merged config: %w", err)
	}
	cfg, err := parseExact(encoded)
	return cfg, warnings, err
}

// Upgrade returns a complete configuration in the current schema.
func Upgrade(data []byte) ([]byte, []string, error) {
	var user map[string]any
	if err := yaml.Unmarshal(data, &user); err != nil {
		return nil, nil, fmt.Errorf("parse config for upgrade: %w", err)
	}
	var upgradeWarnings []string
	if auditConfig, ok := user["audit"].(map[string]any); ok {
		if path, _ := auditConfig["path"].(string); path == "~/.policygate/audit.log" {
			auditConfig["path"] = "~/.policygate/log/audit.log"
			upgradeWarnings = append(upgradeWarnings, "migrated the former default audit path to ~/.policygate/log/audit.log")
		}
	}
	migrated, err := yaml.Marshal(user)
	if err != nil {
		return nil, nil, fmt.Errorf("encode config migration: %w", err)
	}
	cfg, warnings, err := ParseWithWarnings(migrated)
	if err != nil {
		return nil, nil, err
	}
	warnings = append(upgradeWarnings, warnings...)
	restored, err := cfg.restoreMissingDefaultRules()
	if err != nil {
		return nil, nil, err
	}
	warnings = append(warnings, restored...)
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("encode upgraded config: %w", err)
	}
	return out, warnings, nil
}

// restoreMissingDefaultRules appends built-in rules that the configuration does
// not already list. A user configuration replaces a rule list wholesale rather
// than merging into it, so without this an upgrade would never deliver rules
// added to a later release. Rules are matched by pattern, and a restored rule
// can simply be deleted again after the upgrade.
func (c *Config) restoreMissingDefaultRules() ([]string, error) {
	defaults, err := Default()
	if err != nil {
		return nil, fmt.Errorf("load embedded defaults for upgrade: %w", err)
	}
	sections := []struct {
		name    string
		target  *[]Rule
		builtin []Rule
	}{
		{"deny", &c.Deny, defaults.Deny},
		{"ask", &c.Ask, defaults.Ask},
		{"allow", &c.Allow, defaults.Allow},
		{"sensitive_paths.patterns", &c.SensitivePaths.Patterns, defaults.SensitivePaths.Patterns},
		{"protected_paths.patterns", &c.ProtectedPaths.Patterns, defaults.ProtectedPaths.Patterns},
	}
	var warnings []string
	for _, section := range sections {
		present := make(map[string]bool, len(*section.target))
		for _, rule := range *section.target {
			present[rule.Pattern] = true
		}
		var added []string
		for _, rule := range section.builtin {
			if present[rule.Pattern] {
				continue
			}
			*section.target = append(*section.target, rule)
			added = append(added, rule.Pattern)
		}
		if len(added) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s: restored %d built-in rule(s) missing from this configuration: %s",
				section.name, len(added), strings.Join(added, ", ")))
		}
	}
	return warnings, nil
}

func mergeMaps(base, overlay map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(overlay))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range overlay {
		if child, ok := value.(map[string]any); ok {
			if baseChild, ok := out[key].(map[string]any); ok {
				out[key] = mergeMaps(baseChild, child)
				continue
			}
		}
		out[key] = value
	}
	return out
}

func parseExact(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.compile(); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	var errs []string
	if c.Version != CurrentConfigVersion {
		errs = append(errs, fmt.Sprintf("config_version: got %d, want %d", c.Version, CurrentConfigVersion))
	}
	if !oneOf(c.Mode, "enforce", "observe") {
		errs = append(errs, fmt.Sprintf("mode: invalid value %q (want enforce or observe)", c.Mode))
	}

	if c.PathScope.ProjectRoot != "" && c.PathScope.ProjectRoot != "cwd" && !filepath.IsAbs(c.PathScope.ProjectRoot) {
		errs = append(errs, fmt.Sprintf("path_scope.project_root: must be \"cwd\" or an absolute path, got %q", c.PathScope.ProjectRoot))
	}
	errs = append(errs, validateAccessPolicy("path_scope.outside_project", c.PathScope.OutsideProject)...)
	errs = append(errs, validateAccessPolicy("sensitive_paths.policy", c.SensitivePaths.Policy)...)

	if !oneOf(c.Unknown.Action, "", "defer", "deny") {
		errs = append(errs, fmt.Sprintf("unknown.action: invalid value %q (want defer or deny)", c.Unknown.Action))
	}
	if !oneOf(c.ParseError.Action, "", "defer", "deny") {
		errs = append(errs, fmt.Sprintf("parse_error.action: invalid value %q (want defer or deny)", c.ParseError.Action))
	}
	if !oneOf(c.Audit.CommandMode, "redacted", "full", "hash", "none") {
		errs = append(errs, fmt.Sprintf("audit.command_mode: invalid value %q (want redacted, full, hash, or none)", c.Audit.CommandMode))
	}
	if c.Audit.MaxBytes < 0 {
		errs = append(errs, "audit.max_bytes: must not be negative")
	}
	if c.Audit.MaxFiles < 0 {
		errs = append(errs, "audit.max_files: must not be negative")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid config: %s", strings.Join(errs, "; "))
	}
	return nil
}

func validateAccessPolicy(field string, p AccessPolicy) []string {
	var errs []string
	for _, entry := range []struct{ name, value string }{
		{"read", p.Read}, {"write", p.Write}, {"delete", p.Delete},
	} {
		if !oneOf(entry.value, "", "allow", "ask", "deny") {
			errs = append(errs, fmt.Sprintf("%s.%s: invalid value %q (want allow, ask, or deny)", field, entry.name, entry.value))
		}
	}
	return errs
}

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func (c *Config) compile() error {
	if err := compileRules(c.Deny, "deny"); err != nil {
		return err
	}
	if err := compileRules(c.Ask, "ask"); err != nil {
		return err
	}
	if err := compileRules(c.Allow, "allow"); err != nil {
		return err
	}
	if err := compileRules(c.SensitivePaths.Patterns, "sensitive_paths"); err != nil {
		return err
	}
	if err := compileRules(c.ProtectedPaths.Patterns, "protected_paths"); err != nil {
		return err
	}
	return nil
}

func compileRules(rules []Rule, section string) error {
	for i := range rules {
		re, err := regexp.Compile(rules[i].Pattern)
		if err != nil {
			return fmt.Errorf("compile %s rule %q: %w", section, rules[i].Pattern, err)
		}
		rules[i].compiled = re
	}
	return nil
}

// MatchDeny returns the first deny rule matching cmd.
func (c *Config) MatchDeny(cmd string) *Rule {
	return firstMatch(c.Deny, cmd)
}

// MatchAsk returns the first ask rule matching cmd. Ask rules request
// explicit host approval for specific commands without denying them outright.
func (c *Config) MatchAsk(cmd string) *Rule {
	return firstMatch(c.Ask, cmd)
}

// MatchAllow returns the first audit-classification allow rule matching cmd.
func (c *Config) MatchAllow(cmd string) *Rule {
	return firstMatch(c.Allow, cmd)
}

// MatchSensitive returns the first sensitive-path rule matching path.
func (c *Config) MatchSensitive(path string) *Rule {
	return firstMatch(c.SensitivePaths.Patterns, path)
}

// MatchProtected returns the first protected-path rule matching path.
func (c *Config) MatchProtected(path string) *Rule {
	return firstMatch(c.ProtectedPaths.Patterns, path)
}

func firstMatch(rules []Rule, s string) *Rule {
	for i := range rules {
		if rules[i].compiled.MatchString(s) {
			return &rules[i]
		}
	}
	return nil
}
