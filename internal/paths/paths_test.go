package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLayoutIsRootedAtBaseDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	base, err := BaseDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".policygate"); base != want {
		t.Errorf("BaseDir() = %q, want %q", base, want)
	}

	// The binary must live under BaseDir so the built-in protected_paths rule
	// covers it without extra configuration.
	bin, err := BinDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "bin"); bin != want {
		t.Errorf("BinDir() = %q, want %q", bin, want)
	}

	cfg, err := DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "config.yaml"); cfg != want {
		t.Errorf("DefaultConfig() = %q, want %q", cfg, want)
	}
}

func TestConfigTargetIgnoresExistence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(EnvConfig, "")

	// init has to name the file it is about to create, so a missing default
	// path is still the answer.
	got, err := ConfigTarget()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".policygate", "config.yaml"); got != want {
		t.Errorf("ConfigTarget() = %q, want %q", got, want)
	}
}

func TestConfigTargetPrefersEnv(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv(EnvConfig, filepath.Join(t.TempDir(), "elsewhere.yaml"))

	got, err := ConfigTarget()
	if err != nil {
		t.Fatal(err)
	}
	if got != os.Getenv(EnvConfig) {
		t.Errorf("ConfigTarget() = %q, want the POLICYGATE_CONFIG value", got)
	}
}

func TestConfigSourceReturnsExplicitPathEvenWhenMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	t.Setenv(EnvConfig, missing)

	// An explicit policy that cannot be read must surface as a load error, not
	// as a silent fall back to the embedded defaults.
	got, explicit := ConfigSource()
	if got != missing {
		t.Errorf("ConfigSource() = %q, want %q", got, missing)
	}
	if !explicit {
		t.Error("ConfigSource() reported an explicit path as implicit")
	}
}

func TestConfigSourceSkipsMissingDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(EnvConfig, "")

	got, explicit := ConfigSource()
	if got != "" {
		t.Errorf("ConfigSource() = %q, want \"\" so the embedded defaults are used", got)
	}
	if explicit {
		t.Error("ConfigSource() reported the default path as explicit")
	}
}

func TestConfigSourceFindsExistingDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(EnvConfig, "")

	dir := filepath.Join(home, ".policygate")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(want, []byte("config_version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, explicit := ConfigSource()
	if got != want {
		t.Errorf("ConfigSource() = %q, want %q", got, want)
	}
	if explicit {
		t.Error("ConfigSource() reported the default path as explicit")
	}
}

func TestExpand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"tilde prefix", DefaultAuditLog, filepath.Join(home, ".policygate", "log", "audit.log")},
		{"absolute path", filepath.Join(home, "kept"), filepath.Join(home, "kept")},
		{"relative path", "log/audit.log", "log/audit.log"},
		// A bare ~ and ~user are left alone: only the ~/ form is expanded.
		{"bare tilde", "~", "~"},
		{"other user", "~someone/file", "~someone/file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Expand(tc.in); got != tc.want {
				t.Errorf("Expand(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
