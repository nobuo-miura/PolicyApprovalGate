package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAppendCreatesRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits don't apply on windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "audit.log")

	if err := Append(path, Record{Time: time.Now(), Command: "echo hi"}); err != nil {
		t.Fatalf("Append error: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat error: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != filePerm {
		t.Errorf("audit log perm = %o, want %o", perm, filePerm)
	}

	di, err := os.Stat(filepath.Join(dir, "nested"))
	if err != nil {
		t.Fatalf("Stat dir error: %v", err)
	}
	if perm := di.Mode().Perm(); perm != dirPerm {
		t.Errorf("audit log dir perm = %o, want %o", perm, dirPerm)
	}
}

// Tighten only a pre-existing log file with loose permissions.
func TestAppendTightensExistingLooseFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits don't apply on windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	if err := os.WriteFile(path, []byte(`{"command":"pre-existing"}`+"\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if err := Append(path, Record{Time: time.Now(), Command: "echo hi"}); err != nil {
		t.Fatalf("Append error: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat error: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != filePerm {
		t.Errorf("audit log perm = %o, want %o (existing loose file perm should be tightened)", perm, filePerm)
	}
}

// Never change permissions on a pre-existing shared parent directory.
func TestAppendNeverTouchesPreExistingDirPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits don't apply on windows")
	}
	sharedDir := t.TempDir() // stands in for something like /tmp
	if err := os.Chmod(sharedDir, 0o755); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	path := filepath.Join(sharedDir, "policygate.log")

	if err := Append(path, Record{Time: time.Now(), Command: "echo hi"}); err != nil {
		t.Fatalf("Append error: %v", err)
	}

	di, err := os.Stat(sharedDir)
	if err != nil {
		t.Fatalf("Stat dir error: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o755 {
		t.Errorf("shared dir perm = %o, want unchanged 0755 — a pre-existing directory must never be chmod'd", perm)
	}
	// Preserve the parent and restrict only the log file.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat file error: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != filePerm {
		t.Errorf("audit log file perm = %o, want %o", perm, filePerm)
	}
}

// Directories created by Append receive restrictive permissions.
func TestAppendCreatesFreshDirWithRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits don't apply on windows")
	}
	base := t.TempDir()
	path := filepath.Join(base, "not-yet-created", "audit.log")

	if err := Append(path, Record{Time: time.Now(), Command: "echo hi"}); err != nil {
		t.Fatalf("Append error: %v", err)
	}

	di, err := os.Stat(filepath.Join(base, "not-yet-created"))
	if err != nil {
		t.Fatalf("Stat dir error: %v", err)
	}
	if perm := di.Mode().Perm(); perm != dirPerm {
		t.Errorf("freshly-created dir perm = %o, want %o", perm, dirPerm)
	}
}

func TestAppendRejectsSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks behave differently on windows")
	}
	dir := t.TempDir()
	elsewhere := filepath.Join(t.TempDir(), "actually-written-here.log")
	link := filepath.Join(dir, "audit.log")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if err := Append(link, Record{Time: time.Now(), Command: "echo hi"}); err == nil {
		t.Fatal("expected Append to refuse writing through a symlink")
	}
	if _, err := os.Stat(elsewhere); err == nil {
		t.Error("Append must not have written through the symlink to elsewhere")
	}
}

func TestAppendWritesValidJSONLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	rec := Record{Time: time.Now(), ToolName: "Bash", Command: "git status", Decision: "deny", Reason: "test"}
	if err := Append(path, rec); err != nil {
		t.Fatalf("Append error: %v", err)
	}
	if err := Append(path, rec); err != nil {
		t.Fatalf("second Append error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	var got Record
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if got.Command != "git status" || got.Decision != "deny" {
		t.Errorf("unexpected record: %+v", got)
	}
}

func TestAppendRotatesAtConfiguredSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	first := Record{Time: time.Now(), Command: "first command"}
	if err := Append(path, first, Options{MaxBytes: 1, MaxFiles: 2}); err != nil {
		t.Fatal(err)
	}
	second := Record{Time: time.Now(), Command: "second command"}
	if err := Append(path, second, Options{MaxBytes: 1, MaxFiles: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotated audit log missing: %v", err)
	}
}

func TestAppendSerializesConcurrentRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	const writers = 32
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs <- Append(path, Record{Time: time.Now(), Command: "command-" + strconv.Itoa(i)}, Options{MaxBytes: 1, MaxFiles: writers})
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Append: %v", err)
		}
	}

	seen := make(map[string]bool, writers)
	for i := 0; i <= writers; i++ {
		candidate := path
		if i > 0 {
			candidate += "." + strconv.Itoa(i)
		}
		data, err := os.ReadFile(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var rec Record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("invalid JSON line in %s: %v", candidate, err)
			}
			seen[rec.Command] = true
		}
	}
	if len(seen) != writers {
		t.Fatalf("found %d unique records, want %d", len(seen), writers)
	}
}

func TestAppendResolvesParentSymlinkBeforeOpening(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink setup differs on Windows")
	}
	realDir := t.TempDir()
	container := t.TempDir()
	link := filepath.Join(container, "logs")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	if err := Append(filepath.Join(link, "audit.log"), Record{Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(realDir, "audit.log")); err != nil {
		t.Fatal(err)
	}
}

func TestRedactFlagAssignment(t *testing.T) {
	got := Redact("curl -H --token=abc123secret https://api.example.com")
	if strings.Contains(got, "abc123secret") {
		t.Errorf("expected token to be redacted, got %q", got)
	}
	if !strings.Contains(got, redactedPlaceholder) {
		t.Errorf("expected placeholder in output, got %q", got)
	}
}

func TestRedactSpaceSeparatedFlag(t *testing.T) {
	got := Redact("mytool --password hunter2ISecret")
	if strings.Contains(got, "hunter2ISecret") {
		t.Errorf("expected password to be redacted, got %q", got)
	}
}

func TestRedactEnvStyleAssignment(t *testing.T) {
	got := Redact("AWS_SECRET_ACCESS_KEY=AKIAABCDEFGHIJK aws s3 ls")
	if strings.Contains(got, "AKIAABCDEFGHIJK") {
		t.Errorf("expected secret env value to be redacted, got %q", got)
	}
}

func TestRedactAuthorizationHeader(t *testing.T) {
	got := Redact(`curl -H "Authorization: Bearer sk-live-abcdef123456" https://api.example.com`)
	if strings.Contains(got, "sk-live-abcdef123456") {
		t.Errorf("expected bearer token to be redacted, got %q", got)
	}
	if !strings.Contains(got, "Bearer") {
		t.Errorf("expected Bearer scheme to remain visible, got %q", got)
	}
}

func TestRedactURLUserinfo(t *testing.T) {
	got := Redact("curl https://user:hunter2@example.com/api")
	if strings.Contains(got, "hunter2") {
		t.Errorf("expected URL password to be redacted, got %q", got)
	}
	if !strings.Contains(got, "user:") {
		t.Errorf("expected username to remain visible, got %q", got)
	}
}

func TestRedactLeavesOrdinaryCommandsAlone(t *testing.T) {
	cmd := "go test ./... -run TestFoo"
	if got := Redact(cmd); got != cmd {
		t.Errorf("expected ordinary command unchanged, got %q", got)
	}
}

func TestRedactCurlBasicAuth(t *testing.T) {
	got := Redact("curl -u alice:hunter2 https://api.example.com")
	if strings.Contains(got, "alice:hunter2") || strings.Contains(got, "hunter2") {
		t.Fatalf("basic-auth credentials leaked: %q", got)
	}
}

func TestRedactCurlBasicAuthVariants(t *testing.T) {
	for _, command := range []string{
		"curl -ualice:hunter2 https://api.example.com",
		"curl --user=alice:hunter2 https://api.example.com",
		`curl --proxy-user "alice:hunter2" https://api.example.com`,
	} {
		if got := Redact(command); strings.Contains(got, "hunter2") {
			t.Errorf("basic-auth credentials leaked for %q: %q", command, got)
		}
	}
}

func TestRedactMySQLJoinedPassword(t *testing.T) {
	got := Redact("mysql -h db.internal -uroot -pSuperSecret123")
	if strings.Contains(got, "SuperSecret123") {
		t.Fatalf("joined MySQL password leaked: %q", got)
	}
}

func TestRedactQuotedPasswordWithSpaces(t *testing.T) {
	got := Redact(`curl --password "my secret with spaces" https://x`)
	for _, fragment := range []string{"my secret", "with spaces", `spaces"`} {
		if strings.Contains(got, fragment) {
			t.Fatalf("quoted password leaked %q: %q", fragment, got)
		}
	}
	if strings.Count(got, redactedPlaceholder) != 1 {
		t.Fatalf("quoted password should be replaced once: %q", got)
	}
}

func TestRedactDoesNotTreatUnrelatedShortFlagsAsPasswords(t *testing.T) {
	for _, command := range []string{"ssh -p 22 example.com", "mysql -uroot database"} {
		if got := Redact(command); got != command {
			t.Errorf("ordinary flag was redacted: got %q, want %q", got, command)
		}
	}
}
