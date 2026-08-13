// Package audit records policygate decisions as JSON Lines.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Record is one audit-log entry.
type Record struct {
	Time      time.Time `json:"time"`
	ToolName  string    `json:"tool_name"`
	CWD       string    `json:"cwd"`
	Command   string    `json:"command"`
	Source    string    `json:"source"` // Stable identifier for the decision source.
	Decision  string    `json:"decision"`
	Reason    string    `json:"reason,omitempty"`
	MatchedBy string    `json:"matched_by,omitempty"`

	// Dialect is the shell language the command was read as. It records which
	// analysis ran, so a decision reached without one - PowerShell has no
	// structural analysis - is not mistaken later for a command that was
	// examined and found ordinary.
	Dialect string `json:"dialect,omitempty"`
}

// Options controls audit-log rotation.
type Options struct {
	MaxBytes int64
	MaxFiles int
}

// Command arguments may contain secrets, so newly created paths use restrictive permissions.
const (
	dirPerm  = 0o700
	filePerm = 0o600
)

// Append writes rec as one JSON line, creating and rotating the log as needed.
// Existing parent permissions are preserved, the final file is opened without
// following symlinks, and non-regular targets are rejected.
func Append(path string, rec Record, option ...Options) error {
	var opts Options
	if len(option) > 0 {
		opts = option[0]
	}
	dir := filepath.Dir(path)
	resolvedDir, err := ensureDir(dir)
	if err != nil {
		return err
	}
	path = filepath.Join(resolvedDir, filepath.Base(path))
	return withFileLock(path+".lock", func() error {
		return appendLocked(path, rec, opts)
	})
}

func appendLocked(path string, rec Record, opts Options) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal audit record: %w", err)
	}
	line = append(line, '\n')
	if err := rotate(path, int64(len(line)), opts); err != nil {
		return err
	}

	f, err := openNoFollow(path, filePerm)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Chmod(filePerm); err != nil {
		return fmt.Errorf("tighten audit log file permissions: %w", err)
	}

	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	return nil
}

// ensureDir resolves existing symlink components and creates only missing directories.
func ensureDir(dir string) (string, error) {
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("audit log directory %s exists but is not a directory", dir)
		}
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return "", fmt.Errorf("resolve audit log directory: %w", err)
		}
		return resolved, nil
	}
	ancestor := dir
	var suffix []string
	for {
		if _, err := os.Stat(ancestor); err == nil {
			break
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", fmt.Errorf("find existing audit log ancestor for %s", dir)
		}
		suffix = append([]string{filepath.Base(ancestor)}, suffix...)
		ancestor = parent
	}
	resolvedAncestor, err := filepath.EvalSymlinks(ancestor)
	if err != nil {
		return "", fmt.Errorf("resolve audit log ancestor: %w", err)
	}
	resolvedDir := filepath.Join(append([]string{resolvedAncestor}, suffix...)...)
	if err := os.MkdirAll(resolvedDir, dirPerm); err != nil {
		return "", fmt.Errorf("create audit log dir: %w", err)
	}
	return resolvedDir, nil
}

func rotate(path string, incoming int64, opts Options) error {
	if opts.MaxBytes <= 0 || opts.MaxFiles <= 0 {
		return nil
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect audit log for rotation: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size()+incoming <= opts.MaxBytes {
		return rejectUnsafeExisting(path)
	}
	oldest := fmt.Sprintf("%s.%d", path, opts.MaxFiles)
	if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove oldest audit log %s: %w", oldest, err)
	}
	for i := opts.MaxFiles - 1; i >= 1; i-- {
		oldPath := fmt.Sprintf("%s.%d", path, i)
		newPath := fmt.Sprintf("%s.%d", path, i+1)
		if err := os.Rename(oldPath, newPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("rotate audit log %s: %w", oldPath, err)
		}
	}
	if err := os.Rename(path, path+".1"); err != nil {
		return fmt.Errorf("rotate audit log: %w", err)
	}
	return nil
}

// rejectUnsafeExisting rejects existing paths that are not regular files.
func rejectUnsafeExisting(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("audit log path %s is a symlink, refusing to write through it", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("audit log path %s is not a regular file (mode %s), refusing to write", path, info.Mode())
	}
	return nil
}

const redactedPlaceholder = "***REDACTED***"

var (
	sensitiveNameRe       = regexp.MustCompile(`(?i)(token|password|passwd|secret|api[_-]?key|access[_-]?key)`)
	sensitiveStandaloneRe = regexp.MustCompile(`(?i)^(?:[\w.-]*[_.-])?(?:token|password|passwd|secret|api[_-]?key|access[_-]?key)(?:[_.-][\w.-]*)?$`)
	urlUserinfoRe         = regexp.MustCompile(`(://[^:/\s@]+:)([^@/\s]+)(@)`)
)

// Redact masks common secret-bearing arguments on a best-effort basis.
func Redact(s string) string {
	words := scanShellWords(s)
	if len(words) == 0 {
		return s
	}
	replacements := make(map[int]string)
	pendingSecret := false
	activeTool := ""
	previousEnd := 0
	for i, word := range words {
		if containsCommandSeparator(s[previousEnd:word.start]) {
			pendingSecret = false
			activeTool = ""
		}
		previousEnd = word.end
		raw := s[word.start:word.end]
		value := unquoteShellWord(raw)
		name := strings.ToLower(filepath.Base(value))
		if name == "curl" || isMySQLClient(name) {
			activeTool = name
		}

		if pendingSecret {
			replacements[i] = redactedPlaceholder
			pendingSecret = false
			continue
		}
		if redacted, ok := redactAuthorization(value); ok {
			replacements[i] = requoteLike(raw, redacted)
			continue
		}
		if key, _, ok := strings.Cut(value, "="); ok {
			cleanKey := strings.TrimLeft(key, "-")
			if sensitiveNameRe.MatchString(cleanKey) || (activeTool == "curl" && (key == "--user" || key == "--proxy-user")) {
				replacements[i] = requoteLike(raw, key+"="+redactedPlaceholder)
				continue
			}
		}
		switch {
		case activeTool == "curl" && (value == "-u" || value == "--user" || value == "--proxy-user"):
			pendingSecret = true
			continue
		case activeTool == "curl" && strings.HasPrefix(value, "-u") && len(value) > 2:
			replacements[i] = "-u" + redactedPlaceholder
			continue
		case isMySQLClient(activeTool) && (value == "-p" || value == "--password"):
			pendingSecret = true
			continue
		case isMySQLClient(activeTool) && strings.HasPrefix(value, "-p") && len(value) > 2:
			replacements[i] = "-p" + redactedPlaceholder
			continue
		}
		trimmedFlag := strings.TrimSuffix(strings.TrimLeft(value, "-"), ":")
		if sensitiveStandaloneRe.MatchString(trimmedFlag) && !strings.Contains(value, "=") {
			pendingSecret = true
			continue
		}
	}

	var out strings.Builder
	cursor := 0
	for i, word := range words {
		out.WriteString(s[cursor:word.start])
		if replacement, ok := replacements[i]; ok {
			out.WriteString(replacement)
		} else {
			out.WriteString(s[word.start:word.end])
		}
		cursor = word.end
	}
	out.WriteString(s[cursor:])
	return urlUserinfoRe.ReplaceAllString(out.String(), "$1"+redactedPlaceholder+"$3")
}

type shellWord struct {
	start int
	end   int
}

func scanShellWords(s string) []shellWord {
	var words []shellWord
	start := -1
	inSingle := false
	inDouble := false
	escaped := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if start < 0 {
			if isShellDelimiter(ch) {
				continue
			}
			start = i
		}
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && !inSingle {
			escaped = true
			continue
		}
		switch ch {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		}
		if !inSingle && !inDouble && i+1 < len(s) && isShellDelimiter(s[i+1]) {
			words = append(words, shellWord{start: start, end: i + 1})
			start = -1
		}
	}
	if start >= 0 {
		words = append(words, shellWord{start: start, end: len(s)})
	}
	return words
}

func isShellDelimiter(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || strings.ContainsRune("|&;<>()", rune(ch))
}

func containsCommandSeparator(s string) bool {
	return strings.ContainsAny(s, "|&;\n")
}

func unquoteShellWord(word string) string {
	if len(word) >= 2 && ((word[0] == '\'' && word[len(word)-1] == '\'') || (word[0] == '"' && word[len(word)-1] == '"')) {
		return word[1 : len(word)-1]
	}
	return word
}

func requoteLike(original, replacement string) string {
	if len(original) >= 2 && original[0] == original[len(original)-1] && (original[0] == '\'' || original[0] == '"') {
		return string(original[0]) + replacement + string(original[0])
	}
	return replacement
}

func redactAuthorization(value string) (string, bool) {
	colon := strings.IndexByte(value, ':')
	if colon < 0 || !strings.EqualFold(strings.TrimSpace(value[:colon]), "authorization") {
		return "", false
	}
	rest := strings.TrimSpace(value[colon+1:])
	if len(rest) >= len("Bearer ") && strings.EqualFold(rest[:len("Bearer ")], "Bearer ") {
		return value[:colon+1] + " Bearer " + redactedPlaceholder, true
	}
	return value[:colon+1] + " " + redactedPlaceholder, true
}

func isMySQLClient(name string) bool {
	switch name {
	case "mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump", "mariadb-admin":
		return true
	default:
		return false
	}
}
