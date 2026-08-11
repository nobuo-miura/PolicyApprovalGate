// Package pathpolicy classifies shell path arguments as reads, writes, or
// deletions and evaluates them relative to a project root.
package pathpolicy

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/nobuo-miura/policyapprovalgate/internal/shellparse"
)

// Op is a filesystem access operation.
type Op string

const (
	OpRead   Op = "read"
	OpWrite  Op = "write"
	OpDelete Op = "delete"
)

// rank returns the severity of an access operation.
func (o Op) rank() int {
	switch o {
	case OpDelete:
		return 3
	case OpWrite:
		return 2
	case OpRead:
		return 1
	default:
		return 0
	}
}

// Access is one path access detected in a command.
type Access struct {
	Path string
	Op   Op
	// Indeterminate indicates unresolved variables or command substitutions.
	Indeterminate bool
}

// readOnly contains commands whose positional paths are reads.
var readOnly = map[string]bool{
	"cat": true, "less": true, "more": true, "head": true, "tail": true,
	"wc": true, "file": true, "stat": true, "readlink": true, "du": true,
	"diff": true, "cmp": true, "md5sum": true, "sha1sum": true, "sha256sum": true,
	"shasum": true, "hexdump": true, "xxd": true, "strings": true, "tree": true,
	"ls": true, "grep": true, "egrep": true, "fgrep": true, "rg": true, "ag": true,
	"realpath": true, "basename": true, "dirname": true,
}

// deleteCmds contains commands whose positional paths are deletions.
var deleteCmds = map[string]bool{
	"rm": true, "rmdir": true, "unlink": true, "shred": true,
}

// createOrModify contains commands whose positional paths are writes.
var createOrModify = map[string]bool{
	"touch": true, "mkdir": true, "tee": true,
	"chmod": true, "chown": true, "chgrp": true,
}

// isFlag reports whether arg looks like a command-line option.
func isFlag(arg string) bool {
	return strings.HasPrefix(arg, "-") && arg != "-"
}

// looksLikePath reports whether arg can be treated as a path candidate.
func looksLikePath(arg string) bool {
	if arg == "" || isFlag(arg) {
		return false
	}
	return true
}

// Classify extracts path accesses from one parsed command.
func Classify(cmd shellparse.Command) []Access {
	var out []Access
	cmd = shellparse.Unwrap(cmd)

	name := baseName(cmd.Name())
	args := cmd.Argv
	if len(args) > 0 {
		args = args[1:]
	}

	switch {
	case readOnly[name]:
		for _, a := range args {
			if looksLikePath(a) {
				out = append(out, newAccess(a, OpRead))
			}
		}
	case deleteCmds[name]:
		for _, a := range args {
			if looksLikePath(a) {
				out = append(out, newAccess(a, OpDelete))
			}
		}
	case createOrModify[name]:
		for _, a := range args {
			if looksLikePath(a) {
				out = append(out, newAccess(a, OpWrite))
			}
		}
	case name == "cp" || name == "mv" || name == "install" || name == "ln":
		out = append(out, classifyCopyLike(name, args)...)
	case name == "sed":
		out = append(out, classifySed(args)...)
	case name == "find":
		out = append(out, classifyFind(args)...)
	case name == "dd":
		out = append(out, classifyDD(args)...)
	}

	for _, r := range cmd.Redirects {
		switch {
		case r.Target == "":
			continue
		case r.Op == "<":
			out = append(out, newAccess(r.Target, OpRead))
		case r.Op == "<<" || r.Op == "<<-" || r.Op == "<<<":
			// Here-document and here-string targets are not paths.
		default:
			out = append(out, newAccess(r.Target, OpWrite))
		}
	}

	return out
}

// classifyCopyLike classifies sources and destinations for copy-like commands.
func classifyCopyLike(name string, args []string) []Access {
	if name == "install" && hasOption(args, "-d", "--directory") {
		var out []Access
		for _, path := range copyPositionals(args) {
			out = append(out, newAccess(path, OpWrite))
		}
		return out
	}

	targetDirectory, paths := copyTargetAndPositionals(args)
	if targetDirectory != "" {
		var out []Access
		for _, source := range paths {
			out = append(out, newAccess(source, OpRead))
			if name == "mv" {
				out = append(out, newAccess(source, OpDelete))
			}
		}
		out = append(out, newAccess(targetDirectory, OpWrite))
		return out
	}

	if len(paths) == 0 {
		return nil
	}
	var out []Access
	dest := paths[len(paths)-1]
	sources := paths[:len(paths)-1]
	for _, s := range sources {
		out = append(out, newAccess(s, OpRead))
		if name == "mv" {
			out = append(out, newAccess(s, OpDelete))
		}
	}
	out = append(out, newAccess(dest, OpWrite))
	return out
}

func hasOption(args []string, short, long string) bool {
	for _, a := range args {
		if a == short || a == long {
			return true
		}
	}
	return false
}

func copyPositionals(args []string) []string {
	_, positional := copyTargetAndPositionals(args)
	return positional
}

// copyTargetAndPositionals parses the destination-bearing options shared by
// GNU and BSD variants of cp, mv, install, and ln.
func copyTargetAndPositionals(args []string) (string, []string) {
	var target string
	var positional []string
	optionsDone := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if optionsDone {
			positional = append(positional, a)
			continue
		}
		switch {
		case a == "--":
			optionsDone = true
		case a == "-t" || a == "--target-directory":
			if i+1 < len(args) {
				i++
				target = args[i]
			}
		case strings.HasPrefix(a, "--target-directory="):
			target = strings.TrimPrefix(a, "--target-directory=")
		case strings.HasPrefix(a, "-t") && len(a) > 2:
			target = a[2:]
		case optionConsumesNext(a):
			if i+1 < len(args) {
				i++
			}
		case isFlag(a):
		default:
			positional = append(positional, a)
		}
	}
	return target, positional
}

func optionConsumesNext(option string) bool {
	switch option {
	case "-S", "--suffix":
		return true
	case "-m", "--mode", "-o", "--owner", "-g", "--group", "--strip-program":
		return true
	default:
		return false
	}
}

// classifySed treats input files as writes only when in-place mode is enabled.
func classifySed(args []string) []Access {
	inPlace := false
	var files []string
	for _, a := range args {
		if a == "-i" || strings.HasPrefix(a, "-i") || a == "--in-place" || strings.HasPrefix(a, "--in-place=") {
			inPlace = true
			continue
		}
		if looksLikePath(a) {
			files = append(files, a)
		}
	}
	op := OpRead
	if inPlace {
		op = OpWrite
	}
	var out []Access
	// The first non-option argument is normally the sed program, not a path.
	if len(files) > 1 {
		files = files[1:]
	} else {
		files = nil
	}
	for _, f := range files {
		out = append(out, newAccess(f, op))
	}
	return out
}

// classifyFind treats roots as deletions when a destructive action is present.
func classifyFind(args []string) []Access {
	destructive := false
	var roots []string
	collectingRoots := true
	for _, a := range args {
		if collectingRoots {
			if a == "-H" || a == "-L" || a == "-P" || strings.HasPrefix(a, "-O") {
				continue
			}
			if looksLikePath(a) {
				roots = append(roots, a)
				continue
			}
			collectingRoots = false
		}
		if a == "-delete" {
			destructive = true
		}
		// Conservatively treat rm or mv in an incompletely parsed -exec clause as destructive.
		if a == "rm" || a == "mv" {
			destructive = true
		}
	}
	op := OpRead
	if destructive {
		op = OpDelete
	}
	var out []Access
	for _, r := range roots {
		out = append(out, newAccess(r, op))
	}
	return out
}

// classifyDD classifies dd if= and of= operands.
func classifyDD(args []string) []Access {
	var out []Access
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "if="):
			out = append(out, newAccess(strings.TrimPrefix(a, "if="), OpRead))
		case strings.HasPrefix(a, "of="):
			out = append(out, newAccess(strings.TrimPrefix(a, "of="), OpWrite))
		}
	}
	return out
}

func newAccess(path string, op Op) Access {
	return Access{
		Path:          path,
		Op:            op,
		Indeterminate: containsUnresolved(path),
	}
}

func containsUnresolved(path string) bool {
	return strings.ContainsAny(path, "$`")
}

func baseName(cmdName string) string {
	// Use the base name so absolute argv[0] values still match.
	return filepath.Base(cmdName)
}

// Worst returns the most severe operation in accesses.
func Worst(accesses []Access) Op {
	var worst Op
	for _, a := range accesses {
		if a.Op.rank() > worst.rank() {
			worst = a.Op
		}
	}
	return worst
}

// CWDState describes the working directory at one point in a command chain.
type CWDState struct {
	Path string
	// Indeterminate means subsequent relative paths cannot be resolved reliably.
	Indeterminate bool
}

// Symlink describes a symbolic link created earlier in the same command chain.
type Symlink struct {
	Link   string // Absolute path of the link itself.
	Target string // Absolute path of the link target.
}

// RewriteThroughPending rewrites an absolute path through links that are
// created earlier in the same chain but do not exist during analysis.
func RewriteThroughPending(path string, links []Symlink) string {
	bestLen := -1
	var best Symlink
	for _, l := range links {
		if l.Link == "" {
			continue
		}
		if path == l.Link || strings.HasPrefix(path, l.Link+string(filepath.Separator)) {
			if len(l.Link) > bestLen {
				bestLen = len(l.Link)
				best = l
			}
		}
	}
	if bestLen < 0 {
		return path
	}
	return filepath.Join(best.Target, strings.TrimPrefix(path, best.Link))
}

// TrackCWD returns the effective CWD and pending symbolic links before each
// command. A directory change that a shell scope makes unreliable marks every
// following command indeterminate, so relative paths are not incorrectly
// assumed to remain inside the project. A command that only shares a pipeline,
// branch, or loop with such a scope keeps its own known directory.
func TrackCWD(subcmds []shellparse.Command, startCWD, home string) ([]CWDState, [][]Symlink) {
	states := make([]CWDState, len(subcmds))
	linksBefore := make([][]Symlink, len(subcmds))
	cur := CWDState{Path: startCWD}
	var links []Symlink
	for i, sc := range subcmds {
		unwrapped := shellparse.Unwrap(sc)
		state := cur
		if unwrapped.CWDOverride != "" {
			override := Resolve(cur.Path, home, unwrapped.CWDOverride)
			if containsUnresolved(unwrapped.CWDOverride) {
				state = CWDState{Indeterminate: true}
			} else if info, err := os.Stat(override); err == nil && info.IsDir() {
				state = CWDState{Path: override}
			} else {
				state = CWDState{Indeterminate: true}
			}
		}
		if sc.IndeterminateScope {
			state.Indeterminate = true
		}
		states[i] = state
		linksBefore[i] = links[:len(links):len(links)]

		// A link persists on the filesystem even when it is created by a child
		// shell, so it is tracked whenever its own location resolves.
		links = append(links, parseLnSymlinks(unwrapped, state, home, links)...)

		if baseName(unwrapped.Name()) != "cd" || unwrapped.CWDOverride != "" {
			continue
		}
		// A directory change made by a child shell, by a branch that may not run,
		// or inside a loop leaves the following commands without a known
		// directory. Only the directory change itself is contagious: commands
		// that merely share the same pipeline or branch keep their own directory.
		if sc.IsolatedScope || sc.ConditionalScope || sc.IndeterminateScope {
			// The last known directory is kept for reporting; it is also the
			// directory that still applies if the change never took effect.
			cur = CWDState{Path: cur.Path, Indeterminate: true}
			continue
		}
		var target string
		for _, a := range unwrapped.Argv[1:] {
			if !isFlag(a) {
				target = a
				break
			}
		}
		switch {
		case cur.Indeterminate:
			cur = CWDState{Indeterminate: true}
		case target == "":
			if home != "" {
				cur = tryCD(cur, CWDState{Path: home}, links)
			} else {
				cur = CWDState{Indeterminate: true}
			}
		case target == "-" || containsUnresolved(target):
			// Resolving `cd -` requires the unavailable $OLDPWD state.
			cur = CWDState{Indeterminate: true}
		default:
			cur = tryCD(cur, CWDState{Path: Resolve(cur.Path, home, target)}, links)
		}
	}
	return states, linksBefore
}

// tryCD returns candidate when it resolves to an existing directory, or from
// when the cd would fail.
func tryCD(from, candidate CWDState, links []Symlink) CWDState {
	resolved := RewriteThroughPending(candidate.Path, links)
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return from
	}
	return CWDState{Path: resolved}
}

// parseLnSymlinks returns symbolic links created by ln -s, including
// directory destinations, multiple sources, and GNU target-directory forms.
func parseLnSymlinks(sc shellparse.Command, cur CWDState, home string, pending []Symlink) []Symlink {
	if baseName(sc.Name()) != "ln" || cur.Indeterminate {
		return nil
	}
	symbolic := false
	noTargetDirectory := false
	targetDirectory := ""
	var positional []string
	args := sc.Argv[1:]
	optionsDone := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if optionsDone {
			positional = append(positional, a)
			continue
		}
		switch {
		case a == "--":
			optionsDone = true
		case a == "-s" || a == "--symbolic":
			symbolic = true
		case a == "-T" || a == "--no-target-directory":
			noTargetDirectory = true
		case a == "-t" || a == "--target-directory":
			if i+1 >= len(args) {
				return nil
			}
			i++
			targetDirectory = args[i]
		case strings.HasPrefix(a, "--target-directory="):
			targetDirectory = strings.TrimPrefix(a, "--target-directory=")
		case strings.HasPrefix(a, "--"):
			// Other long options do not affect link placement.
		case strings.HasPrefix(a, "-") && a != "-":
			if strings.ContainsRune(a, 's') {
				symbolic = true
			}
			if strings.ContainsRune(a, 'T') {
				noTargetDirectory = true
			}
		default:
			positional = append(positional, a)
		}
	}
	if !symbolic || len(positional) == 0 {
		return nil
	}

	if targetDirectory != "" {
		if containsUnresolved(targetDirectory) {
			return nil
		}
		var links []Symlink
		for _, source := range positional {
			if l := makePendingSymlink(cur, home, source, filepath.Join(targetDirectory, filepath.Base(source)), pending); l != nil {
				links = append(links, *l)
			}
		}
		return links
	}

	if len(positional) == 1 {
		source := positional[0]
		return symlinkSlice(makePendingSymlink(cur, home, source, filepath.Base(source), pending))
	}

	sources := positional[:len(positional)-1]
	destination := positional[len(positional)-1]
	if containsUnresolved(destination) {
		return nil
	}

	destinationPath := RewriteThroughPending(Resolve(cur.Path, home, destination), pending)
	destinationIsDir := len(sources) > 1
	if !destinationIsDir && !noTargetDirectory {
		if info, err := os.Stat(destinationPath); err == nil && info.IsDir() {
			destinationIsDir = true
		}
	}

	var links []Symlink
	for _, source := range sources {
		linkPath := destination
		if destinationIsDir {
			linkPath = filepath.Join(destination, filepath.Base(source))
		}
		if l := makePendingSymlink(cur, home, source, linkPath, pending); l != nil {
			links = append(links, *l)
		}
	}
	return links
}

func symlinkSlice(link *Symlink) []Symlink {
	if link == nil {
		return nil
	}
	return []Symlink{*link}
}

// makePendingSymlink resolves a link and target to absolute paths. Relative
// link targets are interpreted from the link's directory.
func makePendingSymlink(cur CWDState, home, source, linkPath string, pending []Symlink) *Symlink {
	if containsUnresolved(source) || containsUnresolved(linkPath) {
		return nil
	}
	link := RewriteThroughPending(Resolve(cur.Path, home, linkPath), pending)
	targetBase := filepath.Dir(link)
	if filepath.IsAbs(source) || source == "~" || strings.HasPrefix(source, "~/") {
		targetBase = cur.Path
	}
	return &Symlink{
		Link:   link,
		Target: RewriteThroughPending(Resolve(targetBase, home, source), pending),
	}
}

// Resolve expands a leading tilde and converts path to a clean absolute path.
func Resolve(cwd, home, path string) string {
	if path == "" {
		return path
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home != "" {
			path = filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	return filepath.Clean(path)
}

// ResolvePhysical resolves symlinks in the longest existing ancestor and
// rejoins missing trailing components.
func ResolvePhysical(path string) string {
	if path == "" {
		return path
	}
	p := path
	var suffix []string
	for {
		if _, err := os.Lstat(p); err == nil {
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			return path
		}
		suffix = append([]string{filepath.Base(p)}, suffix...)
		p = parent
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return path
	}
	if len(suffix) == 0 {
		return real
	}
	return filepath.Join(append([]string{real}, suffix...)...)
}

// IsOutside reports whether resolvedPath is outside resolvedRoot.
func IsOutside(resolvedRoot, resolvedPath string) bool {
	rel, err := filepath.Rel(resolvedRoot, resolvedPath)
	if err != nil {
		return true
	}
	if rel == "." {
		return false
	}
	return strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".."
}
