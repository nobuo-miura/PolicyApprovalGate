// Package gitpush detects force pushes, deletions, and direct pushes to
// protected branches, including refspec and branch-omitting forms.
package gitpush

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nobuo-miura/policyapprovalgate/internal/shellparse"
)

// Config defines which pushes to protected branches are blocked.
type Config struct {
	// Names contains protected branch names matched exactly.
	Names []string
	// BlockForcePush rejects force pushes to protected branches.
	BlockForcePush bool
	// BlockDelete rejects deletion of protected branches.
	BlockDelete bool
	// BlockDirectPush rejects direct pushes regardless of force flags.
	BlockDirectPush bool
}

// Verdict is the result of checking one git push command.
type Verdict struct {
	Blocked bool
	Reason  string
}

// none is the zero-value verdict for no violation.
var none = Verdict{}

// Check evaluates a parsed git push command against cfg. For pushes without a
// refspec it resolves the configured push branch, then falls back to HEAD.
func Check(cmd shellparse.Command, cwd string, cfg Config) Verdict {
	if len(cfg.Names) == 0 {
		return none
	}
	unwrapped := shellparse.Unwrap(cmd)
	unresolvedCWD := containsUnresolvedExpansion(unwrapped.CWDOverride) || containsUnresolvedGitC(unwrapped.Argv)
	if unwrapped.CWDOverride != "" {
		cwd = applyChdir(cwd, unwrapped.CWDOverride)
	}
	argv, gitCWD, gitOptions := normalizeGit(unwrapped.Argv, cwd)
	if len(argv) < 1 || argv[0] != "push" {
		return none
	}
	args := argv[1:]

	forceAll := false
	deleteAll := false
	pushMirror := false
	pushAll := false
	pushPrune := false
	repositoryFromOption := false
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-f" || a == "--force" || strings.HasPrefix(a, "--force-with-lease") || strings.HasPrefix(a, "--force-if-includes"):
			forceAll = true
		case a == "-d" || a == "--delete":
			deleteAll = true
		case a == "--mirror":
			pushMirror = true
		case a == "--all" || a == "--branches":
			// git documents --branches as a synonym for --all.
			pushAll = true
		case a == "--prune":
			pushPrune = true
		case a == "--repo":
			repositoryFromOption = true
			i++
		case strings.HasPrefix(a, "--repo="):
			repositoryFromOption = true
		case pushOptionConsumesNext(a):
			i++
		case strings.HasPrefix(a, "--receive-pack=") || strings.HasPrefix(a, "--exec=") || strings.HasPrefix(a, "--push-option="):
		case strings.HasPrefix(a, "--"):
			// Ignore long options that do not change protected-branch impact.
		case strings.HasPrefix(a, "-") && a != "-":
			// Short options cluster, so -fu is --force plus --set-upstream.
			flags := a[1:]
			forceAll = forceAll || strings.ContainsRune(flags, 'f')
			deleteAll = deleteAll || strings.ContainsRune(flags, 'd')
			if strings.ContainsRune(flags, 'o') {
				i++
			}
		default:
			positional = append(positional, a)
		}
	}

	var refspecs []string
	if repositoryFromOption {
		refspecs = positional
	} else if len(positional) > 0 {
		// The first positional is the repository or remote; the rest are refspecs.
		refspecs = positional[1:]
	}

	// --mirror force-updates differing refs and deletes remote-only refs.
	if pushMirror && (cfg.BlockForcePush || cfg.BlockDelete) {
		return Verdict{Blocked: true, Reason: "git push --mirror force-updates and deletes remote refs to match local exactly, which can hit a protected branch (" + strings.Join(cfg.Names, ", ") + ")"}
	}
	if pushPrune && cfg.BlockDelete {
		return Verdict{Blocked: true, Reason: "git push --prune can delete a protected branch (" + strings.Join(cfg.Names, ", ") + ")"}
	}
	// --all pushes all local branches without inherently forcing or deleting.
	if pushAll && ((forceAll && cfg.BlockForcePush) || cfg.BlockDirectPush) {
		return Verdict{Blocked: true, Reason: "git push --all can push a protected branch (" + strings.Join(cfg.Names, ", ") + ")"}
	}

	if len(refspecs) == 0 {
		if unresolvedCWD && (forceAll || deleteAll || cfg.BlockDirectPush) {
			return Verdict{Blocked: true, Reason: "git push working directory cannot be resolved and may select a protected branch (" + strings.Join(cfg.Names, ", ") + ")"}
		}
		branch, err := pushBranch(gitCWD, gitOptions)
		if err != nil || branch == "" {
			return none
		}
		return evalTarget(cfg, branch, forceAll, deleteAll)
	}

	for _, rs := range refspecs {
		force := forceAll
		spec := rs
		if strings.HasPrefix(spec, "+") {
			force = true
			spec = spec[1:]
		}
		dst := spec
		isDelete := deleteAll
		if idx := strings.Index(spec, ":"); idx >= 0 {
			src := spec[:idx]
			dst = spec[idx+1:]
			if src == "" {
				// ":dst" is a deletion refspec for dst.
				isDelete = true
			}
		} else if spec == "HEAD" || spec == "@" {
			branch, err := currentBranch(gitCWD, gitOptions)
			if err != nil || branch == "" {
				// A symbolic source without an explicit destination is unsafe to
				// classify when Git cannot resolve the branch it will update.
				if force || isDelete || cfg.BlockDirectPush {
					return Verdict{Blocked: true, Reason: "cannot resolve destination branch for git push " + spec}
				}
				continue
			}
			dst = branch
		}
		dst = strings.TrimPrefix(dst, "refs/heads/")
		if dst == "" {
			continue
		}
		// A destination decided at run time, as in git push -f origin "$branch",
		// may well be a protected branch, so it is not assumed to be safe.
		if containsUnresolvedExpansion(dst) {
			if (isDelete && cfg.BlockDelete) || (force && cfg.BlockForcePush) || cfg.BlockDirectPush {
				return Verdict{Blocked: true, Reason: "destination of git push " + rs +
					" cannot be resolved and may be a protected branch (" + strings.Join(cfg.Names, ", ") + ")"}
			}
			continue
		}
		if v := evalTarget(cfg, dst, force, isDelete); v.Blocked {
			return v
		}
	}
	return none
}

func normalizeGit(argv []string, cwd string) ([]string, string, []string) {
	if len(argv) == 0 || trimExecutable(baseName(argv[0])) != "git" {
		return nil, cwd, nil
	}
	var globalOptions []string
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-C":
			if i+1 < len(argv) {
				cwd = applyChdir(cwd, argv[i+1])
				i++
				continue
			}
			return nil, cwd, nil
		case strings.HasPrefix(a, "-C") && len(a) > 2:
			cwd = applyChdir(cwd, a[2:])
		case gitGlobalOptionConsumesNext(a):
			if i+1 < len(argv) {
				if forwardableGitOption(a) {
					globalOptions = append(globalOptions, a, argv[i+1])
				}
				i++
				continue
			}
			return nil, cwd, nil
		case strings.HasPrefix(a, "--git-dir=") || strings.HasPrefix(a, "--work-tree=") || strings.HasPrefix(a, "--namespace="):
			globalOptions = append(globalOptions, a)
		case strings.HasPrefix(a, "--config-env=") || strings.HasPrefix(a, "--exec-path="):
			// Not forwarded, for the reason given on forwardableGitOption.
		case strings.HasPrefix(a, "-"):
		default:
			return argv[i:], filepath.Clean(cwd), globalOptions
		}
	}
	return nil, filepath.Clean(cwd), globalOptions
}

// applyChdir resolves a directory selected by git -C or an env -C wrapper.
func applyChdir(cwd, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(cwd, path)
}

// containsUnresolvedGitC reports whether git -C selects its repository through
// a variable or command substitution that is resolved only at execution time.
func containsUnresolvedGitC(argv []string) bool {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "push":
			return false
		case a == "-C":
			if i+1 < len(argv) && containsUnresolvedExpansion(argv[i+1]) {
				return true
			}
			i++
		case strings.HasPrefix(a, "-C") && len(a) > 2:
			if containsUnresolvedExpansion(a[2:]) {
				return true
			}
		}
	}
	return false
}

// gitGlobalOptionConsumesNext reports whether a global option takes a separate
// argument. Parsing skips that argument even for options that are not
// forwarded, so the push subcommand is still located correctly.
func gitGlobalOptionConsumesNext(option string) bool {
	switch option {
	case "-c", "--config-env", "--exec-path", "--git-dir", "--work-tree", "--namespace":
		return true
	default:
		return false
	}
}

// forwardableGitOption reports whether a global option only locates the
// repository. Options that inject configuration or relocate git's helper
// programs (-c, --config-env, --exec-path) are dropped: the branch lookup runs
// before the host has approved the command, so the command being inspected must
// not be able to steer policygate's own git subprocess.
func forwardableGitOption(option string) bool {
	switch option {
	case "--git-dir", "--work-tree", "--namespace":
		return true
	default:
		return false
	}
}

func pushOptionConsumesNext(option string) bool {
	switch option {
	case "--repo", "--receive-pack", "--exec", "--push-option", "-o":
		return true
	default:
		return false
	}
}

func trimExecutable(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".exe")
}

func evalTarget(cfg Config, branch string, force, isDelete bool) Verdict {
	if !isProtected(cfg.Names, branch) {
		return none
	}
	switch {
	case isDelete && cfg.BlockDelete:
		return Verdict{Blocked: true, Reason: "deletes " + describeTarget(branch)}
	case force && cfg.BlockForcePush:
		return Verdict{Blocked: true, Reason: "force-pushes to " + describeTarget(branch)}
	case cfg.BlockDirectPush:
		return Verdict{Blocked: true, Reason: "pushes directly to " + describeTarget(branch)}
	default:
		return none
	}
}

// containsUnresolvedExpansion reports whether a refspec still holds a variable
// or command substitution that only the shell can resolve.
func containsUnresolvedExpansion(spec string) bool {
	return strings.ContainsAny(spec, "$`")
}

// describeTarget names the push destination, distinguishing a literal branch
// from a refspec pattern that can expand onto one.
func describeTarget(branch string) string {
	if strings.ContainsAny(branch, "*?[") {
		return "a protected branch through refspec " + branch
	}
	return "protected branch " + branch
}

func isProtected(names []string, branch string) bool {
	for _, n := range names {
		if n == branch {
			return true
		}
		// A wildcard refspec such as refs/heads/*:refs/heads/* expands on the
		// remote, so it is treated as covering every protected branch it can
		// reach rather than as a literal branch name.
		if strings.ContainsAny(branch, "*?[") {
			if ok, err := filepath.Match(branch, n); err == nil && ok {
				return true
			}
		}
	}
	return false
}

func pushBranch(cwd string, globalOptions []string) (string, error) {
	if branch, err := resolvePushBranch(cwd, globalOptions); err == nil && branch != "" {
		return branch, nil
	}
	return currentBranch(cwd, globalOptions)
}

func resolvePushBranch(cwd string, globalOptions []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	args := append(append([]string{}, globalOptions...), "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{push}")
	// args holds only repository-locating options; see forwardableGitOption.
	cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204 -- only repository-locating options are forwarded
	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	ref := strings.TrimSpace(string(out))
	if _, branch, ok := strings.Cut(ref, "/"); ok {
		return branch, nil
	}
	return ref, nil
}

func currentBranch(cwd string, globalOptions []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	args := append(append([]string{}, globalOptions...), "symbolic-ref", "--short", "HEAD")
	// args holds only repository-locating options; see forwardableGitOption.
	cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204 -- only repository-locating options are forwarded
	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func baseName(path string) string {
	if idx := strings.LastIndexByte(path, '/'); idx >= 0 {
		return path[idx+1:]
	}
	return path
}
