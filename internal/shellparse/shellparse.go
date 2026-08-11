// Package shellparse decomposes shell source into simple commands and
// redirects without executing expansions or command substitutions.
package shellparse

import (
	"bytes"
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Redirect describes one input or output redirect.
type Redirect struct {
	Op     string
	Target string
}

// Command describes one simple command extracted from a compound command.
type Command struct {
	// Argv includes argv[0]. Unresolved expansions remain unexpanded.
	Argv []string
	// ArgvRaw holds each argument as written, with its quoting intact. Matching
	// a resolved program name against raw arguments keeps an argument's contents
	// from being read as command syntax.
	ArgvRaw []string
	// Raw is the original simple command, including redirects.
	Raw string
	// Redirects contains redirects attached to this command.
	Redirects []Redirect
	// IndeterminateScope marks commands whose own working directory cannot be
	// derived from the linear order of the chain, such as a command in a loop
	// body that changes directory between iterations.
	IndeterminateScope bool
	// IsolatedScope marks commands that run in a child shell — a subshell,
	// pipeline component, command substitution, process substitution, or
	// background statement — so a directory change they perform cannot affect
	// the working directory of the parent shell.
	IsolatedScope bool
	// ConditionalScope marks commands that may or may not run, such as the body
	// of an if, case, or loop, a function body, or either side of ||.
	ConditionalScope bool
	// CWDOverride is a directory selected by a transparent wrapper such as env -C.
	CWDOverride string
	// Background marks commands executed asynchronously in a child shell.
	Background bool
}

// Name returns argv[0], or an empty string when Argv is empty.
func (c Command) Name() string {
	if len(c.Argv) == 0 {
		return ""
	}
	return c.Argv[0]
}

// Parse splits cmd into simple commands. It returns an error for invalid shell
// syntax. Callers must handle that error conservatively.
func Parse(cmd string) ([]Command, error) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err != nil {
		return nil, fmt.Errorf("parse shell command: %w", err)
	}

	printer := syntax.NewPrinter()
	print := func(node syntax.Node) string {
		if node == nil {
			return ""
		}
		var buf bytes.Buffer
		if err := printer.Print(&buf, node); err != nil {
			return ""
		}
		return buf.String()
	}

	scopes := markScopes(f)

	var commands []Command
	syntax.Walk(f, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok {
			return true
		}

		argv := make([]string, 0, len(call.Args))
		argvRaw := make([]string, 0, len(call.Args))
		for _, w := range call.Args {
			argv = append(argv, wordValue(w, print))
			argvRaw = append(argvRaw, print(w))
		}

		redirs := make([]Redirect, 0, len(stmt.Redirs))
		for _, r := range stmt.Redirs {
			redirs = append(redirs, Redirect{
				Op:     r.Op.String(),
				Target: wordValue(r.Word, print),
			})
		}

		background := stmt.Background || stmt.Coprocess || stmt.Disown
		scope := scopes[stmt]
		commands = append(commands, Command{
			Argv:               argv,
			ArgvRaw:            argvRaw,
			Raw:                strings.TrimSpace(print(stmt)),
			Redirects:          redirs,
			IndeterminateScope: scope.indeterminate,
			IsolatedScope:      scope.isolated || background,
			ConditionalScope:   scope.conditional,
			Background:         background,
		})
		return true
	})
	return commands, nil
}

// scope describes how an enclosing shell construct affects a statement.
type scope struct {
	// indeterminate means the statement's own working directory cannot be
	// derived from the linear order of the chain.
	indeterminate bool
	// isolated means the statement runs in a child shell.
	isolated bool
	// conditional means the statement may or may not run.
	conditional bool
}

// markScopes records the scope characteristics of every statement in f. Scopes
// nest, so a statement inherits every construct it is contained in.
func markScopes(f *syntax.File) map[*syntax.Stmt]scope {
	out := make(map[*syntax.Stmt]scope)
	apply := func(root syntax.Node, set func(*scope)) {
		syntax.Walk(root, func(node syntax.Node) bool {
			if stmt, ok := node.(*syntax.Stmt); ok {
				s := out[stmt]
				set(&s)
				out[stmt] = s
			}
			return true
		})
	}
	isolate := func(s *scope) { s.isolated = true }
	condition := func(s *scope) { s.conditional = true }

	syntax.Walk(f, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst:
			apply(node, isolate)
		case *syntax.BinaryCmd:
			switch node.Op {
			case syntax.Pipe, syntax.PipeAll:
				apply(node, isolate)
			case syntax.OrStmt:
				// Whether the right side runs depends on the left side's status,
				// so neither side establishes a directory for what follows.
				apply(node, condition)
			}
		case *syntax.IfClause, *syntax.CaseClause, *syntax.FuncDecl:
			apply(node, condition)
		case *syntax.ForClause, *syntax.WhileClause:
			apply(node, condition)
			if changesDirectory(node) {
				// A later iteration re-runs the body from whatever directory the
				// previous iteration left behind, so linear order proves nothing.
				apply(node, func(s *scope) { s.indeterminate = true })
			}
		}
		return true
	})
	return out
}

// changesDirectory reports whether any command below node may change the
// working directory. It errs toward true so loops stay conservative.
func changesDirectory(node syntax.Node) bool {
	found := false
	syntax.Walk(node, func(n syntax.Node) bool {
		call, ok := n.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		for i, word := range call.Args {
			value := literalWord(word)
			if i == 0 {
				switch baseName(value) {
				case "cd", "pushd", "popd":
					found = true
					return false
				}
				continue
			}
			// env -C and similar wrappers relocate the command they run.
			if value == "-C" || value == "--chdir" || strings.HasPrefix(value, "--chdir=") {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// literalWord returns the statically known text of word, or an empty string.
func literalWord(word *syntax.Word) string {
	var value strings.Builder
	if appendWordParts(&value, word.Parts, false, nil) {
		return value.String()
	}
	return ""
}

func wordValue(word *syntax.Word, fallback func(syntax.Node) string) string {
	var value strings.Builder
	if appendWordParts(&value, word.Parts, false, fallback) {
		return value.String()
	}
	return fallback(word)
}

// appendWordParts resolves quoting while preserving dynamic expansions through
// render. A nil renderer keeps literalWord restricted to fully static words.
func appendWordParts(dst *strings.Builder, parts []syntax.WordPart, inDouble bool, render func(syntax.Node) string) bool {
	for _, part := range parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if inDouble {
				dst.WriteString(unescapeDoubleQuoted(part.Value))
			} else {
				dst.WriteString(part.Value)
			}
		case *syntax.SglQuoted:
			dst.WriteString(part.Value)
		case *syntax.DblQuoted:
			if !appendWordParts(dst, part.Parts, true, render) {
				return false
			}
		default:
			if render == nil {
				return false
			}
			dst.WriteString(render(part))
		}
	}
	return true
}

// unescapeDoubleQuoted applies the shell's limited backslash semantics inside
// double quotes. A backslash is special only before $, `, ", \\, or newline.
func unescapeDoubleQuoted(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' || i+1 >= len(value) {
			out.WriteByte(value[i])
			continue
		}
		next := value[i+1]
		switch next {
		case '$', '`', '"', '\\':
			out.WriteByte(next)
			i++
		case '\n':
			i++
		default:
			out.WriteByte(value[i])
		}
	}
	return out.String()
}

// Unwrap removes common transparent command wrappers. It intentionally stops
// when an option cannot be interpreted without executing shell semantics.
func Unwrap(cmd Command) Command {
	argv, argvRaw := cmd.Argv, cmd.ArgvRaw

unwrapLoop:
	for budget := 0; len(argv) > 0 && budget < 16; budget++ {
		name := baseName(argv[0])
		if spec, ok := wrappers[name]; ok {
			n := spec.strip(argv)
			argv, argvRaw = dropN(argv, n), dropN(argvRaw, n)
			continue
		}
		if name != "env" {
			break
		}
		n, split := stripEnv(argv, &cmd.CWDOverride)
		if split != "" {
			// env -S performs its own word splitting and quote removal, so the
			// string is re-parsed rather than treated as one opaque argument. env
			// appends every argument following the split string to that result.
			if inner, err := Parse(split); err == nil && len(inner) > 0 {
				rest, restRaw := dropN(argv, n), dropN(argvRaw, n)
				argv = append(append([]string(nil), inner[0].Argv...), rest...)
				argvRaw = append(append([]string(nil), inner[0].ArgvRaw...), restRaw...)
				continue
			}
			break unwrapLoop
		}
		argv, argvRaw = dropN(argv, n), dropN(argvRaw, n)
	}
	cmd.Argv, cmd.ArgvRaw = normalizeArgv0(argv), argvRaw
	return cmd
}

// dropN removes the first n elements, tolerating a count past the end.
func dropN(argv []string, n int) []string {
	if n >= len(argv) {
		return nil
	}
	return argv[n:]
}

// stripEnv reports how many leading arguments belong to env, recording any -C
// directory. A non-empty second result is an -S string to re-parse.
func stripEnv(argv []string, cwdOverride *string) (int, string) {
	for i := 1; i < len(argv); {
		a := argv[i]
		switch {
		case a == "--":
			return i + 1, ""
		case a == "-C" || a == "--chdir":
			if i+1 < len(argv) {
				*cwdOverride = argv[i+1]
			}
			i += 2
		case strings.HasPrefix(a, "--chdir="):
			*cwdOverride = strings.TrimPrefix(a, "--chdir=")
			i++
		case a == "-S" || a == "--split-string":
			if i+1 < len(argv) {
				return i + 2, argv[i+1]
			}
			i++
		case strings.HasPrefix(a, "--split-string="):
			return i + 1, strings.TrimPrefix(a, "--split-string=")
		case strings.HasPrefix(a, "-S") && len(a) > 2:
			return i + 1, a[2:]
		case a == "-u" || a == "--unset":
			i += 2
		case strings.HasPrefix(a, "-"):
			i++
		case strings.Contains(a, "="):
			i++
		default:
			return i, ""
		}
	}
	return len(argv), ""
}

// normalizeArgv0 drops the alias-suppressing backslash from a command name so
// callers that split on path separators still recognize it.
func normalizeArgv0(argv []string) []string {
	if len(argv) == 0 || !strings.HasPrefix(argv[0], `\`) {
		return argv
	}
	out := append([]string(nil), argv...)
	out[0] = strings.TrimPrefix(out[0], `\`)
	return out
}

func baseName(name string) string {
	// A leading backslash only suppresses alias expansion; \rm is still rm.
	name = strings.TrimPrefix(name, `\`)
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		return name[i+1:]
	}
	return name
}

// wrapperSpec describes a command that execs the command in its own arguments
// without otherwise changing what runs.
type wrapperSpec struct {
	// valueOptions are options that consume the following argument.
	valueOptions map[string]bool
	// operands is the number of leading non-option arguments that belong to the
	// wrapper rather than to the wrapped command, such as timeout's duration.
	operands int
}

// strip reports how many leading arguments belong to the wrapper itself.
func (s wrapperSpec) strip(argv []string) int {
	i, operands := 1, s.operands
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "--":
			return i + 1
		case s.valueOptions[a]:
			i += 2
		case strings.HasPrefix(a, "-") && a != "-":
			i++
		case operands > 0:
			operands--
			i++
		default:
			return i
		}
	}
	return len(argv)
}

// wrappers lists transparent wrappers. Missing one only costs detection, so
// entries stay limited to commands whose operand layout is unambiguous.
var wrappers = map[string]wrapperSpec{
	"command": {},
	"builtin": {},
	"nohup":   {},
	"setsid":  {},
	"time":    {},
	// Multi-call binaries take the applet name as their first operand.
	"busybox": {},
	"toybox":  {},
	"sudo":    {valueOptions: map[string]bool{"-u": true, "--user": true, "-g": true, "--group": true, "-p": true, "-C": true, "-U": true, "-r": true, "-t": true}},
	"doas":    {valueOptions: map[string]bool{"-u": true, "-C": true}},
	"nice":    {valueOptions: map[string]bool{"-n": true, "--adjustment": true}},
	"ionice":  {valueOptions: map[string]bool{"-c": true, "--class": true, "-n": true, "--classdata": true, "-p": true, "--pid": true}},
	"stdbuf":  {valueOptions: map[string]bool{"-i": true, "--input": true, "-o": true, "--output": true, "-e": true, "--error": true}},
	"timeout": {valueOptions: map[string]bool{"-s": true, "--signal": true, "-k": true, "--kill-after": true}, operands: 1},
	"xargs":   {valueOptions: map[string]bool{"-I": true, "--replace": true, "-i": true, "-n": true, "--max-args": true, "-L": true, "--max-lines": true, "-P": true, "--max-procs": true, "-d": true, "--delimiter": true, "-s": true, "--max-chars": true, "-E": true, "--eof": true, "-a": true, "--arg-file": true}},
}
