package main

import (
	"strings"

	"github.com/nobuo-miura/policyapprovalgate/internal/hook"
	"github.com/nobuo-miura/policyapprovalgate/internal/pathpolicy"
	"github.com/nobuo-miura/policyapprovalgate/internal/rules"
)

// fileTools maps the host tools that are handed a path directly to the access
// they perform on it.
//
// These tools reach the same files the shell does, so leaving them uninspected
// meant the gate enforced less than it documented: `cat ~/.ssh/id_rsa` asked
// while a Read of that file passed, and a shell write to policygate's own
// configuration was denied while a Write of it went through - which is enough
// to set mode: observe and turn every later decision off.
//
// Edit counts as a write rather than a delete: it changes a file's contents
// and leaves the file there.
var fileTools = map[string]pathpolicy.Op{
	"read":  pathpolicy.OpRead,
	"write": pathpolicy.OpWrite,
	"edit":  pathpolicy.OpWrite,
}

// fileToolOp reports the access a tool performs on the path it is given, and
// whether it is one of the tools handled this way at all.
func fileToolOp(toolName string) (pathpolicy.Op, bool) {
	op, ok := fileTools[strings.ToLower(toolName)]
	return op, ok
}

// fileToolAccesses reports the single access a file tool performs.
//
// There is no command to parse and no working directory to follow through a
// chain: the host names the file outright. Nothing in it can be obfuscated,
// spelled through a variable, or hidden behind a wrapper, which is why these
// tools are checked more reliably than any shell command.
func fileToolAccesses(path string, op pathpolicy.Op, cwd string) []trackedAccess {
	return []trackedAccess{{
		access: pathpolicy.Access{Path: path, Op: op},
		state:  pathpolicy.CWDState{Path: cwd},
	}}
}

// evaluateFileTool decides on a tool that was handed a path.
//
// Only the path policies apply. The deny, ask and allow rules match command
// text, and a bare path is not a command - running them here would test a
// filename against patterns written to recognize programs. The unknown
// fallback is skipped for the same reason: it answers "no rule matched this
// command", and applying it would turn unknown.action: ask into a prompt for
// every file the agent touches.
//
// What remains - sensitive_paths, protected_paths, path_scope and
// self-protection - is exactly the part that was written about paths, and it
// needs no adapting to work here.
func evaluateFileTool(cfg *rules.Config, in hook.Input, path string, op pathpolicy.Op) (decision hook.Decision, reason, source, matchedBy string) {
	d, r, src, matched := checkPathAccess(cfg, fileToolAccesses(path, op, in.CWD), in.CWD)
	switch d {
	case "deny":
		return hook.DecisionDeny, r, src, matched
	case "ask":
		return hook.DecisionAsk, r, src, matched
	}
	return "", "no path policy matched (host approval is never bypassed)", "file_tool", ""
}
