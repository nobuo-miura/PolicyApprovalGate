// Package hook defines the shared PreToolUse input and output protocol used by
// Claude Code and Codex CLI.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
)

// Input is the JSON payload received by a PreToolUse hook.
type Input struct {
	SessionID      string    `json:"session_id"`
	TranscriptPath string    `json:"transcript_path"`
	CWD            string    `json:"cwd"`
	PermissionMode string    `json:"permission_mode"`
	HookEventName  string    `json:"hook_event_name"`
	ToolName       string    `json:"tool_name"`
	ToolInput      ToolInput `json:"tool_input"`
	ToolUseID      string    `json:"tool_use_id"`
}

// ToolInput contains whatever the tool being evaluated was handed: a shell
// command, or the path of a file to read or change.
//
// Only one of the two is ever set. Which one is decided by the tool name
// rather than by which field arrived, so a payload carrying both cannot pick
// the analysis it would rather face.
type ToolInput struct {
	Command  string `json:"command"`
	FilePath string `json:"file_path"`
}

// ReadInput decodes a PreToolUse payload from r.
func ReadInput(r io.Reader) (Input, error) {
	var in Input
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return Input{}, fmt.Errorf("decode hook input: %w", err)
	}
	return in, nil
}

// Decision is a policy decision returned to the host.
type Decision string

const (
	// DecisionDeny rejects a command on both supported hosts.
	DecisionDeny Decision = "deny"
	// DecisionAsk requests confirmation. Codex CLI does not enforce this value.
	DecisionAsk Decision = "ask"
)

type output struct {
	HookSpecificOutput *hookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type hookSpecificOutput struct {
	HookEventName            string   `json:"hookEventName"`
	PermissionDecision       Decision `json:"permissionDecision"`
	PermissionDecisionReason string   `json:"permissionDecisionReason,omitempty"`
}

// WriteDecision encodes a decision to w. An empty decision emits nothing and
// delegates to the host's normal approval flow.
func WriteDecision(w io.Writer, decision Decision, reason string) error {
	if decision == "" {
		return nil
	}
	out := output{
		HookSpecificOutput: &hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       decision,
			PermissionDecisionReason: reason,
		},
	}
	enc := json.NewEncoder(w)
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encode hook output: %w", err)
	}
	return nil
}
