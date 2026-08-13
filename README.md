# PolicyApprovalGate

[English](README.md) | [日本語](README.ja.md)

PolicyApprovalGate is a PreToolUse hook that applies rule-based policies before Claude Code or Codex CLI runs a Bash command. It checks dangerous commands, pushes to protected branches, and access to out-of-project or sensitive paths, then records decisions in an audit log.

> [!IMPORTANT]
> PolicyApprovalGate complements your existing permission model, sandbox, and human review. It is neither a complete shell analyzer nor a security boundary, and should not be your only line of defense.

The built-in rules are intended to reduce missed, clearly dangerous operations, not to block every possible risk. By default, operations that cannot be classified are delegated to the host's normal approval flow.

## Features

- Deterministic rule evaluation without AI or an LLM
- Regex-based denial of dangerous commands
- Regex-based ask rules that prompt in Claude Code and are converted to deny in Codex
- Structural, always-on denial of recursive force-deletion targeting the filesystem root or current user's home
- Controls for force pushes, deletion, and direct pushes to protected branches
- Read / write / delete classification for path access
- Policies for out-of-project, sensitive, and protected paths
- Case-insensitive rule matching, so a filesystem that ignores case cannot be used to slip past a rule
- Path tracking that accounts for `cd` and symbolic links
- Normalization for `env` / `command`, `git -C`, and `cp/install -t`
- Analysis of statically quoted paths and critical deletes inside literal `sh/bash/zsh -c` and `eval` scripts
- Rotating audit logs with redacted, hashed, full, or omitted commands
- Configuration migration, validation, and diagnostics
- Host-specific decision handling through `--host`

## Evaluation order

1. Check deny rules
2. Parse the shell command
3. Check pushes to protected branches
4. Check ask rules (prompt in Claude Code; convert to deny in Codex)
5. Check path scope, sensitive paths, and protected paths
6. Classify every subcommand against allow rules for audit metadata
7. Apply `unknown.action` when nothing matches

An explicit denial always wins. By default, an unknown command is deferred to the host's normal approval flow rather than denied.

## Requirements

- Go 1.26
- PreToolUse hooks in Claude Code or Codex CLI

Fixture/golden compatibility baseline as of 2026-08-11:

| Host | Locally checked version |
| --- | --- |
| Codex CLI | 0.147.0 |
| Claude Code | 2.1.220 |

CI exercises input fixtures and golden return JSON to detect host-contract drift.

The currently supported runtime platforms are macOS and Linux. Windows is built and unit-tested in CI, but remains experimental until PowerShell tool-input support is complete.

## Quick start

### 1. Build

```bash
go build -o policygate ./cmd/policygate
sudo install -m 0755 policygate /usr/local/bin/policygate
```

After a tagged release, you can also install through Go. Configure the hook with the actual absolute path under `GOBIN` or `GOPATH/bin`.

```bash
go install github.com/nobuo-miura/policyapprovalgate/cmd/policygate@latest
```

### 2. Create a configuration file

```bash
policygate init
```

This creates `~/.policygate/config.yaml` by default. Set `POLICYGATE_CONFIG` to use another path. Existing files are not overwritten.

Merge new baseline protections into an older configuration with:

```bash
policygate init --upgrade
policygate check-config
```

`--upgrade` writes a `config.yaml.bak.*` copy beside the existing file before replacing it atomically.

List-valued sections in a user configuration (`deny`, `ask`, `allow`, `sensitive_paths.patterns`, and `protected_paths.patterns`) replace the built-in list at load time rather than merging into it. `--upgrade` therefore matches built-in rules by `pattern`, appends the ones the configuration no longer carries, and reports each restored rule as a warning. A rule you removed on purpose can come back, so read the warnings and delete anything you do not want.

### 3. Register the hook

#### Claude Code

Add the hook to `.claude/settings.json`. See [configs/claude-code.settings.example.json](configs/claude-code.settings.example.json) for the complete example.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/bin/policygate --host claude"
          }
        ]
      }
    ]
  }
}
```

#### Codex CLI

Add the hook to `~/.codex/config.toml`. See [configs/codex-config.example.toml](configs/codex-config.example.toml) for the complete example.

```toml
[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/local/bin/policygate --host codex"
```

Codex hooks are enabled by default. `codex_hooks` is a deprecated alias; the canonical feature key is now `hooks`. See the [official Codex Hooks documentation](https://learn.chatgpt.com/docs/hooks) for details.

After registering the hook, run `/hooks` in Codex, review the displayed command definition, and trust it. An untrusted or changed hook is skipped.

## Host behavior

| PolicyApprovalGate decision | Claude Code | Codex CLI |
| --- | --- | --- |
| `deny` | Denies the command | Denies the command |
| `ask` | Prompts the user | Standalone ask is unsupported, so `--host codex` converts it to deny |
| No decision | Uses the normal approval flow | Uses the normal approval flow |

When `--host` is omitted, PolicyApprovalGate safely treats the host as non-Claude and converts ask to deny. Always pass `--host claude` when registering the Claude Code hook.

## Configuration

See [internal/rules/default.yaml](internal/rules/default.yaml) for every built-in setting and default value.

| Section | Purpose |
| --- | --- |
| `config_version` | Configuration schema version |
| `mode` | `enforce` or audit-only `observe` |
| `deny` | Reject complete commands matched with Go RE2 expressions |
| `ask` | Prompt before specific commands in Claude Code and convert to deny in Codex (empty by default; add patterns such as git/gh write operations as needed) |
| `allow` | Classify familiar low-risk commands without bypassing approval |
| `protected_branches` | Control pushes to protected branches |
| `path_scope` | Control read / write / delete outside the project |
| `sensitive_paths` | Protect `.env`, SSH keys, credentials, and similar paths |
| `protected_paths` | Always deny writes and deletes to gate configuration and hook registration |
| `unknown` | `defer`, `ask`, or `deny` when no rule matches |
| `parse_error` | `defer`, `ask`, or `deny` when shell syntax cannot be parsed |
| `audit` | Configure path, command recording, and rotation |

To require confirmation when PolicyApprovalGate cannot classify a command, set the fallback actions to `ask`:

```yaml
unknown:
  action: ask

parse_error:
  action: ask
```

Claude Code prompts for these fallbacks. Codex does not support standalone `ask`, so PolicyApprovalGate converts the result to `deny`.

Note how far that conversion reaches: under Codex, `unknown.action: ask` **rejects every command that matches no rule**, including ordinary work such as `go build ./...` or `npm run build`. If neither `--host` nor `POLICYGATE_HOST` identifies Claude, the result is the same because an unspecified host is safely treated as non-Claude. Treat an `ask` fallback as a Claude Code setting and identify the host with `--host claude` or `POLICYGATE_HOST=claude`. Both `policygate check-config` and `policygate doctor` detect the setting and print a warning.

### Separate configuration files per host

The configuration has no per-host settings. If you use both hosts and want them to behave differently — `ask` under Claude Code but `defer` under Codex, for example — point each hook registration at its own file with `POLICYGATE_CONFIG`. The configuration is read on every hook call, so each host can carry an independent policy.

Claude Code (`settings.json`):

```json
"command": "/usr/bin/env POLICYGATE_CONFIG=/absolute/home/path/.policygate/claude.yaml /usr/local/bin/policygate --host claude"
```

Codex (`~/.codex/config.toml`):

```toml
command = "/usr/bin/env POLICYGATE_CONFIG=/absolute/home/path/.policygate/codex.yaml /usr/local/bin/policygate --host codex"
```

Keep both files under the user's `.policygate` directory and retain the generated `.policygate` entry in enabled `protected_paths`, so writes and deletes to them are denied. The paths above are placeholders; replace them with the absolute paths to `~/.policygate/claude.yaml` and `~/.policygate/codex.yaml`. `~` and `$HOME` are expanded only when the host runs the command through a shell, and an unexpanded value leaves the configuration file unreadable. If a policy must live elsewhere, add its path to `protected_paths.patterns` before registering the hook.

The policy now lives in two files, so take care that shared parts such as deny rules stay in sync. Note also that an unreadable path makes enforce mode deny the Bash call, so validate each file with `policygate check-config --config <path>` before registering the hook.

Allow rules classify familiar low-risk commands for audit metadata and never bypass host approval. Do not add command launchers such as `find -exec`, `xargs`, or `awk system()`; they produce misleading audit classifications even though they cannot bypass approval.

If an explicitly selected configuration file is unreadable or invalid, enforce mode denies the Bash call instead of silently falling back to embedded defaults. Only `policygate observe` remains non-blocking for diagnostic use.

## Path evaluation

PolicyApprovalGate parses shell syntax with `mvdan.cc/sh` and classifies supported path arguments as read, write, or delete. It also accounts for:

- An earlier `cd`, such as `cd /tmp && rm -rf target`
- Existing symbolic links inside the project that point outside it
- Links created earlier in the same chain, such as `ln -s /outside escape && ...`
- Actual link placement for `ln -s SRC EXISTING_DIR` and `ln -s -t DIR SRC`
- Destinations used by `cp -t DIR SRC` and `install --target-directory=DIR SRC`
- Transparent wrappers such as `env`, `command`, and `nohup`
- Quoted paths containing spaces
- Indeterminate paths containing unresolved variables or `cd -`
- A `cd` inside a pipeline, subshell, command substitution, background statement, or conditional branch, which leaves every later command without a known working directory
- Commands in a `for` or `while` body that changes directory

Only a `cd` in one of those positions makes anything indeterminate. A pipeline or branch with no `cd`, such as `cat a.txt | grep x > out.txt`, keeps its known working directory and is evaluated normally.

Unsupported commands produce no path accesses and continue to other rules or `unknown.action`.

### Case sensitivity

Rule matching (`deny`, `ask`, `allow`, `sensitive_paths`, and `protected_paths`) **ignores case on every platform**.

A filesystem that ignores case would otherwise let a different spelling walk past a rule. Windows NTFS and the default macOS APFS configuration both work this way, and so does Linux with ext4 casefold, an exFAT/NTFS mount, or a network share. On such a filesystem:

- `.ENV` opens the same file as `.env`, so it slips past a rule written for `.env`
- Command names are resolved the same way through `PATH`, so `RM -rf /` runs the same binary as `rm -rf /`

On a genuinely case-sensitive filesystem this behavior can over-match: a distinct file or program whose name differs only by case is treated as a match. That is the direction a gate should fail in, which is why it applies everywhere.

**Project containment is the one exception**: it follows the running platform's default filesystem behavior, so it can be imprecise on a non-standard configuration. See the limitations.

## Audit log

Decisions are written as JSON Lines to `~/.policygate/log/audit.log` by default. The newly created `log` directory uses mode `0700`, separating audit files from configuration and backups.

- New log files use mode `0600`
- Log directories created by PolicyApprovalGate use mode `0700`
- Permissions of existing directories are left unchanged
- Existing symlinks, FIFOs, devices, and other non-regular log paths are rejected
- Final log files are opened without following symlinks
- Rotation uses `max_bytes` and `max_files`
- A cross-process lock serializes concurrent writes and rotation
- `command_mode` supports `redacted`, `full`, `hash`, and `none`
- `redacted` recognizes common token assignments, Authorization headers, URL userinfo, curl Basic-auth flags, and MySQL/MariaDB password flags

Redaction is not exhaustive and may over-redact ordinary text. Use `hash` or `none` when command contents are unnecessary.

## Operational commands

| Command | Description | Example use |
| --- | --- | --- |
| `policygate check-config` | Loads the configuration file and validates its schema and values, printing any warnings or errors. | After creating or editing a configuration, before registering the hook |
| `policygate doctor` | Prints the version, OS/architecture, binary path, host, and configuration load status. | When diagnosing installation or configuration problems |
| `policygate evaluate --host codex --command 'rm -rf /'` | Evaluates a command against the current policy **without executing it**, then prints the result as JSON. | When checking defer / ask / deny behavior after changing rules |
| `policygate observe --host codex` | Reads one PreToolUse JSON input from standard input and records the evaluation without blocking it. | When testing hook integration without enforcement |
| `policygate version` | Prints the PolicyApprovalGate version. | When checking the installed version |
| `policygate help` | Prints the subcommands and environment variables. | When checking usage |

Running with no arguments enters hook mode and reads standard input. An unknown subcommand or flag is reported with exit code 2 instead of being silently processed as a hook call.

For example, use the following sequence after changing the configuration. The `rm -rf /` value passed to `evaluate` is only evaluated as text and is never executed.

```bash
policygate check-config
policygate doctor
policygate evaluate --host codex --command 'rm -rf /'
policygate version
```

`observe` is a hook-oriented mode that expects PreToolUse JSON on standard input. Use `evaluate` for normal interactive checks.

## Limitations

- Only Bash tool calls are covered. Other tools and direct file edits are not inspected.
- An `ask` decision prompts for confirmation in Claude Code but is converted to `deny` in Codex, which does not support standalone confirmation from a PreToolUse hook. The same policy can therefore produce a prompt on Claude Code and a rejected command on Codex.
- Regex and bounded shell analysis cannot fully handle obfuscation or unsupported syntax.
- Deciding whether a path lies inside the project follows the running platform's default filesystem behavior. On a case-sensitive macOS volume, a separate directory differing only by case may be treated as inside the project; on a case-insensitive Linux mount, a path inside the project may be treated as outside it. Rule matching itself is unaffected by the former.
- Git aliases are not resolved, so a push hidden behind one such as `git pushf` passes the protected-branch check. Resolving an alias requires reading `git config`, and an alias can itself be an arbitrary shell command (`!sh -c ...`). Pair this with branch protection on the remote when the rule must hold.
- A command name produced by a variable or command substitution, such as `$CMD -rf /`, cannot be resolved during analysis.
- Pipelines, subshells, and conditionals are not fully executed semantically; related commands are treated as indeterminate and evaluated conservatively.
- A normal directory created earlier in the same chain does not exist at analysis time, so a later `cd` may be treated as failed.
- Unknown commands and shell syntax that cannot be parsed follow `unknown.action` and `parse_error.action`; both default to `defer` and can be changed to `ask` or `deny`. As with other `ask` decisions, Claude Code prompts for confirmation and Codex converts the decision to `deny`.
- An invalid explicit policy configuration returns `deny` for a valid Bash hook call. Hook input, decision-output, and audit-log failures are reported to standard error, but cannot always produce or replace the host decision.
- The bundled rules are a starting point and should be adapted to your environment.

## Development

```bash
gofmt -w .
go vet ./...
go test -race ./...
golangci-lint run ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go build ./...
```

Lint settings are pinned in [.golangci.yml](.golangci.yml). See [.github/workflows/ci.yml](.github/workflows/ci.yml) for the CI configuration; GitHub Actions are pinned to a commit SHA rather than a tag.

Pushing a `v*` tag runs [.github/workflows/release.yml](.github/workflows/release.yml), which builds darwin, linux, and windows binaries for amd64 and arm64, generates `SHA256SUMS`, and publishes them as a pre-release.

See [SECURITY.md](SECURITY.md) for private vulnerability-reporting instructions.

## License

[MIT License](LICENSE)
