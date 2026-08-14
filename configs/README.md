# Hook registration examples

These files show what `policygate install-hook` writes. Prefer the command: it
resolves the absolute path of the running binary, keeps the registration
idempotent, preserves the rest of the file, and backs it up before replacing it.

```bash
policygate install-hook --host claude   # ./.claude/settings.local.json
policygate install-hook --host codex    # ~/.codex/config.toml
```

Register by hand only if you need to, and then note:

- **Spell the path out.** A `~` or `$HOME` is expanded only when the host runs
  the command through a shell. `/home/you/...` in these files is a placeholder.
- **On Windows, use forward slashes** (`D:/bin/policygate.exe`). Inside a JSON
  string `\b` reads as a backspace, and a host that passes the command to a
  shell drops each backslash as an escape.
- **Claude Code needs all five matchers.** `Bash` and `PowerShell` carry shell
  commands. `Read`, `Write`, and `Edit` carry direct file paths. Leaving any of
  them out creates a corresponding gap in path or command inspection.
- **Codex needs the definition trusted** with `/hooks`, or the hook is skipped.
