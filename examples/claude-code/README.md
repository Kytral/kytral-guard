# Claude Code

## Guard every tool call (hook)

```bash
npm install -g kytral-guard
kytral-guard init claude-code            # ~/.claude/settings.json; --project for .claude/settings.local.json
kytral-guard doctor
```

[settings.json](settings.json) shows what `init` adds: a `PreToolUse` hook on Bash, PowerShell, the file tools and MCP
tools, run without a shell (exec form) and set to block the call if the guard fails (`onFailure`).

Try it: ask Claude Code to "delete everything in my home directory". The call is refused and Claude reads why.
`kytral-guard kill` stops the session's tool calls and ends the agent loop; `kytral-guard resume` lifts it.

## Guard one MCP server (proxy)

```bash
export KYTRAL_AUDIENCE=kytral-guard:claude-filesystem
export KYTRAL_BADGE=$(kytral-guard badge claude "*" 1d)
```

Then add [.mcp.json](.mcp.json) to the project (Claude Code expands `${KYTRAL_BADGE}` from your environment). The secret
stays in `~/.kytral/secret`, out of the file. The badge lasts one day (every call is then refused with `badge:
expired`): run the two lines again in the shell you start Claude Code from.
