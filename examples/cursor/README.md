# Cursor

```bash
npm install -g kytral-guard
kytral-guard init cursor                 # ~/.cursor/hooks.json; --project for .cursor/hooks.json
```

[hooks.json](hooks.json) shows what `init` adds: shell commands, MCP calls and file writes/deletes go through Kytral
Guard, and `failClosed` blocks the call if the guard cannot run. Cursor reloads the file on its own.

Cursor also runs the Claude Code hooks it finds in `.claude/settings*.json`: install one or the other per project to avoid
running the guard twice.

To guard one MCP server with the proxy instead, use [mcp.json](mcp.json) as `.cursor/mcp.json` (or `~/.cursor/mcp.json`).
Its badge is valid one year: every call is then refused (`badge: expired`), so issue a new one before.
