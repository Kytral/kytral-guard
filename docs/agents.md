# Coding agents

`kytral-guard init` installs a pre-tool hook in every agent found on the machine (or in the agents you name); the agent
then runs `kytral-guard hook <agent>` before each guarded tool call, sends the call as JSON on stdin and reads the
decision on stdout. Install the package globally first (`npm install -g kytral-guard`): the hook runs it by absolute
paths, so a temporary `npx` copy is refused.

```bash
kytral-guard init                       # every agent found on this machine (user-level configuration)
kytral-guard init claude-code           # only this one
kytral-guard init cursor --project      # this project only
kytral-guard init codex --dry-run       # show the change without writing it
kytral-guard init --no-agents           # only the secret and the policy file (MCP proxy, SDK)
kytral-guard uninstall claude-code      # or --all
kytral-guard doctor                     # check everything, run a self-test
kytral-guard allow "<command>"          # stop being asked for one exact command
```

The configuration file is merged, never replaced: other settings and hooks stay, the previous file is kept as
`<file>.kytral-backup`, a file that does not parse is left untouched, and installing twice changes nothing.

Hooks name node and the CLI by their absolute paths; for a Homebrew node, its stable link (`/opt/homebrew/opt/node/bin/node`),
which `brew upgrade` follows, not the folder of its version. After a Node.js upgrade that moves them (nvm, fnm, Volta keep one
folder per version, global packages included), install the package again with the new Node.js and run `kytral-guard
init` and `kytral-guard mcp wrap` again: until then agents that fail closed refuse every call, and the others run their
tools unguarded. `kytral-guard doctor` names every path that no longer exists.

To remove Kytral Guard, run `kytral-guard uninstall --all` first (and `kytral-guard uninstall --all --project` in each
project where you used `--project`), then `npm uninstall -g kytral-guard`. `--all` also takes the proxy off the MCP
servers of the apps and of the files wrapped with `mcp wrap --file` (restart them). A hook left behind names a program
that is gone: Claude Code and Cursor, which fail closed, then refuse every tool call. Reinstall the package and run the
uninstall, or delete the Kytral Guard entry from
the agent's file (`.claude/settings.json`, `.cursor/hooks.json`…). `~/.kytral` (settings, log, secret) is kept; delete
it to remove them.

## Decisions in each agent

When the policy allows a call, the guard raises no objection (the agent's own permission settings apply; Cursor gets an
explicit `allow`). Otherwise:

| Agent | Policy says confirm | Policy says block | Kill switch |
|---|---|---|---|
| Claude Code | `ask` (refused in `bypassPermissions` and `dontAsk`) | `deny` + exit 2; the agent reads why | `deny`, and `continue: false` ends the loop |
| Cursor | `ask` (refused for `preToolUse`) | `deny` | `deny` |
| OpenAI Codex CLI | refused | `deny` + exit 2 | `deny` |
| Gemini CLI | refused | `deny` + exit 2 | `deny` |
| GitHub Copilot CLI | `ask` | `deny` + exit 2 | `deny` |
| Windsurf | refused | exit 2 | exit 2 |
| Grok Build | `ask` (refused in `bypassPermissions` and before the 2026-08-28 builds) | `deny` + exit 2 | `deny` and `continue: false` |
| Kimi Code | refused (it reads any other answer as an approval) | `deny` + exit 2 | `deny` |
| TRAE, TRAE CN | `ask` | `deny` + exit 2 | `deny` and `continue: false` |
| opencode, MiMo Code (plugin) | refused (plugins cannot ask) | the call fails with the reason (MiMo: cancelled) | same |
| Qwen Code | `ask` (a prompt even in YOLO mode; refused where nobody can answer) | `deny` in JSON, exit 0 | `deny` |
| iFlow CLI | refused | `decision: block` + exit 2 | `decision: block` |
| Qoder CLI | `ask` (refused in `bypassPermissions` and `dontAsk`) | `deny` + exit 2 | `deny` |
| CodeBuddy Code | `ask` (refused in `bypassPermissions` and `dontAsk`) | `deny` + exit 2, with a top-level `reason` | `deny` |
| Factory Droid | refused (it does not ask) | `deny` + exit 2 | `deny` and `continue: false` |
| Augment Auggie | refused (its hooks can only refuse) | `deny` + exit 2 | `deny` and `continue: false` |
| Devin CLI | refused | `deny` + exit 2 | `deny` |
| Kiro CLI | refused (headless runs would approve an ask) | exit 2 | exit 2 |
| Amp (plugin) | Amp's dialog asks the user | `reject-and-continue` with the reason | same |
| Cline | refused | `cancel` (the task stops: Cline cannot refuse one call) | same |

"Refused" means the confirmation becomes a refusal whose message tells the agent to ask the user: an agent that cannot
show a prompt, or a session that turned prompts off, must not run a call that needs a human. While a dashboard is open
(`kytral-guard dashboard`), the question goes to its page first: the call runs if you approve it there in time
([dashboard.md](dashboard.md)).

Every failure of the guard is a refusal: an unreadable event, an unknown agent name, a broken policy, an audit log that
cannot be written, an internal error. The hooks are also configured to block when the guard cannot start or times out
(Claude Code `onFailure: "block"`, Cursor `failClosed: true`); other agents run the tool when a hook crashes, which is why
the guard answers every error itself.

## When the hook itself fails

What happens when the hook process cannot start, crashes or runs past its timeout is up to the agent. Only two agents
can be told to block the call then, and `init` tells them to; no other one has such an option, so `init` writes none (an
option an agent does not know can make it drop the hook: Kimi Code then runs no hook at all).

| Agent | Fail-closed option `init` writes | The hook crashes or exits with another code | The hook times out |
|---|---|---|---|
| Claude Code | `onFailure: "block"` (2.1.295 or later; older versions ignore it) | blocked | blocked |
| Cursor | `failClosed: true` | blocked | blocked |
| GitHub Copilot CLI | none (no such option) | blocked (built in) | the tool runs |
| CodeBuddy Code | none (no such option) | the tool runs | blocked (built in) |
| opencode, MiMo Code, Amp | none needed: the plugin `init` writes blocks | blocked | blocked (the plugin's own timeout) |
| Cline | none needed: the script `init` writes refuses | blocked | blocked (the script's own timeout) |
| OpenAI Codex CLI, Gemini CLI, Grok Build, Kimi Code, Qwen Code, iFlow CLI, Qoder CLI, Factory Droid, Augment Auggie, Kiro CLI | none (no such option) | the tool runs | the tool runs |
| Windsurf, TRAE, Devin CLI | none (no such option) | the tool runs | not documented |

So the guard keeps its hook from failing or waiting: it answers every error with a refusal, ends every wait of its own (the
analysis, remote approvals) 3 s before the hook timeout written in its command, and opens the files of `KYTRAL_HOME` only
as regular files and without waiting: a FIFO, a device or a folder put in place of the audit log, the kill switch, the
policy or another of its files is refused at once instead of holding the hook until the agent gives up and runs the tool
([kill-switch.md](kill-switch.md#fail-closed)). Grok Build and Devin CLI also run the hooks they find in Claude Code's (and,
for Grok, Cursor's) files without honoring these options: the hook `init` writes for them decides.

## Claude Code

- File: `~/.claude/settings.json` (`--project`: `.claude/settings.local.json`, which holds machine-specific paths and is
  not committed). Hook: `PreToolUse`, matcher `^(Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read)$|^mcp__`, exec
  form (`node` + `cli.js`, no shell, so a shell profile cannot corrupt the answer), `timeout: 30`, `onFailure: "block"`
  (Claude Code 2.1.295 or later; older versions ignore it and fail open on a crash).
- Bash and PowerShell commands are analyzed; Write, Edit and NotebookEdit are checked by path (system, credential and
  guard files), not by content; Read is checked for the guard's secret; MCP tools get the full analysis.
- A `"disableAllHooks": true` in any settings file turns every non-managed hook off, this one included; `kytral-guard
  doctor` reports it as a failure, and the coding-agent preset blocks the agent from writing settings files. For a hook nobody on
  the machine can turn off, deploy it in Claude Code's managed settings.

## Cursor

- File: `~/.cursor/hooks.json` (`--project`: `.cursor/hooks.json`). Events: `beforeShellExecution`, `beforeMCPExecution`,
  and `preToolUse` for `Write|Delete`, all with `failClosed: true`.
- Cursor also runs the Claude Code hooks of `.claude/settings*.json` by default. If both are installed, the guard runs
  twice for the same call (same decision, two audit entries).
- Grok Build runs these hooks too, for every tool (they have no matcher there): see [Grok Build](#grok-build).
- Cursor cloud agents do not run `beforeMCPExecution`, and do not read user-level hooks.

## OpenAI Codex CLI

- File: `~/.codex/hooks.json` (`--project`: `.codex/hooks.json`). Event `PreToolUse`, matcher `^(Bash|apply_patch)$|^mcp__`.
- Codex runs a new or changed hook only after you trust it: open `/hooks` in Codex once after `init`.
- Codex does not support `ask`: confirmations are refused. `apply_patch` is checked by the files it touches.

## Gemini CLI

- File: `~/.gemini/settings.json` (`--project`: `.gemini/settings.json`). Event `BeforeTool`, matcher
  `^(run_shell_command|write_file|replace)$|^mcp_`, timeout 30000 ms.
- Gemini hooks cannot ask: confirmations are refused. A changed project hook needs to be trusted again.

## GitHub Copilot CLI

- File: `~/.copilot/hooks/kytral-guard.json` (`--project`: `.github/hooks/kytral-guard.json`). Event `preToolUse`, with
  a `bash` and a `powershell` command.
- Copilot treats a crashing hook as a refusal (good) but a timeout as an approval: keep the 30 s timeout.

## Windsurf (Cascade)

- File: `~/.codeium/windsurf/hooks.json`. Events `pre_run_command`, `pre_mcp_tool_use`, `pre_write_code`. Cascade hooks
  only block through exit code 2: there is no "ask".

## Grok Build

- File: `~/.grok/hooks/kytral-guard.json` (`--project`: `.grok/hooks/kytral-guard.json`, which runs once you trust the
  folder with `/hooks-trust`). Event `PreToolUse`, matcher
  `^(run_terminal_command|search_replace|hashline_edit|write|read_file|hashline_read|Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read)$|__`
  (a regular expression Grok also tests against the Claude Code names of its tools; MCP tools are named `server__tool`),
  timeout 30 s. Grok has no exec form: the command runs through a shell (sh, PowerShell or Git Bash on Windows). With
  `GROK_SHELL=cmd`, Grok hands the command to cmd.exe with escaped quotes it cannot run, then runs the tool:
  `kytral-guard doctor` warns.
- Grok Build runs the tool when a hook crashes or times out, which is why the guard answers every error itself.
- Confirmations are asked in the builds since 2026-08-28: Grok then shows its permission prompt, never lets its `auto`
  classifier approve it, and refuses where nobody can answer. Older builds treat "ask" as a failed hook, so the guard
  refuses there (those builds are recognized because they send camelCase keys only). Also refused in `bypassPermissions`.
- A call over 128 KB reaches the hook truncated: what it holds is analyzed (and can block it); otherwise a human confirms.
- Grok Build also runs the hooks it finds in `~/.claude/settings.json` and `~/.cursor/hooks.json`, with its own events.
  The guard recognizes them whatever hook command receives them and answers in Grok's vocabulary, for the same tools as
  this hook. Grok cannot run the Claude Code hook (exec form: it drops the arguments) and shows it as failed; that changes
  nothing, this hook decides. To hide that message, set `[compat.claude] hooks = false` in `~/.grok/config.toml` (Grok
  then ignores every Claude Code hook).

## Kimi Code (Moonshot AI)

- File: `~/.kimi-code/config.toml` (or `$KIMI_CODE_HOME/config.toml`): a `[[hooks]]` entry, event `PreToolUse`, matcher
  `^(Bash|Write|Edit|Read)$|^mcp__` (an unanchored regular expression), timeout 30 s. The rest of the file is kept as
  it is; a file that defines `hooks = [...]` inline is not touched (the entry to add is printed). Kimi Code has no
  project hooks.
- Kimi Code runs the tool when a hook crashes, times out or exits with another code, and reads any decision but `deny`
  as an approval: confirmations are refused. Restart it after `init`: it loads hooks at startup.
- The archived Python `kimi-cli` (`~/.kimi/config.toml`, shell tool `Shell`) is not supported.

## TRAE and TRAE CN (ByteDance)

- File: `~/.trae/hooks.json` (TRAE CN: `~/.trae-cn/hooks.json`; `--project`: `.trae/hooks.json`). Claude Code's format
  with TRAE's tool names: matcher `^(RunCommand|Write|Edit|Read)$|^mcp__`.
- Turn hooks on in TRAE: Settings > Hooks (Global, or Project for a project file), and choose "Run Automatically Locally":
  in the sandbox the guard cannot read its own state and refuses every call.
- TRAE can also import Claude Code's hooks; it then runs them with its own tool names (`RunCommand`, not `Bash`).
- TRAE CLI 2.0 (a fork of Codex) is not installed by `init` yet: its hook format is not documented.

## opencode and MiMo Code (Xiaomi)

- No command hooks: `init` writes a plugin of its own, `~/.config/opencode/plugins/kytral-guard.js` (MiMo Code:
  `~/.config/mimocode/plugins/kytral-guard.js`; `--project`: `.opencode/plugins/` or `.mimocode/plugins/`). It runs the
  guard before each tool call except the read-only ones (glob, grep, list, web search, plans…), with the absolute paths
  of node and the CLI, and lets the call run only when the guard answers with exit code 0: a refusal, a crash or no
  answer within 30 s blocks it (opencode: the call fails with the reason; MiMo Code: it is cancelled with the reason).
- MCP tools are named `server_tool` there: they get the MCP rules (`mcp__server_tool`).
- Plugins cannot ask: confirmations are refused. `--pure` starts these agents without plugins, so without the guard.
  `init` never overwrites a plugin file it did not write. Restart the agent after `init`.

## Qwen Code (Alibaba)

- File: `~/.qwen/settings.json` (or `$QWEN_HOME/settings.json`; `--project`: `.qwen/settings.json`, which runs in a
  trusted folder only). Event `PreToolUse`, matcher `^(run_shell_command|write_file|edit|notebook_edit|read_file|exec)$|^mcp__`.
- A refusal is a JSON `deny` with exit code 0: Qwen Code lets another hook's JSON `allow` win over a refusal by exit
  code 2. It asks even in YOLO mode, and refuses where nobody can answer (`-p`, background agents, IDE sessions).
- Qwen Code runs the tool when a hook crashes or times out. It loads hooks when a session starts or `/hooks` opens.

## iFlow CLI (Alibaba)

- File: `~/.iflow/settings.json` (`--project`: `.iflow/settings.json`, for trusted workspaces). Event `PreToolUse`,
  matcher `^(run_shell_command|write_file|replace|multi_edit|read_file|read_many_files)$`.
- iFlow reads only a top-level `decision` (`block`): the guard answers `{"decision":"block","reason":…}` and exit 2. Its
  hooks cannot ask: confirmations are refused. It runs the tool when a hook crashes or times out.
- iFlow names MCP tools without a prefix, so its hook cannot tell them from its own: `kytral-guard mcp wrap iflow` runs
  its MCP servers through the proxy instead.

## Qoder CLI (Alibaba)

- File: `~/.qoder/settings.json` (or `$QODER_CONFIG_DIR`; `--project`: `.qoder/settings.local.json`). Claude Code's
  format and tool names; the hook runs node and the CLI directly (an `args` array, no shell).
- In interactive mode, Qoder runs no hook at all in a folder you have not trusted, user hooks included: trust your
  project folders. Plain text on a hook's output counts as an approval there; the guard never prints any.
- Qoder IDE has hooks too (other tool names); `init` does not install them yet.

## CodeBuddy Code (Tencent)

- File: `~/.codebuddy/settings.json` (`--project`: `.codebuddy/settings.local.json`). Claude Code's format and tool
  names; the answer also carries a top-level `reason`, the message CodeBuddy shows.
- CodeBuddy refuses the call when a hook times out or cannot start (good), and runs it on other failures.

## Factory Droid

- File: `~/.factory/hooks.json` (`--project`: `.factory/hooks.json`), whose top-level keys are the events. Matcher
  `^(Execute|Create|Edit|ApplyPatch|Read)$|___|^mcp__` (MCP tools are named `server___tool`).
- Droid skips every hook while it waits for you to trust the folder, and reads hooks at startup. It runs the tool when
  a hook fails or times out.

## Augment Auggie

- File: `~/.augment/settings.json` (`--project`: `.augment/settings.local.json`). Two matchers: Auggie's own tools
  (`launch-process`, `save-file`, `str-replace-editor`, `remove-files`, `view`…) and `mcp:*` (its MCP tools only match a
  matcher that starts with `mcp:`). node runs directly (an `args` array), timeout in milliseconds.
- Its hooks can only refuse: confirmations are refused. Auggie runs matching hooks together, and one that fails (an exit
  code other than 0 and 2) cancels the refusal of the others: keep your other hooks working.

## Devin CLI

- File: `~/.config/devin/config.json` (Windows: `%APPDATA%\devin\config.json`; `--project`: `.devin/config.local.json`).
  Matcher `^(exec|write|edit|apply_patch|read)$|^mcp__`.
- Devin also runs the hooks of `~/.claude/settings.json` with its own tool names (`exec`, not `Bash`): the Claude Code
  hook only fires there for MCP tools, and this hook decides.

## Kiro CLI

- File: `~/.kiro/hooks/kytral-guard.json` (`--project`: `.kiro/hooks/kytral-guard.json`), read by the CLI's V3 engine
  (`kiro-cli chat --v3`, or `chat.agentEngine` set to `v3`), in trusted workspaces only. The default V2 engine reads hooks
  from agent profiles (`~/.kiro/agents/*.json`), which `init` does not edit.
- Kiro reads only exit code 2 as a refusal; confirmations are refused (headless runs with `--trust-all-tools` approve
  an ask). MCP tools are named `mcp_server_tool`.

## Amp

- No command hooks: `init` writes a plugin, `~/.config/amp/plugins/kytral-guard.js` (`--project`: `.amp/plugins/`),
  that runs the guard before Amp's shell, file and MCP tools (`Bash`, `shell_command`, `create_file`, `edit_file`,
  `apply_patch`, `mcp__…`). A confirmation opens Amp's own dialog; a refusal rejects the call and the agent goes on.
  Plugins load at startup (`plugins: reload` in the command palette).

## Cline

- File: `~/Documents/Cline/Hooks/PreToolUse` (Windows: `PreToolUse.ps1`; `--project`: `.clinerules/hooks/`), a
  script of Kytral's own run by the VS Code extension and by the Cline CLI before each tool call.
- Cline's hooks cannot refuse one call: a refusal (`cancel`) stops the task, with the reason. Confirmations are
  refused. A guard that cannot start or answer also stops it (fail closed); Cline itself runs the tool when a hook
  crashes, which the script prevents.

## Any other agent or framework

`kytral-guard hook generic` and `kytral-guard check` take a generic event and answer with JSON and an exit code
(0 allow, 3 confirm, 2 block):

```bash
echo '{"tool":"run_sql","args":{"sql":"DELETE FROM users"}}' | kytral-guard hook generic
{"action":"block","rule":"sql-destructive","reason":"matched rule 'sql-destructive': …"}
```

`hook auto` detects Claude Code, Cursor, Codex, Gemini CLI, Copilot CLI, Windsurf, Grok Build, Kimi Code, TRAE, Qwen Code, iFlow, CodeBuddy, Augment and Cline events by their shape;
a tool call it cannot read is refused. In TypeScript, use the `HookGuard` class or `evaluate()` directly (see
[sdk.md](sdk.md)).

## Policy and state

Hooks use `--policy <file>` or `--preset <name>` if the hook command has them, else `$KYTRAL_POLICY`, else
`~/.kytral/policy.yaml` (created by `init`, extending the `coding-agent` preset), else the `coding-agent` preset. A policy
that does not load refuses every call until it is fixed: run `kytral-guard doctor`. The secret, the kill switch and the
audit log are shared with every other hook and proxy using the same `KYTRAL_HOME`.

## Performance and time limits

A guarded call costs one Node.js process start plus the analysis: about 0.15 s (the analysis thread starts while the
CLI loads). Read-only tools (Glob, Grep, LS, web
search) are not routed through the hook.

Most agents run the tool when a hook times out, so the guard never lets an analysis run past its own deadline. `init`
writes the agent's hook timeout into the hook command (`hook <agent> --timeout 30`): every wait of the guard (analysis,
remote approvals) ends 3 s before it. Every call is analyzed in a worker thread stopped after
`KYTRAL_ANALYSIS_TIMEOUT_MS` (default 8 s), whatever its size: a few dozen characters can be expensive (SQL the parser
backtracks on, a slow regular expression in a custom policy). Calls over 2 MB are not analyzed. Either way the call needs
a human (rule `analysis-limit`: asked where the agent can ask, refused elsewhere). The built-in analyzers are tested
against inputs built to slow them down, and SQL parsing has its own deadline. Keep the hook timeout at 30 s or more.
