# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [semantic versioning](https://semver.org/).

## [0.1.0] - Unreleased

First public release.

### Dashboard
- `kytral-guard dashboard`: a page on this computer, with no account (the command signs you in with a one-time link). A
  Simple view in plain words (whether you are protected, what waits for your answer, what happened today, three
  protection levels, what is watched) and an Advanced view (the log with an hourly chart and its integrity, Block / Ask /
  Allow for every rule of coding agents and AI apps, exceptions for exact commands, approvals with their complete
  arguments, agents and apps to protect in one click, settings), in Kytral's colors and fonts. It updates by itself as
  soon as something happens (long polling), offers Undo after a change, protects everything it found in one click, and
  shows waiting requests in the browser tab. In 10 languages: English, French, Spanish, German, Italian, Brazilian
  Portuguese, Russian, Japanese, Korean and Simplified Chinese (the browser's language, or the one picked).
- While it is open, calls nobody could answer wait for you on the page: MCP servers of AI apps, and agents that cannot
  show a prompt (Codex, Gemini CLI, Kimi Code, opencode...) or run without prompts. `KYTRAL_CONFIRM_QUEUE` is now
  automatic by default (`1`: always wait, `0`: never).
- A catastrophe can never be allowed from the page, `guard-tamper` stays block, agents cannot start it. Every rule that
  matches a command counts for an exception, not only the one deciding now; `kytral-guard allow --call <n>` allows the
  exact text of a call the page shows, with no quoting to get right. Security: 127.0.0.1
  and its own Host only, one-time link in the URL fragment, session key in an Authorization header (no cookie: other local
  servers never receive it), same-origin JSON changes, text-only rendering under a strict CSP. Every change is journaled.
- Policy `overrides:` set the action of rules by name (a preset's included; not `guard-tamper`); exceptions for exact
  commands can also always ask or always block. The MCP proxy reads `~/.kytral/mcp-policy.yaml` when it has no other,
  and follows its policy file: a change applies from the next call, a file that no longer loads refuses every call.
- The text of refused, asked and approved calls is kept apart from the log (`kept-calls.jsonl`, passwords, tokens and
  keys masked, about the last thousand), for the dashboard; `keepCalls` and `auditAllows` in `config.json`.

### Coding agents
- `kytral-guard hook <agent>` for Claude Code, Cursor, OpenAI Codex CLI, Gemini CLI, GitHub Copilot CLI, Windsurf and
  Grok Build, plus a generic JSON format and agent auto-detection. Confirmations become the agent's "ask" where a human
  can answer, and refusals elsewhere (including Claude Code's `bypassPermissions` and `dontAsk` modes).
- Factory Droid (events at the top level of hooks.json), Augment Auggie (exec form, timeout in ms, an `mcp:*` matcher),
  Devin CLI, Kiro CLI (a hook file of its V3 engine), Amp (a plugin; a confirmation opens Amp's dialog) and Cline (a hook
  script, PowerShell on Windows; a refusal stops the task, the only refusal its hooks have).
- Qwen Code (a JSON refusal with exit code 0, which wins over another hook's approval there), iFlow CLI (a top-level
  `decision: block`, its MCP servers through `mcp wrap iflow`), Qoder CLI (exec form) and CodeBuddy Code.
- Kimi Code (a `[[hooks]]` entry in its config.toml, confirmations refused since it reads any other answer as an
  approval), TRAE and TRAE CN, and opencode and MiMo Code (a plugin of Kytral's own that runs the guard before each tool
  call and blocks unless it answers exit code 0). `hook auto` tells Kimi Code and TRAE events from Claude Code's.
- The folder a shell command runs in (`cwd`, `workdir`, `directory` of its tool call) is where its scripts are read from.
- With a Homebrew node, hooks and wrapped MCP servers name its stable link, which `brew upgrade node` follows, instead of
  the folder of its version (macOS reports that one), which the upgrade removes.
- Grok Build also runs the hooks of Claude Code and Cursor, with its own events: they are recognized whatever hook command
  receives them and answered in Grok's vocabulary (`hook auto` used to read them as Copilot calls without arguments and
  let them through). A call Grok truncates is checked on what it holds and otherwise needs a human.
- `kytral-guard init` installs the hook in every agent found on the machine (or the agents named; `--no-agents` for the
  secret and policy only) and ends with what to try next; `kytral-guard uninstall <agent>|--all`. The hook is merged into
  the agent's configuration, fails closed where the agent allows it, keeps a backup and never overwrites an unreadable
  file. `uninstall --all` also takes the proxy off MCP servers and says how to remove the rest. `kytral-guard doctor`
  checks the setup, ends with a summary, and warns when no agent or app runs the guard.
- `kytral-guard allow "<command>"` lets agents run one exact command without asking (raw text, kept blocked if it ever
  turns catastrophic; `--force` for a catastrophe, `--list`, `--remove`); confirmations of a shell command show the
  line to run. Agents cannot run it themselves. New rule fields `argEquals` and `exceptCatastrophic`.
- `coding-agent` preset: catastrophes blocked, scoped destruction confirmed, routine work silent; file contents are not
  analyzed as commands, their paths are.

### Analysis
- Severity model: catastrophic, destructive, harmless; deletion targets classified by blast radius.
- Routine cleanup stays silent: dependency lockfiles, `find` of files tools write again (`find . -name '*.pyc' -delete`),
  caches of the home folder (`~/Library/Caches/<app>`, Xcode's `DerivedData`, `~/.cache/<tool>`), `Get-ChildItem
  -Include __pycache__ | Remove-Item`. SQL files a database client reads (`psql -f`, `mysql < file`) are judged by their
  SQL. macOS backups and system settings (`tmutil delete`, `csrutil disable`…) and `robocopy /MIR` are caught.
- Shell: wrappers with their options (`sudo -u`, `timeout`, `nice -n`, `env -S`, `su -c`, `xargs`…), remote and container
  execution (`ssh`, `docker exec`, `kubectl exec`…), runners (`npx`, `bundle exec`, `python manage.py`…).
- Catalog of destructive CLIs: Terraform, OpenTofu, Pulumi, CDK, kubectl, Helm, AWS, GCP, Azure and other clouds, Docker,
  databases, ORMs and migration tools, object storage, hosting platforms, `npm unpublish`, HTTP DELETE, system commands.
- SQL passed to database clients (`psql -c`, `mysql -e`, `sqlite3`…) is analyzed, including statements written over
  several lines inside the quotes; DROP and TRUNCATE are decided by their head. Refusals quote the statement (`delete from users (no WHERE that pins rows)`).
- The files a command runs are analyzed with it: shell scripts, `package.json` scripts (workspaces, turbo, lerna, nx),
  Makefile, justfile and Taskfile recipes, git hooks (husky, `core.hooksPath`), crontabs, PowerShell scripts, Python /
  JavaScript / TypeScript / Ruby / Perl / PHP programs with the local modules they import, here-documents, and files the
  same command writes before running them. Hooks read them from the agent's working directory; `cd` is followed.
- Shell variables set by plain assignments, script arguments, `$(mktemp)` and `${TMPDIR:-/tmp}` are followed; subshells,
  `$(…)`, reserved words, case patterns, here-strings, process substitutions and `trap` handlers are analyzed as the
  shell runs them (`(cd x && rm -rf ~)` and `echo "import shutil; shutil.rmtree('/')" | python3` were allowed before).
- Interpreter one-liners: a deletion is judged by its target (`node -e "fs.rmSync('dist', …)"` is routine).
- PowerShell and cmd.exe analyzer.
- Self-protection: reading the guard's secret, lifting the kill switch or approving from the agent, editing hook
  configurations or the guard's installed code, taking the proxy off MCP servers (`mcp unwrap`), uninstalling its global
  package; a custom `KYTRAL_HOME` is protected like `~/.kytral`.
- The description an agent writes beside a shell command (Claude Code, Gemini CLI, Grok Build…) is a note, not a
  command: "Search for rm -rf ~ usages" no longer blocks a `grep`.
- Analyzers and preset patterns fuzzed for super-linear running time (a fork-bomb pattern, brace lists, `find -exec`
  and two preset patterns were quadratic). SQL is parsed in a worker thread with a deadline, and unbalanced or very
  deep parentheses (exponential for the parser) are not parsed. In hooks, every call is analyzed in a worker thread with a
  deadline (`KYTRAL_ANALYSIS_TIMEOUT_MS`, 8 s), calls over 2 MB are not analyzed: a human confirms (`analysis-limit`).
  An analysis can no longer outlast the agent's hook timeout, which most agents treat as an approval.
- Malformed pre-tool events are refused; tool arguments that are not an object are analyzed as text.
- Installed hook commands carry the agent's hook timeout (`--timeout`): no wait of the guard outlasts it.
- The CLI is one bundle behind a small entry point that starts the analysis thread first: its start-up overlaps loading
  the CLI and reading the event (a guarded call takes about 0.14 s instead of 0.17 s).

### Platform
- `kytral-guard mcp list | wrap | unwrap`: runs the local MCP servers of Claude Desktop, VS Code, Cline, Roo Code, Kilo
  Code, LM Studio and Continue (or of any JSON or YAML file given) through the proxy, each with its own audience and
  badge, and back.
  `doctor` lists the servers left unprotected.
- The proxy starts `npx`, `pnpm` and other `.cmd` shims on Windows (cmd.exe, every argument escaped; they failed with
  ENOENT), and the wrapped server no longer inherits `KYTRAL_SECRET`, `KYTRAL_AUDIT_SECRET` or `KYTRAL_BADGE`.
- The proxy refuses `tools/call` arguments that are not an object (they were analyzed as no argument and forwarded as
  sent) and `resources/read` of the guard's secret, and follows MCP's stdio shutdown: when the client closes its input,
  the server's input is closed and the proxy exits with it (it waited to be killed); a signal stops the server too.
- `mcp wrap` repairs wrapped servers that no longer work (a new secret, a badge near its end, a node or CLI that moved
  after a Node.js upgrade), never a revoked one; `mcp list`, `doctor` and the dashboard show them. They used to stay
  "protected" while every call was refused or the server did not start.
- Plugins (`KYTRAL_PLUGINS`, `$KYTRAL_HOME/config.json`): central policies for hooks and proxies (YAML validated by the
  guard), extra kill switch, remote approvals (`remoteConfirmTimeoutSeconds`), copies of decisions and audit entries; a
  plugin that does not load, or provides an invalid policy, fails closed.
- MCP stdio proxy, TypeScript SDK, signed agent badges, shared kill switch with signed monotonic generations,
  HMAC-chained audit log with a signed tail marker, local confirmation queue, known-tools grants with anti-replay.
- Kill switch states are bound to this deployment (an id derived from the key and the real path of `kill-switch.json`,
  never stored) and a resume is chained to the state it replaces; writers continue from the highest generation whose
  journal entry's HMAC verifies; v1 states are refused ([docs/kill-switch.md](docs/kill-switch.md)).
- `kytral-guard kill` is never refused: when the audit log cannot be read or cannot record it, or `kill-switch.json` holds
  something that cannot be checked (JSON nested too deep, a FIFO, a device, or a folder, which is moved aside), the kill is
  written all the same, stderr says why and it exits 3 (0: stopped and journaled; 1: nothing written); `resume` is refused
  until the log can be read, and while `kill-switch.json` or the log's tail marker is no regular file.
- Agent hooks, MCP proxies and SDK guards start from the last kill or resume recorded in the audit log's signed tail
  marker: deleting `kill-switch.json`, or putting back an older resume, does not lift a kill for one started afterwards.
  The marker and every kill and resume in the log sign the id of their log (an HMAC of the log's real path, as for
  `kill-switch.json`): `kill-switch.json`, the log or the marker of another `KYTRAL_HOME` using the same secret, copied in
  alone or together, does not lift a kill either. A marker in doubt (another home's, an older version's, edited,
  unreadable) never lifts one, and a resume found in the log never counts then: with no kill of this log as recent, every
  call is refused until a single `kytral-guard resume`; so does a kill or resume of another log found in this one.
- `kytral-guard doctor` and the agent hooks (one line on stderr after the answer, without a path) warn when none of the
  kill switch's files exists where `KYTRAL_HOME` or `KYTRAL_AUDIT` points while a default path it replaces still holds
  one: a home wiped, or redirected to a blank one, where a kill in force at the default path is not seen. A warning, not
  a block: answers, stdout and exit codes are unchanged ([docs/kill-switch.md](docs/kill-switch.md#limits)).
- "Always" grants, confirmation requests and decisions, and the kept texts of refused calls (which `allow --call` and the
  dashboard turn into exceptions) are signed for the file or folder they belong to: another home's, using the same
  secret, grant nothing here (a table of every file of a home in [docs/threat-model.md](docs/threat-model.md)).
- No file of `KYTRAL_HOME` that a hook or a proxy reads can make it wait: the audit log, its marker, `kill-switch.json`,
  the policy, `config.json`, kept calls and the other state files are opened only as regular files, without waiting, so a
  FIFO put in their place cannot hold a hook past the agent's timeout. A state file built so that checking it fails is
  refused as corrupt, and never stops a proxy.
- Upgrading from a pre-release build: a kill switch state it wrote (v1, or a random id in `kill-switch.id`) stops every
  guard of this version, which says so (`a v1 state, written by an older version of Kytral Guard`); a single
  `kytral-guard resume` lifts it, no `kill` is needed first. Its audit log tail marker and the kills and resumes it
  journaled sign no log id: every call is refused, whatever they record, with `the audit log's tail marker was written by
  an older version of Kytral Guard, so the last kill or resume is not known, ...: a single 'kytral-guard resume' lifts
  it`, and a single `kytral-guard resume` lifts it, journaled with the id. Its "always" grants and kept texts are not
  signed for their file: the tools are asked about again, and older texts are no longer shown.
- `kytral-guard doctor --report`: a diagnostic for public bug reports, built from a whitelist of formats (no secret,
  value, path, audit entry or tool argument); issue forms and a security policy that ask for it.
- Options fail closed: an unknown option, in any form, is an error that repeats nothing typed, and an option given twice
  is refused; the proxy checks its options before it reads a secret or a file or starts the server.
- `kytral-guard check` and `kytral-guard policy` to test policies; `extends:` presets; `toolNotMatches` and `argFields`
  rule fields.
- The secret can live in `$KYTRAL_HOME/secret` instead of the environment.
