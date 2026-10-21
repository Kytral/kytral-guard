# Dashboard

`kytral-guard dashboard` opens a page, on this computer only, to see what your agents did and to decide what they may do.
There is no account: the person who starts it in a terminal signs in with a link the command opens in the browser.

```bash
kytral-guard dashboard               # opens the page in your browser
kytral-guard dashboard --no-open     # prints the link only
kytral-guard dashboard --port 4719   # a fixed port (default: a free one)
```

The page works as long as the command runs (Ctrl+C stops it). Its link signs you in once: press Enter in that terminal for
a new link, to open the page in another browser.

## Two views

**Simple**, shown first, says in plain words:
- whether you are protected, with a button that stops every agent;
- what waits for your answer;
- what happened today: "Claude Code tried to erase your whole home folder in projects/api", "Codex tried to remove a
  service running in Kubernetes. It cannot ask you, so it was blocked";
- how careful Kytral Guard should be (three levels, below);
- what it watches, and one button that protects everything it found: the coding agents installed here and the local
  MCP servers of your apps.

**Advanced** has the details:
- **Activity**: today's counts, an hourly chart, whether the audit log is intact, and every entry with its finding, folder
  and rule. Open a blocked or asked command to always allow, ask or block that exact command.
- **Rules**: Block, Ask or Allow for each rule, for coding agents and for the MCP servers of AI apps.
- **Exceptions**: the exact commands and MCP tools you decided once, to remove.
- **Approvals**: the calls waiting for you, with their complete arguments.
- **Agents & apps**: what is protected; protect a coding agent, or the MCP servers of an app, in one click. A server
  whose protection no longer works (a new secret, Node.js moved) shows as not checked: protecting it again repairs it.
- **Settings**: what is kept, where the files are.

The page updates by itself as soon as an agent does something: there is nothing to refresh. A change shows Undo for a few
seconds. While a request waits for you, the browser tab says so ("(2) Kytral Guard needs you").

The page speaks English, French, Spanish, German, Italian, Brazilian Portuguese, Russian, Japanese, Korean and Simplified
Chinese. It follows your browser's language; the bottom of the Simple view, or Settings, changes it. What agents wrote
(commands, tool names, folders), the rules' examples and the log stay as they are.

## Protection levels

| Level | Coding agents | AI apps (MCP servers) |
|---|---|---|
| Relaxed | destructive commands, unreadable commands and SQL run without asking; payments and mass messages are asked | the same; tools a server did not declare run |
| Balanced (the presets) | destructive commands, unreadable commands and SQL, deleting MCP tools, payments and mass messages are asked | the same, and undeclared tools are asked |
| Strict | destructive commands and deleting MCP tools are blocked; the rest is asked | deleting tools and undeclared tools are blocked |

At every level, catastrophes stay blocked (`rm -rf ~`, `DROP TABLE`, `terraform destroy`, a force-push to `main`, writing
`~/.ssh`), and so does everything that would turn the guard off. A rule changed by hand in Advanced makes the level
"Custom"; picking a level sets those rules again.

## What the page cannot do

- **Allow a catastrophe.** The rules that block catastrophes (`shell-catastrophic`, `sensitive-file-write`,
  `sql-destructive`; for AI apps `destructive-sql`, `sql-unrestricted-write`, `rm-rf`, `recursive-delete-other-commands`,
  `sensitive-path` and `shell-destructive`, which also cover catastrophes there) can be set to Block or Ask, never Allow.
  An exact catastrophic command can only be allowed in your terminal: `kytral-guard allow --force --call <n>` (the page
  shows the line to run). To allow a whole rule anyway, edit the policy file. Every rule that matches a command counts,
  so "Always ask" and then "Always allow" does not get around this.
- **Weaken the guard's own protection.** `guard-tamper` stays Block (the policy file refuses it too).
- **Make an exception from a text that is not the command that ran**: a text whose secrets were masked, or that was cut,
  or that holds control or invisible characters (they can make a command look like another; the page shows them as
  `\u…` codes).

## Approvals

While the dashboard is open, the calls that need a human and that nobody can answer elsewhere wait for you on the page:
- calls of the MCP servers of your apps (the proxy has no screen);
- calls of agents that cannot show a prompt (Codex, Gemini CLI, Windsurf, Kimi Code, iFlow, opencode, MiMo Code, Droid,
  Auggie, Devin, Kiro, Cline), and of sessions that turned prompts off.

A hook waits for your answer as long as a remote approval (20 s by default, always ending before the agent's own hook
timeout); a proxy waits `KYTRAL_CONFIRM_TIMEOUT_MS` (60 s). Without an answer, the call is refused. To get more time,
set `remoteConfirmTimeoutSeconds` in `~/.kytral/config.json` (or `KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS`), and give the
agents a longer hook timeout with `kytral-guard init --timeout <seconds>`: the wait always ends 3 s before it. With no dashboard open,
these calls are refused at once, as before. `KYTRAL_CONFIRM_QUEUE=1` makes them always wait (answer with
`kytral-guard confirm`), `KYTRAL_CONFIRM_QUEUE=0` never. "Notify me" lets the browser show a notification when a request
arrives while the page is in the background.

## Where changes go

| On the page | In the files | Same as |
|---|---|---|
| Rules and levels | `overrides:` in the hooks' policy file (`~/.kytral/policy.yaml`) and in `~/.kytral/mcp-policy.yaml`, the policy of the MCP servers `mcp wrap` started without `--policy` or `--preset` | editing those files |
| Exceptions | a rule on one exact command (`allow-…`, `ask-…`, `block-…`) first in the hooks' policy | `kytral-guard allow` |
| Approvals | a signed decision in the confirmation queue | `kytral-guard confirm` |
| Stop all agents, Resume | the kill switch | `kytral-guard kill`, `resume` |
| Approved for good, removed | `known-tools.json` and its tombstones | `kytral-guard known remove` |
| Settings | `~/.kytral/config.json` (`keepCalls`, `auditAllows`) | editing that file |

A change that would make a policy invalid is refused and nothing is written; comments and hand edits are kept. Every
change is journaled (`policy-change`, `settings-change`, `mcp-wrap`, `kill`, `resume`, `known-remove`) with the OS account
followed by `(dashboard)`, never with a command's text. Stop all agents is never refused: if the audit log cannot be read
or cannot record it, the kill is written all the same and the page says what went wrong (Resume is refused until the log
can be read). Coding agents apply a change from their next tool call, and so do the MCP servers of your apps: the proxy
follows its policy file (a `--preset` stays fixed, a plugin's central policy is the plugin's). A policy file that no
longer loads makes the proxy refuse every call until it is fixed.

## The text of refused calls

The audit log never stores arguments. To show what an agent tried, and to make an exception from it, the text of the
calls that were blocked, asked or approved is kept apart, in `~/.kytral/kept-calls.jsonl`: the command, the file a write
touched, the SQL, or else the arguments, 4000 characters at most. Passwords, tokens and keys are masked before anything is
written (credentials in URLs, Authorization headers, cookies and sessions, `--password` and similar options,
`*_TOKEN=` and similar assignments, JSON fields such as `"api_key"`, the passwords of `mysql -p`, `curl -u`,
`sshpass -p`, `redis-cli -a` and `docker login -p`, known key formats, private keys). Masking takes a time linear in the
text, so a text built to slow it down cannot hold a hook's answer back. About the last thousand calls are kept. Turn it
off in Settings (or with `KYTRAL_KEEP_CALLS=0`); "Forget texts" deletes them. Masking is best effort: a secret in an
unusual form can stay readable, so the file is owner-only, like everything in `~/.kytral`. Each text is signed for its
file: only a text the guard of this home kept is shown and can become an exception (here or with
`kytral-guard allow --call`); one copied from another home, edited, or kept by an older version, unsigned, is not read.

## Security

- The server listens on 127.0.0.1 only, and answers only requests addressed to its own address and port (421
  otherwise), which defeats DNS rebinding.
- The link carries a one-time key (256 bits) in its fragment, which browsers never send to a server nor put in a
  Referer header; it works once, within 10 minutes. The page trades it for a session key, kept in sessionStorage (which
  belongs to this exact address and port) and sent in an Authorization header. There is no cookie: browsers send the
  cookies of 127.0.0.1 to every port, a development server an agent starts included.
- Changes need that header, a JSON body and, when the browser sends them, this page's Origin and `Sec-Fetch-Site:
  same-origin`. The server sends no CORS header, so no other site can read or act.
- What agents wrote (commands, tool names, folders, arguments) is shown as text, never as HTML, under a strict
  Content-Security-Policy: scripts, styles, images and fonts come from the page itself; no frame, no form.
- Agents cannot start it: the `guard-tamper` analyzer blocks `kytral-guard dashboard` (its link would sign them in).
- A link used twice is reported in the terminal. If your browser says the link was already used, someone opened it
  first: stop the dashboard and look at what runs on this computer.
- Limits: a process running as you can read the browser's storage, the terminal's output or `~/.kytral/secret`. See
  [threat-model.md](threat-model.md).
