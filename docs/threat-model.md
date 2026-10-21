# Threat model

Kytral Guard is a **control layer** in front of an agent's tools. It is not a sandbox, an antivirus or a permission
system of the operating system. This page says what it is built to stop, what it cannot stop, and why.

## What it protects

Your files, repositories, databases, cloud resources, credentials, customers' inboxes and money, from tool calls that an
AI agent makes on your behalf, through the integrations that route those calls to the guard: agent hooks, the MCP proxy
and the SDK.

## What it defends against

| Threat | How |
|---|---|
| **An agent making a catastrophic mistake** (wrong directory, empty variable, "clean up" gone wrong, migration reset on the wrong database, force-push) | structural analysis of shell, SQL and PowerShell; a catalog of destructive CLIs; deletion targets classified by blast radius; block or human confirmation |
| **Code the agent writes and then runs** (a script, a `package.json` script, a recipe, a git hook, a Python or JavaScript program) | what a command runs is read from the call's working directory and analyzed with it: `bash x.sh`, `./x.sh`, `source x.sh`, `npm`/`yarn`/`pnpm`/`bun` scripts (workspaces, turbo, lerna, nx), `make`, `just`, `task`, git hooks (`.git/hooks`, `core.hooksPath`, husky), `python`/`node`/`tsx`/`deno`/`bun` programs and the local modules they import, here-documents, `crontab` files, files the same command writes before running them; variables set by plain assignments are followed; a script nobody can read (too large, downloaded by the same command) is confirmed |
| **A prompt-injected agent** told by a web page, an issue or a file to destroy something | the same analysis applies whatever the agent's intent; obfuscation is normalized (encodings, homoglyphs, quoting tricks, `$IFS`, ANSI-C strings, nested shells, remote execution); what cannot be resolved statically is confirmed, never guessed |
| **An agent disabling or bypassing its guard** in the obvious ways | the coding-agent preset blocks reading the secret, running `kytral-guard resume` / `confirm approve` / `uninstall` / `mcp unwrap` / `allow` / `dashboard`, removing the global package (`npm uninstall -g kytral-guard`), and writing the guard's files, its installed code and the agents' hook configuration (`.claude/settings*.json`, `.cursor/hooks.json`, `.grok/hooks/`, `~/.kytral` or a custom `KYTRAL_HOME`, whether named by path or through `$KYTRAL_HOME`) |
| **A forged approval, resume or grant** written to a state file | requests, decisions, kill switch states, grants and kept calls are HMAC-signed with a key derived from the deployment secret, for the file or folder they belong to (an id derived from its real path): copied from another home that uses the same secret, they do not count there (see [Files of another home](#files-of-another-home)); the waiting process only acts on its own in-memory request |
| **Replay of an old state** (restored backup of the kill switch or grants) | kill switch generations are monotonic and signed; agent hooks (a new process at each call), MCP proxies and SDK guards start from the last kill or resume recorded in the audit log's signed tail marker; the marker and every kill and resume in the log sign the id of their log: deleting `kill-switch.json`, putting back an older resume, or putting in place `kill-switch.json`, the log or the marker of another home with the same secret, alone or together, does not lift a kill for one started afterwards. A marker in doubt (another home's, an older version's, edited) never lets a resume found in the log count: with no kill of this log as recent, it stops every call until a resume, and so does a kill or resume of another log found in this one; removed grants leave tombstones. A kill is still lifted, for guards started afterwards, by a same-user rollback or wipe of this home's own `kill-switch.json`, audit log and marker together (see below) |
| **Silent tampering with the audit log** by someone without the key | HMAC chain, sequence numbers and a signed tail marker detect modified, inserted, deleted, reordered or truncated entries |
| **Badge theft or reuse** across MCP proxies | audience binding, expiry, revocation, optional single-use binding |
| **A crashing or misconfigured guard** | fail closed: errors refuse the call; hooks are installed with the agent's fail-closed option where it exists (Claude Code, Cursor: no other agent has one, see [agents.md](agents.md#when-the-hook-itself-fails)) |
| **A file of the guard swapped for a FIFO, a device or a folder**, so that a hook waits past the agent's timeout (most agents then run the tool) | the files of `KYTRAL_HOME` a hook or a proxy reads (audit log, tail marker, kill switch, policy, configuration, kept calls...) are opened only as regular files, without waiting (type checked before and after a non-blocking open): hooks refuse at once, a proxy refuses to start, `kill` is written all the same (exit 3) and `resume` refuses. Not plugin modules, which Node loads ([plugins.md](plugins.md)) |
| **A state file built so that checking it fails** (JSON nested thousands of levels deep) | refused as corrupt at every check, never thrown out of a guard: a proxy keeps running and refusing; `kill` writes over it (exit 3) |
| **Input built to slow the guard down**, so that the agent's hook timeout lets the call through | analyzers and preset patterns fuzzed for super-linear running time; SQL parsing has its own deadline and refuses unbalanced parentheses; in hooks, every call is analyzed in a worker stopped after 8 s (and before the agent's own timeout), calls over 2 MB are not analyzed: a human confirms |
| **A broken or hanging plugin** | a plugin that does not load, throws in its kill switch or provides an invalid policy refuses every call; waits on plugins are bounded; a hook that would end without an answer refuses |
| **Tools an MCP server never advertised** | confirmation by default (`unknownTools: confirm`) |
| **Another program or web page acting through the dashboard** | it listens on 127.0.0.1 and answers only its own address (DNS rebinding); one-time link, session key in an Authorization header and no cookie (other local servers never receive it), JSON changes from its own origin only, text-only rendering under a strict CSP; agents cannot start it; a catastrophe cannot be allowed from it |

## What it does not defend against

- **Calls that do not go through it.** A hook only sees the tools it is registered for; the proxy only sees the servers it
  wraps; the SDK only sees wrapped functions. A tool the agent reaches another way is not guarded.
- **A determined process running as the same OS user.** It can read `~/.kytral/secret` (and therefore forge approvals or
  a resume), edit or delete the guard's files, remove the hook from the agent's configuration, or turn hooks off. The
  self-protection rules block the obvious paths, not every path (a Python script can write a file the analyzer does not
  see). For a hard boundary, run the agent under another OS user or in a container, deploy hooks through managed
  settings, and keep approvals and the kill switch off the machine (Kytral Guard Pro, coming soon).
- **Code loaded another way, or changed after the check.** Files are read when the call is checked, from the working
  directory the agent reports (the MCP proxy and the SDK have none: there, only the command line is judged). Not analyzed:
  files a tool picks up on its own (test files run by a test runner, `webpack.config.js`, plugins), dependencies
  (`node_modules`, `site-packages`, `vendor`), local modules beyond 48 files or 3 MB, scripts beyond 64 files or 4 MB per
  call (confirmed), programs in other languages, code built at run time (`eval` of computed text inside a script), and a
  script modified between the check and its run. In programs, deleting a computed path is routine and not reported,
  unless a home or root directory is in sight. Keep version control and backups.
- **A hostile MCP server.** It can advertise its own tools, annotate them as harmless and do anything when called. Only
  run servers you trust.
- **Every destructive command ever written.** The catalog and analyzers cover the common catastrophes; an unusual CLI may
  be missing. Policies can add rules, and reports of missed catastrophes are the most valuable contribution.
- **Data exfiltration.** Reading a file and sending it out is not destructive; Kytral Guard is not a DLP tool.
- **The plugins you install.** A plugin runs inside the guard and can replace its policy: install only plugins you trust.
  Agents cannot edit `~/.kytral/config.json` through guarded tools.
- **Clock and identity of approvers.** `--by <name>` and the OS account are declared, not verified.
- **A rollback or a wipe of this home's own files** by a same-user process: rolling back the audit log and its tail
  together, or a state file before a running guard reads it, needs an anchor outside the machine to be detected. For the
  kill switch: rolling back or deleting this home's own `kill-switch.json`, audit log and marker together lifts a kill for
  agent hooks, proxies and SDK guards started afterwards (with all three gone, the home looks new). Deleting
  `revocations.json`, `nonces.json` or the tombstones of grants undoes what they refuse for guards started afterwards (a
  running proxy keeps the revocations and tombstones it has seen). A kill that `kill` could not journal (exit 3) rests on
  `kill-switch.json` until `kill` is run again once the log is repaired. This limit is about this home's own files only:
  the files of another home, copied in alone or together, never lift a block or grant an allow here (see below).
- **A home redirected to a blank one**: `KYTRAL_HOME` (or `KYTRAL_AUDIT`, or the home folder replaced by a link)
  redirected to a blank home is like a wipe: the kill is lifted for new processes (agent hooks, proxies and SDK guards
  started afterwards); a proxy (or SDK guard) already running keeps the id it started with and stays stopped. An agent
  able to change the host's environment is outside the threat model. `kytral-guard doctor` and the agent hooks (one line
  on stderr) report a place left with none of the kill switch's files while a default path that `KYTRAL_HOME` or
  `KYTRAL_AUDIT` replaces still holds one: a warning, not a block, which a determined same-user process can avoid
  ([kill-switch.md](kill-switch.md#limits)).

## Files of another home

Several homes can share a secret (two `KYTRAL_HOME`s of one user, a copy restored elsewhere), so a file signed in one
carries a valid signature in another. Everything that can lift a block or grant an allow is therefore bound to the file
or folder it was written for (`dep`: an HMAC, with a key derived from the secret, of its real path, inside its signature),
or refused. The table covers each file of `KYTRAL_HOME` copied from another home that uses the same secret, alone or with
the others, with this home's own deleted or not: `test/kill-switch-cross-home.test.ts` runs every combination of the
three kill switch files for hooks and SDK guards, and `test/cross-home.test.ts` the rest, a whole home copied over this
one included. This home moved to another path, or reached through another real path, counts as another home for these
ids: it stops every call until a `resume`, and its grants and kept calls no longer count (fail closed). Two machines that
share the secret and the same `KYTRAL_HOME` path compute the same ids: give each its own `KYTRAL_AUDIT_SECRET` or path
([kill-switch.md](kill-switch.md#trade-offs-of-the-derived-id)).

| File | Can it lift a block or grant an allow? | Bound to its home (`dep`)? | Copied from another home |
|---|---|---|---|
| `kill-switch.json` | a resume lifts a kill | yes, signed | another home's resume never lifts a kill here; its kill stops every call |
| `audit.jsonl`: kill and resume entries | new guards start from them | yes, in each entry's MAC | never this log's: one more recent than this log's own last record stops every call until a resume |
| `audit.jsonl.tail` | new guards start from its record | yes, signed | in doubt: never lifts a kill nor counts as a resume; with no kill of this log as recent, every call stops until a resume |
| those three, in any combination | | | refused or held: a kill is lifted only by a rollback or a wipe of this home's own three (the limit above) |
| `audit.jsonl`: other entries | no: shown and verified, never read to decide | chained (HMAC) | no effect on any decision |
| `known-tools.json` ("always" grants) | a grant allows an unknown tool without asking | yes, its key | rejected (`known-reject`): the tool is asked about again |
| `confirmations/` (requests, decisions) | a decision approves a call or a grant | yes, its key (the folder) | another home's requests are neither shown nor answerable here, and its decisions are refused (`confirm-invalid`) |
| `kept-calls.jsonl` | becomes an exception with `allow --call` or the dashboard | yes, each line signed | not read: no exception can be made from it |
| `secret` | it is the root of every signature | (the root) | another secret: what this home signed no longer verifies, and every call stops; with that home's files too, they are bound to its paths: every call stops |
| `revocations.json`, `nonces.json`, `known-tools.tombstones.json` | no: they only refuse | no | add refusals; replacing this home's is a wipe of it (the limit above) |
| `dashboard.json`, `mcp-files.json` | no | no | confirmations wait in this home's queue for a human of this home, else are refused when they time out; `mcp list`, `doctor` and `uninstall --all` see other files |
| `policy.yaml`, `mcp-policy.yaml`, `config.json`, plugin modules | yes: a person writes them, and plugins are code | no signature: a copy is an edit | the same-user limit above (agents cannot write them); no policy lifts a kill, which is checked first |
| badges (`KYTRAL_BADGE`, not a file of a home) | they identify an agent, the policy decides | their audience (one per proxy), expiry, revocations | the kill switch is checked before them |
| `*.lock`, `*.tmp`, `*.moved-aside`, `kill-switch.id` | no | | a lock can delay a writer (a `kill` never waits more than 1 s); the others are never read |
| `KYTRAL_HOME` (or `KYTRAL_AUDIT`, or the home folder replaced by a link) redirected to another home | the guard then uses that home | ids follow real paths (a link in the path reaches the same folder) | no copy: this home's own files are out of sight. Redirected to a blank home, it is like a wipe: the kill is lifted for new processes (agent hooks, proxies and SDK guards started afterwards); a proxy (or SDK guard) already running keeps the id it started with and stays stopped (the limits above; `doctor` and the hooks warn about it: a warning, not a block) |

## Windows

Kytral Guard and its test suite run on Windows too (the suite in CI). What differs there:

- **File permissions.** On Linux and macOS, `KYTRAL_HOME` is created owner-only (0700), and so are its files (0600).
  Windows has no such modes: the access control lists (ACLs) of the folder decide who can read or change the secret and
  the state files. `~/.kytral` inherits those of the user profile (by default, only that user, administrators and
  SYSTEM have access); a `KYTRAL_HOME` outside the profile inherits those of its parent folder, which may let other
  users read it: restrict them yourself. Kytral Guard refuses no file for its owner or its mode, on any system; what
  Windows skips is the warning of `kytral-guard doctor` when other users can open `KYTRAL_HOME` (it reads the mode),
  and narrowing back to owner-only a `confirmations` folder that already existed. The tests of these modes do not run
  on Windows, nor those that make the audit log or its tail marker unreadable with `chmod`, which cannot take read
  access away there.
- **Symbolic links.** Creating one on Windows needs Developer Mode, or a process run as administrator. The guard checks
  links the same way there (a link in place of the default secret file is refused, state files are checked through
  links, ids follow real paths), but their tests are limited: the one for a link planted in place of the secret file is
  skipped when no link can be made, the one for Homebrew's links does not run on Windows, and the others that plant a
  link need one of the two.
- **Kill switch.** Several processes running `kill` and `resume` at once are tested on Linux and macOS, not on Windows:
  the test starts them from bash. The file lock they rely on is tested on Windows too, by several processes that write
  the audit log, revocations or grants at once. The ids of paths that hold a line break, which no Windows file name can
  hold, are tested on the other systems only.

## Design decisions

- **Fail closed.** When the guard cannot decide, the answer is no. Most agents run the tool when a hook fails, so the
  guard answers every error itself, never waits on one of its files, and hooks are installed with the agent's fail-closed
  option where one exists.
- **Decide what can be decided, confirm the rest.** Structural analysis (SQL AST, shell argv) instead of text patterns
  alone; regex rules remain a safety net. A variable in command position, a bind parameter, a script piped into a shell
  or an unparseable SQL write is confirmed. Inside script files, dynamic code is routine (variable commands,
  redirections to computed paths, `eval`, sourcing a computed path): there it is not confirmed by itself, while remote
  code, scripts nobody can read and unknown commands run on `/` or `~` still are.
- **Blast radius, not keywords.** `rm -rf node_modules` is routine, `rm -rf src` needs a human, `rm -rf ~` is refused.
  A guard that blocks routine work gets uninstalled.
- **Refusals explain themselves** to the agent, so it can tell the user instead of looking for another way.
- **Tool arguments are not journaled whole.** They can contain secrets and personal data. A refusal keeps only its finding
  (the fragment of the command or SQL statement that was refused, for example the target path of an `rm`, 300 characters
  at most), so that a human can understand it, and a hook's entry keeps the working directory.
  The text of refused, asked and approved calls is kept apart for the dashboard (`kept-calls.jsonl`, masked, owner-only,
  about the last thousand calls, can be turned off), never in the log.

## Testing

The test suite keeps every bypass ever found as a regression test (`test/bypass*.test.ts`), plus corpora of
catastrophic, destructive and harmless commands (`test/catastrophe-catalog.test.ts`) and false positives
(`test/analyze-v5.test.ts`). Known open limits are kept as `todo` tests. Found a bypass? See [SECURITY.md](../SECURITY.md).
