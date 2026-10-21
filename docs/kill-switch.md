# Kill switch

```bash
kytral-guard kill [--by name]     # every agent hook, proxy and SDK guard using this KYTRAL_HOME refuses every tool call
kytral-guard resume [--by name]   # lifts it (needs the deployment secret, and KYTRAL_AUDIT_SECRET if it was set)
```

`kill` exits **0** when the kill is written and journaled; **3** when it is written and in force, with a caveat that
stderr gives: the audit log could not be read or could not record it (see [State and replay protection](#state-and-replay-protection)),
or `kill-switch.json` held something that could not be checked and the kill took its place (see [Fail closed](#fail-closed));
**1** when nothing could be written: agents are **not** stopped; **2** on a usage error. 3 rather than 0, so that a
script that checks `kill` sees that something needs a human (`resume` is refused until the log can be read); rather than
1, which says that nothing was written. The caveat of a kill the log could not record: it is in no journal entry and in
no tail marker, so it rests on `kill-switch.json` and on the guards that already saw it; deleting the file would lift it
for hooks, proxies and SDK guards started afterwards. Repair the log, then run `kill` again. `resume` exits 0 when done,
1 when refused or failed (nothing written).

- **Agent hooks** read the switch on every tool call: the next call is refused. Claude Code also receives
  `continue: false`, which ends its loop.
- **Proxies** read it before every tool call (re-parsed when its content changes) and while a confirmation is pending;
  when idle they poll it every 250 ms and say on stderr when they stop or run again. No restart is needed.
- The kill wins over everything: known tools, allow rules and pending confirmations, which are refused at once (within
  100 ms; the queue request is withdrawn, and an "always" given meanwhile is not recorded). Calls already running are not
  interrupted. Only tool calls are blocked, as with `KYTRAL_KILL=1`: an MCP client can still list tools, `resources/read`,
  `prompts/*` and the client's other requests still pass during a kill, and so do the requests the server sends to the
  client (sampling, elicitation, roots) and their replies.

## State and replay protection

- Shared state: `$KYTRAL_HOME/kill-switch.json` (0600), written under the inter-process lock (0600 temp file + atomic
  rename).
- Replay protection does not depend on the clock. Each kill or resume carries a generation, the previous one + 1,
  HMAC-signed with the deployment key (derived from `KYTRAL_AUDIT_SECRET`, else the deployment secret, label
  `kill-switch/v1`) together with its time, which is only displayed and journaled. A running guard (an MCP proxy, an SDK
  `Guard`, the dashboard) accepts a state only if its generation is greater than the last one it saw: a kill and a resume
  in the same millisecond work, a clock set back does not block a resume, and an older state put back (from a backup, or
  after the file was deleted) is refused, whatever its date.
- Writers never make the generation go back: they continue from the file's, or, when the file is missing, corrupt or
  rolled back, from the highest one journaled by `kill` or `resume` in the audit log (the later of the two). Journal
  entries with a generation above 2^40 or that is not a positive integer are ignored. Only journal entries whose HMAC
  verifies with the audit key count (a line appended without the key, edited, or MAC'd with another key is skipped, so a
  forged huge generation cannot block `resume` and a forged low one cannot lower the floor); the floor is the maximum of
  those. Entries written before HMAC chains, or by a `kill` run without a secret, do not count for it (the file's own
  generation then applies). An `AuditLog` built by hand without a key is read unverified.
- The log is read as a stream, 1 MB at a time, whatever its size (about 0.1 s for 200 MB and 0.3 s for 600 MB when the
  system has it in memory, more from disk; see [audit-log.md](audit-log.md) to start a new log). A log that exists but
  cannot be read (no permission, a folder in its place, an I/O error) makes `resume` refuse: exit 1, nothing written, the
  generation kept for when it can be read again. A resume written without it could carry an older generation: running
  guards would refuse it (they stay stopped while the command says OFF), and a later resume could chain wrongly. **A kill
  is never refused**: `kill` writes it all the same, one generation after the highest it knows without the log (the last
  kill or resume the log's signed tail marker records, the generation of `kill-switch.json`, and the lines read before the
  error, if any), journals it if the log still takes the entry, says so on stderr and exits 3. Without a marker the log may
  hold a higher generation: running guards that saw it take the kill for a replay, which blocks every call too (fail
  closed), until a `resume` once the log can be read. A `kill` run without a secret carries no generation and does not
  read the log.
- A resume is chained to what it replaces. Each signed state also signs `after` (SHA-256 of the file content it replaced,
  `none` if there was none) and `dep`, the id of this deployment: an HMAC, with the deployment key, of the real path of
  `kill-switch.json` (its directory with links resolved, plus the file name; a link put in place of the file itself is not
  followed). The id is derived, never stored: there is nothing to copy to another home and computing it needs the secret,
  so a `resume` run in another home with the same secret, even over a copy of this home's kill, signs that home's id and
  lifts nothing here. A guard computes the id when it starts and never changes it while it runs. It lifts a kill only with
  a resume that carries it, has a generation greater than the last one seen, and chains to a kill it holds; a signed
  resume taken from another home or an older install does nothing, whether the kill in force is signed or not. A kill
  that does not carry the id (from another home, or chained to unsigned or corrupt content) still stops the guard but
  moves neither its generation nor its id. Unsigned or corrupt content that arrives while a signed kill is in force is
  never something a resume can chain to. If the file was deleted or overwritten, the resume chains to the kill the journal
  says is in force, if the journal entry is authenticated: only entries whose HMAC verifies with the audit key count (a
  kill written without a secret is journaled without one, so after a deleted file the resume does not chain to it and the
  guard stays stopped until the next `kill` + `resume`; fail closed). Only v2 states exist: v1 states (never published)
  are refused. A guard that missed an intermediate kill (the file changed twice between two checks) refuses the resume
  that follows it and stays stopped until the next `kill` + `resume` or a restart (fail closed).
- Agent hooks run as a new process for each tool call, with no memory of the states seen before, and an MCP proxy or
  an SDK guard that starts has none either. Each one starts from the last kill or resume the audit log records: every
  writer that holds the audit key records it (its generation and the SHA-256 of the state it wrote) in the log's
  signed tail marker, so a guard reads it in two small reads. The marker also signs the id of its log (`dep`: an HMAC,
  with the audit key, of the log's real path, derived as the id of `kill-switch.json` is), and so does every kill and
  resume journaled with the key, inside its MAC: they speak for that log only. The marker is believed while it
  certifies the log as it is (the entry it names in place, nothing written with the key after it); otherwise (put
  back, a log cut short, replaced or renamed) its record stands and the log can only add a later kill of its own: a
  later resume found only in the log does not lift it. Without a marker, the guard reads the log itself and starts
  from the log's own last kill or resume. A kill or resume of another log (copied in from another home that uses the
  same secret, or this log reached through another path) or of an older version (no id) is never this log's: one more
  recent than what speaks for the log **holds** the switch (below), unless that is a kill of this log. A marker **in
  doubt** (taken from another home that uses the same secret, or from this one through another path; written by an
  older version, which signed no id; edited, forged, written with another key, or unreadable) never lifts a kill, and
  a resume found in the log never counts then: a kill of this log at least as recent as what is in doubt stands;
  otherwise the switch is **held**: every hook, proxy and SDK guard refuses every call, whatever `kill-switch.json`
  holds until the next `resume` (`the audit log's tail marker ..., so the last kill or resume is not known, ...: a
  single 'kytral-guard resume' lifts it`; when the doubt is an entry, `the audit log holds a kill or resume written
  for another audit log ...` or `... written by an older version of Kytral Guard ...`), the markers that entries write
  meanwhile keep it held, and a single `resume` lifts it, for running proxies and SDK guards too. So the log, the
  marker and `kill-switch.json` of another home, copied in alone or together, with this home's own deleted or not,
  never lift a kill. A hook, a proxy or an SDK guard started after a kill refuses a missing `kill-switch.json`, and an
  older resume put back over it (`holds a replayed resume`), until a `resume`. A guard reads its own audit log and,
  for the default `kill-switch.json`, the default one (`$KYTRAL_AUDIT`, else `$KYTRAL_HOME/audit.jsonl`), where
  `kytral-guard kill` and the dashboard journal; a log that cannot be read stops it from starting (a hook refuses the
  call, a proxy refuses to start, an SDK `Guard` throws). `kill` and `resume` count the generation of any marker, and
  of any kill or resume in the log, that verifies in their floor too, and a `resume` chains only to a kill of this
  log. `doctor`, `doctor --report`, `check` and the dashboard show the switch as a hook finds it.

### Trade-offs of the derived id

All fail closed: a state carrying another id still stops a guard, it never resumes one.

- **Another path:** the same directory reached through another real path (bind mount, container) or moved elsewhere has
  another id, so states written through the other path stop the guard but never resume it: run `kill` then `resume`
  through the path the guard uses (after a move, restart the proxies on the new path, then `kill` + `resume`).
- **Case:** links are resolved but the case of the path is kept as written, so on a case-insensitive file system (the
  default on macOS and Windows) the same directory spelled with another case (`KYTRAL_HOME=~/.Kytral` for the CLI while
  the proxy uses `~/.kytral`) has another id: states written with that spelling stop the proxy but never resume it, until
  a `kill` + `resume` run with the proxy's spelling.
- **Unresolvable path:** if the real path cannot be resolved when the guard starts (for example `KYTRAL_HOME` goes
  through a link whose target does not exist yet), the guard derives its id from the path as given, while the writers,
  once the link resolves, sign the id of the real path: a kill still stops the guard, but no `resume` lifts it until the
  guard is restarted.
- **Upgrade:** a state written by a version that kept a random id in `kill-switch.id`, or a v1 state, does not carry this
  version's id, so a guard of this version that finds it starts stopped (a v1 state is refused as `a v1 state, written by
  an older version of Kytral Guard`). A single `kytral-guard resume` lifts it: it chains to that state, no `kill` is
  needed first, and `resume` then says that agents run again. `kill-switch.id` is no longer read or written: copying,
  editing or deleting it has no effect. The audit log's tail marker written by an earlier version signs no log id, and
  neither do the kills and resumes it journaled: they are in doubt. Whatever they record (a kill in force, a resume, or
  no kill or resume at all) and whether `kill-switch.json` is there or not, every agent hook, proxy and SDK guard refuses
  every call with `kill switch active: the audit log's tail marker was written by an older version of Kytral Guard, so the
  last kill or resume is not known, every tool call is refused (fail closed): a single 'kytral-guard resume' lifts it`
  (`the audit log holds a kill or resume written by an older version of Kytral Guard, ...` when the marker is gone;
  `doctor` says the same). A single `kytral-guard resume` lifts it, for running proxies and SDK guards too: it journals
  the resume with this log's id and writes a marker with it, and from then on the switch works as usual (the older
  entries stay in the log, below the new generation). Restart the proxies of the older version: they still write markers
  without the id, which hold the switch again. A marker or entries in doubt for another reason (this home moved to
  another path, a new secret or `KYTRAL_AUDIT_SECRET`) are handled the same way.
- **Two machines, same secret, same path:** they compute the same ids (of `kill-switch.json`, of the audit log, its
  marker and entries, and of grants, the confirmation queue and kept calls), so the files of one, copied to the other,
  count there as its own: a resume written on one over a kill copied from the other lifts it there. Give each machine
  its own `KYTRAL_AUDIT_SECRET` (every one of these keys is then derived from it) or its own `KYTRAL_HOME` path. Known
  limit: no machine identifier (`/etc/machine-id`, IOPlatformUUID, MachineGuid) is mixed into the id. They are
  missing, shared or regenerated in containers, cloned VMs and some WSL or read-only systems; macOS and Windows would
  need `ioreg` or `reg` run at every start; and a proxy and a CLI that read different values (a container and its host
  sharing a mount at the same path) could never resume each other.

## Fail closed

- Only a valid resume lets calls through. An engaged kill, an unreadable or corrupt file, an unsigned or forged resume,
  and a replayed state all block every call. Deleting the file does not lift a kill for a running guard. An unusable state
  is journaled once (`kill-switch-invalid`); refused calls are journaled `block`, rule `kill-switch`.
- Content built so that checking it fails, such as JSON nested thousands of levels deep (JSON.parse reads it, signing it
  again would overflow the stack), is refused as corrupt (`JSON nested too deep to be a state`) at every check: the check
  never throws, so a proxy's poll keeps running and a guard never falls back on an older verdict. `kill` writes over it
  (exit 3, with a warning).
- The audit log, its tail marker and `kill-switch.json` are only opened as regular files, and no open waits: the type is
  checked before the open (lstat, and what a link points to) and on what was opened (fstat), and the open is non-blocking
  (O_NONBLOCK). A FIFO put in their place (opening it would wait for a writer, and an agent whose hook times out may run
  the tool), a socket, a device or a folder is never read: a `kill-switch.json` that is no regular file is unreadable for
  every guard (every call refused); a log or a marker that is no regular file makes agent hooks refuse at once and a proxy
  refuse to start, and a running proxy refuses every call it cannot journal. `kill` is written all the same (exit 3, with a
  warning): the rename that puts it in place replaces a FIFO, a socket, a device or a link there, and a folder, which a
  rename cannot replace, is first moved aside to `kill-switch.json.<random>.moved-aside` (nothing it held is lost); a
  marker that is no regular file is not read, and the kill's journal entry writes a new one. `resume` refuses while
  `kill-switch.json`, the log or its marker is no regular file: remove it, then run `resume` again. Temp files are created
  exclusively, under a random name, so nothing planted at a predictable name is opened. The other files a hook or a proxy
  reads in `KYTRAL_HOME` (the policy, `config.json`, a `KYTRAL_SECRET_FILE`, kept calls, the confirmation queue,
  revocations, nonces, known tools) are read the same way. Plugin modules are not: Node loads them (`import`), so a FIFO
  put in place of one holds a hook until the agent's timeout ([plugins.md](plugins.md)).
- `kill` is signed with the next generation when a strong secret is available. It also works without one: it is then
  written unsigned, honored as a kill but not trusted for ordering, and it carries the last signed state, so a guard
  started meanwhile still knows the generation. `kill` never waits for a stuck lock: if the lock cannot be taken within
  1 s, the state is written without it (still atomically). `resume` needs the secret, the lock and an audit log that can
  be read (or none yet); `kill` needs none of them: see above.
- Every kill and resume is journaled (`kill`, `resume`) with who did it (the OS account, plus `--by <name>` if given:
  declared, not verified), the generation it wrote, the SHA-256 of the state it wrote (`state`) and, with the audit
  key, the id of the log (`dep`, inside its MAC). A resume is journaled before it takes effect. A kill the log cannot
  take is in force all the same: `kill` says so on stderr and exits 3.

## Process-local switches

`guard.kill()` (SDK) and `KYTRAL_KILL=1` (read when a proxy starts) stop one process only; `kytral-guard resume` does not
lift them, and `guard.resume()` does not lift `kytral-guard kill`.

## Limits

- A process running as the same OS user can restore an old copy of the file before a running guard has read the kill
  (same-user rollback). Agent hooks, proxies and SDK guards start from the audit log's last kill or resume: for one
  started afterwards, a kill is lifted only by rewriting this home's own `kill-switch.json`, audit log and tail marker
  together (rolled back to before the kill, or deleted), which only an anchor off the machine can detect (Kytral Guard
  Pro, coming soon; the coding-agent preset refuses agents writes to `KYTRAL_HOME`, but a process outside the agent
  can do it). The files of another home that uses the same secret, put in place of these, never lift it (see above);
  on another machine, at the same path, they carry the same ids (see Trade-offs). A kill written without a secret is
  journaled without a MAC and is not in the marker, and a kill the log could not record (`kill` exit 3) is in neither:
  deleting its file lifts it for guards started afterwards, until `kill` is run again once the log can record it.
- `KYTRAL_HOME` (or `KYTRAL_AUDIT`, or the home folder replaced by a link) redirected to a blank home is like a wipe: the
  kill is lifted for new processes (agent hooks, proxies and SDK guards started afterwards); a proxy (or SDK guard)
  already running keeps the id it started with and stays stopped. An agent able to change the host's environment is
  outside the threat model.
- **A warning, not a block.** `kytral-guard doctor` (a `warn` line with the paths) and every agent hook (one line on
  stderr, after its answer, without any path: `Kytral Guard: warning: no kill switch state where KYTRAL_HOME or
  KYTRAL_AUDIT points, although the default location still holds some (wiped or redirected?): ...`) report a place left
  with no kill switch state: `KYTRAL_HOME` or `KYTRAL_AUDIT` is set, none of the three files the switch is read from
  exists there (`kill-switch.json`, the audit log, its tail marker), and a default path that the variable replaces still
  holds one (`~/.kytral/kill-switch.json`, `~/.kytral/audit.jsonl` or its marker for `KYTRAL_HOME`;
  `$KYTRAL_HOME/audit.jsonl` or its marker for `KYTRAL_AUDIT`). These paths are only checked for existence, before the
  hook reads anything: nothing is opened, read, written or created, and no secret is used. The hook's answer, its stdout
  and its exit code are the same with the warning as without it; proxies, SDK guards, `doctor --report` and the
  in-process API (`runHook`, `runHookAsync`) say nothing. It is silent when neither variable is set, on a fresh install
  (no default home), and as soon as one of the three files exists in the new place: hooks journal every call by default
  (`KYTRAL_AUDIT_ALLOWS`), so the warning comes with the first call made there, and from `doctor` until then. It misses
  a wipe of the default home itself and that folder replaced by a link (no variable is set: there is nothing to compare
  with), a redirection from one custom home to another (only default paths are evidence), and a new place that already
  holds one of the files (an empty audit log is enough): a determined same-user process avoids it.
- An SDK guard with a `killSwitchFile` of its own and an audit log kept in memory has no journal to start from: deleting
  that file before it starts lifts a kill for it. Give it an `AuditLog` with a file (the one `engageKillSwitch` writes to).
- A writer that lost both the file and the audit log starts again at generation 1: running guards refuse it and stay
  stopped until they are restarted (fail closed).
- Anyone on the machine who holds the secret can resume, including an agent that managed to read it, and through any path
  that leads to this directory: the id binds a state to the directory, not to who runs the command (a link planted in
  place of another operator's `KYTRAL_HOME` makes their routine `resume` act here). The coding-agent preset blocks the
  obvious ways (`cat ~/.kytral/secret`, `kytral-guard resume` run by the agent), not every way. A kill switch that an
  agent cannot lift needs its key off the machine (Kytral Guard Pro, coming soon).
- On Windows, several processes running `kill` and `resume` at once are not tested (the test needs bash), and the
  switch's files are protected by the folder's ACLs, not by the modes 0600 and 0700: see
  [Windows](threat-model.md#windows) in the threat model.
