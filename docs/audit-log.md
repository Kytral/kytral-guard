# Audit log

Every decision of every hook, proxy and SDK guard is appended to one log: `$KYTRAL_AUDIT`, else
`$KYTRAL_HOME/audit.jsonl` (default `~/.kytral/audit.jsonl`). One JSON object per line:

```json
{"ts":"2026-10-15T07:29:04.511Z","agentId":"claude-code","tool":"Bash","decision":"block","rule":"shell-catastrophic","reason":"matched rule 'shell-catastrophic': rm -r ~","server":"/home/me/project","seq":12,"prev":"…","hash":"…","mac":"…"}
```

| Field | Meaning |
|---|---|
| `agentId` | the badge's agent (proxy, SDK), or the agent name for hooks (`claude-code`, `cursor`…) |
| `tool` | the tool name as the agent sent it |
| `decision` | `allow`, `block`, `ask` (a human was asked in the agent), `confirmed` / `confirmed-always` (a human approved), and the control events `kill`, `resume`, `known-add`, `known-remove`, `known-reject`, `confirm-invalid`, `kill-switch-invalid`, `known-tools-corrupt`, plus the changes made on the dashboard (agent `dashboard`) and in a terminal by `init`, `uninstall` and `mcp wrap` / `unwrap` (agent `*`): `policy-change`, `settings-change`, `mcp-wrap`, whose `reason` says what changed (never a command), such as `removed the hook of Claude Code` |
| `rule` | the policy rule that decided |
| `reason` | for refusals from hooks: the finding (`rm -r ~`), never the full arguments |
| `server` | the MCP server key (proxy), or the working directory (hooks) |
| `approver` | who took a human decision (OS account, plus `--by <name>` if given: declared, not verified) |
| `generation` | the kill switch generation a `kill` or `resume` wrote |
| `state` | the SHA-256 of the `kill-switch.json` content a `kill` or `resume` wrote ([kill-switch.md](kill-switch.md)) |

**Tool arguments are not journaled whole**: they can hold secrets and personal data. A refusal keeps only its finding
(`reason`: the fragment of the command or SQL statement that was refused, for example the target path of an `rm`, 300
characters at most), which can still hold a name or a path; a hook's entry keeps the working directory (`server`). The
confirmation queue keeps the full arguments of a pending call only until it is answered.

Set `KYTRAL_AUDIT_ALLOWS=0` to skip `allow` entries of agent hooks (refusals and confirmations are always journaled).

## Verify it

```bash
kytral-guard audit verify [file]   # needs the deployment secret (and KYTRAL_AUDIT_SECRET if it was set)
```

Exit **0**: everything verifies. **1**: something was modified, deleted, inserted, reordered or truncated, or written with
another key (the first broken line is printed). **3**: nothing is broken, but some lines cannot be verified (see below).
**2**: no usable key.

When it says BROKEN: copy `audit.jsonl` and `audit.jsonl.tail` somewhere else as they are, before anything writes to them
again; the lines before the one printed still verify. Then find out what changed it: an edit by hand or a script, a
restore from a backup, a disk that filled up during a write, or a secret replaced since (verify with the old one). To
go on with a clean chain, rename both files as for an archive (see the end of this page); Kytral Guard starts a new log.

## How it is protected

- Each entry carries `mac = HMAC-SHA256(auditKey, prev || canonical JSON of the entry)`, where `prev` is the previous
  entry's mac, plus `seq` (its position). The key is derived from `KYTRAL_AUDIT_SECRET` if set, else the deployment
  secret (`KYTRAL_SECRET` or `$KYTRAL_HOME/secret`), with the label `audit/v1`; it is never written to the log. Without
  the key, an attacker who edits an entry cannot produce a valid mac, even after recomputing its SHA-256.
- A signed tail marker, `<log>.tail` (0600, written under the same lock), certifies the last entry: removing lines from the
  end is detected. It also records the last kill or resume (its generation and the digest of the state it wrote), which
  agent hooks start from at each call ([kill-switch.md](kill-switch.md)), and signs the id of its log (an HMAC of the log's
  real path), as every `kill` and `resume` entry does inside its mac (`dep`): a marker or an entry copied next to another
  log never speaks for that log's kill switch, while `audit verify` still checks them after the log and its marker are
  renamed together (an archive). A writer that finds the log no longer matching its marker (truncated, rolled back, marker
  missing or forged) does not paper over it: its entry starts a new segment that records the anomaly, and `audit verify`
  keeps reporting it.
- Several writers (hooks of several agents, proxies, the CLI) append to the same file under an inter-process lock and
  re-read the tail first, so they extend one chain instead of forking it.
- Old logs (unkeyed SHA-256 chain) are read as **legacy, unverified**, never valid (exit 3). The first entry written with
  the key starts an HMAC segment, marked `"segment": "hmac-sha256/v1"`, that binds the legacy lines by their count and
  SHA-256: they cannot change afterward unnoticed.
- `kytral-guard kill` and `known remove` work without a secret; their entry is then written without a mac, marked
  `unauthenticated`, and reported as unverifiable (exit 3). An entry written with the key after it binds it into the chain.
- `verifyChain(entries, key)` does the same check in memory. Without a key it only checks the unkeyed SHA-256 links, which
  catches accidental damage, not tampering.

## Limits

- The key that verifies the log can also write it: a process running as the same OS user, which can read the secret, can
  rewrite the log and its marker consistently. A rollback of both the log and its marker to an earlier consistent copy
  is not detected either. Both need an anchor outside the machine: ship the log or its tail to another system (Kytral
  Guard Pro anchors it externally).
- Changing the audit key makes earlier entries unverifiable with the new one: archive `audit.jsonl` and `audit.jsonl.tail`
  together and verify them with the old key.
- The log grows without bound (a few hundred bytes per decision). `audit verify`, `doctor` and the dashboard read it in
  pieces, whatever its size (about 8 s and 120 MB of memory for 560 MB), and so do `kill` and `resume`, which take the
  kill switch's generation from it (about 0.3 s for 600 MB). To start afresh, rename `audit.jsonl` and
  `audit.jsonl.tail` together (`audit-2026.jsonl` and `audit-2026.jsonl.tail`): the next writer starts a new chain, and
  `kytral-guard audit verify audit-2026.jsonl` still verifies the archive.
