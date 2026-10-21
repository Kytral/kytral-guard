# MCP proxy

`kytral-guard [--policy file | --preset name] -- <mcp server command...>` starts an MCP server and sits between it and
the MCP client (Claude Code, Cursor, Claude Desktop, n8n, any stdio client). Every `tools/call` is checked before it is
forwarded; everything else passes through. The default policy is the `strict` preset.

## The MCP servers of your apps, in one command

```bash
kytral-guard mcp list                 # every MCP server of Claude Desktop, VS Code, Cline, Roo Code, Kilo Code, LM Studio, Continue
kytral-guard mcp wrap                 # run each local server through the proxy (or name apps: mcp wrap claude-desktop)
kytral-guard mcp wrap --file cfg.json # any other JSON file with "mcpServers" (or "servers")
kytral-guard mcp unwrap               # give every server its own command back
```

`wrap` rewrites each local (stdio) server so that the app starts it through the proxy: `node …/cli.js -- <its own
command>`, with its own audience (`kytral-guard:mcp:<app>:<server>`) and a badge valid five years in its environment.
A wrapped server that works is left as it is. One that no longer works is repaired by `mcp wrap`: a badge that the
current secret does not sign (a new secret), that expires within 30 days or that names another audience gets a new one,
and a node or CLI that moved (a Node.js upgrade) is replaced by this installation's. A revoked badge is never renewed.
`mcp list`, `doctor` and the dashboard show these servers. The file is merged: other settings and remote servers stay as they are, the previous file
is kept as `<file>.kytral-backup`, and a file that is not plain JSON is left untouched. Restart the app afterwards. The
proxy uses `~/.kytral/mcp-policy.yaml` (which the dashboard writes), else the `strict` preset, unless you pass
`--preset <name>` or `--policy <file>`. It follows that file, or the `--policy` file: a change applies from the next call,
a file that no longer loads refuses every call until it is fixed (rule `invalid-policy-file`), and deleting
`mcp-policy.yaml` brings the `strict` preset back. A call that needs a human waits for you on the dashboard while it is open, and is
refused otherwise (the proxy has no screen). Remote servers (a URL) cannot be wrapped by a local proxy. Coding agents with a Kytral
hook (Claude Code, Cursor, Codex, Gemini CLI, Copilot CLI, Windsurf, Grok Build) already check their own MCP tools.
`kytral-guard doctor` lists the servers left unprotected.

On Windows, `npx`, `pnpm` and other `.cmd` shims start through cmd.exe with every argument escaped, as the apps start them.
The wrapped server never sees `KYTRAL_SECRET` or the badge.

## Setup by hand

```bash
npm install -g kytral-guard
kytral-guard init --no-agents                                       # creates ~/.kytral/secret (or set KYTRAL_SECRET)
export KYTRAL_AUDIENCE=kytral-guard:postgres                        # one audience per proxy
kytral-guard badge my-agent '*' 1y                                  # agent id, allowed tools, lifetime (seconds, or 90m, 12h, 30d, 1y)
```

A badge written in a configuration file stops working when it expires (every call is then refused with `badge:
expired`): give it a lifetime that suits the file, and issue a new one before. `kytral-guard mcp wrap` gives five years,
and running it again renews a badge in its last 30 days.

Then wrap the server in the client's MCP configuration (`.mcp.json`, `~/.cursor/mcp.json`, `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "postgres": {
      "command": "kytral-guard",
      "args": ["--preset", "strict", "--", "npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/app"],
      "env": { "KYTRAL_AUDIENCE": "kytral-guard:postgres", "KYTRAL_BADGE": "<the badge>" }
    }
  }
}
```

Keep the secret out of these files: the proxy reads `KYTRAL_SECRET`, else `$KYTRAL_HOME/secret`. Examples for Claude
Code, Cursor and n8n are in [examples/](../examples).

## What the proxy enforces

- **Strong secret, required audience.** The proxy refuses to start without a strong secret (at least 32 non-whitespace
  bytes, enough distinct characters, no placeholder) and without a `KYTRAL_AUDIENCE` of its own (`kytral-guard` alone is
  refused).
- **Options checked before anything starts.** An unknown option before `--` (a misspelled `--polcy`, the `--policy=file`
  form, `-p`), a file given without `--policy`, `--policy` or `--preset` given twice or together, or an unknown preset is
  an error (exit 2, the server is not started), never a silent fallback to another policy. The error repeats nothing
  typed, and a policy file that cannot be read is named by what it is, with an error code. After the first `--`, every
  argument goes to the MCP server as it is.
- **A policy file that is not a valid policy** (a YAML syntax error, a `.env` or any other file, YAML that is not a
  policy, an empty file) is refused before anything starts or is created: exit 2 and one line, `kytral-guard: refusing to
  start: the --policy file is not a valid policy (line N)` (`mcp-policy.yaml is not a valid policy` for a proxy started
  without `--policy` or `--preset`), with the line only for a YAML syntax error. Nothing of the file is shown (YAML's
  errors and warnings quote it), nor its path: `kytral-guard policy validate <file>` shows the whole message, in your
  terminal.
- **Badges.** `KYTRAL_BADGE` is an HMAC-signed token: agent id, allowed tools (`*` or exact names), expiry, audience,
  issue time and nonce. A badge for another audience, expired, revoked or not signed with the secret is refused.
  `badge ... --once` binds a badge to the first proxy that uses it (`$KYTRAL_HOME/nonces.json`).
- **Revocation.** `kytral-guard revoke <badgeId|agentId|nonce>` writes `$KYTRAL_HOME/revocations.json` (or
  `KYTRAL_REVOCATIONS`), re-read on change, written under an inter-process lock. A running proxy never forgets a
  revocation it has seen, even if the file is deleted or rewritten.
- **JSON-RPC hygiene.** Every element of a batch is checked; any refusal rejects the whole batch. Non-JSON input gets a
  `-32700` error and is never forwarded, and so do `tools/call` arguments that are not an object (`-32602`: the server
  would receive what the policy never saw). Messages are forwarded in strict order, even while a confirmation is pending.
- **The guard's secret.** A `resources/read` whose URI names the guard's secret or keys (`file:///home/me/.kytral/secret`,
  percent-encoded or not) is refused (`-32000`) and journaled, as a tool call reading them is.
- **Shutdown.** When the client closes the proxy's input (MCP's stdio shutdown), the server's input is closed once every
  earlier message is decided, and the proxy exits with the server. A proxy stopped by a signal stops its server.
- **Policy** on the tool name and every argument (see [policy.md](policy.md)).
- **Server annotations.** A tool the server annotates with `destructiveHint` (and not `readOnlyHint`) needs confirmation
  even when the policy allows it.

## Unknown tools

A tool is *unknown* when the server never advertised it in `tools/list` (learned by the proxy) and it matches no
`knownTools` glob of the policy. `unknownTools` (default `confirm`) applies only when no rule matched; explicit rules
always win, and it only ever makes the decision stricter.

```yaml
extends: strict
unknownTools: confirm   # confirm (default) | allow | block
knownTools: ["internal_*"]
```

Known tools are learned **only** from the server's reply to a `tools/list` the client sent (matched by JSON-RPC id); each
reply replaces the previous list, and `result.tools` in any other message is ignored. Any reply to a pending `tools/list`
(an error, or a result without tools) consumes its id. Pages are merged only when the client's request carries the last
`nextCursor` received. At most 1024 pending `tools/list` ids and 4096 known tools are kept (extra names stay unknown).
`destructiveHint` names are capped at 4096 and never forgotten; beyond the cap the proxy enters **strict mode** (every
otherwise-allowed call needs confirmation) until it restarts.

> The `confirm` default protects against tools the server never advertised, **not against a hostile server**, which can
> advertise its own tools. Only run servers you trust, and use blocking rules for sensitive ones.

## Confirming a call: once, always, deny

A human answering a confirmation has three choices: **once** (this call only), **always** (this exact tool, for this
agent, on this server; offered only for the `unknown-tool` rule, for a plain tool name the server did not annotate as
destructive), **deny**. "Always" never makes a rule's confirm or block permanent: every rule is evaluated first.

Grants live in `$KYTRAL_HOME/known-tools.json` (or `KYTRAL_KNOWN_TOOLS`): one HMAC-signed entry per server + tool + agent,
with `approver` and `approvedAt`, signed for that file (a key bound to its real path): a grant copied from another home
that uses the same secret, or written by an older version, is rejected (`known-reject`) and the tool is confirmed again.
A corrupt file grants nothing (unknown tools are confirmed again) and is journaled.
Removing a grant (`kytral-guard known remove <tool> [agentId] [server]`) writes a tombstone, so restoring an old copy of
the file does not bring the grant back.

```bash
kytral-guard known list
kytral-guard known remove <tool> [agentId] [server] [--by name]
```

## Confirmation queue

A stdio proxy has no screen. While a dashboard is open (`kytral-guard dashboard`), a confirmation waits for a human on
its page; with none open, it is refused at once. `KYTRAL_CONFIRM_QUEUE=1` makes confirmations always wait (answer them
from a terminal), `KYTRAL_CONFIRM_QUEUE=0` refuses them all. A waiting proxy writes a signed request to
`$KYTRAL_HOME/confirmations/` and logs its id on stderr; answer on the dashboard ([dashboard.md](dashboard.md)) or from
another terminal:

```bash
kytral-guard confirm list [--full]                               # id, tool, agent, server, rule, choices, arguments, expiry
kytral-guard confirm approve <id> [--full] [--by name]           # once: this call only, bound to its arguments' hash
kytral-guard confirm approve <id> --always [--full] [--by name]  # always (unknown-tool rule only)
kytral-guard confirm deny <id> [--by name]
```

- No valid answer within `KYTRAL_CONFIRM_TIMEOUT_MS` (default 60000) is a refusal. The kill switch refuses a pending
  request at once.
- Requests and decisions are HMAC-signed for their queue folder (a key bound to its real path), and the first decision
  wins: another home's queue neither shows nor answers a request copied there, and a decision made for another queue
  is refused. A decision counts only if it is signed, made for that request id and the same arguments hash, and
  allowed for it; anything else is a refusal, journaled `confirm-invalid`. Only the proxy that waits acts on a
  decision, for the request it holds in memory: a forged request file cannot make a proxy run anything.
- The request holds the complete arguments so the human knows what they approve. `confirm list` shows the first 2000
  characters and flags anything longer; approving a longer request needs `--full`. Control and bidi characters are
  escaped.
- Limits: while a request waits, later messages from that client wait too and the client may time out; anyone on the
  machine who holds the secret can answer.

## State files

All state lives in `$KYTRAL_HOME` (default `~/.kytral`, created 0700; files 0600): `secret`, `audit.jsonl` and its
`.tail`, `kill-switch.json`, `revocations.json`, `nonces.json`, `known-tools.json` and its tombstones, `confirmations/`.
Files are reloaded when the SHA-256 of their content changes, written under an inter-process lock with an atomic rename.
Restrictions (revocations, tombstones) are never forgotten by a running proxy; grants are dropped when their file is
deleted or does not verify. Proxies sharing one `KYTRAL_HOME` must share the same secret.
