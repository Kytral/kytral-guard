# Configuration reference

Kytral Guard needs no configuration to protect a coding agent: `kytral-guard init` creates what it needs in `~/.kytral`.
Everything below is optional.

## Files in `$KYTRAL_HOME` (default `~/.kytral`)

| File | Content |
|---|---|
| `secret` | the deployment secret (created by `init`, owner-only), unless `KYTRAL_SECRET` is set |
| `policy.yaml` | the hooks' policy (created by `init`, extends the `coding-agent` preset; `kytral-guard allow` and the dashboard add rules and `overrides` to it) |
| `mcp-policy.yaml` | the policy of MCP proxies started without `--policy` or `--preset` (created by the dashboard, extends the `strict` preset); without it they use the `strict` preset |
| `config.json` | `{"plugins": [...], "remoteConfirmTimeoutSeconds": n, "keepCalls": true, "auditAllows": true}`: plugins to load, longest wait for a remote approval in hooks, keep the text of refused calls, journal allowed calls |
| `audit.jsonl`, `audit.jsonl.tail` | the HMAC-chained audit log and its signed tail marker |
| `kept-calls.jsonl` | the text of the calls that were refused, asked or approved, masked, for the dashboard ([dashboard.md](dashboard.md)) |
| `kill-switch.json` | the shared kill switch (signed, monotonic generations) |
| `dashboard.json` | written while a dashboard runs (process, port, heartbeat): confirmations wait for it |
| `known-tools.json`, `revocations.json`, `nonces.json`, `confirmations/` | MCP proxy state: always-allowed tools, revoked badges, single-use badges, the confirmation queue |

Agents are refused writes to this folder (and reads of the secret and `*.key` files), whether it is `~/.kytral` or a
custom `KYTRAL_HOME`.

## Environment variables

### Everywhere

| Variable | Default | Meaning |
|---|---|---|
| `KYTRAL_HOME` | `~/.kytral` | the state folder above |
| `KYTRAL_SECRET` | the `secret` file | deployment secret (at least 32 bytes, e.g. `openssl rand -hex 32`); signs kill switch states, approvals, grants, badges and the audit chain |
| `KYTRAL_SECRET_FILE` | `$KYTRAL_HOME/secret` | where the secret file is |
| `KYTRAL_AUDIT_SECRET` | `KYTRAL_SECRET` | a separate secret for the audit chain |
| `KYTRAL_AUDIT` | `$KYTRAL_HOME/audit.jsonl` | the audit log |
| `KYTRAL_POLICY` | `$KYTRAL_HOME/policy.yaml` (hooks) | the policy file |
| `KYTRAL_PLUGINS` | | comma-separated plugins, loaded before those of `config.json` ([plugins.md](plugins.md)) |
| `KYTRAL_SQL_TIMEOUT_MS` | `2000` (`5000` for the first) | deadline of one SQL parse (in a worker thread); past it the SQL is unparseable (a human confirms) |
| `KYTRAL_KEEP_CALLS` | `keepCalls` in `config.json`, else `1` | `0`: do not keep the text of refused calls; `1`: keep it (masked) |
| `KYTRAL_KEPT_CALLS` | `$KYTRAL_HOME/kept-calls.jsonl` | where those texts are kept |
| `KYTRAL_CONFIRM_QUEUE` | automatic | `1`: calls that need a human always wait in the confirmation queue; `0`: never; unset: while a dashboard is open (agents that cannot ask, MCP proxies), refused at once otherwise |

### Agent hooks

| Variable | Default | Meaning |
|---|---|---|
| `KYTRAL_ANALYSIS_TIMEOUT_MS` | `8000` | deadline of the analysis of a call (in a worker thread, also limited to 512 MB; hooks, MCP proxy and SDK); past it, a human confirms |
| `KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS` | `config.json`, else what is left of 20 s | longest wait for a plugin's remote approval; keep the agent's hook timeout above it |
| `KYTRAL_AUDIT_ALLOWS` | `auditAllows` in `config.json`, else `1` | `0`: do not journal allowed calls (refusals and confirmations are always journaled) |

### MCP proxy and SDK

| Variable | Default | Meaning |
|---|---|---|
| `KYTRAL_AUDIENCE` | required | unique name of this proxy (`kytral-guard:crm-prod`): badges issued for another audience are refused |
| `KYTRAL_BADGE` | | the agent's signed badge, presented by the proxy for its client |
| `KYTRAL_SERVER_ID` | the audience | the server's name in known-tools grants |
| `KYTRAL_CONFIRM_TIMEOUT_MS` | `60000` | how long a queued confirmation waits (see `KYTRAL_CONFIRM_QUEUE` above) |
| `KYTRAL_KILL` | | `1`: start the proxy with its own kill switch engaged (this process only; `kytral-guard kill` stops every guard) |
| `KYTRAL_REVOCATIONS`, `KYTRAL_NONCES`, `KYTRAL_KNOWN_TOOLS`, `KYTRAL_CONFIRMATIONS` | in `$KYTRAL_HOME` | other locations for the proxy's state files |

See [mcp-proxy.md](mcp-proxy.md) and [sdk.md](sdk.md) for the proxy's and the SDK's options.
