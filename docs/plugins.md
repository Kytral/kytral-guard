# Plugins

A plugin extends every guard of a machine (agent hooks, the MCP proxy, SDK guards) without forking Kytral Guard:

- **a central policy** that replaces the local one;
- **a second kill switch**, for example one that stops every machine of a team at once;
- **remote approvals**: a confirmation the agent cannot show a human (bypass mode, Codex, Gemini, the proxy) is offered
  to the plugin first: Slack, a web page, an on-call approver;
- **a copy of every decision and audit entry**: a SIEM, a dashboard, an alert.

Kytral Guard Pro (coming soon) is such a plugin. Anyone can write one.

## Enabling plugins

List module names or paths in `KYTRAL_PLUGINS` (comma-separated) or in `$KYTRAL_HOME/config.json`:

```json
{ "plugins": ["@kytral/guard-pro", "/opt/kytral/slack-notify.mjs"] }
```

Plugins are loaded by every hook invocation and every proxy at startup. **A plugin that does not load makes the guard
refuse every call** (hooks) or refuse to start (proxy): it was configured to enforce something. `kytral-guard doctor`
loads them and reports errors. Node loads the modules (`import`): unlike the guard's own files, which are opened only as
regular files and without waiting, a FIFO put in place of a plugin module holds a hook until the agent's timeout (most
agents then run the tool). Keep plugin files where agents cannot write.

## Writing one

A module whose default export is a plugin, or a function that receives `{ home, version }` and returns one (async allowed):

```js
// slack-notify.mjs: posts every refusal to a Slack channel.
export default ({ version }) => {
  const pending = [];
  return {
    name: "slack-notify",
    onDecision(event) {
      if (event.outcome !== "deny") return;
      pending.push(fetch(process.env.SLACK_WEBHOOK_URL, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ text: `Kytral Guard ${version} blocked ${event.agent} ${event.tool}: ${event.reason}` }),
      }).catch(() => {}));
    },
    async flush() { await Promise.all(pending); },   // hooks are short-lived: send before the process exits
  };
};
```

## The interface

```ts
interface KytralPlugin {
  name: string;
  policy?(target: "hook" | "proxy"): Policy | string | null | undefined;   // once per process; replaces the local policy
  killReason?(): string | null;                                     // before every decision; synchronous and fast
  confirm?(request: ConfirmRequestInfo): Promise<RemoteVerdict | null>;
  onAudit?(entry: Entry): void;                                     // every audit entry, once written and signed
  onDecision?(event: DecisionEvent): void;                          // every decision and its outcome
  flush?(): Promise<void>;                                          // before a hook exits (at most 2 s in total)
}
interface ConfirmRequestInfo { source: "hook" | "proxy" | "sdk"; agent: string; tool: string; args: Record<string, unknown>;
  rule?: string; reason: string; cwd?: string; session?: string; localPrompt: boolean;
  timeoutMs?: number }   // how long the guard waits for this verdict: expire the request then
interface RemoteVerdict { verdict: "allow" | "deny"; approver?: string; note?: string }
```

Semantics, all fail closed:

- `killReason` is checked after the local kill switch, before the policy. A plugin that throws refuses every call.
- `confirm` is asked only for `confirm` decisions, never for blocks. Hooks wait at most `KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS`,
  and never past the agent's own hook timeout (the `--timeout` that `init` writes into the hook command, minus 3 s),
  else `"remoteConfirmTimeoutSeconds"` in `$KYTRAL_HOME/config.json`, else what is left of 20 s; the proxy and the SDK at
  most 60 s. Keep the agent's hook timeout above the wait: for approvals by a human on Slack, set
  `"remoteConfirmTimeoutSeconds": 300` and run `kytral-guard init <agent> --timeout 330`. No answer (`null`, an error or
  the timeout): the agent asks locally if it can (`localPrompt`), otherwise the call is refused; the proxy falls back to
  its confirmation queue. An approval is journaled `confirmed` with the approver, a refusal `block`.
- `onAudit`, `onDecision` and `flush` never change a decision; their errors are ignored. A plugin that never settles
  cannot keep a hook from answering: the waits are bounded, and a hook process that would end without an answer refuses.
- `policy` is called once per process with the target: `"hook"` for agent hooks, `"proxy"` for the MCP proxy. The first
  plugin that returns one wins. A string is YAML, parsed and validated by this guard exactly like a local policy file
  (prefer it: the plugin then does not depend on the guard's internal types); an object is read exactly like a
  policy file (its `extends` preset is merged and checked here). An invalid
  policy refuses every call. The policy replaces the local one entirely, so keep the `guard-tamper` rule in it (extend a
  preset).

`args` are the tool call's arguments: treat them as sensitive (they can hold secrets), as the audit log does by never
storing them.
