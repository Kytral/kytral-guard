# TypeScript SDK

```bash
npm install kytral-guard
```

ESM only, Node.js 22 or later, full type definitions.

## Guard: badges, policy, confirmation, kill switch, audit

`Guard` is what the MCP proxy uses: it checks a signed badge, the policy, unknown tools, the shared kill switch, asks a
human when the policy says `confirm`, and journals everything.

```ts
import { Guard, GuardError, issueBadge, presetPolicy } from "kytral-guard";

const secret = process.env.KYTRAL_SECRET!;          // >= 32 random bytes: openssl rand -hex 32
const guard = new Guard({
  policy: presetPolicy("strict"),                   // or loadPolicy(yamlText)
  secret,
  audience: "kytral-guard:billing",                 // required: unique per deployment
  knownToolsFile: null,                             // keep "always" grants in memory only
  confirm: async (call, decision, ctx) => {         // optional: without it, every confirmation is refused
    const ok = await askOnSlack(`${ctx.agentId} wants ${call.tool}: ${decision.reason}`);
    return ok ? { choice: "once", approver: "alice" } : "deny";
  },
});

const badge = issueBadge(secret, "billing-agent", ["refund_payment", "get_invoice"], 3600, Date.now(), { aud: "kytral-guard:billing" });

const refund = guard.wrap(badge, "refund_payment", async (args: { charge: string; amount: number }) => stripe.refunds.create(args));
try { await refund({ charge: "ch_123", amount: 500 }); }
catch (e) { if (e instanceof GuardError) console.log("refused:", e.message); else throw e; }
```

| Option | Meaning |
|---|---|
| `policy` | required: a `Policy` (`presetPolicy(name)`, `loadPolicy(text)`) |
| `secret` | required: signs and verifies badges; the audit, kill switch and grant keys derive from it (or from `KYTRAL_AUDIT_SECRET`) |
| `audience` | required (or `KYTRAL_AUDIENCE`): badges must carry it |
| `confirm(call, decision, ctx)` | asks a human; answer `"once"`, `"always"` (only offered for unknown tools; needs `{ choice, approver }`), `"deny"`, or a boolean |
| `audit` | an `AuditLog`: `new AuditLog(file, { key: auditKey(secret) })` journals to a file, HMAC-chained; default: kept in memory |
| `killSwitchFile` | shared kill switch file; default `$KYTRAL_HOME/kill-switch.json`. The guard starts from the last kill or resume recorded in the tail marker of its audit log (when it has a file) and, for the default file, of the default log (`$KYTRAL_AUDIT`, else `$KYTRAL_HOME/audit.jsonl`): a kill-switch.json deleted after a kill still stops it, and so does a marker in doubt (another home's, an older version's) or a kill or resume of another log found in its log, until a resume. A log that cannot be read makes the constructor throw |
| `revocationFile`, `nonceFile`, `knownToolsFile` | state files; `null` keeps them in memory |
| `confirmQueue` | a `ConfirmQueue` (the proxy's file queue, or your own) used when `confirm` is not given |
| `server` | key of this server in known-tools grants (default: the audience) |

Methods: `check(badge, call)` (resolves or throws `GuardError`), `checkSync` (no await when no confirmation is needed),
`wrap(badge, tool, fn)`, `kill()` / `resume()` (this process only), `revoke(idOrAgent)`, `removeKnown(tool, agentId)`,
`killReason()`.

Each call is analyzed in a worker thread, started on the first call and then reused (about 0.4 ms per call): an
argument built to make the analysis slow or memory-hungry cannot stop your process or hold it for long. Past
`KYTRAL_ANALYSIS_TIMEOUT_MS` (8 s) or 512 MB, and for arguments over 2 MB, the call needs a human (rule
`analysis-limit`). `evaluateSyncBounded(policy, call)` does the same for a policy alone.

With the SDK no `tools/list` is observed: list the tools you expose in the policy's `knownTools`, or set
`unknownTools: allow`.

## Policy only

```ts
import { evaluate, presetPolicy } from "kytral-guard";

const policy = presetPolicy("coding-agent");
evaluate(policy, { tool: "Bash", args: { command: "rm -rf ~" } });
// { action: "block", rule: "shell-catastrophic", reason: "matched rule 'shell-catastrophic': rm -r ~" }
```

`evaluate` is pure and synchronous: no badge, no kill switch, no audit. The analyzers are exported too:
`analyzeShell(text)`, `analyzeWindows(text)`, `analyzeSql(sql, dialect)`, `shellFindings(args, tool)`,
`sqlFindings(args, dialect)`.

## Agent-style guard without badges

`HookGuard` is the engine behind `kytral-guard hook`: the kill switch, the policy and the audit, for a process that runs
tools on behalf of a local agent (no badge).

```ts
import { HookGuard } from "kytral-guard";

const guard = new HookGuard({ preset: "coding-agent" });   // secret: KYTRAL_SECRET or $KYTRAL_HOME/secret
const event = { agent: "generic" as const, tool: "run_sql", args: { sql } };
const verdict = guard.decide(event);                       // { action, rule, reason, killed? }
guard.journal(event, verdict, verdict.action === "allow" ? "allow" : "deny");
```

`runHook(agent, jsonText)` runs one full hook invocation and returns `{ stdout, stderr, exitCode }` in the agent's wire
format.

## Building blocks

`issueBadge` / `verifyBadge`, `AuditLog` / `verifyAuditFile` / `verifyChain`, `KillSwitch` / `engageKillSwitch` /
`releaseKillSwitch`, `FileConfirmQueue`, `FileSet`, `assertStrongSecret`, `resolveSecret`: see the type definitions and
[audit-log.md](audit-log.md), [kill-switch.md](kill-switch.md), [mcp-proxy.md](mcp-proxy.md).
