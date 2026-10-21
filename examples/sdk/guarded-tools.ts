// Guard your own agent's tools with the Kytral Guard SDK.
//   npm install kytral-guard tsx
//   KYTRAL_SECRET=$(openssl rand -hex 32) npx tsx guarded-tools.ts
import { createInterface } from "node:readline/promises";
import { Guard, GuardError, issueBadge, presetPolicy, type Confirmer } from "kytral-guard";

const secret = process.env.KYTRAL_SECRET!;
const audience = "kytral-guard:example";

// Ask on the terminal when the policy says "confirm" (in production: Slack, a web page, a ticket...).
const rl = createInterface({ input: process.stdin, output: process.stdout });
const confirm: Confirmer = async (call, decision) => {
  const answer = await rl.question(`Kytral Guard: ${call.tool} needs confirmation (${decision.reason}). Run it? [y/N] `).catch(() => "");
  return answer.trim().toLowerCase() === "y" ? { choice: "once", approver: process.env.USER ?? process.env.USERNAME ?? "me" } : "deny";
};

const guard = new Guard({
  // The SDK sees no MCP tools/list: name the tools you expose, or every call to them would need confirmation.
  policy: { ...presetPolicy("strict"), knownTools: ["run_sql", "send_email"] },
  secret, audience, confirm,
  revocationFile: null, nonceFile: null, knownToolsFile: null,   // keep this example's state in memory
});

// The agent's identity: which tools it may call, for one hour, on this deployment only.
const badge = issueBadge(secret, "support-agent", ["run_sql", "send_email"], 3600, Date.now(), { aud: audience });

// Your real tools; here they only print.
const runSql = guard.wrap(badge, "run_sql", async (args: { sql: string }) => `ran: ${args.sql}`);
const sendEmail = guard.wrap(badge, "send_email", async (args: { to: string[]; subject: string }) => `sent to ${args.to.length}`);

async function attempt(label: string, fn: () => Promise<string>) {
  try { console.log(`${label}: ${await fn()}`); }
  catch (e) { if (e instanceof GuardError) console.log(`${label}: REFUSED - ${e.message}`); else throw e; }
}

await attempt("select", () => runSql({ sql: "SELECT * FROM tickets WHERE id = 42" }));
await attempt("targeted update", () => runSql({ sql: "UPDATE tickets SET status = 'closed' WHERE id = 42" }));
await attempt("mass update", () => runSql({ sql: "UPDATE tickets SET status = 'closed'" }));      // no WHERE: blocked
await attempt("drop", () => runSql({ sql: "DROP TABLE tickets" }));                                // blocked
await attempt("one e-mail", () => sendEmail({ to: ["a@example.com"], subject: "Your ticket" }));
await attempt("mass e-mail", () => sendEmail({ to: Array.from({ length: 50 }, (_, i) => `u${i}@example.com`), subject: "Promo" }));   // confirm
rl.close();
