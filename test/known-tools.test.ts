import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs"; import { tmpdir } from "node:os"; import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge, AuditLog, knownKey } from "../src/index.js";
const S = "7c3e9a1f5b2d8064e1a7c9f3b5d2e8a04f6c1b9d3e7a5f2c8b0d4e6a1f3c5b7d"; const AUD = "kytral-guard:allow-test";
const bd = (agent = "agent-a") => issueBadge(S, agent, ["*"], 60, Date.now(), { aud: AUD });
const tmp = () => mkdtempSync(join(tmpdir(), "kg-allow-"));
const mk = (o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null, ...o });

test("policy built in code without unknownTools: unknown tool is confirmed, never silently allowed", async () => {
  let asked = 0;
  const g = mk({ policy: { default: "allow", rules: [] } as any, confirm: async () => (asked++, false) });
  await assert.rejects(g.check(bd(), { tool: "never_advertised", args: {} }), /confirmation refused/); assert.equal(asked, 1);
  await assert.rejects(mk({ policy: { default: "allow", rules: [], unknownTools: "maybe" } as any }).check(bd(), { tool: "x", args: {} }), /invalid unknownTools/);
});
test("proxy mode without a confirmer: unknown tool is refused", async () => {
  await assert.rejects(mk().check(bd(), { tool: "mystery", args: {} }), /confirmation refused/);
});
test("three choices offered for unknown tools, 'once' is the default and is per call", async () => {
  const ctxs: any[] = []; let n = 0;
  const g = mk({ confirm: async (_c: any, _d: any, ctx: any) => { ctxs.push(ctx); return n++ === 0 ? ctx.defaultChoice : "deny"; } });
  await g.check(bd(), { tool: "mystery", args: {} });
  await assert.rejects(g.check(bd(), { tool: "mystery", args: {} }), /refused/);
  assert.deepEqual(ctxs[0].choices, ["once", "always", "deny"]); assert.equal(ctxs[0].defaultChoice, "once");
  assert.equal(ctxs[0].agentId, "agent-a"); assert.equal(ctxs[0].server, AUD);
});
test("'always' persists per server + tool + agent, is audited, and is revocable", async () => {
  const f = join(tmp(), "allow.json"); let asked = 0;
  const g = mk({ knownToolsFile: f, confirm: async () => (asked++, { choice: "always", approver: "qa" }) });
  await g.check(bd(), { tool: "mystery", args: {} }); assert.equal(asked, 1);
  const g2 = mk({ knownToolsFile: f });                                       // restart, no confirmer at all
  await g2.check(bd(), { tool: "mystery", args: {} });
  await assert.rejects(g2.check(bd("agent-b"), { tool: "mystery", args: {} }), /refused/, "other agent");
  await assert.rejects(g2.check(bd(), { tool: "mystery2", args: {} }), /refused/, "other tool");
  await assert.rejects(mk({ knownToolsFile: f, server: "other-server" }).check(bd(), { tool: "mystery", args: {} }), /refused/, "other server");
  const decisions = g.audit.entries.map(e => e.decision);
  assert.ok(decisions.includes("known-add") && decisions.includes("confirmed-always"));
  assert.equal(g2.audit.entries.at(-3)!.rule, "known-tool");
  assert.equal(g2.removeKnown("mystery", "agent-a"), true); assert.equal(g2.audit.entries.at(-1)!.decision, "known-remove");
  await assert.rejects(mk({ knownToolsFile: f }).check(bd(), { tool: "mystery", args: {} }), /refused/, "revoked");
});
test("blocking rules win over known tools; 'always' is not offered for other confirmations", async () => {
  const f = join(tmp(), "allow.json");
  const g = mk({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) });
  await g.check(bd(), { tool: "run_query", args: {} });                       // learned as always-allowed
  await assert.rejects(g.check(bd(), { tool: "run_query", args: { sql: "DROP TABLE users" } }), /blocked/);
  const ctxs: any[] = [];
  const g3 = mk({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), confirm: async (_c: any, _d: any, ctx: any) => (ctxs.push(ctx), { choice: "always", approver: "qa" }) });
  await assert.rejects(g3.check(bd(), { tool: "stripe", args: { op: "payout" } }), /refused/, "'always' not valid for money-transfer");
  assert.deepEqual(ctxs[0].choices, ["once", "deny"]);
});
test("CLI: known list / known remove (journaled in the audit log)", async () => {
  const d = tmp(); const f = join(d, "allow.json"); const audit = join(d, "audit.jsonl");
  await mk({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) }).check(bd(), { tool: "mystery", args: {} });
  const ROOT = resolve(import.meta.dirname, ".."); const env = { ...process.env, KYTRAL_KNOWN_TOOLS: f, KYTRAL_AUDIT: audit, KYTRAL_AUDIENCE: AUD, KYTRAL_SECRET: S };
  const cli = (...a: string[]) => execFileSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...a], { env, encoding: "utf8" });
  assert.match(cli("known", "list"), new RegExp(`${AUD}\\tmystery\\tagent-a`));
  assert.match(cli("known", "remove", "mystery", "agent-a"), /removed/);
  assert.equal(cli("known", "list").trim(), "");
  assert.match(readFileSync(audit, "utf8"), /"decision":"known-remove"/);
  assert.equal(JSON.parse(readFileSync(f, "utf8"))[knownKey(AUD, "mystery", "agent-a")], undefined);
});
test("anti-replay: revoked entry restored from backup refused; re-grant after revoke works", async () => {
  const f = join(tmp(), "allow.json"); const g = mk({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) });
  await g.check(bd(), { tool: "mystery", args: {} }); const backup = readFileSync(f, "utf8");
  g.removeKnown("mystery", "agent-a"); writeFileSync(f, backup);
  const g2 = mk({ knownToolsFile: f }); await assert.rejects(g2.check(bd(), { tool: "mystery", args: {} }), /refused/);
  assert.ok(g2.audit.entries.some(e => e.decision === "known-reject"));
  await mk({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) }).check(bd(), { tool: "mystery", args: {} });
  await mk({ knownToolsFile: f }).check(bd(), { tool: "mystery", args: {} });
});
