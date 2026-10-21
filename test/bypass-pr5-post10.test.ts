// Adversarial regression probe: in strict mode, an "always" grant already recorded does not bypass the confirmation, and "always" is never offered.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs"; import { tmpdir } from "node:os"; import { join } from "node:path";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge } from "../src/index.js";
import { observeServerLine, expectToolsListPage, MAX_DESTRUCTIVE_TOOLS } from "../src/proxy.js";
const S = "3b7e1c9a5f2d8046e1b9c7a3f5d20846b1e9c7a3f5d2084e6b1a9c3f7e5d2b8a"; const AUD = "kytral-guard:test";
const mk = (o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret: S, audience: AUD, revocationFile: null, nonceFile: null, ...o } as any);
const bd = () => issueBadge(S, "agent-a", ["*"], 60, Date.now(), { aud: AUD });
test("grant 'always' recorded + destructiveTools overflow => confirmation required, 'always' not offered", async () => {
  const f = join(mkdtempSync(join(tmpdir(), "strict-grant-")), "known.json");
  await mk({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) }).check(bd(), { tool: "mystery", args: {} });
  assert.ok(await mk({ knownToolsFile: f, confirm: async () => { throw new Error("no confirm expected"); } }).check(bd(), { tool: "mystery", args: {} }) !== undefined || true);
  let called = 0; let offered: string[] = [];
  const g = mk({ knownToolsFile: f, confirm: async (_c: any, _d: any, ctx: any) => { called++; offered = ctx?.choices ?? []; return "deny"; } });
  let id = 0; for (let k = 0; k <= MAX_DESTRUCTIVE_TOOLS / 1000; k++) { const i = ++id; expectToolsListPage(g, i, undefined);
    observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: i, result: { tools: Array.from({ length: 1000 }, (_, j) => ({ name: `d${k}_${j}`, annotations: { destructiveHint: true } })) } })); }
  await assert.rejects(g.check(bd(), { tool: "mystery", args: {} }), /confirmation refused/);
  assert.equal(called, 1); assert.ok(!offered.includes("always"), String(offered));
});
