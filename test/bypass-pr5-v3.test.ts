// Adversarial regression probes: the cap on the destructive tools a server announces fails closed.
import { test } from "node:test"; import assert from "node:assert/strict";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge } from "../src/index.js";
import { observeServerLine, expectToolsListPage, MAX_DESTRUCTIVE_TOOLS, CappedDestructiveSet } from "../src/proxy.js";
const S = "3b7e1c9a5f2d8046e1b9c7a3f5d20846b1e9c7a3f5d2084e6b1a9c3f7e5d2b8a";
const mk = (o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: "kytral-guard:test", revocationFile: null, nonceFile: null, allowlistFile: null, knownToolsFile: null, ...o } as any);
let id = 0; const page = (g: Guard, tools: any[], cursor?: string, next?: string) => { const i = ++id; expectToolsListPage(g, i, cursor); observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: i, result: { tools, ...(next ? { nextCursor: next } : {}) } })); };
const overflow = (g: Guard) => { for (let k = 0; k <= MAX_DESTRUCTIVE_TOOLS / 1000; k++) page(g, Array.from({ length: 1000 }, (_, j) => ({ name: `d${k}_${j}`, annotations: { destructiveHint: true } }))); };
test("overflow survives new listing, error, cursor, readOnly re-announce", () => {
  const g = mk(); overflow(g); const d = g.destructiveTools as any; assert.ok(d instanceof CappedDestructiveSet && d.overflowed);
  page(g, [{ name: "x" }]); page(g, [{ name: "y" }], undefined, "c"); page(g, [{ name: "z" }], "c");
  const i = ++id; expectToolsListPage(g, i, undefined); observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: i, error: { code: -1, message: "e" } }));
  page(g, [{ name: "d0_0", annotations: { readOnlyHint: true } }]);
  assert.ok(d.overflowed && d.has("d0_0") && d.has("anything"));
});
test("a name is never forgotten below the cap either (re-announce non-destructive, new listing)", () => {
  const g = mk(); page(g, [{ name: "rm", annotations: { destructiveHint: true } }]); page(g, [{ name: "rm" }]); page(g, []);
  assert.ok(g.destructiveTools.has("rm")); g.destructiveTools.delete("rm"); g.destructiveTools.clear(); assert.ok(g.destructiveTools.has("rm"));
});
test("strict mode: an allowed known tool needs confirmation, and 'always' is never offered", async () => {
  let called = 0; let offered: string[] = [];
  const g = mk({ confirm: async (...a: any[]) => { called++; offered = a.find((x: any) => x?.choices)?.choices ?? []; return false; } }); overflow(g);
  await g.check(issueBadge(S, "a", ["*"], 60, Date.now(), { aud: "kytral-guard:test" }), { tool: "harmless", args: {} }).catch((e: any) => { assert.match(String(e.message), /confirm/); });
  assert.equal(called, 1); assert.ok(!offered.includes("always"), String(offered));
});
