import { test } from "node:test"; import assert from "node:assert/strict";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge, observeServerLine } from "../src/index.js";
const S = "7c3e9a1f5b2d8064e1a7c9f3b5d2e8a04f6c1b9d3e7a5f2c8b0d4e6a1f3c5b7d"; const b = issueBadge(S, "a", ["*"], 60);
const mk = (yaml: string, confirm?: any) => new Guard({ policy: loadPolicy(yaml), secret: S, confirm, revocationFile: null, nonceFile: null });
const listed = (g: Guard, ...names: string[]) => (g.expectToolsList(1), observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: 1, result: { tools: names.map(name => ({ name })) } })));
test("unknownTools defaults to confirm; default stays allow for known tools", async () => {
  assert.equal(loadPolicy(DEFAULT_POLICY).unknownTools, "confirm");
  assert.equal(loadPolicy("rules: []\n").unknownTools, "confirm");
  assert.equal(loadPolicy(DEFAULT_POLICY).default, "allow");
  await assert.rejects(mk(DEFAULT_POLICY).check(b, { tool: "never_advertised", args: {} }), /confirmation refused/);
});
test("unknownTools: block refuses tools the server never advertised", async () => {
  const g = mk("default: allow\nunknownTools: block\nrules: []\n"); listed(g, "read_file");
  await g.check(b, { tool: "read_file", args: {} });
  await assert.rejects(g.check(b, { tool: "shadow_tool", args: {} }), /unknown/);
});
test("unknownTools: confirm asks a human; knownTools globs whitelist", async () => {
  let asked = 0; const g = mk("default: allow\nunknownTools: confirm\nknownTools: ['internal_*']\nrules: []\n", async () => (asked++, true));
  await g.check(b, { tool: "internal_ping", args: {} }); assert.equal(asked, 0);
  await g.check(b, { tool: "mystery", args: {} }); assert.equal(asked, 1);
  assert.equal(g.audit.entries.at(-1)!.rule, "unknown-tool");
});
test("explicit rules win over unknownTools; invalid value is refused", async () => {
  const g = mk("default: allow\nunknownTools: block\nrules:\n  - name: ok\n    tool: 'ping'\n    action: allow\n");
  await g.check(b, { tool: "ping", args: {} });
  assert.throws(() => loadPolicy("rules: []\nunknownTools: maybe\n"), /unknownTools/);
});
test("known tools are learned only from the reply to the client's tools/list, and each reply replaces the list", async () => {
  const { handleClientLine } = await import("../src/index.js");
  const g = mk(DEFAULT_POLICY); const reply = (id: unknown, ...names: string[]) => observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id, result: { tools: names.map(name => ({ name })) } }));
  reply(7, "sneaky");                                                       // nobody asked: ignored
  await assert.rejects(g.check(b, { tool: "sneaky", args: {} }), /confirmation refused/);
  await handleClientLine(g, b, JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/list" }), () => {}, () => {});
  reply(8, "wrong_id"); reply(7, "a", "b");
  await g.check(b, { tool: "a", args: {} }); await assert.rejects(g.check(b, { tool: "wrong_id", args: {} }), /refused/);
  reply(7, "late");                                                          // id already answered: ignored
  await assert.rejects(g.check(b, { tool: "late", args: {} }), /refused/);
  await handleClientLine(g, b, JSON.stringify({ jsonrpc: "2.0", id: "x", method: "tools/list" }), () => {}, () => {});
  reply("x", "b");                                                           // replaces, does not extend
  await assert.rejects(g.check(b, { tool: "a", args: {} }), /refused/); await g.check(b, { tool: "b", args: {} });
});
test("pagination: pages merge only when the request carries the last nextCursor; otherwise replace", async () => {
  const { handleClientLine } = await import("../src/index.js");
  const g = mk(DEFAULT_POLICY);
  const req = (id: number, cursor?: string) => handleClientLine(g, b, JSON.stringify({ jsonrpc: "2.0", id, method: "tools/list", params: cursor ? { cursor } : {} }), () => {}, () => {});
  const rep = (id: number, names: string[], nextCursor?: string) => observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id, result: { tools: names.map(name => ({ name })), nextCursor } }));
  await req(1); rep(1, ["a"], "c1"); await req(2, "c1"); rep(2, ["b"], "c2"); await req(3, "c2"); rep(3, ["c"]);
  assert.ok(["a", "b", "c"].every(t => g.isKnownTool(t)), "3 pages of one listing merged");
  await req(4); rep(4, ["d"]);                                                   // fresh listing: replaces
  assert.ok(!g.isKnownTool("a") && g.isKnownTool("d"));
  await req(5); rep(5, ["e"], "c5"); await req(6, "stale"); rep(6, ["f"]);       // wrong cursor: replaces
  assert.ok(!g.isKnownTool("e") && g.isKnownTool("f"));
  await req(7); rep(7, ["g"], "c7");
  observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: 99, error: { code: -1, message: "x" } }));  // unsolicited error: ignored
  await req(8); observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: 8, error: { code: -1, message: "boom" } }));  // error resets
  await req(9, "c7"); rep(9, ["h"]);
  assert.ok(!g.isKnownTool("g") && g.isKnownTool("h"), "after an error, c7 no longer continues the listing");
});
test("no-cursor requests always replace, even if the server always sends nextCursor", () => {
  const g = mk(DEFAULT_POLICY); const rep = (id: number, names: string[], nextCursor?: string) => { g.expectToolsList(id); observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id, result: { tools: names.map(name => ({ name })), nextCursor } })); };
  rep(1, ["a"], "c1"); rep(2, ["b"]); assert.equal(g.isKnownTool("a"), false);
  for (let i = 10; i < 15; i++) rep(i, [`t${i}`], "again"); rep(99, ["final"]); assert.equal(g.isKnownTool("t10"), false);
});
test("serverTools is capped (MAX_SERVER_TOOLS); extra names stay unknown", async () => {
  const { handleClientLine, MAX_SERVER_TOOLS } = await import("../src/proxy.js");
  const g = mk(DEFAULT_POLICY); let next: string | undefined;
  for (let i = 0; i < 6; i++) {
    await handleClientLine(g, b, JSON.stringify({ jsonrpc: "2.0", id: i, method: "tools/list", params: next ? { cursor: next } : {} }), () => {}, () => {});
    next = `p${i}`; observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: i, result: { tools: Array.from({ length: 1000 }, (_, j) => ({ name: `t${i}_${j}` })), nextCursor: next } }));
  }
  assert.equal(g.serverTools.size, MAX_SERVER_TOOLS); assert.equal(g.isKnownTool("t5_999"), false);
});
test("inverse of the pagination case: after a page with nextCursor, a request WITHOUT cursor replaces the list", async () => {
  const { expectToolsListPage } = await import("../src/proxy.js");
  const g = mk(DEFAULT_POLICY);
  expectToolsListPage(g, 1, undefined); observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: 1, result: { tools: [{ name: "a" }], nextCursor: "c" } }));
  expectToolsListPage(g, 2, undefined); observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: 2, result: { tools: [{ name: "b" }] } }));
  assert.equal(g.isKnownTool("a"), false); assert.equal(g.isKnownTool("b"), true);
});
test("destructiveTools is capped, never forgets a name, and fails closed (confirm everything) beyond the cap", async () => {
  const { expectToolsListPage, MAX_DESTRUCTIVE_TOOLS, CappedDestructiveSet } = await import("../src/proxy.js");
  const g = mk(DEFAULT_POLICY + "knownTools: ['*']\n"); let next: string | undefined;
  for (let i = 0; i * 1000 <= MAX_DESTRUCTIVE_TOOLS; i++) {
    expectToolsListPage(g, i, next); next = `p${i}`;
    observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: i, result: { nextCursor: next, tools: Array.from({ length: 1000 }, (_, j) => ({ name: `d${i}_${j}`, annotations: { destructiveHint: true } })) } }));
  }
  const d = g.destructiveTools as InstanceType<typeof CappedDestructiveSet>;
  assert.ok(d instanceof CappedDestructiveSet && d.size === MAX_DESTRUCTIVE_TOOLS && d.overflowed);
  assert.ok(d.has("d0_0"), "first name never forgotten"); d.delete("d0_0"); d.clear(); assert.ok(d.has("d0_0"));
  expectToolsListPage(g, 999, undefined); observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: 999, result: { tools: [{ name: "harmless" }] } }));
  await assert.rejects(g.check(b, { tool: "harmless", args: {} }), /confirmation refused/, "beyond the cap every call needs confirmation");
});
test("strict mode (destructiveTools full) is logged exactly once on stderr", async () => {
  const { CappedDestructiveSet } = await import("../src/proxy.js");
  const logs: string[] = []; const orig = console.error; console.error = (m: string) => { logs.push(String(m)); };
  try { const d = new CappedDestructiveSet([], 2); for (const x of ["a", "b", "c", "d", "e"]) d.add(x); assert.ok(d.overflowed && d.has("zzz")); }
  finally { console.error = orig; }
  assert.equal(logs.filter(l => l.includes("STRICT MODE")).length, 1);
});
