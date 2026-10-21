import { test } from "node:test"; import assert from "node:assert/strict";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge, ClientPipeline, handleClientLineSync } from "../src/index.js";
const S = "7c3e9a1f5b2d8064e1a7c9f3b5d2e8a04f6c1b9d3e7a5f2c8b0d4e6a1f3c5b7d"; const policy = loadPolicy(DEFAULT_POLICY);
// unknownTools defaults to confirm: tests that are not about unknown tools opt in explicitly, per test, via this policy.
const knownPolicy = loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"); const badge = issueBadge(S, "a", ["*"], 60);
const call = (id: number, name: string, args = {}) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
test("decision without confirmation is synchronous", () => {
  const g = new Guard({ policy: knownPolicy, secret: S, revocationFile: null, nonceFile: null }); const srv: string[] = [];
  const r = handleClientLineSync(g, badge, call(1, "read_file"), s => srv.push(s), () => {});
  assert.equal(r, undefined); assert.equal(srv.length, 1);
});
test("pipeline preserves order across a pending human confirmation", async () => {
  let release!: (v: boolean) => void;
  const g = new Guard({ policy: knownPolicy, secret: S, revocationFile: null, nonceFile: null, confirm: () => new Promise<boolean>(r => (release = r)) });
  const out: string[] = []; const p = new ClientPipeline(g, badge, s => out.push(JSON.parse(s).id ?? JSON.parse(s).method), () => {});
  p.push(call(1, "read_file")); p.push(call(2, "delete_file", { path: "x" })); p.push(call(3, "read_file"));
  p.push(JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled" }));
  assert.deepEqual(out, [1], "nothing after the pending call is forwarded");
  release(true); await new Promise(r => setTimeout(r, 10));
  assert.deepEqual(out, [1, 2, 3, "notifications/cancelled"]); assert.equal(p.pending, 0);
});
test("kill switch during a pending confirmation refuses it", async () => {
  let release!: (v: boolean) => void;
  const g = new Guard({ policy, secret: S, revocationFile: null, nonceFile: null, confirm: () => new Promise<boolean>(r => (release = r)) });
  const srv: string[] = []; const cli: string[] = [];
  const pr = handleClientLineSync(g, badge, call(1, "delete_file", { path: "x" }), s => srv.push(s), s => cli.push(s));
  g.kill(); release(true); await pr;
  assert.equal(srv.length, 0); assert.match(cli[0], /confirmation refused/);
});
