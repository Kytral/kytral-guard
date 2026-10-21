import { test } from "node:test"; import assert from "node:assert/strict";
import { Guard, GuardError, loadPolicy, DEFAULT_POLICY, evaluate, issueBadge, verifyChain, handleClientLine } from "../src/index.js";
const S = "7c3e9a1f5b2d8064e1a7c9f3b5d2e8a04f6c1b9d3e7a5f2c8b0d4e6a1f3c5b7d"; const policy = loadPolicy(DEFAULT_POLICY);
// unknownTools defaults to confirm: tests that are not about unknown tools opt in explicitly, per test, via this policy.
const knownPolicy = loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n");
// revocation is persistent by default (kytral-revocations.json) : unit tests use an in-memory list so they stay isolated
const mkKnown = () => new Guard({ policy: knownPolicy, secret: S, revocationFile: null, nonceFile: null });
const mk = (confirm?: any) => new Guard({ policy, secret: S, confirm, revocationFile: null, nonceFile: null });
const badge = issueBadge(S, "agent-1", ["*"], 60);
test("allows harmless call", async () => { await mkKnown().check(badge, { tool: "query", args: { sql: "SELECT 1" } }); });
test("blocks DROP TABLE", async () => { await assert.rejects(mk().check(badge, { tool: "query", args: { sql: "DROP TABLE users" } }), GuardError); });
test("blocks rm -rf", () => assert.equal(evaluate(policy, { tool: "shell", args: { cmd: "rm -rf /data" } }).action, "block"));
test("delete needs confirmation", async () => {
  await assert.rejects(mk().check(badge, { tool: "delete_file", args: { path: "a" } }));
  await mk(async () => true).check(badge, { tool: "delete_file", args: { path: "a" } });
});
test("transfer needs confirmation", () => assert.equal(evaluate(policy, { tool: "stripe", args: { op: "payout", amount: 500 } }).action, "confirm"));
test("mass email over 20 recipients needs confirmation", () => {
  assert.equal(evaluate(policy, { tool: "send_email", args: { recipients: Array(21).fill("x@y") } }).action, "confirm");
  assert.equal(evaluate(policy, { tool: "send_email", args: { recipients: ["x@y"] } }).action, "allow");
});
test("badge scope, expiry, signature, revocation", async () => {
  const g = mk();
  await assert.rejects(g.check(issueBadge(S, "a", ["read"], 60), { tool: "write", args: {} }), /not on badge/);
  await assert.rejects(g.check(issueBadge(S, "a", ["*"], -1), { tool: "x", args: {} }), /expired/);
  await assert.rejects(g.check(issueBadge("0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071", "a", ["*"], 60), { tool: "x", args: {} }), /signature/);
  g.revoke("agent-1"); await assert.rejects(g.check(badge, { tool: "x", args: {} }), /revoked/);
});
test("kill switch blocks everything", async () => { const g = mkKnown(); g.kill(); await assert.rejects(g.check(badge, { tool: "x", args: {} }), /kill switch/); g.resume(); await g.check(badge, { tool: "x", args: {} }); });
test("audit log is hash-chained and tamper-evident", async () => {
  const g = mkKnown(); await g.check(badge, { tool: "a", args: {} }); await g.check(badge, { tool: "b", args: {} }).catch(() => {});
  assert.ok(verifyChain(g.audit.entries));
  g.audit.entries[0].tool = "tampered"; assert.equal(verifyChain(g.audit.entries), false);
});
test("MCP proxy blocks tools/call and forwards others", async () => {
  const g = mk(); const srv: string[] = []; const cli: string[] = [];
  await handleClientLine(g, badge, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }), s => srv.push(s), s => cli.push(s));
  await handleClientLine(g, badge, JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "sql", arguments: { q: "drop table users" } } }), s => srv.push(s), s => cli.push(s));
  assert.equal(srv.length, 1); assert.match(cli[0], /Kytral Guard: blocked/);
});
