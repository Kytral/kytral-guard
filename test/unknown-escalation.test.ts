// The unknown-tool rule only ever makes the policy stricter: it must never turn `default: block` into a confirmation
// (and, through "always", into a permanent allow).
import { test } from "node:test"; import assert from "node:assert/strict";
import { Guard, loadPolicy, issueBadge } from "../src/index.js";
const S = "6e1a9c4f2b7d5038e6a1c9f4b2d7e503a8c6f1e9b4d2a7c5f3e8b1d6a9c4f2e7"; const AUD = "kytral-guard:escalation";
const b = issueBadge(S, "agent-a", ["*"], 60, Date.now(), { aud: AUD });
const mk = (policy: any, confirm?: any) => new Guard({ policy, secret: S, audience: AUD, confirm, revocationFile: null, nonceFile: null, knownToolsFile: null });

test("default: block stays block for unknown tools; the human is never asked and 'always' cannot apply", async () => {
  let asked = 0;
  const g = mk(loadPolicy("default: block\nrules: []\n"), async () => (asked++, { choice: "always", approver: "qa" }));      // unknownTools defaults to confirm
  await assert.rejects(g.check(b, { tool: "mystery", args: {} }), /blocked/);
  await assert.rejects(g.check(b, { tool: "mystery", args: {} }), /blocked/);
  assert.equal(asked, 0);
  assert.deepEqual(g.audit.entries.map(e => e.decision), ["block", "block"]);
});
test("default: confirm stays a plain confirmation for unknown tools ('always' is not offered); unknownTools: block still escalates", async () => {
  const ctxs: any[] = [];
  const g = mk(loadPolicy("default: confirm\nrules: []\n"), async (_c: any, _d: any, ctx: any) => (ctxs.push(ctx), { choice: "always", approver: "qa" }));
  await assert.rejects(g.check(b, { tool: "mystery", args: {} }), /confirmation refused/);
  assert.deepEqual(ctxs[0].choices, ["once", "deny"]);
  await assert.rejects(mk(loadPolicy("default: confirm\nunknownTools: block\nrules: []\n")).check(b, { tool: "mystery", args: {} }), /blocked: tool 'mystery' is unknown/);
});
test("an invalid action in a policy built in code is refused, never allowed", async () => {
  await assert.rejects(mk({ default: "maybe", rules: [], knownTools: ["*"] }).check(b, { tool: "t", args: {} }), /invalid policy action 'maybe'/);
  await assert.rejects(mk({ default: "maybe", rules: [] }).check(b, { tool: "t", args: {} }), /invalid policy action/);
  await assert.rejects(mk({ default: "allow", rules: [{ name: "r", tool: "t", action: "toString" }], knownTools: ["*"] }).check(b, { tool: "t", args: {} }), /invalid policy action 'toString'/);
});
