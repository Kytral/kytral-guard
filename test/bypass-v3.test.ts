// Adversarial regression probes: UPDATE without WHERE, more DELETE tautologies, quoted rm, the SDK's audience, unknown tools. Red = a flaw.
import { test } from "node:test"; import assert from "node:assert/strict";
import { loadPolicy, DEFAULT_POLICY, evaluate, Guard, issueBadge } from "../src/index.js";
const p = loadPolicy(DEFAULT_POLICY);
const act = (tool: string, args: Record<string, unknown>) => evaluate(p, { tool, args }).action;
test("sql_update_without_where", () => {
  for (const sql of ["UPDATE users SET password = 'x'", "UPDATE accounts SET balance = 0;"]) assert.notEqual(act("query", { sql }), "allow", sql);
});
test("sql_delete_other_tautologies", () => {
  for (const sql of ["DELETE FROM users WHERE 1", "DELETE FROM users WHERE id IS NOT NULL", "DELETE FROM users WHERE name LIKE '%'",
    "DELETE FROM users WHERE id IN (SELECT id FROM users)", "DELETE u FROM users u", "DELETE FROM users WHERE \"a\"=\"a\""])
    assert.equal(act("query", { sql }), "block", sql);
});
test("shell_quoted_rm", () => {
  for (const cmd of ["\"rm\" -rf /", "r\"m\" -rf /", "'rm' -rf /", "$'\\x72m' -rf /"]) assert.equal(act("shell", { cmd }), "block", cmd);
});
test("sdk_audience_defaults_to_shared", () => {
  // Proxy/CLI refuse the shared audience, but the Guard SDK still silently accepts aud 'kytral-guard'
  const secret = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV-zyx";
  const prev = process.env.KYTRAL_AUDIENCE; delete process.env.KYTRAL_AUDIENCE;
  try {
    const g = new Guard({ policy: p, secret, revocationFile: null, nonceFile: null });
    const b = issueBadge(secret, "agent", ["*"], 60, Date.now());
    assert.throws(() => g.checkSync(b, { tool: "read", args: {} }));
  } finally { if (prev !== undefined) process.env.KYTRAL_AUDIENCE = prev; }
});
test("unknown_tools_default_allow", () => {
  assert.notEqual(p.unknownTools, "allow", "a tool never advertised nor listed is allowed by default");
});
