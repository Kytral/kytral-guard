// Adversarial regression probes: each test fails while its flaw exists (SQL and shell obfuscation, statements no rule covered).
import { test } from "node:test"; import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { Guard, loadPolicy, DEFAULT_POLICY, evaluate, issueBadge, verifyBadge, handleClientLine } from "../src/index.js";
const S = "7c3e9a1f5b2d8064e1a7c9f3b5d2e8a04f6c1b9d3e7a5f2c8b0d4e6a1f3c5b7d"; const policy = loadPolicy(DEFAULT_POLICY);
const badge = issueBadge(S, "agent-1", ["*"], 60);
const act = (tool: string, args: Record<string, unknown>) => evaluate(policy, { tool, args }).action;

// --- obfuscated SQL ---
test("bypass_sql_newline_tab", () => {
  assert.equal(act("query", { sql: "DROP\nTABLE users" }), "block");
  assert.equal(act("query", { sql: "DROP\tTABLE users" }), "block");
});
test("bypass_sql_inline_comment", () => assert.equal(act("query", { sql: "DROP/**/TABLE users" }), "block"));
test("bypass_sql_string_concat", () => assert.equal(act("query", { sql: "EXEC('DR'+'OP TABLE users')" }), "block"));
test("bypass_sql_hex_char", () => assert.equal(act("query", { sql: "EXEC(CHAR(68,82,79,80)+' TABLE users')" }), "block"));
test("bypass_sql_delete_where_tautology", () => assert.equal(act("query", { sql: "DELETE FROM users WHERE 1=1" }), "block"));
test("bypass_sql_uncovered_statements", () => {
  for (const sql of ["DROP SCHEMA public CASCADE", "DROP VIEW v", "ALTER TABLE users DROP COLUMN email", "TRUNCATE users"])
    assert.equal(act("query", { sql }), "block", sql);
});
// --- case: regex and glob with /i -> robust (regression test, must PASS) ---
test("case_variation_is_handled", () => {
  assert.equal(act("query", { sql: "DrOp TaBlE users" }), "block");
  assert.equal(act("DELETE_FILE", { path: "a" }), "confirm");
});
// --- encoding ---
test("bypass_encoding_url", () => assert.equal(act("query", { sql: "DROP%20TABLE%20users" }), "block"));
test("bypass_encoding_base64", () => assert.equal(act("query", { sql_b64: Buffer.from("DROP TABLE users").toString("base64") }), "block"));
test("bypass_encoding_homoglyph", () => assert.equal(act("stripe", { op: "p\u0430yout", amount: 500 }), "confirm")); // Cyrillic 'а'
test("bypass_money_plural_word_boundary", () => assert.equal(act("stripe", { op: "payouts.create", amount: 500 }), "confirm"));
test("bypass_rm_rf_variants", () => {
  for (const cmd of ["rm -fr /data", "rm -r -f /data", "rm --recursive --force /data", "rm\t-rf /data"])
    assert.equal(act("shell", { cmd }), "block", cmd);
});
// --- renamed tools / aliases / transport ---
test("bypass_renamed_delete_tool", () => {
  for (const tool of ["remove_file", "unlink", "fs.rm", "erase_backup"]) assert.equal(act(tool, { path: "a" }), "confirm", tool);
});
test("bypass_mass_email_alias_and_string", () => {
  assert.equal(act("send_email", { recipients: Array(30).fill("x@y").join(",") }), "confirm");
  assert.equal(act("send_email", { to: Array(30).fill("x@y") }), "confirm");
  assert.equal(act("mail_blast", { recipients: Array(30).fill("x@y") }), "confirm");
});
test("bypass_proxy_jsonrpc_batch", async () => {
  const g = new Guard({ policy, secret: S }); const srv: string[] = [];
  const line = JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "sql", arguments: { q: "drop table users" } } }]);
  await handleClientLine(g, badge, line, s => srv.push(s), () => {});
  assert.equal(srv.length, 0, "a JSON-RPC batch holding tools/call was forwarded unchecked");
});
// --- badges ---
test("badge_forgery_empty_secret", () => {
  // KYTRAL_SECRET not set => secret "" (proxy.ts:20, cli.ts:5): anyone can forge a badge.
  const body = Buffer.from(JSON.stringify({ agentId: "attacker", tools: ["*"], expiresAt: Date.now() + 1e9, id: "x" })).toString("base64url");
  const forged = `${body}.${createHmac("sha256", "").update(body).digest("base64url")}`;
  assert.throws(() => verifyBadge("", forged, new Set()));
});
test("badge_never_expires_nan_ttl", () => {
  const t = issueBadge(S, "a", ["*"], Number("abc")); // cli.ts:5 Number(a[3])
  assert.throws(() => verifyBadge(S, t, new Set(), Date.now() + 10 * 365 * 864e5));
});
test("badge_replay_revocation_not_persistent", async () => {
  const g1 = new Guard({ policy, secret: S }); g1.revoke("agent-1");
  const g2 = new Guard({ policy, secret: S }); // proxy restart
  await assert.rejects(g2.check(badge, { tool: "x", args: {} }), /revoked/);
});
test("badge_replay_no_audience_binding", async () => {
  // badge issued for another deployment/server sharing the secret: no aud/nonce field.
  const other = issueBadge(S, "agent-prod-crm", ["*"], 60);
  const b = verifyBadge(S, other, new Set()) as any;
  assert.ok(b.aud, "badge without an audience: replayable on any proxy sharing the secret");
});
