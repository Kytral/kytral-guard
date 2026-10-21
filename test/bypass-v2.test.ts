// Adversarial regression probes: SQL deletes with tautologies, obfuscated rm, recursive deletes by other commands, mass emails. Red = a flaw.
import { test } from "node:test"; import assert from "node:assert/strict";
import { loadPolicy, DEFAULT_POLICY, evaluate } from "../src/index.js";
const p = loadPolicy(DEFAULT_POLICY);
const act = (tool: string, args: Record<string, unknown>) => evaluate(p, { tool, args }).action;
test("sql_delete_non_equality_tautology", () => {
  for (const sql of ["DELETE FROM users WHERE 1<2", "DELETE FROM users WHERE id>0", "DELETE users"]) assert.equal(act("query", { sql }), "block", sql);
});
test("shell_rm_obfuscation", () => {
  for (const cmd of ["rm -r\\\n /", "r''m -rf /", "rm${IFS}-rf${IFS}/", "$(echo rm) -rf /"]) assert.equal(act("shell", { cmd }), "block", cmd);
});
test("shell_recursive_delete_other_commands", () => {
  for (const cmd of ["find / -delete", "python -c 'import shutil;shutil.rmtree(\"/\")'"]) assert.notEqual(act("shell", { cmd }), "allow", cmd);
});
test("mass_email_unlisted_field_and_tool", () => {
  assert.notEqual(act("sendBulk", { list: Array(500).fill("a@b.c") }), "allow");
});
