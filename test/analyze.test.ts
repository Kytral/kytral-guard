import { test } from "node:test"; import assert from "node:assert/strict";
import { loadPolicy, DEFAULT_POLICY, evaluate } from "../src/index.js";
import { analyzeSql, shellDestructive, decodeAnsiC } from "../src/analyze.js";
const p = loadPolicy(DEFAULT_POLICY);
const act = (tool: string, args: Record<string, unknown>) => evaluate(p, { tool, args });
test("SQL: restrictive writes stay allowed", () => {
  for (const sql of ["DELETE FROM users WHERE id=5", "UPDATE users SET name='x' WHERE id=5", "DELETE FROM t WHERE id IN (1,2,3)",
    "UPDATE t SET a=1 WHERE id=5 AND deleted=0", "DELETE FROM t WHERE id=1 OR id=2", "SELECT * FROM t WHERE 1=1"])
    assert.equal(act("query", { sql }).action, "allow", sql);
});
test("SQL: non-restrictive writes are blocked by the parser", () => {
  for (const sql of ["UPDATE t SET a=1", "UPDATE t SET a=1 WHERE id>0", "DELETE FROM t WHERE id=5 OR 1", "DELETE FROM t WHERE x=x",
    "UPDATE a SET x=1 FROM b WHERE a.id=b.id", "DELETE FROM t WHERE id=(SELECT max(id) FROM t)"])
    assert.equal(analyzeSql(sql), "unrestricted-write", sql);
});
test("SQL: unparseable write goes to confirmation", () => {
  const d = act("query", { sql: "UPDATE users SET (((" });
  assert.equal(d.action, "confirm"); assert.equal(d.rule, "sql-unparseable");
});
test("shell: tokenizer catches destructive commands", () => {
  for (const c of ["sudo rm -rf /", "dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sdb1", "bash -c 'rm -rf ~'", "x=1 env rm -Rf /srv",
    "find / -exec rm {} ;", "echo ok && \\rm -r /srv/x"]) assert.ok(shellDestructive(c), c);
  for (const c of ["rm -f a.txt", "dd if=a of=b", "ls -r", "echo 'rm -rf /'"]) assert.equal(shellDestructive(c), null, c);
  assert.equal(decodeAnsiC("$'\\x72\\155'"), "'rm'");
});
