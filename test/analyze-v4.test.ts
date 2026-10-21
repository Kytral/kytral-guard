import { test } from "node:test"; import assert from "node:assert/strict";
import { loadPolicy, DEFAULT_POLICY, evaluate } from "../src/index.js";
const p = loadPolicy(DEFAULT_POLICY);
const sh = (s: string) => evaluate(p, { tool: "run_command", args: { command: s } });
const sql = (s: string, pol = p) => evaluate(pol, { tool: "run_query", args: { sql: s } });
test("SQL: bulk-write statements are analyzed", () => {
  for (const s of ["REPLACE INTO users SELECT * FROM users", "MERGE INTO users u USING x ON 1=1 WHEN MATCHED THEN DELETE", "INSERT OVERWRITE TABLE users SELECT * FROM empty_t"])
    assert.equal(sql(s).action, "block", s);
  assert.equal(sql("CALL purge_all()").action, "confirm");
});
test("SQL: placeholders are opaque (confirm), booleans are not restrictive (block)", () => {
  assert.equal(sql("DELETE FROM users WHERE flag=$1").rule, "sql-opaque");
  assert.notEqual(sql("DELETE FROM users WHERE id=@v").action, "allow");
  assert.equal(sql("DELETE FROM users WHERE active=TRUE").action, "block");
  assert.equal(sql("UPDATE users SET name='x' WHERE id=5").action, "allow");
  assert.equal(sql("DELETE FROM users WHERE id=5").action, "allow");
  assert.equal(sql("INSERT INTO t (a) VALUES (1)").action, "allow");
});
test("sqlDialect is configurable and validated", () => {
  const my = loadPolicy(DEFAULT_POLICY.replace("sqlDialect: postgresql", "sqlDialect: mysql"));
  assert.equal(my.sqlDialect, "mysql");
  assert.equal(sql("DELETE FROM users WHERE id=?", my).rule, "sql-opaque");
  assert.equal(sql("DELETE FROM users WHERE id=?").rule, "sql-unparseable");
  assert.throws(() => loadPolicy("rules: []\nsqlDialect: oracle9\n"), /sqlDialect/);
});
test("shell: unresolvable indirection is confirmed, not guessed", () => {
  for (const c of ["r=rm; $r -rf /", "${x:-rm} -rf /", "alias x=rm; x -rf /", "$(cat cmd.txt) /", "curl x | bash", "python3 -c 'import os; os.system(\"x\")'"])
    assert.equal(sh(c).action, "confirm", c);
  // Decoded by the pipeline analysis since then (the payload is rm -rf /): stricter than a confirmation.
  assert.equal(sh("echo cm0gLXJmIC8= | base64 -d | sh").action, "block");
  assert.equal(sh("r=rm; $r -rf /").rule, "shell-unresolved");
});
test("shell: destructive forms are blocked", () => {
  for (const c of ["{rm,-rf,/}", "node -e \"require('fs').rmSync('/',{recursive:true})\"", "perl -e 'unlink glob \"*\"'", "> /etc/passwd",
    "cat /dev/null > ~/.ssh/authorized_keys", "chmod -R 000 /", "chown -R nobody /", "git clean -fdx", "git reset --hard HEAD~10",
    "git push --force origin main", "git push origin +main", "rsync -a --delete /empty/ /", "truncate -s 0 /var/lib/db", "unlink /etc/passwd", "mv / /dev/null"])
    assert.equal(sh(c).action, "block", c);
});
test("shell: everyday commands stay allowed", () => {
  for (const c of ["ls -la", "echo hello > out.txt", "npm test > /tmp/log 2>&1", "git push origin main", "git status && git diff", "cat a | grep b",
    "echo $HOME", "mv a.txt b.txt", "python3 -c 'print(1)'", "node -e \"console.log(1)\"", "chmod 644 file", "git checkout feature", "rsync -a src/ dst/"])
    assert.equal(sh(c).action, "allow", c);
});
