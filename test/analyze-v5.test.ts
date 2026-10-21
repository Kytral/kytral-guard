// Analyzer tests + extra items + false-positive corpus.
import { test } from "node:test"; import assert from "node:assert/strict";
import { loadPolicy, DEFAULT_POLICY, evaluate } from "../src/index.js";
const p = loadPolicy(DEFAULT_POLICY);
const ev = (tool: string, args: any) => evaluate(p, { tool, args } as any);
const notAllowed = (tool: string, args: any, label: string) => assert.notEqual(ev(tool, args).action, "allow", label);

test("indirection in neutral tool/field names", () => {
  for (const s of ["r=rm; $r -rf /", "${x:-rm} -rf /", "alias x=rm; x -rf /", "echo cm0gLXJmIC8= | base64 -d | sh", "eval $X", "x=r; ${x}m -rf /"])
    for (const tool of ["task", "docker_exec", "k8s", "ci_job"]) notAllowed(tool, { input: s }, `${tool} ${s}`);
});
test("argv arrays in neutral fields, nested, or JSON in a string", () => {
  notAllowed("task", { input: ["rm", "-rf", "/"] }, "input argv");
  notAllowed("task", { steps: [["rm", "-rf", "/"]] }, "nested argv");
  notAllowed("task", { payload: JSON.stringify({ argv: ["rm", "-rf", "/"] }) }, "JSON argv");
  notAllowed("task", { payload: JSON.stringify({ q: "DELETE FROM users" }) }, "JSON SQL");
});
test("EXPLAIN ANALYZE executes the write", () => {
  for (const s of ["EXPLAIN ANALYZE DELETE FROM users WHERE id=$1", "EXPLAIN ANALYZE UPDATE users SET a=1", "EXPLAIN (ANALYZE, BUFFERS) DELETE FROM t"])
    notAllowed("run_query", { sql: s }, s);
  assert.equal(ev("run_query", { sql: "EXPLAIN ANALYZE SELECT * FROM t" }).action, "allow");
});
test("overwrite variants", () => {
  for (const s of ["> etc/passwd", "echo x | tee /etc/passwd", "cp /dev/null /etc/passwd", "node --eval=\"require('fs').rmSync('/',{recursive:true})\"",
    "echo 'x' >> /etc/passwd", "echo key >> ~/.ssh/authorized_keys", "sed -i 's/root/x/' /etc/passwd", "ln -sf /dev/null ~/.bashrc",
    "install -m 777 evil /usr/bin/sudo", "echo x > ./etc/sudoers"]) notAllowed("run_command", { command: s }, s);
});
test("SQL COPY / ALTER RENAME / GRANT / SQL after text", () => {
  for (const s of ["COPY users TO '/tmp/u.csv'", "COPY t FROM PROGRAM 'rm -rf /'", "ALTER TABLE users RENAME TO old_users", "GRANT ALL ON users TO public",
    "REVOKE SELECT ON t FROM bob"]) notAllowed("run_query", { sql: s }, s);
  assert.equal(ev("run_query", { sql: "COPY t FROM PROGRAM 'rm -rf /'" }).action, "block");
  for (const s of ["x UPDATE users SET a=1", "please run: DELETE FROM users;", "note\nUPDATE accounts SET balance=0"]) notAllowed("task", { input: s }, s);
  assert.equal(ev("task", { input: "please run: DELETE FROM users WHERE id=5;" }).action, "allow");
});
test("everyday commands stay allowed everywhere", () => {
  for (const c of ["echo hi >> build.log", "sed -i 's/a/b/' src/x.ts", "ln -sf ../shared node_modules/shared", "cp a.txt b.txt", "install -m 644 a.conf ./dist/",
    "echo hi | tee out.log", "echo $PATH", "git commit -am 'fix'", "make && make install"]) assert.equal(ev("task", { input: c }).action, "allow", c);
});

// --- false-positive corpus: harmless prose, code, Markdown, JSON, SQL reads -----------------
export const CORPUS = [
  "Bonjour Sam, voici le compte rendu de la réunion de mardi.", "Please update the README before the release.", "Delete the old files from the shared drive when you have time.",
  "Truncate the table later? Let's discuss.", "Unlink the account from Stripe in the dashboard.", "Remove the duplicate entries manually.",
  "$5 off today only!", "Price: $10 | Tax: $2", "`npm test` runs the whole suite.", "Use {name} in the template, e.g. Hello {name}!",
  "> Note: this is a quote in Markdown.", "> see docs/setup.md for details", "- item one\n- item two\n> quoted line", "# Title\n\nSome *bold* text and `code`.",
  "if (a > b) { return a; }", "const x = arr.filter(v => v > 0);", "for i in range(10):\n    print(i)", "SELECT id, name FROM users WHERE id = 5",
  "SELECT count(*) FROM orders WHERE created_at > now() - interval '1 day'", "Alias: Bob", "source: Wikipedia", "Use rm carefully.",
  "The update set includes 3 changes.", "Call me at 5pm (Paris time).", "We will execute the plan tomorrow.", "Grant access on Monday once approved.",
  "Copy the file to the team folder.", "Alter your settings in Preferences.", "Drop me a line when ready.", "x > 5 and y < 3",
  "Merge into main after review.", "Insert into the doc a table of contents.", "echo 'hello world'", "ls -la ~/projects", "git log --oneline -5",
  "cat package.json | jq .version", "{\"name\":\"kytral\",\"tags\":[\"ai\",\"security\"]}", "[\"hello\", \"world\"]", "https://example.com/path?q=a%20b",
  "Le prix est de 5 € > 3 €.", "Contact: sam@example.com", "TODO: refactor the parser; then run the tests", "a=1; b=2; echo $a",
];
test("false positives: harmless corpus is allowed", () => {
  const fp = CORPUS.filter(s => ev("task", { input: s }).action !== "allow");
  assert.deepEqual(fp.map(s => `${s} -> ${ev("task", { input: s }).rule}`), [], `false positives ${fp.length}/${CORPUS.length}`);
  for (const s of CORPUS) assert.equal(ev("send_message", { body: s, tags: ["a", "b"] }).action === "block", false, s);
});
