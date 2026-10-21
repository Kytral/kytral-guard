// Non-regression: normalization must not turn harmless calls into blocks.
import { test } from "node:test"; import assert from "node:assert/strict";
import { loadPolicy, DEFAULT_POLICY, evaluate } from "../src/index.js";
const p = loadPolicy(DEFAULT_POLICY);
const act = (tool: string, args: Record<string, unknown>) => evaluate(p, { tool, args }).action;
test("harmless calls stay allowed", () => {
  for (const [t, a] of [["query", { sql: "SELECT * FROM users WHERE id = 5" }], ["query", { sql: "DELETE FROM sessions WHERE id = 42" }],
    ["shell", { cmd: "rm -f build.log" }], ["shell", { cmd: "ls -r /tmp" }], ["read_text_file", { path: "/home/a/notes.md" }],
    ["send_email", { to: "a@b.c, d@e.f" }]] as const) assert.equal(act(t, a as any), "allow", JSON.stringify(a));
});
test("obfuscations are caught", () => {
  assert.equal(act("query", { sql: "dRoP -- x\n  TaBle users" }), "block");
  assert.equal(act("query", { sql: "DROP%2520TABLE%2520users" }), "block");             // double URL-encoding
  assert.equal(act("shell", { cmd: "r\u200bm -rf /" }), "block");                        // zero-width
  assert.equal(act("query", { sql: "EXEC(0x44524f50205441424c45207573657273)" }), "block"); // hex literal
});

test("renamed delete tools need confirmation, harmless names do not", async () => {
  for (const t of ["rmFile", "purge_cache", "trashMessage", "drop_index", "files.unlink"]) assert.equal(act(t, {}), "confirm", t);
  for (const t of ["read_file", "list_directory", "search_files", "format_report", "get_remote_info"]) assert.equal(act(t, {}), "allow", t);
});
test("server destructiveHint escalates allow to confirm", async () => {
  const { Guard, issueBadge, observeServerLine } = await import("../src/index.js");
  const g = new Guard({ policy: p, secret: "2b8e4f1a6c9d3e7b5a0f2d8c4e6b1a9f7d3c5e8b0a2f4d6c1e9b7a3f5d8c2e4b", revocationFile: null } as any);
  g.expectToolsList(1); observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: 1, result: { tools: [{ name: "write_file", annotations: { destructiveHint: true } }] } }));
  await assert.rejects(g.check(issueBadge("2b8e4f1a6c9d3e7b5a0f2d8c4e6b1a9f7d3c5e8b0a2f4d6c1e9b7a3f5d8c2e4b", "a", ["*"], 60), { tool: "write_file", args: {} }), /confirmation refused/);
});
test("the bypass fixes keep harmless calls allowed", () => {
  for (const [t, a] of [["query", { sql: "DELETE FROM users WHERE id=5" }], ["query", { sql: "DELETE FROM users WHERE email = 'a@b.c'" }],
    ["shell", { cmd: "find . -name '*.ts'" }], ["shell", { cmd: "echo 'it''s ok'" }], ["send_email", { list: ["a@b.c", "d@e.f"], body: "hi" }]] as const)
    assert.equal(act(t, a as any), "allow", JSON.stringify(a));
  assert.equal(act("query", { sql: "DELETE FROM logs WHERE created_at < '2026-01-01'" }), "block"); // documented side effect: range deletes blocked
});
