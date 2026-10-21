// Several writers on one audit.jsonl (proxies, the CLI): appends are serialized by the inter-process lock and each one
// re-reads the file's last hash, so the file stays one valid chain.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawn } from "node:child_process"; import { appendFileSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path"; import { pathToFileURL } from "node:url";
import { AuditLog, verifyChain } from "../src/index.js";
const ROOT = resolve(import.meta.dirname, "..");
const tmp = () => mkdtempSync(join(tmpdir(), "kg-audit-"));
const lines = (f: string) => readFileSync(f, "utf8").trim().split("\n").map(l => JSON.parse(l));

test("a CLI writer and a running proxy extend one valid chain", () => {
  const f = join(tmp(), "audit.jsonl");
  const proxy = new AuditLog(f); proxy.append({ agentId: "a", tool: "t", decision: "allow" });
  const cli = new AuditLog(f); cli.append({ agentId: "a", tool: "t", decision: "known-remove" });   // e.g. `kytral-guard known remove`
  proxy.append({ agentId: "a", tool: "t", decision: "allow" });                                   // stale in-memory hash before the fix
  const all = lines(f);
  assert.deepEqual(all.map(e => e.decision), ["allow", "known-remove", "allow"]);
  assert.ok(verifyChain(all), "file is a single valid chain");
  assert.equal(all[2].prev, all[1].hash);
});
test("concurrent writers in several processes keep one valid chain", { timeout: 60000 }, async () => {
  const f = join(tmp(), "audit.jsonl"); const N = 6, PER = 20;
  const code = `import { AuditLog } from ${JSON.stringify(pathToFileURL(join(ROOT, "src/audit.ts")).href)}; const log = new AuditLog(process.argv[1]); for (let i = 0; i < ${PER}; i++) log.append({ agentId: "p" + process.argv[2], tool: "t" + i, decision: "allow" });`;
  const runs = Array.from({ length: N }, (_, k) => new Promise<number>(r => spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", code, f, String(k)], { stdio: "inherit" }).on("exit", c => r(c ?? 1))));
  assert.deepEqual(await Promise.all(runs), Array(N).fill(0));
  const all = lines(f);
  assert.equal(all.length, N * PER, "no entry lost");
  assert.ok(verifyChain(all), "no fork in the chain");
});
test("a torn or rewritten last line makes the next append fail (fail closed)", () => {
  const f = join(tmp(), "audit.jsonl");
  const log = new AuditLog(f); log.append({ agentId: "a", tool: "t", decision: "allow" });
  appendFileSync(f, '{"ts":"2026-10-14T00:00:00Z","agentId":"a","tool');
  assert.throws(() => log.append({ agentId: "a", tool: "t", decision: "allow" }), /not a valid entry/);
  assert.throws(() => new AuditLog(f), /not a valid entry/);
});
test("audit file is created with mode 0600", { skip: process.platform === "win32" && "POSIX file modes" }, () => {
  const f = join(tmp(), "audit.jsonl");
  new AuditLog(f).append({ agentId: "a", tool: "t", decision: "allow" });
  assert.equal(statSync(f).mode & 0o777, 0o600);
});
