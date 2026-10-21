import { test } from "node:test"; import assert from "node:assert/strict";
import { spawn } from "node:child_process"; import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, isAbsolute, resolve } from "node:path"; import { pathToFileURL } from "node:url";
import { FileSet, statePath, withFileLock, Guard, loadPolicy, DEFAULT_POLICY } from "../src/index.js";
const ROOT = resolve(import.meta.dirname, "..");
test("state paths are absolute", () => {
  assert.ok(isAbsolute(statePath(undefined, "revocations.json")));
  assert.ok(isAbsolute(statePath("rel/rev.json", "x")));
  const g = new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret: "2b8e4f1a6c9d3e7b5a0f2d8c4e6b1a9f7d3c5e8b0a2f4d6c1e9b7a3f5d8c2e4b" });
  assert.ok(isAbsolute(g.revoked.path!) && isAbsolute(g.nonces.path!));
});
test("concurrent revocations from many processes are all kept (inter-process lock)", { timeout: 60000 }, async () => {
  const f = join(mkdtempSync(join(tmpdir(), "kg-lock-")), "rev.json");
  const N = 8, PER = 15;
  const code = `import { FileSet } from ${JSON.stringify(pathToFileURL(join(ROOT, "src/store.ts")).href)}; const s = new FileSet(process.argv[1]); for (let i = 0; i < ${PER}; i++) s.add("p" + process.argv[2] + "-" + i);`;
  const runs = Array.from({ length: N }, (_, k) => new Promise<number>(r => spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", code, f, String(k)], { stdio: "inherit" }).on("exit", c => r(c ?? 1))));
  assert.deepEqual(await Promise.all(runs), Array(N).fill(0));
  const keys = Object.keys(JSON.parse(readFileSync(f, "utf8")));
  assert.equal(keys.length, N * PER, "no revocation lost");
  assert.equal(existsSync(f + ".lock"), false, "lock released");
});
test("lock times out while held, and stale locks are broken", () => {
  const f = join(mkdtempSync(join(tmpdir(), "kg-lock-")), "rev.json");
  withFileLock(f, () => assert.throws(() => withFileLock(f, () => 1, 100), /lock timeout/));
  writeFileSync(f + ".lock", "99999"); assert.equal(withFileLock(f, () => 42, 1000, 0), 42);
});
