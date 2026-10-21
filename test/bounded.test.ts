// The proxy and the SDK analyze with a deadline and a memory limit too (Guard.checkSync, HookGuard.decide), and the inputs a
// robustness test found super-linear are linear: a crafted argument neither stops the guard nor holds its calls for minutes.
import { test } from "node:test"; import assert from "node:assert/strict";
import { analyzeShell, sqlFindingsDetailed } from "../src/analyze.js";
import { analyzeWindows } from "../src/windows.js";
import { evaluateSyncBounded, stopEvaluateWorker, workerExecArgv } from "../src/evaluate-bounded.js";
import { Guard, GuardError, issueBadge, presetPolicy } from "../src/index.js";

const S = "5e9d2c8a1f7b4063d2e8a5f1c9b74d30e6a2f8b1", AUD = "kytral-guard:bounded";
const doubling = (n: number) => ["v0=x", ...Array.from({ length: n }, (_, i) => `v${i + 1}=$v${i}$v${i}`), "echo ok"].join("\n");
const timed = <T>(f: () => T): [T, number] => { const t = performance.now(), r = f(); return [r, performance.now() - t]; };

test("a variable doubled on every line is an expansion bomb, caught at once, not gigabytes later", () => {
  const [r, ms] = timed(() => analyzeShell(doubling(40)));   // 2^40 characters if followed
  assert.ok((r.catastrophic ?? []).some(f => /variable expansion bomb/.test(f)), JSON.stringify(r));
  assert.ok(ms < 3000, `${ms} ms`);
  // values that stay small are still followed: OUT=dist, then rm -rf "$OUT" is the dist folder
  assert.deepEqual(analyzeShell('OUT=dist\nrm -rf "$OUT"').catastrophic, []);
  assert.ok(analyzeShell('T=/\nrm -rf "$T"').catastrophic.length > 0, "a known value still decides");
});

test("the proxy and SDK path (Guard.checkSync) decides crafted arguments quickly, and an analysis past its deadline needs a human", () => {
  const guard = new Guard({ policy: presetPolicy("strict"), secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null });
  const badge = issueBadge(S, "agent", ["*"], 3600, Date.now(), { aud: AUD });
  const refused = (call: { tool: string; args: Record<string, unknown> }) => { try { guard.checkSync(badge, call); return ""; } catch (e) { assert.ok(e instanceof GuardError); return (e as Error).message; } };
  const [why, ms] = timed(() => refused({ tool: "Bash", args: { command: doubling(30) } }));
  assert.match(why, /variable expansion bomb/); assert.ok(ms < 15000, `${ms} ms`);
  const saved = process.env.KYTRAL_ANALYSIS_TIMEOUT_MS;
  try {
    evaluateSyncBounded(presetPolicy("strict"), { tool: "Bash", args: { command: "ls" } });   // the thread is started (2 s more for that)
    process.env.KYTRAL_ANALYSIS_TIMEOUT_MS = "1";   // a 200 KB command is not analyzed in 1 ms
    const late = evaluateSyncBounded(presetPolicy("strict"), { tool: "Bash", args: { command: "echo a | ".repeat(20_000) + "ls" } });
    assert.equal(late.action, "confirm"); assert.equal(late.rule, "analysis-limit"); assert.match(late.reason, /could not be analyzed within/);
  } finally { if (saved === undefined) delete process.env.KYTRAL_ANALYSIS_TIMEOUT_MS; else process.env.KYTRAL_ANALYSIS_TIMEOUT_MS = saved; stopEvaluateWorker(); }
  assert.equal(evaluateSyncBounded(presetPolicy("strict"), { tool: "Bash", args: { command: "ls" } }).action, "allow", "the next call starts a new thread");
  assert.equal(evaluateSyncBounded(presetPolicy("strict"), { tool: "Bash", args: { command: "x".repeat(3 * 1024 * 1024) } }).rule, "analysis-limit", "over 2 MB: not analyzed");
});

test("open .NET file calls, repeated SQL heads and database clients are read in linear time, with the same findings", () => {
  const [r, ms] = timed(() => analyzeWindows("[IO.File]::Delete('".repeat(5000)));   // 95 KB: 12 minutes before
  assert.ok(ms < 3000, `${ms} ms`); assert.deepEqual(r.catastrophic, []);
  assert.ok(analyzeWindows("[System.IO.Directory]::Delete('C:\\', $true)").catastrophic.length > 0, "a real call is still caught");
  assert.ok(analyzeWindows("$p = 'C:\\'; [IO.Directory]::Delete($p, $true)").catastrophic.length > 0, "a variable argument too");
  const [m, ms2] = timed(() => sqlFindingsDetailed({ sql: "merge into t using s on 1 " + "when ".repeat(100_000) }));
  assert.ok(ms2 < 5000, `${ms2} ms`); assert.ok(!m.has("unrestricted-write"));
  assert.ok(sqlFindingsDetailed({ sql: "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE" }).has("unrestricted-write"), "MERGE … THEN DELETE still caught");
  const [p, ms3] = timed(() => sqlFindingsDetailed({ command: "psql app < migrations/001_init.sql ".repeat(20_000) }));
  assert.ok(ms3 < 5000, `${ms3} ms`); assert.match(p.get("opaque") ?? "", /more than 16 database clients in one command/);
});

test("worker threads get the parent's node options without the code of node -e (they would run it and never answer)", () => {
  assert.deepEqual(workerExecArgv(["--import", "tsx", "--input-type=module", "-e", "console.log(1)"]), ["--import", "tsx"]);
  assert.deepEqual(workerExecArgv(["--import", "tsx", "--input-type", "module", "--eval", "x", "-p", "1", "--print=2", "--eval=3"]), ["--import", "tsx"]);
  assert.equal(workerExecArgv(["--max-old-space-size=4096", "--enable-source-maps"]), undefined, "nothing to remove: inherited as usual");
});

test("the strict preset's regex safety nets run in linear time on repeated heads, with the same verdicts", async () => {
  const { evaluate } = await import("../src/policy.js");
  const strict = presetPolicy("strict"), run = (command: string) => evaluate(strict, { tool: "run", args: { command } }).action;
  for (const text of ["find . -name '*.ts' ".repeat(5000), "rm -" + "r".repeat(20000) + "!", "fs.rm(x, ".repeat(10000), "remove-item x ".repeat(8000)]) {
    const [, ms] = timed(() => run(text)); assert.ok(ms < 3000, `${text.slice(0, 20)}…: ${ms} ms`);
  }
  for (const c of ["rm -rf /tmp/x", "rm -f -r ./x", "find . -name x -delete", "find a find b -exec rm {} +", "node -e \"fs.rmSync(d, { recursive: true })\"", "Remove-Item x -Recurse"]) assert.equal(run(c), "block", c);
  for (const c of ["rm -f x", "find . -name x", "ls -la"]) assert.equal(run(c), "allow", c);
});
