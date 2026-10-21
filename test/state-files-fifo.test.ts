// No file of KYTRAL_HOME that an agent hook or a proxy reads can make it wait: a FIFO put in place of the hook policy,
// config.json, the secret file, kept-calls.jsonl, dashboard.json or a FileSet (revocations.json) is refused, never opened
// for good (opening a FIFO waits for a writer, and an agent whose hook times out may run the tool). The hook answers at once.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { lstatSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const S = "4a7d0c3f6b9e2d5a8c1f4b7e0a3d6c9f2b5e8a1d4c7f0b3e6a9d2c5f8b1e4a7d", AUD = "kytral-guard:fifo-test";
const NO_FIFO = process.platform === "win32" && "FIFOs are not in the file system on Windows";
function fifo(path: string) { rmSync(path, { force: true }); assert.equal(spawnSync("mkfifo", [path]).status, 0); assert.ok(lstatSync(path).isFIFO()); }
const env = (h: string, extra: Record<string, string | undefined> = {}) => {
  const e: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_AUDIT: join(h, "audit.jsonl"), KYTRAL_SECRET: S, KYTRAL_AUDIENCE: AUD, ...extra };
  for (const k of ["KYTRAL_AUDIT_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS", "KYTRAL_KEEP_CALLS", "KYTRAL_CONFIRM_QUEUE"]) if (!(k in extra)) delete e[k];
  for (const k of Object.keys(e)) if (e[k] === undefined) delete e[k];
  return e as NodeJS.ProcessEnv;
};
/** A hook of `agent` for one shell command, stopped after 20 s: it must answer long before. */
function hook(h: string, agent: string, command: string, extra: Record<string, string | undefined> = {}) {
  const ev = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, cwd: tmpdir(), session_id: "s", ...(agent === "codex" ? { turn_id: "t" } : {}) };
  const t0 = Date.now();
  const r = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "hook", agent], { cwd: ROOT, env: env(h, extra), input: JSON.stringify(ev), encoding: "utf8", timeout: 20000 });
  assert.equal(r.signal, null, `${agent} hook for ${command}: still waiting after ${Date.now() - t0} ms`);
  return { code: r.status, out: r.stdout, err: r.stderr, ms: Date.now() - t0 };
}
const reason = (r: { out: string }) => JSON.parse(r.out).hookSpecificOutput.permissionDecisionReason as string;
const home = () => mkdtempSync(join(tmpdir(), "kg-fifo-"));

test("a FIFO in place of the hook policy, config.json or the secret file: the hook refuses at once (fail closed)", { skip: NO_FIFO, timeout: 120000 }, () => {
  let h = home(); fifo(join(h, "policy.yaml"));
  let r = hook(h, "claude-code", "ls");
  assert.equal(r.code, 2, r.out + r.err); assert.match(reason(r), /the hook policy cannot be read \(EFTYPE\)/);
  h = home(); fifo(join(h, "config.json"));
  r = hook(h, "claude-code", "ls");
  assert.equal(r.code, 2, r.out + r.err); assert.match(reason(r), /config\.json is not a regular file \(a FIFO\)/);
  h = home(); const secret = join(h, "secret-file"); fifo(secret);
  r = hook(h, "claude-code", "ls", { KYTRAL_SECRET: undefined, KYTRAL_SECRET_FILE: secret });
  assert.equal(r.code, 2, r.out + r.err); assert.match(reason(r), /secret-file is not a regular file \(a FIFO\)/);
});

test("a FIFO in place of kept-calls.jsonl or dashboard.json: refusals and confirmations are answered at once, the rest as usual", { skip: NO_FIFO, timeout: 120000 }, () => {
  const h = home(); fifo(join(h, "kept-calls.jsonl")); fifo(join(h, "dashboard.json"));
  const blocked = hook(h, "claude-code", "rm -rf ~");
  assert.equal(blocked.code, 2, blocked.out + blocked.err); assert.match(reason(blocked), /blocked this call/);
  assert.equal(hook(h, "claude-code", "ls").code, 0, "allowed as usual");
  // Codex cannot ask: a confirmation goes to an open dashboard, which dashboard.json would say; a FIFO there is no dashboard
  const asked = hook(h, "codex", "rm -rf src");
  assert.equal(asked.code, 2, asked.out + asked.err); assert.match(reason(asked), /needs a human to confirm this call/);
  assert.ok(lstatSync(join(h, "kept-calls.jsonl")).isFIFO(), "never written through");
});

test("e2e: a proxy with a FIFO in place of revocations.json refuses to start, in fixed words, at once", { skip: NO_FIFO, timeout: 60000 }, async () => {
  const h = home(); fifo(join(h, "revocations.json"));
  const server = [process.execPath, join(ROOT, "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"), h];
  const p = spawn(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "--", ...server], { cwd: ROOT, env: env(h, { KYTRAL_BADGE: "x", KYTRAL_CONFIRM_QUEUE: "0" }), stdio: ["pipe", "pipe", "pipe"] });
  let err = ""; p.stderr.setEncoding("utf8"); p.stderr.on("data", d => (err += d));
  const code = await new Promise<number | null | "still running">(r => { const t = setTimeout(() => { p.kill(); r("still running"); }, 20000); p.on("close", c => { clearTimeout(t); r(c); }); });
  assert.equal(code, 2, err);
  assert.equal(err, "kytral-guard: refusing to start: the audit log, the kill switch or another state file of KYTRAL_HOME cannot be read (EFTYPE): run 'kytral-guard doctor'\n");
});
