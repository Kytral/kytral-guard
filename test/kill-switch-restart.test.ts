// MCP proxies and SDK guards start, as agent hooks do, from the last kill or resume the audit log records in its signed tail
// marker: one started after kill-switch.json was deleted, or after an older resume was put back, still refuses every call
// until a resume. A proxy whose audit log cannot be read refuses to start, in fixed words.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path"; import { createInterface } from "node:readline";
import { AuditLog, auditKey } from "../src/audit.js";
import { engageKillSwitch, killSwitchKey, releaseKillSwitch } from "../src/kill-switch.js";
import { DEFAULT_POLICY, Guard, issueBadge, loadPolicy } from "../src/index.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "2d7f0a3c6e9b1d4f7a0c3e6b9d2f5a8c1e4b7d0f3a6c9e2b5d8f1a4c7e0b3d6f", AUD = "kytral-guard:restart-test";
const tmp = () => mkdtempSync(join(tmpdir(), "kg-restart-"));
const bd = () => issueBadge(S, "agent-a", ["*"], 600, Date.now(), { aud: AUD });
const POLICY = loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n");
/** One allowed call through a new SDK guard: null when it goes through, else why it is refused. */
function call(o: Record<string, unknown>) {
  const g = new Guard({ policy: POLICY, secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null, ...o });
  try { return g.checkSync(bd(), { tool: "read_file", args: {} }); } catch (e) { return (e as Error).message; }
}
function cli(h: string, args: string[]) {
  const e: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_AUDIT: join(h, "audit.jsonl"), KYTRAL_SECRET: S, KYTRAL_AUDIENCE: AUD };
  for (const k of ["KYTRAL_AUDIT_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS"]) delete e[k];
  const r = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...args], { cwd: ROOT, env: e as NodeJS.ProcessEnv, encoding: "utf8" });
  assert.equal(r.status, 0, `${args.join(" ")}: ${r.stdout}${r.stderr}`);
}
/** Runs `f` with KYTRAL_HOME (and no KYTRAL_AUDIT) set to `h` in this process: the default paths are then those of `h`. */
function inHome<T>(h: string, f: () => T): T {
  const saved = { home: process.env.KYTRAL_HOME, audit: process.env.KYTRAL_AUDIT };
  process.env.KYTRAL_HOME = h; delete process.env.KYTRAL_AUDIT;
  try { return f(); } finally { process.env.KYTRAL_HOME = saved.home; if (saved.audit === undefined) delete process.env.KYTRAL_AUDIT; else process.env.KYTRAL_AUDIT = saved.audit; }
}

test("an SDK guard started after kill-switch.json was deleted, or after an older resume was put back, refuses every call until a resume", () => {
  const h = tmp(), ks = join(h, "kill-switch.json"), audit = () => new AuditLog(join(h, "audit.jsonl"), { key: auditKey(S) });
  const o = () => ({ killSwitchFile: ks, audit: audit() });
  const kill = () => engageKillSwitch("qa", { path: ks, audit: audit(), key: killSwitchKey(S) }), resume = () => releaseKillSwitch(S, "qa", { path: ks, audit: audit() });
  kill(); resume(); const old = readFileSync(ks);   // a resume, generation 2
  kill();
  assert.equal(call(o()), "kill switch active");
  unlinkSync(ks);
  assert.equal(call(o()), "kill switch active", "kill-switch.json deleted: a guard started now still stops");
  writeFileSync(ks, old);
  assert.match(String(call(o())), /holds a replayed resume \(generation 2, not newer than 3\)/, "an older resume put back");
  resume(); assert.equal(call(o()), null, "a resume lifts it");
  // a guard started after the file was deleted, then resumed: the resume (after the kill the journal holds) lifts it
  kill(); unlinkSync(ks);
  const g = new Guard({ policy: POLICY, secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null, ...o() });
  assert.equal(g.killReason(), "kill switch active");
  resume(); assert.equal(g.killReason(), null);
});

test("an SDK guard with the default kill-switch.json reads the default audit log (where `kytral-guard kill` journals), even with a log of its own or none", () => {
  const h = tmp();
  cli(h, ["kill"]); cli(h, ["resume"]); cli(h, ["kill"]);
  unlinkSync(join(h, "kill-switch.json"));
  inHome(h, () => {
    assert.equal(call({}), "kill switch active", "no log of its own (in memory)");
    assert.equal(call({ audit: new AuditLog(join(tmp(), "own.jsonl"), { key: auditKey(S) }) }), "kill switch active", "a log of its own elsewhere");
    assert.equal(call({ killSwitchFile: join(tmp(), "kill-switch.json") }), null, "another kill-switch.json: the default log does not speak for it");
  });
  cli(h, ["resume"]);
  inHome(h, () => assert.equal(call({}), null, "resumed"));
});

/** The real stdio proxy in front of the real filesystem MCP server, with `h` as KYTRAL_HOME. */
function proxy(dir: string, h: string) {
  const env: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_AUDIT: join(h, "audit.jsonl"), KYTRAL_SECRET: S, KYTRAL_AUDIENCE: AUD, KYTRAL_BADGE: bd(), KYTRAL_CONFIRM_QUEUE: "0" };
  for (const k of ["KYTRAL_AUDIT_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS"]) delete env[k];
  const server = [process.execPath, join(ROOT, "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"), dir];
  const p = spawn(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "--", ...server], { cwd: ROOT, env: env as NodeJS.ProcessEnv, stdio: ["pipe", "pipe", "pipe"] });
  const pending = new Map<number, (m: any) => void>(), stderr: string[] = []; let id = 0;
  createInterface({ input: p.stdout! }).on("line", l => { try { const m = JSON.parse(l); pending.get(m.id)?.(m); pending.delete(m.id); } catch {} });
  createInterface({ input: p.stderr! }).on("line", l => stderr.push(l));
  const rpc = (method: string, params: any = {}) => new Promise<any>((res, rej) => {
    const i = ++id, t = setTimeout(() => rej(new Error(`timeout ${method}: ${stderr.join(" / ")}`)), 20000);
    pending.set(i, m => { clearTimeout(t); res(m); }); p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id: i, method, params }) + "\n");
  });
  const init = async () => {
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "restart-test", version: "0" } });
    p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n"); await rpc("tools/list");
  };
  const ls = async () => ((await rpc("tools/call", { name: "list_directory", arguments: { path: dir } })).result?.content ?? []).map((c: any) => c.text).join("\n") as string;
  const said = async (re: RegExp) => { for (let i = 0; i < 100 && !stderr.some(l => re.test(l)); i++) await new Promise(r => setTimeout(r, 20)); return stderr.some(l => re.test(l)); };
  const exit = new Promise<number | null>(r => p.on("close", c => r(c)));   // once its output is read
  return { p, init, ls, said, stderr, exit, stop: () => p.kill() };
}

test("e2e: a proxy started after kill-switch.json was deleted, or after an older resume was put back, refuses every call; resume lifts it without a restart", { timeout: 120000 }, async () => {
  const dir = tmp(), h = join(dir, "home"); writeFileSync(join(dir, "a.txt"), "a");
  cli(h, ["kill"]); cli(h, ["resume"]); const old = readFileSync(join(h, "kill-switch.json"));
  cli(h, ["kill"]); unlinkSync(join(h, "kill-switch.json"));
  let s = proxy(dir, h);
  try {
    await s.init();
    assert.ok(await s.said(/^kytral-guard: kill switch active$/), `said at startup: ${s.stderr.join(" / ")}`);
    assert.match(await s.ls(), /^Kytral Guard: kill switch active$/);
    cli(h, ["resume"]);
    assert.ok(await s.said(/kill switch lifted/), "the resume reaches the running proxy");
    assert.match(await s.ls(), /a\.txt/);
  } finally { s.stop(); }
  cli(h, ["kill"]); writeFileSync(join(h, "kill-switch.json"), old);
  s = proxy(dir, h);
  try {
    await s.init();
    assert.match(await s.ls(), /^Kytral Guard: kill switch active: kill-switch\.json holds a replayed resume \(generation 2, not newer than 5\)/);
  } finally { s.stop(); }
});

test("e2e: a proxy whose audit log cannot be read refuses to start, in fixed words", { timeout: 60000, skip: (process.platform === "win32" || process.getuid?.() === 0) && "file permissions do not stop this user from reading" }, async () => {
  const dir = tmp(), h = join(dir, "home"), log = join(h, "audit.jsonl");
  cli(h, ["kill"]); cli(h, ["resume"]);
  chmodSync(log, 0o000);
  try {
    const s = proxy(dir, h);
    assert.equal(await s.exit, 2);
    assert.deepEqual(s.stderr, ["kytral-guard: refusing to start: the audit log, the kill switch or another state file of KYTRAL_HOME cannot be read (EACCES): run 'kytral-guard doctor'"]);
  } finally { chmodSync(log, 0o600); }
});
