// The audit log, its tail marker and kill-switch.json are only ever opened as regular files, without waiting: a FIFO put in
// their place (opening it would wait for a writer forever, and an agent whose hook times out may run the tool), a socket, a
// device or a folder is never read. Agent hooks refuse at once (fail closed), `kill` is written all the same (exit 3, with a
// warning; a kill-switch.json that is no regular file is replaced, a folder moved aside first), `resume` refuses.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path"; import { createInterface } from "node:readline";
import { AuditLog, auditKey } from "../src/audit.js";
import { engageKillSwitch, KillSwitch, killSwitchKey, releaseKillSwitch } from "../src/kill-switch.js";
import { appendRegular, NotRegularFile, readRegular } from "../src/store.js";
import { DEFAULT_POLICY, Guard, issueBadge, loadPolicy } from "../src/index.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "6f9b2e5a8d1c4f7b0e3a6d9c2f5b8e1a4d7c0f3b6e9a2d5c8f1b4e7a0d3c6f9b", AUD = "kytral-guard:file-types";
const tmp = () => mkdtempSync(join(tmpdir(), "kg-types-"));
const NO_FIFO = process.platform === "win32" && "FIFOs are not in the file system on Windows";
/** A FIFO at `path` (mkfifo), in place of what was there. */
function fifo(path: string) {
  rmSync(path, { force: true });
  const r = spawnSync("mkfifo", [path]);
  assert.equal(r.status, 0, `mkfifo: ${r.stderr}`); assert.ok(lstatSync(path).isFIFO());
}
const event = JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, cwd: tmpdir(), session_id: "s" });
/** `kytral-guard ...` with `h` as KYTRAL_HOME, stopped after 20 s (it must never wait): its exit code, output and time. */
function cli(h: string, args: string[], input = "") {
  const e: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_AUDIT: join(h, "audit.jsonl"), KYTRAL_SECRET: S, KYTRAL_AUDIENCE: AUD };
  for (const k of ["KYTRAL_AUDIT_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS"]) delete e[k];
  const t0 = Date.now();
  const r = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...args], { cwd: ROOT, env: e as NodeJS.ProcessEnv, encoding: "utf8", input, timeout: 20000 });
  return { code: r.status, out: r.stdout, err: r.stderr, ms: Date.now() - t0, signal: r.signal };
}
/** An agent hook (Claude Code) for `ls`: refused at once (exit 2, never killed by the timeout), and why. */
function refusedHook(h: string): string {
  const r = cli(h, ["hook", "claude-code"], event);
  assert.equal(r.signal, null, `the hook waited until it was stopped (${r.ms} ms)`); assert.equal(r.code, 2, r.out + r.err);
  assert.ok(r.ms < 10000, `answered in ${r.ms} ms`);
  return JSON.parse(r.out).hookSpecificOutput.permissionDecisionReason;
}
const gen = (h: string) => JSON.parse(readFileSync(join(h, "kill-switch.json"), "utf8")).gen as number;
/** A home with a kill (1) and a resume (2) written by the CLI. */
function home() { const h = join(tmp(), "home"); assert.equal(cli(h, ["kill"]).code, 0); assert.equal(cli(h, ["resume"]).code, 0); return h; }

test("readRegular and appendRegular never open anything but a regular file: a FIFO, a device, a folder, a link to a FIFO throw NotRegularFile", { skip: NO_FIFO }, () => {
  const d = tmp(), f = join(d, "file"), p = join(d, "pipe"), l = join(d, "link"), dangling = join(d, "dangling");
  writeFileSync(f, "x"); fifo(p); symlinkSync(p, l); symlinkSync(join(d, "none"), dangling);
  assert.equal(readRegular(f).toString(), "x");
  for (const [path, kind, code] of [[p, "a FIFO", "EFTYPE"], [l, "a FIFO", "EFTYPE"], ["/dev/null", "a device", "EFTYPE"], [d, "a folder", "EISDIR"]] as const) {
    assert.throws(() => readRegular(path), (e: unknown) => e instanceof NotRegularFile && e.kind === kind && e.code === code, path);
    assert.throws(() => appendRegular(path, "y"), (e: unknown) => e instanceof NotRegularFile && e.code === code, path);
  }
  assert.throws(() => readRegular(dangling), { code: "ENOENT" });
  symlinkSync(f, join(d, "to-file")); assert.equal(readRegular(join(d, "to-file")).toString(), "x", "a link to a regular file is read");
  appendRegular(join(d, "new"), "z"); assert.equal(readFileSync(join(d, "new"), "utf8"), "z");
});

test("CLI, a FIFO in place of the audit log: a hook refuses at once; resume refuses; kill is written (exit 3) and stops hooks; the FIFO gone, resume lifts it", { skip: NO_FIFO, timeout: 120000 }, () => {
  const h = home(), log = join(h, "audit.jsonl");
  fifo(log);
  assert.match(refusedHook(h), /refused because the guard could not decide \(fail closed\): .*audit\.jsonl is not a regular file \(a FIFO\)/);
  const before = readFileSync(join(h, "kill-switch.json"));
  const r = cli(h, ["resume"]);
  assert.equal(r.code, 1, r.out + r.err); assert.equal(r.signal, null);
  assert.match(r.err, /^kytral-guard: resume refused: the audit log cannot be read \(not a regular file: a FIFO\) .*nothing was written/);
  assert.deepEqual(readFileSync(join(h, "kill-switch.json")), before, "resume wrote nothing");
  const k = cli(h, ["kill", "--by", "ops"]);
  assert.equal(k.signal, null, `kill waited (${k.ms} ms)`); assert.equal(k.code, 3, k.out + k.err);
  assert.match(k.err, /^kytral-guard: warning: the audit log cannot be read \(not a regular file: a FIFO\): the kill was written all the same, at generation 3, one after the highest generation known without the log \(tail marker: 2, kill-switch\.json: 2\)\./m);
  assert.match(k.err, /^kytral-guard: warning: kill switch ON, but the kill could not be journaled: .*audit\.jsonl is not a regular file \(a FIFO\)/m);
  assert.equal(JSON.parse(readFileSync(join(h, "kill-switch.json"), "utf8")).killed, true); assert.equal(gen(h), 3);
  refusedHook(h);
  unlinkSync(log);
  assert.match(refusedHook(h), /every agent is stopped \(kill switch\)/, "the FIFO gone: the kill holds");
  const res = cli(h, ["resume"]);
  assert.equal(res.code, 0, res.err); assert.equal(gen(h), 4);
  assert.equal(cli(h, ["hook", "claude-code"], event).code, 0);
});

test("CLI, a FIFO in place of the tail marker: a hook refuses at once; resume refuses; kill is written (exit 3), journaled, and its marker takes the FIFO's place", { skip: NO_FIFO, timeout: 120000 }, () => {
  const h = home(), tail = join(h, "audit.jsonl.tail");
  fifo(tail);
  assert.match(refusedHook(h), /refused because the guard could not decide \(fail closed\): .*audit\.jsonl\.tail is not a regular file \(a FIFO\)/);
  const r = cli(h, ["resume"]);
  assert.equal(r.code, 1, r.out + r.err);
  assert.match(r.err, /^kytral-guard: resume refused: the audit log's tail marker is not a regular file \(a FIFO\), so nothing was written: the kill switch is unchanged/);
  assert.equal(gen(h), 2, "resume wrote nothing");
  const k = cli(h, ["kill"]);
  assert.equal(k.signal, null); assert.equal(k.code, 3, k.out + k.err); assert.match(k.out, /\tgeneration=3\t/);
  assert.deepEqual(k.err.trim().split("\n"), ["kytral-guard: warning: the audit log's tail marker was not a regular file (a FIFO): it was not read, the kill's generation comes from the log"]);
  assert.ok(lstatSync(tail).isFile(), "the kill's entry wrote a new marker in place of the FIFO");
  assert.match(refusedHook(h), /every agent is stopped \(kill switch\)/);
  unlinkSync(join(h, "kill-switch.json"));
  assert.match(refusedHook(h), /every agent is stopped \(kill switch\)/, "the new marker records the kill");
  assert.equal(cli(h, ["resume"]).code, 0); assert.equal(cli(h, ["hook", "claude-code"], event).code, 0);
});

test("a FIFO in place of kill-switch.json: hooks and running guards refuse every call, never wait; resume refuses; kill takes its place (exit 3) and resume then lifts it", { skip: NO_FIFO, timeout: 120000 }, () => {
  const h = home(), ks = join(h, "kill-switch.json");
  const running = new KillSwitch(ks, killSwitchKey(S));
  const g = new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null,
    killSwitchFile: ks, audit: new AuditLog(join(h, "audit.jsonl"), { key: auditKey(S) }) });
  const sdk = () => { try { return g.checkSync(issueBadge(S, "a", ["*"], 600, Date.now(), { aud: AUD }), { tool: "read_file", args: {} }); } catch (e) { return (e as Error).message; } };
  assert.equal(running.check(), null); assert.equal(sdk(), null);
  fifo(ks);
  const WHY = /^kill switch active: kill-switch\.json unreadable \(not a regular file: a FIFO\), every tool call is refused \(fail closed\)$/;
  assert.match(running.check() ?? "", WHY); assert.match(String(sdk()), WHY); assert.match(String(sdk()), WHY, "and the next call");
  assert.match(refusedHook(h), /kill-switch\.json unreadable \(not a regular file: a FIFO\)/);
  const r = cli(h, ["resume"]);
  assert.equal(r.code, 1, r.out + r.err);
  assert.match(r.err, /^kytral-guard: resume refused: kill-switch\.json is not a regular file \(a FIFO\), so nothing was written: the kill switch is unchanged/);
  assert.ok(lstatSync(ks).isFIFO(), "resume wrote nothing");
  const k = cli(h, ["kill", "--by", "ops"]);
  assert.equal(k.signal, null); assert.equal(k.code, 3, k.out + k.err);
  assert.match(k.out, /\twas=unreadable \(not a regular file: a FIFO\)\tgeneration=3\t/);
  assert.deepEqual(k.err.trim().split("\n"), ["kytral-guard: warning: kill-switch.json was not a regular file (a FIFO): the kill was written in its place"]);
  assert.ok(lstatSync(ks).isFile()); assert.equal(gen(h), 3);
  assert.equal(running.check(), "kill switch active"); assert.equal(sdk(), "kill switch active");
  assert.match(refusedHook(h), /every agent is stopped \(kill switch\)/);
  assert.equal(cli(h, ["resume"]).code, 0);
  assert.equal(running.check(), null, "the resume chains to the kill"); assert.equal(sdk(), null);
  assert.equal(cli(h, ["hook", "claude-code"], event).code, 0);
});

test("a folder in place of kill-switch.json: kill moves it aside and writes in its place (exit 3); resume refuses while it is there", { timeout: 120000 }, () => {
  const h = home(), ks = join(h, "kill-switch.json");
  rmSync(ks); mkdirSync(ks); writeFileSync(join(ks, "kept.txt"), "evidence");
  const r = cli(h, ["resume"]);
  assert.equal(r.code, 1, r.out + r.err); assert.match(r.err, /^kytral-guard: resume refused: kill-switch\.json is not a regular file \(a folder\)/);
  const k = cli(h, ["kill"]);
  assert.equal(k.code, 3, k.out + k.err); assert.match(k.out, /\twas=unreadable \(EISDIR\)\tgeneration=3\t/);
  const aside = readdirSync(h).filter(f => f.startsWith("kill-switch.json.") && f.endsWith(".moved-aside"));
  assert.equal(aside.length, 1, readdirSync(h).join(", "));
  assert.deepEqual(k.err.trim().split("\n"), [`kytral-guard: warning: kill-switch.json was not a regular file (a folder): the kill was written in its place (the folder was moved aside to ${aside[0]})`]);
  assert.equal(readFileSync(join(h, aside[0], "kept.txt"), "utf8"), "evidence", "nothing it held is lost");
  assert.equal(JSON.parse(readFileSync(ks, "utf8")).killed, true);
  assert.equal(cli(h, ["resume"]).code, 0); assert.equal(gen(h), 4);
});

test("in process: a kill with kill-switch.json, the audit log and its marker all FIFOs is written, never waits, and says all three; resume refuses", { skip: NO_FIFO }, () => {
  const h = tmp(), ks = join(h, "kill-switch.json"), log = join(h, "audit.jsonl"), saved = process.env.KYTRAL_AUDIT;
  const audit = () => new AuditLog(log, { key: auditKey(S) });
  engageKillSwitch("qa", { path: ks, audit: audit(), key: killSwitchKey(S) }); releaseKillSwitch(S, "qa", { path: ks, audit: audit() });
  for (const f of [ks, log, `${log}.tail`]) fifo(f);
  process.env.KYTRAL_AUDIT = log;   // the log the CLI uses: `kill` reads and journals it
  try {
    const k = engageKillSwitch("qa", { path: ks, key: killSwitchKey(S), auditKey: auditKey(S) });
    assert.deepEqual([JSON.parse(readFileSync(ks, "utf8")).killed, JSON.parse(readFileSync(ks, "utf8")).gen], [true, 1], "no generation known without the log and its marker");
    assert.deepEqual(k.warnings?.map(w => w.replace(/:.*/s, "")), ["kill-switch.json was not a regular file (a FIFO)", "the audit log's tail marker was not a regular file (a FIFO)",
      "the audit log cannot be read (not a regular file", "kill switch ON, but the kill could not be journaled"]);
    assert.throws(() => releaseKillSwitch(S, "qa", { path: ks }), /^Error: resume refused: the audit log cannot be read \(not a regular file: a FIFO\)/);
    assert.ok(existsSync(ks));
  } finally { if (saved === undefined) delete process.env.KYTRAL_AUDIT; else process.env.KYTRAL_AUDIT = saved; }
});

/** The real stdio proxy in front of the real filesystem MCP server, with `h` as KYTRAL_HOME. */
function proxy(dir: string, h: string) {
  const env: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_AUDIT: join(h, "audit.jsonl"), KYTRAL_SECRET: S, KYTRAL_AUDIENCE: AUD, KYTRAL_CONFIRM_QUEUE: "0",
    KYTRAL_BADGE: issueBadge(S, "agent-a", ["*"], 600, Date.now(), { aud: AUD }) };
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
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "file-types", version: "0" } });
    p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n"); await rpc("tools/list");
  };
  const ls = async () => ((await rpc("tools/call", { name: "list_directory", arguments: { path: dir } })).result?.content ?? []).map((c: any) => c.text).join("\n") as string;
  const said = async (re: RegExp, from = 0) => { for (let i = 0; i < 100 && !stderr.slice(from).some(l => re.test(l)); i++) await new Promise(r => setTimeout(r, 20)); return stderr.slice(from).some(l => re.test(l)); };
  const closed = new Promise<number | null>(r => p.on("close", c => r(c)));
  return { p, init, ls, said, stderr, closed, stop: () => p.kill() };
}

test("e2e: a proxy never waits on a FIFO: started with one in place of the log it refuses to start; running, a FIFO log or kill-switch.json refuses every call and kill and resume still reach it", { skip: NO_FIFO, timeout: 120000 }, async () => {
  const dir = tmp(), h = join(dir, "home"), log = join(h, "audit.jsonl"), ks = join(h, "kill-switch.json"); writeFileSync(join(dir, "a.txt"), "a");
  assert.equal(cli(h, ["kill"]).code, 0); assert.equal(cli(h, ["resume"]).code, 0);
  const saved = readFileSync(log);
  fifo(log);
  const t0 = Date.now(), refused = proxy(dir, h);
  assert.equal(await refused.closed, 2);
  assert.deepEqual(refused.stderr, ["kytral-guard: refusing to start: the audit log, the kill switch or another state file of KYTRAL_HOME cannot be read (EFTYPE): run 'kytral-guard doctor'"]);
  assert.ok(Date.now() - t0 < 15000);
  unlinkSync(log); writeFileSync(log, saved);
  const s = proxy(dir, h);
  try {
    await s.init(); assert.match(await s.ls(), /a\.txt/);
    fifo(log);
    assert.match(await s.ls(), /^Kytral Guard: .*audit\.jsonl is not a regular file \(a FIFO\)$/, "a call it cannot journal is refused");
    unlinkSync(log); writeFileSync(log, saved);
    assert.match(await s.ls(), /a\.txt/);
    let seen = s.stderr.length;
    fifo(ks);
    assert.ok(await s.said(/kill-switch\.json unreadable \(not a regular file: a FIFO\)/, seen), s.stderr.join(" / "));
    assert.match(await s.ls(), /^Kytral Guard: kill switch active: kill-switch\.json unreadable \(not a regular file: a FIFO\)/);
    seen = s.stderr.length;
    const k = cli(h, ["kill"]);
    assert.equal(k.code, 3, k.err); assert.ok(await s.said(/^kytral-guard: kill switch active$/, seen));
    seen = s.stderr.length;
    assert.equal(cli(h, ["resume"]).code, 0); assert.ok(await s.said(/kill switch lifted/, seen));
    assert.match(await s.ls(), /a\.txt/); assert.equal(s.p.exitCode, null, "never stopped");
  } finally { s.stop(); }
});
