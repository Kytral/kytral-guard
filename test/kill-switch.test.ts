// Kill switch shared by every proxy of one KYTRAL_HOME ($KYTRAL_HOME/kill-switch.json): `kytral-guard kill` from another
// process stops a running proxy within 1 s (every tool call refused, pending confirmations ended), `resume` re-enables it.
// Fail closed: an unreadable or corrupt file and an unsigned, forged or replayed resume block every call; deleting the file
// does not lift a kill. Every kill and resume is journaled with who did it.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo } from "node:os"; import { join, resolve } from "node:path"; import { createInterface } from "node:readline";
import { AuditLog, Guard, loadPolicy, DEFAULT_POLICY, issueBadge, knownKey, listRequests, verifyChain, engageKillSwitch, releaseKillSwitch, killSwitchKey } from "../src/index.js";
const ROOT = resolve(import.meta.dirname, "..");
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d"; const AUD = "kytral-guard:kill-test";
const OTHER = "c4f8a2e6d0b4f8a2c6e0d4b8f2a6c0e4d8b2f6a0c4e8d2b6f0a4c8e2d6b0f4a8";   // another deployment's secret
const bd = (agent = "agent-a") => issueBadge(S, agent, ["*"], 600, Date.now(), { aud: AUD });
const tmp = () => mkdtempSync(join(tmpdir(), "kg-kill-"));
const call = (tool: string, args: Record<string, unknown> = {}) => ({ tool, args });
const ALWAYS = { choice: "always", approver: "qa" } as const;
const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));
const lines = (f: string) => readFileSync(f, "utf8").trim().split("\n").map(l => JSON.parse(l));
/** A guard whose kill switch is <home>/kill-switch.json: the file `kytral-guard kill` writes with KYTRAL_HOME=<home>. Every tool is known. */
const mk = (home: string, o: Record<string, unknown> = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD,
  revocationFile: null, nonceFile: null, knownToolsFile: null, killSwitchFile: join(home, "kill-switch.json"), ...o });
/** Environment of the CLI and the proxy: this KYTRAL_HOME and its audit log, the proxies' secret. Entries set to undefined are removed. */
function envFor(home: string, extra: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  const e: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: home, KYTRAL_AUDIT: join(home, "audit.jsonl"), KYTRAL_SECRET: S, KYTRAL_AUDIT_SECRET: undefined, ...extra };
  for (const k of Object.keys(e)) if (e[k] === undefined) delete e[k];
  return e;
}
const CLI = ["--import", "tsx", join(ROOT, "src/cli.ts")];
/** `kytral-guard ...` in another process (blocks this one until it exits). */
const cli = (home: string, args: string[], env: Record<string, string | undefined> = {}) =>
  spawnSync(process.execPath, [...CLI, ...args], { cwd: ROOT, env: envFor(home, env), encoding: "utf8" });
/** Same without blocking; `at` = when the CLI process exited (the state file is written before). */
const cliAsync = (home: string, args: string[]) => new Promise<{ code: number | null; out: string; err: string; at: number }>(res => {
  const p = spawn(process.execPath, [...CLI, ...args], { cwd: ROOT, env: envFor(home) }); let out = "", err = "", at = 0;
  p.stdout.on("data", d => (out += d)); p.stderr.on("data", d => (err += d));
  p.on("exit", () => (at = Date.now())); p.on("close", code => res({ code, out, err, at }));
});
async function waitFor<T>(f: () => T | undefined, ms: number): Promise<T | undefined> {
  for (const end = Date.now() + ms; Date.now() < end; await sleep(20)) { const v = f(); if (v) return v; }
  return f();
}

// Run with node directly: the node_modules/.bin shim is a POSIX script that cannot be spawned on Windows.
const SERVER = [process.execPath, join(ROOT, "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js")];
/** The real stdio proxy in front of the real filesystem MCP server, with its own KYTRAL_HOME. Replies and stderr lines carry `at` (arrival time). */
function startProxy(dir: string, home: string, extraEnv: Record<string, string> = {}) {
  const p = spawn(process.execPath, [...CLI, "--", ...SERVER, dir], { cwd: ROOT, env: envFor(home, { KYTRAL_AUDIENCE: AUD, KYTRAL_BADGE: bd(), ...extraEnv }), stdio: ["pipe", "pipe", "pipe"] });
  const pending = new Map<number, (m: any) => void>(); const stderr: { at: number; line: string }[] = [];
  createInterface({ input: p.stdout! }).on("line", l => { try { const m = JSON.parse(l); pending.get(m.id)?.({ ...m, at: Date.now() }); pending.delete(m.id); } catch {} });
  createInterface({ input: p.stderr! }).on("line", line => stderr.push({ at: Date.now(), line }));
  let id = 0;
  const rpc = (method: string, params: any = {}) => new Promise<any>((res, rej) => {
    const i = ++id, t = setTimeout(() => rej(new Error(`timeout ${method}`)), 20000);
    pending.set(i, m => { clearTimeout(t); res(m); }); p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id: i, method, params }) + "\n");
  });
  const init = async () => {
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "kill-test", version: "0" } });
    p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
  };
  return { p, rpc, init, stderr, stop: () => p.kill() };
}
const text = (r: any) => (r.result?.content ?? []).map((c: any) => c.text).join("\n");

test("e2e: `kytral-guard kill` from another process stops a running proxy within 1 s; `resume` re-enables it; a corrupt file blocks it", { timeout: 120000 }, async () => {
  const dir = tmp(); writeFileSync(join(dir, "a.txt"), "a"); const home = join(dir, "home");
  const ls = { name: "list_directory", arguments: { path: dir } };
  const s = startProxy(dir, home);
  try {
    await s.init(); await s.rpc("tools/list");                                             // list_directory is known: allowed by the policy
    assert.match(text(await s.rpc("tools/call", ls)), /a\.txt/);
    const kill = await cliAsync(home, ["kill", "--by", "alice"]);
    assert.equal(kill.code, 0, kill.err); assert.match(kill.out, /^kill switch ON\tby=alice \(os:[^)]+\)\t/);
    const r = await s.rpc("tools/call", ls);
    assert.match(text(r), /^Kytral Guard: kill switch active$/); assert.ok(r.at - kill.at < 1000, `refused ${r.at - kill.at} ms after the kill`);
    const note = await waitFor(() => s.stderr.find(e => /kill switch active/.test(e.line)), 1500);
    assert.ok(note && note.at - kill.at < 1000, "the proxy reports the kill on stderr within 1 s, without any call");
    const res = await cliAsync(home, ["resume", "--by", "bob"]);
    assert.equal(res.code, 0, res.err); assert.match(res.out, /^kill switch OFF\tby=bob \(os:[^)]+\)\tat=[^\t]+\twas=on by alice \(os:/);
    assert.match(text(await s.rpc("tools/call", ls)), /a\.txt/, "the same proxy process runs again");
    writeFileSync(join(home, "kill-switch.json"), "{corrupt");
    assert.match(text(await s.rpc("tools/call", ls)), /kill switch active: kill-switch\.json corrupt \(not JSON\), every tool call is refused \(fail closed\)/);
    const fix = await cliAsync(home, ["resume"]);
    assert.equal(fix.code, 0, fix.err); assert.match(fix.out, /\twas=corrupt\t/);
    assert.match(text(await s.rpc("tools/call", ls)), /a\.txt/);
    assert.equal(s.p.exitCode, null, "never restarted");
  } finally { s.stop(); }
  const all = lines(join(home, "audit.jsonl"));
  assert.deepEqual(all.map(e => e.decision), ["allow", "kill", "block", "resume", "allow", "kill-switch-invalid", "block", "resume", "allow"]);
  assert.deepEqual(all.filter(e => e.decision === "block").map(e => e.rule), ["kill-switch", "kill-switch"]);
  assert.ok(verifyChain(all), "the proxy and the CLI wrote one valid chain");
});

test("e2e: an audit log that cannot be read never stops `kytral-guard kill`: written (exit 3, one after the tail marker's generation), it stops a running proxy; resume is refused until the log can be read, then lifts it", { timeout: 120000, skip: (process.platform === "win32" || process.getuid?.() === 0) && "file permissions do not stop this user from reading" }, async () => {
  const dir = tmp(); writeFileSync(join(dir, "a.txt"), "a"); const home = join(dir, "home"), log = join(home, "audit.jsonl");
  const ls = { name: "list_directory", arguments: { path: dir } };
  const s = startProxy(dir, home);
  try {
    await s.init(); await s.rpc("tools/list");
    // generation 2, a resume; each step waits for the proxy to say it (a CLI run can be shorter than its 250 ms poll)
    for (const [cmd, note] of [["kill", /kill switch active/], ["resume", /kill switch lifted/]] as const) {
      const r = await cliAsync(home, [cmd]); assert.equal(r.code, 0, r.err);
      assert.ok(await waitFor(() => s.stderr.find(e => note.test(e.line)), 1500), `${cmd}: the proxy says it`);
    }
    assert.match(text(await s.rpc("tools/call", ls)), /a\.txt/);
    unlinkSync(join(home, "kill-switch.json"));   // only the journal and its tail marker know the generation
    const seen = s.stderr.length;
    chmodSync(log, 0o000);
    try {
      const k = await cliAsync(home, ["kill", "--by", "ops"]);
      assert.equal(k.code, 3, k.out + k.err); assert.match(k.out, /^kill switch ON\tby=ops \(os:[^)]+\)\t.*\tgeneration=3\t/);
      assert.match(k.err, /^kytral-guard: warning: the audit log cannot be read \(EACCES\): the kill was written all the same, at generation 3, .*\(tail marker: 2, kill-switch\.json: none\)/m);
      const note = await waitFor(() => s.stderr.slice(seen).find(e => /kill switch active/.test(e.line)), 1500);
      assert.ok(note, "the running proxy sees the kill while the log cannot be read");
      const r = await s.rpc("tools/call", ls);
      assert.doesNotMatch(text(r), /a\.txt/); assert.match(text(r), /^Kytral Guard: /, "refused (it cannot journal the call either)");
      const res = await cliAsync(home, ["resume"]);
      assert.equal(res.code, 1); assert.match(res.err, /^kytral-guard: resume refused: the audit log cannot be read \(EACCES\)/);
    } finally { chmodSync(log, 0o600); }
    assert.match(text(await s.rpc("tools/call", ls)), /^Kytral Guard: kill switch active$/, "the log readable again: the kill holds");
    const res = await cliAsync(home, ["resume"]);
    assert.equal(res.code, 0, res.err); assert.match(res.out, /\tgeneration=4\t/);
    assert.match(text(await s.rpc("tools/call", ls)), /a\.txt/, "the same proxy process runs again");
  } finally { s.stop(); }
});

test("e2e: a pending confirmation is refused within 1 s when another process engages the kill switch; the request is withdrawn, nothing is recorded", { timeout: 120000 }, async () => {
  const dir = tmp(); const home = join(dir, "home"); const queue = join(home, "confirmations");
  const s = startProxy(dir, home, { KYTRAL_CONFIRM_QUEUE: "1", KYTRAL_CONFIRM_TIMEOUT_MS: "30000" });
  let req: any;
  try {
    await s.init();                                                                         // no tools/list: list_directory is unknown, a human must answer
    const pending = s.rpc("tools/call", { name: "list_directory", arguments: { path: dir } });
    for (let i = 0; i < 400 && !(req = listRequests(S, queue).requests[0]); i++) await sleep(50);
    assert.ok(req, "confirmation request written"); assert.equal(req.always, true);
    const kill = await cliAsync(home, ["kill"]);
    assert.equal(kill.code, 0, kill.err);
    const r = await pending;
    assert.match(text(r), /^Kytral Guard: confirmation refused: kill switch active$/); assert.ok(r.at - kill.at < 1000, `refused ${r.at - kill.at} ms after the kill`);
    assert.equal(listRequests(S, queue).requests.length, 0, "the request is withdrawn");
    const late = await cliAsync(home, ["confirm", "approve", req.id, "--always"]);
    assert.equal(late.code, 1); assert.match(late.err, /no pending request/);
  } finally { s.stop(); }
  assert.equal(existsSync(join(home, "known-tools.json")), false, "nothing recorded");
  // The kill is journaled once in force, so the proxy, which saw it first, may journal the refused call before it: either order.
  assert.deepEqual(lines(join(home, "audit.jsonl")).map(e => `${e.decision}:${e.rule ?? ""}`).sort(), ["block:kill-switch", "kill:"]);
});

test("kill from another process blocks a running guard at its next call, over known tools and allow rules, and a guard started meanwhile; resume re-enables both", { timeout: 120000 }, async () => {
  const home = tmp();
  const g = mk(home, { policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['read_*']\n"), knownToolsFile: join(home, "known-tools.json"), confirm: async () => ALWAYS });
  await g.check(bd(), call("mystery"));                                                     // unknown tool approved "always": known from now on
  const calls = [call("mystery"), call("read_file")];                                       // a known-tools grant, an allow by the policy
  for (const c of calls) await g.check(bd(), c);
  const k = cli(home, ["kill"]); assert.equal(k.status, 0, k.stderr);
  for (const c of calls) await assert.rejects(g.check(bd(), c), /^Error: kill switch active$/, c.tool);
  const fresh = mk(home);
  await assert.rejects(fresh.check(bd(), call("read_file")), /kill switch active/, "a guard started while killed");
  const r = cli(home, ["resume"]); assert.equal(r.status, 0, r.stderr);
  for (const c of calls) await g.check(bd(), c);
  await fresh.check(bd(), call("read_file"));
  assert.deepEqual(g.audit.entries.filter(e => e.decision === "block").map(e => e.rule), ["kill-switch", "kill-switch"]);
});

test("kill and resume are journaled with who did it (OS account, plus --by); kill needs no secret, resume needs the proxies' secret", { timeout: 120000 }, async () => {
  const home = tmp(); const auditFile = join(home, "audit.jsonl"); const os = userInfo().username;
  const g = mk(home, { audit: new AuditLog(auditFile) });
  await g.check(bd(), call("read_file"));
  for (const env of [{ KYTRAL_SECRET: undefined }, { KYTRAL_SECRET: "short", KYTRAL_AUDIT_SECRET: "weak" }]) {
    const r = cli(home, ["kill"], env); assert.equal(r.status, 0, `${JSON.stringify(env)}: ${r.stderr}`);
  }
  await assert.rejects(g.check(bd(), call("read_file")), /kill switch active/);
  for (const [env, why] of [[{ KYTRAL_SECRET: undefined }, /KYTRAL_SECRET is missing/], [{ KYTRAL_SECRET: "short" }, /KYTRAL_SECRET too short/], [{ KYTRAL_AUDIT_SECRET: "weak" }, /KYTRAL_AUDIT_SECRET too short/]] as const) {
    const r = cli(home, ["resume"], env); assert.equal(r.status, 2, JSON.stringify(env)); assert.match(r.stderr, why);
  }
  await assert.rejects(g.check(bd(), call("read_file")), /kill switch active/, "still stopped");
  const ok = cli(home, ["resume", "--by", "bob"]); assert.equal(ok.status, 0, ok.stderr);
  await g.check(bd(), call("read_file"));
  assert.equal(cli(home, ["kill", "--by", "alice"]).status, 0);
  const done = lines(auditFile).filter(e => e.decision === "kill" || e.decision === "resume");
  assert.deepEqual(done.map(e => [e.decision, e.approver]), [["kill", os], ["kill", os], ["resume", `bob (os:${os})`], ["kill", `alice (os:${os})`]]);
  assert.ok(done.every(e => e.agentId === "*" && e.tool === "*" && Date.parse(e.ts) > 0));
  assert.ok(verifyChain(lines(auditFile)), "the guard and the CLI wrote one valid chain");
  assert.equal(cli(home, ["kill", "now"]).status, 2, "usage"); assert.equal(cli(home, ["resume", "--bogus"]).status, 2, "usage");
});

test("an unreadable or corrupt kill-switch file blocks every call, at startup and while running (fail closed), journaled once per content; resume rewrites it", { timeout: 60000 }, async () => {
  const home = tmp(); const f = join(home, "kill-switch.json");
  const g = mk(home); await g.check(bd(), call("read_file"));
  const bad = ["{corrupt", "", "null", "[]", "42", '"off"', "{}", '{"killed":"false"}', '{"killed":0}'];
  for (const content of bad) {
    writeFileSync(f, content);
    for (const guard of [g, mk(home)]) await assert.rejects(guard.check(bd(), call("read_file")), /kill switch active: kill-switch\.json corrupt/, JSON.stringify(content));
    await assert.rejects(g.check(bd(), call("read_file")), /corrupt/, "same content again");
  }
  unlinkSync(f); mkdirSync(f);                                                               // a directory cannot be read
  for (const guard of [g, mk(home)]) await assert.rejects(guard.check(bd(), call("read_file")), /kill switch active: kill-switch\.json unreadable \(EISDIR\)/);
  rmSync(f, { recursive: true });
  await assert.rejects(g.check(bd(), call("read_file")), /kill switch active/, "file gone: the last state seen stays");
  assert.equal(g.audit.entries.filter(e => e.decision === "kill-switch-invalid").length, bad.length + 1, "journaled once per content (and per read error), not per call");
  const r = cli(home, ["resume"]); assert.equal(r.status, 0, r.stderr);
  await g.check(bd(), call("read_file")); await mk(home).check(bd(), call("read_file"));
});

test("a resume must be signed with the proxies' key and newer than every state seen: unsigned, foreign, edited and replayed resumes keep every call blocked", async () => {
  const home = tmp(); const f = join(home, "kill-switch.json"); const o = { path: f, audit: new AuditLog() };
  const g = mk(home); const ok = () => g.check(bd(), call("read_file"));
  const blocked = (re: RegExp, why: string) => assert.rejects(ok(), re, why);
  writeFileSync(f, JSON.stringify({ v: 1, killed: false, gen: Date.now(), at: new Date().toISOString(), by: "mallory" }));
  await blocked(/holds a resume not signed with this deployment's key/, "unsigned resume");
  releaseKillSwitch(OTHER, "mallory", o); await blocked(/not signed with this deployment's key/, "signed with another deployment's secret");
  releaseKillSwitch(S, "qa", o); await ok();
  const backup = readFileSync(f);
  writeFileSync(f, JSON.stringify({ ...JSON.parse(backup.toString()), by: "mallory" })); await blocked(/not signed with this deployment's key/, "edited resume");
  writeFileSync(f, backup); await ok();                                                       // the resume in force, read again
  engageKillSwitch("qa", o); await blocked(/^Error: kill switch active$/, "killed");
  writeFileSync(f, backup); await blocked(/holds a replayed resume/, "an old resume restored from a backup");
  assert.ok(g.audit.entries.some(e => e.decision === "kill-switch-invalid" && /replayed/.test(e.rule!)), "journaled");
  releaseKillSwitch(S, "qa", o); await ok();
  // The generation of an unsigned kill is never trusted: a forged huge one cannot make later resumes look old.
  writeFileSync(f, JSON.stringify({ v: 1, killed: true, gen: Number.MAX_SAFE_INTEGER, at: "", by: "mallory" })); await blocked(/kill switch active/, "forged kill");
  writeFileSync(f, "{garbage"); await blocked(/corrupt/, "garbage");
  releaseKillSwitch(S, "qa", o); await ok();
});

test("deleting the kill-switch file does not lift a kill: a running guard stays stopped until a resume", async () => {
  const home = tmp(); const f = join(home, "kill-switch.json"); const o = { path: f, audit: new AuditLog() };
  const g = mk(home);
  engageKillSwitch("qa", o); await assert.rejects(g.check(bd(), call("read_file")), /kill switch active/);
  unlinkSync(f); await assert.rejects(g.check(bd(), call("read_file")), /kill switch active/, "deleted: still stopped");
  releaseKillSwitch(S, "qa", o); await g.check(bd(), call("read_file"));
});

/** Runs `fn` with Date.now() frozen at `t`: kill switch generations must not depend on the clock. */
function atClock<T>(t: number, fn: () => T): T { const now = Date.now; Date.now = () => t; try { return fn(); } finally { Date.now = now; } }
/** One allowed call, checked synchronously: null when it goes through, else why it is refused. */
const verdict = (g: Guard) => { try { return g.checkSync(bd(), call("read_file")); } catch (e) { return (e as Error).message; } };
const gen = (c: { state: object }) => (c.state as { gen?: number }).gen;

test("a kill and a resume in the same millisecond work: each state is the previous generation + 1, signed, whatever the clock says", () => {
  const home = tmp(); const f = join(home, "kill-switch.json"); const o = { path: f, audit: new AuditLog(), key: killSwitchKey(S) };
  const g = mk(home), t = Date.now();
  const [kill, resume] = atClock(t, () => {
    const k = engageKillSwitch("qa", o); assert.equal(verdict(g), "kill switch active");
    const r = releaseKillSwitch(S, "qa", o); assert.equal(verdict(g), null, "resumed in the same millisecond");
    return [k, r];
  });
  assert.deepEqual([gen(kill), gen(resume), kill.state.at === resume.state.at], [1, 2, true]);
  assert.deepEqual(o.audit.entries.map(e => [e.decision, e.generation]), [["kill", 1], ["resume", 2]], "journaled with their generation");
});

test("a clock set back neither blocks a legitimate resume nor lets an older state in, even one dated later", () => {
  const home = tmp(); const f = join(home, "kill-switch.json"); const o = { path: f, audit: new AuditLog(), key: killSwitchKey(S) };
  const g = mk(home), t = Date.now(), hourBack = t - 3_600_000;
  const r1 = atClock(t, () => { releaseKillSwitch(S, "qa", o); return readFileSync(f); });           // generation 1, at t
  atClock(t, () => engageKillSwitch("qa", o));                                                        // 2, at t
  atClock(hourBack, () => { releaseKillSwitch(S, "qa", o); assert.equal(verdict(g), null, "resume written after the clock went back an hour"); });   // 3
  const k4 = atClock(hourBack, () => engageKillSwitch("qa", o));                                      // 4, at t - 1 h
  assert.equal(verdict(g), "kill switch active");
  assert.ok(Date.parse(JSON.parse(r1.toString()).at) > Date.parse(k4.state.at), "the old resume is dated after the kill");
  writeFileSync(f, r1);
  assert.match(verdict(g) ?? "", /holds a replayed resume \(generation 1, not newer than 4\)/);
});

test("a replayed older generation is refused by a running guard, also after a kill written without the key, and by a guard started during it", () => {
  const home = tmp(); const f = join(home, "kill-switch.json"); const audit = new AuditLog(), key = killSwitchKey(S);
  const g = mk(home);
  releaseKillSwitch(S, "qa", { path: f, audit }); const r1 = readFileSync(f);                         // generation 1
  engageKillSwitch("qa", { path: f, audit, key }); const k2 = readFileSync(f);                         // 2
  releaseKillSwitch(S, "qa", { path: f, audit }); const r3 = readFileSync(f);                         // 3
  assert.equal(verdict(g), null);
  writeFileSync(f, r1); assert.match(verdict(g) ?? "", /holds a replayed resume \(generation 1, not newer than 3\)/);
  writeFileSync(f, k2); assert.match(verdict(g) ?? "", /holds a replayed kill \(generation 2, not newer than 3\)/);
  writeFileSync(f, r3); assert.equal(verdict(g), null, "the resume in force, read again");
  engageKillSwitch("qa", { path: f, audit });                                                         // no key: unsigned, carries resume 3
  const unsigned = JSON.parse(readFileSync(f, "utf8"));
  assert.deepEqual([unsigned.sig, unsigned.gen, unsigned.last?.gen], [undefined, undefined, 3]);
  const late = mk(home);                                                                               // started during that kill
  for (const guard of [g, late]) assert.equal(verdict(guard), "kill switch active");
  writeFileSync(f, r3);                                                                                // the resume that kill replaced, put back
  for (const guard of [g, late]) assert.match(verdict(guard) ?? "", /holds a replayed resume \(generation 3, not newer than 3\)/);
  releaseKillSwitch(S, "qa", { path: f, audit });                                                     // 4
  for (const guard of [g, late]) assert.equal(verdict(guard), null);
  assert.ok(g.audit.entries.filter(e => e.decision === "kill-switch-invalid" && /replayed/.test(e.rule!)).length >= 3, "journaled");
});

test("a generation rollback after the file is deleted is refused by a running guard; the journal keeps writers going forward", () => {
  const home = tmp(); const f = join(home, "kill-switch.json"); const audit = new AuditLog(), key = killSwitchKey(S);
  const g = mk(home);
  releaseKillSwitch(S, "qa", { path: f, audit }); const r1 = readFileSync(f);                         // generation 1
  assert.equal(verdict(g), null);
  engageKillSwitch("qa", { path: f, audit, key }); assert.equal(verdict(g), "kill switch active");    // 2
  unlinkSync(f); assert.equal(verdict(g), "kill switch active", "deleted: still stopped");
  writeFileSync(f, r1); assert.match(verdict(g) ?? "", /holds a replayed resume \(generation 1, not newer than 2\)/, "an old copy put back");
  unlinkSync(f); releaseKillSwitch(S, "qa", { path: f, audit: new AuditLog() });                       // a writer that lost the file and the journal: 1 again
  assert.equal(JSON.parse(readFileSync(f, "utf8")).gen, 1);
  assert.match(verdict(g) ?? "", /holds a replayed resume \(generation 1, not newer than 2\)/, "the rollback is refused");
  assert.equal(verdict(mk(home)), null, "only a guard started now, with no memory, takes it: the recovery is a restart");
  unlinkSync(f); releaseKillSwitch(S, "qa", { path: f, audit });                                      // with the journal: 3, not 1
  assert.equal(JSON.parse(readFileSync(f, "utf8")).gen, 3); assert.equal(verdict(g), null);
});

test("with the key, a kill is signed too and its generation never goes back: after a corrupt file it follows the journal, and a guard started then refuses an older resume", () => {
  const home = tmp(); const f = join(home, "kill-switch.json"); const audit = new AuditLog(), key = killSwitchKey(S);
  const g = mk(home);
  releaseKillSwitch(S, "qa", { path: f, audit }); engageKillSwitch("qa", { path: f, audit, key });
  releaseKillSwitch(S, "qa", { path: f, audit }); const r3 = readFileSync(f);                         // generations 1 to 3
  writeFileSync(f, "{corrupt");
  const k = engageKillSwitch("qa", { path: f, audit, key });
  assert.deepEqual([gen(k), typeof (k.state as { sig?: string }).sig], [4, "string"], "signed, after the journal's 3: the file could not tell");
  const late = mk(home);
  for (const guard of [g, late]) assert.equal(verdict(guard), "kill switch active");
  writeFileSync(f, r3);
  for (const guard of [g, late]) assert.match(verdict(guard) ?? "", /holds a replayed resume \(generation 3, not newer than 4\)/);
});

test("CLI: kill is signed when a secret is set, unsigned without one (carrying the last signed state); kill and resume journal their generation", { timeout: 60000 }, () => {
  const home = tmp(); const f = join(home, "kill-switch.json"); const state = () => JSON.parse(readFileSync(f, "utf8"));
  assert.match(cli(home, ["kill"]).stdout, /\tgeneration=1\t/); assert.deepEqual([state().gen, typeof state().sig], [1, "string"]);
  assert.match(cli(home, ["resume"]).stdout, /\tgeneration=2\t/);
  const u = cli(home, ["kill"], { KYTRAL_SECRET: undefined });
  assert.equal(u.status, 0, u.stderr); assert.match(u.stderr, /the kill was written unsigned/); assert.match(u.stdout, /\tgeneration=none \(unsigned\)\t/);
  assert.deepEqual([state().sig, state().gen, state().last?.gen, state().last?.killed], [undefined, undefined, 2, false]);
  assert.match(cli(home, ["resume"]).stdout, /\tgeneration=3\t/);
  assert.deepEqual(lines(join(home, "audit.jsonl")).map(e => [e.decision, e.generation]), [["kill", 1], ["resume", 2], ["kill", undefined], ["resume", 3]]);
});

test("guard.kill() stops this process only and `resume` does not lift it; guard.resume() does not lift the shared kill", async () => {
  const home = tmp(); const o = { path: join(home, "kill-switch.json"), audit: new AuditLog() };
  const g = mk(home), other = mk(home);
  g.kill(); await assert.rejects(g.check(bd(), call("read_file")), /kill switch active/); await other.check(bd(), call("read_file"));
  releaseKillSwitch(S, "qa", o); await assert.rejects(g.check(bd(), call("read_file")), /kill switch active/, "resume does not lift kill()");
  g.resume(); await g.check(bd(), call("read_file"));
  engageKillSwitch("qa", o); g.resume();
  await assert.rejects(g.check(bd(), call("read_file")), /kill switch active/, "guard.resume() does not lift the shared kill");
});

test("a pending SDK confirmation is refused within 1 s when another process engages the kill switch; an 'always' given later records nothing", { timeout: 60000 }, async () => {
  const home = tmp(); let release!: (v: unknown) => void;
  const g = mk(home, { policy: loadPolicy(DEFAULT_POLICY), knownToolsFile: join(home, "known-tools.json"), confirm: () => new Promise(r => (release = r)) });
  const outcome = g.check(bd(), call("mystery")).then(() => "allowed", (e: Error) => e.message);
  const k = cli(home, ["kill"]); assert.equal(k.status, 0, k.stderr); const t = Date.now();   // this process is blocked until the CLI exits
  const out = await Promise.race([outcome, sleep(3000).then(() => "still pending 3 s after the kill")]);
  assert.match(out, /^confirmation refused: kill switch active$/); assert.ok(Date.now() - t < 1000, `refused ${Date.now() - t} ms after the kill`);
  release(ALWAYS); await sleep(50);
  assert.equal(g.knownTools.has(knownKey(AUD, "mystery", "agent-a")), false, "nothing recorded");
  assert.ok(!g.audit.entries.some(e => e.decision === "known-add" || e.decision === "confirmed-always"));
});

test("a lock that cannot be taken does not stop a kill: after 1 s it is written without the lock (still atomic)", { timeout: 60000 }, async () => {
  const home = tmp(); const f = join(home, "kill-switch.json"); const g = mk(home);
  writeFileSync(`${f}.lock`, "4242");                                                        // held by a stuck or hostile process (recent: not stale)
  const r = cli(home, ["kill", "--by", "alice"]);
  assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /^kill switch ON\t/); assert.match(r.stderr, /lock not taken \(lock timeout[^)]*\): written without it/);
  await assert.rejects(g.check(bd(), call("read_file")), /kill switch active/);
  unlinkSync(`${f}.lock`);
  assert.equal(cli(home, ["resume"]).status, 0); await g.check(bd(), call("read_file"));
});

test("kill-switch.json is written with mode 0600", { skip: process.platform === "win32" && "POSIX file modes" }, () => {
  const o = { path: join(tmp(), "kill-switch.json"), audit: new AuditLog() };
  engageKillSwitch("qa", o); assert.equal(statSync(o.path).mode & 0o777, 0o600);
  releaseKillSwitch(S, "qa", o); assert.equal(statSync(o.path).mode & 0o777, 0o600);
});
