// A kill-switch.json holding JSON nested thousands of levels deep (JSON.parse reads it, signing it again overflows the
// stack): every guard refuses every call, at every check and not only the first, and never throws; `kill` writes over it
// (exit 3, with a warning); a running proxy stays alive, refuses calls, and runs again after `resume`.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path"; import { createInterface } from "node:readline";
import { AuditLog, auditKey } from "../src/audit.js";
import { engageKillSwitch, KillSwitch, killSwitchKey, releaseKillSwitch } from "../src/kill-switch.js";
import { DEFAULT_POLICY, Guard, issueBadge, loadPolicy } from "../src/index.js";
import { runHook } from "../src/hooks.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "8c1e4a7d0b3f6c9e2a5d8b1f4c7e0a3d6b9f2c5e8a1d4b7f0c3e6a9d2b5f8c1e", AUD = "kytral-guard:nested-test";
const tmp = () => mkdtempSync(join(tmpdir(), "kg-nested-"));
const NESTED = '{"a":'.repeat(5000) + "1" + "}".repeat(5000);
const WHY = /^kill switch active: kill-switch\.json corrupt \(JSON nested too deep to be a state\), every tool call is refused \(fail closed\)$/;
/** The state of `path` with its `by` field replaced by JSON nested 5000 levels deep. */
function nest(path: string) {
  const st = JSON.parse(readFileSync(path, "utf8")); st.by = "__X__";
  writeFileSync(path, JSON.stringify(st).replace('"__X__"', NESTED));
}
function home() {
  const h = tmp(), ks = join(h, "kill-switch.json"), log = join(h, "audit.jsonl");
  const audit = () => new AuditLog(log, { key: auditKey(S) });
  return { h, ks, log, audit, kill: () => engageKillSwitch("qa", { path: ks, audit: audit(), key: killSwitchKey(S) }), resume: () => releaseKillSwitch(S, "qa", { path: ks, audit: audit() }) };
}
const bd = () => issueBadge(S, "agent-a", ["*"], 600, Date.now(), { aud: AUD });
const sdk = (m: ReturnType<typeof home>) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD, revocationFile: null, nonceFile: null,
  knownToolsFile: null, killSwitchFile: m.ks, audit: m.audit() });
const verdict = (g: Guard) => { try { return g.checkSync(bd(), { tool: "read_file", args: {} }); } catch (e) { return (e as Error).message; } };
const event = JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, cwd: tmpdir(), session_id: "s" });
const gen = (r: { state: object }) => (r.state as { gen?: number }).gen;
function cli(h: string, args: string[], env: Record<string, string | undefined> = {}, input = "") {
  const e: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_AUDIT: join(h, "audit.jsonl"), KYTRAL_SECRET: S, KYTRAL_AUDIENCE: AUD, ...env };
  for (const k of ["KYTRAL_AUDIT_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS"]) delete e[k];
  for (const k of Object.keys(e)) if (e[k] === undefined) delete e[k];
  const r = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...args], { cwd: ROOT, env: e as NodeJS.ProcessEnv, encoding: "utf8", input });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test("a running guard, an SDK guard and a hook refuse every call over nested content, at every check, and never throw", () => {
  const m = home(); m.kill(); m.resume();
  const ks = new KillSwitch(m.ks, killSwitchKey(S)), g = sdk(m);
  assert.equal(ks.check(), null); assert.equal(verdict(g), null);
  nest(m.ks);
  for (let i = 0; i < 3; i++) {
    assert.match(ks.check() ?? "", WHY, `check ${i + 1}`);
    assert.match(String(verdict(g)), WHY, `SDK call ${i + 1}: refused, not only the first`);
  }
  assert.match(String(verdict(sdk(m))), WHY, "an SDK guard started now");
  const r = runHook("claude-code", event, { secret: S, audit: m.audit(), killSwitchFile: m.ks, preset: "coding-agent" });
  assert.equal(r.exitCode, 2); assert.match(JSON.parse(r.stdout).hookSpecificOutput.permissionDecisionReason, /JSON nested too deep to be a state/);
  // nested content inside the signed state an unsigned kill carries: a kill all the same, never a throw
  writeFileSync(m.ks, `{"v":1,"killed":true,"at":"","by":"x","last":{"v":2,"killed":false,"gen":99,"sig":"x","by":${NESTED}}}`);
  assert.match(ks.check() ?? "", WHY); assert.match(String(verdict(g)), WHY);
  // a resume lifts it, for the guards that saw it
  m.resume(); assert.equal(ks.check(), null); assert.equal(verdict(g), null);
});

test("kill writes over nested content, signed, one after the journal's generation, with a warning; without a key too", () => {
  const m = home(); m.kill(); m.resume(); nest(m.ks);
  const k = m.kill();
  assert.equal(gen(k), 3, "one after the journal's floor (2)"); assert.equal(k.was, "corrupt (JSON nested too deep)");
  assert.deepEqual(k.warnings, ["kill-switch.json held JSON nested too deep to be a state (content built so that checking it fails): the kill was written over it"]);
  assert.deepEqual([JSON.parse(readFileSync(m.ks, "utf8")).killed, JSON.parse(readFileSync(m.ks, "utf8")).gen], [true, 3]);
  // without a key: unsigned, and nothing of the nested content carried along (it would not even be written)
  nest(m.ks);
  const u = engageKillSwitch("qa", { path: m.ks, audit: m.audit() });
  const st = JSON.parse(readFileSync(m.ks, "utf8"));
  assert.deepEqual([st.v, st.killed, st.sig, st.last], [1, true, undefined, undefined]); assert.equal(u.warnings?.length, 1);
  assert.equal(gen(m.resume()), 4, "the generation goes on");
});

test("CLI: kill over nested content is written (exit 3, a warning on stderr); hooks stay stopped; resume lifts it", () => {
  const h = tmp(), ks = join(h, "kill-switch.json"), hook = () => cli(h, ["hook", "claude-code"], {}, event);
  assert.equal(cli(h, ["kill"]).code, 0); assert.equal(cli(h, ["resume"]).code, 0); assert.equal(hook().code, 0);
  nest(ks);
  assert.equal(hook().code, 2, "a hook refuses nested content");
  const k = cli(h, ["kill", "--by", "ops"]);
  assert.equal(k.code, 3, k.out + k.err); assert.match(k.out, /^kill switch ON\tby=ops \(os:[^)]+\)\t.*\twas=corrupt \(JSON nested too deep\)\tgeneration=3\t/m);
  assert.match(k.err, /^kytral-guard: warning: kill-switch\.json held JSON nested too deep to be a state \(content built so that checking it fails\): the kill was written over it$/m);
  assert.equal(JSON.parse(readFileSync(ks, "utf8")).killed, true);
  assert.equal(hook().code, 2);
  const r = cli(h, ["resume"]);
  assert.equal(r.code, 0, r.err); assert.match(r.out, /\tgeneration=4\t/); assert.equal(hook().code, 0);
});

test("e2e: a running proxy whose kill-switch.json gets nested content stays alive and refuses every call; kill (exit 3) and resume reach it", { timeout: 120000 }, async () => {
  const dir = tmp(), h = join(dir, "home"); writeFileSync(join(dir, "a.txt"), "a");
  assert.equal(cli(h, ["kill"]).code, 0); assert.equal(cli(h, ["resume"]).code, 0);
  const env: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_AUDIT: join(h, "audit.jsonl"), KYTRAL_SECRET: S, KYTRAL_AUDIENCE: AUD, KYTRAL_BADGE: bd(), KYTRAL_CONFIRM_QUEUE: "0" };
  for (const k of ["KYTRAL_AUDIT_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS"]) delete env[k];
  const server = [process.execPath, join(ROOT, "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"), dir];
  const p = spawn(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "--", ...server], { cwd: ROOT, env: env as NodeJS.ProcessEnv, stdio: ["pipe", "pipe", "pipe"] });
  const pending = new Map<number, (m: any) => void>(), stderr: string[] = []; let id = 0;
  createInterface({ input: p.stdout! }).on("line", l => { try { const m = JSON.parse(l); pending.get(m.id)?.(m); pending.delete(m.id); } catch {} });
  createInterface({ input: p.stderr! }).on("line", l => stderr.push(l));
  const rpc = (method: string, params: any = {}) => new Promise<any>((res, rej) => {
    const i = ++id, t = setTimeout(() => rej(new Error(`timeout ${method}`)), 20000);
    pending.set(i, m => { clearTimeout(t); res(m); }); p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id: i, method, params }) + "\n");
  });
  const ls = async () => ((await rpc("tools/call", { name: "list_directory", arguments: { path: dir } })).result?.content ?? []).map((c: any) => c.text).join("\n") as string;
  const said = async (re: RegExp, from: number) => { for (let i = 0; i < 100 && !stderr.slice(from).some(l => re.test(l)); i++) await new Promise(r => setTimeout(r, 20)); return stderr.slice(from).some(l => re.test(l)); };
  try {
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "nested-test", version: "0" } });
    p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n"); await rpc("tools/list");
    assert.match(await ls(), /a\.txt/);
    let seen = stderr.length;
    nest(join(h, "kill-switch.json"));
    assert.ok(await said(/JSON nested too deep to be a state/, seen), `the poll reports it: ${stderr.join(" / ")}`);
    await new Promise(r => setTimeout(r, 600));   // several polls over the nested content
    assert.equal(p.exitCode, null, `the proxy is alive: ${stderr.join(" / ")}`);
    assert.match(await ls(), /^Kytral Guard: kill switch active: kill-switch\.json corrupt \(JSON nested too deep to be a state\)/);
    assert.match(await ls(), /JSON nested too deep/, "and the next call");
    seen = stderr.length;
    const k = cli(h, ["kill"]);
    assert.equal(k.code, 3, k.err); assert.ok(await said(/^kytral-guard: kill switch active$/, seen), "the proxy sees the kill");
    assert.match(await ls(), /^Kytral Guard: kill switch active$/);
    seen = stderr.length;
    assert.equal(cli(h, ["resume"]).code, 0); assert.ok(await said(/kill switch lifted/, seen));
    assert.match(await ls(), /a\.txt/, "the same proxy process runs again");
    assert.equal(p.exitCode, null);
  } finally { p.kill(); }
});
