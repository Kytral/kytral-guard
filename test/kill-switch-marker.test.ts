// The audit log's tail marker signs the id of its log (`dep`: an HMAC, with the audit key, of the log's real path, derived as
// kill-switch.json's id is). A marker taken from another KYTRAL_HOME using the same secret, written by an older version (no id),
// or that does not verify never speaks for the kill switch: it never lifts a kill and is never taken for a resume. When the
// log itself records no kill or resume as recent as what such a marker says, every guard starts held (every call refused),
// and the markers written after it say so, until a single `kytral-guard resume`, which writes a marker with this log's id.
import { test } from "node:test"; import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdtempSync, readFileSync, renameSync, truncateSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path"; import { createInterface } from "node:readline";
import { AuditLog, auditKey, auditTailPath, lastSwitch, tailDep } from "../src/audit.js";
import { canonicalJson } from "../src/confirm-queue.js";
import { DEFAULT_POLICY, Guard, issueBadge, loadPolicy } from "../src/index.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "4e9b2d7a1c6f3e8b5d0a7c2f9e4b1d6a8c3f0e5b2d9a6c1f4e7b0d3a8c5f2e9b", AUD = "kytral-guard:marker-test", AK = auditKey(S);
const tmp = () => mkdtempSync(join(tmpdir(), "kg-marker-"));
const log = (h: string) => join(h, "audit.jsonl"), marker = (h: string) => auditTailPath(log(h)), state = (h: string) => join(h, "kill-switch.json");
const readMarker = (h: string) => JSON.parse(readFileSync(marker(h), "utf8"));
const HELD = (doubt: string) => new RegExp(`kill switch active: the audit log's tail marker ${doubt}, so the last kill or resume is not known, every tool call is refused \\(fail closed\\): a single 'kytral-guard resume' lifts it`);
const FOREIGN = HELD("was written for another audit log \\(another KYTRAL_HOME using the same secret, or this one through another path\\)");
const OLDER = HELD("was written by an older version of Kytral Guard"), INVALID = HELD("does not verify \\(edited, forged, written with another key, or unreadable\\)");

function cli(h: string, args: string[], input = "") {
  const env: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_SECRET: S };
  for (const k of ["KYTRAL_AUDIT", "KYTRAL_AUDIT_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS"]) delete env[k];
  const r = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...args], { cwd: ROOT, env: env as NodeJS.ProcessEnv, encoding: "utf8", input });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
const ok = (h: string, ...args: string[]) => { const r = cli(h, args); assert.equal(r.code, 0, `${args.join(" ")}: ${r.out}${r.err}`); return r; };
/** An agent hook as Claude Code runs it, for `ls`: its exit code (0 allowed, 2 refused) and the reason its agent reads. */
function hook(h: string) {
  const r = cli(h, ["hook", "claude-code"], JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, cwd: tmpdir(), session_id: "s" }));
  return { code: r.code, reason: r.out.trim() ? String(JSON.parse(r.out).hookSpecificOutput?.permissionDecisionReason) : "" };
}
/** A new SDK guard of the home `h` (its kill-switch.json and its audit log). */
const sdk = (h: string) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD, revocationFile: null, nonceFile: null,
  knownToolsFile: null, killSwitchFile: state(h), audit: new AuditLog(log(h), { key: AK }) });
/** One call through the SDK guard `g`: null when it goes through, else why it is refused. */
const call = (g: Guard) => { try { return g.checkSync(issueBadge(S, "agent-a", ["*"], 600, Date.now(), { aud: AUD }), { tool: "read_file", args: {} }); } catch (e) { return (e as Error).message; } };
const mac = (body: object) => createHmac("sha256", AK).update(`audit-tail\n${canonicalJson(body)}`).digest("hex");
/** The marker of `h` as a version without the log's id wrote it: v1, signed with the same audit key, with its record (or without, as before it was recorded). */
function olderMarker(h: string, record = true) {
  const { mac: _m, dep: _d, v: _v, killSwitch, ...rest } = readMarker(h), body = { v: 1, ...rest, ...(record ? { killSwitch } : {}) };
  writeFileSync(marker(h), JSON.stringify({ ...body, mac: mac(body) }));
}
/** The marker of `h` signed with the audit key for the log at `other` (as if this home were reached through another path). */
function signedFor(h: string, other: string) {
  const { mac: _m, ...body } = readMarker(h), b = { ...body, dep: tailDep(AK, other) };
  writeFileSync(marker(h), JSON.stringify({ ...b, mac: mac(b) }));
}
/** A home whose history ends on a resume at generation 10, with the same secret. */
function otherHome() { const o = tmp(); for (let i = 0; i < 5; i++) { ok(o, "kill"); ok(o, "resume"); } return o; }

/** The real stdio proxy in front of the real filesystem MCP server, with `h` as KYTRAL_HOME. */
function proxy(dir: string, h: string) {
  const env: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_SECRET: S, KYTRAL_AUDIENCE: AUD, KYTRAL_BADGE: issueBadge(S, "agent-a", ["*"], 600, Date.now(), { aud: AUD }), KYTRAL_CONFIRM_QUEUE: "0" };
  for (const k of ["KYTRAL_AUDIT", "KYTRAL_AUDIT_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS"]) delete env[k];
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
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "marker-test", version: "0" } });
    p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n"); await rpc("tools/list");
  };
  const ls = async () => ((await rpc("tools/call", { name: "list_directory", arguments: { path: dir } })).result?.content ?? []).map((c: any) => c.text).join("\n") as string;
  const said = async (re: RegExp) => { for (let i = 0; i < 100 && !stderr.some(l => re.test(l)); i++) await new Promise(r => setTimeout(r, 20)); return stderr.some(l => re.test(l)); };
  return { init, ls, said, stderr, stop: () => p.kill() };
}

test("e2e: the marker of another home using the same secret (a newer resume there), kill-switch.json deleted here: hooks at every call, a new SDK guard and a new proxy stay stopped; one resume lifts it", { timeout: 300000 }, async () => {
  const d = tmp(), h = join(d, "kh"), other = otherHome(); writeFileSync(join(d, "a.txt"), "a");
  ok(h, "kill"); ok(h, "resume"); ok(h, "kill");   // a kill in force, generation 3
  const ours = readMarker(h), theirs = JSON.parse(readFileSync(marker(other), "utf8"));
  assert.deepEqual([ours.v, ours.dep], [2, tailDep(AK, log(h))], "the marker signs the id of its log");
  assert.notEqual(theirs.dep, ours.dep); assert.equal(theirs.killSwitch.killed, false); assert.ok(theirs.killSwitch.gen > ours.killSwitch.gen, "the other home's resume is newer");
  unlinkSync(state(h)); copyFileSync(marker(other), marker(h));
  for (let i = 0; i < 3; i++) { const r = hook(h); assert.equal(r.code, 2, `hook ${i + 1}`); assert.match(r.reason, FOREIGN, `hook ${i + 1}`); }
  assert.match(String(call(sdk(h))), FOREIGN, "a new SDK guard");
  const s = proxy(d, h);
  try { await s.init(); assert.match(await s.ls(), /^Kytral Guard: kill switch active: the audit log's tail marker was written for another audit log/, "a new proxy"); }
  finally { s.stop(); }
  assert.equal(lastSwitch(log(h), AK)?.gen, theirs.killSwitch.gen, "held at the highest generation known");
  const r = ok(h, "resume"); assert.match(r.out, /Agents and MCP proxies run again/);
  assert.match(r.out, new RegExp(`\\tgeneration=${theirs.killSwitch.gen + 1}\\t`), "the resume is above every generation known");
  assert.equal(hook(h).code, 0); assert.equal(call(sdk(h)), null);
});

test("a marker in doubt with nothing in the log (the log and kill-switch.json deleted after a kill): held at every call, the markers written meanwhile keep it held, a single resume lifts it", { timeout: 300000 }, () => {
  const other = otherHome(), theirs = () => JSON.parse(readFileSync(marker(other), "utf8"));
  const doubts: [string, string, RegExp, (h: string) => void][] = [
    ["another home's marker", "foreign", FOREIGN, h => copyFileSync(marker(other), marker(h))],
    ["a marker of an older version, with its record", "older", OLDER, h => olderMarker(h)],
    ["a marker of an older version, without a record", "older", OLDER, h => olderMarker(h, false)],
    ["this marker with another home's id put in (the MAC breaks)", "invalid", INVALID, h => { const t = readMarker(h); t.dep = theirs().dep; writeFileSync(marker(h), JSON.stringify(t)); }],
    ["this marker signed for the log of another path", "foreign", FOREIGN, h => signedFor(h, log(other))],
    ["this marker's record edited to a resume", "invalid", INVALID, h => { const t = readMarker(h); t.killSwitch.killed = false; writeFileSync(marker(h), JSON.stringify(t)); }],
  ];
  for (const [what, code, says, doubt] of doubts) {
    const h = tmp(); ok(h, "kill");
    doubt(h); unlinkSync(state(h)); unlinkSync(log(h));
    for (let i = 0; i < 3; i++) { const r = hook(h); assert.equal(r.code, 2, `${what}: hook ${i + 1}`); assert.match(r.reason, says, `${what}: hook ${i + 1}`); }
    const t = readMarker(h);
    assert.deepEqual([t.v, t.dep, t.killSwitch.held], [2, tailDep(AK, log(h)), code], `${what}: the markers written since are this log's and keep the switch held`);
    const g = sdk(h); assert.match(String(call(g)), says, `${what}: an SDK guard`);
    assert.match(cli(h, ["doctor"]).out, new RegExp(`^warn {2}${says.source}`, "m"), `${what}: doctor`);
    const r = ok(h, "resume"); assert.match(r.out, /\nAgents and MCP proxies run again/, what); assert.doesNotMatch(r.out, /already off/, what);
    assert.equal(hook(h).code, 0, `${what}: one resume lifts it`); assert.equal(call(g), null, `${what}: the SDK guard started while held, without a restart`);
    const after = readMarker(h); assert.deepEqual([after.v, after.dep, after.killSwitch.killed], [2, tailDep(AK, log(h)), false], `${what}: the resume wrote a marker of this log`);
  }
  // without any marker either, nothing is left to say a kill happened: a fresh installation (the known limit of a same-user wipe)
  const h = tmp(); ok(h, "kill"); for (const f of [state(h), log(h), marker(h)]) unlinkSync(f);
  assert.equal(hook(h).code, 0);
});

test("a marker that cannot be read (no permission) is in doubt too: held, and the next entry replaces it", { skip: (process.platform === "win32" || process.getuid?.() === 0) && "file permissions do not stop this user from reading" }, () => {
  const h = tmp(); ok(h, "kill"); unlinkSync(state(h)); unlinkSync(log(h)); chmodSync(marker(h), 0o000);
  const r = hook(h); assert.equal(r.code, 2); assert.match(r.reason, INVALID);
  assert.equal(readMarker(h).killSwitch.held, "invalid", "replaced by a readable marker that keeps it held");
  assert.equal(hook(h).code, 2); ok(h, "resume"); assert.equal(hook(h).code, 0);
});

test("with the kill in the log, a marker in doubt changes nothing: the log's kill holds (an edited id, another home's id signed in, an older version's marker)", { timeout: 120000 }, () => {
  const other = otherHome();
  const cases: [string, (h: string) => void][] = [
    ["an edited id", h => { const t = readMarker(h); t.dep = "0".repeat(32); writeFileSync(marker(h), JSON.stringify(t)); }],
    ["signed for another log", h => signedFor(h, log(other))],
    ["an older version's marker", h => olderMarker(h)],
  ];
  for (const [what, doubt] of cases) {
    const h = tmp(); ok(h, "kill"); doubt(h); unlinkSync(state(h));
    const r = hook(h); assert.equal(r.code, 2, what); assert.match(r.reason, /every agent is stopped \(kill switch\)/, what);
    assert.equal(call(sdk(h)), "kill switch active", what);
    ok(h, "resume"); assert.equal(hook(h).code, 0, what);
  }
});

test("upgrade: a marker written by a version without the log's id, with a kill in force or with no state and no kill or resume in the log: every guard stops and says that a single resume lifts it; one does, and writes this log's id", { timeout: 300000 }, () => {
  // a kill in force: the log holds it, the kill holds; one resume lifts it
  let h = tmp(); ok(h, "kill"); olderMarker(h);
  let r = hook(h); assert.equal(r.code, 2); assert.match(r.reason, /every agent is stopped \(kill switch\)/);
  ok(h, "resume"); assert.equal(hook(h).code, 0, "kill in force: one resume");
  assert.deepEqual([readMarker(h).v, readMarker(h).dep], [2, tailDep(AK, log(h))]);
  // no state and no kill or resume in the log (an installation that never used the kill switch): held, in these words
  for (const record of [true, false]) {
    h = tmp(); assert.equal(hook(h).code, 0, "hooks run"); olderMarker(h, record);
    assert.ok(!existsSync(state(h)));
    r = hook(h); assert.equal(r.code, 2);
    assert.ok(r.reason.startsWith("Kytral Guard kill switch: kill switch active: the audit log's tail marker was written by an older version of Kytral Guard, so the last kill or resume is not known, every tool call is refused (fail closed): a single 'kytral-guard resume' lifts it."), r.reason);
    assert.match(cli(h, ["doctor"]).out, /^warn {2}kill switch active: the audit log's tail marker was written by an older version of Kytral Guard, .*: a single 'kytral-guard resume' lifts it/m);
    assert.equal(hook(h).code, 2, "still held at the next call");
    r = ok(h, "resume"); assert.match(r.out, /\twas=absent\t/); assert.match(r.out, /\nAgents and MCP proxies run again/); assert.doesNotMatch(r.out, /already off/);
    assert.equal(hook(h).code, 0, "no state: one resume"); assert.equal(readMarker(h).v, 2);
  }
  // the log records the last resume and kill-switch.json holds it: a resume found in the log never stands for a marker in
  // doubt, so the switch is held all the same, in the same words, until a single resume
  h = tmp(); ok(h, "kill"); ok(h, "resume"); olderMarker(h);
  r = hook(h); assert.equal(r.code, 2, "a resume in the log does not lift a marker in doubt"); assert.match(r.reason, OLDER);
  ok(h, "resume"); assert.equal(hook(h).code, 0, "the log says resumed: one resume");
  // an older version's marker that records a kill the log no longer holds (cut short): the kill is not lifted
  h = tmp(); ok(h, "kill"); ok(h, "resume"); const cut = readFileSync(log(h)).length; ok(h, "kill"); olderMarker(h);
  truncateSync(log(h), cut); unlinkSync(state(h));
  r = hook(h); assert.equal(r.code, 2); assert.match(r.reason, OLDER);
  ok(h, "resume"); assert.equal(hook(h).code, 0);
});

test("the log of another home using the same secret (a newer resume there) put in place of this one, kill-switch.json deleted: this log's marker keeps the kill", { timeout: 120000 }, () => {
  const h = tmp(), other = otherHome();
  ok(h, "kill"); ok(h, "resume"); ok(h, "kill");
  unlinkSync(state(h)); copyFileSync(log(other), log(h));
  for (let i = 0; i < 2; i++) { const r = hook(h); assert.equal(r.code, 2, `hook ${i + 1}`); assert.match(r.reason, /every agent is stopped \(kill switch\)/); }
  assert.equal(call(sdk(h)), "kill switch active");
  ok(h, "resume"); assert.equal(hook(h).code, 0);
});

test("e2e: a proxy started while the switch is held refuses every call, and the single resume reaches it without a restart", { timeout: 120000 }, async () => {
  const d = tmp(), h = join(d, "kh"), other = otherHome(); writeFileSync(join(d, "a.txt"), "a");
  ok(h, "kill"); unlinkSync(state(h)); unlinkSync(log(h)); copyFileSync(marker(other), marker(h));
  const s = proxy(d, h);
  try {
    await s.init();
    assert.ok(await s.said(FOREIGN), `said at startup: ${s.stderr.join(" / ")}`);
    assert.match(await s.ls(), /^Kytral Guard: kill switch active: the audit log's tail marker was written for another audit log/);
    ok(h, "resume");
    assert.ok(await s.said(/kill switch lifted/), "the resume reaches the running proxy");
    assert.match(await s.ls(), /a\.txt/);
  } finally { s.stop(); }
});

test("audit verify: a log and its marker renamed together (an archive) still verify, and so does a log whose marker an older version wrote: the log's id binds only the kill switch record", () => {
  const h = tmp(); ok(h, "kill"); ok(h, "resume"); hook(h);
  const archive = join(h, "audit-2026.jsonl");
  renameSync(log(h), archive); renameSync(marker(h), auditTailPath(archive));
  let r = cli(h, ["audit", "verify", archive]);
  assert.equal(r.code, 0, r.out + r.err); assert.match(r.out, /OK: nothing modified, deleted, reordered or truncated \(tail marker: seq \d+\)/);
  const o = tmp(); ok(o, "kill"); olderMarker(o);
  r = cli(o, ["audit", "verify"]); assert.equal(r.code, 0, r.out + r.err);
});
