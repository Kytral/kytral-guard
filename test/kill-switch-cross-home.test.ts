// No artifact of another KYTRAL_HOME that uses the same secret lifts a kill here: kill-switch.json, the audit log and its tail
// marker, copied in alone or together, with or without deleting this home's own, the secret file, or kill and resume lines
// copied into this log. Kills and resumes sign the id of the log they are journaled in (an HMAC of its real path, as its tail
// marker does): another log's are never this log's, and neither marker nor log in doubt is ever taken for a resume. Only
// deleting all three files of this home lifts a kill (a fresh home: the known limit of a same-home wipe). An older version's
// log (kills and resumes without the log's id, a marker without it) holds every call until a single resume, which writes
// both in the new format.
import { test } from "node:test"; import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { spawnSync } from "node:child_process";
import { appendFileSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path";
import { AuditLog, auditKey, auditTailPath, tailDep, verifyAuditFile } from "../src/audit.js";
import { canonicalJson } from "../src/confirm-queue.js";
import { engageKillSwitch, killSwitchKey, releaseKillSwitch } from "../src/kill-switch.js";
import { DEFAULT_POLICY, Guard, issueBadge, loadPolicy } from "../src/index.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "7c1e9a4f2b8d6035e9c2a7f4b1d8e6035c9a2f7e4b1d8c6a3f9e2b7d4a1c8f5e", AUD = "kytral-guard:cross-home-test";
const AK = auditKey(S), KK = killSwitchKey(S);
const tmp = () => mkdtempSync(join(tmpdir(), "kg-cross-home-"));
const FILES = { state: "kill-switch.json", log: "audit.jsonl", marker: "audit.jsonl.tail" } as const;
type File = keyof typeof FILES;
const ALL = Object.keys(FILES) as File[];
const at = (h: string, f: File) => join(h, FILES[f]);
const journal = (h: string, key = AK) => new AuditLog(at(h, "log"), { key });
const kill = (h: string) => engageKillSwitch("ops", { path: at(h, "state"), audit: journal(h), key: KK });
const resume = (h: string) => releaseKillSwitch(S, "ops", { path: at(h, "state"), audit: journal(h) });
const lines = (h: string) => readFileSync(at(h, "log"), "utf8").split("\n").filter(Boolean);

function cli(h: string, args: string[], o: { input?: string; secret?: string | null } = {}) {
  const env: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_SECRET: o.secret === null ? undefined : o.secret ?? S };
  for (const k of ["KYTRAL_AUDIT", "KYTRAL_AUDIT_SECRET", "KYTRAL_SECRET_FILE", "KYTRAL_POLICY", "KYTRAL_PLUGINS"]) delete env[k];
  if (env.KYTRAL_SECRET === undefined) delete env.KYTRAL_SECRET;
  const r = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...args], { cwd: ROOT, env: env as NodeJS.ProcessEnv, encoding: "utf8", input: o.input ?? "" });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
/** An agent hook as Claude Code runs it, for `ls`: its exit code (0 allowed, 2 refused) and the reason its agent reads. */
function hook(h: string, secret?: string | null) {
  const r = cli(h, ["hook", "claude-code"], { secret, input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, cwd: tmpdir(), session_id: "s" }) });
  return { code: r.code, reason: r.out.trim() ? String(JSON.parse(r.out).hookSpecificOutput?.permissionDecisionReason) : "" };
}
/** A new SDK guard of the home `h` (its kill-switch.json and its audit log), as an MCP proxy builds one. */
const sdk = (h: string) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD, revocationFile: null, nonceFile: null,
  knownToolsFile: null, killSwitchFile: at(h, "state"), audit: journal(h) });
/** One call through the SDK guard `g`: null when it goes through, else why it is refused. */
const call = (g: Guard) => { try { g.checkSync(issueBadge(S, "agent-a", ["*"], 600, Date.now(), { aud: AUD }), { tool: "read_file", args: {} }); return null; } catch (e) { return (e as Error).message; } };
/** This home: killed at generation 3 (kill, resume, kill). */
const ours = (d: string, name = "ours") => { const h = join(d, name); kill(h); resume(h); kill(h); return h; };
/** Another home with the same secret whose last change is a resume: at generation 10 (above ours), or 2 (below). */
function theirs(d: string, gen: 10 | 2) { const h = join(d, `theirs-${gen}`); for (let i = 0; i < gen / 2; i++) { kill(h); resume(h); } return h; }
/** Every subset of `files`. */
const subsets = (files: File[]): File[][] => files.reduce<File[][]>((all, f) => [...all, ...all.map(s => [...s, f])], [[]]);

test("a kill or resume signs the id of the log it is journaled in, inside its MAC, and the log still verifies", () => {
  const h = ours(tmp());
  const switches = lines(h).map(l => JSON.parse(l)).filter(e => e.decision === "kill" || e.decision === "resume");
  assert.equal(switches.length, 3);
  for (const e of switches) assert.equal(e.dep, tailDep(AK, at(h, "log")), "the log's id");
  assert.equal(JSON.parse(readFileSync(at(h, "marker"), "utf8")).dep, tailDep(AK, at(h, "log")), "the same id as its marker's");
  assert.equal(verifyAuditFile(at(h, "log"), AK).exitCode, 0);
  // the id is covered by the MAC: put another log's id in, and the log no longer verifies
  const all = lines(h), i = all.findIndex(l => l.includes('"decision":"resume"')), e = JSON.parse(all[i]);
  all[i] = JSON.stringify({ ...e, dep: tailDep(AK, join(h, "elsewhere.jsonl")) }); writeFileSync(at(h, "log"), all.join("\n") + "\n");
  const r = verifyAuditFile(at(h, "log"), AK); assert.equal(r.exitCode, 1); assert.equal(r.broken?.line, i + 1);
});

test("every combination of kill-switch.json, the audit log and its marker copied from another home with the same secret (a newer or an older resume there), with or without deleting this home's others: hooks and new SDK guards stay stopped; one resume lifts it, for a guard already running too", { timeout: 300000 }, () => {
  const d = tmp(), homes = [theirs(d, 10), theirs(d, 2)];
  let n = 0;
  for (const other of homes) for (const copied of subsets(ALL).filter(s => s.length)) for (const deleted of subsets(ALL.filter(f => !copied.includes(f)))) {
    const what = `from ${other.slice(d.length + 1)}: copied ${copied.join("+")}${deleted.length ? `, deleted ${deleted.join("+")}` : ""}`;
    const h = ours(d, `ours-${++n}`);
    for (const f of copied) copyFileSync(at(other, f), at(h, f));
    for (const f of deleted) unlinkSync(at(h, f));
    const r = hook(h); assert.equal(r.code, 2, `${what}: a hook`); assert.match(r.reason, /kill switch/, what);
    // started after the hook journaled its refusal (a new entry, a new marker): the switch stays stopped
    const running = sdk(h); assert.match(String(call(running)), /^kill switch active/, `${what}: a new SDK guard`);
    resume(h);
    assert.equal(hook(h).code, 0, `${what}: one resume lifts it`); assert.equal(call(sdk(h)), null, `${what}: one resume lifts it for SDK guards`);
    assert.equal(call(running), null, `${what}: and for the SDK guard already running`);
  }
  assert.equal(n, 38);
});

test("this home's own files, some of them deleted after a kill: whatever is left keeps it; all three deleted is a fresh home (the known limit of a same-home wipe)", { timeout: 120000 }, () => {
  const d = tmp(); let n = 0;
  for (const deleted of subsets(ALL).filter(s => s.length && s.length < ALL.length)) {
    const h = ours(d, `ours-${++n}`);
    for (const f of deleted) unlinkSync(at(h, f));
    assert.equal(hook(h).code, 2, `deleted ${deleted.join("+")}`);
  }
  const h = ours(d, "wiped"); for (const f of ALL) unlinkSync(at(h, f));
  assert.equal(hook(h).code, 0, "nothing is left to say a kill happened");
});

test("kill and resume lines of another log copied into this one, at the end or in the middle, with or without its marker: never this log's", { timeout: 120000 }, () => {
  const d = tmp(), other = theirs(d, 10);
  const foreign = lines(other).filter(l => /"decision":"(kill|resume)"/.test(l));
  const cases: [string, (h: string) => void][] = [
    ["appended at the end, this marker kept", h => appendFileSync(at(h, "log"), foreign.join("\n") + "\n")],
    ["appended at the end, this marker deleted", h => { appendFileSync(at(h, "log"), foreign.join("\n") + "\n"); unlinkSync(at(h, "marker")); }],
    ["in the middle, this marker deleted", h => { const l = lines(h); l.splice(2, 0, ...foreign); writeFileSync(at(h, "log"), l.join("\n") + "\n"); unlinkSync(at(h, "marker")); }],
    ["at the end, with the other home's marker", h => { appendFileSync(at(h, "log"), foreign.join("\n") + "\n"); copyFileSync(at(other, "marker"), at(h, "marker")); }],
  ];
  for (const [what, splice] of cases) {
    const h = ours(d, `ours-${what.replace(/\W+/g, "-")}`);
    splice(h); unlinkSync(at(h, "state"));
    assert.equal(hook(h).code, 2, what); assert.match(String(call(sdk(h))), /^kill switch active/, what);
  }
  // this home resumed: another log's newer kill or resume in it holds every call (a doubt), until a single resume
  const h = join(d, "resumed"); kill(h); resume(h);
  appendFileSync(at(h, "log"), foreign.join("\n") + "\n"); unlinkSync(at(h, "marker"));
  const r = hook(h); assert.equal(r.code, 2);
  assert.match(r.reason, /the audit log holds a kill or resume written for another audit log \(another KYTRAL_HOME using the same secret, or this one through another path\), so the last kill or resume is not known, every tool call is refused \(fail closed\): a single 'kytral-guard resume' lifts it/);
  resume(h); assert.equal(hook(h).code, 0);
});

test("the secret file of another home (another secret), alone or with that home's kill-switch.json, log and marker: hooks stay stopped", { timeout: 120000 }, () => {
  const d = tmp(), T = "e3b1f7a9c5d2084b6f1e3a9c7d5b2f8064e1c3a5f9b7d2e8c4a6f0b3d1e9c7a5";
  const other = join(d, "theirs"); mkdirSync(other); writeFileSync(join(other, "secret"), T + "\n", { mode: 0o600 });
  for (let i = 0; i < 6; i++) assert.equal(cli(other, [i % 2 ? "resume" : "kill"], { secret: null }).code, 0);   // resumed, generation 6
  for (const withFiles of [false, true]) {
    const h = join(d, `ours-${withFiles}`); mkdirSync(h); writeFileSync(join(h, "secret"), S + "\n", { mode: 0o600 });
    for (const step of ["kill", "resume", "kill"]) assert.equal(cli(h, [step], { secret: null }).code, 0, step);
    copyFileSync(join(other, "secret"), join(h, "secret"));
    if (withFiles) for (const f of ALL) copyFileSync(at(other, f), at(h, f));
    assert.equal(hook(h, null).code, 2, withFiles ? "their secret and their files" : "their secret");
  }
});

/**
 * Rewrites the log of `h` as the last published version wrote it: kill and resume entries without the log's id, the chain
 * linked and signed again with the same key, and a tail marker v1 without the log's id nor a record (or none at all).
 */
function asOlderVersion(h: string, marker = true) {
  let prev = "GENESIS"; const out: string[] = [];
  for (const line of lines(h)) {
    const { hash: _h, mac: _m, dep: _d, ...rest } = JSON.parse(line), body = { ...rest, prev };
    const hashed = { ...body, hash: createHash("sha256").update(JSON.stringify(body)).digest("hex") };
    const full = { ...hashed, mac: createHmac("sha256", AK).update(prev).update(canonicalJson(hashed)).digest("hex") };
    out.push(JSON.stringify(full)); prev = full.mac;
  }
  writeFileSync(at(h, "log"), out.join("\n") + "\n");
  const last = JSON.parse(out.at(-1)!), t = { v: 1, seq: last.seq, link: last.mac, at: new Date().toISOString() };
  if (marker) writeFileSync(auditTailPath(at(h, "log")), JSON.stringify({ ...t, mac: createHmac("sha256", AK).update(`audit-tail\n${canonicalJson(t)}`).digest("hex") }));
  else unlinkSync(auditTailPath(at(h, "log")));
  assert.ok(!lines(h).some(l => l.includes('"dep"')), "no log id left");
  assert.equal(verifyAuditFile(at(h, "log"), AK).exitCode, marker ? 0 : 1, "the older version's log verifies as it did");
}
const OLDER = /^Kytral Guard kill switch: kill switch active: the audit log's tail marker was written by an older version of Kytral Guard, so the last kill or resume is not known, every tool call is refused \(fail closed\): a single 'kytral-guard resume' lifts it\./;
const OLDER_ENTRY = /^Kytral Guard kill switch: kill switch active: the audit log holds a kill or resume written by an older version of Kytral Guard, so the last kill or resume is not known, every tool call is refused \(fail closed\): a single 'kytral-guard resume' lifts it\./;

test("upgrade: a log whose kills and resumes an older version wrote (without the log's id) holds every hook and SDK guard, a kill or a resume in force alike, with kill-switch.json kept or deleted, in words that say a single resume lifts it; one does, for a guard already running too, and writes the new format", { timeout: 300000 }, () => {
  const cases: [string, (h: string) => void, RegExp][] = [
    ["a kill in force", h => { kill(h); resume(h); kill(h); asOlderVersion(h); }, OLDER],
    ["a kill in force, kill-switch.json deleted", h => { kill(h); resume(h); kill(h); asOlderVersion(h); unlinkSync(at(h, "state")); }, OLDER],
    ["resumed (the log's last change is a resume)", h => { kill(h); resume(h); asOlderVersion(h); }, OLDER],
    ["a kill in force, no marker", h => { kill(h); resume(h); kill(h); asOlderVersion(h, false); }, OLDER_ENTRY],
  ];
  for (const [what, older, says] of cases) {
    const h = tmp(); older(h);
    const r = hook(h); assert.equal(r.code, 2, what); assert.match(r.reason, says, what);
    const g = sdk(h); assert.match(String(call(g)), /^kill switch active: the audit log/, `${what}: an SDK guard`);
    assert.equal(hook(h).code, 2, `${what}: still held at the next call`);
    const up = cli(h, ["resume"]); assert.equal(up.code, 0, up.out + up.err); assert.match(up.out, /\nAgents and MCP proxies run again/, what);
    assert.equal(hook(h).code, 0, `${what}: one resume lifts it`);
    assert.equal(call(g), null, `${what}: the SDK guard started while held, without a restart`);
    const e = lines(h).map(l => JSON.parse(l)).filter(x => x.decision === "resume").at(-1), t = JSON.parse(readFileSync(at(h, "marker"), "utf8"));
    assert.equal(e.dep, tailDep(AK, at(h, "log")), `${what}: the resume is journaled in the new format`);
    assert.deepEqual([t.v, t.dep, t.killSwitch.killed, t.killSwitch.gen], [2, tailDep(AK, at(h, "log")), false, e.generation], `${what}: and so is the marker`);
    // from then on, as usual
    assert.equal(cli(h, ["kill"]).code, 0); assert.equal(hook(h).code, 2, `${what}: a kill`);
    assert.equal(cli(h, ["resume"]).code, 0); assert.equal(hook(h).code, 0, `${what}: a resume`);
  }
});
