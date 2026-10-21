// The kill switch's generation floor comes from the audit log, read as a stream: 1 MB at a time, whatever the size of the log
// (a log read into one string failed past about 512 MB, and the floor was then silently lost: `resume` wrote generation 1,
// exit 0). A log that exists but cannot be read refuses `resume`: exit 1, nothing written, the floor kept for when it can be
// read again. It never refuses `kill`: the kill is written all the same, one generation after the highest known without the
// log (the last kill or resume its signed tail marker records, else kill-switch.json's), with a warning and exit code 3.
import { test } from "node:test"; import assert from "node:assert/strict";
import { constants } from "node:buffer";
import { spawnSync } from "node:child_process";
import { chmodSync, closeSync, copyFileSync, existsSync, ftruncateSync, mkdirSync, mkdtempSync, openSync, readFileSync, statSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path";
import { AuditLog, auditKey, auditTailPath, eachLine, findEntries, lastSwitch, MAX_ENTRY_LINE } from "../src/audit.js";
import { engageKillSwitch, KillSwitch, killSwitchKey, releaseKillSwitch } from "../src/kill-switch.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "7d2e9a4c1f8b3e6d0a5c2f9e4b7a1d8c3f6e0b9a2d5c8f1e4a7b0d3c6f9e2a5b";
const tmp = () => mkdtempSync(join(tmpdir(), "kg-journal-"));
const HINT = '"agentId":"*"';
/** A home with a history: kill, resume... seven times (generation 7, a kill), journaled with the key in `log`. */
function history(h: string, log = join(h, "audit.jsonl")) {
  const audit = new AuditLog(log, { key: auditKey(S) }), path = join(h, "kill-switch.json");
  for (let i = 1; i <= 7; i++) {
    const r = i % 2 ? engageKillSwitch("qa", { path, audit, key: killSwitchKey(S) }) : releaseKillSwitch(S, "qa", { path, audit });
    assert.equal((r.state as { gen: number }).gen, i);
  }
  return { log, path };
}
function cli(home: string, args: string[], env: Record<string, string> = {}, input = "") {
  const e: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: home, KYTRAL_SECRET: S, ...env };
  for (const k of ["KYTRAL_AUDIT", "KYTRAL_AUDIT_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS"]) if (!(k in env)) delete e[k];
  const r = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...args], { cwd: ROOT, env: e as NodeJS.ProcessEnv, encoding: "utf8", input });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
/** An agent hook run from the CLI, as Claude Code runs it, for `ls`: exit 0 allowed, 2 refused. */
const hook = (home: string) => cli(home, ["hook", "claude-code"], {}, JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, cwd: tmpdir(), session_id: "s" }));
const reason = (r: { out: string }) => JSON.parse(r.out).hookSpecificOutput.permissionDecisionReason as string;
const gen = (r: { state: object }) => (r.state as { gen: number }).gen;

test("eachLine / findEntries: lines across the 1 MB pieces, the hint itself cut in two, lines too long to be an entry, no final newline: the same entries as reading the file whole", () => {
  const f = join(tmp(), "log.jsonl"), MB = 1 << 20;
  const pad = (n: number) => `{"pad":"${"x".repeat(n - 10)}"}`;   // a line of n bytes
  const parts: string[] = [];
  // a hint line whose hint starts 5 bytes before the end of the first piece (the line starts 6 bytes before it)
  parts.push(pad(MB - 6 - 1), `{"agentId":"*","n":1}`);
  // lines of every size around the next pieces, a third holding the hint
  for (let i = 0; i < 1200; i++) parts.push(i % 3 ? `{"agentId":"a","n":${i},"p":"${"y".repeat((i * 7919) % 9000)}"}` : `{"agentId":"*","n":${i},"p":"${"z".repeat((i * 104729) % 9000)}"}`);
  parts.push("", "not json \"agentId\":\"*\"", `[${HINT.length}, "agentId", "*"]`, `{"agentId":"*","n":"crlf"}\r`, `[{"agentId":"*"}]`);
  parts.push(`{"agentId":"*","long":"${"w".repeat(MAX_ENTRY_LINE)}"}`);   // longer than an entry can be: skipped
  parts.push(`{"agentId":"*","n":"last, no newline"}`);
  const text = parts.join("\n");
  writeFileSync(f, text);
  assert.ok(Buffer.byteLength(text) > MAX_ENTRY_LINE + 3 * MB);
  for (const hint of [HINT, ""]) {
    const want = text.split("\n").filter(l => l.includes(hint) && Buffer.byteLength(l) <= MAX_ENTRY_LINE)
      .flatMap(l => { try { const e = JSON.parse(l); return e && typeof e === "object" ? [e] : []; } catch { return []; } });
    const got = findEntries(f, () => true, hint);
    assert.equal(got.length, want.length, `hint ${JSON.stringify(hint)}`); assert.deepEqual(got, want, `hint ${JSON.stringify(hint)}`);
  }
  assert.equal(findEntries(f, e => (e as { n?: unknown }).n === 1, HINT).length, 1, "the hint cut by the end of the first piece");
  let lines = 0; eachLine(f, () => { lines++; }); assert.equal(lines, parts.length - 1, "every line but the long one");
  // a missing file has no entry; one that cannot be read throws (it used to read as an empty log)
  assert.deepEqual(findEntries(join(tmp(), "none.jsonl"), () => true), []);
  assert.throws(() => findEntries(tmp(), () => true), (e: NodeJS.ErrnoException) => typeof e.code === "string");
});

test("a journal larger than a string can be (> 512 MB): resume and kill continue from its generation floor, in this process and from the CLI", (t) => {
  if (process.platform === "win32") return t.skip("NTFS keeps a hole only with a sparse flag: the file would be written whole");
  const h = tmp(), small = history(h, join(h, "small.jsonl")), log = join(h, "audit.jsonl"), HOLE = 600 * 2 ** 20;
  // 600 MB that are no entry (a hole: nothing is written to the disk), then the real history
  const fd = openSync(log, "w");
  try { ftruncateSync(fd, HOLE); const rest = Buffer.concat([Buffer.from("\n"), readFileSync(small.log)]); writeSync(fd, rest, 0, rest.length, HOLE); } finally { closeSync(fd); }
  copyFileSync(`${small.log}.tail`, `${log}.tail`);
  try {
    if (statSync(log).blocks * 512 > 64 * 2 ** 20) return t.skip("this file system does not keep holes");
    assert.ok(statSync(log).size > constants.MAX_STRING_LENGTH, "the log is larger than the largest string");
    unlinkSync(small.path);   // kill-switch.json deleted: only the journal knows the generation (7)
    const audit = () => new AuditLog(log, { key: auditKey(S) });
    assert.equal((releaseKillSwitch(S, "qa", { path: small.path, audit: audit() }).state as { gen: number }).gen, 8, "the floor was read");
    unlinkSync(small.path);
    assert.equal((engageKillSwitch("qa", { path: small.path, audit: audit(), key: killSwitchKey(S) }).state as { gen: number }).gen, 9);
    // the CLI reads the default log of its KYTRAL_HOME
    unlinkSync(small.path);
    const r = cli(h, ["resume", "--by", "qa"]);
    assert.equal(r.code, 0, r.err); assert.match(r.out, /^kill switch OFF\t.*\tgeneration=10\t/m);
    unlinkSync(small.path);
    const k = cli(h, ["kill", "--by", "qa"]);
    assert.equal(k.code, 0, k.err); assert.match(k.out, /^kill switch ON\t.*\tgeneration=11\t/m);
  } finally { unlinkSync(log); }
});

test("a journal that cannot be read (an I/O error, the append still working): resume refuses, nothing is written; kill is written all the same, one after the highest generation known without the log (tail marker, file, lines read before the error), with a warning; the floor is kept for later", () => {
  class Unreadable extends AuditLog { each(): void { throw Object.assign(new Error("EIO: i/o error, read"), { code: "EIO" }); } }
  const h = tmp(), { log, path } = history(h), before = readFileSync(log), kill = readFileSync(path);
  const unreadable = () => new Unreadable(log, { key: auditKey(S) });
  const engage = () => engageKillSwitch("qa", { path, audit: unreadable(), key: killSwitchKey(S) });
  const WHY = "the audit log cannot be read (EIO): the kill was written all the same";
  const UNTIL = "Make the log readable: 'kytral-guard resume' is refused until then";
  const running = new KillSwitch(path, killSwitchKey(S));   // a guard that saw the kill of generation 7
  assert.equal(running.check(), "kill switch active");
  // resume: the file in place (the kill, generation 7), then deleted (the journal alone knows the generation)
  for (const deleted of [false, true]) {
    if (deleted) unlinkSync(path);
    assert.throws(() => releaseKillSwitch(S, "qa", { path, audit: unreadable() }), /^Error: resume refused: the audit log cannot be read \(EIO\) .*nothing was written.*the kill switch is unchanged/);
    assert.deepEqual(readFileSync(log), before, "nothing journaled");
    if (deleted) assert.ok(!existsSync(path), "no state written"); else assert.deepEqual(readFileSync(path), kill, "the kill in force is unchanged");
  }
  // kill, kill-switch.json deleted: one after the last kill or resume the tail marker records (7); journaled (the append works)
  const k = engage();
  assert.equal(gen(k), 8); assert.equal(JSON.parse(readFileSync(path, "utf8")).killed, true);
  assert.deepEqual(k.warnings, [`${WHY}, at generation 8, one after the highest generation known without the log (tail marker: 7, kill-switch.json: none). ${UNTIL}`]);
  assert.equal(lastSwitch(log, auditKey(S))?.gen, 8, "journaled, and recorded in the marker");
  assert.equal(running.check(), "kill switch active");
  // no tail marker: one after kill-switch.json's generation (8)
  unlinkSync(auditTailPath(log));
  const k2 = engage();
  assert.equal(gen(k2), 9);
  assert.deepEqual(k2.warnings, [`${WHY}, at generation 9, one after the highest generation known without the log (tail marker: none, kill-switch.json: 8); the log may hold a higher one: running guards that saw it take this kill for a replay, which blocks every call too. ${UNTIL}`]);
  assert.equal(running.check(), "kill switch active");
  // no marker and no file: generation 1. A guard that saw a newer one takes it for a replay, which blocks too; a guard started now stops
  unlinkSync(auditTailPath(log)); unlinkSync(path);
  const k3 = engage();
  assert.equal(gen(k3), 1); assert.match(k3.warnings![0], /at generation 1, .*\(tail marker: none, kill-switch\.json: none\); the log may hold a higher one/);
  assert.match(running.check()!, /^kill switch active: kill-switch\.json holds a replayed kill \(generation 1, not newer than 9\), every tool call is refused \(fail closed\)$/);
  assert.equal(new KillSwitch(path, killSwitchKey(S)).check(), "kill switch active");
  // an I/O error in the middle of the log (at the kill of generation 9): the lines read before it count (up to 8)
  class Broken extends AuditLog {
    each(visit: Parameters<AuditLog["each"]>[0], hint?: string): void {
      super.each(e => { if (e.generation === 9) throw Object.assign(new Error("EIO: i/o error, read"), { code: "EIO" }); visit(e); }, hint);
    }
  }
  unlinkSync(auditTailPath(log)); unlinkSync(path);
  const k4 = engageKillSwitch("qa", { path, audit: new Broken(log, { key: auditKey(S) }), key: killSwitchKey(S) });
  assert.equal(gen(k4), 9); assert.match(k4.warnings![0], /at generation 9, .*\(tail marker: none, kill-switch\.json: none, lines read before the error: 8\); the log may hold a higher one/);
  // once it can be read: the generation goes on from the journal's floor (9)
  assert.equal(gen(releaseKillSwitch(S, "qa", { path, audit: new AuditLog(log, { key: auditKey(S) }) })), 10);
});

test("a tail marker built so that it cannot be checked (JSON nested too deep to be signed again) never stops a kill: written from the log's floor, with a warning (it cannot be journaled); resume refuses", () => {
  const h = tmp(), { log, path } = history(h), audit = () => new AuditLog(log, { key: auditKey(S) });
  writeFileSync(auditTailPath(log), `{"v":1,"seq":1,"link":"x","d":${"[".repeat(100_000)}${"]".repeat(100_000)}}`);
  const kill = readFileSync(path);
  assert.throws(() => releaseKillSwitch(S, "qa", { path, audit: audit() }), /^Error: resume refused: the audit log cannot be read \(error\) .*nothing was written/);
  assert.deepEqual(readFileSync(path), kill, "resume: nothing written");
  const k = engageKillSwitch("qa", { path, audit: audit(), key: killSwitchKey(S) });
  assert.equal(gen(k), 8, "one after the log's floor (7)"); assert.equal(JSON.parse(readFileSync(path, "utf8")).killed, true);
  assert.equal(k.warnings?.length, 1); assert.match(k.warnings![0], /^kill switch ON, but the kill could not be journaled: /);
});

test("CLI, a folder in place of the journal: resume refuses (exit 1, nothing written); kill is written all the same (exit 3, a warning on stderr)", () => {
  const h = tmp(), dir = join(h, "a-folder"), path = join(h, "kill-switch.json");
  mkdirSync(dir);
  const r = cli(h, ["resume"], { KYTRAL_AUDIT: dir });
  assert.equal(r.code, 1, r.out + r.err); assert.equal(r.out, "");
  assert.match(r.err, /^kytral-guard: resume refused: the audit log cannot be read \((EISDIR|EPERM|EACCES)\) .*nothing was written.*the kill switch is unchanged/);
  assert.ok(!existsSync(path), "resume: no state written");
  // no marker (a folder has none) and no file: generation 1; the kill cannot be journaled either
  const k = cli(h, ["kill", "--by", "qa"], { KYTRAL_AUDIT: dir });
  assert.equal(k.code, 3, k.out + k.err); assert.match(k.out, /^kill switch ON\tby=qa \(os:[^)]+\)\t.*\tgeneration=1\t/m);
  assert.match(k.out, /now refuses tool calls/);
  assert.match(k.err, /^kytral-guard: warning: the audit log cannot be read \((EISDIR|EPERM|EACCES)\): the kill was written all the same, at generation 1, .*\(tail marker: none, kill-switch\.json: none\); the log may hold a higher one/m);
  assert.match(k.err, /^kytral-guard: warning: kill switch ON, but the kill could not be journaled: /m);
  assert.equal(JSON.parse(readFileSync(path, "utf8")).killed, true);
  assert.equal(cli(h, ["resume"], { KYTRAL_AUDIT: dir }).code, 1, "resume still refused");
});

test("CLI, a journal without permission: resume refuses (exit 1, nothing written); kill is written all the same (exit 3), one after the tail marker's generation, or at 1 with no marker and no file; hooks stay stopped; the floor afterwards", (t) => {
  if (process.platform === "win32" || process.getuid?.() === 0) return t.skip("file permissions do not stop this user from reading");
  const h = tmp(), { log, path } = history(h), unreadable = (f: () => void) => { chmodSync(log, 0o000); try { f(); } finally { chmodSync(log, 0o600); } };
  assert.equal(cli(h, ["resume"]).code, 0); assert.equal(hook(h).code, 0);   // generation 8, a resume: hooks run
  unlinkSync(path);
  unreadable(() => {
    const r = cli(h, ["resume"]);
    assert.equal(r.code, 1, r.out + r.err); assert.equal(r.out, ""); assert.match(r.err, /^kytral-guard: resume refused: the audit log cannot be read \(EACCES\) .*nothing was written/);
    assert.ok(!existsSync(path), "resume: no state written");
    // the tail marker can be read: it records the resume of generation 8
    const k = cli(h, ["kill"]);
    assert.equal(k.code, 3, k.out + k.err); assert.match(k.out, /^kill switch ON\t.*\twas=absent\tgeneration=9\t/m);
    assert.match(k.err, /^kytral-guard: warning: the audit log cannot be read \(EACCES\): the kill was written all the same, at generation 9, one after the highest generation known without the log \(tail marker: 8, kill-switch\.json: none\)\. Make the log readable: 'kytral-guard resume' is refused until then$/m);
    assert.match(k.err, /^kytral-guard: warning: kill switch ON, but the kill could not be journaled: EACCES/m);
    assert.equal(hook(h).code, 2, "a hook refuses while the log cannot be read (fail closed)");
    assert.equal(cli(h, ["resume"]).code, 1, "resume still refused");
  });
  // the log readable again: hooks stop at the kill (newer than the journal's resume), resume lifts it from the floor
  let r = hook(h);
  assert.equal(r.code, 2, r.out + r.err); assert.match(reason(r), /every agent is stopped \(kill switch\)/);
  r = cli(h, ["resume"]);
  assert.equal(r.code, 0, r.err); assert.match(r.out, /\twas=on by .*\tgeneration=10\t/);
  assert.equal(hook(h).code, 0);
  // no marker and no file: generation 1; hooks, which start from the journal's resume (10), take it for a replay: refused too
  unlinkSync(auditTailPath(log)); unlinkSync(path);
  unreadable(() => {
    const k = cli(h, ["kill"]);
    assert.equal(k.code, 3, k.out + k.err); assert.match(k.out, /\tgeneration=1\t/);
    assert.match(k.err, /at generation 1, .*\(tail marker: none, kill-switch\.json: none\); the log may hold a higher one/);
  });
  r = hook(h);
  assert.equal(r.code, 2, r.out + r.err); assert.match(reason(r), /holds a replayed kill \(generation 1, not newer than 10\)/);
  r = cli(h, ["resume"]);
  assert.equal(r.code, 0, r.err); assert.match(r.out, /\tgeneration=11\t/, "the floor (10) was kept");
  assert.equal(hook(h).code, 0);
});
