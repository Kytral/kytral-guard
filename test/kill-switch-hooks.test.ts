// Agent hooks run as a new process at each tool call, with no memory of the kill switch states seen before. They start from
// the last kill or resume the audit log records, which its signed tail marker carries (two small reads at each call), so that
// kill-switch.json deleted, or an older signed resume put back, no longer lifts a kill for hooks (the restart cases, at
// every call). The marker is believed only while it certifies the log as it is; otherwise the log itself is read.
// What is left: rolling back the log, its marker and kill-switch.json together (it needs an anchor off the machine).
import { test } from "node:test"; import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, truncateSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path";
import { AuditLog, auditKey, auditTailPath, lastSwitch } from "../src/audit.js";
import { canonicalJson } from "../src/confirm-queue.js";
import { engageKillSwitch, killSwitchKey, releaseKillSwitch } from "../src/kill-switch.js";
import { runHook } from "../src/hooks.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "3b8f1d6a9c2e5b7d0f4a8c1e6b9d2f5a7c0e3b6d9f1a4c7e2b5d8f0a3c6e9b1d";
const tmp = () => mkdtempSync(join(tmpdir(), "kg-ks-hooks-"));
const event = (command: string) => JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, cwd: "/tmp", session_id: "s" });
/** A home, its journal and a hook run as an agent runs it: a new guard for every call. */
function home() {
  const h = tmp(), ks = join(h, "kill-switch.json"), log = join(h, "audit.jsonl");
  const audit = () => new AuditLog(log, { key: auditKey(S) });
  const kill = () => engageKillSwitch("ops", { path: ks, audit: audit(), key: killSwitchKey(S) });
  const resume = () => releaseKillSwitch(S, "ops", { path: ks, audit: audit() });
  const hook = (command = "ls") => runHook("claude-code", event(command), { secret: S, audit: audit(), killSwitchFile: ks, preset: "coding-agent" });
  return { h, ks, log, kill, resume, hook };
}
const reason = (r: { stdout: string }) => JSON.parse(r.stdout).hookSpecificOutput.permissionDecisionReason as string;
function cli(h: string, args: string[], input = "") {
  const env: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_SECRET: S };
  for (const k of ["KYTRAL_AUDIT", "KYTRAL_AUDIT_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS"]) delete env[k];
  const r = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...args], { cwd: ROOT, env: env as NodeJS.ProcessEnv, encoding: "utf8", input });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test("hooks: kill-switch.json deleted after a kill no longer lifts it; resume does", () => {
  const m = home();
  assert.equal(m.hook().exitCode, 0);
  m.kill(); assert.equal(m.hook().exitCode, 2);
  unlinkSync(m.ks);
  for (let i = 0; i < 3; i++) { const r = m.hook(); assert.equal(r.exitCode, 2, "the deleted kill still stops the hook"); assert.match(reason(r), /every agent is stopped \(kill switch\)/); }
  m.resume(); assert.equal(m.hook().exitCode, 0, "a resume lifts it");
});

test("hooks: an older signed resume put back over a kill no longer lifts it; resume does", () => {
  const m = home();
  m.kill(); m.resume(); const old = readFileSync(m.ks);   // resume, generation 2
  m.kill(); m.resume(); m.kill();                          // kill, generation 5
  writeFileSync(m.ks, old);
  const r = m.hook();
  assert.equal(r.exitCode, 2); assert.match(reason(r), /holds a replayed resume \(generation 2, not newer than 5\)/);
  m.resume(); assert.equal(m.hook().exitCode, 0);
});

test("CLI: kill then rm kill-switch.json, and kill then an old resume put back: the hook still refuses; resume lifts it", () => {
  const h = tmp(), ks = join(h, "kill-switch.json"), hook = () => cli(h, ["hook", "claude-code"], event("ls"));
  assert.equal(cli(h, ["kill", "--by", "ops"]).code, 0);
  assert.equal(hook().code, 2);
  unlinkSync(ks);
  assert.equal(hook().code, 2, "the file deleted, the hook still refuses");
  assert.equal(cli(h, ["resume", "--by", "ops"]).code, 0); assert.equal(hook().code, 0);
  const old = readFileSync(ks);
  assert.equal(cli(h, ["kill", "--by", "ops"]).code, 0); assert.equal(cli(h, ["resume"]).code, 0); assert.equal(cli(h, ["kill"]).code, 0);
  writeFileSync(ks, old);
  const r = hook();
  assert.equal(r.code, 2, "an older resume put back, the hook still refuses"); assert.match(JSON.parse(r.out).hookSpecificOutput.permissionDecisionReason, /replayed resume/);
  assert.equal(cli(h, ["resume"]).code, 0); assert.equal(hook().code, 0);
});

test("the marker records the last kill or resume, signed, and carries it over every entry appended after it", () => {
  const m = home();
  assert.equal(lastSwitch(m.log, auditKey(S)), null);
  const k = m.kill(), t1 = JSON.parse(readFileSync(auditTailPath(m.log), "utf8"));
  assert.deepEqual(t1.killSwitch, { killed: true, gen: 1, state: lastSwitch(m.log, auditKey(S))!.state });
  for (let i = 0; i < 3; i++) m.hook();   // refused calls, journaled: the marker moves and keeps the kill
  const t2 = JSON.parse(readFileSync(auditTailPath(m.log), "utf8"));
  assert.ok(t2.seq > t1.seq); assert.deepEqual(t2.killSwitch, t1.killSwitch);
  assert.equal((k.state as { gen: number }).gen, 1);
  m.resume(); assert.deepEqual(lastSwitch(m.log, auditKey(S)), { ...t1.killSwitch, killed: false, gen: 2, state: lastSwitch(m.log, auditKey(S))!.state });
  assert.deepEqual(lastSwitch(m.log, auditKey("9".repeat(8) + S.slice(8))), { held: "invalid", gen: 0 }, "another key: nothing verifies, so nothing is known: held (every call refused), not 'no kill'");
});

test("the marker is believed only while it certifies the log: put back, deleted, forged, written by an older version, or a log cut short, the log decides", () => {
  const sign = (body: object) => createHmac("sha256", auditKey(S)).update(`audit-tail\n${canonicalJson(body)}`).digest("hex");
  const cases: [string, (m: ReturnType<typeof home>, oldTail: Buffer, oldResume: Buffer) => void][] = [
    ["an older marker put back with the older resume", (m, oldTail, oldResume) => { writeFileSync(auditTailPath(m.log), oldTail); writeFileSync(m.ks, oldResume); }],
    ["the marker and kill-switch.json deleted", m => { unlinkSync(auditTailPath(m.log)); unlinkSync(m.ks); }],
    ["the marker's record edited to a resume", m => { const t = JSON.parse(readFileSync(auditTailPath(m.log), "utf8")); t.killSwitch.killed = false; writeFileSync(auditTailPath(m.log), JSON.stringify(t)); unlinkSync(m.ks); }],
    ["a marker without the record (an older version), signed", m => {
      const { mac: _mac, killSwitch: _ks, ...body } = JSON.parse(readFileSync(auditTailPath(m.log), "utf8"));
      writeFileSync(auditTailPath(m.log), JSON.stringify({ ...body, mac: sign(body) })); unlinkSync(m.ks);
    }],
    ["the log cut back to before the kill, kill-switch.json deleted", (m, _t, _r) => { truncateSync(m.log, LOG_BEFORE_KILL.get(m.log)!); unlinkSync(m.ks); }],
  ];
  const LOG_BEFORE_KILL = new Map<string, number>();
  for (const [what, tamper] of cases) {
    const m = home();
    m.kill(); m.resume(); m.hook();
    const oldTail = readFileSync(auditTailPath(m.log)), oldResume = readFileSync(m.ks);
    LOG_BEFORE_KILL.set(m.log, readFileSync(m.log).length);
    m.kill(); m.hook(); m.hook();
    tamper(m, oldTail, oldResume);
    const r = m.hook();
    assert.equal(r.exitCode, 2, `${what}: the kill holds`);
    m.resume(); assert.equal(m.hook().exitCode, 0, `${what}: a resume lifts it`);
  }
});

test("doctor, doctor --report and check say the kill switch is on while kill-switch.json is deleted after a kill", () => {
  const h = tmp();
  assert.equal(cli(h, ["kill"]).code, 0); unlinkSync(join(h, "kill-switch.json"));
  const d = cli(h, ["doctor"]);
  assert.match(d.out, /^warn {2}kill switch active \('kytral-guard resume' lifts it\)$/m); assert.match(d.out, /Kill switch ON/);
  assert.match(cli(h, ["doctor", "--report"]).out, /^- Killed: yes$/m);
  assert.match(cli(h, ["check", "ls"]).err, /the kill switch is ON/);
  assert.ok(!existsSync(join(h, "kill-switch.json")), "nothing written by them");
  assert.equal(cli(h, ["resume"]).code, 0);
  assert.match(cli(h, ["doctor", "--report"]).out, /^- Killed: no$/m);
});

test("known limit: the log, its marker and kill-switch.json rolled back together lift a kill for hooks", { todo: "needs an anchor off the machine (Kytral Guard Pro): a same-user rollback of every file is consistent" }, () => {
  const m = home();
  m.kill(); m.resume();
  const files = [m.log, auditTailPath(m.log), m.ks].map(f => [f, readFileSync(f)] as const);
  m.kill();
  for (const [f, b] of files) writeFileSync(f, b);
  assert.equal(m.hook().exitCode, 2);
});
