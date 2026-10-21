// Adversarial regression probes: the shared kill switch (replay protection by signed generations, clock changes, deleted
// or restored state files, fail closed). Green = the protection holds; todo = a known limit, documented in docs/kill-switch.md.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, unlinkSync, chmodSync, mkdirSync, symlinkSync, existsSync } from "node:fs";
import { tmpdir } from "node:os"; import { join } from "node:path"; import { execSync } from "node:child_process";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge, AuditLog, engageKillSwitch, releaseKillSwitch, KillSwitch, killSwitchKey } from "../src/index.js";
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d"; const AUD = "kytral-guard:test-audience";
const OTHER = "c4f8a2e6d0b4f8a2c6e0d4b8f2a6c0e4d8b2f6a0c4e8d2b6f0a4c8e2d6b0f4a8";
const tmp = () => mkdtempSync(join(tmpdir(), "kg-test-"));
const bd = () => issueBadge(S, "agent-a", ["*"], 600, Date.now(), { aud: AUD });
const mk = (home: string, o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD,
  revocationFile: null, nonceFile: null, knownToolsFile: null, killSwitchFile: join(home, "kill-switch.json"), audit: new AuditLog(), ...o });
const ks = (h: string) => join(h, "kill-switch.json");
const A = (h: string) => ({ path: ks(h), audit: new AuditLog() });
const withClock = <T>(t: number, f: () => T): T => { const n = Date.now; Date.now = () => t; try { return f(); } finally { Date.now = n; } };
const outcome = (p: Promise<unknown>) => p.then(() => "allowed", (e: Error) => "refused: " + e.message);
const keepAlive = () => { const t = setInterval(() => {}, 1000); return () => clearInterval(t); };   // the poll timer is unref() (in the proxy, stdin keeps the loop alive)
const CALL = { tool: "read_file", args: { path: "/tmp/x" } };

// ---------- replay protection: same millisecond, clock set back, deleted or restored state file ----------
// The first two tests share one file journal per home (AJ), as the CLI does (one audit.jsonl per KYTRAL_HOME): a resume written
// after kill-switch.json was deleted chains to the kill through the journal, which a new in-memory journal at each call
// could not do. The other tests use an in-memory journal (A).
const AJ = (h: string) => ({ path: ks(h), audit: new AuditLog(join(h, "audit.jsonl")) });
test("same_ms_resume_after_deleted_file_is_accepted (shared journal, as the CLI does)", () => {
  const h = tmp(), g = mk(h); const T = Date.now();
  withClock(T, () => { engageKillSwitch("qa", AJ(h)); assert.ok(g.killReason()); unlinkSync(ks(h)); releaseKillSwitch(S, "qa", AJ(h)); });
  assert.equal(g.killReason(), null, "legitimate resume refused as a replay");
});
test("clock_step_back_then_resume_after_deleted_file_is_accepted (shared journal, as the CLI does)", () => {
  const h = tmp(), g = mk(h); engageKillSwitch("qa", AJ(h)); assert.ok(g.killReason()); unlinkSync(ks(h));
  withClock(Date.now() - 3_600_000, () => releaseKillSwitch(S, "qa", AJ(h)));
  assert.equal(g.killReason(), null);
});
// With the clock set back an hour, a kill still gets the previous generation + 1; the resume that was in force before it,
// restored, is then a replay (its generation is not newer) and must never lift the kill in a running guard (it needs no secret).
test("old_resume_with_equal_or_lower_gen_never_lifts_a_newer_kill_in_a_running_guard", () => {
  const h = tmp(), g = mk(h); const T = Date.now();
  engageKillSwitch("qa", A(h)); releaseKillSwitch(S, "qa", A(h)); assert.equal(g.killReason(), null);
  const oldResume = readFileSync(ks(h), "utf8");
  withClock(T - 3_600_000, () => engageKillSwitch("qa", A(h)));   // clock back: kill still gets gen = previous + 1
  assert.ok(g.killReason(), "kill seen");
  writeFileSync(ks(h), oldResume); assert.ok(g.killReason(), "restored old resume (gen <= kill) refused");
});
test("restart_plus_restored_old_resume_lifts_kill (known limit)", { todo: "known limit: no persistent state; needs a signed epoch/counter or an anchor" }, () => {
  const h = tmp(); engageKillSwitch("qa", A(h)); releaseKillSwitch(S, "qa", A(h)); const oldResume = readFileSync(ks(h), "utf8");
  engageKillSwitch("qa", A(h)); writeFileSync(ks(h), oldResume);
  assert.ok(mk(h).killReason(), "new proxy must not honour a resume older than the last kill");
});
test("restart_after_deleted_kill_file_runs (known limit)", { todo: "known limit: deleting the file before a restart lifts the kill" }, () => {
  const h = tmp(); engageKillSwitch("qa", A(h)); unlinkSync(ks(h)); assert.ok(mk(h).killReason());
});
test("future_dated_unsigned_kill_does_not_brick_resume", () => {
  const h = tmp(), g = mk(h); writeFileSync(ks(h), JSON.stringify({ v: 1, killed: true, gen: Date.now() + 4 * 60_000, at: "x", by: "evil" }));
  assert.ok(g.killReason()); releaseKillSwitch(S, "qa", A(h)); assert.equal(g.killReason(), null, "resume chains on gen+1");
});

// ---------- fail closed ----------
test("corrupt_unreadable_directory_wrong_types_refuse", () => {
  const h = tmp(), g = mk(h); releaseKillSwitch(S, "qa", A(h)); assert.equal(g.killReason(), null);
  for (const bad of ["{", "null", "[]", '{"killed":"false"}', '{"v":1,"killed":false,"gen":1}']) { writeFileSync(ks(h), bad); assert.ok(g.killReason(), bad); }
  writeFileSync(ks(h), "{}"); chmodSync(ks(h), 0o000);
  if (process.getuid?.() !== 0) assert.ok(g.killReason(), "unreadable");
  chmodSync(ks(h), 0o600); unlinkSync(ks(h)); mkdirSync(ks(h)); assert.ok(mk(h).killReason(), "a directory is not a resume");
});
test("resume_signed_with_other_secret_or_edited_is_refused", () => {
  const h = tmp(), g = mk(h); engageKillSwitch("qa", A(h)); const o = tmp();
  releaseKillSwitch(OTHER, "evil", { path: ks(h), audit: new AuditLog() }); assert.ok(g.killReason(), "other deployment's key");
  releaseKillSwitch(S, "qa", A(h)); const s = JSON.parse(readFileSync(ks(h), "utf8")); s.gen += 1; writeFileSync(ks(h), JSON.stringify(s));
  assert.ok(g.killReason(), "edited gen"); void o;
});
test("deleted_file_keeps_kill_in_running_guard", () => {
  const h = tmp(), g = mk(h); engageKillSwitch("qa", A(h)); assert.ok(g.killReason()); unlinkSync(ks(h)); assert.ok(g.killReason());
});
test("symlink_to_a_valid_resume_elsewhere_is_only_a_restore (same uid)", () => {
  const h = tmp(), g = mk(h), o = tmp(); releaseKillSwitch(S, "qa", A(o)); const r = readFileSync(ks(o), "utf8");
  engageKillSwitch("qa", A(h)); assert.ok(g.killReason()); unlinkSync(ks(h)); writeFileSync(join(o, "r.json"), r); symlinkSync(join(o, "r.json"), ks(h));
  assert.ok(g.killReason(), "older resume via symlink refused");
});

// ---------- pending confirmation, always, journal ----------
test("pending_confirmation_refused_within_100ms_of_cli_kill", { timeout: 10000 }, async () => {
  const stop = keepAlive(); const h = tmp(); let resolveAsk!: (v: any) => void;
  const g = mk(h, { policy: loadPolicy(DEFAULT_POLICY), confirm: () => new Promise(r => (resolveAsk = r)) });
  const t0 = { v: 0 }; const pr = g.check(bd(), { tool: "mystery2", args: {} }).then(() => "allowed", () => "refused");
  await new Promise(r => setTimeout(r, 50)); engageKillSwitch("qa", A(h)); t0.v = Date.now();
  const res = await pr; const dt = Date.now() - t0.v; resolveAsk?.({ choice: "always", approver: "qa" });
  assert.equal(res, "refused"); assert.ok(dt < 150, `refused after ${dt} ms (poll 100 ms)`); console.log(`# refusal latency ${dt} ms`); stop();
});
test("no_always_recorded_when_answered_during_kill", async () => {
  const h = tmp(), f = join(h, "known.json"); let g!: Guard;
  g = mk(h, { policy: loadPolicy(DEFAULT_POLICY), knownToolsFile: f, confirm: async () => { engageKillSwitch("qa", A(h)); return { choice: "always", approver: "qa" }; } });
  assert.match(await outcome(g.check(bd(), { tool: "mystery", args: {} })), /refused/);
  assert.ok(!existsSync(f) || !readFileSync(f, "utf8").includes("mystery"), "no grant written during a kill");
});
test("invalid_state_journaled_once_and_kill_resume_journaled", () => {
  const h = tmp(), audit = new AuditLog(), g = mk(h, { audit }); writeFileSync(ks(h), "{");
  for (let i = 0; i < 5; i++) assert.throws(() => g.checkSync(bd(), CALL));
  assert.equal(audit.entries.filter(e => e.decision === "kill-switch-invalid").length, 1);
  const a2 = new AuditLog(); engageKillSwitch("qa-k", { path: ks(h), audit: a2 }); releaseKillSwitch(S, "qa-r", { path: ks(h), audit: a2 });
  assert.deepEqual(a2.entries.map(e => [e.decision, e.approver]), [["kill", "qa-k"], ["resume", "qa-r"]]);
});

// ---------- concurrency ----------
test("parallel_kill_and_resume_processes_end_in_a_consistent_state", { timeout: 60000 }, () => {
  const h = tmp(); const cli = join(import.meta.dirname, "..", "src/cli.ts");
  const env = `KYTRAL_HOME=${h} KYTRAL_AUDIT=${h}/audit.jsonl KYTRAL_SECRET=${S}`;
  execSync(`for i in 1 2 3 4; do (${env} node --import tsx ${cli} kill >/dev/null 2>&1 &); (${env} node --import tsx ${cli} resume >/dev/null 2>&1 &); done; sleep 8`, { shell: "/bin/bash" });
  const s = JSON.parse(readFileSync(ks(h), "utf8")); assert.equal(typeof s.killed, "boolean");
  const g = mk(h); assert.equal(g.killReason() === null, s.killed === false, "file state and guard verdict agree");
  for (const l of readFileSync(join(h, "audit.jsonl"), "utf8").trim().split("\n")) JSON.parse(l);
});
test("predictable_tmp_symlink_is_followed_by_writer", () => {
  const h = tmp(), victim = join(tmp(), "victim"); writeFileSync(victim, "keep"); symlinkSync(victim, `${ks(h)}.${process.pid}.tmp`);
  engageKillSwitch("qa", A(h)); assert.equal(readFileSync(victim, "utf8"), "keep");
});
