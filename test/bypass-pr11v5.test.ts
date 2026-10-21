// Adversarial regression probes: a resume cannot lift a kill by chaining to what an attacker placed (unsigned kills,
// corrupt content, a pair of states from another deployment, a steered `after`). Green = the protection holds.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, unlinkSync, appendFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os"; import { join } from "node:path"; import { createHash } from "node:crypto";
import { randomBytes } from "node:crypto"; import * as M from "../src/index.js"; import * as AU from "../src/audit.js";
const { Guard, loadPolicy, DEFAULT_POLICY, AuditLog, engageKillSwitch, releaseKillSwitch, killSwitchKey } = M as any;
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d"; const AUD = "kytral-guard:test-audience";
const AK: Buffer | undefined = (AU as any).auditKey ? (AU as any).auditKey(S) : undefined;
const tmp = () => mkdtempSync(join(tmpdir(), "kg-test-"));
const ks = (h: string) => join(h, "kill-switch.json"); const idf = (h: string) => join(h, "kill-switch.id"); const K = killSwitchKey(S);
// Not depending on kill-switch.id (no longer read or written): absent, rmId deletes nothing and cpId writes an arbitrary id; the same effect if it exists.
const rmId = (h: string) => rmSync(idf(h), { force: true });
const cpId = (from: string, to: string) => writeFileSync(idf(to), existsSync(idf(from)) ? readFileSync(idf(from)) : randomBytes(16).toString("hex") + "\n");
const depOf = (h: string) => JSON.parse(readFileSync(ks(h), "utf8")).dep as string;

const mk = (h: string) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD,
  revocationFile: null, nonceFile: null, knownToolsFile: null, killSwitchFile: ks(h), audit: new AuditLog() });
const J = (h: string) => new AuditLog(join(h, "audit.jsonl"), AK ? { key: AK } : {});
const unsignedKill = (h: string) => engageKillSwitch("op", { path: ks(h), audit: J(h) });
const signedKill = (h: string) => engageKillSwitch("op", { path: ks(h), audit: J(h), key: K, auditKey: AK });
const resume = (h: string) => releaseKillSwitch(S, "op", { path: ks(h), audit: J(h) });
const put = (h: string, b: Buffer | string, g: any) => { writeFileSync(ks(h), b); return g.killReason(); };
/** Another home, same secret: n kill cycles (signed or not) + resume. Captures the last (kill, resume). */
function foreign(n: number, signed: boolean) {
  const o = tmp(); let X = Buffer.alloc(0), R = Buffer.alloc(0);
  for (let i = 0; i < n; i++) { (signed ? signedKill : unsignedKill)(o); X = readFileSync(ks(o)); resume(o); R = readFileSync(ks(o)); }
  return { o, X, R };
}

// --- a bridge through an unsigned kill / refused content must no longer lift ---
test("unsigned_kill_foreign_pair: unsigned kill in force + a foreign pair => refused", () => {
  const h = tmp(), g = mk(h); unsignedKill(h); assert.ok(g.killReason());
  const { X, R } = foreign(5, false); assert.ok(put(h, X, g)); assert.ok(put(h, R, g), "foreign resume"); 
});
test("signed_kill_foreign_pair: SIGNED kill in force + a foreign unsigned bridge + resume => refused", () => {
  const h = tmp(), g = mk(h); signedKill(h); assert.ok(g.killReason());
  const { X, R } = foreign(5, false); assert.ok(put(h, X, g)); assert.ok(put(h, R, g), "lifted through a bridge");
});
test("unsigned_over_signed_then_pair: signed kill, THEN an anchored local unsigned kill, then a foreign pair => refused", () => {
  const h = tmp(), g = mk(h); signedKill(h); assert.ok(g.killReason()); unsignedKill(h); assert.ok(g.killReason());
  const { X, R } = foreign(5, false); assert.ok(put(h, X, g)); assert.ok(put(h, R, g));
});
test("chain_unsigned_kills_then_resume: several (local) unsigned kills in a row to move the anchor, then a foreign resume => refused", () => {
  const h = tmp(), g = mk(h);
  for (let i = 0; i < 4; i++) { unsignedKill(h); assert.ok(g.killReason()); }   // moves the anchor at each unsigned content
  const { X, R } = foreign(6, false);
  for (const b of [X, R, X, R]) put(h, b, g);
  assert.ok(g.killReason(), "no foreign resume lifts");
});
test("corrupt_bridge: unsigned kill, local corrupt content (anchored), a foreign resume chained to that content => refused", () => {
  const h = tmp(), g = mk(h), o = tmp();
  for (let i = 0; i < 4; i++) { signedKill(o); resume(o); }
  const G = Buffer.from("garbage-input\n"); put(o, G, mk(o)); resume(o); const R = readFileSync(ks(o));
  unsignedKill(h); assert.ok(g.killReason()); assert.ok(put(h, G, g)); assert.ok(put(h, R, g), "lifted through corrupt content");
});
test("steered_after: an unauthenticated kill line in the foreign journal => after chosen by the attacker, the resume does not lift here", () => {
  const o = tmp(); for (let i = 0; i < 5; i++) { signedKill(o); resume(o); }
  const Xa = Buffer.from(JSON.stringify({ v: 1, killed: true, at: "", by: "evil" }));
  appendFileSync(join(o, "audit.jsonl"), JSON.stringify({ ts: "", agentId: "*", tool: "*", decision: "kill", state: createHash("sha256").update(Xa).digest("hex"), generation: 1, prev: "", hash: "" }) + "\n");
  unlinkSync(ks(o)); resume(o); const R = readFileSync(ks(o));
  const h = tmp(), g = mk(h); signedKill(h); assert.ok(g.killReason()); assert.ok(put(h, Xa, g)); assert.ok(put(h, R, g));
});
test("replay_after_new_kill: a chained resume replayed after a new kill => refused", () => {
  const h = tmp(), g = mk(h); signedKill(h); const R1 = (() => { resume(h); return readFileSync(ks(h)); })(); assert.equal(g.killReason(), null);
  signedKill(h); assert.ok(g.killReason()); assert.ok(put(h, R1, g), "R1 replayed");
});

// --- dep file deleted / replaced by a same-uid attacker ---
test("dep_replaced_running_guard_no_lift: replacing kill-switch.id with a foreign dep does NOT lift the kill of a RUNNING proxy", () => {
  const h = tmp(), g = mk(h); signedKill(h); assert.ok(g.killReason());   // the proxy pinned its dep at startup
  const { o, R } = foreign(5, true);
  cpId(o, h);   // attacker replaces the dep file
  assert.ok(put(h, R, g), "foreign resume with the dep placed on disk: kill still in force");
  rmId(h); assert.ok(put(h, R, g), "dep deleted: same");
});
test("dep_deleted_fresh_guard_after_kill: dep deleted THEN a proxy started during a signed kill => a foreign resume does not lift", () => {
  const h = tmp(); signedKill(h); rmId(h);   // the next Guard re-pins a NEW dep
  const late = mk(h); assert.ok(late.killReason());
  const { o, R } = foreign(5, true); cpId(o, h);
  assert.ok(put(h, R, late), "the foreign resume does not chain to the held kill");
});
test("dep_preplaced_before_guard_start: an attacker places a foreign dep BEFORE the start, signed kill in force => a foreign resume does not lift", () => {
  const h = tmp(); signedKill(h); const { o, R } = foreign(5, true);
  cpId(o, h);   // the Guard starts with the foreign dep pinned...
  const late = mk(h); assert.ok(late.killReason());
  assert.ok(put(h, R, late), "...but the resume does not chain to a held kill => refused (fail closed)");
});
test("dep_deleted_legit_flow_ok: deleting kill-switch.id does not break the legitimate flow (liveness)", () => {
  const h = tmp(), g = mk(h); signedKill(h); resume(h); assert.equal(g.killReason(), null);
  const d0 = depOf(h); rmId(h); signedKill(h); assert.ok(g.killReason()); resume(h); assert.equal(g.killReason(), null, "legitimate kill+resume go through"); assert.equal(depOf(h), d0, "dep unchanged");
});

// --- fail safe: a missed intermediate state => stays blocked ---
test("failsafe_missed_intermediate: two kills between two checks => the next resume stays refused (fail closed)", () => {
  const h = tmp(), g = mk(h); signedKill(h); assert.ok(g.killReason());
  // the Guard sees ONLY the 2nd signed kill (a new dep? no, same home). A missed kill is simulated with a kill from another deployment put in between.
  const { X } = foreign(1, true); put(h, X, g);   // foreign content put in between, never chained
  const r = resume(h); assert.ok(g.killReason(), `stays blocked (gen ${(r.state as any).gen})`);
});

// --- re-pinning of the dep by a foreign signed kill chained to anchored content (unsigned kill in force) ---
test("repin_via_foreign_kill_over_unsigned: unsigned kill in force; X' (foreign unsigned kill), F (foreign signed kill chained to X'), R_F => must stay stopped", () => {
  const o = tmp(); for (let i = 0; i < 4; i++) { signedKill(o); resume(o); }
  unsignedKill(o); const Xp = readFileSync(ks(o)); signedKill(o); const F = readFileSync(ks(o)); resume(o); const RF = readFileSync(ks(o));
  assert.equal(JSON.parse(F.toString()).after, createHash("sha256").update(Xp).digest("hex"));
  const h = tmp(), g = mk(h); signedKill(h); resume(h); unsignedKill(h); assert.ok(g.killReason());
  assert.ok(put(h, Xp, g)); assert.ok(put(h, F, g)); assert.ok(put(h, RF, g), "kill lifted without the secret: dep re-pinned by a foreign kill");
});
test("repin_via_foreign_kill_over_garbage: unsigned kill in force; G (corrupt), F (foreign signed kill written over G), R_F => must stay stopped", () => {
  const o = tmp(); for (let i = 0; i < 4; i++) { signedKill(o); resume(o); }
  const G = Buffer.from("garbage-input-2\n"); writeFileSync(ks(o), G); signedKill(o); const F = readFileSync(ks(o)); resume(o); const RF = readFileSync(ks(o));
  const h = tmp(), g = mk(h); unsignedKill(h); assert.ok(g.killReason());
  assert.ok(put(h, G, g)); assert.ok(put(h, F, g)); assert.ok(put(h, RF, g), "kill lifted without the secret through corrupt content + a foreign kill");
});
test("repin_signed_kill_in_force_control: the same with a local SIGNED kill in force => refused (control)", () => {
  const o = tmp(); for (let i = 0; i < 4; i++) { signedKill(o); resume(o); }
  unsignedKill(o); const Xp = readFileSync(ks(o)); signedKill(o); const F = readFileSync(ks(o)); resume(o); const RF = readFileSync(ks(o));
  const h = tmp(), g = mk(h); signedKill(h); assert.ok(g.killReason());
  assert.ok(put(h, Xp, g)); assert.ok(put(h, F, g)); assert.ok(put(h, RF, g));
});
