// Adversarial probes of the pinned deployment id and the generation floor, from the attacker's position: a same-account program
// that can write any file in the state dir and journal, and can copy any signed state/journal line from another deployment
// with the same secret, but does NOT know the secret. Green = the protection holds. Each test targets one path that could
// change, bypass or confuse the pin or the floor, with and without journal MACs.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, unlinkSync, appendFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os"; import { join } from "node:path"; import { createHash, randomBytes } from "node:crypto";
import * as M from "../src/index.js"; import * as AU from "../src/audit.js";
const { Guard, loadPolicy, DEFAULT_POLICY, AuditLog, engageKillSwitch, releaseKillSwitch, killSwitchKey } = M as any;
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d"; const AUD = "kytral-guard:test-audience";
const AK: Buffer | undefined = (AU as any).auditKey ? (AU as any).auditKey(S) : undefined;
const tmp = () => mkdtempSync(join(tmpdir(), "kg-test-"));
const ks = (h: string) => join(h, "kill-switch.json"); const idf = (h: string) => join(h, "kill-switch.id"); const K = killSwitchKey(S);
const mk = (h: string) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD,
  revocationFile: null, nonceFile: null, knownToolsFile: null, killSwitchFile: ks(h), audit: new AuditLog() });
const J = (h: string) => new AuditLog(join(h, "audit.jsonl"), AK ? { key: AK } : {});
const unsignedKill = (h: string) => engageKillSwitch("op", { path: ks(h), audit: J(h) });
const signedKill = (h: string) => engageKillSwitch("op", { path: ks(h), audit: J(h), key: K, auditKey: AK });
const resume = (h: string) => releaseKillSwitch(S, "op", { path: ks(h), audit: J(h) });
const put = (h: string, b: Buffer | string, g: any) => { writeFileSync(ks(h), b); return g.killReason(); };
/** Another home, same secret: n signed cycles. Returns its dir, id, a captured kill and the resume after it (high generation). */
function foreign(n: number) {
  const o = tmp(); let X = Buffer.alloc(0), R = Buffer.alloc(0);
  for (let i = 0; i < n; i++) { signedKill(o); X = readFileSync(ks(o)); resume(o); R = readFileSync(ks(o)); }
  return { o, id: existsSync(idf(o)) ? readFileSync(idf(o)) : randomBytes(16).toString("hex") + "\n", X, R };
}

// Not exploitable: a foreign id pre-placed in kill-switch.id before the guard starts has no effect (the
// pin is derived, the file is never read); and chaining is a second line of defence: a foreign resume cannot lift the
// operator's own signed kill, because it does not chain to it (its `after` is not an anchor the guard holds).
test("preplaced_foreign_id_does_not_lift_operator_kill", () => {
  const h = tmp(), { id, R } = foreign(5); writeFileSync(idf(h), id);   // attacker pins a foreign id before the guard starts
  const g = mk(h); signedKill(h); assert.ok(g.killReason(), "operator's signed kill (carries the pinned foreign id) is in force");
  assert.ok(put(h, R, g), "a foreign resume with that same dep does not chain to the operator's kill => no lift");
});

// Not exploitable: with a signed kill in force, swapping the id file to a foreign dep AND appending forged journal
// lines (without a MAC) AND writing a foreign resume never lifts it: the id file is not read and the pin never moves.
test("idswap_and_journal_append_during_signed_kill_no_lift", () => {
  const h = tmp(), g = mk(h); signedKill(h); assert.ok(g.killReason());
  const { o, id, R } = foreign(6);
  writeFileSync(idf(h), id);                                             // swap the pinned id file to the foreign dep
  const evil = createHash("sha256").update(readFileSync(ks(h))).digest("hex");
  appendFileSync(join(h, "audit.jsonl"), JSON.stringify({ ts: "", agentId: "*", tool: "*", decision: "kill", state: evil, generation: 2 ** 39, prev: "", hash: "" }) + "\n");
  assert.ok(put(h, R, g), "foreign resume + swapped id + forged journal line: still killed");
  unlinkSync(idf(h)); assert.ok(put(h, readFileSync(ks(o)), g), "id removed, foreign resume again: still killed");
});

// Not exploitable: an unsigned kill carrying a foreign signed `last` (another dep, high generation) neither raises
// the floor nor confuses the pin: a later legitimate signed kill and resume still work (the foreign `last` was ignored, dep != pin).
test("unsigned_kill_foreign_last_does_not_raise_floor_or_confuse_pin", () => {
  const h = tmp(), g = mk(h); const { R } = foreign(20);               // a resume of another dep at a high generation
  const forged = JSON.stringify({ v: 1, killed: true, at: "", by: "mallory", last: JSON.parse(R.toString()) });
  assert.ok(put(h, forged, g), "unsigned kill carrying a foreign high-gen signed state is honoured (blocks)");
  resume(h); assert.equal(g.killReason(), null, "a legitimate local resume still lifts it (floor not inflated, pin unchanged)");
  signedKill(h); assert.ok(g.killReason()); resume(h); assert.equal(g.killReason(), null, "normal flow continues");
});

// Fail-closed, not a bypass: a foreign high-generation resume fed while NOTHING is in force (id file swapped too)
// is refused: there is no disk-id resume path any more, only the pinned id lifts. The guard blocks (fail closed)
// instead of opening, and a later legitimate signed kill blocks it as well.
test("idle_gen_inflation_is_failclosed", () => {
  const h = tmp(), g = mk(h); signedKill(h); resume(h); assert.equal(g.killReason(), null, "open");
  const { id, R } = foreign(20);
  writeFileSync(idf(h), id); assert.ok(put(h, R, g), "foreign resume while idle: refused, the guard blocks (fail closed)");
  signedKill(h); assert.ok(g.killReason(), "a later legitimate signed kill still BLOCKS this guard (fail closed, never open)");
});

// No effect: swapping the id file between the operator's kill and resume changes nothing: nothing reads
// it, the resume carries the derived id. No foreign resume lifts the kill, and the legitimate resume does.
test("mid_operation_id_swap_has_no_effect", () => {
  const h = tmp(), g = mk(h); signedKill(h); assert.ok(g.killReason());
  const { id, R } = foreign(3); writeFileSync(idf(h), id);              // attacker swaps the id before the operator resumes
  assert.ok(put(h, R, g), "a foreign resume does not lift the kill");
  resume(h); assert.equal(g.killReason(), null, "the legitimate resume lifts it: the swapped id file has no effect");
});

// Fixed: a signed kill that only chains to an attacker-placed anchor (an unsigned kill, or
// corrupt/forged content) is honoured but NEVER re-pins the deployment, so a foreign resume after it does not lift. A witness
// confirms the surgical nature of the fix: the ordinary signed kill + resume flow still lifts.
test("repin_via_anchor_blocked_control", () => {
  const o = tmp(); for (let i = 0; i < 4; i++) { signedKill(o); resume(o); }
  unsignedKill(o); const Xp = readFileSync(ks(o)); signedKill(o); const F = readFileSync(ks(o)); resume(o); const RF = readFileSync(ks(o));
  const h = tmp(), g = mk(h); unsignedKill(h); assert.ok(g.killReason());
  assert.ok(put(h, Xp, g)); assert.ok(put(h, F, g), "foreign signed kill chaining to the anchor: honoured, not re-pinned");
  assert.ok(put(h, RF, g), "foreign resume after it: no lift");
  const w = tmp(), gw = mk(w); signedKill(w); assert.ok(gw.killReason()); resume(w); assert.equal(gw.killReason(), null, "witness: the ordinary flow still lifts");
});
