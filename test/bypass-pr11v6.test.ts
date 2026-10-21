// Adversarial regression probes: no re-pinning of the deployment by a kill chained to the resume in force. Green = the
// protection holds. Model: an attacker running as the same user, without the secret, reads and writes everything in the
// state directories; a legitimate operator uses the CLI (with the secret) in ANOTHER directory (same secret) and runs the
// usual kill and resume there, over what the attacker left.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os"; import { join } from "node:path";
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
const signedKill = (h: string) => engageKillSwitch("op", { path: ks(h), audit: J(h), key: K, auditKey: AK });
const unsignedKill = (h: string) => engageKillSwitch("op", { path: ks(h), audit: J(h) });
const resume = (h: string) => releaseKillSwitch(S, "op", { path: ks(h), audit: J(h) });
const put = (h: string, b: Buffer | string, g: any) => { writeFileSync(ks(h), b); return g.killReason(); };
const cycles = (o: string, n: number) => { for (let i = 0; i < n; i++) { signedKill(o); resume(o); } };

test("repin_on_our_resume_then_lift_own_kill: no kill in force, a foreign F chained to OUR resume (placed in the other home) => never open, no re-pin", () => {
  const h = tmp(), g = mk(h); cycles(h, 2); assert.equal(g.killReason(), null);
  const ours = readFileSync(ks(h));
  const o = tmp(); cycles(o, 5); writeFileSync(ks(o), ours);   // the attacker places our resume in the other home
  signedKill(o); const F = readFileSync(ks(o)); resume(o); const RF = readFileSync(ks(o));   // operator of the other directory
  assert.ok(put(h, F, g), "F blocks"); assert.ok(put(h, RF, g), "R_F does not lift: a foreign F does not re-pin, never open");
  signedKill(h); assert.ok(g.killReason(), "our kill"); resume(h); assert.equal(g.killReason(), null, "no re-pin: our resume still lifts");
});
test("repin_then_operator_kill: a foreign F chained to our resume => never open, no re-pin; the operator's legitimate kill cannot be lifted by a foreign resume", () => {
  const h = tmp(), g = mk(h); cycles(h, 2); assert.equal(g.killReason(), null, "the Guard sees our resume"); const ours = readFileSync(ks(h));
  const o = tmp(); cycles(o, 5); writeFileSync(ks(o), ours); signedKill(o); const F = readFileSync(ks(o)); resume(o); const RF = readFileSync(ks(o));
  assert.ok(put(h, F, g)); assert.ok(put(h, RF, g), "R_F does not lift");   // no re-pin: the pin stays our dep
  signedKill(h); assert.ok(g.killReason(), "operator's kill");
  for (let i = 0; i < 3; i++) { signedKill(o); resume(o); }
  assert.ok(put(h, readFileSync(ks(o)), g), "foreign resume (dep of the other directory) over the operator's kill");
  unsignedKill(h); assert.ok(g.killReason()); signedKill(o); const X = readFileSync(ks(o)); resume(o);
  assert.ok(put(h, X, g)); assert.ok(put(h, readFileSync(ks(o)), g), "same with an unsigned kill");
});
test("repin_with_id_file_swap_then_operator_kill: a foreign F chained to our resume => never open, no re-pin; kill-switch.id replaced with D' => a legitimate kill, then a chained foreign resume does not lift", () => {
  const h = tmp(), g = mk(h); cycles(h, 2); assert.equal(g.killReason(), null, "the Guard sees our resume"); const ours = readFileSync(ks(h));
  const o = tmp(); cycles(o, 5); writeFileSync(ks(o), ours); signedKill(o); const F = readFileSync(ks(o)); resume(o); const RF = readFileSync(ks(o));
  assert.ok(put(h, F, g)); assert.ok(put(h, RF, g), "R_F does not lift"); cpId(o, h);   // no re-pin; id file = D' (no effect)
  signedKill(h); const Kop = readFileSync(ks(h)); assert.ok(g.killReason(), "operator's kill (signed with our dep)");
  writeFileSync(ks(o), Kop); resume(o);   // the operator of the other directory resumes over the placed kill
  assert.ok(put(h, readFileSync(ks(o)), g), "operator's kill lifted here without the secret");
});
test("deputy_id_copy_no_repin: WITHOUT re-pin — our kill-switch.id and our kill copied to the other home, whose operator resumes there => our kill lifted?", () => {
  const h = tmp(), g = mk(h); cycles(h, 2); signedKill(h); const Kop = readFileSync(ks(h)); assert.ok(g.killReason());
  const o = tmp(); cycles(o, 1); cpId(h, o); writeFileSync(ks(o), Kop);
  resume(o);   // operator of the other directory, over a state placed by the attacker
  assert.ok(put(h, readFileSync(ks(o)), g), "kill lifted here without the secret (confused deputy)");
});
test("deputy_unsigned_kill: the same with an UNSIGNED kill here", () => {
  const h = tmp(), g = mk(h); cycles(h, 2); unsignedKill(h); const X = readFileSync(ks(h)); assert.ok(g.killReason());
  const o = tmp(); cycles(o, 1); cpId(h, o); writeFileSync(ks(o), X);
  resume(o); assert.ok(put(h, readFileSync(ks(o)), g), "unsigned kill lifted here without the secret");
});
test("cannot_forge_kill_on_our_resume_without_operator: without an operator in the other directory, no signed piece chained to our resume exists", () => {
  const h = tmp(), g = mk(h); cycles(h, 2); assert.equal(g.killReason(), null, "the Guard sees our resume"); const ours = readFileSync(ks(h));
  const o = tmp(); cycles(o, 5);   // history of the other directory, never exposed to our resume
  const hist: Buffer[] = []; for (let i = 0; i < 3; i++) { signedKill(o); hist.push(readFileSync(ks(o))); resume(o); hist.push(readFileSync(ks(o))); }
  for (const b of hist) put(h, b, g); void ours;
  // no foreign piece re-pins: a legitimate kill cannot be lifted by the foreign history
  signedKill(h); assert.ok(g.killReason()); for (const b of hist) put(h, b, g); assert.ok(g.killReason());
});
