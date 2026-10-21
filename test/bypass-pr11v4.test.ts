// Adversarial regression probes: a resume written after kill-switch.json was deleted chains to the kill through the
// journal, and only journal lines whose MAC verifies count. Green = the protection holds.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, unlinkSync, appendFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os"; import { join } from "node:path"; import { createHmac } from "node:crypto";
import { randomBytes } from "node:crypto"; import * as M from "../src/index.js"; import * as AU from "../src/audit.js"; import * as C from "node:crypto"; const require_crypto = () => C;
const { Guard, loadPolicy, DEFAULT_POLICY, AuditLog, engageKillSwitch, releaseKillSwitch, killSwitchKey } = M as any;
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d"; const AUD = "kytral-guard:test-audience";
const AK: Buffer | undefined = (AU as any).auditKey ? (AU as any).auditKey(S) : undefined;   // HMAC journal, as the CLI
const tmp = () => mkdtempSync(join(tmpdir(), "kg-test-"));
const ks = (h: string) => join(h, "kill-switch.json"); const idf = (h: string) => join(h, "kill-switch.id"); const K = killSwitchKey(S);
// Not depending on kill-switch.id (no longer read or written): absent, rmId deletes nothing and cpId writes an arbitrary id; the same effect if it exists.
const rmId = (h: string) => rmSync(idf(h), { force: true });
const cpId = (from: string, to: string) => writeFileSync(idf(to), existsSync(idf(from)) ? readFileSync(idf(from)) : randomBytes(16).toString("hex") + "\n");
const depOf = (h: string) => JSON.parse(readFileSync(ks(h), "utf8")).dep as string;

const mk = (h: string) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD,
  revocationFile: null, nonceFile: null, knownToolsFile: null, killSwitchFile: ks(h), audit: new AuditLog() });
// One shared file journal per KYTRAL_HOME, as the CLI has.
const J = (h: string) => new AuditLog(join(h, "audit.jsonl"), AK ? { key: AK } : {});
const put = (h: string, b: Buffer | string, g: any) => { writeFileSync(ks(h), b); return g.killReason(); };   // the Guard sees each content
const unsignedKill = (h: string) => engageKillSwitch("op", { path: ks(h), audit: J(h) });
const signedKill = (h: string) => engageKillSwitch("op", { path: ks(h), audit: J(h), key: K });
const resume = (h: string) => releaseKillSwitch(S, "op", { path: ks(h), audit: J(h) });
/** Another KYTRAL_HOME, same secret: n cycles (unsigned kill, resume). Returns the last pair (kill, chained resume) captured on disk (same uid). */
function foreignPair(n: number) {
  const o = tmp(); let X = Buffer.alloc(0), R = Buffer.alloc(0);
  for (let i = 0; i < n; i++) { unsignedKill(o); X = readFileSync(ks(o)); resume(o); R = readFileSync(ks(o)); }
  return { X, R, gen: JSON.parse(R.toString()).gen };
}

test("unsigned_kill_foreign_pair: UNSIGNED kill in force, a pair (unsigned kill, chained resume) copied from another home => must stay stopped", () => {
  const h = tmp(), g = mk(h);
  signedKill(h); resume(h); assert.equal(g.killReason(), null);
  unsignedKill(h); assert.ok(g.killReason(), "kill seen");
  const { X, R } = foreignPair(5);
  writeFileSync(ks(h), X); assert.ok(g.killReason(), "foreign kill: still stopped");
  writeFileSync(ks(h), R); assert.ok(g.killReason(), "foreign resume chained to a foreign kill: kill lifted without the secret");
});
test("signed_kill_foreign_pair: SIGNED kill in force, a bridge through a foreign unsigned kill + its resume => must stay stopped", () => {
  const h = tmp(), g = mk(h);
  signedKill(h); resume(h); signedKill(h); assert.ok(g.killReason());
  const { X, R } = foreignPair(5);
  writeFileSync(ks(h), X); assert.ok(g.killReason());
  writeFileSync(ks(h), R); assert.ok(g.killReason(), "signed kill lifted without the secret through an unsigned bridge");
});
test("corrupt_bridge: signed kill in force, corrupt content + a foreign resume chained to that content => must stay stopped", () => {
  const h = tmp(), g = mk(h), o = tmp();
  for (let i = 0; i < 4; i++) { signedKill(o); resume(o); }
  const G = Buffer.from("garbage-input\n"); writeFileSync(ks(o), G); resume(o); const R = readFileSync(ks(o));
  assert.equal(JSON.parse(R.toString()).after !== undefined, true);
  signedKill(h); assert.ok(g.killReason());
  writeFileSync(ks(h), G); assert.ok(g.killReason()); writeFileSync(ks(h), R); assert.ok(g.killReason(), "kill lifted through anchored corrupt content");
});
test("replay_resume_of_older_kill_same_home: a resume chained to an earlier kill, replayed after a new kill => refused", () => {
  const h = tmp(), g = mk(h);
  unsignedKill(h); const X1 = readFileSync(ks(h)); resume(h); const R1 = readFileSync(ks(h)); assert.equal(g.killReason(), null);
  unsignedKill(h); assert.ok(g.killReason());
  writeFileSync(ks(h), R1); assert.ok(g.killReason(), "R1 alone");
  assert.ok(put(h, X1, g)); assert.ok(put(h, R1, g), "X1 then R1");
  signedKill(h); assert.ok(g.killReason()); assert.ok(put(h, X1, g)); assert.ok(put(h, R1, g), "after a signed kill");
});
test("foreign_signed_resume_alone: a signed resume from another home (high gen, not chained) => refused, kill signed or not", () => {
  for (const kill of [unsignedKill, signedKill]) {
    const h = tmp(), g = mk(h); signedKill(h); resume(h); kill(h); assert.ok(g.killReason());
    const { R } = foreignPair(6); writeFileSync(ks(h), R); assert.ok(g.killReason());
  }
});
test("after_stripped_or_edited: removing or editing after or dep of a signed resume breaks the signature", () => {
  const h = tmp(), g = mk(h); unsignedKill(h); assert.ok(g.killReason());
  const hh = tmp(); unsignedKill(hh); resume(hh); const r = JSON.parse(readFileSync(ks(hh), "utf8"));
  for (const m of [(o: any) => { delete o.after; }, (o: any) => { o.after = "none"; }, (o: any) => { delete o.dep; }, (o: any) => { o.v = 1; delete o.after; delete o.dep; }, (o: any) => { o.gen += 50; }]) {
    const c = { ...r }; m(c); writeFileSync(ks(h), JSON.stringify(c)); assert.ok(g.killReason());
  }
});
test("dep_file_deleted_or_modified: kill-switch.id deleted/modified => legitimate flow OK, no foreign resume accepted", () => {
  const h = tmp(), g = mk(h); signedKill(h); resume(h); assert.equal(g.killReason(), null);
  const d0 = depOf(h); rmId(h); signedKill(h); assert.ok(g.killReason()); resume(h); assert.equal(g.killReason(), null, "id deleted: liveness"); assert.equal(depOf(h), d0, "id deleted: dep unchanged");
  const o = tmp(); signedKill(o); resume(o);
  cpId(o, h); signedKill(h); assert.ok(g.killReason());
  for (let i = 0; i < 5; i++) { signedKill(o); resume(o); }
  writeFileSync(ks(h), readFileSync(ks(o))); assert.ok(g.killReason(), "id copied from the other home: foreign resume refused");
  resume(h); assert.equal(g.killReason(), null, "legitimate resume");
  writeFileSync(idf(h), "zz\n"); signedKill(h); resume(h); assert.equal(g.killReason(), null, "invalid id replaced"); assert.equal(depOf(h), d0, "id modified: dep unchanged");
});
test("shared_journal_same_ms_resume_after_deleted_file", () => {
  const h = tmp(), g = mk(h); const T = Date.now(), n = Date.now; Date.now = () => T;
  try { unsignedKill(h); assert.ok(g.killReason()); unlinkSync(ks(h)); resume(h); } finally { Date.now = n; }
  assert.equal(g.killReason(), null);
});
test("journal_forged_kill_state_steers_after: an unauthenticated kill entry (chosen state) at the end of the journal => not signed into after", () => {
  const h = tmp(), p = join(h, "audit.jsonl");
  signedKill(h); resume(h);
  const evil = "e".repeat(64);
  appendFileSync(p, JSON.stringify({ ts: "", agentId: "*", tool: "*", decision: "kill", state: evil, generation: 3, prev: "", hash: "" }) + "\n");
  unlinkSync(ks(h)); const r = resume(h); assert.notEqual((r.state as any).after, evil, "after dictated by an unauthenticated line");
});
test("steered_after_no_capture: an unauthenticated kill line in another home's journal => a legitimate resume there, chained to a kill the attacker chose, lifts the kill here", () => {
  const { createHash } = require_crypto();
  const o = tmp(); for (let i = 0; i < 5; i++) { signedKill(o); resume(o); }
  const Xa = Buffer.from(JSON.stringify({ v: 1, killed: true, at: "", by: "evil" }));
  appendFileSync(join(o, "audit.jsonl"), JSON.stringify({ ts: "", agentId: "*", tool: "*", decision: "kill", state: createHash("sha256").update(Xa).digest("hex"), generation: 1, prev: "", hash: "" }) + "\n");
  unlinkSync(ks(o)); resume(o); const R = readFileSync(ks(o));   // legitimate operator, other home
  const h = tmp(), g = mk(h); signedKill(h); resume(h); signedKill(h); assert.ok(g.killReason());
  assert.ok(put(h, Xa, g)); assert.ok(put(h, R, g), "signed kill lifted without the secret, without capturing anything");
});

// ---------- findLast (HMAC journal). Without journal MACs: skip, a documented limit. ----------
const L = { skip: AK ? false : "unauthenticated journal (a documented limit)" };
const lines = (p: string) => readFileSync(p, "utf8").trim().split("\n").map(l => JSON.parse(l));
test("unauth_tail_entry_gen_max_ignored: an unauthenticated entry gen=2^40 (valid) at the end of the journal => resume OK, no overflow, floor unchanged", L, () => {
  const h = tmp(), p = join(h, "audit.jsonl"); signedKill(h); resume(h); signedKill(h);
  appendFileSync(p, JSON.stringify({ ts: "", agentId: "*", tool: "*", decision: "resume", generation: 2 ** 40, prev: "", hash: "" }) + "\n");
  appendFileSync(p, JSON.stringify({ ts: "", agentId: "*", tool: "*", decision: "kill", generation: 2 ** 40, unauthenticated: true, prev: "", hash: "" }) + "\n");
  unlinkSync(ks(h)); const r = resume(h); assert.equal((r.state as any).gen, 4);
  unlinkSync(ks(h)); const k = signedKill(h); assert.equal((k.state as any).gen, 5);
});
test("wrong_mac_entry_ignored: a copy of a real entry, generation edited (high/low), mac kept => ignored; max of the valid ones", L, () => {
  const h = tmp(), p = join(h, "audit.jsonl"); for (let i = 0; i < 3; i++) { signedKill(h); resume(h); }
  const last = lines(p).at(-1); assert.ok(last.mac, "HMAC journal");
  appendFileSync(p, JSON.stringify({ ...last, generation: 2 ** 40 }) + "\n");
  appendFileSync(p, JSON.stringify({ ...last, generation: 1 }) + "\n");
  unlinkSync(ks(h)); assert.equal((resume(h).state as any).gen, 7);
});
test("other_key_entry_ignored: an entry MACed with another audit key (high gen) => ignored", L, () => {
  const OTHER = "c4f8a2e6d0b4f8a2c6e0d4b8f2a6c0e4d8b2f6a0c4e8d2b6f0a4c8e2d6b0f4a8";
  const o = tmp(), po = join(o, "x.jsonl"), ao = new AuditLog(po, { key: (AU as any).auditKey(OTHER) });
  ao.append({ agentId: "*", tool: "*", decision: "resume", generation: 2 ** 39 });
  const h = tmp(), p = join(h, "audit.jsonl"); signedKill(h); resume(h);
  appendFileSync(p, readFileSync(po)); unlinkSync(ks(h)); assert.equal((resume(h).state as any).gen, 3);
});
test("low_tail_does_not_lower_floor: a low unauthenticated entry at the end => floor = max of the authentic ones", L, () => {
  const h = tmp(), p = join(h, "audit.jsonl"); for (let i = 0; i < 3; i++) { signedKill(h); resume(h); }
  appendFileSync(p, JSON.stringify({ ts: "", agentId: "*", tool: "*", decision: "kill", generation: 1, prev: "", hash: "" }) + "\n");
  unlinkSync(ks(h)); assert.equal((resume(h).state as any).gen, 7);
});
