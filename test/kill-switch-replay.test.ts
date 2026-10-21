// Replay of kill switch states: a signed state taken from elsewhere (another home, another install, an older state) must not
// lift a kill it does not chain to, whatever its generation; the generation floor read from the journal ignores forged lines.
import { test } from "node:test"; import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { appendFileSync, mkdtempSync, readFileSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join } from "node:path";
import { AuditLog, Guard, loadPolicy, DEFAULT_POLICY, issueBadge, engageKillSwitch, releaseKillSwitch, killSwitchKey, canonicalJson, MAX_GENERATION } from "../src/index.js";
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d"; const AUD = "kytral-guard:kill-replay";
const K = killSwitchKey(S);
const tmp = () => mkdtempSync(join(tmpdir(), "kg-replay-"));
const ks = (h: string) => join(h, "kill-switch.json");
const mk = (home: string) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD,
  revocationFile: null, nonceFile: null, knownToolsFile: null, killSwitchFile: ks(home), audit: new AuditLog() });
const verdict = (g: Guard) => { try { return g.checkSync(issueBadge(S, "agent-a", ["*"], 600, Date.now(), { aud: AUD }), { tool: "read_file", args: {} }); } catch (e) { return (e as Error).message; } };
const journals = new Map<string, AuditLog>();   // one journal per home, as the CLI has
const O = (h: string, key?: Buffer) => ({ path: ks(h), audit: journals.get(h) ?? journals.set(h, new AuditLog()).get(h)!, ...(key ? { key } : {}) });
/** The resume of another deployment (same secret, own home and id) at generation 2 * cycles - 1: what an attacker could carry over. */
function foreignResume(cycles = 5): Buffer {
  const o = tmp(); releaseKillSwitch(S, "qa", O(o));
  for (let i = 1; i < cycles; i++) { engageKillSwitch("qa", O(o, K)); releaseKillSwitch(S, "qa", O(o)); }
  return readFileSync(ks(o));
}
/** A v1 state (before `dep` and `after` were signed), signed as the first version did. */
function v1(killed: boolean, gen: number): string {
  const body = { v: 1, killed, gen, at: new Date().toISOString(), by: "qa" };
  return JSON.stringify({ ...body, sig: createHmac("sha256", K).update(`kill-switch\n${canonicalJson(body)}`).digest("base64url") });
}

test("a signed resume of a higher generation from another deployment does not lift a kill written without the key", () => {
  const h = tmp(), g = mk(h), foreign = foreignResume();
  assert.ok(JSON.parse(foreign.toString()).gen > 3);
  engageKillSwitch("qa", O(h)); assert.equal(verdict(g), "kill switch active");                      // unsigned: no generation of its own
  writeFileSync(ks(h), foreign); assert.match(verdict(g) ?? "", /does not chain to the kill in force/);
  unlinkSync(ks(h)); writeFileSync(ks(h), foreign); assert.match(verdict(g) ?? "", /does not chain/, "also after a delete");
  unlinkSync(ks(h)); engageKillSwitch("qa", O(h)); const late = mk(h); assert.equal(verdict(g), "kill switch active"); assert.equal(verdict(late), "kill switch active");  // a guard started during the kill
  writeFileSync(ks(h), foreign); for (const x of [g, late]) assert.match(verdict(x) ?? "", /does not chain/);
  releaseKillSwitch(S, "qa", O(h)); for (const x of [g, late]) assert.equal(verdict(x), null, "the resume that follows the kill lifts it");
});

test("the same holds through a symlink to the resume of another home, and for a kill whose signed state was stripped", () => {
  const h = tmp(), o = tmp(), g = mk(h);
  releaseKillSwitch(S, "qa", O(o)); const r = readFileSync(ks(o));
  engageKillSwitch("qa", O(h)); assert.equal(verdict(g), "kill switch active");
  unlinkSync(ks(h)); writeFileSync(join(o, "r.json"), r); symlinkSync(join(o, "r.json"), ks(h));
  assert.match(verdict(g) ?? "", /does not chain/);
  releaseKillSwitch(S, "qa", O(tmp())); const old = readFileSync(ks(h));
  const h2 = tmp(); releaseKillSwitch(S, "qa", O(h2)); const r1 = readFileSync(ks(h2));
  writeFileSync(ks(h2), JSON.stringify({ v: 1, killed: true, at: "", by: "qa" })); const late = mk(h2);
  assert.equal(verdict(late), "kill switch active"); writeFileSync(ks(h2), r1); assert.match(verdict(late) ?? "", /does not chain/);
  assert.ok(old.length > 0);
});

test("an old signed resume replayed after a new kill is refused, and so is one from another deployment over a signed kill", () => {
  const h = tmp(), g = mk(h), foreign = foreignResume(), a = O(h, K);
  releaseKillSwitch(S, "qa", a); const r1 = readFileSync(ks(h)); assert.equal(verdict(g), null);
  engageKillSwitch("qa", a); assert.equal(verdict(g), "kill switch active");
  writeFileSync(ks(h), r1); assert.match(verdict(g) ?? "", /replayed resume/);
  writeFileSync(ks(h), foreign); assert.match(verdict(g) ?? "", /does not chain/, "higher generation, other deployment");
  releaseKillSwitch(S, "qa", a); assert.equal(verdict(g), null);
  engageKillSwitch("qa", a); releaseKillSwitch(S, "qa", a); assert.equal(verdict(g), null, "the chain goes on");
});

test("a kill signed after an unsigned one keeps the chain: only the resume that follows it lifts the pair", () => {
  const h = tmp(), g = mk(h), foreign = foreignResume();
  releaseKillSwitch(S, "qa", O(h)); assert.equal(verdict(g), null);
  engageKillSwitch("qa", O(h)); engageKillSwitch("qa", O(h, K)); assert.equal(verdict(g), "kill switch active");
  writeFileSync(ks(h), foreign); assert.match(verdict(g) ?? "", /does not chain/);
  releaseKillSwitch(S, "qa", O(h)); assert.equal(verdict(g), null);
});

test("a resume run after the file was deleted or overwritten still chains to the kill the journal says is in force", () => {
  const h = tmp(), g = mk(h), o = O(h);
  engageKillSwitch("qa", o); assert.equal(verdict(g), "kill switch active");
  unlinkSync(ks(h)); assert.equal(verdict(g), "kill switch active");
  releaseKillSwitch(S, "qa", o); assert.equal(verdict(g), null);
});

test("v1 states (before dep and after were signed, never published) are refused: no resume lifts anything, a v1 kill is only an invalid state", () => {
  const h = tmp(), g = mk(h);
  writeFileSync(ks(h), v1(false, 1)); assert.match(verdict(g) ?? "", /not signed with this deployment's key/, "a v1 resume is no resume");
  writeFileSync(ks(h), v1(true, 2)); assert.ok(verdict(g), "a v1 kill still blocks");
  writeFileSync(ks(h), v1(false, 3)); assert.match(verdict(g) ?? "", /not signed with this deployment's key/, "a newer v1 resume lifts nothing");
  releaseKillSwitch(S, "qa", O(h)); assert.equal(verdict(g), null, "a v2 resume chained to what blocked lifts it");
  const h2 = tmp(), g2 = mk(h2); engageKillSwitch("qa", O(h2)); assert.equal(verdict(g2), "kill switch active");
  writeFileSync(ks(h2), v1(false, 9)); assert.match(verdict(g2) ?? "", /not signed with this deployment's key/);
  const h3 = tmp(), g3 = mk(h3); releaseKillSwitch(S, "qa", O(h3)); assert.equal(verdict(g3), null);
  engageKillSwitch("qa", O(h3, K)); writeFileSync(ks(h3), v1(false, 9)); assert.match(verdict(g3) ?? "", /not signed with this deployment's key/, "no v1 resume over a signed kill");
});

test("a v2 state cannot be turned into another: dep and after are signed", () => {
  const h = tmp(), g = mk(h); releaseKillSwitch(S, "qa", O(h));
  const s = JSON.parse(readFileSync(ks(h), "utf8"));
  for (const edit of [{ after: "0".repeat(64) }, { dep: "0".repeat(32) }, { v: 1 }]) {
    writeFileSync(ks(h), JSON.stringify({ ...s, ...edit })); assert.match(verdict(g) ?? "", /not signed with this deployment's key/, JSON.stringify(edit));
  }
});

test("the generation floor read from the journal is the maximum of the entries, and forged ones beyond the bound are ignored", () => {
  const h = tmp(), p = join(h, "a.jsonl");
  for (let i = 0; i < 3; i++) { engageKillSwitch("qa", { path: ks(h), audit: new AuditLog(p), key: K }); releaseKillSwitch(S, "qa", { path: ks(h), audit: new AuditLog(p) }); }   // 1..6
  const line = (o: object) => JSON.stringify({ ts: "", agentId: "*", tool: "*", decision: "kill", prev: "", hash: "", ...o }) + "\n";
  appendFileSync(p, line({ generation: Number.MAX_SAFE_INTEGER })); appendFileSync(p, line({ generation: MAX_GENERATION + 1 }));
  appendFileSync(p, line({ generation: 1 })); appendFileSync(p, line({ generation: "9" })); appendFileSync(p, line({ generation: -4 })); appendFileSync(p, line({ generation: 2.5 }));
  unlinkSync(ks(h));                                                                                      // the file is lost: only the journal remembers
  const r = releaseKillSwitch(S, "qa", { path: ks(h), audit: new AuditLog(p) });
  assert.equal((r.state as { gen: number }).gen, 7, "max of the valid entries + 1: not lowered by the late entry 1, not blocked by the huge ones");
});

test("a generation at the bound is refused (overflow) instead of wrapping", () => {
  const h = tmp(), p = join(h, "a.jsonl");
  appendFileSync(p, JSON.stringify({ ts: "", agentId: "*", tool: "*", decision: "resume", generation: MAX_GENERATION, prev: "", hash: "" }) + "\n");
  assert.throws(() => releaseKillSwitch(S, "qa", { path: ks(h), audit: new AuditLog(p) }), /generation overflow/);
});
