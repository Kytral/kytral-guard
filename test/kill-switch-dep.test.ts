// The deployment id (`dep`) of the kill switch states is derived, never stored: HMAC, with the states' key, of the state file's
// real path (directory resolved, file name as given). These tests pin the derivation and the trade-offs the README documents:
// the same directory through a link is the same deployment; states from another real path (moved directory, older install)
// block until a kill and a resume written here; a link planted in place of the file or of the directory never makes a
// foreign state lift a kill.
import { test } from "node:test"; import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, realpathSync, renameSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join } from "node:path";
import { AuditLog, Guard, loadPolicy, DEFAULT_POLICY, engageKillSwitch, releaseKillSwitch, killSwitchKey, canonicalJson } from "../src/index.js";
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d"; const AUD = "kytral-guard:kill-dep";
const K = killSwitchKey(S);
const tmp = () => mkdtempSync(join(tmpdir(), "kg-dep-"));
const ks = (h: string) => join(h, "kill-switch.json");
const mk = (h: string) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD,
  revocationFile: null, nonceFile: null, knownToolsFile: null, killSwitchFile: ks(h), audit: new AuditLog() });
const J = (h: string) => new AuditLog(join(h, "audit.jsonl"));   // one journal per home, as the CLI has
const kill = (h: string) => engageKillSwitch("qa", { path: ks(h), audit: J(h), key: K });
const resume = (h: string) => releaseKillSwitch(S, "qa", { path: ks(h), audit: J(h) });
const depOf = (h: string) => JSON.parse(readFileSync(ks(h), "utf8")).dep as string;
const expected = (dir: string) => createHmac("sha256", K).update(`kill-switch/dep\n${join(realpathSync(dir), "kill-switch.json")}`).digest("hex").slice(0, 32);

test("dep is the HMAC of the state file's real path with the states' key: kill-switch.id is never read", () => {
  const h = tmp(), g = mk(h);
  writeFileSync(join(h, "kill-switch.id"), randomBytes(16).toString("hex") + "\n");   // any id file, valid or not, changes nothing
  kill(h); assert.equal(depOf(h), expected(h)); assert.ok(g.killReason());
  writeFileSync(join(h, "kill-switch.id"), "zz\n");
  resume(h); assert.equal(depOf(h), expected(h)); assert.equal(g.killReason(), null);
  unlinkSync(join(h, "kill-switch.id")); kill(h); assert.equal(depOf(h), expected(h)); assert.ok(g.killReason());
  const other = tmp(); kill(other); assert.notEqual(depOf(other), depOf(h), "another directory, same secret: another id");
  const k2 = killSwitchKey("c4f8a2e6d0b4f8a2c6e0d4b8f2a6c0e4d8b2f6a0c4e8d2b6f0a4c8e2d6b0f4a8");
  assert.notEqual(createHmac("sha256", k2).update(`kill-switch/dep\n${join(realpathSync(h), "kill-switch.json")}`).digest("hex").slice(0, 32), depOf(h), "another secret: another id");
});

test("the same directory reached through a link is the same deployment (links in the directory path are resolved)", () => {
  const real = tmp(), link = join(tmp(), "home"); symlinkSync(real, link);
  const g = mk(link);                                                      // the Guard goes through the link, the writers do not
  kill(real); assert.ok(g.killReason()); resume(real); assert.equal(g.killReason(), null);
  kill(link); assert.ok(g.killReason()); resume(real); assert.equal(g.killReason(), null, "mixed paths, one deployment");
  assert.equal(depOf(real), expected(link));
});

test("states written through another real path (moved directory, older install) block until a kill and a resume written here", () => {
  // moved directory: the states of the old place are foreign to a Guard started on the new one; a kill still blocks
  const a = tmp(); kill(a); resume(a); const moved = join(tmp(), "moved"); renameSync(a, moved);
  const g = mk(moved); assert.match(g.killReason() ?? "", /does not chain/, "a resume of the old place: fail closed");
  kill(moved); assert.ok(g.killReason()); resume(moved); assert.equal(g.killReason(), null, "kill + resume here lift it");
  const b = tmp(); kill(b); const movedB = join(tmp(), "moved"); renameSync(b, movedB);
  const gb = mk(movedB); assert.ok(gb.killReason(), "a kill in force before the move still blocks after it");
  kill(movedB); assert.ok(gb.killReason()); resume(movedB); assert.equal(gb.killReason(), null);
  // older install: a state signed with the key but another (random, stored) id
  const h = tmp(), body = { v: 2, killed: false, gen: 7, at: new Date().toISOString(), by: "qa", dep: randomBytes(16).toString("hex"), after: "none" };
  writeFileSync(ks(h), JSON.stringify({ ...body, sig: createHmac("sha256", K).update(`kill-switch\n${canonicalJson(body)}`).digest("base64url") }));
  const late = mk(h); assert.match(late.killReason() ?? "", /does not chain/, "upgrade: the old resume blocks");
  kill(h); assert.ok(late.killReason()); assert.equal(JSON.parse(readFileSync(ks(h), "utf8")).gen, 8, "the generation goes on from the old state");
  resume(h); assert.equal(late.killReason(), null, "kill + resume after the upgrade lift it");
});

test("a link planted in place of kill-switch.json is not followed for the id: the other home's states never lift ours", () => {
  const h = tmp(), o = tmp(); kill(h); resume(h);
  for (let i = 0; i < 3; i++) { kill(o); resume(o); }                        // another home, same secret, an operator at work
  kill(h); const ours = readFileSync(ks(h));
  unlinkSync(ks(h)); symlinkSync(ks(o), ks(h));                             // the attacker links our state file to theirs...
  writeFileSync(ks(o), ours); const g = mk(h); assert.ok(g.killReason(), "...puts our kill there; a Guard started now sees it");
  resume(o); assert.ok(g.killReason(), "their operator's routine resume over our kill carries their id: no lift");
  for (let i = 0; i < 2; i++) { kill(o); assert.ok(g.killReason()); resume(o); assert.ok(g.killReason(), "nor any later one"); }
  kill(h); assert.ok(g.killReason()); resume(h); assert.equal(g.killReason(), null, "our own kill + resume (they replace the link) lift it");
  assert.equal(depOf(h), expected(h));
});

test("a state directory swapped for a link to another home while the Guard runs: fail closed, the pin does not follow", () => {
  const ours = tmp(), o = tmp(), link = join(tmp(), "home"); symlinkSync(ours, link);
  const g = mk(link); kill(link); assert.ok(g.killReason()); const K1 = readFileSync(ks(link));
  for (let i = 0; i < 3; i++) { kill(o); resume(o); }
  unlinkSync(link); symlinkSync(o, link);                                   // the attacker points our home to theirs
  writeFileSync(ks(o), K1); assert.ok(g.killReason());
  resume(o); assert.ok(g.killReason(), "their operator's resume over our kill: no lift");
  unlinkSync(link); symlinkSync(ours, link); resume(link); assert.equal(g.killReason(), null, "link restored: our resume lifts");
});
