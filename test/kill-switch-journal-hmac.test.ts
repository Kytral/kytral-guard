// The generation floor of kill and resume writers is read from the journal. With the audit key only entries whose MAC
// verifies count, and the floor is the maximum: lines appended without the key (huge or low generations), edited lines and
// lines MAC'd with another key are skipped.
import { test } from "node:test"; import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join } from "node:path";
import { AuditLog, auditKey, engageKillSwitch, releaseKillSwitch, killSwitchKey } from "../src/index.js";
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d";
const OTHER = "c4f8a2e6d0b4f8a2c6e0d4b8f2a6c0e4d8b2f6a0c4e8d2b6f0a4c8e2d6b0f4a8";
const K = killSwitchKey(S), AK = auditKey(S);
const tmp = () => mkdtempSync(join(tmpdir(), "kg-kj-"));
const gen = (c: { state: object }) => (c.state as { gen: number }).gen;
/** A home whose journal holds 3 kills and 3 resumes (generations 1..6) written with the audit key. */
function home() {
  const h = tmp(), ks = join(h, "kill-switch.json"), p = join(h, "audit.jsonl");
  for (let i = 0; i < 3; i++) { engageKillSwitch("qa", { path: ks, audit: new AuditLog(p, { key: AK }), key: K }); releaseKillSwitch(S, "qa", { path: ks, audit: new AuditLog(p, { key: AK }) }); }
  return { ks, p };
}
const forged = (o: object) => JSON.stringify({ ts: "", agentId: "*", tool: "*", decision: "kill", approver: "mallory", prev: "", hash: "", ...o }) + "\n";

test("forged or unauthenticated journal lines are ignored; the maximum of the authenticated generations is the floor", () => {
  const { ks, p } = home();
  for (const generation of [Number.MAX_SAFE_INTEGER, 2 ** 40 + 1, 2 ** 39, 1, 2]) appendFileSync(p, forged({ generation }));   // no mac, with or without a plausible value
  appendFileSync(p, JSON.stringify({ ...JSON.parse(forged({ generation: 2 ** 39 })), mac: "00".repeat(32) }) + "\n");            // a mac that does not verify
  unlinkSync(ks);                                                                                                                   // the file is lost: only the journal remembers
  const r = releaseKillSwitch(S, "qa", { path: ks, audit: new AuditLog(p, { key: AK }) });
  assert.equal(gen(r), 7, "6 + 1: neither raised by the forged lines nor lowered by the late low ones");
});

test("an authenticated line whose generation was edited no longer verifies and is skipped", () => {
  for (const marker of [true, false]) {
    const { ks, p } = home();
    const lines = readFileSync(p, "utf8").trimEnd().split("\n"), last = JSON.parse(lines.at(-1)!);
    lines[lines.length - 1] = JSON.stringify({ ...last, generation: 1 });                   // the real generation 6, edited down
    writeFileSync(p, lines.join("\n") + "\n");
    unlinkSync(ks);
    // the signed tail marker records the last kill or resume (generation 6): editing the log does not lower the floor below it
    if (marker) assert.equal(gen(releaseKillSwitch(S, "qa", { path: ks, audit: new AuditLog(p, { key: AK }) })), 7, "6 + 1: the edited line is skipped, the marker's generation holds");
    else { unlinkSync(`${p}.tail`); assert.equal(gen(releaseKillSwitch(S, "qa", { path: ks, audit: new AuditLog(p, { key: AK }) })), 6, "5 + 1: the edited line is skipped, the floor is the last verified one"); }
  }
});

test("entries MAC'd with another deployment's key are skipped, and the writer's own key is derived when no journal is passed (default journal)", () => {
  const h = tmp(), ks = join(h, "kill-switch.json"), p = join(h, "audit.jsonl"), env = process.env.KYTRAL_AUDIT;
  try {
    process.env.KYTRAL_AUDIT = p;
    const other = new AuditLog(p, { key: auditKey(OTHER) }); other.append({ agentId: "*", tool: "*", decision: "resume", approver: "x", generation: 500 });
    const own = new AuditLog(p, { key: AK }); own.append({ agentId: "*", tool: "*", decision: "kill", approver: "qa", generation: 3 });
    assert.equal(gen(releaseKillSwitch(S, "qa", { path: ks })), 4, "journal read with the audit key derived from the secret");
  } finally { if (env === undefined) delete process.env.KYTRAL_AUDIT; else process.env.KYTRAL_AUDIT = env; }
});

test("a kill written without a secret is journaled unauthenticated and does not move the floor; the resume after it still lifts it", () => {
  const { ks, p } = home();
  engageKillSwitch("qa", { path: ks, audit: new AuditLog(p) });                              // no key: unsigned kill, entry without MAC
  const r = releaseKillSwitch(S, "qa", { path: ks, audit: new AuditLog(p, { key: AK }) });
  assert.equal(gen(r), 7);
});
