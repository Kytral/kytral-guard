// Adversarial regression probes: the deployment id derived from the state file's real path. Green = the protection holds.
// Model: an attacker running as the same user, without the secret, reads, writes and links everything in the state
// directories; a legitimate operator (with the secret) runs the usual kill and resume in ANOTHER directory (same secret),
// over what the attacker left there.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, linkSync, symlinkSync, unlinkSync, renameSync, existsSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, relative } from "node:path";
import * as M from "../src/index.js"; import * as AU from "../src/audit.js";
const { Guard, loadPolicy, DEFAULT_POLICY, AuditLog, engageKillSwitch, releaseKillSwitch, killSwitchKey } = M as any;
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d"; const AUD = "kytral-guard:test-audience";
const AK: Buffer | undefined = (AU as any).auditKey ? (AU as any).auditKey(S) : undefined;
const K = killSwitchKey(S);
const tmp = () => mkdtempSync(join(tmpdir(), "kg-test-"));
const ks = (h: string, n = "kill-switch.json") => join(h, n);
const mkf = (f: string) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD,
  revocationFile: null, nonceFile: null, knownToolsFile: null, killSwitchFile: f, audit: new AuditLog() });
const J = (f: string) => new AuditLog(f + ".audit.jsonl", AK ? { key: AK } : undefined);   // one journal per state file
const killF = (f: string) => engageKillSwitch("qa", { path: f, audit: J(f), key: K, ...(AK ? { auditKey: AK } : {}) });
const resumeF = (f: string) => releaseKillSwitch(S, "qa", { path: f, audit: J(f) });
const depOf = (f: string) => JSON.parse(readFileSync(f, "utf8")).dep as string;
const put = (f: string, b: Buffer, g: any) => { writeFileSync(f, b); return g.killReason(); };
const cycles = (f: string, n: number) => { for (let i = 0; i < n; i++) { killF(f); resumeF(f); } };

test("same_dir_two_state_files: two state files in the SAME folder (same secret) => distinct ids; the other file's resume over our kill does not lift", () => {
  const d = tmp(), a = ks(d), b = ks(d, "other-kill-switch.json"), g = mkf(a);
  cycles(a, 2); cycles(b, 3); assert.notEqual(depOf(a), depOf(b), "file name in the computation => distinct ids");
  killF(a); const Ka = readFileSync(a); assert.ok(g.killReason());
  writeFileSync(b, Ka); resumeF(b);                     // b's operator resumes over our kill placed there
  assert.ok(put(a, readFileSync(b), g), "kill lifted here without the secret?");
});
test("hardlink_their_file_to_ours: their kill-switch.json = a hard link to ours; their resume does not touch our file and lifts nothing", () => {
  const h = tmp(), o = tmp(), g = mkf(ks(h)); cycles(ks(h), 2); cycles(ks(o), 3);
  killF(ks(h)); const Kop = readFileSync(ks(h)); assert.ok(g.killReason());
  unlinkSync(ks(o)); linkSync(ks(h), ks(o));            // the attacker links their file to ours
  resumeF(ks(o)); assert.ok(g.killReason(), "our file is not modified through the hard link (written by renaming)");
  assert.deepEqual(readFileSync(ks(h)), Kop, "our kill intact");
  assert.ok(put(ks(h), readFileSync(ks(o)), g), "their resume copied into our home does not lift");
});
test("symlink_their_file_to_ours: their kill-switch.json = a symbolic link to ours; their resume does not lift our kill", () => {
  const h = tmp(), o = tmp(), g = mkf(ks(h)); cycles(ks(h), 2); cycles(ks(o), 3);
  killF(ks(h)); const Kop = readFileSync(ks(h)); assert.ok(g.killReason());
  unlinkSync(ks(o)); symlinkSync(ks(h), ks(o));
  resumeF(ks(o)); assert.ok(g.killReason()); assert.deepEqual(readFileSync(ks(h)), Kop, "the link is replaced, not followed on write");
  assert.ok(put(ks(h), readFileSync(ks(o)), g), "copied into our home: does not lift");
});
test("hardlink_our_file_to_theirs: our kill-switch.json = a hard link to theirs, holding our kill; their resume does not lift", () => {
  const h = tmp(), o = tmp(), g = mkf(ks(h)); cycles(ks(h), 2); cycles(ks(o), 3);
  killF(ks(h)); const Kop = readFileSync(ks(h)); assert.ok(g.killReason());
  writeFileSync(ks(o), Kop); unlinkSync(ks(h)); linkSync(ks(o), ks(h)); assert.ok(g.killReason());
  resumeF(ks(o)); assert.ok(g.killReason(), "the rename breaks the hard link: our file keeps the kill");
  assert.ok(put(ks(h), readFileSync(ks(o)), g), "copied: does not lift");
});
test("dir_symlink_into_their_home: our folder = a link to a folder holding their file; their resume does not lift (pin fixed at start)", () => {
  const ours = tmp(), o = tmp(), link = join(tmp(), "home"); symlinkSync(ours, link);
  const g = mkf(ks(link)); cycles(ks(link), 2); killF(ks(link)); const Kop = readFileSync(ks(link)); assert.ok(g.killReason());
  cycles(ks(o), 3); writeFileSync(ks(o), Kop); unlinkSync(link); symlinkSync(o, link);   // the Guard now reads their file
  resumeF(ks(o)); assert.ok(g.killReason(), "their resume carries their id: does not lift");
});
test("their_home_is_symlink_to_ours (limit documented in the README): their KYTRAL_HOME replaced with a link to ours => their resume acts HERE", { todo: "documented limit: the id ties the state to the folder, not to the operator; the same as redirecting the operator's environment (same uid)" }, () => {
  const h = tmp(), g = mkf(ks(h)); cycles(ks(h), 2); killF(ks(h)); assert.ok(g.killReason());
  const parent = tmp(), theirs = join(parent, "home"); symlinkSync(h, theirs);
  resumeF(ks(theirs)); assert.ok(g.killReason(), "their routine resume lifts our kill");
});
test("relative_and_dotdot_paths: relative and '..' paths to the same file => the same id (liveness), no confusion", () => {
  const h = tmp(), sub = join(h, "x"); mkdirSync(sub);
  const cwd = process.cwd(); process.chdir(tmpdir());
  try {
    const rel = join(relative(tmpdir(), h), "kill-switch.json"), dd = join(sub, "..", "kill-switch.json");
    const g = mkf(rel); killF(ks(h)); assert.ok(g.killReason()); resumeF(dd); assert.equal(g.killReason(), null, "'..': same deployment");
    killF(rel); assert.ok(g.killReason()); resumeF(ks(h)); assert.equal(g.killReason(), null, "relative: same deployment");
  } finally { process.chdir(cwd); }
});
test("special_chars_and_newline_in_path: '\\n', spaces, unicode; neighboring prefixes => distinct ids, no cross lift", () => {
  // a file name cannot hold '\n' on Windows: the names that do are tried on the other systems
  const base = tmp(), names = ["a", "a\nb", "a b", "a\n", "é", "a/kill-switch.json\n", "kill-switch\ndep"].filter(n => process.platform !== "win32" || !n.includes("\n")).map((n, i) => n.includes("/") ? join(base, `p${i}`, n.split("/")[0]) : join(base, n));
  const homes = names.map((d) => { mkdirSync(d, { recursive: true }); return d; });
  const deps = new Set<string>(); for (const d of homes) { cycles(ks(d), 1); deps.add(depOf(ks(d))); }
  assert.equal(deps.size, homes.length, "all ids distinct");
  const g = mkf(ks(homes[0])); killF(ks(homes[0])); const K0 = readFileSync(ks(homes[0])); assert.ok(g.killReason());
  for (const d of homes.slice(1)) { writeFileSync(ks(d), K0); resumeF(ks(d)); assert.ok(put(ks(homes[0]), readFileSync(ks(d)), g), `resume from ${JSON.stringify(d)} does not lift`); }
  const gn = mkf(ks(homes[1])); killF(ks(homes[1])); assert.ok(gn.killReason()); resumeF(ks(homes[1])); assert.equal(gn.killReason(), null, "liveness with '\\n' in the path");
});
test("moved_dir_while_guard_runs: folder moved while the Guard runs => fail closed; states written at the new place do not lift", () => {
  const h = tmp(), g = mkf(ks(h)); cycles(ks(h), 2); killF(ks(h)); assert.ok(g.killReason());
  const moved = join(tmp(), "moved"); renameSync(h, moved); assert.ok(g.killReason(), "file missing: blocked");
  resumeF(ks(moved)); mkdirSync(h); writeFileSync(ks(h), readFileSync(ks(moved)));
  assert.ok(g.killReason(), "resume from the new place copied to the old one: does not lift (other id)");
});
test("dangling_link_home_at_start: a state folder reached through a dangling link at start (realpath fails) => never opened through another path", () => {
  const p = tmp(), tgt = join(p, "target"), link = join(p, "L"); symlinkSync(tgt, link);
  const f = join(link, "home", "kill-switch.json"); let g: any; try { g = mkf(f); } catch { return; }   // the constructor may refuse: fail closed
  mkdirSync(join(tgt, "home"), { recursive: true });
  killF(f); assert.ok(g.killReason()); resumeF(f);
  const r = g.killReason(); if (r !== null) assert.match(r, /does not chain|kill/, "blocked (falls back to the unresolved path): fail closed, restart required");
  const o = tmp(); cycles(ks(o), 2); killF(f); const Kf = readFileSync(f); writeFileSync(ks(o), Kf); resumeF(ks(o));
  assert.ok(put(f, readFileSync(ks(o)), g), "another folder never lifts");
});
