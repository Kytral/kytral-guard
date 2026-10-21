// Audit log as an HMAC chain: mac = HMAC-SHA256(auditKey, prev || canonical JSON of the entry), a signed tail marker
// against truncation, `kytral-guard audit verify` (first broken line; exit 0 valid, 1 broken, 3 unverifiable, 2 no key).
// An old SHA-256 log is never valid: new entries start a marked HMAC segment that binds it. Several writers share one chain.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process"; import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs"; import { tmpdir } from "node:os";
import { join, resolve } from "node:path"; import { pathToFileURL } from "node:url";
import { AuditLog, auditKey, auditTailPath, canonicalJson, deriveKey, Guard, loadPolicy, DEFAULT_POLICY, issueBadge, verifyAuditFile, verifyChain } from "../src/index.js";
const ROOT = resolve(import.meta.dirname, "..");
const S = "4d7a1e9c3f6b2805d4a7e1c9f3b6d2805a4e7c1f9d3b6a2e8c5f1d7b4a9e3c62"; const AUD = "kytral-guard:audit-test";
const OTHER = "a2f6c0e4b8d2f6a0c4e8b2d6f0a4c8e2b6d0f4a8c2e6b0d4f8a2c6e0b4d8f2a6";   // another deployment's secret
const KEY = auditKey(S);
const tmp = () => mkdtempSync(join(tmpdir(), "kg-audit-hmac-"));
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const rows = (f: string) => readFileSync(f, "utf8").split("\n").slice(0, -1);
const put = (f: string, lines: string[]) => writeFileSync(f, lines.map(l => `${l}\n`).join(""));
const entry = (i: number) => ({ agentId: "agent-a", tool: `tool_${i}`, decision: "allow" });
/** A log of n HMAC entries (as a proxy writes them). */
function log(n: number, key = KEY) { const f = join(tmp(), "audit.jsonl"), l = new AuditLog(f, { key }); for (let i = 1; i <= n; i++) l.append(entry(i)); return f; }
/** What an attacker without the key can do: edit an entry and recompute its SHA-256 (field order kept). */
const rehash = (e: any) => { const { hash: _h, mac, ...base } = e; return JSON.stringify({ ...base, hash: sha(JSON.stringify(base)), ...(mac ? { mac } : {}) }); };
/** [exit code, first broken line, why] */
const check = (f: string, key = KEY) => { const r = verifyAuditFile(f, key); return [r.exitCode, r.broken?.line, r.broken?.why ?? ""] as const; };

test("each entry carries mac = HMAC-SHA256(auditKey, prev || canonical JSON of the entry); an intact log verifies (exit 0); the key is never written", () => {
  const f = log(4); const all = rows(f).map(l => JSON.parse(l));
  assert.equal(all[0].segment, "hmac-sha256/v1", "the HMAC segment is marked on its first entry"); assert.equal(all[0].prev, "GENESIS");
  all.forEach((e, i) => {
    assert.equal(e.seq, i + 1); if (i) assert.equal(e.prev, all[i - 1].mac);
    const { mac, ...body } = e;
    assert.equal(mac, createHmac("sha256", KEY).update(e.prev).update(canonicalJson(body)).digest("hex"));
  });
  assert.deepEqual(KEY, deriveKey(S, "audit/v1"), "without KYTRAL_AUDIT_SECRET, derived from the proxy secret (label audit/v1)");
  const r = verifyAuditFile(f, KEY);
  assert.deepEqual([r.exitCode, r.lines, r.hmac, r.tailSeq], [0, 4, 4, 4]);
  assert.ok(verifyChain(all, KEY));
  const written = readFileSync(f, "utf8") + readFileSync(auditTailPath(f), "utf8");
  for (const s of [S, KEY.toString("hex"), KEY.toString("base64"), KEY.toString("base64url")]) assert.ok(!written.includes(s), "neither the secret nor the key is written");
});

test("tamper: a modified entry is detected, also when its SHA-256 is recomputed (only the MAC protects); the first broken line is reported", () => {
  const f = log(5); const lines = rows(f), e = JSON.parse(lines[2]);
  put(f, lines.map((l, i) => (i === 2 ? JSON.stringify({ ...e, decision: "block" }) : l)));
  assert.deepEqual(check(f).slice(0, 2), [1, 3]); assert.match(check(f)[2], /modified/);
  put(f, lines.map((l, i) => (i === 2 ? rehash({ ...e, decision: "block" }) : l)));
  assert.deepEqual(check(f).slice(0, 2), [1, 3]); assert.match(check(f)[2], /MAC does not verify/);
  const parsed = rows(f).map(l => JSON.parse(l));
  assert.equal(verifyChain(parsed), true, "without the key, a recomputed SHA-256 passes");
  assert.equal(verifyChain(parsed, KEY), false);
  put(f, [...lines, rehash({ ...JSON.parse(lines[4]), seq: 6, prev: JSON.parse(lines[4]).mac, mac: "0".repeat(64) })]);   // forged entry appended
  assert.deepEqual(check(f).slice(0, 2), [1, 6]); assert.match(check(f)[2], /MAC does not verify/);
});

test("delete: a line removed from the middle, the start or the end is detected", () => {
  const f = log(5); const lines = rows(f);
  put(f, lines.filter((_, i) => i !== 2));
  assert.deepEqual(check(f).slice(0, 2), [1, 3]); assert.match(check(f)[2], /out of sequence|does not follow/);
  put(f, lines.slice(1));
  assert.deepEqual(check(f).slice(0, 2), [1, 1]); assert.match(check(f)[2], /does not start with a keyed segment entry/);
  put(f, lines.slice(0, 4));
  assert.deepEqual(check(f), [1, 5, "truncated: the tail marker certifies seq 5, the log ends at seq 4"]);
});

test("reorder: swapped lines are detected", () => {
  const f = log(5); const lines = rows(f);
  put(f, [lines[0], lines[2], lines[1], lines[3], lines[4]]);
  assert.deepEqual(check(f).slice(0, 2), [1, 2]); assert.match(check(f)[2], /out of sequence|does not follow/);
  put(f, [...lines.slice(0, 3), lines[4], lines[3]]);
  assert.deepEqual(check(f).slice(0, 2), [1, 4]);
});

test("truncate: lines removed from the end are detected by the signed tail marker, and a writer appending afterward keeps the evidence", () => {
  const f = log(5); const lines = rows(f);
  put(f, lines.slice(0, 3));
  assert.deepEqual(check(f), [1, 4, "truncated: the tail marker certifies seq 5, the log ends at seq 3"]);
  const e = new AuditLog(f, { key: KEY }).append(entry(6));                                // a proxy writes next: no silent re-anchoring
  assert.equal(e.segment, "hmac-sha256/v1"); assert.match(e.anomaly!, /ends at seq 3 but its tail marker certifies seq 5/);
  assert.deepEqual(check(f).slice(0, 2), [1, 4]); assert.match(check(f)[2], /no longer matched its tail marker/);
  const cut = log(3); writeFileSync(cut, readFileSync(cut).subarray(0, -10));                // cut in the middle of the last line
  assert.deepEqual(check(cut).slice(0, 2), [1, 3]); assert.match(check(cut)[2], /incomplete last line/);
  const noTail = log(3); unlinkSync(auditTailPath(noTail));
  assert.deepEqual(check(noTail), [1, 4, "the tail marker is missing: lines removed from the end cannot be ruled out"]);
  const forged = log(3); put(forged, rows(forged).slice(0, 2));
  const t = JSON.parse(readFileSync(auditTailPath(forged), "utf8")); writeFileSync(auditTailPath(forged), JSON.stringify({ ...t, seq: 2, link: JSON.parse(rows(forged)[1]).mac }));
  assert.deepEqual(check(forged).slice(0, 2), [1, 3]); assert.match(check(forged)[2], /tail marker does not verify/);
});

test("wrong key: a log never verifies under another key, KYTRAL_AUDIT_SECRET keys the chain when set, and a writer with another key leaves an anomaly", () => {
  const f = log(3);
  assert.deepEqual(check(f, auditKey(OTHER)).slice(0, 2), [1, 1]); assert.match(check(f, auditKey(OTHER))[2], /MAC does not verify: modified, forged, or written with another key/);
  assert.equal(verifyChain(rows(f).map(l => JSON.parse(l)), auditKey(OTHER)), false);
  process.env.KYTRAL_AUDIT_SECRET = OTHER;
  try { assert.deepEqual(auditKey(S), deriveKey(OTHER, "audit/v1"), "KYTRAL_AUDIT_SECRET takes precedence over the proxy secret"); }
  finally { delete process.env.KYTRAL_AUDIT_SECRET; }
  const e = new AuditLog(f, { key: auditKey(OTHER) }).append(entry(4));
  assert.match(e.anomaly!, /tail marker does not verify/);
  assert.deepEqual(check(f).slice(0, 2), [1, 4], "verified with the first key: line 4 was written with another one");
});

test("legacy: an old SHA-256 log is reported as legacy and unverified, never valid; new entries start a marked HMAC segment that binds it", () => {
  const f = join(tmp(), "audit.jsonl"); let prev = "GENESIS"; const old: string[] = [];
  for (let i = 1; i <= 3; i++) { const base = { ts: new Date().toISOString(), ...entry(i), prev }; prev = sha(JSON.stringify(base)); old.push(JSON.stringify({ ...base, hash: prev })); }
  put(f, old);                                                                                // written by the previous version: unkeyed SHA-256 chain
  let r = verifyAuditFile(f, KEY);
  assert.deepEqual([r.exitCode, r.legacy, r.hmac, r.broken], [3, 3, 0, undefined]);
  assert.equal(verifyChain(old.map(l => JSON.parse(l)), KEY), false, "never valid with the key");
  const e = new AuditLog(f, { key: KEY }).append(entry(4));
  assert.deepEqual([e.segment, e.legacy?.lines, e.legacy?.sha256, e.anomaly, e.prev], ["hmac-sha256/v1", 3, sha(old.map(l => `${l}\n`).join("")), undefined, prev]);
  r = verifyAuditFile(f, KEY);
  assert.deepEqual([r.exitCode, r.legacy, r.hmac], [3, 3, 1], "the HMAC part verifies, the legacy lines stay unverified");
  const lines = rows(f);
  put(f, [JSON.stringify({ ...JSON.parse(lines[0]), decision: "block" }), ...lines.slice(1)]);
  assert.deepEqual(check(f).slice(0, 2), [1, 4]); assert.match(check(f)[2], /3 legacy line\(s\) before the HMAC chain were changed after it started/);
  // a log stripped of its MACs (downgraded to the old format) is never valid either
  const g = log(3); let p = "GENESIS";
  put(g, rows(g).map(l => { const { ts, agentId, tool, decision } = JSON.parse(l), base = { ts, agentId, tool, decision, prev: p }; p = sha(JSON.stringify(base)); return JSON.stringify({ ...base, hash: p }); }));
  assert.equal(check(g)[0], 1, "with its tail marker: the HMAC entries are gone");
  unlinkSync(auditTailPath(g)); assert.equal(check(g)[0], 3, "without it: legacy, unverified");
});

test("entries written without the key (kill or known remove without a secret) stay in the chain but are never valid", () => {
  const f = log(2);
  const e = new AuditLog(f).append({ agentId: "*", tool: "*", decision: "kill", approver: "alice" });
  assert.deepEqual([e.unauthenticated, e.seq, e.mac], [true, 3, undefined]);
  let r = verifyAuditFile(f, KEY); assert.deepEqual([r.exitCode, r.unauthenticated, r.hmac], [3, [3], 2]);
  new AuditLog(f, { key: KEY }).append(entry(4));
  r = verifyAuditFile(f, KEY); assert.deepEqual([r.exitCode, r.unauthenticated, r.hmac, r.tailSeq], [3, [3], 3, 4]);
  const lines = rows(f);
  put(f, lines.filter((_, i) => i !== 2)); assert.deepEqual(check(f).slice(0, 2), [1, 3], "removed");
  put(f, lines.map((l, i) => (i === 2 ? rehash({ ...JSON.parse(l), approver: "mallory" }) : l))); assert.deepEqual(check(f).slice(0, 2), [1, 4], "changed");
});

test("concurrent writers (proxies and the CLI) extend one valid HMAC chain under the lock", { timeout: 120000 }, async () => {
  const home = tmp(); const f = join(home, "audit.jsonl"); const N = 5, PER = 15;
  const env: NodeJS.ProcessEnv = { ...process.env, KYTRAL_SECRET: S, KYTRAL_HOME: home, KYTRAL_AUDIT: f }; delete env.KYTRAL_AUDIT_SECRET;
  const run = (args: string[]) => new Promise<number>(r => spawn(process.execPath, args, { cwd: ROOT, env, stdio: ["ignore", "ignore", "inherit"] }).on("exit", c => r(c ?? 1)));
  const code = `import { AuditLog, auditKey } from ${JSON.stringify(pathToFileURL(join(ROOT, "src/audit.ts")).href)};
    const log = new AuditLog(process.argv[1], { key: auditKey(process.env.KYTRAL_SECRET) });
    for (let i = 0; i < ${PER}; i++) log.append({ agentId: "p" + process.argv[2], tool: "t" + i, decision: "allow" });`;
  const writers = Array.from({ length: N }, (_, k) => run(["--import", "tsx", "--input-type=module", "-e", code, f, String(k)]));
  const cli = (async () => { const codes = []; for (const c of ["kill", "resume", "kill", "resume"]) codes.push(await run(["--import", "tsx", join(ROOT, "src/cli.ts"), c, "--by", "ops"])); return codes; })();
  assert.deepEqual(await Promise.all(writers), Array(N).fill(0)); assert.deepEqual(await cli, [0, 0, 0, 0]);
  const r = verifyAuditFile(f, KEY);
  assert.equal(r.exitCode, 0, JSON.stringify(r.broken)); assert.deepEqual([r.lines, r.hmac, r.tailSeq], [N * PER + 4, N * PER + 4, N * PER + 4]);
  assert.deepEqual(rows(f).map(l => JSON.parse(l).decision).filter(d => d !== "allow"), ["kill", "resume", "kill", "resume"]);
});

test("the Guard keys an AuditLog given without a key with the deployment key (KYTRAL_AUDIT_SECRET when set)", async () => {
  const run = async (f: string) => {
    const g = new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null, audit: new AuditLog(f) });
    const badge = issueBadge(S, "agent-a", ["*"], 60, Date.now(), { aud: AUD });
    await g.check(badge, { tool: "read_file", args: {} }); await assert.rejects(g.check(badge, { tool: "shell", args: { cmd: "rm -rf /" } }));
    return g;
  };
  const f = join(tmp(), "audit.jsonl"), g = await run(f);
  assert.equal(check(f)[0], 0); assert.ok(verifyChain(g.audit.entries, KEY));
  process.env.KYTRAL_AUDIT_SECRET = OTHER;
  try { const f2 = join(tmp(), "audit.jsonl"); await run(f2); assert.equal(check(f2, deriveKey(OTHER, "audit/v1"))[0], 0); assert.equal(check(f2, deriveKey(S, "audit/v1"))[0], 1); }
  finally { delete process.env.KYTRAL_AUDIT_SECRET; }
});

test("CLI: audit verify reports the first broken line; exit 0 valid, 1 broken, 3 unverifiable, 2 without a usable key", { timeout: 120000 }, () => {
  const f = log(3);
  const cli = (env: Record<string, string | undefined>, ...a: string[]) => {
    const e: Record<string, string | undefined> = { ...process.env, KYTRAL_SECRET: S, KYTRAL_AUDIT: f, KYTRAL_AUDIT_SECRET: undefined, ...env };
    for (const k of Object.keys(e)) if (e[k] === undefined) delete e[k];
    return spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "audit", "verify", ...a], { cwd: ROOT, env: e as NodeJS.ProcessEnv, encoding: "utf8" });
  };
  let r = cli({}); assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /OK: nothing modified, deleted, reordered or truncated \(tail marker: seq 3\)/);
  const lines = rows(f); put(f, [lines[0], lines[2]]);
  r = cli({}); assert.equal(r.status, 1); assert.match(r.stdout, /BROKEN at line 2: out of sequence/);
  put(f, lines.slice(0, 2));
  r = cli({}); assert.equal(r.status, 1); assert.match(r.stdout, /BROKEN at the end of the log \(after line 2\): truncated/);
  put(f, lines); assert.equal(cli({ KYTRAL_SECRET: OTHER }).status, 1, "another key");
  const legacy = join(tmp(), "old.jsonl"); new AuditLog(legacy).append(entry(1));                // written without a key: legacy format
  r = cli({}, legacy); assert.equal(r.status, 3); assert.match(r.stdout, /UNVERIFIED: .*lines 1-1 are legacy SHA-256 entries/);
  for (const [env, why] of [[{ KYTRAL_SECRET: undefined }, /KYTRAL_SECRET is missing/], [{ KYTRAL_AUDIT_SECRET: "weak" }, /KYTRAL_AUDIT_SECRET too short/]] as const) {
    r = cli(env); assert.equal(r.status, 2, JSON.stringify(env)); assert.match(r.stderr, why);
  }
  assert.equal(cli({}, "a", "b").status, 2, "usage");
});

test("the tail marker is written with mode 0600", { skip: process.platform === "win32" && "POSIX file modes" }, () => {
  const f = log(1); assert.equal(statSync(auditTailPath(f)).mode & 0o777, 0o600); assert.equal(statSync(f).mode & 0o777, 0o600);
});

test("a log larger than what is read at once: lines across chunks, a broken line in the middle with the number of lines, legacy bytes hashed as read", () => {
  // about 3 MB with 1 MB reads: entries of a few KB, so that many lines straddle two reads
  const f = join(tmp(), "audit.jsonl"); let prev = "GENESIS"; const old: string[] = [];
  for (let i = 1; i <= 400; i++) { const base = { ts: new Date().toISOString(), ...entry(i), reason: "x".repeat(1000 + (i % 7) * 333), prev }; prev = sha(JSON.stringify(base)); old.push(JSON.stringify({ ...base, hash: prev })); }
  put(f, old);   // legacy lines over the first read, then the HMAC chain
  const l = new AuditLog(f, { key: KEY });
  for (let i = 1; i <= 700; i++) l.append({ ...entry(i), reason: "y".repeat(2000 + (i % 11) * 97) });
  assert.ok(statSync(f).size > 2.5 * (1 << 20), "more than two reads");
  let r = verifyAuditFile(f, KEY);
  assert.deepEqual([r.exitCode, r.lines, r.legacy, r.hmac, r.tailSeq, r.broken], [3, 1100, 400, 700, 700, undefined]);
  // one entry changed in the middle: that line, and the number of lines of the whole log
  const lines = rows(f), i = 777;
  put(f, [...lines.slice(0, i), rehash({ ...JSON.parse(lines[i]), decision: "block" }), ...lines.slice(i + 1)]);
  r = verifyAuditFile(f, KEY);
  assert.deepEqual([r.exitCode, r.broken?.line, r.lines], [1, i + 1, 1100]); assert.match(r.broken!.why, /MAC does not verify/);
  // a legacy line changed, far before the HMAC chain starts: the hash of the legacy bytes no longer matches
  put(f, [...lines.slice(0, 3), JSON.stringify({ ...JSON.parse(lines[3]), tool: "rm" }), ...lines.slice(4)]);
  assert.deepEqual(check(f).slice(0, 2), [1, 401]); assert.match(check(f)[2], /400 legacy line\(s\) before the HMAC chain were changed/);
  // cut in the middle of a line: reported first, as the line after the last complete one
  writeFileSync(f, lines.join("\n") + "\n" + lines[5].slice(0, 100));
  assert.deepEqual(check(f).slice(0, 2), [1, 1101]); assert.match(check(f)[2], /incomplete last line/);
});
