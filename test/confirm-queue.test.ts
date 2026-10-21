// Confirmation queue (proxy mode): approve = this call only (bound to argsHash), approve_always = known-tools grant
// (unknown-tool rule only), deny, timeout, kill switch, forged or misdirected files. Anything but a valid decision is a refusal.
import { test } from "node:test"; import assert from "node:assert/strict";
import { createHmac } from "node:crypto"; import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, statSync, utimesSync, writeFileSync } from "node:fs"; import { hostname, tmpdir } from "node:os"; import { join, resolve } from "node:path";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge, knownKey, FileConfirmQueue, ConfirmError, listRequests, decide, argsHash, canonicalJson, confirmKey, ARGS_SHOWN } from "../src/index.js";
const ROOT = resolve(import.meta.dirname, "..");
const S = "8d2f6a1c9e4b7035d2a8f6c1e9b4d703a5f8c2e6b1d9a4f7c3e5b2d8a6f1c9e4"; const AUD = "kytral-guard:queue-test";
const bd = (agent = "agent-a") => issueBadge(S, agent, ["*"], 60, Date.now(), { aud: AUD });
const tmp = () => mkdtempSync(join(tmpdir(), "kg-queue-"));
function setup(o: Record<string, unknown> = {}, timeoutMs = 10000) {
  const dir = join(tmp(), "confirmations");
  const g = new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null,
    confirmQueue: new FileConfirmQueue({ secret: S, dir, timeoutMs, pollMs: 5 }), ...o });
  return { g, dir };
}
/** The single pending request (its file is written as soon as check() is called). */
function pendingOf(dir: string) { const { requests } = listRequests(S, dir); assert.equal(requests.length, 1, "one pending request"); return requests[0]; }
/** Signs like the CLI does, but without its checks: what an attacker or a buggy tool holding a key could write, for the queue `dir`. */
const signedFile = (secret: string, kind: "request" | "decision", body: object, dir: string) =>
  JSON.stringify({ ...body, sig: createHmac("sha256", confirmKey(secret, dir)).update(`${kind}\n${canonicalJson(body)}`).digest("base64url") });

test("approve is for this call only, bound to its arguments; the next call is asked again", async () => {
  const { g, dir } = setup();
  const p = g.check(bd(), { tool: "mystery", args: { b: 1, a: "x" } });
  const r = pendingOf(dir);
  assert.deepEqual([r.tool, r.agentId, r.server, r.rule, r.always], ["mystery", "agent-a", AUD, "unknown-tool", true]);
  assert.equal(r.argsHash, argsHash({ a: "x", b: 1 }), "canonical JSON: key order does not matter");
  assert.equal(r.args, '{"a":"x","b":1}', "the human sees the arguments");
  decide(S, r.id, "approve", "alice", dir);
  await p;
  assert.deepEqual([g.audit.entries.at(-1)!.decision, g.audit.entries.at(-1)!.approver], ["confirmed", "alice"]);
  assert.deepEqual(readdirSync(dir), [], "request and decision files are removed");
  const p2 = g.check(bd(), { tool: "mystery", args: { b: 1, a: "x" } });
  const r2 = pendingOf(dir); assert.notEqual(r2.id, r.id);
  decide(S, r2.id, "deny", "alice", dir);
  await assert.rejects(p2, /confirmation refused/);
});

test("approve_always adds the exact tool for this agent to known-tools.json, with who and when; later calls are not queued", async () => {
  const { g, dir } = setup({ knownToolsFile: join(tmp(), "known-tools.json") });
  const p = g.check(bd(), { tool: "mystery", args: {} });
  decide(S, pendingOf(dir).id, "approve_always", "alice (os:ops)", dir);
  await p;
  const add = g.audit.entries.find(e => e.decision === "known-add")!;
  assert.deepEqual([add.tool, add.agentId, add.server, add.rule, add.approver], ["mystery", "agent-a", AUD, "unknown-tool", "alice (os:ops)"]);
  assert.equal(g.audit.entries.at(-1)!.decision, "confirmed-always");
  await g.check(bd(), { tool: "mystery", args: { other: "arguments" } });
  assert.equal(listRequests(S, dir).requests.length, 0, "known now: nothing queued");
  assert.equal(g.audit.entries.at(-1)!.rule, "known-tool");
  const p2 = g.check(bd("agent-b"), { tool: "mystery", args: {} });                   // another agent is still asked
  decide(S, pendingOf(dir).id, "deny", "alice", dir);
  await assert.rejects(p2, /confirmation refused/);
});

test("--always is refused when the confirmation does not come from the unknown-tool rule (CLI side and proxy side)", async () => {
  const { g, dir } = setup({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n") });
  const p = g.check(bd(), { tool: "delete_file", args: { path: "/srv/x" } });
  const r = pendingOf(dir);
  assert.deepEqual([r.rule, r.always], ["delete-files-or-backups", false]);
  assert.throws(() => decide(S, r.id, "approve_always", "alice", dir), (e: any) => e instanceof ConfirmError && e.exitCode === 2 && /--always is not allowed/.test(e.message));
  // a correctly signed approve_always written without the CLI's check is still refused by the proxy
  writeFileSync(join(dir, `${r.id}.decision.json`), signedFile(S, "decision", { v: 1, id: r.id, verdict: "approve_always", argsHash: r.argsHash, approver: "mallory", decidedAt: new Date().toISOString() }, dir));
  await assert.rejects(p, /confirmation refused/);
  assert.ok(g.audit.entries.some(e => e.decision === "confirm-invalid" && /only valid for the unknown-tool rule/.test(e.rule!)));
  for (const t of ["run_query", "stripe", "send_email"]) {                             // money transfer, mass e-mail: same
    const args = t === "stripe" ? { op: "payout" } : t === "send_email" ? { to: Array(30).fill("a@b.c") } : { sql: "CALL purge()" };
    const p2 = g.check(bd(), { tool: t, args }); const r2 = pendingOf(dir);
    assert.equal(r2.always, false, t);
    assert.throws(() => decide(S, r2.id, "approve_always", "alice", dir), /--always is not allowed/, t);
    decide(S, r2.id, "deny", "alice", dir); await assert.rejects(p2, /refused/);
  }
});

test("a forged, foreign-key, misdirected or unreadable decision is a refusal, journaled as confirm-invalid", async () => {
  const cases: [string, (r: any, dir: string) => string][] = [
    ["bad signature", r => JSON.stringify({ v: 1, id: r.id, verdict: "approve", argsHash: r.argsHash, approver: "x", decidedAt: "now", sig: "forged" })],
    ["other secret", (r, dir) => signedFile("f4a8c2e6b0d4f8a2c6e0b4d8f2a6c0e4b8d2f6a0c4e8b2d6f0a4c8e2b6d0f4a8", "decision", { v: 1, id: r.id, verdict: "approve", argsHash: r.argsHash, approver: "x", decidedAt: "now" }, dir)],
    ["other arguments", (r, dir) => signedFile(S, "decision", { v: 1, id: r.id, verdict: "approve", argsHash: argsHash({ path: "/" }), approver: "x", decidedAt: "now" }, dir)],
    ["other request", (r, dir) => signedFile(S, "decision", { v: 1, id: "f".repeat(32), verdict: "approve", argsHash: r.argsHash, approver: "x", decidedAt: "now" }, dir)],
    ["no approver", (r, dir) => signedFile(S, "decision", { v: 1, id: r.id, verdict: "approve", argsHash: r.argsHash, approver: "", decidedAt: "now" }, dir)],
    ["not JSON", () => "{approve"],
  ];
  for (const [label, content] of cases) {
    const { g, dir } = setup();
    const p = g.check(bd(), { tool: "mystery", args: { path: "/tmp/a" } });
    const r = pendingOf(dir);
    writeFileSync(join(dir, `${r.id}.decision.json`), content(r, dir));
    await assert.rejects(p, /confirmation refused/, label);
    assert.ok(g.audit.entries.some(e => e.decision === "confirm-invalid"), label);
    assert.ok(!g.audit.entries.some(e => e.decision === "confirmed"), label);
  }
});

test("no answer before the timeout is a refusal (not journaled as invalid) and the files are removed", async () => {
  const { g, dir } = setup({}, 150);
  const t0 = Date.now();
  await assert.rejects(g.check(bd(), { tool: "mystery", args: {} }), /confirmation refused/);
  assert.ok(Date.now() - t0 >= 140);
  assert.deepEqual(readdirSync(dir), []);
  assert.ok(!g.audit.entries.some(e => e.decision === "confirm-invalid"));
});

test("the kill switch refuses a pending request at once, even with an approve_always already written; nothing is recorded", async () => {
  const f = join(tmp(), "known-tools.json");
  const { g, dir } = setup({ knownToolsFile: f }, 30000);
  const p = g.check(bd(), { tool: "mystery", args: {} });
  const r = pendingOf(dir); const t0 = Date.now();
  decide(S, r.id, "approve_always", "alice", dir); g.kill();                           // both before the next poll
  await assert.rejects(p, /confirmation refused/);
  assert.ok(Date.now() - t0 < 5000, "does not wait for the timeout");
  assert.equal(g.knownTools.has(knownKey(AUD, "mystery", "agent-a")), false);
  assert.ok(!g.audit.entries.some(e => e.decision === "known-add" || e.decision === "confirmed-always"));
  const { g: g2, dir: dir2 } = setup({}, 30000);
  const p2 = g2.check(bd(), { tool: "mystery", args: {} }); const r2 = pendingOf(dir2); const t1 = Date.now();
  g2.kill();
  await assert.rejects(p2, /confirmation refused/);
  assert.ok(Date.now() - t1 < 5000, "no answer needed: the kill switch ends the wait");
  assert.throws(() => decide(S, r2.id, "approve", "alice", dir2), /no pending request/, "the request is withdrawn");
});

test("decide validates the id (no path traversal), the signature, expiry and uniqueness of the answer", async () => {
  const { g, dir } = setup();
  for (const bad of ["../../etc/passwd", "ABC", "0".repeat(31), `${"0".repeat(32)}/../x`]) assert.throws(() => decide(S, bad, "approve", "x", dir), (e: any) => e.exitCode === 2, bad);
  assert.throws(() => decide(S, "0".repeat(32), "approve", "x", dir), (e: any) => e.exitCode === 1 && /no pending request/.test(e.message));
  assert.throws(() => decide(S, "0".repeat(32), "yes" as any, "x", dir), (e: any) => e.exitCode === 2);
  const p = g.check(bd(), { tool: "mystery", args: {} }); const r = pendingOf(dir);
  assert.throws(() => decide("f4a8c2e6b0d4f8a2c6e0b4d8f2a6c0e4b8d2f6a0c4e8b2d6f0a4c8e2b6d0f4a8", r.id, "approve", "x", dir), /no pending request/, "requests are verified with the secret");
  decide(S, r.id, "deny", "x", dir);
  assert.throws(() => decide(S, r.id, "approve", "x", dir), (e: any) => e.exitCode === 1 && /already answered/.test(e.message), "the first decision wins");
  await assert.rejects(p, /refused/);
  const id = "a".repeat(32), old = { v: 1, id, server: AUD, agentId: "agent-a", tool: "t", rule: "unknown-tool", reason: "r", argsHash: argsHash({}), args: "{}", always: true, createdAt: "2026-01-01T00:00:00.000Z", expiresAt: "2026-01-01T00:01:00.000Z", pid: 1 };
  writeFileSync(join(dir, `${id}.request.json`), signedFile(S, "request", old, dir));   // left behind by a crashed proxy
  assert.throws(() => decide(S, id, "approve", "x", dir), /expired/);
  writeFileSync(join(dir, `${"b".repeat(32)}.request.json`), JSON.stringify({ ...old, id: "b".repeat(32), sig: "forged" }));
  assert.deepEqual(listRequests(S, dir).invalid, [`${"b".repeat(32)}.request.json`]);
  assert.throws(() => decide(S, "b".repeat(32), "approve", "x", dir), /no pending request/);
});

test("long arguments: the request keeps them whole; approving them needs full (--full), refusing does not", async () => {
  const { g, dir } = setup();
  const big = { blob: "x".repeat(ARGS_SHOWN + 500) };
  const p = g.check(bd(), { tool: "mystery", args: big });
  const r = pendingOf(dir);
  assert.equal(r.args, canonicalJson(big), "complete arguments in the request"); assert.equal(r.argsHash, argsHash(big));
  for (const v of ["approve", "approve_always"] as const)
    assert.throws(() => decide(S, r.id, v, "alice", dir), (e: any) => e instanceof ConfirmError && e.exitCode === 2 && /confirm list --full/.test(e.message), v);
  decide(S, r.id, "approve", "alice", dir, { full: true });
  await p;
  const p2 = g.check(bd(), { tool: "mystery", args: big });
  decide(S, pendingOf(dir).id, "deny", "alice", dir);
  await assert.rejects(p2, /confirmation refused/);
  const exact = { blob: "y".repeat(ARGS_SHOWN - canonicalJson({ blob: "" }).length) };   // exactly ARGS_SHOWN characters: shown whole
  const p3 = g.check(bd(), { tool: "mystery", args: exact });
  const r3 = pendingOf(dir); assert.equal(r3.args.length, ARGS_SHOWN);
  decide(S, r3.id, "approve", "alice", dir); await p3;
});

test("the confirmations directory is 0700, also when it existed with wider permissions", { skip: process.platform === "win32" && "POSIX file modes" }, () => {
  const fresh = join(tmp(), "confirmations"); new FileConfirmQueue({ secret: S, dir: fresh });
  assert.equal(statSync(fresh).mode & 0o777, 0o700);
  const wide = join(tmp(), "wide"); mkdirSync(wide); chmodSync(wide, 0o755);
  new FileConfirmQueue({ secret: S, dir: wide });
  assert.equal(statSync(wide).mode & 0o777, 0o700);
});

test("startup removes orphaned requests (expired, or left by a stopped proxy of this host) and stray files; live and unverifiable ones stay", () => {
  const dir = join(tmp(), "confirmations"); mkdirSync(dir);
  const now = Date.now(), gone = 2 ** 30 + 7;                                            // a pid no system uses (Linux max 2^22, Windows pids are multiples of 4)
  const req = (id: string, o: object = {}) => ({ v: 1, id, server: AUD, agentId: "agent-a", tool: "t", rule: "unknown-tool", reason: "r", argsHash: argsHash({}), args: "{}", always: true,
    createdAt: new Date(now).toISOString(), expiresAt: new Date(now + 60000).toISOString(), pid: process.pid, host: hostname(), ...o });
  const put = (name: string, content: string) => writeFileSync(join(dir, name), content);
  const [expired, stopped, live, elsewhere, forged, answered] = ["1", "2", "3", "4", "5", "6"].map(c => c.repeat(32));
  put(`${expired}.request.json`, signedFile(S, "request", req(expired, { expiresAt: new Date(now - 1000).toISOString() }), dir));
  put(`${expired}.decision.json`, "{}");
  put(`${stopped}.request.json`, signedFile(S, "request", req(stopped, { pid: gone }), dir));
  put(`${live}.request.json`, signedFile(S, "request", req(live), dir));
  put(`${elsewhere}.request.json`, signedFile(S, "request", req(elsewhere, { pid: gone, host: "another-host" }), dir));   // not ours to judge before it expires
  put(`${forged}.request.json`, JSON.stringify({ ...req(forged, { expiresAt: new Date(now - 1000).toISOString() }), sig: "forged" }));
  put(`${answered}.decision.json`, "{}");                                                 // its request is gone
  put("stale.tmp", "x"); utimesSync(join(dir, "stale.tmp"), new Date(now - 120000), new Date(now - 120000));
  put("recent.tmp", "x");
  const q = new FileConfirmQueue({ secret: S, dir });
  assert.equal(q.orphansRemoved, 2);
  assert.deepEqual(readdirSync(dir).sort(), [`${live}.request.json`, `${elsewhere}.request.json`, `${forged}.request.json`, "recent.tmp"].sort());
});

test("arguments are hashed canonically; non-JSON arguments are refused", async () => {
  assert.equal(canonicalJson({ b: [{ d: 1, c: 2 }], a: null }), '{"a":null,"b":[{"c":2,"d":1}]}');
  assert.equal(argsHash({ x: 1, y: [1, 2] }), argsHash({ y: [1, 2], x: 1 }));
  assert.notEqual(argsHash({ y: [1, 2] }), argsHash({ y: [2, 1] }));
  const { g, dir } = setup();
  await assert.rejects(g.check(bd(), { tool: "mystery", args: { n: 10n } as any }), /confirmation refused/);
  assert.deepEqual(readdirSync(dir), []);
  assert.ok(g.audit.entries.some(e => e.decision === "confirm-invalid"));
});

test("CLI: confirm list shows the call (control characters escaped); approve --always / deny; secret required", { timeout: 120000 }, async () => {
  const { g, dir } = setup({ knownToolsFile: join(tmp(), "known-tools.json") }, 60000);   // each CLI run starts tsx (~1 s)
  const env = { ...process.env, KYTRAL_CONFIRMATIONS: dir, KYTRAL_SECRET: S };
  const cli = (e: NodeJS.ProcessEnv, ...a: string[]) => spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...a], { env: e, encoding: "utf8" });
  const p = g.check(bd(), { tool: "mystery", args: { note: "ok\u001b[2K\u202etxt.exe" } });
  const r = pendingOf(dir);
  const list = cli(env, "confirm", "list");
  assert.equal(list.status, 0);
  assert.match(list.stdout, new RegExp(`^${r.id}\\ttool=mystery\\tagent=agent-a\\tserver=${AUD}\\trule=unknown-tool\\tchoices=once,always,deny\\t`, "m"));
  assert.ok(!/[\u001b\u202e]/.test(list.stdout), "no raw escape or bidi character reaches the terminal");
  const noSecret = { ...env }; delete noSecret.KYTRAL_SECRET; delete noSecret.KYTRAL_AUDIT_SECRET;
  assert.equal(cli(noSecret, "confirm", "approve", r.id).status, 2);
  assert.equal(cli(env, "confirm", "approve", r.id, "--bogus").status, 2);
  const ok = cli(env, "confirm", "approve", r.id, "--always", "--by", "alice");
  assert.equal(ok.status, 0, ok.stderr); assert.match(ok.stdout, /^approve_always\t/);
  await p;
  assert.match(g.audit.entries.find(e => e.decision === "known-add")!.approver!, /^alice \(os:.+\)$/);
  const p2 = g.check(bd(), { tool: "\u001b[31mevil", args: {} });
  const r2 = pendingOf(dir);
  const list2 = cli(env, "confirm", "list").stdout;
  assert.ok(list2.includes("tool=\\u001b[31mevil") && !list2.includes("\u001b"), "tool names are escaped too");
  assert.equal(r2.always, false, "not a plain name: no 'always'");
  const denied = cli(env, "confirm", "approve", r2.id, "--always");
  assert.equal(denied.status, 2); assert.match(denied.stderr, /--always is not allowed for this request \(rule 'unknown-tool'\)/);
  assert.equal(cli(env, "confirm", "deny", r2.id).status, 0);
  await assert.rejects(p2, /refused/);
});

test("CLI: truncated arguments are flagged; confirm list --full shows them all; approve needs --full", { timeout: 120000 }, async () => {
  const { g, dir } = setup({}, 60000);
  const env = { ...process.env, KYTRAL_CONFIRMATIONS: dir, KYTRAL_SECRET: S };
  const cli = (...a: string[]) => spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...a], { env, encoding: "utf8" });
  const p = g.check(bd(), { tool: "mystery", args: { a: "x".repeat(ARGS_SHOWN), b: "HIDDEN-TAIL" } });   // canonical order: the tail comes last
  const r = pendingOf(dir);
  const short = cli("confirm", "list");
  assert.equal(short.status, 0, short.stderr);
  assert.ok(short.stdout.includes(`ARGUMENTS TRUNCATED: first ${ARGS_SHOWN} of ${r.args.length} characters shown`));
  assert.ok(!short.stdout.includes("HIDDEN-TAIL"), "the cut part is not shown");
  const full = cli("confirm", "list", "--full");
  assert.ok(full.stdout.includes("HIDDEN-TAIL") && !full.stdout.includes("TRUNCATED"));
  const refused = cli("confirm", "approve", r.id);
  assert.equal(refused.status, 2); assert.match(refused.stderr, /confirm list --full/);
  const ok = cli("confirm", "approve", r.id, "--full");
  assert.equal(ok.status, 0, ok.stderr);
  await p;
});

test("proxy refuses to start with an invalid KYTRAL_CONFIRM_TIMEOUT_MS", () => {
  for (const t of ["abc", "0", "-5", "1.5"]) {
    const r = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "--", process.execPath, "-e", "0"],
      { env: { ...process.env, KYTRAL_SECRET: "9f2c4e7a1b3d5f60718293a4b5c6d7e8f9012a3b4c5d6e7f8091a2b3c4d5e6f7", KYTRAL_AUDIENCE: AUD, KYTRAL_HOME: tmp(), KYTRAL_CONFIRM_QUEUE: "1", KYTRAL_CONFIRM_TIMEOUT_MS: t }, encoding: "utf8" });
    assert.equal(r.status, 2, t); assert.match(r.stderr, /refusing to start: confirmation timeout/, t);
  }
});
