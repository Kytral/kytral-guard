// "Allow once" vs "always allow" for unknown tools (known-tools.json): acceptance tests.
// once != always; always never beats an explicit block/confirm rule; a corrupt file falls back to confirm (fail closed);
// the kill switch wins; the audit records who approved and when; `known remove` revokes immediately.
import { test } from "node:test"; import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process"; import { existsSync, mkdtempSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path"; import { pathToFileURL } from "node:url";
import { AuditLog, Guard, loadPolicy, DEFAULT_POLICY, issueBadge, knownKey, parseGrant, verifyChain } from "../src/index.js";
const ROOT = resolve(import.meta.dirname, "..");
const S = "3b9e1f7a5c2d8046b1e9f3a7c5d20864e1b7f9a3c5d2e8604b1f7a9e3c5d2b86"; const AUD = "kytral-guard:always-test";
const bd = (agent = "agent-a") => issueBadge(S, agent, ["*"], 60, Date.now(), { aud: AUD });
const tmp = () => mkdtempSync(join(tmpdir(), "kg-always-"));
const mk = (o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null, ...o });
const call = (tool: string, args: Record<string, unknown> = {}) => ({ tool, args });
/** "always" must name its approver (a bare "always" is refused). */
const ALWAYS = { choice: "always", approver: "qa" } as const;
const lines = (f: string) => readFileSync(f, "utf8").trim().split("\n").map(l => JSON.parse(l));
/** A scripted human: answers in order (then "deny") and records every question. */
function human(...answers: unknown[]) {
  const asked: { tool: string; rule?: string; choices: string }[] = [];
  return Object.assign(async (c: any, d: any, ctx: any) => { asked.push({ tool: c.tool, rule: d.rule, choices: ctx.choices.join("/") }); return answers.length ? answers.shift() : "deny"; }, { asked });
}

test("once and always differ: once asks again on every call and writes nothing; always asks once and survives a restart", async () => {
  const f = join(tmp(), "known-tools.json");
  const h = human("once", "deny");
  const g = mk({ knownToolsFile: f, confirm: h });
  await g.check(bd(), call("mystery"));
  await assert.rejects(g.check(bd(), call("mystery")), /confirmation refused/, "once is for one call only");
  assert.equal(h.asked.length, 2); assert.equal(existsSync(f), false, "once records nothing");
  const h2 = human({ choice: "always", approver: "alice" });
  const g2 = mk({ knownToolsFile: f, confirm: h2 });
  await g2.check(bd(), call("mystery")); await g2.check(bd(), call("mystery"));
  assert.equal(h2.asked.length, 1, "always: asked only the first time");
  assert.deepEqual(h2.asked[0], { tool: "mystery", rule: "unknown-tool", choices: "once/always/deny" });
  await mk({ knownToolsFile: f }).check(bd(), call("mystery"));                       // restarted proxy, no confirmer at all
  await assert.rejects(mk({ knownToolsFile: f }).check(bd("agent-b"), call("mystery")), /confirmation refused/, "other agent");
});

test("the audit records who approved and when (once, always), and the grant itself is signed with approver and date", async () => {
  const d = tmp(); const f = join(d, "known-tools.json"); const auditFile = join(d, "audit.jsonl"); const t0 = Date.now() - 1000;
  const g = mk({ knownToolsFile: f, audit: new AuditLog(auditFile), confirm: async () => ({ choice: "always", approver: "alice@ops" }) });
  await g.check(bd(), call("mystery"));
  const all = lines(auditFile);
  const add = all.find(e => e.decision === "known-add");
  assert.deepEqual([add.agentId, add.tool, add.rule, add.server, add.approver], ["agent-a", "mystery", "unknown-tool", AUD, "alice@ops"]);
  assert.ok(Date.parse(add.ts) >= t0);
  assert.equal(all.find(e => e.decision === "confirmed-always").approver, "alice@ops");
  assert.ok(verifyChain(all));
  const key = knownKey(AUD, "mystery", "agent-a"); const grant = parseGrant(key, g.knownTools.get(key))!;
  assert.equal(grant.approver, "alice@ops"); assert.ok(Date.parse(grant.approvedAt) >= t0);
  const once = mk({ confirm: async () => ({ choice: "once", approver: "bob" }) }); await once.check(bd(), call("other"));
  assert.deepEqual([once.audit.entries.at(-1)!.decision, once.audit.entries.at(-1)!.approver], ["confirmed", "bob"]);
  const bare = mk({ confirm: async () => "once" }); await bare.check(bd(), call("other"));
  assert.equal(bare.audit.entries.at(-1)!.approver, "unidentified", "a bare answer does not invent a name");
});

test("an SDK 'always' without the approver's name is refused and records nothing; a bare 'once' still works (journaled as unidentified)", async () => {
  const f = join(tmp(), "known-tools.json");
  for (const ans of ["always", { choice: "always" }, { choice: "always", approver: "" }, { choice: "always", approver: "   " }, { choice: "always", approver: "\u0000\u0007" }, { choice: "always", approver: 42 }]) {
    const g = mk({ knownToolsFile: f, confirm: async () => ans });
    await assert.rejects(g.check(bd(), call("mystery")), /'always' needs the approver's name/, JSON.stringify(ans));
    assert.equal(existsSync(f), false, "nothing recorded");
    assert.ok(!g.audit.entries.some(e => e.decision === "known-add" || e.decision === "confirmed-always"));
  }
  const once = mk({ knownToolsFile: f, confirm: async () => "once" }); await once.check(bd(), call("mystery"));
  assert.equal(once.audit.entries.at(-1)!.approver, "unidentified");
  await assert.rejects(mk({ knownToolsFile: f }).check(bd(), call("mystery")), /confirmation refused/, "still unknown after once");
});

test("always never bypasses an explicit block or confirm rule (SQL, shell, transfer, mass e-mail, deletion, policy rules, default: block)", async () => {
  const f = join(tmp(), "known-tools.json");
  const grant = mk({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "alice" }) });
  for (const t of ["run_query", "shell", "stripe", "send_email", "mystery", "mystery2"]) await grant.check(bd(), call(t));   // all granted "always"
  const h = human(ALWAYS, ALWAYS, ALWAYS, ALWAYS);
  const g = mk({ knownToolsFile: f, confirm: h });
  await assert.rejects(g.check(bd(), call("run_query", { sql: "DROP TABLE users" })), /blocked/);
  await assert.rejects(g.check(bd(), call("run_query", { sql: "DELETE FROM users" })), /blocked/);
  await assert.rejects(g.check(bd(), call("shell", { command: "rm -rf /" })), /blocked/);
  await assert.rejects(g.check(bd(), call("stripe", { op: "payout", amount: 500 })), /confirmation refused/);
  await assert.rejects(g.check(bd(), call("send_email", { to: Array(25).fill("x@y.z") })), /confirmation refused/);
  await assert.rejects(g.check(bd(), call("delete_backup", { id: 1 })), /confirmation refused/);
  assert.deepEqual(h.asked.map(q => `${q.tool}:${q.rule}:${q.choices}`),
    ["stripe:money-transfer:once/deny", "send_email:mass-email:once/deny", "delete_backup:delete-files-or-backups:once/deny"], "'always' is never offered there");
  await g.check(bd(), call("run_query", { sql: "SELECT 1" }));                         // the grant still works for harmless calls
  const rules = loadPolicy("default: allow\nrules:\n  - name: no-mystery\n    tool: mystery\n    action: block\n  - name: ask-mystery2\n    tool: mystery2\n    action: confirm\n");
  const h2 = human(ALWAYS);
  const g2 = mk({ policy: rules, knownToolsFile: f, confirm: h2 });
  await assert.rejects(g2.check(bd(), call("mystery")), /blocked: matched rule 'no-mystery'/);
  await assert.rejects(g2.check(bd(), call("mystery2")), /confirmation refused/);
  assert.deepEqual(h2.asked.map(q => q.choices), ["once/deny"]);
  await assert.rejects(mk({ policy: loadPolicy("default: block\nrules: []\n"), knownToolsFile: f }).check(bd(), call("mystery")), /blocked/);
  // the server's destructiveHint still escalates a granted tool, and "always" is not offered for a destructive unknown tool
  const h3 = human(ALWAYS, ALWAYS);
  const g3 = mk({ knownToolsFile: f, confirm: h3 }); g3.destructiveTools.add("mystery"); g3.destructiveTools.add("zap_thing");
  await assert.rejects(g3.check(bd(), call("mystery")), /confirmation refused/);
  await assert.rejects(g3.check(bd(), call("zap_thing")), /confirmation refused/);
  assert.deepEqual(h3.asked.map(q => `${q.rule}:${q.choices}`), ["mcp-destructive-hint:once/deny", "unknown-tool:once/deny"]);
});

test("always stores exact names only: never offered for glob-like or non-ASCII names, and a signed pattern entry is not honored", async () => {
  const f = join(tmp(), "known-tools.json");
  const h = human(ALWAYS, ALWAYS, ALWAYS);
  const g = mk({ knownToolsFile: f, confirm: h });
  for (const t of ["read_*", "my?tool", "mуstery" /* Cyrillic у */]) await assert.rejects(g.check(bd(), call(t)), /confirmation refused/);
  assert.deepEqual(h.asked.map(q => q.choices), ["once/deny", "once/deny", "once/deny"]);
  assert.equal(existsSync(f), false);
  g.knownTools.add(knownKey(AUD, "*", "agent-a"), JSON.stringify({ approver: "x", approvedAt: "y" }));   // validly signed, but a pattern
  await assert.rejects(mk({ knownToolsFile: f }).check(bd(), call("*")), /confirmation refused/);
  await assert.rejects(mk({ knownToolsFile: f }).check(bd(), call("mystery")), /confirmation refused/);
  await mk({ knownToolsFile: f, confirm: async () => ALWAYS }).check(bd(), call("Mystery"));
  await assert.rejects(mk({ knownToolsFile: f }).check(bd(), call("mystery")), /confirmation refused/, "case-sensitive");
});

test("a corrupt known-tools.json falls back to confirm (fail closed), is audited, and is never written over", async () => {
  const f = join(tmp(), "known-tools.json");
  await mk({ knownToolsFile: f, confirm: async () => ALWAYS }).check(bd(), call("mystery"));
  writeFileSync(f, "{corrupt");
  const g = mk({ knownToolsFile: f });                                                  // still starts
  assert.ok(g.audit.entries.some(e => e.decision === "known-tools-corrupt"));
  await assert.rejects(g.check(bd(), call("mystery")), /confirmation refused/, "no grant, no confirmer: refused");
  const h = human("once", ALWAYS);
  const g2 = mk({ knownToolsFile: f, confirm: h });
  await g2.check(bd(), call("mystery"));                                                // asked again; once works
  await assert.rejects(g2.check(bd(), call("mystery")), /'always' could not be recorded/);
  assert.equal(h.asked.length, 2); assert.equal(readFileSync(f, "utf8"), "{corrupt", "never written over");
  for (const bad of ["", "null", "42", '"text"']) {
    writeFileSync(f, bad);
    await assert.rejects(mk({ knownToolsFile: f }).check(bd(), call("mystery")), /confirmation refused/, JSON.stringify(bad));
  }
  unlinkSync(f);                                                                        // deleting the file resets it
  await mk({ knownToolsFile: f, confirm: async () => ALWAYS }).check(bd(), call("mystery"));
  await mk({ knownToolsFile: f }).check(bd(), call("mystery"));
});

test("the kill switch wins over a known tool and over a pending 'always' (nothing is recorded)", async () => {
  const f = join(tmp(), "known-tools.json");
  const g = mk({ knownToolsFile: f, confirm: async () => ALWAYS });
  await g.check(bd(), call("mystery"));
  g.kill(); await assert.rejects(g.check(bd(), call("mystery")), /kill switch active/);
  g.resume(); await g.check(bd(), call("mystery"));
  let release!: (v: unknown) => void;
  const g2 = mk({ knownToolsFile: f, confirm: () => new Promise(r => (release = r)) });
  const pending = g2.check(bd(), call("newtool"));
  g2.kill(); release(ALWAYS);
  await assert.rejects(pending, /confirmation refused/);
  assert.equal(g2.knownTools.has(knownKey(AUD, "newtool", "agent-a")), false);
  assert.ok(!g2.audit.entries.some(e => e.decision === "known-add"));
});

test("CLI: known list shows who and when; known remove <tool> revokes every agent at once, immediately, journaled with who", async () => {
  const d = tmp(); const f = join(d, "known-tools.json"); const auditFile = join(d, "audit.jsonl");
  const g = mk({ knownToolsFile: f, audit: new AuditLog(auditFile), confirm: async () => ({ choice: "always", approver: "alice" }) });
  for (const [agent, t] of [["agent-a", "mystery"], ["agent-b", "mystery"], ["agent-a", "keep_me"]]) await g.check(bd(agent), call(t));
  const running = mk({ knownToolsFile: f, audit: new AuditLog(auditFile) });            // a proxy running without a confirmer
  await running.check(bd(), call("mystery")); await running.check(bd("agent-b"), call("mystery"));
  const env = { ...process.env, KYTRAL_KNOWN_TOOLS: f, KYTRAL_AUDIT: auditFile, KYTRAL_SECRET: S };
  const cli = (...a: string[]) => execFileSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...a], { env, encoding: "utf8", stdio: "pipe" });
  assert.match(cli("known", "list"), new RegExp(`^${AUD}\\tmystery\\tagent-a\\talice\\t\\d{4}-\\d\\d-\\d\\dT`, "m"));
  assert.match(cli("known", "remove", "mystery", "--by", "carol"), /removed\t[^\t]+\tmystery\tagent-a\nremoved\t[^\t]+\tmystery\tagent-b\n/);
  await assert.rejects(running.check(bd(), call("mystery")), /confirmation refused/, "running proxy sees the removal at once");
  await assert.rejects(running.check(bd("agent-b"), call("mystery")), /confirmation refused/);
  await running.check(bd(), call("keep_me"));                                          // other grants untouched
  assert.throws(() => cli("known", "remove", "keep_me", "agent-b"), (e: any) => e.status === 1, "narrowed to another agent: nothing removed");
  assert.throws(() => cli("known", "remove", "keep_me", "agent-a", "other-server"), (e: any) => e.status === 1);
  assert.match(cli("known", "remove", "keep_me", "agent-a", AUD), /removed/);
  const removals = lines(auditFile).filter(e => e.decision === "known-remove" && !e.rule);
  assert.equal(removals.length, 3);
  assert.match(removals[0].approver, /^carol \(os:.+\)$/); assert.ok(removals.every(e => e.server === AUD && Date.parse(e.ts) > 0));
  assert.ok(verifyChain(lines(auditFile)), "CLI and proxies share one valid audit chain");
  writeFileSync(f, "{corrupt");
  assert.throws(() => cli("known", "list"), (e: any) => e.status === 1 && /corrupt/.test(e.stderr));
  assert.throws(() => cli("known", "remove", "mystery"), (e: any) => e.status === 1 && /corrupt/.test(e.stderr));
  assert.equal(readFileSync(f, "utf8"), "{corrupt");
});

test("known remove tombstones what it removes (anti-replay, every agent): a restored backup grants nothing; a later grant works", { timeout: 60000 }, async () => {
  const d = tmp(); const f = join(d, "known-tools.json"); const auditFile = join(d, "audit.jsonl");
  const g = mk({ knownToolsFile: f, audit: new AuditLog(auditFile), confirm: async () => ALWAYS });
  for (const agent of ["agent-a", "agent-b"]) await g.check(bd(agent), call("mystery"));
  const backup = readFileSync(f, "utf8");
  const env = { ...process.env, KYTRAL_KNOWN_TOOLS: f, KYTRAL_AUDIT: auditFile, KYTRAL_SECRET: S };
  execFileSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "known", "remove", "mystery"], { env, stdio: "pipe" });
  assert.ok(existsSync(join(d, "known-tools.tombstones.json")));
  writeFileSync(f, backup);                                                               // replay an old copy
  const running = mk({ knownToolsFile: f });
  for (const agent of ["agent-a", "agent-b"]) await assert.rejects(running.check(bd(agent), call("mystery")), /confirmation refused/, agent);
  assert.equal(running.audit.entries.filter(e => e.decision === "known-reject" && /tombstone/.test(e.rule!)).length, 2);
  await mk({ knownToolsFile: f, confirm: async () => ALWAYS }).check(bd(), call("mystery"));
  await mk({ knownToolsFile: f }).check(bd(), call("mystery"));
});

test("CLI known and confirm apply the strong-secret rule to KYTRAL_SECRET and KYTRAL_AUDIT_SECRET", { timeout: 120000 }, () => {
  const d = tmp();
  const run = (extra: Record<string, string>, ...a: string[]) => {
    const env: Record<string, string | undefined> = { ...process.env, KYTRAL_KNOWN_TOOLS: join(d, "known-tools.json"), KYTRAL_CONFIRMATIONS: join(d, "confirmations"), KYTRAL_AUDIT: join(d, "audit.jsonl"), KYTRAL_SECRET: S, ...extra };
    if (!("KYTRAL_AUDIT_SECRET" in extra)) delete env.KYTRAL_AUDIT_SECRET;
    return spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...a], { env, encoding: "utf8" });
  };
  for (const [extra, why] of [[{ KYTRAL_SECRET: "short" }, "KYTRAL_SECRET too short"], [{ KYTRAL_AUDIT_SECRET: "x" }, "KYTRAL_AUDIT_SECRET too short"]] as const)
    for (const cmd of [["known", "list"], ["known", "remove", "mystery"], ["confirm", "list"]]) {
      const r = run(extra, ...cmd);
      assert.equal(r.status, 2, `${cmd.join(" ")}: ${why}`); assert.match(r.stderr, new RegExp(why), cmd.join(" "));
    }
  assert.equal(run({}, "known", "list").status, 0);
});

test("concurrent 'always' grants from several processes are all kept (inter-process lock)", { timeout: 60000 }, async () => {
  const f = join(tmp(), "known-tools.json"); const N = 5, PER = 8;
  const code = `import { Guard, loadPolicy, issueBadge } from ${JSON.stringify(pathToFileURL(join(ROOT, "src/index.ts")).href)};
    const [f, k] = process.argv.slice(1);
    const g = new Guard({ policy: loadPolicy("default: allow\\nrules: []\\n"), secret: ${JSON.stringify(S)}, audience: ${JSON.stringify(AUD)}, revocationFile: null, nonceFile: null, knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "p" + k }) });
    const b = issueBadge(${JSON.stringify(S)}, "agent-" + k, ["*"], 60, Date.now(), { aud: ${JSON.stringify(AUD)} });
    for (let i = 0; i < ${PER}; i++) await g.check(b, { tool: "tool_" + i, args: {} });`;
  const runs = Array.from({ length: N }, (_, k) => new Promise<number>(r => spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", code, f, String(k)], { stdio: "inherit" }).on("exit", c => r(c ?? 1))));
  assert.deepEqual(await Promise.all(runs), Array(N).fill(0));
  const g = mk({ knownToolsFile: f });
  for (let k = 0; k < N; k++) for (let i = 0; i < PER; i++) assert.ok(g.knownTools.has(knownKey(AUD, `tool_${i}`, `agent-${k}`)), `agent-${k}/tool_${i}`);
  assert.equal(Object.keys(JSON.parse(readFileSync(f, "utf8"))).length, N * PER);
});

test("known-tools.json is created with mode 0600", { skip: process.platform === "win32" && "POSIX file modes" }, async () => {
  const f = join(tmp(), "known-tools.json");
  await mk({ knownToolsFile: f, confirm: async () => ALWAYS }).check(bd(), call("mystery"));
  assert.equal(statSync(f).mode & 0o777, 0o600);
});
