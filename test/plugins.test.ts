// Plugins: loading (env and config file, fail closed), central policy, extra kill switch, remote approvals for hooks and
// the SDK guard, copies of decisions and audit entries, flush.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs"; import { tmpdir } from "node:os"; import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { loadPlugins, pluginSpecs, pluginKillReason, type KytralPlugin } from "../src/plugins.js";
import { runHookAsync } from "../src/hooks.js";
import { AuditLog, auditKey, verifyAuditFile, type Entry } from "../src/audit.js";
import { Guard, GuardError, issueBadge, presetPolicy, loadPolicy } from "../src/index.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "2e7b9d4f1a6c8e3052b7d1f9a4c6e8b3d0f5a7c2e9b4d6f1a3c8e5b7d2f9a4c6";
const tmp = () => mkdtempSync(join(tmpdir(), "kg-plugins-"));
const cc = (command: string, mode = "default") => JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, permission_mode: mode, cwd: "/p" });
function hook(input: string, plugins: KytralPlugin[], extra: Record<string, unknown> = {}) {
  const home = tmp(), audit = new AuditLog(join(home, "audit.jsonl"), { key: auditKey(S) });
  return runHookAsync("claude-code", input, { secret: S, audit, killSwitchFile: join(home, "ks.json"), preset: "coding-agent", plugins, ...extra })
    .then(r => ({ r, home, entries: audit.entries }));
}
const decision = (r: { stdout: string; exitCode: number }) => r.stdout ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision : r.exitCode === 0 ? "allow" : `exit ${r.exitCode}`;

test("plugins load from KYTRAL_PLUGINS and $KYTRAL_HOME/config.json; a plugin that does not load throws", async () => {
  const dir = tmp(), a = join(dir, "a.mjs"), b = join(dir, "b.mjs");
  writeFileSync(a, "export default { name: 'a', killReason: () => null };");
  writeFileSync(b, "export default (ctx) => ({ name: 'b:' + typeof ctx.home });");
  const saved = { p: process.env.KYTRAL_PLUGINS, h: process.env.KYTRAL_HOME };
  try {
    process.env.KYTRAL_HOME = dir; process.env.KYTRAL_PLUGINS = a;
    writeFileSync(join(dir, "config.json"), JSON.stringify({ plugins: [b, a] }));
    assert.deepEqual(pluginSpecs(), [a, b]);
    assert.deepEqual((await loadPlugins()).map(p => p.name), ["a", "b:string"]);
    await assert.rejects(loadPlugins([join(dir, "missing.mjs")]), /cannot be loaded/);
    writeFileSync(join(dir, "c.mjs"), "export default 42;");
    await assert.rejects(loadPlugins([join(dir, "c.mjs")]), /does not export a plugin/);
    writeFileSync(join(dir, "config.json"), "{ nope");
    assert.throws(() => pluginSpecs(), /not valid JSON/);
  } finally {
    for (const [k, v] of [["KYTRAL_PLUGINS", saved.p], ["KYTRAL_HOME", saved.h]] as const) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
});

test("a plugin's kill switch refuses every call; a plugin that throws refuses too (fail closed)", async () => {
  const { r } = await hook(cc("ls"), [{ name: "fleet", killReason: () => "stopped from the dashboard" }]);
  assert.equal(r.exitCode, 2); assert.match(r.stderr, /fleet: stopped from the dashboard/); assert.equal(JSON.parse(r.stdout).continue, false);
  assert.match(pluginKillReason([{ name: "x", killReason: () => { throw new Error("cache unreadable"); } }])!, /fail closed/);
  assert.equal((await hook(cc("ls"), [{ name: "calm", killReason: () => null }])).r.exitCode, 0);
});

test("remote approval: a confirmation nobody can answer locally is approved or refused by a plugin", async () => {
  const seen: unknown[] = [];
  const approve: KytralPlugin = { name: "slack", confirm: async req => { seen.push(req); return { verdict: "allow", approver: "alice" }; } };
  const a = await hook(cc("git reset --hard", "bypassPermissions"), [approve]);
  assert.equal(decision(a.r), "allow");
  const last = a.entries.at(-1)!;
  assert.equal(last.decision, "confirmed"); assert.match(last.approver!, /alice \(via slack\)/);
  assert.equal((seen[0] as any).localPrompt, false); assert.equal((seen[0] as any).rule, "shell-destructive");
  const d = await hook(cc("git reset --hard"), [{ name: "slack", confirm: async () => ({ verdict: "deny", approver: "bob", note: "not on Friday" }) }]);
  assert.equal(decision(d.r), "deny"); assert.match(d.r.stderr, /refused by bob \(via slack\): not on Friday/);
  // no verdict in time: the agent asks locally, or refuses in bypass mode
  const slow: KytralPlugin = { name: "slow", confirm: () => new Promise(r => setTimeout(() => r({ verdict: "allow" }), 5000)) };
  assert.equal(decision((await hook(cc("git reset --hard"), [slow], { remoteConfirmTimeoutMs: 50 })).r), "ask");
  assert.equal(decision((await hook(cc("git reset --hard", "bypassPermissions"), [slow], { remoteConfirmTimeoutMs: 50 })).r), "deny");
  // a block is never offered to a plugin
  let asked = false;
  assert.equal(decision((await hook(cc("rm -rf ~"), [{ name: "x", confirm: async () => { asked = true; return { verdict: "allow" }; } }])).r), "deny");
  assert.equal(asked, false);
});

test("plugins receive every audit entry and decision, and are flushed", async () => {
  const audits: Entry[] = [], decisions: any[] = []; let flushed = 0;
  const p: KytralPlugin = { name: "siem", onAudit: e => audits.push(e), onDecision: e => decisions.push(e), flush: async () => { flushed++; } };
  const { home } = await hook(cc("rm -rf ~"), [p]);
  assert.equal(audits.length, 1); assert.equal(audits[0].decision, "block"); assert.ok(audits[0].mac, "entries are passed once signed");
  assert.deepEqual(decisions.map(d => [d.outcome, d.rule]), [["deny", "shell-catastrophic"]]);
  assert.equal(flushed, 1);
  assert.equal(verifyAuditFile(join(home, "audit.jsonl"), auditKey(S)).exitCode, 0);
  // a throwing observer never changes a decision
  const noisy: KytralPlugin = { name: "noisy", onAudit: () => { throw new Error("x"); }, onDecision: () => { throw new Error("y"); } };
  assert.equal((await hook(cc("ls"), [noisy])).r.exitCode, 0);
});

test("a plugin's central policy replaces the local one", async () => {
  const central: KytralPlugin = { name: "central", policy: () => loadPolicy("rules:\n  - name: no-npm\n    argMatches: '^npm '\n    action: block\n") };
  const home = tmp(), audit = new AuditLog(join(home, "audit.jsonl"), { key: auditKey(S) });
  const r = await runHookAsync("claude-code", cc("npm install"), { secret: S, audit, killSwitchFile: join(home, "ks.json"), plugins: [central] });
  assert.equal(r.exitCode, 2); assert.match(r.stderr, /no-npm/);
});

test("SDK guard: plugin kill switch, remote approvals before the queue, audit copies", async () => {
  const aud = "kytral-guard:plugins";
  const mk = (plugins: KytralPlugin[]) => new Guard({ policy: { ...presetPolicy("strict"), knownTools: ["refund"] }, secret: S, audience: aud, plugins,
    revocationFile: null, nonceFile: null, knownToolsFile: null, killSwitchFile: join(tmp(), "ks.json"), audit: new AuditLog() });
  const badge = issueBadge(S, "billing", ["*"], 60, Date.now(), { aud });
  const call = { tool: "refund", args: { charge: "ch_1", note: "refund requested" } };
  await assert.rejects(mk([]).check(badge, call), /confirmation refused/);
  const g = mk([{ name: "web", confirm: async () => ({ verdict: "allow", approver: "carol" }) }]);
  await g.check(badge, call);
  assert.equal(g.audit.entries.at(-1)!.decision, "confirmed"); assert.match(g.audit.entries.at(-1)!.approver!, /carol \(via web\)/);
  await assert.rejects(mk([{ name: "web", confirm: async () => ({ verdict: "deny", approver: "dan" }) }]).check(badge, call), GuardError);
  await assert.rejects(mk([{ name: "fleet", killReason: () => "frozen" }]).check(badge, { tool: "refund", args: {} }), /fleet: frozen/);
});

test("CLI: a plugin that does not load makes the hook refuse (exit 2)", { timeout: 60000 }, () => {
  const home = tmp();
  const r = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "hook", "claude-code"],
    { cwd: ROOT, input: cc("ls"), encoding: "utf8", env: { ...process.env, KYTRAL_HOME: home, KYTRAL_SECRET: S, KYTRAL_PLUGINS: join(home, "nope.mjs") } });
  assert.equal(r.status, 2); assert.match(r.stderr, /plugin .* cannot be loaded/);
  mkdirSync(join(home, "p"), { recursive: true }); writeFileSync(join(home, "p", "ok.mjs"), "export default { name: 'ok' };");
  const ok = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "hook", "claude-code"],
    { cwd: ROOT, input: cc("ls"), encoding: "utf8", env: { ...process.env, KYTRAL_HOME: home, KYTRAL_SECRET: S, KYTRAL_PLUGINS: join(home, "p", "ok.mjs") } });
  assert.equal(ok.status, 0, ok.stderr);
});
