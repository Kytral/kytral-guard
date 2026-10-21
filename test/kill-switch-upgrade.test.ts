// An installation that upgrades from a pre-release build may hold a kill switch state this version refuses: a v1 state, or a
// v2 state signed with the random id an older version kept in kill-switch.id. Every guard stops and says why; a single
// `kytral-guard resume` lifts it (no kill first) and says that agents run again (it used to say the switch "was already off").
import { test } from "node:test"; import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path";
import { canonicalJson } from "../src/confirm-queue.js";
import { killSwitchKey } from "../src/kill-switch.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "6c1e9b4f2a7d0c5e8b3f1a6d9c2e5b8f0a4d7c1e6b9f2a5d8c0e3b7f1a4d6c9e";
const sign = (body: object) => createHmac("sha256", killSwitchKey(S)).update(`kill-switch\n${canonicalJson(body)}`).digest("base64url");
/** A v1 state, signed as the first version did (no deployment id, no `after`). */
const v1 = (killed: boolean) => { const body = { v: 1, killed, gen: 3, at: "2026-09-01T10:00:00.000Z", by: "ops" }; return JSON.stringify({ ...body, sig: sign(body) }); };
/** A v2 state signed with the random id an older version kept in kill-switch.id. */
const randomId = (killed: boolean) => { const body = { v: 2, killed, gen: 2, at: "2026-09-01T10:00:00.000Z", by: "ops", dep: randomBytes(16).toString("hex"), after: "none" }; return JSON.stringify({ ...body, sig: sign(body) }, null, 1); };
const event = JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, cwd: "/tmp", session_id: "s" });
function cli(h: string, args: string[], input = "") {
  const env: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_SECRET: S };
  for (const k of ["KYTRAL_AUDIT", "KYTRAL_AUDIT_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS"]) delete env[k];
  const r = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...args], { cwd: ROOT, env: env as NodeJS.ProcessEnv, encoding: "utf8", input });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test("a v1 state left by an older version: refused in words that say so and that a single resume lifts it; one resume does, and says agents run again", () => {
  for (const killed of [false, true]) {
    const h = mkdtempSync(join(tmpdir(), "kg-upgrade-")), what = killed ? "kill" : "resume";
    writeFileSync(join(h, "kill-switch.json"), v1(killed));
    const hook = cli(h, ["hook", "claude-code"], event);
    assert.equal(hook.code, 2, what);
    assert.ok(JSON.parse(hook.out).hookSpecificOutput.permissionDecisionReason.includes(`kill-switch.json holds a ${what} not signed with this deployment's key (a v1 state, written by an older version of Kytral Guard, or forged), every tool call is refused (fail closed): a single 'kytral-guard resume' lifts it`), hook.out);
    assert.match(cli(h, ["doctor"]).out, /^warn {2}kill switch active: kill-switch\.json holds a .* \(a v1 state, written by an older version of Kytral Guard, or forged\).*a single 'kytral-guard resume' lifts it/m);
    const r = cli(h, ["resume", "--by", "ops"]);
    assert.equal(r.code, 0, r.err); assert.match(r.out, /\nAgents and MCP proxies run again: every tool call is checked as before\./, what);
    assert.doesNotMatch(r.out, /already off/, `${what}: it was blocking`);
    assert.equal(cli(h, ["hook", "claude-code"], event).code, 0, `${what}: one resume is enough`);
    assert.match(cli(h, ["resume"]).out, /The kill switch was already off: nothing was stopped\./);
  }
});

test("a state signed with the random id of an older version (kill-switch.id): refused, one resume lifts it and says agents run again", () => {
  for (const killed of [false, true]) {
    const h = mkdtempSync(join(tmpdir(), "kg-upgrade-")), what = killed ? "kill" : "resume";
    writeFileSync(join(h, "kill-switch.json"), randomId(killed));
    const hook = cli(h, ["hook", "claude-code"], event);
    assert.equal(hook.code, 2, what);
    if (!killed) assert.match(JSON.parse(hook.out).hookSpecificOutput.permissionDecisionReason, /does not chain to the kill in force \(generation 2: taken from another state or deployment, written by an older version, or the kill it follows was missed\)/);
    const r = cli(h, ["resume"]);
    assert.equal(r.code, 0, r.err); assert.match(r.out, /Agents and MCP proxies run again/, what); assert.doesNotMatch(r.out, /already off/, what);
    assert.equal(cli(h, ["hook", "claude-code"], event).code, 0, `${what}: one resume is enough`);
  }
});
