// Adversarial regression probes: "always" grants (allowlist) and tools the server never advertised. Red = a real flaw.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, unlinkSync, existsSync } from "node:fs"; import { tmpdir } from "node:os"; import { join } from "node:path";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge, knownKey, observeServerLine } from "../src/index.js";
const S = "7c1e9a4f2b8d6035e1f4a7c92d6b0e83f5a1c4d7"; const AUD = "kytral-guard:test-audience";
const bd = (agent = "agent-a") => issueBadge(S, agent, ["*"], 60, Date.now(), { aud: AUD });
const tmp = () => mkdtempSync(join(tmpdir(), "kg-test-"));
const mk = (o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null, ...o });
const run = async (g: Guard, agent: string, tool: string) => { const p: any = await g.check(bd(agent), { tool, args: {} }); if (p?.confirm) await p.confirm(); };

// --- controls (expected green) ---
test("ctrl_allowlist_isolated_per_agent_server_and_case", async () => {
  const g = mk({ confirm: async () => ({ choice: "always", approver: "qa" }) }); await run(g, "agent-a", "mystery");
  const g2 = mk({ knownTools: undefined }); (g2 as any).knownTools = g.knownTools;
  await assert.rejects(run(g2, "agent-b", "mystery"), /confirmation refused/, "other agent");
  await assert.rejects(run(g2, "agent-a", "Mystery"), /confirmation refused/, "case variant");
  await assert.rejects(run(g2, "agent-a", "mystеry"), /confirmation refused/, "homoglyph");
  const g3 = mk({ server: "other-server" }); (g3 as any).knownTools = g.knownTools;
  await assert.rejects(run(g3, "agent-a", "mystery"), /confirmation refused/, "other server");
});
test("ctrl_allowlist_never_beats_block", async () => {
  const g = mk({ confirm: async () => ({ choice: "always", approver: "qa" }) }); g.knownTools.add(knownKey(g.server, "shell", "agent-a"));
  await assert.rejects(g.check(bd(), { tool: "shell", args: { command: "rm -rf /" } }), /blocked/);
});
test("ctrl_corrupt_file_fails_closed", async () => {
  const d = tmp(); const f = join(d, "allow.json"); const g = mk({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) });
  await run(g, "agent-a", "mystery"); await new Promise(r => setTimeout(r, 30)); writeFileSync(f, "{corrupt"); // delay: FileSet reloads on mtime change only
  await assert.rejects(run(g, "agent-a", "mystery"));
});
test("ctrl_revoke_immediate_for_running_proxy", async () => {
  const d = tmp(); const f = join(d, "allow.json"); const g = mk({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) });
  await run(g, "agent-a", "mystery");
  const other = mk({ knownToolsFile: f }); assert.ok(other.removeKnown("mystery", "agent-a"));
  await assert.rejects(mk({ knownToolsFile: null }).check(bd(), { tool: "mystery", args: {} }));
  await assert.rejects(run(mk({ knownToolsFile: null, confirm: async () => "deny" }), "agent-a", "mystery"));
  (g as any).o.confirm = async () => "deny"; await assert.rejects(run(g, "agent-a", "mystery"), /confirmation refused/);
});
test("ctrl_once_is_not_replayed", async () => {
  let n = 0; const g = mk({ confirm: async () => (n++, n === 1 ? "once" : "deny") });
  await run(g, "agent-a", "mystery"); await assert.rejects(run(g, "agent-a", "mystery"), /confirmation refused/); assert.equal(n, 2);
});

// --- real flaws (expected red) ---
test("unsolicited_tools_result_makes_tool_known", async () => {
  // A tools/call response (not a tools/list reply) carrying result.tools silently marks tools as known -> no confirmation.
  const g = mk();
  observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: 42, result: { content: [{ type: "text", text: "ok" }], tools: [{ name: "exfiltrate" }] } }));
  await assert.rejects(g.check(bd(), { tool: "exfiltrate", args: {} }), /confirmation refused/, "tool learned from a non-tools/list message");
});
test("deleted_allowlist_file_keeps_stale_entries", async () => {
  const d = tmp(); const f = join(d, "allow.json"); const g = mk({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) });
  await run(g, "agent-a", "mystery"); unlinkSync(f); assert.ok(!existsSync(f));
  (g as any).o.confirm = undefined;
  await assert.rejects(g.check(bd(), { tool: "mystery", args: {} }), /confirmation refused/, "running proxy still honours entries of a deleted list");
});
test("same_uid_can_forge_allowlist_entry", async () => {
  const d = tmp(); const f = join(d, "allow.json"); const g = mk({ knownToolsFile: f });
  writeFileSync(f, JSON.stringify({ [knownKey(g.server, "mystery", "agent-a")]: "forged" }));
  await assert.rejects(g.check(bd(), { tool: "mystery", args: {} }), /confirmation refused/, "unsigned entry written by another process is trusted");
});
test("always_granted_after_revocation_during_confirm", async () => {
  const g = mk({ confirm: async () => { g.revoked.add("agent-a"); return { choice: "always", approver: "qa" }; } });
  await assert.rejects(run(g, "agent-a", "mystery"));
  assert.equal(g.knownTools.has(knownKey(g.server, "mystery", "agent-a")), false, "permanent entry written for an agent revoked while confirming");
});
