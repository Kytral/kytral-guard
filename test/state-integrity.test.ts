import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, unlinkSync } from "node:fs"; import { tmpdir } from "node:os"; import { join } from "node:path";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge, knownKey } from "../src/index.js";
const S = "7c3e9a1f5b2d8064e1a7c9f3b5d2e8a04f6c1b9d3e7a5f2c8b0d4e6a1f3c5b7d"; const AUD = "kytral-guard:integrity";
const bd = () => issueBadge(S, "agent-a", ["*"], 60, Date.now(), { aud: AUD });
const tmp = () => mkdtempSync(join(tmpdir(), "kg-int-"));
const mk = (o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null, ...o });
const mkU = (o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret: S, audience: AUD, revocationFile: null, nonceFile: null, ...o });
test("known-tools entries are HMAC-signed; a forged or re-targeted entry is rejected and audited", async () => {
  const f = join(tmp(), "allow.json"); await mkU({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) }).check(bd(), { tool: "mystery", args: {} });
  const signed = JSON.parse(readFileSync(f, "utf8")); const [[k, v]] = Object.entries(signed);
  assert.match(String(v), /"sig"/);
  writeFileSync(f, JSON.stringify({ [knownKey(AUD, "other_tool", "agent-a")]: v }));          // valid signature moved to another key
  const g = mkU({ knownToolsFile: f });
  await assert.rejects(g.check(bd(), { tool: "other_tool", args: {} }), /confirmation refused/);
  assert.ok(g.audit.entries.some(e => e.decision === "known-reject" && e.tool === "other_tool"));
  const g2 = mkU({ knownToolsFile: f, secret: "e1d4c7b0a3f6e9d2c5b8a1f4e7d0c3b6a9f2e5d8c1b4a7f0e3d6c9b2a5f8e1d4" }); void k;
  assert.equal(g2.knownTools.has(knownKey(AUD, "mystery", "agent-a")), false, "other secret cannot validate");
});
test("deleted known-tools.json clears a running proxy's grants", async () => {
  const f = join(tmp(), "allow.json"); const g = mkU({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) });
  await g.check(bd(), { tool: "mystery", args: {} }); unlinkSync(f);
  assert.equal(g.knownTools.has(knownKey(AUD, "mystery", "agent-a")), false);
});
test("revocations are never forgotten by a running proxy (file deleted or rewritten)", async () => {
  const f = join(tmp(), "rev.json"); const g = mk({ revocationFile: f }); g.revoke("agent-a");
  unlinkSync(f); await assert.rejects(g.check(bd(), { tool: "t", args: {} }), /revoked/);
  writeFileSync(f, "{}"); await new Promise(r => setTimeout(r, 20)); writeFileSync(f, JSON.stringify({ other: "x" }));
  await assert.rejects(g.check(bd(), { tool: "t", args: {} }), /revoked/);
});
