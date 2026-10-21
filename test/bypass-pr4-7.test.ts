// Adversarial regression probes: pending tools/list ids, a corrupt allowlist, revocation tombstones. Green tests only; the open limits are in known-open-pr4-7.test.ts.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, unlinkSync, existsSync } from "node:fs"; import { tmpdir } from "node:os"; import { join } from "node:path";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge, knownKey } from "../src/index.js";
import { observeServerLine } from "../src/proxy.js";
const S = "5e9d2c8a1f7b4063d2e8a5f1c9b74d30e6a2f8b1"; const AUD = "kytral-guard:test-audience";
const bd = (a = "agent-a") => issueBadge(S, a, ["*"], 60, Date.now(), { aud: AUD });
const tmp = () => mkdtempSync(join(tmpdir(), "kg-test-"));
const mkU = (o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null, ...o });
const reply = (g: Guard, id: number, names: string[], nextCursor?: string) => observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id, result: { tools: names.map(name => ({ name })), nextCursor } }));
const call = (g: Guard) => g.check(bd(), { tool: "mystery", args: {} }).then(() => "allowed", () => "refused");
const tomb = (f: string) => f.replace(/\.json$/, "") + ".tombstones.json";

// ---- pagination
// ---- pending ids
test("beyond 1024 pending ids the oldest is evicted fail-closed (its reply is not learned)", () => {
  const g = mkU(); for (let i = 0; i < 2000; i++) g.expectToolsList(i);
  reply(g, 0, ["evicted"]); assert.equal(g.isKnownTool("evicted"), false);
  reply(g, 1999, ["fresh"]); assert.equal(g.isKnownTool("fresh"), true);
});
// ---- reload by hash / corrupt allowlist
test("allowlist corrupt at start: construction ok, call refused, file restored -> grant works again", async () => {
  const f = join(tmp(), "allow.json"); await mkU({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) }).check(bd(), { tool: "mystery", args: {} });
  const good = readFileSync(f, "utf8"); writeFileSync(f, "{oops");
  const g = mkU({ knownToolsFile: f }); assert.equal(await call(g), "refused");
  writeFileSync(f, good); assert.equal(await call(g), "allowed");
});
// ---- tombstones
async function grantRevokeRestore() {
  const f = join(tmp(), "allow.json"); await mkU({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) }).check(bd(), { tool: "mystery", args: {} });
  const backup = readFileSync(f, "utf8"); mkU({ knownToolsFile: f }).removeKnown("mystery", "agent-a", AUD); return { f, backup };
}
test("running proxy: tombstone file deleted + backup restored -> still refused", async () => {
  const f = join(tmp(), "allow.json"); await mkU({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) }).check(bd(), { tool: "mystery", args: {} });
  const backup = readFileSync(f, "utf8"); const g = mkU({ knownToolsFile: f }); g.removeKnown("mystery", "agent-a", AUD);
  unlinkSync(tomb(f)); writeFileSync(f, backup); assert.equal(await call(g), "refused");
});
test("corrupt tombstone file: never allows (refuse to start or refuse the call)", async () => {
  const { f, backup } = await grantRevokeRestore(); writeFileSync(tomb(f), "{bad"); writeFileSync(f, backup);
  let r: string; try { r = await call(mkU({ knownToolsFile: f })); } catch { r = "refused-at-start"; }
  assert.notEqual(r, "allowed");
});
test("re-grant after revoke is valid, and a second revoke kills it again even if backup of the re-grant is restored", async () => {
  const { f } = await grantRevokeRestore();
  await mkU({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) }).check(bd(), { tool: "mystery", args: {} });
  const b2 = readFileSync(f, "utf8"); assert.equal(await call(mkU({ knownToolsFile: f })), "allowed");
  mkU({ knownToolsFile: f }).removeKnown("mystery", "agent-a", AUD); writeFileSync(f, b2);
  assert.equal(await call(mkU({ knownToolsFile: f })), "refused");
});
