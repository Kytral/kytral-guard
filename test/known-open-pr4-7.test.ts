// Adversarial probes of known limits: those still open are marked todo, so that they do not break the suite; a todo is removed when its fix lands.
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

test("a fresh tools/list (no cursor) after a page with nextCursor must REPLACE, not merge", () => {
  const g = mkU(); g.expectToolsList(1); reply(g, 1, ["a"], "c1");
  g.expectToolsList(2); reply(g, 2, ["b"]);           // client never asked for cursor c1: new listing
  assert.equal(g.isKnownTool("a"), false, "stale tool 'a' kept: a server that always sends nextCursor makes the list append-only");
});
test("hostile server always sends nextCursor: known tools never shrink", () => {
  const g = mkU(); for (let i = 0; i < 5; i++) { g.expectToolsList(i); reply(g, i, [`t${i}`], "again"); }
  g.expectToolsList(99); reply(g, 99, ["final"]);
  assert.equal(g.isKnownTool("t0"), false);
});
test("a reply without tools (result:{}) consumes the id: a second reply is ignored", () => {
  const g = mkU(); g.expectToolsList(5);
  observeServerLine(g, JSON.stringify({ jsonrpc: "2.0", id: 5, result: {} })); reply(g, 5, ["evil"]);
  assert.equal(g.isKnownTool("evil"), false);
});
async function grantRevokeRestore() {
  const f = join(tmp(), "allow.json"); await mkU({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) }).check(bd(), { tool: "mystery", args: {} });
  const backup = readFileSync(f, "utf8"); mkU({ knownToolsFile: f }).removeKnown("mystery", "agent-a", AUD); return { f, backup };
}
test("RESTART: tombstone file deleted + allowlist backup restored -> revoked grant comes back (known limit, same uid)", { todo: "known limit: same uid, tombstones deleted + backup restored before a restart (needs an external anchor)" }, async () => {
  const { f, backup } = await grantRevokeRestore(); assert.ok(existsSync(tomb(f)));
  unlinkSync(tomb(f)); writeFileSync(f, backup);
  assert.equal(await call(mkU({ knownToolsFile: f })), "refused", "replay after restart once tombstones are removed");
});
test("RESTART: tombstones rewritten to {} + backup restored", { todo: "known limit: same uid, tombstones rewritten to {} + backup restored before a restart (needs an external anchor)" }, async () => {
  const { f, backup } = await grantRevokeRestore(); writeFileSync(tomb(f), "{}"); writeFileSync(f, backup);
  assert.equal(await call(mkU({ knownToolsFile: f })), "refused");
});
