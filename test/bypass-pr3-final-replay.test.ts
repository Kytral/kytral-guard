// Adversarial regression probe: an "always" grant restored from a backup after its revocation.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, openSync, writeSync, closeSync, statSync, utimesSync } from "node:fs"; import { tmpdir } from "node:os"; import { join } from "node:path";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge, knownKey } from "../src/index.js";
import { execSync } from "node:child_process"; import { observeServerLine } from "../src/proxy.js";
const S = "b3f8e2a71c9d4056a8e1f3b7c2d94e60f1a5b8c3"; const AUD = "kytral-guard:final";
const bd = (a="agent-a") => issueBadge(S, a, ["*"], 60, Date.now(), { aud: AUD });
const tmp = () => mkdtempSync(join(tmpdir(), "kg-fin-"));
const mkU = (o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret: S, audience: AUD, revocationFile: null, nonceFile: null, ...o });
const mkK = (o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null, ...o });
async function grant(f: string) { await mkU({ knownToolsFile: f, confirm: async () => ({ choice: "always", approver: "qa" }) }).check(bd(), { tool: "mystery", args: {} }); }
test("ROLLBACK: revoked 'always' entry restored from backup is accepted again", async () => {
  const f = join(tmp(), "a.json"); await grant(f); const backup = readFileSync(f,"utf8");
  const g = mkU({ knownToolsFile: f }); g.removeKnown ? g.removeKnown("mystery","agent-a") : (g as any).knownTools.remove(knownKey(AUD,"mystery","agent-a"));
  writeFileSync(f, backup);
  const r = await mkU({ knownToolsFile: f }).check(bd(), { tool: "mystery", args: {} }).then(()=>"allowed",()=>"refused");
  assert.equal(r, "refused", "rollback replay");
});
