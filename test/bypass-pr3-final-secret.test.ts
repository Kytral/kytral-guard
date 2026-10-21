// Adversarial regression probes: an empty secret.
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
test("empty secret: guard refuses to build or rejects entries", async () => {
  let built = true; let g: any; try { g = new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret: "", audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null }); } catch { built = false; }
  assert.equal(built, false, "Guard accepts empty secret");
});
test("empty secret: any call with a badge works?", async () => {
  // Construction inside the promise (consistent with the previous test): a constructor that throws = refused.
  const r = await Promise.resolve().then(() => {
    const g = new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: "", audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null });
    return g.check(issueBadge("", "x", ["*"], 60, Date.now(), { aud: AUD }), { tool: "t", args: {} });
  }).then(()=>"allowed",(e)=>"refused:"+e.message);
  assert.match(r, /^refused/, r);
});
