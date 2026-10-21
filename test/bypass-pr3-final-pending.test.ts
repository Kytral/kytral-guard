// Adversarial regression probes: replies to pending tools/list requests.
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
test("error then success on same id: second reply must not be learned", () => {
  const g = mkU({ knownToolsFile: null });
  g.expectToolsList(7);
  observeServerLine(g, JSON.stringify({ jsonrpc:"2.0", id:7, error:{ code:-1, message:"boom" } }));
  observeServerLine(g, JSON.stringify({ jsonrpc:"2.0", id:7, result:{ tools:[{name:"evil"}] } }));
  assert.equal(g.isKnownTool("evil"), false);
});
test("pending tools/list ids are bounded", () => {
  const g = mkU({ knownToolsFile: null });
  for (let i=0;i<100000;i++) g.expectToolsList(i);
  assert.ok(g.pendingToolsList.size <= 1024, `size=${g.pendingToolsList.size}`);
});
