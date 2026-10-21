// Adversarial regression probes: state files reloaded while a proxy runs (allowlist, revocations).
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
test("entry moved to other agent rejected", async () => {
  const f = join(tmp(), "a.json"); await grant(f); const [[, v]] = Object.entries(JSON.parse(readFileSync(f,"utf8")));
  writeFileSync(f, JSON.stringify({ [knownKey(AUD,"mystery","agent-b")]: v }));
  await assert.rejects(mkU({ knownToolsFile: f }).check(bd("agent-b"), { tool: "mystery", args: {} }));
});
test("entry moved to other server rejected", async () => {
  const f = join(tmp(), "a.json"); await grant(f); const [[, v]] = Object.entries(JSON.parse(readFileSync(f,"utf8")));
  writeFileSync(f, JSON.stringify({ [knownKey("other-srv","mystery","agent-a")]: v }));
  assert.equal(mkU({ knownToolsFile: f, server: "other-srv" }).knownTools.has(knownKey("other-srv","mystery","agent-a")), false);
});
for (const [name, body] of [["truncated", '{"x'], ["garbage", "\u0000\u0001"], ["array", '["a"]'], ["number", "42"]] as const)
  test(`allowlist ${name} does not allow`, async () => {
    const f = join(tmp(), "a.json"); await grant(f); writeFileSync(f, body);
    const r = await mkU({ knownToolsFile: f }).check(bd(), { tool: "mystery", args: {} }).then(()=>"allowed",()=>"refused");
    assert.equal(r, "refused");
  });
test("revocations deleted/truncated/corrupt never un-revoke (running)", async () => {
  const f = join(tmp(), "r.json"); const g = mkK({ revocationFile: f }); g.revoke("agent-a");
  for (const body of ["{}", "[]", ""]) { writeFileSync(f, body); const r = await g.check(bd(), { tool: "t", args: {} }).then(()=>"allowed",()=>"refused"); assert.equal(r, "refused", body); }
});
test("same size, same mtime, in-place write (same inode) of revocations", async () => {
  const f = join(tmp(), "r.json"); writeFileSync(f, JSON.stringify({ zzzzzzz: "x" })); const g = mkK({ revocationFile: f });
  await g.check(bd(), { tool: "t", args: {} });
  const ref = f+".ref"; execSync(`touch -r ${f} ${ref}`); const st = statSync(f); const fd = openSync(f, "r+"); writeSync(fd, JSON.stringify({ "agent-a": "x" }), 0); closeSync(fd); execSync(`touch -r ${ref} ${f}`);
  const st2 = statSync(f); assert.equal(st2.ino, st.ino); assert.equal(st2.size, st.size); assert.equal(st2.mtimeMs, st.mtimeMs);
  const r = await g.check(bd(), { tool: "t", args: {} }).then(()=>"allowed",()=>"refused");
  assert.equal(r, "refused", "stale cache: in-place revocation not seen");
});
test("running proxy: allowlist corrupted after start refuses", async () => {
  const f = join(tmp(), "a.json"); await grant(f); const g = mkU({ knownToolsFile: f });
  await g.check(bd(), { tool: "mystery", args: {} });
  await new Promise(r=>setTimeout(r,15)); writeFileSync(f, '{"x');
  const r = await g.check(bd(), { tool: "mystery", args: {} }).then(()=>"allowed",(e)=>"refused:"+e.message);
  assert.match(r, /^refused/);
});
