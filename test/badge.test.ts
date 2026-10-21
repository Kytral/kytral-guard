import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs"; import { tmpdir } from "node:os"; import { join } from "node:path";
import { createHmac } from "node:crypto";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge, verifyBadge, assertStrongSecret } from "../src/index.js";
const S = "7c3e9a1f5b2d8064e1a7c9f3b5d2e8a04f6c1b9d3e7a5f2c8b0d4e6a1f3c5b7d"; const policy = loadPolicy(DEFAULT_POLICY);
// unknownTools defaults to confirm: tests that are not about unknown tools opt in explicitly, per test, via this policy.
const knownPolicy = loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n");
const tmp = () => mkdtempSync(join(tmpdir(), "kg-badge-"));
test("revocation survives a restart (file-backed)", async () => {
  const d = tmp(); const o = { policy: knownPolicy, secret: S, revocationFile: join(d, "rev.json"), nonceFile: null };
  const b = issueBadge(S, "agent-x", ["*"], 60);
  await new Guard(o).check(b, { tool: "t", args: {} });
  new Guard(o).revoke("agent-x");
  await assert.rejects(new Guard(o).check(b, { tool: "t", args: {} }), /revoked/);
});
test("audience is enforced", async () => {
  const g = new Guard({ policy: knownPolicy, secret: S, audience: "proxy-crm", revocationFile: null, nonceFile: null });
  await assert.rejects(g.check(issueBadge(S, "a", ["*"], 60), { tool: "t", args: {} }), /wrong audience/);
  await g.check(issueBadge(S, "a", ["*"], 60, Date.now(), { aud: "proxy-crm" }), { tool: "t", args: {} });
});
test("legacy badge without aud/nonce is refused", () => {
  const body = Buffer.from(JSON.stringify({ agentId: "a", tools: ["*"], expiresAt: Date.now() + 6e4, id: "x" })).toString("base64url");
  assert.throws(() => verifyBadge(S, `${body}.${createHmac("sha256", S).update(body).digest("base64url")}`, new Set()), /aud\/nonce/);
});
test("single-use badge is bound to the first proxy instance", async () => {
  const d = tmp(); const o = { policy: knownPolicy, secret: S, revocationFile: null, nonceFile: join(d, "n.json") };
  const b = issueBadge(S, "a", ["*"], 60, Date.now(), { once: true });
  const g1 = new Guard(o); await g1.check(b, { tool: "t", args: {} }); await g1.check(b, { tool: "t", args: {} });
  await assert.rejects(new Guard(o).check(b, { tool: "t", args: {} }), /single-use/);
});
test("corrupt revocation file fails closed", () => {
  const f = join(tmp(), "rev.json"); writeFileSync(f, "{not json");
  assert.throws(() => new Guard({ policy, secret: S, revocationFile: f }));
});
test("weak secrets are refused", () => {
  for (const s of [undefined, "", "short", "a".repeat(64), "changeme-changeme-changeme-changeme"]) assert.throws(() => assertStrongSecret(s), String(s));
  assertStrongSecret("9f2c4e7a1b3d5f60718293a4b5c6d7e8f9012a3b4c5d6e7f8091a2b3c4d5e6f7");
});
test("SDK: audience is mandatory and the shared default is refused", async () => {
  const prev = process.env.KYTRAL_AUDIENCE; delete process.env.KYTRAL_AUDIENCE;
  try {
    const shared = issueBadge(S, "a", ["*"], 60, Date.now(), { aud: "kytral-guard" });
    await assert.rejects(new Guard({ policy: knownPolicy, secret: S, revocationFile: null, nonceFile: null }).check(shared, { tool: "t", args: {} }), /KYTRAL_AUDIENCE is missing/);
    await assert.rejects(new Guard({ policy: knownPolicy, secret: S, audience: "kytral-guard", revocationFile: null, nonceFile: null }).check(shared, { tool: "t", args: {} }), /shared default/);
    const g = new Guard({ policy: knownPolicy, secret: S, audience: "svc:billing", revocationFile: null, nonceFile: null });
    await g.check(issueBadge(S, "a", ["*"], 60, Date.now(), { aud: "svc:billing" }), { tool: "t", args: {} });
  } finally { if (prev !== undefined) process.env.KYTRAL_AUDIENCE = prev; }
});
test("Guard constructor: empty, short or placeholder secret refused; weak KYTRAL_AUDIT_SECRET refused", () => {
  const mkS = (secret: string) => new Guard({ policy, secret, revocationFile: null, nonceFile: null, knownToolsFile: null } as any);
  assert.throws(() => mkS(""), /missing/);
  assert.throws(() => mkS("test-secret"), /too short/);
  assert.throws(() => mkS("changeme".repeat(5)), /too weak/);
  mkS(S);
  const prev = process.env.KYTRAL_AUDIT_SECRET; process.env.KYTRAL_AUDIT_SECRET = "short";
  try { assert.throws(() => mkS(S), /KYTRAL_AUDIT_SECRET too short/); } finally { if (prev === undefined) delete process.env.KYTRAL_AUDIT_SECRET; else process.env.KYTRAL_AUDIT_SECRET = prev; }
});

test("a signature has one spelling: characters the base64url decoder would skip make the badge invalid", () => {
  const b = issueBadge(S, "agent", ["*"], 60, Date.now(), { aud: "kytral-guard:spelling" });
  assert.equal(verifyBadge(S, b, new Set()).agentId, "agent");
  const [body, sig] = b.split(".");
  for (const bad of [`${sig.slice(0, 10)}&&${sig.slice(10)}`, `${sig} `, `${sig}=`, `${sig.slice(0, 20)}\n${sig.slice(20)}`])
    assert.throws(() => verifyBadge(S, `${body}.${bad}`, new Set()), /bad signature/, JSON.stringify(bad));
});
