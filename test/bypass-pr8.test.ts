// Adversarial regression probes: weak, empty or placeholder secrets. Red = a flaw. Run them WITHOUT KYTRAL_TEST_WEAK_SECRET.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs"; import { tmpdir } from "node:os"; import { join } from "node:path";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge, knownKey, deriveKey } from "../src/index.js";
import { createHmac } from "node:crypto";
const STRONG = "9f2c4e7a1b3d5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4"; const AUD = "kytral-guard:test-audience";
const mk = (secret: any, o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null, ...o });
const withEnv = (k: string, v: string | undefined, f: () => void) => { const p = process.env[k]; if (v === undefined) delete process.env[k]; else process.env[k] = v; try { f(); } finally { if (p === undefined) delete process.env[k]; else process.env[k] = p; } };
test("empty/whitespace/Buffer/undefined/null secrets refused", () => withEnv("KYTRAL_TEST_WEAK_SECRET", undefined, () => {
  for (const s of ["", " ", " ".repeat(64), "\t\n".repeat(32), undefined, null, Buffer.alloc(0), Buffer.alloc(64), 0, {}])
    assert.throws(() => mk(s), undefined, `accepted: ${JSON.stringify(s)}`);
}));
test("KYTRAL_TEST_WEAK_SECRET=1 flag (settable in production through the environment): does not accept a weak secret", () => withEnv("KYTRAL_TEST_WEAK_SECRET", "1", () => {
  assert.throws(() => mk("a"), undefined, "1-byte secret accepted under the flag");
}));
test("weak KYTRAL_AUDIT_SECRET: the derived allowlist must refuse", () => withEnv("KYTRAL_TEST_WEAK_SECRET", undefined, () => withEnv("KYTRAL_AUDIT_SECRET", "x", () => {
  assert.throws(() => mk(STRONG), undefined, "KYTRAL_AUDIT_SECRET='x' accepted: allowlist signatures can be forged");
})));
