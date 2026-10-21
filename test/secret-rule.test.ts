import { test } from "node:test"; import assert from "node:assert/strict";
import { assertStrongSecret, issueBadge, verifyBadge } from "../src/index.js";
const STRONG = "4d9a2f7c1e8b5036a9d2c7f4e1b8a5d2c9f6e3b0a7d4c1f8";
test("whitespace padding never makes a weak secret strong", () => {
  for (const s of ["abcdefghij" + " ".repeat(22), " ".repeat(22) + "abcdefghij", "abcde" + " ".repeat(22) + "fghij",
    "a b c d e f g h i j ".repeat(4), "\t" + STRONG, STRONG + "\n", " " + STRONG + " ", "abcdefghij\u00a0".repeat(3)])
    assert.throws(() => assertStrongSecret(s), undefined, JSON.stringify(s));
  assert.equal(assertStrongSecret(STRONG), STRONG);
});
test("issueBadge and verifyBadge apply the strong-secret rule", () => {
  for (const s of ["", "short", "abcdefghij" + " ".repeat(22), "changeme".repeat(5)]) {
    assert.throws(() => issueBadge(s, "a", ["*"], 60), undefined, `issue ${JSON.stringify(s)}`);
    assert.throws(() => verifyBadge(s, "x.y", new Set()), /secret|KYTRAL_SECRET/, `verify ${JSON.stringify(s)}`);
  }
  const t = issueBadge(STRONG, "a", ["*"], 60, Date.now(), { aud: "kytral-guard:f1" });
  assert.equal(verifyBadge(STRONG, t, new Set()).agentId, "a");
});
