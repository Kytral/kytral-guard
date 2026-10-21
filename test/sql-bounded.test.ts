// SQL parsing has a deadline: the parser runs in a worker thread, and a parse that does not answer in time gives
// "unparseable" (a human confirms). Its own test file: a timeout pauses SQL parsing for 10 s in the process.
import { test } from "node:test"; import assert from "node:assert/strict";
import { analyzeSql } from "../src/analyze.js";
import { parseSqlBounded, stopSqlWorker } from "../src/sql-bounded.js";

test("statements are parsed in a reused worker; hostile parentheses are refused without parsing", () => {
  assert.equal(analyzeSql("DELETE FROM users"), "unrestricted-write");
  assert.equal(analyzeSql("DELETE FROM users WHERE id = 3"), "ok");
  const t0 = performance.now();
  for (let i = 0; i < 100; i++) assert.equal(analyzeSql(`UPDATE t SET a = 1 WHERE id = ${i}`), "ok");
  assert.ok(performance.now() - t0 < 3000, "a warm worker answers in well under a millisecond per statement");
  // unbalanced parentheses made the parser backtrack exponentially (28 levels: minutes): refused at once
  const bomb = "delete from t where " + "(".repeat(28) + "1=1";
  const t1 = performance.now();
  assert.equal(analyzeSql(bomb), "unparseable");
  assert.equal(analyzeSql("select " + "(".repeat(70) + "1" + ")".repeat(70)), "ok", "deep but balanced parentheses parse fast");
  assert.equal(analyzeSql("select " + "(".repeat(1100) + "1" + ")".repeat(1100)), "unparseable", "nesting deeper than 1000 (the parser's stack)");
  assert.equal(analyzeSql("select ')(' from t where a = '((('"), "ok", "quoted parentheses do not count");
  assert.ok(performance.now() - t1 < 500);
});

test("a parse that does not answer in time is abandoned: unparseable (unconditional writes still blocked), no parsing for a while", () => {
  stopSqlWorker();
  process.env.KYTRAL_SQL_TIMEOUT_MS = "1";   // the worker cannot even start in 1 ms
  try {
    const t0 = performance.now();
    assert.equal(parseSqlBounded("DELETE FROM users WHERE id = 3", "postgresql"), "unparseable");
    assert.ok(performance.now() - t0 < 1000);
    delete process.env.KYTRAL_SQL_TIMEOUT_MS;
    assert.equal(parseSqlBounded("DELETE FROM users WHERE id = 3", "postgresql"), "unparseable", "paused after a timeout");
    // without the parser, an unconditional DELETE/UPDATE is still an unrestricted write (not a mere confirmation)
    assert.equal(parseSqlBounded("DELETE FROM users", "postgresql"), "unrestricted-write");
    assert.equal(parseSqlBounded("update accounts set balance = 0", "postgresql"), "unrestricted-write");
  } finally { delete process.env.KYTRAL_SQL_TIMEOUT_MS; }
});
