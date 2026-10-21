// SQL as agents and MCP tools send it: what deobfuscation reads (comments, concatenation) must not mangle legitimate
// statements (strings holding commas, #, -- or /* stay strings), and must still see through what hides a statement.
import { test } from "node:test"; import assert from "node:assert/strict";
import { evaluate, presetPolicy } from "../src/policy.js";

const strict = presetPolicy("strict"), q = (sql: string) => evaluate(strict, { tool: "query", args: { sql } }).action;

test("strings holding commas, #, -- or /* stay strings: legitimate statements run", () => {
  for (const s of ["INSERT INTO users (name, email) VALUES ('a', 'a@x.com')", "INSERT INTO t (c) VALUES ('#ff0000')", "UPDATE t SET note = 'a--b' WHERE id = 1",
    "INSERT INTO logs VALUES ('/* not a comment */')", "SELECT 'it''s' AS x", "INSERT INTO t (a, b, c) VALUES ('x', 'y', 'z'), ('u', 'v', 'w')",
    "SELECT name FROM users WHERE tag IN ('a', 'b', 'c')"])
    assert.equal(q(s), "allow", s);
});

test("concatenation and comments that hide a statement are still seen through", () => {
  for (const s of ["EXECUTE concat('DR','OP ', 'TABLE users')", "EXEC('DR'+'OP TABLE users')", "SELECT 1; # x\nDROP TABLE users", "DROP/**/TABLE users",
    "SELECT '#'; DROP TABLE users", "SELECT 'a', 'b'; DELETE FROM users"])
    assert.equal(q(s), "block", s);
});
