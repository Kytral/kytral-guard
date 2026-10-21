// Adversarial regression probe: tools/list pagination. The second tools/list request carries cursor = nextCursor
// (real MCP pagination); the assertion is the original one. A strong secret, with allowlistFile and knownToolsFile null.
import { test } from "node:test"; import assert from "node:assert/strict";
import { Guard, loadPolicy, DEFAULT_POLICY } from "../src/index.js";
import { observeServerLine, expectToolsListPage } from "../src/proxy.js";
const S = "3b7e1c9a5f2d8046e1b9c7a3f5d20846b1e9c7a3f5d2084e6b1a9c3f7e5d2b8a"; const AUD = "kytral-guard:final";
const mkU = (o: any = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret: S, audience: AUD, revocationFile: null, nonceFile: null, allowlistFile: null, knownToolsFile: null, ...o } as any);
test("pagination: a 2nd page requested with nextCursor is merged (page-1 tools stay known)", () => {
  const g = mkU();
  expectToolsListPage(g, 1, undefined);
  observeServerLine(g, JSON.stringify({ jsonrpc:"2.0", id:1, result:{ tools:[{name:"a"}], nextCursor:"c" } }));
  expectToolsListPage(g, 2, "c");
  observeServerLine(g, JSON.stringify({ jsonrpc:"2.0", id:2, result:{ tools:[{name:"b"}] } }));
  assert.ok(g.isKnownTool("a") && g.isKnownTool("b"), `a=${g.isKnownTool("a")} b=${g.isKnownTool("b")}`);
});
