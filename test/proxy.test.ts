// The MCP proxy itself: the shape of tools/call arguments, resources naming the guard's secret, the order of lines while a
// confirmation waits, and the stdio shutdown of MCP (the client closes the proxy's input and waits for it to exit).
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs"; import { tmpdir } from "node:os"; import { join, resolve } from "node:path";
import { Guard, loadPolicy, DEFAULT_POLICY, issueBadge, handleClientLine, ClientPipeline } from "../src/index.js";
import { resourcePath } from "../src/proxy.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "3b8e1f6a9c2d4705e8b1a6f3c9d2e5b7a4f1c8e3d6b9a2f5c7e1d4b8a3f6c9e2", AUD = "kytral-guard:proxy-test";
const badge = issueBadge(S, "agent-p", ["*"], 60, Date.now(), { aud: AUD });
const mk = (o: Record<string, unknown> = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY + "knownTools: ['*']\n"), secret: S, audience: AUD, revocationFile: null, nonceFile: null, knownToolsFile: null, ...o });
async function send(g: Guard, msg: unknown) {
  const toServer: string[] = [], toClient: string[] = [];
  await handleClientLine(g, badge, JSON.stringify(msg), s => toServer.push(s), s => toClient.push(s));
  return { toServer, replies: toClient.map(s => JSON.parse(s)) };
}

test("tools/call arguments that are not an object are refused, not analyzed as none and forwarded", async () => {
  const g = mk();
  for (const args of [["rm -rf ~"], "DROP TABLE users", 42, true]) {
    const r = await send(g, { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "run", arguments: args } });
    assert.deepEqual(r.toServer, [], JSON.stringify(args));
    assert.equal(r.replies[0].error.code, -32602); assert.match(r.replies[0].error.message, /arguments must be an object/);
  }
  // a notification is never answered, and never forwarded either
  assert.deepEqual(await send(g, { jsonrpc: "2.0", method: "tools/call", params: { name: "run", arguments: ["rm -rf ~"] } }), { toServer: [], replies: [] });
  // absent or null: no argument, as the SDKs read them
  for (const params of [{ name: "list_things" }, { name: "list_things", arguments: null }])
    assert.equal((await send(g, { jsonrpc: "2.0", id: 8, method: "tools/call", params })).toServer.length, 1);
  // an object is analyzed as before
  assert.match((await send(g, { jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "run", arguments: { cmd: "rm -rf ~" } } })).replies[0].result.content[0].text, /blocked/);
});

test("resources/read of the guard's secret or keys is refused and journaled; other resources go through", async () => {
  const g = mk();
  for (const uri of ["file:///home/u/.kytral/secret", "file:///C:/Users/me/.kytral/secret", "file:///home/u/%2Ekytral/secret", "file://localhost/home/u/.kytral/kill.key", "file:/home/u/.kytral/secret"]) {
    const r = await send(g, { jsonrpc: "2.0", id: 3, method: "resources/read", params: { uri } });
    assert.deepEqual(r.toServer, [], uri); assert.equal(r.replies[0].error.code, -32000); assert.match(r.replies[0].error.message, /guard's own secret/);
  }
  assert.deepEqual(g.audit.entries.at(-1), { ...g.audit.entries.at(-1), agentId: "agent-p", tool: "resources/read", decision: "block", rule: "guard-tamper" });
  for (const uri of ["file:///home/u/project/README.md", "file:///home/u/.kytral-notes.md", "postgres://db/users/schema"])
    assert.equal((await send(g, { jsonrpc: "2.0", id: 4, method: "resources/read", params: { uri } })).toServer.length, 1, uri);
  assert.equal(resourcePath("file:///C:/Users/me/My%20Docs/a.txt"), "C:/Users/me/My Docs/a.txt");
  assert.equal(resourcePath("file:///home/u/a%ZZ"), "/home/u/a%ZZ", "a malformed escape stays as it is");
});

test("the pipeline keeps the order of lines and tells when every line received so far is decided", async () => {
  let approve!: () => void;
  const g = mk({ policy: loadPolicy(DEFAULT_POLICY), confirm: () => new Promise(r => { approve = () => r("once"); }) });
  const toServer: string[] = [];
  const p = new ClientPipeline(g, badge, s => toServer.push(s), () => {});
  let idle = 0;
  p.whenIdle(() => idle++);
  assert.equal(idle, 1, "nothing waits: at once");
  p.push(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "mystery", arguments: {} } }));   // unknown tool: asked
  p.push(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }));
  p.whenIdle(() => idle++);
  assert.equal(idle, 1); assert.deepEqual(toServer, []);
  approve();
  await new Promise(r => setTimeout(r, 20));
  assert.equal(idle, 2); assert.deepEqual(toServer.map(s => JSON.parse(s).id), [1, 2]);
});

test("the proxy ends its server's input when the client closes its own, and exits with it", { timeout: 60_000 }, async () => {
  // a server that answers each line and exits when its input ends, as MCP servers do
  const server = "process.stdin.setEncoding('utf8'); let b = ''; process.stdin.on('data', d => { b += d; let i; while ((i = b.indexOf('\\n')) >= 0) { const m = JSON.parse(b.slice(0, i)); b = b.slice(i + 1); process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: {} }) + '\\n'); } }); process.stdin.on('end', () => process.exit(0));";
  const proxy = spawn(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "--", process.execPath, "-e", server],
    { cwd: ROOT, env: { ...process.env, KYTRAL_SECRET: S, KYTRAL_AUDIENCE: AUD, KYTRAL_HOME: mkdtempSync(join(tmpdir(), "kg-proxy-")), KYTRAL_BADGE: badge, KYTRAL_CONFIRM_QUEUE: "0" }, stdio: ["pipe", "pipe", "pipe"] });
  let out = ""; proxy.stdout.setEncoding("utf8"); proxy.stdout.on("data", d => out += d);
  let err = ""; proxy.stderr.setEncoding("utf8"); proxy.stderr.on("data", d => err += d);
  proxy.stdin.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) + "\n");
  // a proxy that never exits would keep this test file running forever: stopped after 20 s, which fails the test
  const code = await new Promise<number | null | "still running">(r => {
    const t = setTimeout(() => { proxy.kill(); r("still running"); }, 20_000);
    proxy.on("exit", c => { clearTimeout(t); r(c); });
  });
  assert.equal(code, 0, err); assert.match(out, /"id":1/);
});
