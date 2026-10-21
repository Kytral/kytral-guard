// End-to-end: real MCP client JSON-RPC over stdio -> kytral-guard proxy -> real @modelcontextprotocol/server-filesystem.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, ChildProcess, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { issueBadge } from "../src/badge.js";
import { listRequests } from "../src/confirm-queue.js";
import { verifyChain } from "../src/audit.js";

const ROOT = resolve(import.meta.dirname, "..");
const SECRET = "9f2c4e7a1b3d5f60718293a4b5c6d7e8f9012a3b4c5d6e7f8091a2b3c4d5e6f7";
const AUD = "kytral-guard:e2e";
// Run with node directly: the node_modules/.bin shim is a POSIX script that cannot be spawned on Windows.
const SERVER = [process.execPath, join(ROOT, "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js")];

function startProxy(dir: string, badge: string, extraEnv: Record<string, string> = {}) {
  const audit = join(dir, "audit.jsonl");
  const p = spawn(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "--", ...SERVER, dir],
    { cwd: ROOT, env: { ...process.env, KYTRAL_SECRET: SECRET, KYTRAL_AUDIENCE: AUD, KYTRAL_BADGE: badge, KYTRAL_AUDIT: audit, ...extraEnv }, stdio: ["pipe", "pipe", "pipe"] });
  const pending = new Map<number, (m: any) => void>();
  createInterface({ input: p.stdout! }).on("line", l => { try { const m = JSON.parse(l); pending.get(m.id)?.(m); pending.delete(m.id); } catch {} });
  let id = 0;
  const rpc = (method: string, params: any = {}) => new Promise<any>((res, rej) => {
    const i = ++id; pending.set(i, res); p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id: i, method, params }) + "\n");
    setTimeout(() => rej(new Error(`timeout ${method}`)), 20000);
  });
  const init = async () => {
    const r = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e", version: "0" } });
    p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    return r;
  };
  return { p, rpc, init, audit, stop: () => (p as ChildProcess).kill() };
}
const text = (r: any) => (r.result?.content ?? []).map((c: any) => c.text).join("\n");

test("e2e: real filesystem MCP server through the proxy", { timeout: 60000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "kg-e2e-"));
  writeFileSync(join(dir, "hello.txt"), "hello kytral");
  const s = startProxy(dir, issueBadge(SECRET, "e2e-agent", ["*"], 600, Date.now(), { aud: AUD }));
  try {
    const init = await s.init();
    assert.ok(init.result?.serverInfo, "initialize passes through");
    const list = await s.rpc("tools/list");
    assert.ok(list.result.tools.some((t: any) => t.name === "read_text_file"));
    const ok = await s.rpc("tools/call", { name: "read_text_file", arguments: { path: join(dir, "hello.txt") } });
    assert.ok(!ok.result.isError); assert.match(text(ok), /hello kytral/);
    const bad = await s.rpc("tools/call", { name: "write_file", arguments: { path: join(dir, "x.sh"), content: "rm -rf /" } });
    assert.equal(bad.result.isError, true); assert.match(text(bad), /Kytral Guard: blocked/);
    assert.equal(existsSync(join(dir, "x.sh")), false, "blocked call never reached the server");
    const lines = readFileSync(s.audit, "utf8").trim().split("\n").map(l => JSON.parse(l));
    assert.deepEqual(lines.map(l => l.decision), ["allow", "block"]);
  } finally { s.stop(); }
});

test("e2e: proxy refuses to start with weak secret or missing/shared audience", { timeout: 30000 }, async () => {
  const cases: Record<string, string>[] = [{ KYTRAL_SECRET: "", KYTRAL_AUDIENCE: AUD }, { KYTRAL_SECRET: "short", KYTRAL_AUDIENCE: AUD }, { KYTRAL_SECRET: "a".repeat(40), KYTRAL_AUDIENCE: AUD },
    { KYTRAL_SECRET: SECRET, KYTRAL_AUDIENCE: "" }, { KYTRAL_SECRET: SECRET, KYTRAL_AUDIENCE: "kytral-guard" }];
  for (const env of cases) {
    const secret = JSON.stringify(env);
    const p = spawn(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "--", ...SERVER, tmpdir()], { cwd: ROOT, env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let err = ""; p.stderr!.on("data", d => err += d);
    const code = await new Promise(r => p.on("exit", r));
    assert.equal(code, 2, `secret ${JSON.stringify(secret)}`); assert.match(err, /refusing to start/);
  }
});

test("e2e: non-JSON and batch through the proxy", { timeout: 60000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "kg-e2e-"));
  const s = startProxy(dir, issueBadge(SECRET, "e2e-agent", ["*"], 600, Date.now(), { aud: AUD }));
  const raw: string[] = []; createInterface({ input: s.p.stdout! }).on("line", l => raw.push(l));
  try {
    await s.init();
    s.p.stdin!.write("not json at all\n");
    s.p.stdin!.write(JSON.stringify([{ jsonrpc: "2.0", id: 900, method: "tools/call", params: { name: "write_file", arguments: { path: join(dir, "y.sh"), content: "rm -rf /" } } }]) + "\n");
    await new Promise(r => setTimeout(r, 1500));
    assert.ok(raw.some(l => /-32700/.test(l)), "parse error returned");
    assert.ok(raw.some(l => l.startsWith("[") && /Kytral Guard: blocked/.test(l)), "batch element refused");
    assert.equal(existsSync(join(dir, "y.sh")), false);
  } finally { s.stop(); }
});

test("e2e: badge scope and kill switch with real server", { timeout: 60000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "kg-e2e-"));
  writeFileSync(join(dir, "a.txt"), "a");
  const s = startProxy(dir, issueBadge(SECRET, "reader", ["list_directory"], 600, Date.now(), { aud: AUD }));
  try {
    await s.init(); await s.rpc("tools/list");   // real clients list tools first: the proxy learns them (unknownTools=confirm)
    const ok = await s.rpc("tools/call", { name: "list_directory", arguments: { path: dir } });
    assert.match(text(ok), /a\.txt/);
    const no = await s.rpc("tools/call", { name: "write_file", arguments: { path: join(dir, "b.txt"), content: "b" } });
    assert.match(text(no), /not on badge/); assert.equal(existsSync(join(dir, "b.txt")), false);
  } finally { s.stop(); }
  const k = startProxy(dir, issueBadge(SECRET, "reader", ["*"], 600, Date.now(), { aud: AUD }), { KYTRAL_KILL: "1" });
  try {
    await k.init(); await k.rpc("tools/list");
    const r = await k.rpc("tools/call", { name: "list_directory", arguments: { path: dir } });
    assert.match(text(r), /kill switch active/);
  } finally { k.stop(); }
  const other = startProxy(dir, issueBadge(SECRET, "reader", ["*"], 600, Date.now(), { aud: "kytral-guard:other-proxy" }));
  try {
    await other.init(); await other.rpc("tools/list");
    const r = await other.rpc("tools/call", { name: "list_directory", arguments: { path: dir } });
    assert.match(text(r), /wrong audience/, "badge for another proxy is refused");
  } finally { other.stop(); }
});

test("e2e: unknown tool -> confirmation queue -> CLI approve --always (who/when); kill switch wins; known remove -> asked again -> deny", { timeout: 120000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "kg-e2e-")); writeFileSync(join(dir, "a.txt"), "a");
  const home = join(dir, "home"); const queueDir = join(home, "confirmations"); const audit = join(dir, "audit.jsonl");
  const badge = issueBadge(SECRET, "e2e-agent", ["*"], 600, Date.now(), { aud: AUD });
  const env = { KYTRAL_HOME: home, KYTRAL_CONFIRM_QUEUE: "1", KYTRAL_CONFIRM_TIMEOUT_MS: "30000" };
  const cli = (...a: string[]) => execFileSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...a],
    { cwd: ROOT, env: { ...process.env, KYTRAL_SECRET: SECRET, KYTRAL_AUDIENCE: AUD, KYTRAL_HOME: home, KYTRAL_AUDIT: audit }, encoding: "utf8", stdio: "pipe" });
  const nextRequest = async () => {
    for (let i = 0; i < 400; i++) { const [r] = listRequests(SECRET, queueDir).requests; if (r) return r; await new Promise(res => setTimeout(res, 50)); }
    throw new Error("no confirmation request");
  };
  const ls = { name: "list_directory", arguments: { path: dir } };
  const s = startProxy(dir, badge, env);
  try {
    await s.init();                                                                    // no tools/list: every tool is unknown
    const first = s.rpc("tools/call", ls);
    const r = await nextRequest();
    assert.deepEqual([r.tool, r.agentId, r.rule, r.always], ["list_directory", "e2e-agent", "unknown-tool", true]);
    assert.match(cli("confirm", "list"), new RegExp(`^${r.id}\ttool=list_directory\t`, "m"));
    assert.match(cli("confirm", "approve", r.id, "--always", "--by", "alice"), /^approve_always\t/);
    assert.match(text(await first), /a\.txt/);
    assert.match(text(await s.rpc("tools/call", ls)), /a\.txt/, "known now");
    assert.equal(listRequests(SECRET, queueDir).requests.length, 0, "nothing queued for a known tool");
    assert.match(cli("known", "list"), /\tlist_directory\te2e-agent\talice \(os:[^)]+\)\t\d{4}-/);
    const k = startProxy(dir, badge, { ...env, KYTRAL_KILL: "1" });                   // same state, kill switch on
    try { await k.init(); assert.match(text(await k.rpc("tools/call", ls)), /kill switch active/); } finally { k.stop(); }
    assert.match(cli("known", "remove", "list_directory", "--by", "bob"), /^removed\t/m);
    const third = s.rpc("tools/call", ls);
    const r3 = await nextRequest();
    assert.match(cli("confirm", "deny", r3.id), /^deny\t/);
    assert.match(text(await third), /confirmation refused/);
  } finally { s.stop(); }
  const lines = readFileSync(audit, "utf8").trim().split("\n").map(l => JSON.parse(l));
  assert.deepEqual(lines.map(e => e.decision), ["known-add", "confirmed-always", "allow", "block", "known-remove", "block"]);
  assert.match(lines[0].approver, /^alice \(os:.+\)$/); assert.match(lines[4].approver, /^bob \(os:.+\)$/);
  assert.equal(lines[2].rule, "known-tool");
  assert.ok(verifyChain(lines), "two proxies and the CLI wrote one valid chain");
});
