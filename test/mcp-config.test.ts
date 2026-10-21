// `kytral-guard mcp list | wrap | unwrap`: the MCP servers of the AI apps run through the proxy, and back; files merged,
// remote servers left alone, an unreadable file never overwritten, and a wrapped server really works through the proxy.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"; import { tmpdir } from "node:os"; import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { listMcp, unwrapMcp, wrapMcp, isWrapped } from "../src/mcp-config.js";
import { verifyBadge } from "../src/badge.js";
import { evaluate, presetPolicy } from "../src/policy.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "7c1e9a4f2b8d6035e9a2c7f4b1d8e5a2c9f6b3d0e7a4c1f8b5d2e9a6c3f0b7d4";
const tmp = () => mkdtempSync(join(tmpdir(), "kg-mcp-"));
const write = (f: string, v: unknown) => { mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, JSON.stringify(v, null, 2)); };
const read = (f: string) => JSON.parse(readFileSync(f, "utf8"));
const CLI = join(ROOT, "src", "cli.ts");

function apps() {
  const home = tmp(), appData = join(home, "AppData");
  const claude = join(appData, "Claude", "claude_desktop_config.json"), vscode = join(appData, "Code", "User", "mcp.json");
  const claudeConfig = { globalShortcut: "Ctrl+Space", mcpServers: {
    fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\me\\Documents"] },
    linear: { url: "https://mcp.linear.app/sse" } } };
  const vscodeConfig = { inputs: [{ id: "token", type: "promptString" }], servers: {
    github: { type: "stdio", command: "docker", args: ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"], env: { GITHUB_TOKEN: "${input:token}" } },
    web: { type: "http", url: "https://example.com/mcp" } } };
  write(claude, claudeConfig); write(vscode, vscodeConfig);
  return { home, appData, claude, vscode, claudeConfig, vscodeConfig, o: { home, appData, cliPath: CLI, nodePath: process.execPath } };
}

test("wrap runs every local server of the apps through the proxy, with its own audience and badge; unwrap restores them", () => {
  const t = apps();
  const before = listMcp(t.o);
  assert.deepEqual(before.map(f => f.client), ["claude-desktop", "vscode"]);
  assert.deepEqual(before[0].servers.map(s => [s.name, s.remote, s.wrapped]), [["fs", false, false], ["linear", true, false]]);
  const w = wrapMcp(S, t.o);
  assert.deepEqual(w.map(c => c.changed), [["fs"], ["github"]]);
  assert.match(w[0].skipped[0].why, /remote/); assert.ok(w[0].backup && existsSync(w[0].backup));
  const c = read(t.claude), fs = c.mcpServers.fs;
  assert.equal(c.globalShortcut, "Ctrl+Space", "other settings are kept"); assert.deepEqual(c.mcpServers.linear, t.claudeConfig.mcpServers.linear);
  assert.equal(fs.command, process.execPath);
  assert.deepEqual(fs.args, [CLI, "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\me\\Documents"]);
  assert.equal(fs.env.KYTRAL_AUDIENCE, "kytral-guard:mcp:claude-desktop:fs");
  const badge = verifyBadge(S, fs.env.KYTRAL_BADGE, new Set(), Date.now(), { audience: fs.env.KYTRAL_AUDIENCE });
  assert.ok(badge.expiresAt > Date.now() + 4 * 365 * 24 * 3600 * 1000, "a badge lasts years: wrap again renews it");
  const gh = read(t.vscode).servers.github;
  assert.equal(gh.type, "stdio"); assert.equal(gh.env.GITHUB_TOKEN, "${input:token}"); assert.ok(isWrapped(gh));
  assert.deepEqual(read(t.vscode).inputs, t.vscodeConfig.inputs);
  assert.deepEqual(wrapMcp(S, t.o).map(r => r.changed), [[], []], "wrapping twice changes nothing");
  assert.ok(listMcp(t.o).every(f => f.servers.every(s => s.remote || s.wrapped)));
  assert.deepEqual(unwrapMcp(t.o).map(r => r.changed), [["fs"], ["github"]]);
  assert.deepEqual(read(t.claude), t.claudeConfig); assert.deepEqual(read(t.vscode), t.vscodeConfig);
});

test("a wrapped server that no longer works is shown and repaired by wrap: a new secret, a moved CLI or node, a badge near its end; never a revoked one", () => {
  const t = apps();
  wrapMcp(S, { ...t.o, clients: ["claude-desktop"] });
  const fs = () => read(t.claude).mcpServers.fs;
  const problem = (secret = S, now?: number) => listMcp({ ...t.o, clients: ["claude-desktop"], secret, now })[0].servers.find(s => s.name === "fs")!.problem;
  assert.equal(problem(), undefined, "a fresh wrap works");
  assert.deepEqual(wrapMcp(S, { ...t.o, clients: ["claude-desktop"] })[0].changed, [], "and is left as it is");
  // a new secret: every call of the old badge is refused; wrap gives it a badge of this secret, for the same audience
  const S2 = "4e8b2f6a1c9d3075e2b8f4a6c1d9e3b7a5f2c8e4d1b7a3f9c6e2d8b4a1f7c3e5", aud = fs().env.KYTRAL_AUDIENCE;
  assert.match(problem(S2)!, /not signed by this secret/);
  const r = wrapMcp(S2, { ...t.o, clients: ["claude-desktop"] })[0];
  assert.deepEqual(r.changed, ["fs"]); assert.match(r.renewed![0].why, /not signed by this secret/);
  assert.equal(verifyBadge(S2, fs().env.KYTRAL_BADGE, new Set(), Date.now(), { audience: aud }).aud, aud);
  assert.deepEqual(fs().args.slice(fs().args.indexOf("--") + 1), ["npx", "-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\me\\Documents"], "its own command is kept");
  // a CLI and a node that are gone (a Node.js upgrade): this installation's
  const c = read(t.claude); c.mcpServers.fs.args[0] = join(t.home, "old", "dist", "cli.js"); c.mcpServers.fs.command = join(t.home, "old", "node.exe"); write(t.claude, c);
  assert.match(problem(S2)!, /node is no longer at/);
  assert.deepEqual(wrapMcp(S2, { ...t.o, clients: ["claude-desktop"] })[0].changed, ["fs"]);
  assert.equal(fs().command, process.execPath); assert.equal(fs().args[0], CLI); assert.equal(problem(S2), undefined);
  // a badge in its last 30 days (badges last 5 years)
  const later = Date.now() + (5 * 365 - 10) * 24 * 3600 * 1000;
  assert.match(problem(S2, later)!, /expires within 30 days/);
  // revoked (by its agent): shown, and never renewed, which would undo the revocation
  writeFileSync(join(process.env.KYTRAL_HOME!, "revocations.json"), JSON.stringify(["mcp:claude-desktop:fs"]));
  try {
    assert.match(problem(S)!, /revoked/);
    const badge = fs().env.KYTRAL_BADGE, w = wrapMcp(S, { ...t.o, clients: ["claude-desktop"] })[0];
    assert.deepEqual(w.changed, []); assert.match(w.skipped.find(s => s.name === "fs")!.why, /revoked: left as it is/); assert.equal(fs().env.KYTRAL_BADGE, badge);
  } finally { writeFileSync(join(process.env.KYTRAL_HOME!, "revocations.json"), "[]"); }
});

test("a moved node keeps the badge; a revoked badge is never renewed, even with a moved node; another KYTRAL_HOME is not checked with this secret", () => {
  const t = apps();
  wrapMcp(S, { ...t.o, clients: ["claude-desktop"] });
  const fs = () => read(t.claude).mcpServers.fs, badge = fs().env.KYTRAL_BADGE;
  const moveNode = () => { const c = read(t.claude); c.mcpServers.fs.command = join(t.home, "old", "node.exe"); write(t.claude, c); };
  // only the path is repaired: the badge still works and is kept
  moveNode();
  assert.deepEqual(wrapMcp(S, { ...t.o, clients: ["claude-desktop"] })[0].changed, ["fs"]);
  assert.equal(fs().command, process.execPath); assert.equal(fs().env.KYTRAL_BADGE, badge, "the badge is kept");
  // revoked: nothing is renewed, whatever else is wrong
  const rev = join(process.env.KYTRAL_HOME!, "revocations.json");
  writeFileSync(rev, JSON.stringify([JSON.parse(Buffer.from(badge.split(".")[0], "base64url").toString()).id]));
  try {
    moveNode();
    const w = wrapMcp(S, { ...t.o, clients: ["claude-desktop"] })[0];
    assert.deepEqual(w.changed, []); assert.match(w.skipped.find(s => s.name === "fs")!.why, /revoked: left as it is/);
    assert.equal(fs().env.KYTRAL_BADGE, badge); assert.notEqual(fs().command, process.execPath);
  } finally { writeFileSync(rev, "[]"); }
  // a server wrapped for another KYTRAL_HOME uses that home's secret: not checked, not re-signed with this one
  const c = read(t.claude); c.mcpServers.fs.command = process.execPath; c.mcpServers.fs.env.KYTRAL_HOME = join(t.home, "other-home"); write(t.claude, c);
  const S2 = "5d9c3a7e1f4b8062d5c9a3e7f1b4d806c2a5e9f3b7d1c4a8e6f2b9d5c3a7e1f4";
  assert.equal(listMcp({ ...t.o, clients: ["claude-desktop"], secret: S2 })[0].servers.find(s => s.name === "fs")!.problem, undefined);
  assert.deepEqual(wrapMcp(S2, { ...t.o, clients: ["claude-desktop"] })[0].changed, []); assert.equal(fs().env.KYTRAL_BADGE, badge);
});

test("only the apps named, or the files given; an unreadable file is never overwritten", () => {
  const t = apps();
  assert.deepEqual(wrapMcp(S, { ...t.o, clients: ["vscode"] }).map(c => c.client), ["vscode"]);
  assert.throws(() => listMcp({ ...t.o, clients: ["nope"] }), /unknown app 'nope'/);
  const other = join(t.home, "cherry-export.json");
  write(other, { mcpServers: { db: { command: "uvx", args: ["mcp-server-sqlite", "--db-path", "app.db"] } } });
  assert.deepEqual(wrapMcp(S, { ...t.o, files: [other] }).map(c => c.changed), [["db"]]);
  writeFileSync(t.claude, "{ // comments are not JSON\n}");
  const r = wrapMcp(S, { ...t.o, clients: ["claude-desktop"] });
  assert.match(r[0].error!, /has comments or trailing commas.*nothing was changed/); assert.equal(readFileSync(t.claude, "utf8"), "{ // comments are not JSON\n}");
  assert.deepEqual(wrapMcp(S, { ...t.o, clients: ["vscode"], dryRun: true }).map(c => c.changed), [[]], "already wrapped");
});

test("Continue: the YAML list of servers is wrapped and unwrapped, its comments kept", () => {
  const home = tmp(), file = join(home, ".continue", "config.yaml");
  const text = `# my configuration
name: Local config
version: 1.0.0
schema: v1
mcpServers:
  - name: SQLite # the app database
    command: npx
    args:
      - -y
      - mcp-sqlite
      - /Users/me/app.db
  - name: Docs
    type: streamable-http
    url: https://example.com/mcp
`;
  mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, text);
  const o = { home, appData: join(home, "AppData"), cliPath: CLI, nodePath: process.execPath, clients: ["continue"] };
  assert.deepEqual(listMcp(o)[0].servers.map(s => [s.name, s.remote, s.wrapped]), [["SQLite", false, false], ["Docs", true, false]]);
  assert.deepEqual(wrapMcp(S, o).map(c => c.changed), [["SQLite"]]);
  const wrapped = readFileSync(file, "utf8");
  assert.match(wrapped, /# my configuration/); assert.match(wrapped, /# the app database/); assert.match(wrapped, /KYTRAL_BADGE/);
  assert.ok(listMcp(o)[0].servers[0].wrapped);
  assert.deepEqual(unwrapMcp(o).map(c => c.changed), [["SQLite"]]);
  const back = readFileSync(file, "utf8");
  assert.match(back, /# the app database/); assert.doesNotMatch(back, /KYTRAL/);
  assert.match(back, /command: npx/); assert.match(back, /- \/Users\/me\/app\.db/);
});

test("iFlow CLI: its settings.json servers are wrapped (its hooks cannot tell MCP tools apart), its other settings kept", () => {
  const home = tmp(), file = join(home, ".iflow", "settings.json");
  write(file, { hooks: { PreToolUse: [] }, mcpServers: { fs: { command: "npx", args: ["-y", "fs-server"] }, web: { httpUrl: "https://example.com/mcp" } } });
  const r = wrapMcp(S, { home, appData: join(home, "AppData"), cliPath: CLI, nodePath: process.execPath, clients: ["iflow"] });
  assert.deepEqual(r.map(c => c.changed), [["fs"]]); assert.match(r[0].skipped[0].why, /remote/);
  assert.deepEqual(read(file).hooks, { PreToolUse: [] });
});

test("the MCP configurations of these apps are guard files: agents cannot unwrap a server", () => {
  const p = presetPolicy("coding-agent");
  for (const f of ["C:\\Users\\me\\AppData\\Roaming\\Code\\User\\mcp.json", "/home/me/.lmstudio/mcp.json", "/home/me/.config/Claude/claude_desktop_config.json",
    "C:/Users/me/AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"])
    assert.equal(evaluate(p, { tool: "Write", args: { file_path: f, content: "{}" } }).action, "block", f);
});

test("a wrapped server really runs through the proxy: its calls are checked", { timeout: 60000 }, async () => {
  const t = apps(), kh = tmp(), dir = tmp();
  writeFileSync(join(kh, "secret"), S); writeFileSync(join(dir, "hello.txt"), "hello kytral");
  const server = join(ROOT, "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js");
  write(t.claude, { mcpServers: { fs: { command: process.execPath, args: [server, dir] } } });
  wrapMcp(S, { ...t.o, clients: ["claude-desktop"] });
  const e = read(t.claude).mcpServers.fs;
  // what Claude Desktop runs, with tsx to load the TypeScript CLI here
  const env: NodeJS.ProcessEnv = { ...process.env, ...e.env, KYTRAL_HOME: kh, KYTRAL_AUDIT: join(kh, "audit.jsonl") };
  delete env.KYTRAL_SECRET;
  const p = spawn(e.command, ["--import", "tsx", ...e.args], { cwd: ROOT, env, stdio: ["pipe", "pipe", "pipe"] });
  const pending = new Map<number, (m: any) => void>(); let id = 0;
  createInterface({ input: p.stdout! }).on("line", l => { try { const m = JSON.parse(l); pending.get(m.id)?.(m); } catch {} });
  const rpc = (method: string, params: any = {}) => new Promise<any>((res, rej) => {
    const i = ++id; pending.set(i, res); p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id: i, method, params }) + "\n"); setTimeout(() => rej(new Error(`timeout ${method}`)), 20000);
  });
  try {
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "claude-desktop", version: "0" } });
    p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    await rpc("tools/list");
    const ok = await rpc("tools/call", { name: "read_text_file", arguments: { path: join(dir, "hello.txt") } });
    assert.ok(!ok.result.isError, JSON.stringify(ok)); assert.match(JSON.stringify(ok.result), /hello kytral/);
    const bad = await rpc("tools/call", { name: "write_file", arguments: { path: join(dir, "x.sh"), content: "rm -rf /" } });
    assert.equal(bad.result.isError, true); assert.equal(existsSync(join(dir, "x.sh")), false);
  } finally { p.kill(); }
});
