// Adversarial regression probes: `kytral-guard doctor --report`. Green = nothing leaks. Each test runs the real CLI with
// its own HOME, project folder and KYTRAL_HOME.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path"; import { pathToFileURL } from "node:url";

const ROOT = resolve(import.meta.dirname, "..");
const TSX = pathToFileURL(join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d";
// Short secrets, of unknown format or encoded: redaction by patterns does not recognize them.
const SHORT = ["hunter2", "Pw0rd!x9", "tok12345", "test-sekret-77", "zebra-loom-91"];
function machine(env: Record<string, string> = {}) {
  const t = mkdtempSync(join(tmpdir(), "kg-test-")), home = join(t, "home"), project = join(t, "project"), kytral = join(home, ".kytral");
  mkdirSync(home, { recursive: true }); mkdirSync(project, { recursive: true });
  const e: Record<string, string | undefined> = { ...process.env, HOME: home, USERPROFILE: home, APPDATA: join(home, "AppData", "Roaming"), XDG_CONFIG_HOME: join(home, ".config") };
  for (const k of Object.keys(e)) if (/^KYTRAL_/i.test(k)) delete e[k];
  Object.assign(e, { KYTRAL_HOME: kytral }, env);
  const cli = (args: string[], extra: string[] = []) => {
    const r = spawnSync(process.execPath, ["--import", TSX, ...extra, join(ROOT, "src/cli.ts"), ...args], { cwd: project, env: e as NodeJS.ProcessEnv, encoding: "utf8" });
    return { code: r.status, out: r.stdout, err: r.stderr, all: r.stdout + r.stderr };
  };
  return { t, home, project, kytral, cli };
}
const noLeak = (text: string, secrets: string[]) => { for (const s of secrets) assert.ok(!text.includes(s), `leak: ${JSON.stringify(s)}\n${text}`); };

test("env_secrets_any_format_never_shown: environment values (KYTRAL_*, GITHUB_*, *_TOKEN, *_KEY, AWS, URLs with credentials), even short ones", () => {
  const env = { KYTRAL_SECRET: S, KYTRAL_AUDIT_SECRET: "c4f8a2e6d0b4f8a2c6e0d4b8f2a6c0e4d8b2f6a0c4e8d2b6f0a4c8e2d6b0f4a8", KYTRAL_BADGE: "eyJhbGciOi.test.badge", KYTRAL_X: "hunter2",
    GITHUB_TOKEN: "Pw0rd!x9", GH_TOKEN: "tok12345", NPM_TOKEN: "test-sekret-77", OPENAI_API_KEY: "zebra-loom-91", AWS_ACCESS_KEY_ID: "AKIAQAQAQAQAQAQAQAQA",
    AWS_SECRET_ACCESS_KEY: "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", AWS_SESSION_TOKEN: "FwoGZXIvYXdzEQAQAQ", DATABASE_URL: "postgres://dbuser:Pw0rd!x9@db.internal:5432/app",
    SLACK_WEBHOOK: "https://hooks.slack.com/services/T000/B000/XXXXtestsecret", MY_PASSWORD: "hunter2" };
  const r = machine(env).cli(["doctor", "--report"]); assert.equal(r.code, 0, r.err);
  noLeak(r.all, [...Object.values(env).filter(v => v !== S || true), "dbuser", "db.internal", "XXXXtestsecret"]);
});

test("mcp_configs_args_env_urls_headers_never_shown: the 6 config locations, arguments, env, user:pass@ and ?token= URLs, headers", () => {
  const m = machine();
  const servers = { qa: { command: "kytral-guard", args: ["--policy", "/srv/p.yaml", "--", "npx", "srv", "--password=hunter2", "postgres://u:Pw0rd!x9@h/db"], env: { KYTRAL_SECRET: S, API_KEY: "tok12345" } },
    remote: { type: "http", url: "https://qa:test-sekret-77@mcp.example.com/sse?token=zebra-loom-91", headers: { Authorization: "Bearer zebra-loom-91" } } };
  const files = [join(m.project, ".mcp.json"), join(m.home, ".claude.json"), join(m.project, ".cursor", "mcp.json"), join(m.home, ".cursor", "mcp.json"), join(m.home, ".config", "Claude", "claude_desktop_config.json")];
  for (const f of files) { mkdirSync(join(f, ".."), { recursive: true }); writeFileSync(f, JSON.stringify({ mcpServers: servers, projects: { [m.project]: { mcpServers: servers } } })); }
  const r = m.cli(["doctor", "--report"]); assert.equal(r.code, 0, r.err);
  noLeak(r.all, [...SHORT, S, "/srv/p.yaml", "mcp.example.com", "Bearer", "srv"]);
  assert.match(r.out, /wrapped: qa; not wrapped: remote/);
});

test("server_name_free_text: a server name holding credentials (user:pass@ URL, ?token=, k=v) is not copied as is", () => {
  const m = machine();
  writeFileSync(join(m.project, ".mcp.json"), JSON.stringify({ mcpServers: { "postgres://admin:hunter2@db": { command: "x" }, "api?token=tok12345": { command: "y" }, "db password=Pw0rd!x9": { command: "z" } } }));
  const r = m.cli(["doctor", "--report"]); assert.equal(r.code, 0, r.err);
  noLeak(r.all, ["hunter2", "tok12345", "Pw0rd!x9"]);
});

test("policy_points_to_secret_files: --policy pointing to .env, JSON, AWS INI, a PEM key, YAML of the wrong schema => nothing quoted", () => {
  const m = machine(), d = join(m.t, "p"); mkdirSync(d);
  const cases: Record<string, string> = {
    env: "GITHUB_TOKEN=hunter2\nPASSWORD=Pw0rd!x9\n", json: '{"token":"tok12345","password":"test-sekret-77"}', ini: "[default]\naws_secret_access_key = zebra-loom-91\n",
    pem: "-----BEGIN OPENSSH PRIVATE KEY-----\nhunter2hunter2\n-----END OPENSSH PRIVATE KEY-----\n", rules: "rules: hunter2\n", dflt: "rules: []\ndefault: Pw0rd!x9\n",
    dialect: "rules: []\nsqlDialect: tok12345\n", action: "rules:\n  - name: test-sekret-77\n    action: zebra-loom-91\n", analyzer: "rules:\n  - name: hunter2\n    analyzer: Pw0rd!x9\n    action: block\n",
    regex: "rules:\n  - name: r\n    argMatches: \"(tok12345\"\n    action: block\n", alias: "rules: *hunter2\n", dup: "rules: []\nrules: [tok12345]\n", known: "rules: []\nknownTools: test-sekret-77\n" };
  for (const [k, v] of Object.entries(cases)) { const f = join(d, `${k}-hunter2.yaml`); writeFileSync(f, v);
    const r = m.cli(["doctor", "--report", "--policy", f]); assert.equal(r.code, 0, `${k}: ${r.err}`); noLeak(r.all, SHORT); }
  const link = join(d, "link.yaml"); symlinkSync(join(d, "env-hunter2.yaml"), link);
  noLeak(m.cli(["doctor", "--report", "--policy", link]).all, SHORT);
  noLeak(m.cli(["doctor", "--report", "--policy", d]).all, SHORT);   // a folder: EISDIR
});

test("state_files_content_never_shown: audit (corrupt lines included), confirmations, known-tools, allowlist, kill-switch.json corrupt or signed", () => {
  const m = machine({ KYTRAL_SECRET: S }); mkdirSync(join(m.kytral, "confirmations"), { recursive: true });
  writeFileSync(join(m.kytral, "audit.jsonl"), JSON.stringify({ agentId: "hunter2", tool: "tok12345", args: { pw: "Pw0rd!x9" } }) + "\nnot json test-sekret-77\n" + "zebra-loom-91");
  writeFileSync(join(m.kytral, "confirmations", "a.request.json"), JSON.stringify({ tool: "hunter2", args: { token: "tok12345" } }));
  writeFileSync(join(m.kytral, "known-tools.json"), JSON.stringify({ hunter2: ["tok12345"] })); writeFileSync(join(m.kytral, "allowlist.json"), '{"test-sekret-77":1}');
  writeFileSync(join(m.kytral, "revocations.json"), '["zebra-loom-91"]');
  writeFileSync(join(m.kytral, "kill-switch.json"), '{"v":2,"killed":true,"by":"hunter2","note":"Pw0rd!x9"');   // corrupt
  let r = m.cli(["doctor", "--report"]); assert.equal(r.code, 0, r.err); noLeak(r.all, SHORT); assert.match(r.out, /^- Killed: yes$/m); assert.match(r.out, /^- Present: yes, 3 entries$/m);
  const k = machine({ KYTRAL_SECRET: S }); assert.equal(k.cli(["kill", "--by", "hunter2"]).code, 0);   // signed kill (intact journal)
  r = k.cli(["doctor", "--report"]); noLeak(r.all, SHORT); assert.match(r.out, /^- Killed: yes$/m);
});

test("symlinked_client_configs: a client config replaced with a link to a secret file or a loop => no content", () => {
  const m = machine(), sec = join(m.t, "secret.txt"); writeFileSync(sec, "token=hunter2\npassword=Pw0rd!x9\n");
  symlinkSync(sec, join(m.home, ".claude.json")); symlinkSync(join(m.project, ".mcp.json"), join(m.project, ".mcp.json.loop")); symlinkSync(join(m.project, ".mcp.json.loop"), join(m.project, ".mcp.json"));
  const r = m.cli(["doctor", "--report"]); assert.equal(r.code, 0, r.err); noLeak(r.all, [...SHORT, "secret.txt"]);
});

test("cli_errors_do_not_echo_secrets: an unknown option or a missing value does not copy a secret typed on the command line", () => {
  const m = machine();
  for (const args of [["doctor", "--report", "--token=hunter2"], ["doctor", "--report", "--token", "tok12345"], ["doctor", "--report", "hunter2"], ["doctor", "--policy"]]) {
    const r = m.cli(args); assert.notEqual(r.code, 0); noLeak(r.all, SHORT);
  }
});

test("paths_under_home: a KYTRAL_HOME under ~ with a folder named after a secret does not copy it (only ~ is shown)", () => {
  const m = machine(); const kh = join(m.home, "clients", "hunter2-acme", ".kytral");
  const r = machineWith(m, kh); noLeak(r.all, ["hunter2-acme"]);
});
function machineWith(m: ReturnType<typeof machine>, kh: string) {
  const e = { ...process.env, HOME: m.home, KYTRAL_HOME: kh } as NodeJS.ProcessEnv; for (const k of Object.keys(e)) if (/^KYTRAL_(?!HOME)/i.test(k)) delete e[k];
  const r = spawnSync(process.execPath, ["--import", TSX, join(ROOT, "src/cli.ts"), "doctor", "--report"], { cwd: m.project, env: e, encoding: "utf8" });
  return { all: r.stdout + r.stderr };
}

test("no_write_no_network_no_subprocess: --report writes no file, opens no connection, starts no process; output = stdout only", () => {
  const m = machine({ KYTRAL_SECRET: S }); mkdirSync(m.kytral, { recursive: true }); writeFileSync(join(m.kytral, "audit.jsonl"), "{}\n");
  writeFileSync(join(m.project, ".mcp.json"), JSON.stringify({ mcpServers: { a: { command: "kytral-guard", args: ["--", "x"] } } }));
  const marker = join(m.t, "net-marker"), hook = join(m.t, "hook.mjs");
  writeFileSync(hook, `import net from "node:net"; import dns from "node:dns"; import http from "node:http"; import https from "node:https"; import cp from "node:child_process"; import tls from "node:tls"; import { appendFileSync } from "node:fs"; import { syncBuiltinESMExports } from "node:module";
const mark = (w) => function () { appendFileSync(${JSON.stringify(marker)}, w + "\\n"); throw new Error("blocked " + w); };
net.Socket.prototype.connect = mark("connect"); net.connect = net.createConnection = mark("net"); tls.connect = mark("tls");
dns.lookup = mark("dns"); dns.resolve = mark("dns"); http.request = http.get = mark("http"); https.request = https.get = mark("https"); globalThis.fetch = mark("fetch");
for (const k of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) cp[k] = mark(k); syncBuiltinESMExports();`);
  const list = (d: string): string[] => readdirSync(d, { withFileTypes: true }).flatMap(e => e.isDirectory() ? list(join(d, e.name)).map(x => join(e.name, x)) : [join(e.name) + ":" + statSync(join(d, e.name)).mtimeMs + ":" + statSync(join(d, e.name)).size]);
  const before = list(m.t);
  const r = m.cli(["doctor", "--report"], ["--import", pathToFileURL(hook).href]); assert.equal(r.code, 0, r.err);
  assert.ok(!existsSync(marker), `network/process used: ${existsSync(marker) ? readFileSync(marker, "utf8") : ""}`);
  assert.deepEqual(list(m.t), before, "no file created or modified");
  assert.match(r.out, /^### Kytral Guard diagnostic/);
});
