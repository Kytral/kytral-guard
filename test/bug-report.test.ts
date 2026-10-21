// `kytral-guard doctor --report`: the diagnostic to paste into a public bug report. Every section is there, on a fresh
// machine too (no policy file, no audit log), and what must not leave the machine never does: secrets (KYTRAL_SECRET,
// KYTRAL_AUDIT_SECRET, a secret file, a badge, any variable's value, tokens in a policy), tool arguments, audit entries,
// user and host names, paths (the home folder is ~), server names that are not plain names (<name>), unknown variable
// names. Each test runs the CLI with its own home folder, project folder and KYTRAL_HOME: nothing touches the real
// configurations. Also: usage errors that never repeat a value nor name an option this CLI does not have, options checked before
// a command acts (the proxy starts no server after an unknown option), the issue forms and SECURITY.md that ask for the report.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir, hostname, tmpdir, userInfo } from "node:os"; import { basename, dirname, join, resolve, sep } from "node:path"; import { pathToFileURL } from "node:url";
import { parse } from "yaml";
import { DEFAULT_POLICY, issueBadge, loadPolicy } from "../src/index.js";
import { KYTRAL_VARS, redact, runsGuard, serverName, shortPath, tokenLike } from "../src/bug-report.js";

const ROOT = resolve(import.meta.dirname, "..");
const TSX = pathToFileURL(join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;   // the project folder has no node_modules
const VERSION: string = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d";    // the proxies' secret
const AS = "c4f8a2e6d0b4f8a2c6e0d4b8f2a6c0e4d8b2f6a0c4e8d2b6f0a4c8e2d6b0f4a8";   // their audit secret
const GHP = "ghp_N4r7Q2x9L1m8K3v6B5c0Z7a2S4d6F8g1H3j5";
/** A name as a whole word, whatever the case: how the report must never show a user or host name. */
const word = (name: string) => new RegExp(`(?<![A-Za-z0-9])${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![A-Za-z0-9])`, "i");
let realUser = ""; try { realUser = userInfo().username; } catch {}
const realHost = hostname();
/** Claude Desktop's configuration under a home folder (APPDATA and XDG_CONFIG_HOME point inside it, see machine()). */
const desktopConfig = (home: string) => join(home, ...(process.platform === "darwin" ? ["Library", "Application Support"] : process.platform === "win32" ? ["AppData", "Roaming"] : [".config"]), "Claude", "claude_desktop_config.json");

/** A fresh machine: a home folder, a project folder (the CLI's working folder), KYTRAL_HOME (not created), and no KYTRAL_ variable but these. */
function machine(o: { root?: string; kytral?: (home: string, t: string) => string; env?: Record<string, string | undefined> } = {}) {
  const t = o.root ?? mkdtempSync(join(tmpdir(), "kg-report-")), home = join(t, "home"), project = join(t, "project");
  mkdirSync(home, { recursive: true }); mkdirSync(project, { recursive: true });
  const kytral = o.kytral ? o.kytral(home, t) : join(home, ".kytral");
  const env: Record<string, string | undefined> = { ...process.env, HOME: home, USERPROFILE: home, APPDATA: join(home, "AppData", "Roaming"), XDG_CONFIG_HOME: join(home, ".config") };
  for (const k of Object.keys(env)) if (/^KYTRAL_/i.test(k)) delete env[k];
  Object.assign(env, { KYTRAL_HOME: kytral }, o.env);
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  const cli = (...args: string[]) => {
    const r = spawnSync(process.execPath, ["--import", TSX, join(ROOT, "src/cli.ts"), ...args], { cwd: project, env: env as NodeJS.ProcessEnv, encoding: "utf8" });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };
  return { t, home, project, kytral, env, cli };
}

test("doctor --report on a fresh machine: every section, the built-in policy, no audit log, nothing created", () => {
  const m = machine(), r = m.cli("doctor", "--report");
  assert.equal(r.code, 0, r.err);
  const p = loadPolicy(DEFAULT_POLICY), n = (a: string) => p.rules.filter(x => x.action === a).length;
  for (const line of ["### Kytral Guard diagnostic (kytral-guard doctor --report)", "#### Versions", `- kytral-guard: ${VERSION}`, `- Node.js: ${process.versions.node}`,
    "#### Setup (this shell)", "- KYTRAL_HOME: ~/.kytral (default), does not exist yet", "- KYTRAL_ variables set (names only): KYTRAL_HOME", "- KYTRAL_SECRET: not set",
    "#### Agents and MCP servers", "- Agent hooks: none", "- MCP clients: no configuration found",
    "#### Policy", "- Source: built-in default", `- Rules: ${p.rules.length} (block ${n("block")}, confirm ${n("confirm")}, allow ${n("allow")})`,
    "- Default: allow; unknownTools: confirm", "- Presets: the built-in strict preset", "#### Policy (agent hooks)", "- Source: built-in coding-agent preset",
    "- Presets: the built-in coding-agent preset", "#### Kill switch", "- Killed: no", "#### Audit log", "- Present: no"])
    assert.ok(r.out.includes(line), `missing: ${line}\n${r.out}`);
  assert.match(r.out, new RegExp(`^- OS: .+, platform ${process.platform}, arch ${process.arch}$`, "m"));
  assert.doesNotMatch(r.out, /```/, "no code fence: the bug form already shows the output as code (render: shell)");
  assert.match(r.err, /redacted for a public bug report .*read it before posting/);
  assert.ok(!existsSync(m.kytral), "read-only: KYTRAL_HOME is not created");
});

test("doctor --report never shows a secret: KYTRAL_SECRET, KYTRAL_AUDIT_SECRET, a secret file, a badge, a variable's value, tokens in a policy, tool arguments, audit entries", () => {
  const badge = issueBadge(S, "agent-planted-4417", ["*"], 3600, Date.now(), { aud: "kytral-guard:report-test" });
  // a passphrase looks like no token: only the variable that holds it says it is a secret
  const passphrase = "orange-staple-battery-horse-7731", buildRef = "Zq81kQ0pLm2vNb7cXr4tWq19aa", fileSecret = "f1le-s3cret-9d8c7b6a5f4e3d2c1b0a99887766";
  const sk = "sk-live-0123456789abcdefABCDEF", random = "svc_Q7rT2mX9pL4vB8nK3wZ6", argSecret = "--password=hunter2-planted-arg-5521";
  const m = machine({ env: { KYTRAL_SECRET: S, KYTRAL_AUDIT_SECRET: AS, KYTRAL_BADGE: badge, KYTRAL_AUDIENCE: "kytral-guard:report-test", ACME_SERVICE_TOKEN: passphrase, BUILD_REF: buildRef } });
  mkdirSync(m.kytral, { recursive: true }); writeFileSync(join(m.kytral, "secret"), fileSecret + "\n");
  // the MCP configuration: secrets in env, a password and paths among the arguments, and four servers named after a secret
  writeFileSync(join(m.project, ".mcp.json"), JSON.stringify({ mcpServers: {
    fs: { command: "node", args: [join(m.home, "kytral-guard", "dist", "cli.js"), "--policy", join(m.home, "p.yaml"), "--", "npx", "db-server", argSecret], env: { KYTRAL_SECRET: S, KYTRAL_BADGE: badge, KYTRAL_AUDIENCE: "kytral-guard:fs" } },
    github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_TOKEN: GHP } },
    [passphrase]: { command: "kytral-guard", args: ["--", "x"] }, [S]: { command: "y" }, [GHP]: { command: "z" }, [random]: { command: "w" } } }));
  // a policy whose rules and file name hold tokens
  const policy = join(m.t, `policy-${GHP}.yaml`);
  writeFileSync(policy, `rules:\n  - name: ${GHP}\n    argMatches: "${sk}"\n    action: block\n  - name: rule-${passphrase}\n    tool: "*${buildRef}*"\n    action: block\n  - name: mail\n    toolMatches: "send"\n    action: confirm\nknownTools: ["${sk}*"]\n`);
  /** Nothing planted is shown, nor any secret of the environment the report ran in (`env`): without ACME_SERVICE_TOKEN, the server named after its value is just a name. */
  const leaks = (text: string, env: Record<string, string | undefined> = m.env) => {
    for (const s of [S, AS, badge, ...badge.split("."), fileSecret, ...(env.ACME_SERVICE_TOKEN ? [passphrase] : []), buildRef, GHP, sk, random, "hunter2", argSecret, "db-server",
      "agent-planted-4417", "tool_planted_4417", "rule-planted-4417", "approver-planted-4417", "victim-planted", basename(policy), "generation"]) assert.ok(!text.includes(s), `shown: ${s}\n${text}`);
    for (const [k, v] of Object.entries(env)) if (v && v.length >= 8 && /SECRET|TOKEN|PASSW|API_?KEY|PRIVATE|CREDENTIAL/i.test(k)) assert.ok(!text.includes(v), `value of ${k} shown`);
  };
  // a kill journaled by the CLI: the report says yes, never who or when
  assert.equal(m.cli("kill", "--by", "approver-planted-4417").code, 0);
  let r = m.cli("doctor", "--report", "--policy", policy);
  assert.equal(r.code, 0, r.err); leaks(r.out + r.err);
  assert.match(r.out, /^- Killed: yes$/m);
  assert.equal(m.cli("resume", "--by", "approver-planted-4417").code, 0);
  // decisions journaled with their agent, tool and rule (and arguments, which real entries never hold): only their number is shown
  const audit = join(m.kytral, "audit.jsonl");
  for (const tool of ["tool_planted_4417", "send_mail"])
    appendFileSync(audit, JSON.stringify({ ts: new Date().toISOString(), agentId: "agent-planted-4417", tool, decision: "block", rule: "rule-planted-4417", args: { to: "victim-planted@example.com" }, prev: "x", hash: "y" }) + "\n");
  r = m.cli("doctor", "--report", "--policy", policy);
  assert.equal(r.code, 0, r.err); leaks(r.out + r.err);
  const entries = readFileSync(audit, "utf8").split("\n").filter(Boolean).length;
  assert.ok(entries >= 4);
  for (const line of [/^- Killed: no$/m, new RegExp(`^- Present: yes, ${entries} entries$`, "m"),
    /^- Claude Code, project \.mcp\.json: wrapped: fs, <name>; not wrapped: github, <name>, <name>, <name>$/m,
    /^- Source: the file given with --policy \(name redacted\)$/m, /^- Rules: 3 \(block 2, confirm 1, allow 0\)$/m,
    /^- KYTRAL_ variables set \(names only\): KYTRAL_AUDIENCE, KYTRAL_AUDIT_SECRET, KYTRAL_BADGE, KYTRAL_HOME, KYTRAL_SECRET$/m,
    /^- KYTRAL_SECRET: set, usable$/m, /^- KYTRAL_AUDIT_SECRET: set, usable$/m]) assert.match(r.out, line);
  // the secret file, which a proxy started in this shell would use, holds another secret: the resume does not verify with it,
  // so that proxy would stay stopped (fail closed), and the report says so, still without who or when
  const f = machine({ root: m.t, env: { KYTRAL_HOME: m.kytral } }), withFile = f.cli("doctor", "--report");
  assert.match(withFile.out, /^- Killed: yes$/m); leaks(withFile.out + withFile.err, f.env);
  // without the secret the state cannot be verified: the report says so, still without who or when
  const b = machine({ root: m.t, env: { KYTRAL_HOME: m.kytral, KYTRAL_SECRET_FILE: join(m.t, "no-secret-file") } }), bare = b.cli("doctor", "--report");
  assert.match(bare.out, /^- Killed: no \(signature not checked: no usable secret in this shell\)$/m); leaks(bare.out + bare.err, b.env);
  // a weak secret is refused in words that do not quote it
  const weak = machine({ root: m.t, env: { KYTRAL_HOME: m.kytral, KYTRAL_SECRET: "changeme-changeme" } }).cli("doctor", "--report");
  assert.match(weak.out, /^- KYTRAL_SECRET: set, refused \(too short: .*\)$/m); assert.ok(!weak.out.includes("changeme"));
});

test("doctor --report shows the home folder as ~ and any other absolute path as <path>; user and host names never appear", () => {
  const pu = "planteduser7731", ph = "plantedhost7731";
  // the real and the planted names are in every path: the temporary folder, the home folder, KYTRAL_HOME, the policy file
  const root = join(mkdtempSync(join(tmpdir(), "kg-report-")), `${realUser || "u"}-${realHost}-${pu}-${ph}`);
  const env = { USER: pu, LOGNAME: pu, USERNAME: pu, HOSTNAME: `${ph}.example.com`, COMPUTERNAME: ph, KYTRAL_SECRET: S };
  const m = machine({ root, env });
  mkdirSync(join(m.home, ".cursor"), { recursive: true });
  writeFileSync(join(m.home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { [`db-${pu}`]: { command: "kytral-guard", args: ["--", "x"] }, [`${ph}-files`]: { command: "x" },
    [`${realHost}.files`]: { command: "x" }, [`${realUser || "u"}_db`]: { command: "x" }, [join(m.t, "a-path-as-a-name")]: { command: "x" } } }));
  // Claude Code: user servers, and the local servers of this project, under its path (as given, and real: the CLI's working folder is either)
  const local = { mcpServers: { local1: { command: "x" } } };
  writeFileSync(join(m.home, ".claude.json"), JSON.stringify({ mcpServers: { shared: { command: "npx", args: ["-y", "kytral-guard@0.1.0", "--", "x"] } },
    projects: { [m.project]: local, [realpathSync(m.project)]: local, [join(m.t, "elsewhere")]: { mcpServers: { other: { command: "x" } } } } }));
  mkdirSync(dirname(desktopConfig(m.home)), { recursive: true }); writeFileSync(desktopConfig(m.home), `{ "mcpServers": { "a": ${GHP} } `);
  const policy = join(m.t, `${pu}-${ph}-policy.yaml`); writeFileSync(policy, "rules: []\n");
  assert.equal(m.cli("kill", "--by", pu).code, 0);
  const r = m.cli("doctor", "--report", "--policy", policy), text = r.out + r.err;
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /^- KYTRAL_HOME: ~\/\.kytral \(default\), exists$/m);
  for (const p of [m.t, realpathSync(m.t), basename(dirname(m.t)), ...(homedir().length > 3 ? [homedir()] : [])]) assert.ok(!text.includes(p), `path shown: ${p}\n${text}`);
  for (const n of [pu, ph]) assert.ok(!text.toLowerCase().includes(n), `name shown: ${n}\n${text}`);
  for (const n of [realUser, realHost, realHost.split(".")[0]]) if (n.length >= 2) assert.doesNotMatch(text, word(n), `name shown: ${n}\n${text}`);
  assert.ok(!text.includes(GHP), "an unreadable configuration is not quoted");
  // a name that holds a user or host name, or that is a path, is not shown at all (u_db: no real user name to hide)
  for (const line of [/^- Cursor, user \(~\/\.cursor\/mcp\.json\): wrapped: <name>; not wrapped: <name>, <name>, (?:<name>|\w_db), <name>$/m,
    /^- Claude Code, user \(~\/\.claude\.json\): wrapped: shared; not wrapped: none$/m, /^- Claude Code, local \(~\/\.claude\.json, this project\): wrapped: none; not wrapped: local1$/m,
    /^- Claude Desktop: cannot be read \(not valid JSON\)$/m, /^- Killed: yes$/m]) assert.match(r.out, line);
  assert.doesNotMatch(r.out, /\bother\b/, "another project's local servers are not listed");
  // KYTRAL_HOME outside the home folder: <path>
  const out = machine({ root: join(m.t, "second"), kytral: (_h, t) => join(t, `state-${pu}`), env }).cli("doctor", "--report");
  assert.equal(out.code, 0, out.err); assert.match(out.out, /^- KYTRAL_HOME: <path>, does not exist yet$/m);
  assert.ok(!out.out.toLowerCase().includes(pu) && !out.out.includes(m.t));
});

test("doctor --report: a server name only if it is a plain name, KYTRAL_HOME in three forms, KYTRAL_ variables named only if this version reads them", () => {
  // free text as a name (a URL with a password, a query token, a key=value pair, non-ASCII), a token prefix, a leading -
  const plain = ["filesystem", "brave-search", "my_db.prod", "context7", "claude-3-5-sonnet-20241022"];
  const hidden = ["postgres://admin:hunter2@db", "api?token=tok12345", "db password=Pw0rd!x9", "naïve", "-x", "ghp_short"];
  const m = machine({ env: { KYTRAL_HOME: undefined, KYTRAL_SECRT: "planted-value-4417", kytral_planted_4417: "x" } });
  writeFileSync(join(m.project, ".mcp.json"), JSON.stringify({ mcpServers: Object.fromEntries([...plain, ...hidden].map(n => [n, { command: "x" }])) }));
  const r = m.cli("doctor", "--report"), text = r.out + r.err;
  assert.equal(r.code, 0, r.err);
  assert.ok(r.out.includes(`- Claude Code, project .mcp.json: wrapped: none; not wrapped: ${[...plain, ...hidden.map(() => "<name>")].join(", ")}\n`), r.out);
  for (const s of ["hunter2", "tok12345", "pw0rd", "naïve", "ghp_", "kytral_secrt", "planted"]) assert.ok(!text.toLowerCase().includes(s), `shown: ${s}\n${text}`);
  // KYTRAL_HOME not set: the default; outside the home folder: <path> (previous test); under it: only that it is
  assert.match(r.out, /^- KYTRAL_HOME: ~\/\.kytral \(default\), does not exist yet$/m);
  assert.match(r.out, /^- KYTRAL_ variables set \(names only\): none; plus 2 unknown to this version \(not named\)$/m);
  const c = machine({ root: m.t, kytral: home => join(home, "clients", "acme-planted-4417", ".kytral") }).cli("doctor", "--report");
  assert.equal(c.code, 0, c.err); assert.match(c.out, /^- KYTRAL_HOME: under ~ \(custom\), does not exist yet$/m);
  assert.ok(!(c.out + c.err).includes("acme"), c.out);
});

test("serverName() and tokenLike(): plain names as they are; free text, a token, a secret of the environment: <name>", () => {
  const plain = ["filesystem", "github", "brave-search", "sequential-thinking", "my_db.prod", "context7", "k8s-cluster-01", "claude-3-5-sonnet-20241022",
    "ec2-us-east-1-prod-01", "PostgresProd2024Replica", "orange-staple-battery-horse-7731", "e2e-tests-2024-10-20", "npm_search", "hf-mcp-server", "a", "x".repeat(64)]
    .filter(n => ![realUser, realHost, realHost.split(".")[0]].some(w => w.length >= 2 && word(w).test(n)));
  for (const n of plain) { assert.ok(!tokenLike(n), n); assert.equal(serverName(n), n, n); }
  // token prefixes (even short), hex (UUIDs too), random-looking strings: base62, lowercase or uppercase base36, base64url
  for (const n of [GHP, S, "github_pat_" + "A1b2".repeat(6), "sk-proj-abc", "sk_live_x", "xoxb-1", "AKIAQAQAQAQAQAQAQAQA", "AIzaSyQAQAQAQ", "eyJhbGciOi", "glpat-x",
    "npm_" + "Zq81kQ0pLm2vNb7cXr4tWq19aaB3", "hf_" + "QwErTyUiOpAsDfGhJkLzXcVbNm", "0123456789abcdef", "123e4567-e89b-12d3-a456-426614174000", "Zq81kQ0pLm2vNb7cXr4t",
    "k3j5h2g8f9d7s6a4q1w2", "Q7RT2MX9PL4VB8NK3WZ6", "svc_Q7rT2mX9pL4vB8nK3wZ6", "key-3ax6xnjp29jd6fds4gc373sgvjxteol0"]) { assert.ok(tokenLike(n), n); assert.equal(serverName(n), "<name>", n); }
  for (const n of ["postgres://admin:hunter2@db", "api?token=tok12345", "db password=Pw0rd!x9", "user@host", "a/b", "C:\\x", "-x", ".x", "_x", "naïve", "tab\tname", "", "x".repeat(65)])
    assert.equal(serverName(n), "<name>", JSON.stringify(n));
  // a passphrase looks like no token: only the variable that holds it says it is a secret
  const planted = "orange-staple-planted-7731";
  assert.equal(serverName(planted), planted);
  process.env.ACME_PLANTED_SERVICE_TOKEN = planted;
  try { assert.equal(serverName(planted), "<name>"); } finally { delete process.env.ACME_PLANTED_SERVICE_TOKEN; }
});

test("KYTRAL_VARS: every KYTRAL_ variable the code reads, in order", () => {
  const read = new Set<string>();
  for (const f of readdirSync(join(ROOT, "src")).filter(f => f.endsWith(".ts")))
    for (const x of readFileSync(join(ROOT, "src", f), "utf8").matchAll(/process\.env(?:\.|\[["'`])(KYTRAL_[A-Z0-9_]+)/g)) read.add(x[1]);
  assert.deepEqual([...read].sort(), KYTRAL_VARS);
});

test("doctor --report: agent hooks by id with their problems in fixed words, the AI apps' MCP servers, the hooks' policy; every line from the whitelist", () => {
  const m = machine({ env: { KYTRAL_SECRET: S } }), appData = dirname(dirname(desktopConfig(m.home))), hunter = "hunter2-planted-4417";
  for (const d of [".claude", ".cursor", ".codex"]) mkdirSync(join(m.home, d), { recursive: true });
  assert.equal(m.cli("init", "claude-code", "cursor").code, 0);   // run from the sources, the hooks name a cli.js that only a build creates
  const wrapped = { command: process.execPath, args: [join(m.home, "kytral-guard", "dist", "cli.js"), "--", "npx", "srv", `--password=${hunter}`], env: { KYTRAL_BADGE: "b" } };
  const put = (f: string, text: string) => { mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, text); };
  // VS Code (comments allowed, "servers"), Cline as Cursor keeps it, Continue (a YAML list of servers that carry their name)
  put(join(appData, "Code", "User", "mcp.json"), `{\n  // planted comment ${hunter}\n  "servers": { "fs": ${JSON.stringify(wrapped)}, "gh": { "command": "npx", "args": ["${hunter}"] }, },\n}\n`);
  put(join(appData, "Cursor", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), JSON.stringify({ mcpServers: { [`postgres://u:${hunter}@h`]: { command: "x" } } }));
  put(join(m.home, ".continue", "config.yaml"), `mcpServers:\n  - name: pg\n    command: npx\n    args: ["${hunter}"]\n  - name: guarded\n    command: ${JSON.stringify(process.execPath)}\n    args: ${JSON.stringify(wrapped.args)}\n    env: { KYTRAL_BADGE: b }\n`);
  put(join(m.home, ".lmstudio", "mcp.json"), `{ "mcpServers": { "a": ${hunter} } `);
  const r = m.cli("doctor", "--report"), text = r.out + r.err;
  assert.equal(r.code, 0, r.err);
  for (const line of ["- Agent hooks: installed for claude-code, cursor; found without the hook: codex; problems: claude-code: a file it runs is missing; cursor: a file it runs is missing",
    "- VS Code: wrapped: fs; not wrapped: gh", "- Cline (Cursor): wrapped: none; not wrapped: <name>", "- Continue: wrapped: guarded; not wrapped: pg", "- LM Studio: cannot be read (not valid JSON)",
    "#### Policy (agent hooks)", "- Source: the policy file in the kytral home folder (what kytral-guard init writes)", "- Presets: extends coding-agent; built in: strict, coding-agent"])
    assert.ok(r.out.split("\n").includes(line), `missing: ${line}\n${r.out}`);
  for (const s of [S, hunter, "planted", m.t, realpathSync(m.t), "cli.js", "settings.json", "hooks.json", "mcp.json", "config.yaml"]) assert.ok(!text.includes(s), `shown: ${s}\n${text}`);
  // the proxies' policy kept in KYTRAL_HOME, the hooks' policy named by KYTRAL_POLICY: what they are, never their names
  writeFileSync(join(m.kytral, "mcp-policy.yaml"), "extends: strict\nrules: []\n");
  const named = join(m.t, `${hunter}.yaml`); writeFileSync(named, "rules:\n  - name: x\n    action: block\n");
  const p = machine({ root: m.t, env: { KYTRAL_SECRET: S, KYTRAL_POLICY: named } }).cli("doctor", "--report");
  assert.equal(p.code, 0, p.err); assert.ok(!(p.out + p.err).includes(hunter), p.out);
  for (const line of ["- Source: the mcp policy file in the kytral home folder (what a proxy started without --policy or --preset uses)", "- Presets: extends strict; built in: strict, coding-agent",
    "- Source: the file the policy variable names (name redacted)", "- Rules: 1 (block 1, confirm 0, allow 0)", "- Presets: none (extends no preset); built in: strict, coding-agent"])
    assert.ok(p.out.split("\n").includes(line), `missing: ${line}\n${p.out}`);
  // every line of both reports has one of the whitelisted shapes (test/bypass-pr16-r14.test.ts)
  const NAME = "(?:<name>|[A-Za-z0-9][A-Za-z0-9._-]{0,63})", NAMES = `(?:none|${NAME}(?:, ${NAME})*(?:, and \\d+ more)?)`;
  const T = [/^$/, /^#{3,4} [A-Za-z ():-]+(?: \(kytral-guard doctor --report\))?$/, /^Redacted: .*$/, /^- kytral-guard: (\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?|unknown)$/, /^- Node\.js: \d+\.\d+\.\d+$/,
    /^- OS: (Linux|Darwin|Windows_NT|FreeBSD|OpenBSD|NetBSD|SunOS|AIX|other) (\d+(\.\d+){0,3}|unknown)( \(WSL\))?, platform [a-z0-9]+, arch [a-z0-9]+$/,
    /^- KYTRAL_HOME: (~\/\.kytral \(default\)|under ~ \(custom\)|<path>), (exists|does not exist yet)$/, /^- KYTRAL_ variables set \(names only\): (none|KYTRAL_[A-Z_]+(, KYTRAL_[A-Z_]+)*)(; plus \d+ unknown to this version \(not named\))?$/,
    /^- KYTRAL_(AUDIT_)?SECRET: (not set|set but empty|set, usable|set, refused \([a-z0-9 :,]+\))$/, /^- Agent hooks: [A-Za-z0-9 ,;:()-]+$/, new RegExp(`^- [A-Za-z ,.()~/]+: (wrapped: ${NAMES}; not wrapped: ${NAMES}|no MCP server|cannot be read \\([A-Za-z0-9_ ]+\\))$`),
    /^- MCP clients: no configuration found .*$/, /^- Source: [a-z -]+\(?[a-z -]*\)?(, (cannot be read \([A-Z0-9_]+\)|does not load: [A-Za-z0-9 ':|()]+))?$/, /^- Rules: \d+ \(block \d+, confirm \d+, allow \d+\)$/,
    /^- Default: (allow|block|confirm|unknown); unknownTools: (allow|block|confirm|unknown)$/, /^- Presets: [a-z ,;:()-]+$/, /^- Killed: (yes|no)( \(signature not checked: no usable secret in this shell\))?$/,
    /^- Present: (no|yes, \d+ entr(y|ies)|yes, cannot be read \([A-Z0-9_]+\))$/, /^- could not be checked \([A-Z0-9_]+\)$/];
  for (const line of [...r.out.split("\n"), ...p.out.split("\n")]) assert.ok(T.some(re => re.test(line)), `line out of the whitelist: ${JSON.stringify(line)}`);
});

test("doctor --report: a policy that cannot be read or does not load says why, without quoting it or naming it", () => {
  const m = machine(), f = (name: string, text: string) => { const p = join(m.t, name); writeFileSync(p, text); return p; };
  const cases: [string, RegExp][] = [
    [f("yaml.yaml", `rules:\n  - name: ok\n    action: block\n  - name: "${GHP}\n    action: [unclosed\n`), /^- Source: .*, does not load: YAML syntax error at line \d+$/m],
    [f("regex.yaml", `rules:\n  - name: r\n    argMatches: "(${GHP}"\n    action: block\n`), /, does not load: a rule has an invalid regular expression$/m],
    [f("action.yaml", `rules:\n  - name: ${GHP}\n    action: maybe\n`), /, does not load: policy: bad action in a rule$/m],
    [f("dialect.yaml", `sqlDialect: ${GHP}\nrules: []\n`), /, does not load: policy: unsupported sqlDialect$/m],
    [f("norules.yaml", "default: allow\n"), /, does not load: policy: 'rules' list required$/m],
    [f("nullrule.yaml", "rules:\n  - null\n"), /, does not load: not a valid policy$/m],
    [join(m.t, `missing-${GHP}.yaml`), /^- Source: the file given with --policy \(name redacted\), cannot be read \(ENOENT\)$/m],
  ];
  for (const [file, expect] of cases) {
    const r = m.cli("doctor", "--report", "--policy", file);
    assert.equal(r.code, 0, r.err); assert.match(r.out, expect, file);
    assert.ok(!(r.out + r.err).includes(GHP) && !(r.out + r.err).includes(basename(file)), `quoted: ${file}\n${r.out}`);
  }
});

test("--help lists doctor --report; doctor without --report checks the setup; an operand, or --policy without --report, gives its usage", () => {
  const m = machine();
  const h = m.cli("--help");
  assert.equal(h.code, 0); assert.ok(h.out.startsWith(`Kytral Guard ${VERSION} `)); assert.match(h.out, /kytral-guard doctor --report \[--policy file\]/);
  // doctor alone: the setup check (ok / warn / FAIL lines), not a usage error; nothing to fix but the missing secret here
  const d = m.cli("doctor");
  assert.equal(d.code, 1, d.out + d.err); assert.match(d.out, /^FAIL  secret: /m); assert.match(d.out, /^ok    self-test: /m); assert.doesNotMatch(d.err, /usage:/);
  for (const args of [["doctor", "extra"], ["doctor", "--report", "extra"], ["doctor", "--policy", "p.yaml"]]) {
    const r = m.cli(...args);
    assert.equal(r.code, 2, args.join(" ")); assert.match(r.err, /^usage: kytral-guard doctor --report/);
  }
  assert.equal(m.cli("doctor", "--report", "--verbose").err.trim(), "kytral-guard: unknown option; run kytral-guard --help");
  const u = m.cli("doctor", "--help");
  assert.equal(u.code, 0); assert.match(u.out, /^usage: kytral-guard doctor --report/);
});

test("usage errors name an option only if this CLI has it, never the value typed with it", () => {
  const m = machine(), unknown = "unknown option; run kytral-guard --help";
  for (const [args, said] of [[["doctor", "--report", "--token=planted-4417"], unknown], [["doctor", "--report", "--policy=planted-4417"], unknown],
    [["kill", "--by=planted-4417"], unknown], [["doctor", "--report", "--planted:4417"], unknown], [["doctor", "--report", "--verbose", "planted-4417"], unknown]] as [string[], string][]) {
    const r = m.cli(...args);
    assert.equal(r.code, 2, args.join(" ")); assert.equal(r.err.trim(), `kytral-guard: ${said}`); assert.ok(!(r.out + r.err).includes("planted"), r.err);
  }
  assert.ok(!existsSync(join(m.kytral, "kill-switch.json")), "a usage error engages nothing");
});

test("every command and the proxy: an option this CLI does not have is never named, in any form, nor a value repeated; an operand that starts with - goes after --", () => {
  const m = machine({ env: { KYTRAL_SECRET: S, KYTRAL_AUDIENCE: "kytral-guard:report-test" } }), unknown = "kytral-guard: unknown option; run kytral-guard --help";
  const shown = (r: { out: string; err: string }) => r.out + r.err, what = (args: string[]) => args.join(" ").replaceAll(GHP, "<token>");
  // a token typed as an option, after each command (the secret is set: confirm and badge get past it)
  for (const c of [["kill"], ["resume"], ["audit", "verify"], ["known", "list"], ["known", "remove", "tool"], ["confirm", "list"], ["confirm", "approve"], ["confirm", "deny"],
    ["doctor", "--report"], ["badge", "agent", "*", "60"], ["revoke"]]) {
    const r = m.cli(...c, `--${GHP}`);
    assert.equal(r.code, 2, what(c)); assert.equal(r.err.trim(), unknown, what(c)); assert.ok(!shown(r).includes(GHP), what(c));
  }
  // with one dash, or a value after =: an option too, never taken as the operand (an id, a tool, a file, what to revoke)
  for (const args of [["confirm", "approve", `-${GHP}`], ["confirm", "deny", `-t=${GHP}`], ["known", "remove", `-${GHP}`], ["audit", "verify", `-t=${GHP}`], ["revoke", `-${GHP}`], ["revoke", `--x=${GHP}`]]) {
    const r = m.cli(...args);
    assert.equal(r.code, 2, what(args)); assert.equal(r.err.trim(), unknown, what(args)); assert.ok(!shown(r).includes(GHP), what(args));
  }
  assert.ok(!existsSync(join(m.kytral, "kill-switch.json")) && !existsSync(join(m.kytral, "revocations.json")), "a usage error engages and revokes nothing");
  // an option of another command is not named either; an invalid request id is not repeated
  assert.equal(m.cli("kill", "--full").err.trim(), unknown);
  const id = m.cli("confirm", "deny", "planted-4417");
  assert.equal(id.code, 2); assert.match(id.err, /^kytral-guard: invalid request id: /); assert.ok(!shown(id).includes("planted"), id.err);
  // after --, operands, even those that start with -
  const rv = m.cli("revoke", "--", "-agent-7");
  assert.equal(rv.code, 0, rv.err); assert.equal(rv.out, "revoked -agent-7\n");
  assert.match(m.cli("known", "remove", "--", "-tool-7").out, /^not found\t\(any server\)\t-tool-7\t\(any agent\)$/m);
  // the proxy: a --policy file it cannot read, a server command it cannot start: an error code, not the path nor the arguments
  const p = m.cli("--policy", join(m.t, `missing-${GHP}.yaml`), "--", process.execPath, "-e", "0");
  assert.equal(p.code, 2); assert.equal(p.err.trim(), "kytral-guard: refusing to start: the --policy file cannot be read (ENOENT)"); assert.ok(!shown(p).includes(GHP));
  const s = m.cli("--", join(m.t, "no-such-server"), `--api-key=${GHP}`);
  assert.equal(s.code, 1); assert.equal(s.err.trim(), "kytral-guard: the MCP server command cannot be started (ENOENT)"); assert.ok(!shown(s).includes(GHP));
});

test("the proxy fails closed: an unknown option before -- (--policy=file, a misspelling, one dash, among known ones) starts no server and is not repeated; after --, every argument is the server's", () => {
  const m = machine({ env: { KYTRAL_SECRET: S, KYTRAL_AUDIENCE: "kytral-guard:report-test" } }), unknown = "kytral-guard: unknown option; run kytral-guard --help";
  const usage = "usage: kytral-guard [proxy] [--policy file | --preset name] -- <mcp server command...>", what = (args: string[]) => args.join(" ").replaceAll(m.t, "<t>");
  // a policy whose path holds a planted value, and a server that records each start with its arguments (the secret is set: only the options stop it)
  const policy = join(m.t, "policy-planted-4417.yaml"), server = join(m.t, "server.mjs"), started = join(m.t, "started.jsonl");
  writeFileSync(policy, "rules: []\n");
  writeFileSync(server, `import { appendFileSync } from "node:fs";\nappendFileSync(${JSON.stringify(started)}, JSON.stringify(process.argv.slice(2)) + "\\n");\n`);
  const starts = () => existsSync(started) ? readFileSync(started, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l)) : [];
  // --policy=<file> is not this CLI's syntax (--policy <file>): it used to be ignored, and the server ran under the built-in policy
  for (const opts of [[`--policy=${policy}`], ["--polcy", policy], ["--policy-file", policy], ["-p", policy], ["-policy", policy], ["--policy", policy, "--dry-run"],
    ["--dry-run", "--policy", policy], ["--policy", policy, `--planted-4417=${policy}`, "--policy", policy]]) {
    const r = m.cli(...opts, "--", process.execPath, server);
    assert.equal(r.code, 2, what(opts)); assert.equal(r.err.trim(), unknown, what(opts)); assert.equal(r.out, "", what(opts));
    assert.ok(opts.every(x => !r.err.includes(x)), `repeated: ${what(opts)}`);   // no name (--policy neither), no value
  }
  // other mistakes before the server command: the file without --policy, -- taken for its file, --policy twice, no --, nothing after --
  for (const [args, said] of [[[policy, "--", process.execPath, server], usage], [["--policy", "--", process.execPath, server], "kytral-guard: --policy needs a value"],
    [["--policy", policy, "--policy", policy, "--", process.execPath, server], "kytral-guard: --policy given more than once"],
    [["--policy", policy, process.execPath, server], usage], [["--policy", policy, "--"], usage],
    // a preset that does not exist is not repeated, and a file and a preset together are not both taken
    [["--preset", "planted-4417", "--", process.execPath, server], "kytral-guard: unknown preset (strict, coding-agent)"],
    [["--policy", policy, "--preset", "strict", "--", process.execPath, server], "kytral-guard: use --policy or --preset, not both"],
    [["proxy", "--polcy", policy, "--", process.execPath, server], unknown]] as [string[], string][]) {
    const r = m.cli(...args);
    assert.equal(r.code, 2, what(args)); assert.equal(r.err.trim(), said, what(args)); assert.equal(r.out, "", what(args)); assert.ok(!r.err.includes("planted"), r.err);
  }
  assert.deepEqual(starts(), [], "no server started");
  // after the first --, nothing is parsed: options of any form, and another --, reach the server as they are
  const tail = ["--polcy", "x", `--policy=${policy}`, "-p", "--", "--dry-run"];
  const ok = m.cli("--policy", policy, "--", process.execPath, server, ...tail);
  assert.equal(ok.code, 0, ok.err);
  const bare = m.cli("--", process.execPath, server, "-z");
  assert.equal(bare.code, 0, bare.err);
  assert.deepEqual(starts(), [tail, ["-z"]]);
});

test("every other command checks its options before it acts: an unknown one among known ones, an option of another command, an option given twice", () => {
  const m = machine({ env: { KYTRAL_SECRET: S, KYTRAL_AUDIENCE: "kytral-guard:report-test" } }), unknown = "kytral-guard: unknown option; run kytral-guard --help";
  for (const args of [["kill", "--by", "ops", "--now"], ["doctor", "--report", "--verbose", "--policy", "p.yaml"], ["doctor", "--report", "--by", "ops"],
    ["badge", "agent", "*", "60", "--once", "-v"], ["confirm", "approve", "x", "--always", "--force", "--full"], ["known", "remove", "tool", "--by", "ops", "--all"]]) {
    const r = m.cli(...args);
    assert.equal(r.code, 2, args.join(" ")); assert.equal(r.err.trim(), unknown, args.join(" ")); assert.equal(r.out, "", args.join(" "));
  }
  for (const args of [["kill", "--by", "a", "--by", "b"], ["doctor", "--report", "--policy", "a.yaml", "--policy", "b.yaml"], ["confirm", "deny", "x", "--by", "a", "--by", "b"]]) {
    const r = m.cli(...args);
    assert.equal(r.code, 2, args.join(" ")); assert.equal(r.err.trim(), `kytral-guard: ${args.at(-2)} given more than once`, args.join(" ")); assert.equal(r.out, "", args.join(" "));
  }
  assert.ok(!existsSync(join(m.kytral, "kill-switch.json")), "a usage error engages nothing");
});

test("redact(): secrets, the home folder, other paths, user and host names, tokens; ordinary text unchanged", () => {
  const home = homedir();
  const env = { KYTRAL_SECRET: S, ACME_API_KEY: "k3y-0f-acme-Wq81zz", BUILD_ID: "Zq81kQ0pLm2vNb7cXr4tWq19", USER: "planted-user", HOSTNAME: "planted-host.example.com",
    PATH: "/usr/bin:/bin", SHORT_TOKEN: "abc", SSH_AUTH_SOCK: "/tmp/ssh-x/agent.1" };
  const r = (s: string) => redact(s, env);
  assert.equal(r(`a ${S} b`), "a <redacted> b");
  assert.equal(r("key k3y-0f-acme-Wq81zz."), "key <redacted>.");
  assert.equal(r("id Zq81kQ0pLm2vNb7cXr4tWq19"), "id <redacted>", "a variable's value shaped like a credential, whatever its name");
  if (home.length > 3) {   // not with HOME=/ (some containers): no folder is then shown as ~
    assert.equal(r(home), "~"); assert.equal(r(join(home, ".kytral")), `~${sep}.kytral`); assert.equal(r(`(${join(home, "a b")})`), `(~${sep}a b)`);
    assert.equal(r(`${home}:/opt/x`), "~:<path>"); assert.equal(r(`${home}2${sep}x`), "<path>");
  }
  assert.equal(r("see /etc/kytral/policy.yaml, then /srv/x"), "see <path>, then <path>");
  assert.equal(r("C:\\Users\\other\\p.yaml and \\\\server\\share\\x"), "<path> and <path>");
  assert.equal(r("db-planted-user, Planted-Host and planted-host.example.com"), "db-<user>, <host> and <host>");
  for (const tok of [GHP, "github_pat_" + "A1b2".repeat(10), "xoxb-1234567890-abcdefghij", "AKIAABCDEFGHIJKLMNOP", "sk-proj-" + "Ab1".repeat(10),
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", issueBadge(S, "a", ["*"], 60, Date.now(), { aud: "kytral-guard:t" }), "0123456789abcdef".repeat(4),
    "Zm9vYmFyQmF6MTIzNDU2Nzg5MGFiY2RlZkdISUpLTE1OT1BRUlNU", "svc_Q7rT2mX9pL4vB8nK3wZ6"]) assert.equal(r(`x ${tok} y`), "x <redacted> y", tok);
  assert.equal(r("getUserById2FactorAuth, PostgresProd2024Replica, KYTRAL_CONFIRM_TIMEOUT_MS"), "getUserById2FactorAuth, PostgresProd2024Replica, KYTRAL_CONFIRM_TIMEOUT_MS", "names are not tokens");
  assert.equal(r("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE\n-----END OPENSSH PRIVATE KEY-----"), "<redacted>");
  const plain = ["- kytral-guard: 0.1.0", "- Default: allow; unknownTools: confirm", "- KYTRAL_HOME: ~/.kytral (exists)", "- n/a, allow/confirm, https://github.com/Kytral/kytral-guard",
    "- Rules: 12 (block 5, confirm 7, allow 0)", "- Cursor, project .cursor/mcp.json: wrapped: fs-guarded; not wrapped: abc"].join("\n");
  if (![realUser, realHost].some(n => n.length >= 2 && word(n).test(plain))) assert.equal(r(plain), plain);
});

test("runsGuard() and shortPath()", () => {
  for (const e of [{ command: "node", args: ["/x/kytral-guard/dist/cli.js", "--policy", "p.yaml", "--", "npx", "srv"] }, { command: "kytral-guard", args: ["--", "srv"] },
    { command: "npx", args: ["-y", "kytral-guard@0.1.0", "--", "srv"] }, { command: "C:\\tools\\kytral-guard.cmd", args: ["--", "srv"] },
    { command: "node", args: ["/home/me/kg/dist/cli.js", "--", "srv"], env: { KYTRAL_BADGE: "b" } }]) assert.ok(runsGuard(e), JSON.stringify(e));
  for (const e of [{ command: "node", args: ["/home/me/kg/dist/cli.js", "--", "srv"] }, { command: "npx", args: ["srv", "--", "kytral-guard"] },
    { command: "kytral-guard" }, { type: "http", url: "https://x.example.com/mcp" }, "kytral-guard -- srv", null]) assert.ok(!runsGuard(e), JSON.stringify(e));
  const home = resolve("/home/kg-someone");
  assert.equal(shortPath(home, home), "~"); assert.equal(shortPath(join(home, ".kytral", "x"), home), "~/.kytral/x");
  assert.equal(shortPath(`${home}2`, home), "<path>"); assert.equal(shortPath(join(home, "..", "elsewhere"), home), "<path>"); assert.equal(shortPath(resolve("/srv/kytral"), home), "<path>");
});

test("issue forms and SECURITY.md: the bug form asks for doctor --report, vulnerabilities go to the security policy, the supported version follows package.json", () => {
  const form = (f: string) => parse(readFileSync(join(ROOT, ".github", "ISSUE_TEMPLATE", f), "utf8"));
  const bug = form("bug_report.yml"), ids: string[] = bug.body.map((b: any) => b.id).filter(Boolean);
  assert.deepEqual(ids, [...new Set(ids)], "ids are unique");
  for (const id of ["what-happened", "expected", "steps", "doctor-report", "client", "os", "version"]) assert.ok(ids.includes(id), id);
  const report = bug.body.find((b: any) => b.id === "doctor-report");
  assert.match(report.attributes.label, /kytral-guard doctor --report/); assert.equal(report.attributes.render, "shell");
  assert.ok(bug.body.some((b: any) => b.type === "checkboxes" && b.attributes.options.some((o: any) => o.required && /secret/.test(o.label) && /audit log/.test(o.label))));
  for (const f of ["bug_report.yml", "feature_request.yml"]) { const x = form(f); assert.ok(x.name && x.description && Array.isArray(x.body) && x.body.every((b: any) => b.type && b.attributes), f); }
  const config = form("config.yml");
  assert.equal(config.blank_issues_enabled, false);
  assert.ok(config.contact_links.some((l: any) => l.url === "https://github.com/Kytral/kytral-guard/security/policy" && l.name && l.about));
  const policy = readFileSync(join(ROOT, "SECURITY.md"), "utf8"), [major, minor] = VERSION.split(".");
  assert.match(policy, new RegExp(`^\\| ${major}\\.${minor}\\.x \\| Yes \\|$`, "m"), "the current minor release is supported");
  assert.match(policy, new RegExp(`^\\| < ${major}\\.${minor} \\| No \\|$`, "m"), "older ones are not");
  for (const s of ["security@kytral.com", "Report a vulnerability", "2 business days", "7 days", "30 days"]) assert.ok(policy.includes(s), s);
  // email first; GitHub's private reporting works only once the repository is public; the response times are targets
  assert.match(policy, /^Report it privately, by email to \*\*security@kytral\.com\*\*\. Once the repository is public, you can also use GitHub private\s+vulnerability reporting/m);
  assert.match(policy, /^We aim to:\n\n- acknowledge your report within 2 business days;\n- .* within 7 days;\n- .* within 30 days\.$/m);
  assert.ok(config.contact_links.some((l: any) => /by email to security@kytral\.com/.test(l.about)));
});
