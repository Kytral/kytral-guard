// A policy, a preset, an MCP configuration or a Taskfile is read without printing a word of it, wherever it is read: the
// proxy (its stdout is the MCP channel), the hooks (their stdout is the answer to the agent, their refusals go into the
// agent's context), doctor --report (pasted into public issues), the dashboard, `check`, `allow`, `policy show`, `mcp list`.
// yaml's warnings quote the text at fault and, with LOG_TOKENS or LOG_STREAM set, its parser writes every token on stdout:
// every YAML text goes through quiet-yaml.ts. A hook policy that does not load is refused in fixed words, without its path or a
// word of it; a plugin's policy that does not load too, and it stops the proxy with one line before anything is created.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path"; import { pathToFileURL } from "node:url";
import { parse } from "yaml";
import { parseDocumentQuietly, parseQuietly } from "../src/quiet-yaml.js";
import { evaluate, loadPolicy, policyProblem, presetPolicy, PRESETS } from "../src/policy.js";
import { HookPolicyError, loadHookPolicy } from "../src/hooks.js";
import { addException, basePolicy, listExceptions, removeRule, setOverrides, setPolicyField } from "../src/policy-file.js";
import { listMcp } from "../src/mcp-config.js";
import { startDashboard } from "../src/dashboard.js";

const ROOT = resolve(import.meta.dirname, "..");
const TSX = pathToFileURL(join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d";
const GHP = "ghp_Qm7Zx2Lr9Pw4Ks8Vn5Bt1Hc6Jd3Fg0Ya7Ue4";   // the token planted in each file
const LOG = { LOG_TOKENS: "1", LOG_STREAM: "1" };
const FIXED = /^(YAML syntax error( at line [1-9]\d*)?|a rule has an invalid regular expression|policy: [a-zA-Z' ()|]+|not a valid policy)$/;
/** No 8-character piece of the token, nor `also` (file names, folders). */
function noLeak(text: string, what: string, also: string[] = []) {
  for (let i = 0; i + 8 <= GHP.length; i++) assert.ok(!text.includes(GHP.slice(i, i + 8)), `${what}: a piece of the token is shown\n${text.slice(0, 600)}`);
  for (const s of also) assert.ok(!text.includes(s), `${what}: ${s} is shown\n${text.slice(0, 600)}`);
}
/** A valid policy that makes yaml warn (an unknown tag, a list as a key) and holds the token in a comment, a tag and a key. */
const WARNS = `# ${GHP}\nextends: coding-agent\nrules: []\nknownTools: [!custom "${GHP}*"]\n? [${GHP}]\n: x\n`;
/** The same warnings, with the token in a comment only: what `policy show` prints of a policy holds no token, only yaml's own output would. */
const WARNS_COMMENT = `# ${GHP}\nextends: coding-agent\nrules: []\nknownTools: [!custom "tool-*"]\n? [list, key]\n: x\n`;

/**
 * What `f` prints through the console and the process warnings it emits (kept, not written), with LOG_TOKENS and LOG_STREAM
 * set; they are set again after. yaml prints with console.log (tokens), console.dir (stream) and process.emitWarning
 * (warnings); stdout itself is left alone: the test runner reports on it.
 */
async function printed(f: () => unknown): Promise<string> {
  const out: string[] = [], methods = ["log", "info", "warn", "error", "dir", "debug", "trace"] as const;
  const saved = { c: methods.map(k => console[k]), w: process.emitWarning, env: { LOG_TOKENS: process.env.LOG_TOKENS, LOG_STREAM: process.env.LOG_STREAM } };
  for (const k of methods) console[k] = ((...a: unknown[]) => { out.push(a.map(x => typeof x === "string" ? x : JSON.stringify(x)).join(" ")); }) as typeof console.log;
  process.emitWarning = ((w: unknown) => { out.push(String(w)); }) as typeof process.emitWarning;
  Object.assign(process.env, LOG);
  try { await f(); assert.equal(process.env.LOG_TOKENS, "1"); assert.equal(process.env.LOG_STREAM, "1"); }
  finally {
    methods.forEach((k, i) => { console[k] = saved.c[i] as typeof console.log; }); process.emitWarning = saved.w;
    for (const [k, v] of Object.entries(saved.env)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  return out.join("\n");
}

/** A fresh machine: home, project and KYTRAL_HOME folders, a strong secret, and an MCP server that records each start (with LOG_*). */
function machine() {
  const t = mkdtempSync(join(tmpdir(), "kg-quiet-")), home = join(t, "home"), project = join(t, "project"), kytral = join(t, "kytral-home");
  mkdirSync(home); mkdirSync(project);
  const e: Record<string, string | undefined> = { ...process.env, HOME: home, USERPROFILE: home, APPDATA: join(home, "AppData", "Roaming"), XDG_CONFIG_HOME: join(home, ".config") };
  for (const k of Object.keys(e)) if (/^(KYTRAL_|LOG_TOKENS$|LOG_STREAM$|NODE_OPTIONS$)/i.test(k)) delete e[k];
  Object.assign(e, { KYTRAL_HOME: kytral, KYTRAL_SECRET: S, KYTRAL_AUDIENCE: "kytral-guard:quiet-test" });
  const server = join(t, "server.mjs"), started = join(t, "started.jsonl");
  writeFileSync(server, `import { appendFileSync } from "node:fs";\nappendFileSync(${JSON.stringify(started)}, JSON.stringify({ LOG_TOKENS: process.env.LOG_TOKENS ?? null, LOG_STREAM: process.env.LOG_STREAM ?? null }) + "\\n");\n`);
  const cli = (args: string[], o: { input?: string; env?: Record<string, string> } = {}) => {
    const r = spawnSync(process.execPath, ["--import", TSX, join(ROOT, "src/cli.ts"), ...args], { cwd: project, env: { ...e, ...o.env } as NodeJS.ProcessEnv, encoding: "utf8", input: o.input ?? "" });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };
  const starts = (): Record<string, string | null>[] => existsSync(started) ? readFileSync(started, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l)) : [];
  const file = (name: string, content: string) => { const f = join(t, name); writeFileSync(f, content); return f; };
  return { t, home, project, kytral, cli, starts, file, proxy: (pre: string[], env: Record<string, string> = {}) => cli([...pre, "--", process.execPath, server], { env }) };
}
const event = (command: string, cwd = "/tmp") => JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, cwd, session_id: "s" });

test("every YAML text is read through quiet-yaml.ts: no other module of src/ takes a parser from yaml", () => {
  const PARSERS = new Set(["parse", "parseDocument", "parseAllDocuments", "Parser", "Lexer", "Composer", "LineCounter", "default"]);
  const files = readdirSync(join(ROOT, "src"), { recursive: true }).map(String).filter(f => /\.[cm]?[jt]s$/.test(f) && !f.endsWith("quiet-yaml.ts"));
  assert.ok(files.length > 30);
  for (const f of files) {
    const text = readFileSync(join(ROOT, "src", f), "utf8");
    assert.doesNotMatch(text, /import\s+(\*\s+as\s+)?\w+\s*(,\s*\{[^}]*\})?\s*from\s*["']yaml["']|require\(\s*["']yaml["']\s*\)|import\(\s*["']yaml["']\s*\)/, `${f}: yaml imported whole`);
    for (const m of text.matchAll(/import\s*(?:type\s*)?\{([^}]*)\}\s*from\s*["']yaml["']/g)) {
      const names = m[1].split(",").map(x => x.trim().replace(/^type\s+/, "").split(/\s+as\s+/)[0]).filter(Boolean);
      assert.deepEqual(names.filter(n => PARSERS.has(n)), [], `${f} reads YAML without quiet-yaml.ts`);
    }
  }
});

test("parseQuietly and parseDocumentQuietly print nothing (warnings, LOG_TOKENS, LOG_STREAM), throw or report errors as yaml does, and leave LOG_* as they were", async () => {
  // the harness sees what yaml prints when it is asked to
  const raw = await printed(() => parse(WARNS));
  assert.ok(raw.includes(GHP), "yaml prints its tokens with LOG_TOKENS: the capture sees it");
  assert.equal(await printed(() => assert.deepEqual((parseQuietly(WARNS) as { rules: unknown[] }).rules, [])), "");
  assert.equal(await printed(() => { const d = parseDocumentQuietly(WARNS); assert.equal(d.errors.length, 0); d.toJS(); d.toString(); }), "");
  assert.equal(await printed(() => assert.throws(() => parseQuietly(`a: 1\na: ${GHP}\n`))), "");
  assert.equal(await printed(() => assert.equal(parseDocumentQuietly(`a: 1\na: ${GHP}\n`).errors.length, 1)), "");
});

test("in this process: loadPolicy (extends included), every preset, loadHookPolicy, the policy files the dashboard and `allow` edit, a Continue configuration, a Taskfile and pnpm-workspace.yaml a command runs: nothing printed", async () => {
  const t = mkdtempSync(join(tmpdir(), "kg-quiet-in-")), pol = join(t, "policy.yaml"), bad = join(t, "bad-policy.yaml");
  writeFileSync(pol, WARNS);
  assert.equal(await printed(() => assert.equal(loadPolicy(WARNS).extends, "coding-agent")), "");
  for (const name of Object.keys(PRESETS)) assert.equal(await printed(() => presetPolicy(name)), "", name);
  assert.equal(await printed(() => loadHookPolicy({ policyFile: pol })), "");
  assert.equal(await printed(() => {
    assert.deepEqual(listExceptions(pol), []); basePolicy(pol);
    const name = addException(pol, "echo hello", "allow"); setOverrides(pol, { "shell-destructive": "block" }); setPolicyField(pol, "unknownTools", "block");
    assert.equal(removeRule(pol, name), true); assert.equal(basePolicy(pol, ["unknownTools"]).unknownTools, presetPolicy("coding-agent").unknownTools);
  }), "");
  assert.ok(readFileSync(pol, "utf8").includes(`# ${GHP}`), "comments are kept by the edits");
  // the hooks' policy that does not load: in fixed words for the agent, the file and the parser's message for the user's terminal
  writeFileSync(bad, `default: allow\nrules: []\ndefault: ${GHP}\n`);
  let thrown: unknown;
  assert.equal(await printed(() => { try { loadHookPolicy({ policyFile: bad }); } catch (e) { thrown = e; } }), "");
  assert.ok(thrown instanceof HookPolicyError);
  assert.equal(thrown.fixed, "the hook policy is not a valid policy (YAML syntax error at line 3): 'kytral-guard doctor' says which file and why");
  assert.ok(thrown.message.startsWith(`${bad}: `) && thrown.message.includes(GHP), "the terminal gets the file and the parser's message");
  const missing = (() => { try { loadHookPolicy({ policyFile: join(t, "none.yaml") }); } catch (e) { return e as HookPolicyError; } })()!;
  assert.equal(missing.fixed, "the hook policy cannot be read (ENOENT): 'kytral-guard doctor' says which file and why");
  // Continue keeps its MCP servers in YAML
  const cont = join(t, "config.yaml");
  writeFileSync(cont, `# ${GHP}\nmcpServers:\n  - name: fs\n    command: npx\n    args: ["-y", "server-fs"]\n    env: { TOKEN: !secret "${GHP}" }\n`);
  assert.equal(await printed(() => assert.deepEqual(listMcp({ files: [cont] })[0].servers.map(s => s.name), ["fs"])), "");
  // a Taskfile and a pnpm workspace read while a command is analyzed (in a hook, the analysis runs in a worker whose output is the hook's stdout)
  const proj = join(t, "proj"); mkdirSync(join(proj, "pkgs", "a"), { recursive: true });
  writeFileSync(join(proj, "Taskfile.yml"), `# ${GHP}\nversion: '3'\ntasks:\n  build:\n    cmds: [echo built]\n`);
  writeFileSync(join(proj, "package.json"), JSON.stringify({ name: "root", scripts: { build: "echo root" } }));
  writeFileSync(join(proj, "pnpm-workspace.yaml"), `# ${GHP}\npackages: [!pkgs "pkgs/*"]\n`);
  writeFileSync(join(proj, "pkgs", "a", "package.json"), JSON.stringify({ name: "a", scripts: { build: "rm -rf ~" } }));
  const policy = presetPolicy("coding-agent");
  assert.equal(await printed(() => assert.equal(evaluate(policy, { tool: "Bash", args: { command: "task build" }, cwd: proj }).action, "allow")), "");
  assert.equal(await printed(() => assert.equal(evaluate(policy, { tool: "Bash", args: { command: "pnpm -r run build" }, cwd: proj }).action, "block")), "", "the workspace was read");
});

test("dashboard: its page state and a protection level change read and rewrite both policy files, and print nothing", async () => {
  const t = mkdtempSync(join(tmpdir(), "kg-quiet-dash-")), home = join(t, "home"), kytral = join(t, "kytral");
  mkdirSync(home); mkdirSync(kytral);
  const saved = Object.fromEntries(["HOME", "USERPROFILE", "APPDATA", "XDG_CONFIG_HOME", "KYTRAL_HOME", "KYTRAL_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS", "KYTRAL_AUDIT"].map(k => [k, process.env[k]]));
  Object.assign(process.env, { HOME: home, USERPROFILE: home, APPDATA: join(home, "AppData", "Roaming"), XDG_CONFIG_HOME: join(home, ".config"), KYTRAL_HOME: kytral, KYTRAL_SECRET: S });
  for (const k of ["KYTRAL_POLICY", "KYTRAL_PLUGINS", "KYTRAL_AUDIT"]) delete process.env[k];
  writeFileSync(join(kytral, "policy.yaml"), WARNS);
  writeFileSync(join(kytral, "mcp-policy.yaml"), WARNS.replace("coding-agent", "strict"));
  const http = (port: number, method: string, path: string, headers: Record<string, string> = {}, body?: unknown) => new Promise<{ status: number; json: any }>((ok, ko) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const req = request({ host: "127.0.0.1", port, method, path, headers: { Host: `127.0.0.1:${port}`, ...(data ? { "Content-Type": "application/json" } : {}), ...headers } }, res => {
      const chunks: Buffer[] = []; res.on("data", c => chunks.push(c)); res.on("end", () => { const text = Buffer.concat(chunks).toString("utf8"); let json: any; try { json = JSON.parse(text); } catch {} ok({ status: res.statusCode!, json }); });
    });
    req.on("error", ko); if (data) req.write(data); req.end();
  });
  try {
    const d = await startDashboard({ port: 0 });
    try {
      const said = await printed(async () => {
        const s = await http(d.port, "POST", "/api/session", {}, { token: d.newLink().split("#k=")[1] }); assert.equal(s.status, 200);
        const auth = { Authorization: `Bearer ${s.json.session}` };
        const st = await http(d.port, "GET", "/api/state", auth); assert.equal(st.status, 200); assert.equal(st.json.rules.agents.error ?? null, null);
        assert.equal((await http(d.port, "POST", "/api/level", { ...auth, Origin: `http://127.0.0.1:${d.port}` }, { level: "strict" })).status, 200);
        assert.equal((await http(d.port, "GET", "/api/state", auth)).status, 200);
      });
      noLeak(said, "dashboard");
      for (const f of ["policy.yaml", "mcp-policy.yaml"]) assert.ok(readFileSync(join(kytral, f), "utf8").includes(`# ${GHP}`), `${f} rewritten with its comments`);
    } finally { await d.close(); }
  } finally { for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

test("proxy without --policy: an mcp-policy.yaml that does not load stops it with a 'refusing to start' line; one that loads, a preset, and LOG_TOKENS/LOG_STREAM leave stdout (the MCP channel) empty", () => {
  for (const [what, text, line] of [["a key given twice", `rules: []\nunknownTools: confirm\nrules: [${GHP}]\n`, 3], ["a bad action", `rules: [{ name: "${GHP}", action: maybe }]\n`, 0]] as const) {
    const m = machine(); mkdirSync(m.kytral); writeFileSync(join(m.kytral, "mcp-policy.yaml"), text);
    const r = m.proxy([], LOG);
    assert.equal(r.code, 2, what); assert.equal(r.out, "", what);
    assert.equal(r.err, `kytral-guard: refusing to start: mcp-policy.yaml is not a valid policy${line ? ` (line ${line})` : ""}\n`, what);
    noLeak(r.out + r.err, what, [m.t]); assert.deepEqual(m.starts(), [], what); assert.deepEqual(readdirSync(m.kytral), ["mcp-policy.yaml"], `${what}: nothing created`);
  }
  const m = machine(); mkdirSync(m.kytral); writeFileSync(join(m.kytral, "mcp-policy.yaml"), WARNS.replace("coding-agent", "strict"));
  for (const pre of [[], ["--preset", "strict"], ["--preset", "coding-agent"]]) {
    const r = m.proxy(pre, LOG);
    assert.equal(r.code, 0, `${pre.join(" ")}: ${r.err}`); assert.equal(r.out, "", `${pre.join(" ")}: stdout is the MCP channel`); noLeak(r.err, pre.join(" "));
  }
  assert.deepEqual(m.starts(), Array(3).fill({ LOG_TOKENS: "1", LOG_STREAM: "1" }), "the server still gets LOG_TOKENS and LOG_STREAM");
});

test("a plugin's policy that does not load: the proxy stops with one fixed line before anything is created; a hook refuses in fixed words", () => {
  const m = machine(), plugin = m.file("central.mjs", `export default { name: "central", policy: () => ${JSON.stringify(`rules: []\nrules: [${GHP}]\n`)} };\n`);
  const r = m.proxy([], { KYTRAL_PLUGINS: plugin, ...LOG });
  assert.equal(r.code, 2); assert.equal(r.out, "");
  assert.equal(r.err, "kytral-guard: refusing to start: plugin 'central' provides an invalid proxy policy (YAML syntax error at line 2)\n");
  noLeak(r.err, "proxy"); assert.deepEqual(m.starts(), []); assert.ok(!existsSync(m.kytral), "KYTRAL_HOME created");
  const h = m.cli(["hook", "claude-code"], { input: event("ls"), env: { KYTRAL_PLUGINS: plugin, ...LOG } });
  assert.equal(h.code, 2);
  assert.match(JSON.parse(h.out).hookSpecificOutput.permissionDecisionReason, /could not decide \(fail closed\): plugin 'central' provides an invalid hook policy \(YAML syntax error at line 2\)/);
  noLeak(h.out + h.err, "hook", [plugin]);
});

test("hooks: a policy that does not load (KYTRAL_POLICY or --policy) is refused in fixed words in every dialect, without its path or a word of it, LOG_* set or not", () => {
  const cases: [string, string, string][] = [
    ["a key given twice", `default: allow\nrules: []\ndefault: ${GHP}\n`, "YAML syntax error at line 3"],
    ["a token as a rule name, with a bad action", `rules:\n  - name: ${GHP}\n    action: maybe\n`, "policy: bad action in a rule"],
    ["a token as the preset", `extends: ${GHP}\nrules: []\n`, "policy: unknown preset in extends"],
    ["an invalid regular expression", `rules:\n  - name: r\n    argMatches: "(${GHP}"\n    action: block\n`, "a rule has an invalid regular expression"],
    ["a token as the SQL dialect", `sqlDialect: ${GHP}\nrules: []\n`, "policy: unsupported sqlDialect"],
    ["a .env", `GITHUB_TOKEN=${GHP}\nGREETING=Hello: world\n`, "YAML syntax error at line 1"],
  ];
  const m = machine();
  for (const [what, text, why] of cases) {
    assert.match(why, FIXED);
    const f = m.file(`hook-policy-${cases.findIndex(c => c[0] === what)}.yaml`, text);
    assert.equal(policyProblem((() => { try { loadPolicy(text); } catch (e) { return e; } })()), why, what);
    const reason = `refused because the guard could not decide (fail closed): the hook policy is not a valid policy (${why}): 'kytral-guard doctor' says which file and why`;
    for (const [how, args, env] of [["KYTRAL_POLICY", ["hook", "claude-code"], { KYTRAL_POLICY: f }], ["--policy", ["hook", "claude-code", "--policy", f], {}],
      ["LOG_*", ["hook", "claude-code"], { KYTRAL_POLICY: f, ...LOG }]] as const) {
      const r = m.cli([...args], { input: event("ls"), env }), w = `${what} (${how})`;
      assert.equal(r.code, 2, w); assert.ok(JSON.parse(r.out).hookSpecificOutput.permissionDecisionReason.includes(reason), `${w}: ${r.out}`); assert.ok(r.err.includes(reason), w);
      noLeak(r.out + r.err, w, [f, m.t, "hook-policy-"]);
    }
    const cursor = m.cli(["hook", "cursor"], { input: JSON.stringify({ hook_event_name: "beforeShellExecution", command: "ls", cwd: "/tmp", cursor_version: "2" }), env: { KYTRAL_POLICY: f } });
    assert.equal(JSON.parse(cursor.out).permission, "deny"); assert.ok(JSON.parse(cursor.out).agent_message.includes(reason)); noLeak(cursor.out + cursor.err, `${what} (cursor)`, [f, m.t]);
    const generic = m.cli(["hook", "generic"], { input: JSON.stringify({ command: "ls" }), env: { KYTRAL_POLICY: f } });
    assert.equal(generic.code, 2); assert.equal(JSON.parse(generic.out).reason, reason); noLeak(generic.out + generic.err, `${what} (generic)`, [f, m.t]);
  }
  // a file that cannot be read: its error code only
  for (const [f, code] of [[join(m.t, `missing-${GHP}.yaml`), "ENOENT"], [m.t, "EISDIR"]] as const) {
    const r = m.cli(["hook", "claude-code"], { input: event("ls"), env: { KYTRAL_POLICY: f } });
    assert.equal(r.code, 2); assert.ok(r.err.includes(`the hook policy cannot be read (${code}): 'kytral-guard doctor' says which file and why`), r.err);
    noLeak(r.out + r.err, code, [m.t]);
  }
  // the hooks' own policy in KYTRAL_HOME: the same words
  mkdirSync(m.kytral, { recursive: true }); writeFileSync(join(m.kytral, "policy.yaml"), cases[0][1]);
  const own = m.cli(["hook", "claude-code"], { input: event("ls") });
  assert.equal(own.code, 2); assert.ok(own.err.includes("the hook policy is not a valid policy (YAML syntax error at line 3)")); noLeak(own.out + own.err, "policy.yaml", [m.kytral]);
});

test("hooks: a policy that loads with yaml warnings, and a Taskfile a command runs, print nothing with LOG_TOKENS and LOG_STREAM: stdout is only the answer", () => {
  const m = machine(), f = m.file("hooks-warn.yaml", WARNS);
  writeFileSync(join(m.project, "Taskfile.yml"), `# ${GHP}\nversion: '3'\ntasks:\n  build:\n    cmds: [echo built]\n`);
  const allow = m.cli(["hook", "claude-code"], { input: event("task build", m.project), env: { KYTRAL_POLICY: f, ...LOG } });
  assert.equal(allow.code, 0, allow.err); assert.equal(allow.out, ""); assert.equal(allow.err, "");
  const block = m.cli(["hook", "claude-code"], { input: event("rm -rf ~", m.project), env: { KYTRAL_POLICY: f, ...LOG } });
  assert.equal(block.code, 2); assert.equal(JSON.parse(block.out).hookSpecificOutput.permissionDecision, "deny"); noLeak(block.out + block.err, "block");
  noLeak(readFileSync(join(m.kytral, "audit.jsonl"), "utf8"), "audit");
});

test("doctor --report and doctor: policies with yaml warnings, a Continue configuration, LOG_TOKENS and LOG_STREAM: nothing of them shown; a hook policy that does not load, in fixed words", () => {
  const m = machine(); mkdirSync(m.kytral); mkdirSync(join(m.home, ".continue"));
  writeFileSync(join(m.kytral, "mcp-policy.yaml"), WARNS.replace("coding-agent", "strict"));
  writeFileSync(join(m.home, ".continue", "config.yaml"), `# ${GHP}\nmcpServers:\n  - name: fs\n    command: npx\n    args: ["-y", "server-fs", "--token", !t "${GHP}"]\n`);
  const hookPolicy = m.file("hooks-warn.yaml", WARNS), proxyPolicy = m.file("proxy-warn.yaml", WARNS.replace("coding-agent", "strict"));
  for (const args of [["doctor", "--report"], ["doctor", "--report", "--policy", proxyPolicy], ["doctor"]]) {
    const r = m.cli(args, { env: { KYTRAL_POLICY: hookPolicy, ...LOG } }), w = args.join(" ");
    assert.equal(r.code, args.length === 1 ? r.code : 0, `${w}: ${r.err}`); noLeak(r.out + r.err, w);
    if (args.length > 1) assert.match(r.out, /^- Continue: wrapped: none; not wrapped: fs$/m, w);
  }
  const bad = m.file("hooks-bad.yaml", `default: allow\nrules: []\ndefault: ${GHP}\n`);
  const r = m.cli(["doctor", "--report"], { env: { KYTRAL_POLICY: bad, ...LOG } });
  assert.equal(r.code, 0); assert.match(r.out, /^- Source: the file the policy variable names \(name redacted\), does not load: YAML syntax error at line 3$/m);
  noLeak(r.out + r.err, "doctor --report, bad hook policy", [bad]);
});

test("check, allow, allow --list, policy show and mcp list print nothing of yaml's own with LOG_TOKENS and LOG_STREAM", () => {
  // what these commands print of a policy or a configuration (policy show: the policy; mcp list: each server's command) is
  // theirs, in the user's terminal: here the token is where only yaml's own output could show it (a comment, an env value)
  const m = machine(); mkdirSync(m.kytral); mkdirSync(join(m.home, ".continue"));
  writeFileSync(join(m.kytral, "policy.yaml"), WARNS_COMMENT);
  writeFileSync(join(m.home, ".continue", "config.yaml"), `# ${GHP}\nmcpServers:\n  - name: fs\n    command: npx\n    args: ["-y", !t "server-fs"]\n    env: { TOKEN: "${GHP}" }\n`);
  const runs: [string[], number][] = [[["check", "ls"], 0], [["check", "rm -rf ~"], 2], [["allow", "git reset --hard"], 0], [["allow", "--list"], 0], [["policy", "show"], 0], [["mcp", "list"], 0]];
  for (const [args, code] of runs) {
    const r = m.cli(args, { env: LOG });
    assert.equal(r.code, code, `${args.join(" ")}: ${r.err}`); noLeak(r.out + r.err, args.join(" "));
  }
  const after = readFileSync(join(m.kytral, "policy.yaml"), "utf8");
  assert.match(after, /argEquals: git reset --hard/, "allow rewrote the file"); assert.ok(after.startsWith(`# ${GHP}\n`), "its comment kept");
});
