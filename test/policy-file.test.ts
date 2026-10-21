// The proxy's --policy file. A file that is not a valid policy (a YAML syntax error, a .env, YAML that is not a policy, an empty or
// binary file) stops the proxy with one fixed line on stderr and exit 2, before anything starts or is created (no server, no
// KYTRAL_HOME). Nothing of the file is shown, on stderr or stdout (YAML's messages quote the line at fault, loadPolicy's a rule name, a
// value or a pattern, and Node's report repeats them), nor its path; a YAML syntax error is located by its line number only. A policy
// that loads prints nothing of itself either, in the proxy and in doctor --report: neither YAML's warnings nor its parser's tokens
// (LOG_TOKENS, LOG_STREAM). Each test runs the CLI with its own home folder, project folder and KYTRAL_HOME.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path"; import { pathToFileURL } from "node:url";
import { DEFAULT_POLICY, loadPolicy, policyErrorLine } from "../src/policy.js";

const ROOT = resolve(import.meta.dirname, "..");
const TSX = pathToFileURL(join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;   // the project folder has no node_modules
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d";   // a strong secret: only the policy can stop the proxy
const GHP = "ghp_N4r7Q2x9L1m8K3v6B5c0Z7a2S4d6F8g1H3j5";                         // the token planted in each file
const FILE = "policy-planted-4417.yaml";                                          // its name is never shown either
const REFUSED = "kytral-guard: refusing to start: the --policy file is not a valid policy";

/** A fresh machine: home and project folders, KYTRAL_HOME (not created), the policy file, and a server that records each start. */
function machine(content: string | Buffer, env: Record<string, string> = {}) {
  const t = mkdtempSync(join(tmpdir(), "kg-policy-")), home = join(t, "home"), project = join(t, "project"), kytral = join(t, "kytral-home");
  mkdirSync(home); mkdirSync(project);
  const e: Record<string, string | undefined> = { ...process.env, HOME: home, USERPROFILE: home, APPDATA: join(home, "AppData", "Roaming"), XDG_CONFIG_HOME: join(home, ".config") };
  for (const k of Object.keys(e)) if (/^(KYTRAL_|LOG_TOKENS$|LOG_STREAM$)/i.test(k)) delete e[k];
  // the confirmation queue on: it would create its folder in KYTRAL_HOME
  Object.assign(e, { KYTRAL_HOME: kytral, KYTRAL_SECRET: S, KYTRAL_AUDIENCE: "kytral-guard:policy-test", KYTRAL_CONFIRM_QUEUE: "1" }, env);
  const policy = join(t, FILE), server = join(t, "server.mjs"), started = join(t, "started.jsonl");
  writeFileSync(policy, content);
  writeFileSync(server, `import { appendFileSync } from "node:fs";\nappendFileSync(${JSON.stringify(started)}, JSON.stringify(process.argv.slice(2)) + "\\n");\n`);
  const cli = (...args: string[]) => {
    const r = spawnSync(process.execPath, ["--import", TSX, join(ROOT, "src/cli.ts"), ...args], { cwd: project, env: e as NodeJS.ProcessEnv, encoding: "utf8", input: "" });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };
  const starts = () => existsSync(started) ? readFileSync(started, "utf8").split("\n").filter(Boolean).length : 0;
  /** Nothing started or created: no server start, no KYTRAL_HOME, no other file in the test, home or project folder. */
  const untouched = (what: string) => {
    assert.equal(starts(), 0, `server started: ${what}`); assert.ok(!existsSync(kytral), `KYTRAL_HOME created: ${what}`);
    assert.deepEqual(readdirSync(t).sort(), [FILE, "home", "project", "server.mjs"].sort(), `file created: ${what}`);
    assert.deepEqual([...readdirSync(home), ...readdirSync(project)], [], `file created in the home or project folder: ${what}`);
  };
  return { policy, cli, proxy: () => cli("--policy", policy, "--", process.execPath, server), starts, untouched };
}
/** The proxy refuses the file the one way it may: exit 2, nothing on stdout, `said` alone on stderr, nothing started or created. */
function refused(content: string | Buffer, said: string, what: string, env: Record<string, string> = {}) {
  const m = machine(content, env), r = m.proxy();
  assert.equal(r.code, 2, what); assert.equal(r.out, "", what); assert.equal(r.err, `${said}\n`, what);
  for (const s of [GHP, FILE]) assert.ok(!(r.out + r.err).includes(s), `${what}: shown ${s}`);
  m.untouched(what);
}
/** What loadPolicy() throws for `text`. */
const thrown = (text: string): unknown => { try { loadPolicy(text); } catch (e) { return e; } return assert.fail(`loaded: ${JSON.stringify(text)}`); };
const lineOf = (text: string, s: string) => text.split("\n").findIndex(l => l.includes(s)) + 1;

test("a --policy file with a YAML syntax error: exit 2, one fixed line with the line of the error, never that line (a token on it), nothing started or created", () => {
  // the token is on the line at fault, which the parser's message quotes
  const cases: Record<string, string> = {
    "a key given twice": `default: allow\nrules: []\ndefault: ${GHP}\n`,
    "a mapping in a value": `rules: []\nunknownTools: confirm\napi_key: ${GHP}: x\n`,
    "a tab as indentation": `rules:\n  - name: a\n    action: block\n\ttoken: ${GHP}\n`,
    "text after a quoted value": `rules: []\nsqlDialect: "postgresql" ${GHP}\n`,
    "an indentation that matches nothing": `default: allow\nrules:\n  - name: a\n    action: block\n   note: ${GHP}\n`,
    "deep in the built-in policy": DEFAULT_POLICY.replace("  - name: money-transfer\n", `  - name: money-transfer\n    note: "${GHP}" trailing\n`),
    "Windows line ends": `default: allow\r\nrules: []\r\ndefault: ${GHP}\r\n`,
    "a second document": `rules: []\n--- ${GHP}\n`,
    "a .env whose value holds ': '": `GITHUB_TOKEN=${GHP}\nGREETING=Hello: world\n`,
  };
  for (const [what, text] of Object.entries(cases)) {
    const line = lineOf(text, GHP), e = thrown(text);
    assert.ok(String((e as Error).message).includes(GHP), `${what}: the parser quotes the line`); assert.equal(policyErrorLine(e), line, what);
    refused(text, `${REFUSED} (line ${line})`, what);
  }
  assert.ok(lineOf(cases["deep in the built-in policy"], GHP) > 30);
  // with yaml's debugging output asked for (it writes every token on stdout, the MCP channel)
  refused(cases["a key given twice"], `${REFUSED} (line 3)`, "LOG_TOKENS and LOG_STREAM set", { LOG_TOKENS: "1", LOG_STREAM: "1" });
});

test("a --policy file that is no policy (a .env, YAML of another shape or with a schema error, an empty or binary file): exit 2, one fixed line, nothing started or created", () => {
  // loadPolicy's messages quote a rule name (bad action), a value (sqlDialect), a pattern (regex); YAML's an alias; Node's report all of them
  const cases: [string, string][] = [
    [".env", `# production\nOPENAI_API_KEY=sk-proj-AbCdEf0123456789\nGITHUB_TOKEN=${GHP}\nDATABASE_URL=postgres://admin:hunter2@db:5432/app\n`],
    ["an empty file", ""], ["a list", `- ${GHP}\n- rules\n`], ["no rules", `default: allow\nnote: ${GHP}\n`], ["a null rule", `rules:\n  - null\n# ${GHP}\n`],
    ["a bad action", `rules:\n  - name: ${GHP}\n    action: maybe\n`], ["an unsupported sqlDialect", `sqlDialect: ${GHP}\nrules: []\n`],
    ["an invalid regex", `rules:\n  - name: r\n    argMatches: "(${GHP}"\n    action: block\n`], ["an alias without its anchor", `rules: *${GHP}\n`],
  ];
  for (const [what, text] of cases) { assert.equal(policyErrorLine(thrown(text)), undefined, what); refused(text, REFUSED, what); }
  // a binary file (NUL bytes, invalid UTF-8): YAML that stops at its first line, where the token is
  const binary = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0]), Buffer.from(GHP), Buffer.from([0xff, 0xfe, 0, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d]),
    Buffer.from("IHDR"), Buffer.from([0x3a, 0x20, 0x09, 0x7f, 0xc3, 0x28, 0x0a, 0x2d, 0x20, 0x5b])]);
  refused(binary, `${REFUSED} (line 1)`, "a binary file");
});

test("a --policy file that loads starts the server and prints nothing of itself: not YAML's warnings (an unknown tag, a list as a key, an unknown directive), nor its tokens (LOG_TOKENS, LOG_STREAM); doctor --report neither", () => {
  const cases: [string, string, Record<string, string>][] = [
    ["an unknown tag", `rules: []\nknownTools: [!custom "${GHP}*"]\n`, {}],
    ["a list as a key", `rules: []\n? [${GHP}]\n: x\n`, {}],
    ["an unknown directive", `%NOTE ${GHP}\n---\nrules: []\n`, {}],
    ["LOG_TOKENS and LOG_STREAM set", `rules: []\nknownTools: ["${GHP}*"]\n`, { LOG_TOKENS: "1", LOG_STREAM: "1" }],
  ];
  for (const [what, text, env] of cases) {
    const m = machine(text, env), r = m.proxy();
    assert.equal(r.code, 0, `${what}: ${r.err}`); assert.equal(m.starts(), 1, `${what}: the server starts`);
    assert.equal(r.out, "", `${what}: stdout is the MCP channel`); assert.ok(!r.err.includes(GHP), `${what}: ${r.err}`);
    const d = m.cli("doctor", "--report", "--policy", m.policy);
    assert.equal(d.code, 0, `${what}: ${d.err}`); assert.match(d.out, /^- Source: the file given with --policy \(name redacted\)$/m, what);
    assert.ok(!(d.out + d.err).includes(GHP), `${what}: ${d.out}${d.err}`);
  }
});

test("policyErrorLine(): the line of a YAML syntax error, nothing for any other error; loadPolicy() leaves LOG_TOKENS and LOG_STREAM as they were", () => {
  assert.equal(policyErrorLine(thrown("rules: []\nrules: []\n")), 2);
  assert.equal(policyErrorLine(thrown("rules:\n  - name: a\n    action: block\n\tx: 1\n")), 4);
  for (const e of [thrown(""), thrown("rules: 1\n"), thrown(`rules:\n  - name: r\n    argMatches: "("\n    action: block\n`), thrown("rules: *x\n"),
    new Error("at line 3"), { name: "YAMLParseError", linePos: [{ line: 3, col: 1 }] }, null, undefined, 3]) assert.equal(policyErrorLine(e), undefined, String(e));
  const saved = { LOG_TOKENS: process.env.LOG_TOKENS, LOG_STREAM: process.env.LOG_STREAM };
  try {
    process.env.LOG_TOKENS = "tokens-4417"; delete process.env.LOG_STREAM;
    loadPolicy("rules: []\n");
    assert.equal(process.env.LOG_TOKENS, "tokens-4417"); assert.equal(process.env.LOG_STREAM, undefined);
  } finally { for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});
