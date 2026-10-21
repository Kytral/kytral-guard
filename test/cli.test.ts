// The command line: init (every agent found, or the ones named), allow / --list / --remove, check, doctor, policy, uninstall.
// Each test runs the CLI with its own home directory and KYTRAL_HOME: nothing touches the real agent configurations.
import { test } from "node:test"; import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"; import { tmpdir } from "node:os"; import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process"; import { pathToFileURL } from "node:url";
import { loadPolicy, evaluate } from "../src/policy.js";
import { appDataDir } from "../src/mcp-config.js";
import { keepCall } from "../src/kept-calls.js";

const ROOT = resolve(import.meta.dirname, "..");
const TSX = pathToFileURL(join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;   // the project folder has no node_modules
/** A fresh machine: a home with the given agents' configuration folders, a KYTRAL_HOME, and a project folder. */
function machine(agents: string[] = []) {
  const t = mkdtempSync(join(tmpdir(), "kg-cli-")), home = join(t, "home"), project = join(t, "project"), kytral = join(t, "kytral");
  mkdirSync(project, { recursive: true });
  for (const a of agents) mkdirSync(join(home, a), { recursive: true });
  // APPDATA too: the MCP configurations of Claude Desktop, VS Code... live there on Windows, and uninstall --all changes them
  const env = { ...process.env, HOME: home, USERPROFILE: home, APPDATA: join(home, "AppData", "Roaming"), KYTRAL_HOME: kytral, KYTRAL_SECRET: undefined, KYTRAL_POLICY: undefined, KYTRAL_PLUGINS: undefined, XDG_CONFIG_HOME: join(home, ".config") };
  const cli = (...args: string[]) => {
    const r = spawnSync(process.execPath, ["--import", TSX, join(ROOT, "src/cli.ts"), ...args], { cwd: project, env, encoding: "utf8" });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };
  return { home, project, kytral, env, cli };
}

test("init with no agent named protects every agent found, and says how to try, allow, stop and remove", () => {
  const m = machine([".claude", ".cursor"]);
  const r = m.cli("init");
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /installed\s+claude-code/); assert.match(r.out, /installed\s+cursor/);
  assert.doesNotMatch(r.out, /codex|gemini/);
  assert.match(r.out, /now checks every tool call of Claude Code, Cursor/);
  assert.match(r.out, /kytral-guard allow "<command>"/); assert.match(r.out, /kytral-guard uninstall --all/);
  assert.ok(existsSync(join(m.home, ".claude", "settings.json")) && existsSync(join(m.home, ".cursor", "hooks.json")));
  assert.ok(existsSync(join(m.kytral, "secret")) && existsSync(join(m.kytral, "policy.yaml")));
  // again: nothing changes
  assert.match(m.cli("init").out, /unchanged\s+claude-code/);
  // doctor sees both hooks and passes its self-test
  const d = m.cli("doctor");
  // (run from the sources, the installed command names src/cli.js, which only a build creates: doctor warns about it)
  assert.match(d.out, /claude-code hook in /); assert.match(d.out, /cursor hook in /); assert.match(d.out, /ok\s+self-test/);
  // uninstall --all removes them
  assert.match(m.cli("uninstall", "--all").out, /removed\s+claude-code/);
});

test("uninstall --all: one line per change, the proxy taken off MCP servers, what to do next; --dry-run; doctor says when nothing runs the guard", () => {
  const m = machine([".claude"]);
  const desktop = join(appDataDir(m.home, m.env), "Claude", "claude_desktop_config.json"), settings = join(m.home, ".claude", "settings.json");
  const hooked = () => /"hook",\s*"claude-code"/.test(readFileSync(settings, "utf8"));   // the CLI path may not name kytral (a clone in ~/kg)
  mkdirSync(dirname(desktop), { recursive: true });
  writeFileSync(desktop, JSON.stringify({ mcpServers: { fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] } } }));
  assert.equal(m.cli("init").code, 0);
  assert.equal(m.cli("mcp", "wrap", "claude-desktop").code, 0);
  assert.equal(typeof JSON.parse(readFileSync(desktop, "utf8")).mcpServers.fs.env.KYTRAL_BADGE, "string");
  // --dry-run says what would change and changes nothing
  const dry = m.cli("uninstall", "--all", "--dry-run");
  assert.match(dry.out, /would remove\s+claude-code/); assert.match(dry.out, /would unwrap\s+Claude Desktop .*: fs/); assert.doesNotMatch(dry.out, /npm uninstall/);
  assert.ok(hooked());
  // an unknown agent among the names: nothing is changed
  assert.equal(m.cli("uninstall", "claude-code", "vim").code, 2);
  assert.ok(hooked());
  const r = m.cli("uninstall", "--all");
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /removed\s+claude-code/); assert.match(r.out, /unwrapped\s+Claude Desktop .*: fs/);
  assert.equal(r.out.match(/not found/g)?.length, 1, "the agents without a hook fit on one line");
  assert.match(r.out, /Restart the apps above/); assert.match(r.out, /npm uninstall -g kytral-guard/);
  assert.ok(!hooked());
  assert.equal(JSON.parse(readFileSync(desktop, "utf8")).mcpServers.fs.command, "npx", "the server starts without the package");
  // the journal (and the dashboard) say who added and removed each protection from the terminal; a dry run journals nothing
  const changes = readFileSync(join(m.kytral, "audit.jsonl"), "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l))
    .filter(e => e.decision === "settings-change" || e.decision === "mcp-wrap").map(e => `${e.agentId} ${e.decision} ${e.reason}`);
  assert.deepEqual(changes, ["* settings-change installed the hook of Claude Code", "* mcp-wrap ran the MCP servers fs of Claude Desktop through Kytral Guard",
    "* settings-change removed the hook of Claude Code", "* settings-change stopped running the MCP servers fs of Claude Desktop through Kytral Guard"]);
  // the guard still works, but nothing runs it: doctor does not say "all good", nor "works", in its last line
  const d = m.cli("doctor");
  assert.match(d.out, /warn\s+no agent or app runs Kytral Guard yet/); assert.match(d.out, /\nNot protecting anything yet: 'kytral-guard init' protects the coding agents/);
  assert.doesNotMatch(d.out, /Works, with|All good/);
});

test("init: no agent found, --no-agents, a named agent, an unknown agent", () => {
  const none = machine();
  const r = none.cli("init");
  assert.equal(r.code, 0); assert.match(r.out, /none found/); assert.doesNotMatch(r.out, /now checks/);
  const m = machine([".claude", ".cursor"]);
  const s = m.cli("init", "--no-agents");
  assert.equal(s.code, 0); assert.doesNotMatch(s.out, /installed/); assert.ok(existsSync(join(m.kytral, "secret")));
  const one = m.cli("init", "cursor");
  assert.match(one.out, /installed\s+cursor/); assert.doesNotMatch(one.out, /claude-code/); assert.match(one.out, /uninstall cursor/);
  assert.equal(m.cli("init", "vim").code, 2);
});

test("allow: an exact command, kept blocked if it turns catastrophic; --force for a catastrophe; --list and --remove", () => {
  const m = machine();
  m.cli("init", "--no-agents");
  assert.equal(m.cli("check", "git reset --hard").code, 3);
  const a = m.cli("allow", "git reset --hard");
  assert.equal(a.code, 0, a.err); assert.match(a.out, /allowed\s+git reset --hard/); assert.match(a.out, /undo: kytral-guard allow --remove allow-[0-9a-f]{8}/);
  assert.equal(m.cli("check", "git reset --hard").code, 0);
  // the exact raw text only: not a homoglyph, not another command
  assert.equal(m.cli("check", "git reset --hаrd").code, 3);
  assert.equal(m.cli("check", "git reset --hard HEAD~3").code, 3);
  // the file keeps its comments and stays a valid policy
  const text = readFileSync(join(m.kytral, "policy.yaml"), "utf8");
  assert.match(text, /# Kytral Guard policy for coding agents/); assert.doesNotThrow(() => loadPolicy(text));
  // allowed already, blocked without --force
  assert.match(m.cli("allow", "ls -la").out, /already allowed/);
  const b = m.cli("allow", "rm -rf ~");
  assert.equal(b.code, 1); assert.match(b.err, /irreversible damage/); assert.match(b.err, /allow --force 'rm -rf ~'/);
  assert.equal(m.cli("check", "rm -rf ~").code, 2);
  // list, remove
  const list = m.cli("allow", "--list");
  assert.match(list.out, /allow-[0-9a-f]{8}\s+git reset --hard/);
  const name = /(allow-[0-9a-f]{8})/.exec(list.out)![1];
  assert.match(m.cli("allow", "--remove", name).out, /removed/);
  assert.equal(m.cli("check", "git reset --hard").code, 3);
  assert.equal(m.cli("allow", "--remove", name).code, 1);
});

test("init replaces an empty secret file; an empty KYTRAL_SECRET is refused, and the message says what to do", () => {
  const m = machine();
  mkdirSync(m.kytral, { recursive: true }); writeFileSync(join(m.kytral, "secret"), "\n");
  const r = m.cli("init", "--no-agents");
  assert.equal(r.code, 0, r.err); assert.match(r.out, /was empty: replaced/);
  assert.match(readFileSync(join(m.kytral, "secret"), "utf8"), /^[0-9a-f]{64}\n$/);
  assert.match(m.cli("init", "--no-agents").out, /\(kept\)/);
  const env = { ...process.env, HOME: m.home, USERPROFILE: m.home, APPDATA: join(m.home, "AppData", "Roaming"), XDG_CONFIG_HOME: join(m.home, ".config"), KYTRAL_HOME: m.kytral, KYTRAL_POLICY: undefined, KYTRAL_PLUGINS: undefined };
  const doctor = spawnSync(process.execPath, ["--import", TSX, join(ROOT, "src/cli.ts"), "doctor"], { cwd: m.project, env: { ...env, KYTRAL_SECRET: "" }, encoding: "utf8" });
  assert.match(doctor.stdout + doctor.stderr, /KYTRAL_SECRET is set but empty: give it a strong value .* or unset it/);
  const audit = spawnSync(process.execPath, ["--import", TSX, join(ROOT, "src/cli.ts"), "doctor"], { cwd: m.project, env: { ...env, KYTRAL_SECRET: undefined, KYTRAL_AUDIT_SECRET: "" }, encoding: "utf8" });
  assert.match(audit.stdout + audit.stderr, /KYTRAL_AUDIT_SECRET is set but empty/);
});

test("allow: every rule that matches counts, the guard's own rule refuses even --force, --call takes the exact text the dashboard shows", () => {
  const m = machine();
  assert.equal(m.cli("init", "--no-agents").code, 0);
  // a catastrophe rule set to Ask still needs --force: an exception would go before it
  writeFileSync(join(m.kytral, "policy.yaml"), "extends: coding-agent\noverrides:\n  sql-destructive: confirm\nrules: []\n");
  const drop = 'psql -c "DROP TABLE users"';
  const a = m.cli("allow", drop);
  assert.equal(a.code, 1, a.out); assert.match(a.err, /irreversible damage/);
  assert.equal(m.cli("allow", "--force", drop).code, 0);
  const t = m.cli("allow", "--force", "kytral-guard resume");
  assert.equal(t.code, 1, t.out); assert.match(t.err, /stays blocked, even with --force/);
  // --call <seq>: the text a hook kept, no quoting (kept as a hook keeps it: masked, signed for this home's file)
  const secret = readFileSync(join(m.kytral, "secret"), "utf8").trim(), file = join(m.kytral, "kept-calls.jsonl");
  const kept = (seq: number, args: Record<string, unknown>, tool = "Bash") => assert.ok(keepCall({ seq, agent: "claude-code", tool, decision: "block", rule: "shell-catastrophic", args, cwd: m.project }, secret, file));
  kept(7, { command: "rm -rf ~" }); kept(8, { command: "mysql -phunter22 shop" }); kept(9, { file_path: "/etc/passwd" }, "Write");
  assert.match(readFileSync(file, "utf8"), /"text":"mysql -p•••••• shop"/);
  const c = m.cli("allow", "--call", "7");
  assert.equal(c.code, 1); assert.match(c.err, /kytral-guard allow --force --call 7/);
  const f = m.cli("allow", "--force", "--call", "7");
  assert.equal(f.code, 0, f.err); assert.match(f.out, /allowed\s+rm -rf ~/);
  assert.match(m.cli("allow", "--call", "8").err, /masked/);
  assert.match(m.cli("allow", "--call", "9").err, /not a shell command/);
  assert.match(m.cli("allow", "--call", "6").err, /no text is kept for call 6/);
  assert.equal(m.cli("allow", "--call", "7", "ls").code, 2);
});

test("an allowed command that runs a script is blocked again once the script turns catastrophic", () => {
  const m = machine();
  m.cli("init", "--no-agents");
  writeFileSync(join(m.project, "reset.sh"), "git reset --hard\n");
  assert.equal(m.cli("check", "bash reset.sh").code, 3);
  assert.equal(m.cli("allow", "bash reset.sh").code, 0);
  assert.equal(m.cli("check", "bash reset.sh").code, 0);
  writeFileSync(join(m.project, "reset.sh"), "rm -rf ~\n");
  assert.equal(m.cli("check", "bash reset.sh").code, 2);
});

test("agents cannot allow commands themselves", () => {
  const p = loadPolicy("extends: coding-agent\n");
  for (const command of ["kytral-guard allow 'rm -rf ~'", "npx kytral-guard allow --force x", "node dist/cli.js allow 'git reset --hard'", "kytral-guard.cmd allow x"])
    assert.equal(evaluate(p, { tool: "Bash", args: { command } }).action, "block", command);
  assert.equal(evaluate(p, { tool: "Bash", args: { command: "kytral-guard check 'git commit --allow-empty'" } }).action, "allow");
});

test("a confirmation of a shell command tells the user how to allow it; a block never does", async () => {
  const { renderHookAnswer } = await import("../src/hooks.js");
  const ev = (command: string) => ({ agent: "claude-code" as const, tool: "Bash", args: { command }, mode: "default", native: "PreToolUse" });
  const confirm = { action: "confirm" as const, rule: "shell-destructive", reason: "matched rule 'shell-destructive': git reset --hard" };
  // by the number of the kept call when there is one: nothing the agent wrote is pasted in a terminal
  assert.match(renderHookAnswer(ev("git reset --hard") as any, { ...confirm, call: 42 }, "claude-code").stdout, /in their own terminal: kytral-guard allow --call 42/);
  // else the command in single quotes, on a POSIX system only, and never with a backslash (fish reads \' inside quotes)
  const ask = renderHookAnswer(ev("git reset --hard") as any, confirm, "claude-code");
  assert.match(ask.stdout, process.platform === "win32" ? /from now on with kytral-guard allow, in their own terminal/ : /kytral-guard allow 'git reset --hard'/);
  const tricky = renderHookAnswer(ev("echo a\\'; rm -rf src; echo '") as any, confirm, "claude-code");
  assert.doesNotMatch(tricky.stdout, /kytral-guard allow '/); assert.match(tricky.stdout, /with kytral-guard allow, in their own terminal/);
  const block = renderHookAnswer(ev("rm -rf ~") as any, { action: "block", rule: "shell-catastrophic", reason: "matched rule 'shell-catastrophic': rm -r ~" }, "claude-code");
  assert.doesNotMatch(block.stdout + block.stderr, /kytral-guard allow/);
});

test("check reads scripts from the current directory; policy show and validate", () => {
  const m = machine();
  writeFileSync(join(m.project, "clean.sh"), "rm -rf ~/\n");
  const r = m.cli("check", "bash clean.sh");
  assert.equal(r.code, 2); assert.match(r.out, /rm -r ~\/ \(bash clean\.sh\)/);
  assert.match(m.cli("policy", "show", "--preset", "coding-agent").out, /shell-catastrophic/);
  writeFileSync(join(m.project, "p.yaml"), "rules: [{name: x, action: maybe}]\n");
  assert.equal(m.cli("policy", "validate", join(m.project, "p.yaml")).code, 1);
});

test("typos, --help and wrong names: a usage or a suggestion, never a stack trace, and nothing written", () => {
  const m = machine([".claude"]);
  const nothingWritten = () => assert.ok(!existsSync(m.kytral), "KYTRAL_HOME untouched");
  let r = m.cli("docter");
  // the word typed is not repeated (it may be anything, a token pasted at the wrong place too): only the command meant
  assert.equal(r.code, 2); assert.match(r.err, /unknown command\. Did you mean 'doctor'\?/); assert.ok(!r.err.includes("docter"), r.err);
  assert.match(m.cli("status").err, /Did you mean 'doctor'\?/);
  for (const args of [["init", "--help"], ["init", "-h"], ["help", "init"], ["revoke", "--help"], ["allow", "-h"]]) {
    r = m.cli(...args);
    assert.equal(r.code, 0, args.join(" ")); assert.match(r.out, new RegExp(`^usage: kytral-guard ${args[0] === "help" ? args[1] : args[0]} `), args.join(" "));
  }
  nothingWritten();
  r = m.cli("init", "claude");
  assert.equal(r.code, 2); assert.match(r.err, /unknown agent\. Did you mean 'claude-code'\?/);
  r = m.cli("init", "planted-4417");
  assert.equal(r.code, 2); assert.match(r.err, /^kytral-guard: unknown agent\. Agents: /); assert.ok(!r.err.includes("planted"), r.err);
  nothingWritten();
  // an option given by mistake is not revoked as an id (proxies never forget a revocation)
  assert.equal(m.cli("revoke", "--all").code, 2); nothingWritten();
  assert.equal(m.cli("--").code, 2, "the proxy without a server: its usage");
  r = m.cli("check", "git", "reset", "--hard");
  // an unknown option is never repeated, the command around it neither: the hint says where the command goes
  assert.equal(r.code, 2); assert.equal(r.err, 'kytral-guard: unknown option; run kytral-guard --help\n  (a command that has options goes in quotes: kytral-guard check "<command>")\n');
  assert.equal(m.cli("check", "").code, 2, "nothing to check");
  for (const out of [m.cli("docter"), m.cli("init", "claude"), m.cli("--")]) assert.doesNotMatch(out.err, /\n\s+at /, "no stack trace");
  // a hook command that carries --help is a broken configuration: it refuses like any hook error (exit 0 says "no objection")
  r = m.cli("hook", "claude-code", "--help");
  assert.equal(r.code, 2); assert.match(r.err, /^usage: kytral-guard hook /);
});

test("init: a broken agent file skips that agent only; a policy that does not load, or a file as KYTRAL_HOME, is said in one line", () => {
  const m = machine([".claude", ".cursor"]);
  writeFileSync(join(m.home, ".claude", "settings.json"), '{\n  "a": 1,\n}\n');
  let r = m.cli("init");
  assert.equal(r.code, 1, "exit 1: one agent is not protected");
  assert.match(r.out, /skipped\s+claude-code .*settings\.json is not valid JSON.*Then run: kytral-guard init claude-code/);
  assert.match(r.out, /installed\s+cursor/); assert.match(r.out, /now checks every tool call of Cursor\./); assert.match(r.out, /Not protected yet: Claude Code/);
  writeFileSync(join(m.kytral, "policy.yaml"), 'extends: coding-agent\nrules:\n  - name: my-rule\n    argMatches: "prod\n    action: block\n');
  r = m.cli("init", "--no-agents");
  assert.equal(r.code, 1); assert.match(r.out, /!! policy does not load \(.*policy\.yaml: .*line \d+.*\): every agent tool call is refused until it is fixed\. Check it: kytral-guard policy validate /);
  assert.doesNotMatch(r.out + r.err, /\n\s+at /, "no stack trace");
  writeFileSync(join(m.kytral, "policy.yaml"), "extends: coding-agent\nrules:\n  - name: my-rule\n    argMatches: prod\n    action: deny\n");
  r = m.cli("check", "ls");
  assert.equal(r.code, 1); assert.match(r.err, /policy\.yaml: policy: bad action 'deny' in rule 'my-rule' \(allow, confirm or block\)/);
  const f = machine();
  writeFileSync(f.kytral, "not a folder");
  for (const args of [["init", "--no-agents"], ["kill"]]) {
    r = f.cli(...args);
    assert.equal(r.code, 1, args.join(" ")); assert.match(r.err, /\(KYTRAL_HOME\) is a file, not a folder/); assert.doesNotMatch(r.err, /\n\s+at |EEXIST/);
  }
  assert.match(f.cli("doctor").out, /FAIL\s+.*\(KYTRAL_HOME\) is a file, not a folder/);
});

test("kill and resume say what they did; check says when the kill switch overrides its answer; badge lifetimes", () => {
  const m = machine();
  assert.equal(m.cli("init", "--no-agents").code, 0);
  let r = m.cli("kill");
  assert.match(r.out, /^kill switch ON\t/); assert.match(r.out, /now refuses tool calls, within 1 s\. Lift it with: kytral-guard resume/);
  r = m.cli("check", "ls");
  assert.equal(r.code, 0, "the policy's answer"); assert.match(r.err, /the kill switch is ON: right now every tool call is refused/);
  assert.match(m.cli("doctor").out, /\nKill switch ON: every tool call/);
  assert.match(m.cli("resume").out, /run again: every tool call is checked as before/);
  assert.match(m.cli("resume").out, /The kill switch was already off: nothing was stopped\./);
  assert.doesNotMatch(m.cli("check", "ls").err, /kill switch/);
  const badge = (...args: string[]) => spawnSync(process.execPath, ["--import", TSX, join(ROOT, "src/cli.ts"), "badge", ...args],
    { cwd: m.project, env: { ...m.env, KYTRAL_AUDIENCE: "kytral-guard:test-badge" }, encoding: "utf8" });
  const year = badge("agent", "*", "1y");
  assert.equal(year.status, 0, year.stderr); assert.match(year.stderr, /badge valid until \d{4}-/);
  assert.equal(year.stdout.trim().split("\n").length, 1, "stdout: the badge alone");
  const bad = badge("agent", "*", "soon");
  assert.equal(bad.status, 2); assert.match(bad.stderr, /invalid lifetime: seconds \(3600\), or a number with m, h, d or y/); assert.ok(!bad.stderr.includes("soon"), "the value typed is not repeated");
});

test("mcp --file: next steps name the file, the file is remembered for list and uninstall --all; comments and missing files are said", () => {
  const m = machine();
  assert.equal(m.cli("init", "--no-agents").code, 0);
  const cfg = join(m.project, "cfg.json");
  writeFileSync(cfg, JSON.stringify({ mcpServers: { fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] } } }));
  let r = m.cli("mcp", "list", "--file", "cfg.json");
  assert.match(r.out, /not protected: kytral-guard mcp wrap --file cfg\.json/);
  assert.equal(r.out.split(cfg).length - 1, 1, "the file named once");
  r = m.cli("mcp", "wrap", "--file", "cfg.json");
  assert.equal(r.code, 0, r.err); assert.match(r.out, /Undo: kytral-guard mcp unwrap --file cfg\.json/);
  assert.ok(r.out.includes(join(m.kytral, "mcp-policy.yaml")), "the policy of this KYTRAL_HOME, not ~/.kytral");
  assert.match(m.cli("mcp", "list").out, /cfg\.json\n\s+fs\s+local/, "listed with the apps once wrapped");
  r = m.cli("uninstall", "--all");
  assert.equal(r.code, 0, r.err); assert.match(r.out, /unwrapped\s+.*cfg\.json: fs/);
  assert.equal(JSON.parse(readFileSync(cfg, "utf8")).mcpServers.fs.command, "npx");
  assert.ok(!existsSync(join(m.kytral, "mcp-files.json")), "the record goes with the last wrapped file");
  writeFileSync(join(m.project, "vscode.json"), '{\n  // mine\n  "servers": { "fs": { "command": "npx", "args": ["x"], }, },\n}\n');
  r = m.cli("mcp", "wrap", "--file", "vscode.json");
  assert.equal(r.code, 1); assert.match(r.out, /has comments or trailing commas .*nothing was changed/);
  for (const sub of ["list", "wrap"]) {
    r = m.cli("mcp", sub, "--file", "nope.json");
    assert.equal(r.code, 1, sub); assert.match(r.out, /nope\.json:? *\n?.*no such file/, sub); assert.doesNotMatch(r.out, /ENOENT/, sub);
  }
});
