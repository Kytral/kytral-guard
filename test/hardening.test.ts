// Hardening: no analysis may outlast the agent's hook timeout (most agents then run
// the tool), a hanging plugin must not end the process without an answer, malformed pre-tool events are refused, plugin
// policies are validated, the default secret file must be a plain file, Kytral Guard Pro commands are guard tampering.
import { test } from "node:test"; import assert from "node:assert/strict";
import { existsSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs"; import { homedir, tmpdir } from "node:os"; import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { evaluateBounded, remoteConfirmTimeoutMs, runHook, runHookAsync } from "../src/hooks.js";
import { guardConfig, pluginPolicy } from "../src/plugins.js";
import { evaluate, loadPolicy, presetPolicy } from "../src/policy.js";
import { resolveSecret } from "../src/secret.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "2e7b9d4f1a6c8e3052b7d1f9a4c6e8b3d0f5a7c2e9b4d6f1a3c8e5b7d2f9a4c6";
const tmp = () => mkdtempSync(join(tmpdir(), "kg-hardening-"));
const hookOpts = () => ({ secret: S, audit: null, killSwitchFile: join(tmp(), "ks.json"), preset: "coding-agent" });
const coding = presetPolicy("coding-agent"), strict = presetPolicy("strict");
const ms = (f: () => unknown) => { const t = performance.now(); f(); return performance.now() - t; };

test("long inputs are analyzed in linear time (fork bomb, brace lists, find -exec, preset regexes)", () => {
  const n = 64 * 1024;
  const cases: [string, string][] = [
    ["Bash", "rm -rf ~ ; echo " + "QUJD".repeat(n / 4)], ["Bash", "{".repeat(n)], ["Bash", "find . " + "-exec ".repeat(n / 6)],
    ["run", "rm " + " ".repeat(n)], ["run", "rm ".repeat(n / 3)], ["run", "rm " + "+".repeat(n)], ["run", "DELETE FROM t WHERE " + " ".repeat(n)],
    ["run", "kytral-guard ".repeat(n / 13)], ["run", "printenv ".repeat(n / 9)],
  ];
  for (const [tool, s] of cases) {
    const t = ms(() => evaluate(tool === "Bash" ? coding : strict, { tool, args: { command: s } }));
    assert.ok(t < 3000, `${JSON.stringify(s.slice(0, 30))}… took ${t.toFixed(0)} ms`);
  }
  // detection is unchanged
  for (const c of [":(){ :|:& };:", "bomb () { bomb | bomb & }; bomb", "{rm,-rf,/}"]) assert.equal(evaluate(coding, { tool: "Bash", args: { command: c } }).action, "block", c);
  assert.equal(evaluate(coding, { tool: "Bash", args: { command: "echo {a,b}" } }).action, "allow");
  assert.equal(evaluate(coding, { tool: "Bash", args: { command: "find / -exec rm -rf {} +" } }).action, "block");
  assert.equal(evaluate(coding, { tool: "Bash", args: { command: "find . -name '*.tmp' -exec rm {} \\;" } }).action, "confirm");
  assert.equal(evaluate(strict, { tool: "run", args: { command: "rm -f -r ./x" } }).rule, "rm-rf");
  assert.equal(evaluate(strict, { tool: "q", args: { sql: "delete from users where id = 3 or 1 = 1" } }).action, "block");
});

test("large calls are analyzed in a worker with a deadline: a slow analysis needs a human, it never outlasts the hook", async () => {
  const big = "rm -rf ~ ; echo " + "QUJD".repeat(40_000);
  assert.equal((await evaluateBounded(coding, { tool: "Bash", args: { command: big } }, 20_000)).action, "block");
  const slow = loadPolicy("rules:\n  - name: slow\n    argMatches: '(a+)+$'\n    action: block\n");
  const t = performance.now();
  const v = await evaluateBounded(slow, { tool: "Bash", args: { command: "a".repeat(20_000) + "!" } }, 800);
  assert.ok(performance.now() - t < 5000);
  assert.equal(v.action, "confirm"); assert.equal(v.rule, "analysis-limit"); assert.match(v.reason, /could not be analyzed within/);
  const huge = await evaluateBounded(coding, { tool: "Bash", args: { command: "x".repeat(3 * 1024 * 1024) } }, 800);
  assert.equal(huge.rule, "analysis-limit"); assert.match(huge.reason, /too large to analyze/);
  // through a hook: ask where a human can answer, refused where nobody can
  const ev = (mode: string) => JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "a".repeat(20_000) + "!" }, permission_mode: mode });
  const o = { ...hookOpts(), policy: slow, preset: undefined };
  process.env.KYTRAL_ANALYSIS_TIMEOUT_MS = "800";
  try {
    assert.equal(JSON.parse((await runHookAsync("claude-code", ev("default"), o)).stdout).hookSpecificOutput.permissionDecision, "ask");
    assert.equal((await runHookAsync("claude-code", ev("bypassPermissions"), o)).exitCode, 2);
  } finally { delete process.env.KYTRAL_ANALYSIS_TIMEOUT_MS; }
});

test("small calls are bounded too: a few dozen characters of SQL, or a slow custom pattern, cannot outlast the hook", async () => {
  const ev = (command: string, mode = "default") => JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, permission_mode: mode });
  const t0 = performance.now();
  // unbalanced parentheses: minutes of parser backtracking before (the agent killed the hook: no answer); now at once
  const a = await runHookAsync("claude-code", ev(`echo "delete from t where ${"(".repeat(28)}1=1"`), hookOpts());
  assert.equal(a.exitCode, 0, "an echo runs nothing");
  const a2 = await runHookAsync("claude-code", ev(`rm -rf src && echo "delete from t where ${"(".repeat(25)}1=1"`), hookOpts());
  assert.equal(JSON.parse(a2.stdout).hookSpecificOutput.permissionDecision, "ask");
  // a DROP is not delayed by a slow fragment after it
  const b = await runHookAsync("claude-code", ev(`psql -c "DROP TABLE users; select 'insert into t select ${"(".repeat(18)}x'"`), hookOpts());
  assert.equal(b.exitCode, 2);
  assert.ok(performance.now() - t0 < 10_000);
  // a catastrophic regular expression in a custom policy, on a 31-character call: stopped at the deadline
  const slow = loadPolicy("rules:\n  - name: slow\n    argMatches: '(a+)+$'\n    action: block\n");
  process.env.KYTRAL_ANALYSIS_TIMEOUT_MS = "1500";
  try {
    const t1 = performance.now();
    const c = await runHookAsync("claude-code", ev("a".repeat(30) + "!", "bypassPermissions"), { ...hookOpts(), policy: slow, preset: undefined });
    assert.ok(performance.now() - t1 < 5000); assert.equal(c.exitCode, 2); assert.match(c.stderr, /could not be analyzed within/);
  } finally { delete process.env.KYTRAL_ANALYSIS_TIMEOUT_MS; }
});

test("SQL spread over lines, long GRANT lists and deep parentheses are still decided", () => {
  const d = (command: string) => evaluate(coding, { tool: "Bash", args: { command } });
  // a statement on its own lines inside the client's quotes (it was allowed)
  for (const command of ["psql -c \"\nDELETE FROM users WHERE 1=1\n\"", "psql -c \"\r\nUPDATE accounts SET balance=0\r\n\"", "mysql -e '\nTRUNCATE orders\n'", "psql -c \"DELETE FROM users\n\""])
    assert.equal(d(command).action, "block", JSON.stringify(command));
  assert.equal(d("psql -c \"\nDELETE FROM users WHERE id = 3\n\"").action, "allow");
  // a comment with an apostrophe does not hide the next line
  assert.equal(d("# don't forget\npsql -c \"DROP TABLE users\"").action, "block");
  // privilege changes with long column lists still need a human (they were allowed past 300 characters)
  const cols = Array.from({ length: 60 }, (_, i) => `sensitive_column_${i}`).join(", ");
  assert.equal(d(`psql -c "GRANT SELECT (${cols}) ON customer_pii TO untrusted_analyst"`).action, "confirm");
  assert.equal(d(`psql -c "REVOKE ALL (${cols}) ON customer_pii FROM auditors"`).action, "confirm");
  // deep but balanced parentheses are parsed: an unconditional DELETE stays blocked
  assert.equal(d(`psql -c "DELETE FROM t WHERE ${"(".repeat(70)}1=1${")".repeat(70)}"`).action, "block");
});

test("fork bombs with long names or padded spacing are still found", () => {
  for (const command of [`${"f".repeat(80)}(){ ${"f".repeat(80)}|${"f".repeat(80)}& };${"f".repeat(80)}`, `bomb${" ".repeat(20)}() { bomb | bomb & }; bomb`])
    assert.equal(evaluate(coding, { tool: "Bash", args: { command } }).action, "block", command.slice(0, 40));
});

test("malformed pre-tool events are refused, arguments are never silently dropped", () => {
  const block = (agent: string, ev: unknown) => { const r = runHook(agent, JSON.stringify(ev), hookOpts()); assert.notEqual(r.exitCode === 0 && !/deny/.test(r.stdout), true, JSON.stringify(ev)); return r; };
  block("claude-code", { hook_event_name: "PreToolUse", tool_name: ["Bash"], tool_input: { command: "ls" } });
  block("claude-code", { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: "rm -rf ~" });
  block("codex", { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: ["rm", "-rf", "~"], turn_id: "t" });
  block("gemini", { hook_event_name: "BeforeTool", tool_name: 42, tool_input: {} });
  block("copilot", { toolArgs: { command: "ls" } });
  block("generic", { something: "else" });
  block("cursor", { hook_event_name: "preToolUse", tool_name: null });
  // other events still pass, and ordinary calls are untouched
  assert.equal(runHook("claude-code", JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "Bash" }), hookOpts()).exitCode, 0);
  assert.equal(runHook("claude-code", JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } }), hookOpts()).exitCode, 0);
});

test("a plugin that never settles cannot end the hook without an answer", { timeout: 120_000 }, () => {
  const dir = tmp();
  writeFileSync(join(dir, "hang-confirm.mjs"), "export default { name: 'hang', confirm() { return new Promise(() => {}); } };");
  writeFileSync(join(dir, "hang-flush.mjs"), "export default { name: 'hangf', flush() { return new Promise(() => {}); } };");
  const run = (plugin: string, command: string) => spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), "hook", "gemini"], {
    cwd: ROOT, encoding: "utf8", input: JSON.stringify({ hook_event_name: "BeforeTool", tool_name: "run_shell_command", tool_input: { command } }),
    env: { ...process.env, KYTRAL_HOME: join(dir, "home"), KYTRAL_SECRET: S, KYTRAL_PLUGINS: join(dir, plugin), KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS: "1000" },
  });
  for (const [plugin, command] of [["hang-confirm.mjs", "rm -rf src"], ["hang-flush.mjs", "rm -rf ~"]]) {
    const r = run(plugin, command);
    assert.equal(r.status, 2, `${plugin}: ${r.stderr}`); assert.match(r.stdout, /"decision":"deny"/);
  }
});

test("a plugin that just used fetch() does not crash the hook on exit (the answer and its exit code survive)", { timeout: 120_000 }, async (t) => {
  // the built CLI: the crash depends on timing that the tsx loader changes
  const cli = join(ROOT, "dist/cli.js");
  if (!existsSync(cli)) { t.skip("run npm run build first"); return; }
  // On Windows, process.exit() a few milliseconds after a fetch() aborted the process (libuv assertion, 0xC0000409).
  const { execFile } = await import("node:child_process"), { promisify } = await import("node:util");
  // the server runs in another process and announces a long keep-alive, as a control plane does: both are needed
  const { spawn } = await import("node:child_process");
  const srv = spawn(process.execPath, ["-e", "const s=require(\"node:http\").createServer((q,r)=>{r.setHeader(\"content-type\",\"application/json\");r.end(\"{}\")});s.keepAliveTimeout=65000;s.listen(0,\"127.0.0.1\",()=>console.log(s.address().port))"], { stdio: ["ignore", "pipe", "inherit"] });
  const port = await new Promise<number>(r => srv.stdout!.once("data", d => r(Number(String(d).trim()))));
  const server = { close: () => srv.kill() }, dir = tmp();
  writeFileSync(join(dir, "net.mjs"), `export default { name: "net", async flush() { await (await fetch("http://127.0.0.1:${port}/")).json(); } };`);
  try {
    for (const [command, want] of [["terraform destroy", 2], ["ls", 0]] as const) for (let i = 0; i < 5; i++) {
      const child = promisify(execFile)(process.execPath, [cli, "hook", "gemini"], {
        cwd: ROOT, env: { ...process.env, KYTRAL_HOME: join(dir, "home"), KYTRAL_SECRET: S, KYTRAL_PLUGINS: join(dir, "net.mjs") } });
      child.child.stdin!.end(JSON.stringify({ hook_event_name: "BeforeTool", tool_name: "run_shell_command", tool_input: { command } }));
      const code = await child.then(() => 0, (e: { code?: number }) => e.code ?? -1);
      assert.equal(code, want, `${command}: exit ${code}`);
    }
  } finally { server.close(); }
});

test("plugin policies: YAML parsed by the guard, invalid ones refuse every call; per target", async () => {
  const yaml = "extends: coding-agent\nrules:\n  - name: no-npm\n    argMatches: '^npm '\n    action: block\n";
  const p = pluginPolicy([{ name: "c", policy: t => t === "hook" ? yaml : null }], "hook")!;
  assert.equal(evaluate(p, { tool: "Bash", args: { command: "npm i" } }).rule, "no-npm");
  assert.equal(pluginPolicy([{ name: "c", policy: t => t === "hook" ? yaml : null }], "proxy"), undefined);
  assert.throws(() => pluginPolicy([{ name: "bad", policy: () => "rules: nope" }], "hook"), /plugin 'bad' provides an invalid hook policy/);
  assert.throws(() => pluginPolicy([{ name: "bad", policy: () => ({ default: "allow", rules: [{ name: "x", action: "explode" }] }) as any }], "hook"), /invalid hook policy/);
  // an object is read like a file: its preset is merged (it was silently dropped), an unknown preset is refused
  const obj = pluginPolicy([{ name: "o", policy: () => ({ extends: "coding-agent", rules: [{ name: "no-npm", argMatches: "^npm ", action: "block" }] }) as any }], "hook")!;
  for (const command of ["rm -rf ~", "kytral-guard resume", "npm i"]) assert.equal(evaluate(obj, { tool: "Bash", args: { command } }).action, "block", command);
  assert.throws(() => pluginPolicy([{ name: "o", policy: () => ({ extends: "nope", rules: [] }) as any }], "hook"), /unknown preset/);
  const r = await runHookAsync("claude-code", JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } }),
    { ...hookOpts(), preset: undefined, plugins: [{ name: "bad", policy: () => "rules: nope" }] });
  assert.equal(r.exitCode, 2); assert.match(r.stderr, /invalid hook policy/);
});

test("the agent's hook timeout, written in the installed command, caps every wait of the guard", async () => {
  // a remote approval configured for 10 minutes, behind a hook the agent kills after 5 s: the guard answers in time
  let seen: number | undefined;
  const slow = { name: "slow", confirm: (req: { timeoutMs?: number }) => { seen = req.timeoutMs; return new Promise<null>(() => {}); } };
  const t0 = performance.now();
  const r = await runHookAsync("gemini", JSON.stringify({ hook_event_name: "BeforeTool", tool_name: "run_shell_command", tool_input: { command: "git reset --hard" } }),
    { ...hookOpts(), plugins: [slow as any], remoteConfirmTimeoutMs: 600_000, hookTimeoutMs: 5000 });
  assert.ok(performance.now() - t0 < 4000, "answered before the agent's timeout");
  assert.equal(r.exitCode, 2); assert.ok(seen! <= 2000, `the plugin was told how long the guard waits (${seen} ms)`);
  // init writes the timeout into the command
  const home = tmp();
  const { installHook } = await import("../src/install.js");
  const g = installHook("gemini", { home, timeoutSeconds: 120, cliPath: "/opt/kg/dist/cli.js", nodePath: "/usr/bin/node", dryRun: true } as any);
  assert.match(g.content, /hook gemini --timeout 120/);
});

test("remote approval wait: explicit, environment, config.json, else what is left of 20 s", () => {
  const home = tmp(), saved = { h: process.env.KYTRAL_HOME, e: process.env.KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS };
  try {
    process.env.KYTRAL_HOME = home; delete process.env.KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS;
    assert.ok(remoteConfirmTimeoutMs(undefined, Date.now() - 5000) <= 15_000);
    writeFileSync(join(home, "config.json"), JSON.stringify({ remoteConfirmTimeoutSeconds: 300 }));
    assert.equal(remoteConfirmTimeoutMs(undefined), 300_000); assert.equal(guardConfig().remoteConfirmTimeoutSeconds, 300);
    process.env.KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS = "4000"; assert.equal(remoteConfirmTimeoutMs(undefined), 4000);
    assert.equal(remoteConfirmTimeoutMs(1234), 1234);
    writeFileSync(join(home, "config.json"), JSON.stringify({ remoteConfirmTimeoutSeconds: "soon" }));
    assert.throws(() => guardConfig(), /remoteConfirmTimeoutSeconds/);
  } finally {
    for (const [k, v] of [["KYTRAL_HOME", saved.h], ["KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS", saved.e]] as const) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
});

test("the default secret file must be a plain file (a planted symbolic link is refused)", (t) => {
  const home = tmp(), saved = process.env.KYTRAL_HOME, savedSecret = process.env.KYTRAL_SECRET;
  writeFileSync(join(home, "known"), S);
  try { symlinkSync(join(home, "known"), join(home, "secret")); } catch { t.skip("symbolic links are not available"); return; }
  try {
    process.env.KYTRAL_HOME = home; delete process.env.KYTRAL_SECRET;
    assert.throws(() => resolveSecret(), /not a regular file/);
  } finally {
    if (saved === undefined) delete process.env.KYTRAL_HOME; else process.env.KYTRAL_HOME = saved;
    if (savedSecret !== undefined) process.env.KYTRAL_SECRET = savedSecret;
  }
});

test("a custom KYTRAL_HOME is protected like ~/.kytral: absolute paths, $KYTRAL_HOME references, secret and key files", () => {
  const saved = process.env.KYTRAL_HOME, base = tmp(), state = join(base, "kytral-state");
  process.env.KYTRAL_HOME = state;
  try {
    const d = (tool: string, args: Record<string, unknown>) => evaluate(coding, { tool, args });
    assert.equal(d("Write", { file_path: join(state, "pro-state.json"), content: "{}" }).action, "block");
    assert.equal(d("Edit", { file_path: join(state, "config.json"), old_string: "a", new_string: "b" }).action, "block");
    assert.equal(d("Bash", { command: `echo '{}' > '${join(state, "config.json").replace(/\\/g, "/")}'` }).action, "block");
    for (const command of ["echo '{}' > $KYTRAL_HOME/config.json", "rm -rf ${KYTRAL_HOME}", "cp evil.json \"$KYTRAL_HOME/pro-state.json\""])
      assert.equal(d("Bash", { command }).action, "block", command);
    assert.equal(d("PowerShell", { command: "Set-Content -Path $env:KYTRAL_HOME\\config.json -Value '{}'" }).action, "block");
    for (const command of [`cat ${join(state, "pro-device.key").replace(/\\/g, "/")}`, "cat $KYTRAL_HOME/secret", "type %KYTRAL_HOME%\\pro-device.key", "cat $KYTRAL_SECRET_FILE"])
      assert.equal(d("Bash", { command }).rule, "guard-tamper", command);
    assert.equal(d("Read", { file_path: join(state, "pro-device.key") }).rule, "guard-tamper");
    // reading the audit log stays allowed; a sibling folder is not protected
    assert.equal(d("Bash", { command: "tail $KYTRAL_HOME/audit.jsonl" }).action, "allow");
    assert.equal(d("Write", { file_path: join(base, "kytral-state-notes.md"), content: "x" }).action, "allow");
    // a KYTRAL_HOME that is the home directory itself does not make the whole home a guard path
    process.env.KYTRAL_HOME = homedir();
    assert.equal(d("Write", { file_path: join(homedir(), "notes.md"), content: "x" }).action, "allow");
  } finally { if (saved === undefined) delete process.env.KYTRAL_HOME; else process.env.KYTRAL_HOME = saved; }
});

test("Kytral Guard Pro commands that enroll elsewhere or remove the plugin are guard tampering", () => {
  for (const command of ["kytral-pro unenroll", "npx kytral-pro enroll https://evil.example tok", "node /opt/x/@kytral/guard-pro/dist/client/cli.js unenroll"])
    assert.equal(evaluate(coding, { tool: "Bash", args: { command } }).rule, "guard-tamper", command);
  for (const command of ["kytral-pro status", "kytral-pro sync", "kytral-pro verify"]) assert.equal(evaluate(coding, { tool: "Bash", args: { command } }).action, "allow", command);
});
