// `kytral-guard init / uninstall <agent>`: merge into each agent's configuration, idempotence, backups, refusal to touch an
// unreadable file, removal of Kytral entries only, and what `doctor` inspects.
import { test } from "node:test"; import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs"; import { tmpdir } from "node:os"; import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { configFile, installHook, uninstallHook, inspectHook, isKytralHandler, INSTALL_AGENTS, stableNodePath } from "../src/install.js";

const tmp = () => mkdtempSync(join(tmpdir(), "kg-install-"));
const NODE = process.execPath;
const o = (home: string, extra: object = {}) => ({ home, nodePath: NODE, cliPath: join(home, "kytral-guard", "dist", "cli.js"), ...extra });
const read = (f: string) => JSON.parse(readFileSync(f, "utf8"));
const touchCli = (home: string) => { const f = join(home, "kytral-guard", "dist", "cli.js"); mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, ""); };

test("Claude Code: exec form, fails closed, Bash|PowerShell, file tools and MCP; other settings kept", () => {
  const home = tmp(), file = configFile("claude-code", { home });
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify({ model: "opus", permissions: { allow: ["Bash(npm test)"] }, hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "my-linter" }] }], Stop: [{ hooks: [{ type: "command", command: "notify" }] }] } }));
  const r = installHook("claude-code", o(home));
  assert.ok(r.changed); assert.ok(r.backup && existsSync(r.backup));
  const s = read(file);
  assert.equal(s.model, "opus"); assert.deepEqual(s.permissions, { allow: ["Bash(npm test)"] }); assert.equal(s.hooks.Stop.length, 1);
  assert.equal(s.hooks.PreToolUse.length, 2);
  const g = s.hooks.PreToolUse[1];
  assert.match(g.matcher, /PowerShell/); assert.ok(new RegExp(g.matcher).test("Bash") && new RegExp(g.matcher).test("mcp__github__delete_repo") && new RegExp(g.matcher).test("Write"));
  assert.ok(!new RegExp(g.matcher).test("Glob"), "read-only tools do not pay the hook latency");
  assert.deepEqual(g.hooks[0], { type: "command", command: NODE, args: [o(home).cliPath, "hook", "claude-code", "--timeout", "30"], timeout: 30, onFailure: "block" });
  assert.equal(installHook("claude-code", o(home)).changed, false, "idempotent");
  const u = uninstallHook("claude-code", o(home));
  assert.ok(u.changed);
  assert.deepEqual(read(file).hooks.PreToolUse, [{ matcher: "Bash", hooks: [{ type: "command", command: "my-linter" }] }], "only Kytral entries are removed");
});

test("project install goes to .claude/settings.local.json (machine-specific paths are not committed)", () => {
  const home = tmp(), project = tmp();
  const r = installHook("claude-code", o(home, { project }));
  assert.equal(r.file, join(project, ".claude", "settings.local.json")); assert.ok(existsSync(r.file));
});

test("every agent gets its own format; installing twice changes nothing; uninstall removes everything Kytral", () => {
  for (const agent of INSTALL_AGENTS) {
    const home = tmp(); touchCli(home);
    const r = installHook(agent, o(home));
    const hookName = agent === "trae-cn" ? "trae" : agent, json = !["kimi", "opencode", "mimo", "kiro", "amp", "cline"].includes(agent);
    if (json) {
      const s = read(r.file), hooks = agent === "droid" ? s : s.hooks;   // Droid's hooks.json holds the events at its top level
      assert.ok(Object.values(hooks).flat().length >= 1, agent);
      assert.ok(JSON.stringify(s).includes(`hook ${hookName}`) || JSON.stringify(s).includes(`"hook","${hookName}"`), agent);
      if (["cursor", "copilot", "trae", "trae-cn"].includes(agent)) assert.equal(s.version, 1, agent);
      if (agent === "cursor") assert.ok(Object.values(s.hooks).flat().every((h: any) => h.failClosed === true), "Cursor hooks fail closed");
      if (agent === "gemini") assert.equal(s.hooks.BeforeTool[0].hooks[0].timeout, 30000, "Gemini timeouts are in ms");
    } else {
      const text = readFileSync(r.file, "utf8");
      assert.ok(text.includes(`hook ${hookName}`) || text.includes(`AGENT = "${hookName}"`) || text.includes(`"hook", "${hookName}"`), agent);
    }
    assert.equal(installHook(agent, o(home)).changed, false, agent);
    const ins = inspectHook(agent, o(home));
    assert.ok(ins.installed, agent); assert.deepEqual(ins.problems.filter(p => !/PowerShell/.test(p)), [], agent);
    uninstallHook(agent, o(home));
    assert.ok(!existsSync(r.file) || !readFileSync(r.file, "utf8").match(/kytral/i), agent);
    assert.equal(inspectHook(agent, o(home)).installed, false);
  }
});

test("the fail-closed option is on every handler of the two agents that have one (Claude Code, Cursor), user and project, and on no other agent's", () => {
  for (const agent of INSTALL_AGENTS) for (const project of [undefined, tmp()]) {
    const home = tmp(); touchCli(home);
    const r = installHook(agent, o(home, project ? { project } : {})), text = readFileSync(r.file, "utf8");
    if (agent === "claude-code") {
      const handlers = Object.values(read(r.file).hooks).flat().flatMap((g: any) => g.hooks);
      assert.ok(handlers.length && handlers.every((h: any) => h.onFailure === "block"), `${agent} ${project ? "project" : "user"}`);
    } else if (agent === "cursor") {
      const handlers = Object.values(read(r.file).hooks).flat() as any[];
      assert.ok(handlers.length && handlers.every(h => h.failClosed === true), `${agent} ${project ? "project" : "user"}`);
    } else assert.doesNotMatch(text, /onFailure|failClosed/, `${agent}: a key it does not know can make it drop the hook (Kimi Code drops every [[hooks]] entry then)`);
  }
});

test("Kimi Code: a [[hooks]] entry appended to config.toml, other settings and hooks kept; inline hooks are not touched", () => {
  const home = tmp(), file = configFile("kimi", { home });
  assert.equal(file, join(home, ".kimi-code", "config.toml"));
  mkdirSync(dirname(file), { recursive: true });
  const mine = `default_model = "kimi-k2"\n\n[[hooks]]\nevent = "PreToolUse"\nmatcher = "Bash"\ncommand = "my-linter"\n\n[workspace]\nname = "x"\n`;
  writeFileSync(file, mine);
  const r = installHook("kimi", o(home)), text = readFileSync(file, "utf8");
  assert.ok(text.startsWith(mine.trimEnd()), "the user's content is kept as it was");
  assert.match(text, /\[\[hooks\]\]\nevent = "PreToolUse"\nmatcher = "\^\(Bash\|Write\|Edit\|Read\)\$\|\^mcp__"\ncommand = ".+ hook kimi --timeout 30"\ntimeout = 30\n$/);
  assert.ok(r.backup && existsSync(r.backup));
  assert.equal(installHook("kimi", o(home)).changed, false);
  uninstallHook("kimi", o(home));
  assert.equal(readFileSync(file, "utf8"), mine, "only Kytral's entry is removed");
  writeFileSync(file, `hooks = [{ event = "PreToolUse", command = "x" }]\n`);
  assert.throws(() => installHook("kimi", o(home)), /inline; add this entry to it by hand/);
});

test("TRAE: Claude Code's format with TRAE's tool names, in ~/.trae (TRAE CN: ~/.trae-cn)", () => {
  const home = tmp();
  const r = installHook("trae", o(home)), g = read(r.file).hooks.PreToolUse[0];
  assert.equal(r.file, join(home, ".trae", "hooks.json"));
  assert.ok(new RegExp(g.matcher).test("RunCommand") && new RegExp(g.matcher).test("mcp__github__delete_repo") && !new RegExp(g.matcher).test("Grep"));
  assert.match(g.hooks[0].command, / hook trae --timeout 30$/); assert.match(r.notes.join(" "), /Settings > Hooks/);
  assert.equal(configFile("trae-cn", { home }), join(home, ".trae-cn", "hooks.json"));
  assert.match(read(installHook("trae-cn", o(home)).file).hooks.PreToolUse[0].hooks[0].command, / hook trae --timeout 30$/);
});

test("Cline: the hook script (PowerShell on Windows) runs the guard and stops the task on a refusal", { timeout: 60000 }, () => {
  const home = tmp(), dir = tmp(), root = resolve(import.meta.dirname, "..");
  const file = installHook("cline", { home, nodePath: process.execPath, cliPath: join(root, "src", "cli.ts") }).file;
  assert.equal(file, join(home, "Documents", "Cline", "Hooks", process.platform === "win32" ? "PreToolUse.ps1" : "PreToolUse"));
  const env = { ...process.env, KYTRAL_HOME: join(home, "kytral"),
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --import=${pathToFileURL(join(root, "node_modules", "tsx", "dist", "loader.mjs")).href}`.trim() };
  const event = (commands: string[]) => JSON.stringify({ clineVersion: "4.1.24", hookName: "PreToolUse", timestamp: "1", taskId: "t", workspaceRoots: [dir], userId: "u",
    model: { provider: "p", slug: "s" }, preToolUse: { toolName: "run_commands", parameters: { commands: JSON.stringify(commands) } } });
  // as Cline runs it: PowerShell -File on Windows, the script itself (shebang) elsewhere
  const runHook = (input: string) => process.platform === "win32"
    ? spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file], { input, env, encoding: "utf8" })
    : spawnSync(file, [], { input, env, encoding: "utf8" });
  const no = runHook(event(["npm test", "rm -rf ~"]));
  assert.equal(JSON.parse(no.stdout).cancel, true, no.stderr); assert.match(JSON.parse(no.stdout).errorMessage, /rm -r ~/);
  assert.equal(runHook(event(["ls -la"])).stdout.trim(), "");
});

test("Factory Droid, Augment Auggie, Devin CLI and Kiro CLI: each one's file and format", () => {
  const home = tmp();
  // Droid: the events at the top level of hooks.json, other hooks kept
  const droid = configFile("droid", { home }); mkdirSync(dirname(droid), { recursive: true });
  writeFileSync(droid, JSON.stringify({ PostToolUse: [{ matcher: "", hooks: [{ type: "command", command: "notify" }] }] }));
  installHook("droid", o(home));
  const d = read(droid);
  assert.deepEqual(d.PostToolUse, [{ matcher: "", hooks: [{ type: "command", command: "notify" }] }]); assert.equal(d.hooks, undefined);
  assert.ok(new RegExp(d.PreToolUse[0].matcher).test("Execute") && new RegExp(d.PreToolUse[0].matcher).test("github___delete_repo"));
  uninstallHook("droid", o(home)); assert.deepEqual(Object.keys(read(droid)), ["PostToolUse"]);
  // Auggie: node run directly, a timeout in ms, MCP tools through an "mcp:" matcher
  const a = read(installHook("auggie", o(home)).file).hooks.PreToolUse;
  assert.deepEqual(a.map((g: any) => g.matcher.startsWith("mcp:")), [false, true]);
  assert.equal(a[0].hooks[0].command, NODE); assert.deepEqual(a[0].hooks[0].args.slice(1), ["hook", "auggie", "--timeout", "30"]); assert.equal(a[0].hooks[0].timeout, 30000);
  // Devin: its user configuration file
  assert.equal(configFile("devin", { home }), process.platform === "win32" ? join(home, "AppData", "Roaming", "devin", "config.json") : join(home, ".config", "devin", "config.json"));
  // Kiro: a hook file of the V3 engine
  const k = JSON.parse(readFileSync(installHook("kiro", o(home)).file, "utf8"));
  assert.equal(k.version, "v1"); assert.equal(k.hooks[0].trigger, "PreToolUse"); assert.match(k.hooks[0].action.command, / hook kiro --timeout 30$/);
  const km = new RegExp(k.hooks[0].matcher);
  assert.ok(km.test("execute_bash") && km.test("mcp_github_delete_repo") && !km.test("grep"));
});

test("opencode and MiMo Code: a plugin file of Kytral's own, never one of the user's", () => {
  const home = tmp();
  for (const agent of ["opencode", "mimo"] as const) {
    const r = installHook(agent, o(home)), text = readFileSync(r.file, "utf8");
    assert.equal(r.file, join(home, ".config", agent === "opencode" ? "opencode" : "mimocode", "plugins", "kytral-guard.js"));
    assert.match(text, /^\/\/ Kytral Guard plugin/); assert.match(text, /export const KytralGuard = /);
    assert.equal((text.match(/^export /gm) ?? []).length, 1, "a plugin file may only export plugin functions");
    assert.match(text, agent === "mimo" ? /output\.cancel = true; output\.cancelReason = r\.reason;/ : /throw new Error\(r\.reason\);/);
    writeFileSync(r.file, "export const Mine = async () => ({});\n");
    assert.throws(() => installHook(agent, o(home)), /not written by Kytral Guard/);
    assert.equal(uninstallHook(agent, o(home)).changed, false); assert.ok(existsSync(r.file));
  }
});

test("the opencode plugin blocks what the guard refuses, lets the rest run, and blocks when the guard cannot answer", { timeout: 60000 }, async () => {
  const home = tmp(), dir = tmp(), root = resolve(import.meta.dirname, ".."), saved = process.env.NODE_OPTIONS, savedHome = process.env.KYTRAL_HOME;
  // the plugin runs NODE CLI hook <agent>: here the TypeScript CLI, with tsx for it and its analysis thread, and a state
  // folder of its own (the guard creates its secret there)
  process.env.NODE_OPTIONS = `${saved ?? ""} --import=${pathToFileURL(join(root, "node_modules", "tsx", "dist", "loader.mjs")).href}`.trim();
  process.env.KYTRAL_HOME = join(home, "kytral");
  // each plugin in a home of its own: a module loader may keep the first module loaded from a path
  const plugin = async (agent: "opencode" | "mimo", cliPath = join(root, "src", "cli.ts"), h = home) => {
    const r = installHook(agent, { home: h, nodePath: process.execPath, cliPath });
    const mod = await import(pathToFileURL(r.file).href + `?v=${Math.random()}`);
    return (await mod.KytralGuard({ directory: dir, worktree: dir }))["tool.execute.before"] as (i: object, o: any) => Promise<void>;
  };
  try {
    const before = await plugin("opencode");
    await assert.rejects(before({ tool: "bash", sessionID: "s", callID: "1" }, { args: { command: "rm -rf ~" } }), /rm -r ~/);
    await before({ tool: "bash", sessionID: "s", callID: "2" }, { args: { command: "ls", description: "rm -rf ~ is not run" } });
    await before({ tool: "grep", sessionID: "s", callID: "3" }, { args: { pattern: "rm -rf ~" } });   // read-only: skipped
    await assert.rejects(before({ tool: "github_delete_repository", sessionID: "s", callID: "4" }, { args: { repo: "r" } }), /needs a human/);
    await assert.rejects(before({ tool: "write", sessionID: "s", callID: "5" }, { args: { filePath: join(home, ".ssh", "authorized_keys"), content: "k" } }), /blocked/);
    const mimo = await plugin("mimo"), out: any = { args: { command: "terraform destroy -auto-approve" } };
    await mimo({ tool: "bash", sessionID: "s", callID: "6" }, out);
    assert.equal(out.cancel, true); assert.match(out.cancelReason, /terraform destroy/);
    const broken = await plugin("opencode", join(home, "missing-cli.js"), tmp());
    await assert.rejects(broken({ tool: "bash", sessionID: "s", callID: "7" }, { args: { command: "ls" } }), /./, "a guard that cannot run blocks the call");
    // Amp: a default export that registers tool.call; a confirmation opens Amp's dialog
    const ampFile = installHook("amp", { home: tmp(), nodePath: process.execPath, cliPath: join(root, "src", "cli.ts") }).file;
    const handlers: Record<string, (e: object, ctx: object) => Promise<any>> = {};
    (await import(pathToFileURL(ampFile).href)).default({ on: (name: string, fn: any) => { handlers[name] = fn; } });
    let asked = 0;
    const ctx = (answer: boolean) => ({ ui: { confirm: async () => { asked++; return answer; } } });
    const call = (cmd: string, answer = false, tool = "Bash") => handlers["tool.call"]({ toolUseID: "t", tool, input: { cmd, cwd: dir }, thread: { id: "T" } }, ctx(answer));
    const rm = await call("rm -rf ~");
    assert.equal(rm.action, "reject-and-continue"); assert.match(rm.message, /rm -r ~/); assert.equal(asked, 0, "a block is not offered for approval");
    assert.deepEqual(await call("ls"), { action: "allow" });
    assert.deepEqual(await call("git reset --hard", true), { action: "allow" }); assert.equal(asked, 1);
    assert.equal((await call("git reset --hard", false)).action, "reject-and-continue"); assert.equal(asked, 2);
    assert.deepEqual(await call("x", false, "Read"), { action: "allow" }, "a tool it does not check runs");
  } finally {
    if (saved === undefined) delete process.env.NODE_OPTIONS; else process.env.NODE_OPTIONS = saved;
    if (savedHome === undefined) delete process.env.KYTRAL_HOME; else process.env.KYTRAL_HOME = savedHome;
  }
});

test("Grok Build: a shell command (no exec form there) in ~/.grok/hooks, for its shell, file and MCP tools", () => {
  const home = tmp(), r = installHook("grok", o(home));
  assert.equal(r.file, join(home, ".grok", "hooks", "kytral-guard.json"));
  const g = read(r.file).hooks.PreToolUse[0], h = g.hooks[0];
  assert.equal(h.type, "command"); assert.equal(h.timeout, 30); assert.match(h.command, / hook grok --timeout 30$/);
  assert.ok(h.command.includes(" "), "Grok runs a command without a space as a program with no arguments");
  const m = new RegExp(g.matcher);   // Grok: an unanchored regular expression, also tested against the Claude Code tool names
  for (const t of ["run_terminal_command", "search_replace", "hashline_edit", "write", "read_file", "hashline_read", "github__delete_repository", "Bash"]) assert.ok(m.test(t), t);
  for (const t of ["grep", "list_dir", "web_search", "todo_write", "spawn_subagent"]) assert.ok(!m.test(t), `${t}: read-only tools do not pay the hook latency`);
  assert.match(r.notes.join(" "), /restart/);
  const project = tmp(), p = installHook("grok", o(home, { project }));
  assert.equal(p.file, join(project, ".grok", "hooks", "kytral-guard.json")); assert.match(p.notes.join(" "), /hooks-trust/);
});

test("doctor warns when Grok Build would run the hook through cmd.exe, which it hands escaped quotes", { skip: process.platform !== "win32" && "Windows only" }, () => {
  const home = tmp(), saved = process.env.GROK_SHELL; touchCli(home);
  installHook("grok", o(home));
  try {
    process.env.GROK_SHELL = "cmd";
    assert.match(inspectHook("grok", o(home)).problems.join("\n"), /GROK_SHELL=cmd/);
    process.env.GROK_SHELL = "pwsh";
    assert.deepEqual(inspectHook("grok", o(home)).problems, []);
  } finally { if (saved === undefined) delete process.env.GROK_SHELL; else process.env.GROK_SHELL = saved; }
});

test("an unreadable configuration file is never overwritten", () => {
  const home = tmp(), file = configFile("cursor", { home });
  mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, "{ not json");
  assert.throws(() => installHook("cursor", o(home)), /not valid JSON.*nothing was changed/);
  assert.equal(readFileSync(file, "utf8"), "{ not json");
  writeFileSync(file, "[]");
  assert.throws(() => installHook("cursor", o(home)), /JSON object/);
});

test("dry run writes nothing", () => {
  const home = tmp(), r = installHook("claude-code", o(home, { dryRun: true }));
  assert.ok(r.changed); assert.ok(!existsSync(r.file)); assert.match(r.content, /onFailure/);
});

test("doctor's inspection: missing CLI, fail-open handler, disableAllHooks, no PowerShell", () => {
  const home = tmp(), file = configFile("claude-code", { home });
  installHook("claude-code", o(home));
  assert.ok(inspectHook("claude-code", o(home)).problems.some(p => /does not exist/.test(p)), "the CLI path in the hook is checked");
  touchCli(home);
  const s = read(file); s.disableAllHooks = true; s.hooks.PreToolUse[0].matcher = "Bash"; delete s.hooks.PreToolUse[0].hooks[0].onFailure; writeFileSync(file, JSON.stringify(s));
  const p = inspectHook("claude-code", o(home)).problems.join("\n");
  assert.match(p, /disableAllHooks/); assert.match(p, /fails open/); assert.match(p, /PowerShell/);
  assert.equal(isKytralHandler({ type: "command", command: "node", args: ["/x/kytral-guard/dist/cli.js", "hook", "claude-code"] }), true);
  assert.equal(isKytralHandler({ type: "command", command: "kytral-lint --fix" }), false);
});

test("a copy installed outside a folder named kytral is still recognized: installing twice changes nothing", () => {
  for (const agent of INSTALL_AGENTS) {
    const home = tmp(), cliPath = join(home, "tools", "kg", "dist", "cli.js");
    assert.equal(installHook(agent, o(home, { cliPath })).changed, true, agent);
    assert.equal(installHook(agent, o(home, { cliPath })).changed, false, agent);
    assert.equal(uninstallHook(agent, o(home)).changed, true, agent);
  }
  assert.equal(isKytralHandler({ type: "command", command: "node scripts/cli.js lint" }), false);
  assert.equal(isKytralHandler({ type: "command", command: "npx prettier --write" }), false);
});

test("Homebrew: hooks name the stable link of node, not the folder of its version that the next upgrade removes", { skip: process.platform === "win32" && "symbolic links need privileges on Windows" }, () => {
  const p = tmp(), cellar = join(p, "Cellar", "node", "22.9.0", "bin", "node");
  mkdirSync(dirname(cellar), { recursive: true }); writeFileSync(cellar, "");
  assert.equal(stableNodePath(cellar), cellar, "no link: the path as it is");
  mkdirSync(join(p, "bin")); symlinkSync(cellar, join(p, "bin", "node"));
  assert.equal(stableNodePath(cellar), join(p, "bin", "node"));
  mkdirSync(join(p, "opt")); symlinkSync(join(p, "Cellar", "node", "22.9.0"), join(p, "opt", "node"));
  assert.equal(stableNodePath(cellar), join(p, "opt", "node", "bin", "node"), "the formula's own link first");
  // node@22 (keg-only): its opt link; a bin/node of another version is never taken
  const keg = join(p, "Cellar", "node@22", "22.11.0", "bin", "node"); mkdirSync(dirname(keg), { recursive: true }); writeFileSync(keg, "");
  assert.equal(stableNodePath(keg), keg);
  symlinkSync(join(p, "Cellar", "node@22", "22.11.0"), join(p, "opt", "node@22"));
  assert.equal(stableNodePath(keg), join(p, "opt", "node@22", "bin", "node"));
  assert.equal(stableNodePath("/usr/bin/node"), "/usr/bin/node");
  assert.equal(stableNodePath("/home/u/.nvm/versions/node/v22.9.0/bin/node"), "/home/u/.nvm/versions/node/v22.9.0/bin/node");
});
