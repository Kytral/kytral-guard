// Agent hooks: wire formats of each agent, ask vs deny, fail closed, kill switch, audit, and the CLI entry point.
import { test } from "node:test"; import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs"; import { tmpdir } from "node:os"; import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { detectAgent, parseHookEvent, renderHookAnswer, runHook, canAsk, patchFiles, HookGuard, explain, truncatedArgs } from "../src/hooks.js";
import { engageKillSwitch, releaseKillSwitch, killSwitchKey } from "../src/kill-switch.js";
import { AuditLog, auditKey, verifyAuditFile } from "../src/audit.js";
import { presetPolicy } from "../src/policy.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "4f1c8e2a9b7d3065e8a1c4f7b2d9e6a3c0f5b8d1e4a7c2f9b6d3e0a5c8f1b4d7";
const tmp = () => mkdtempSync(join(tmpdir(), "kg-hooks-"));
const cc = (tool_name: string, tool_input: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ session_id: "s", cwd: "/home/u/p", permission_mode: "default", hook_event_name: "PreToolUse", tool_name, tool_input, ...extra });
/** runHook in an isolated KYTRAL_HOME, with a given secret and audit file. */
function run(agent: string, input: string, o: { home?: string; preset?: string; policyFile?: string } = {}) {
  const home = o.home ?? tmp();
  const audit = new AuditLog(join(home, "audit.jsonl"), { key: auditKey(S) });
  return { home, audit, r: runHook(agent, input, { secret: S, audit, killSwitchFile: join(home, "kill-switch.json"), preset: o.preset ?? (o.policyFile ? undefined : "coding-agent"), policyFile: o.policyFile }) };
}

test("each agent's event is parsed into one tool call", () => {
  const p = (raw: object) => parseHookEvent(detectAgent(raw as any), raw as any);
  assert.deepEqual(p({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, permission_mode: "bypassPermissions" }),
    { agent: "claude-code", cwd: undefined, session: undefined, tool: "Bash", args: { command: "ls" }, mode: "bypassPermissions", native: "PreToolUse" });
  const codex = p({ hook_event_name: "PreToolUse", turn_id: "t", tool_name: "apply_patch", tool_input: { command: "*** Begin Patch\n*** Update File: /etc/hosts\n@@\n-a\n+b\n*** Delete File: src/x.ts\n*** End Patch" } })!;
  assert.equal(codex.agent, "codex"); assert.deepEqual(codex.args.files, ["/etc/hosts", "src/x.ts"]);
  assert.deepEqual(p({ hook_event_name: "beforeShellExecution", command: "rm -rf ~", cwd: "/p" })?.args, { command: "rm -rf ~" });
  const mcp = p({ hook_event_name: "beforeMCPExecution", tool_name: "delete_repo", tool_input: "{\"repo\":\"x\"}", mcp_server_name: "github" })!;
  assert.equal(mcp.tool, "mcp__github__delete_repo"); assert.deepEqual(mcp.args, { repo: "x" });
  assert.equal(p({ hook_event_name: "preToolUse", cursor_version: "2.0", tool_name: "MCP:send_email", tool_input: {} })?.tool, "mcp__cursor__send_email");
  assert.equal(p({ hook_event_name: "BeforeTool", tool_name: "run_shell_command", tool_input: { command: "x" } })?.agent, "gemini");
  assert.deepEqual(p({ sessionId: "1", toolName: "bash", toolArgs: "{\"command\":\"ls\"}" })?.args, { command: "ls" });
  assert.deepEqual(p({ agent_action_name: "pre_run_command", tool_info: { command_line: "rm -rf /", cwd: "/p" } })?.args, { command: "rm -rf /" });
  assert.deepEqual(p({ tool: "query", args: { sql: "DROP TABLE t" } })?.args, { sql: "DROP TABLE t" });
  assert.equal(p({ command: "ls" })?.tool, "shell");
  // events that are not a pre-tool decision get no objection
  for (const raw of [{ hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: {} }, { hook_event_name: "afterFileEdit", cursor_version: "2" }, { hook_event_name: "AfterTool", tool_name: "x" }])
    assert.equal(p(raw), null, JSON.stringify(raw));
  assert.deepEqual(patchFiles("*** Move to: a/b.ts\n*** Add File: c"), ["a/b.ts", "c"]);
});

test("answers use each agent's wire format; a refusal exits 2 where that blocks", () => {
  const block = { action: "block" as const, rule: "shell-catastrophic", reason: "matched rule 'shell-catastrophic': rm -r ~" };
  const ev = (agent: any, extra: object = {}) => ({ agent, tool: "Bash", args: {}, ...extra });
  const c = renderHookAnswer(ev("claude-code"), block, "claude-code");
  assert.equal(c.exitCode, 2); assert.equal(JSON.parse(c.stdout).hookSpecificOutput.permissionDecision, "deny"); assert.match(c.stderr, /blocked this call: rm -r ~ \(rule shell-catastrophic\)/);
  const cur = renderHookAnswer(ev("cursor", { native: "beforeShellExecution" }), block, "cursor");
  assert.equal(cur.exitCode, 0); assert.equal(JSON.parse(cur.stdout).permission, "deny"); assert.ok(JSON.parse(cur.stdout).agent_message);
  assert.deepEqual([renderHookAnswer(ev("gemini"), block, "gemini").exitCode, JSON.parse(renderHookAnswer(ev("gemini"), block, "gemini").stdout).decision], [2, "deny"]);
  assert.equal(JSON.parse(renderHookAnswer(ev("copilot"), block, "copilot").stdout).permissionDecision, "deny");
  assert.deepEqual(renderHookAnswer(ev("windsurf"), block, "windsurf"), { stdout: "", stderr: renderHookAnswer(ev("windsurf"), block, "windsurf").stderr, exitCode: 2 });
  assert.deepEqual(JSON.parse(renderHookAnswer(ev("generic"), block, "generic").stdout), { action: "block", rule: "shell-catastrophic", reason: block.reason });
  // allow: no objection (the agent's own permission flow applies)
  const allow = { action: "allow" as const, reason: "default" };
  assert.deepEqual(renderHookAnswer(ev("claude-code"), allow, "claude-code"), { stdout: "", stderr: "", exitCode: 0 });
  assert.equal(renderHookAnswer(ev("cursor"), allow, "cursor").stdout, JSON.stringify({ permission: "allow" }));
  assert.equal(renderHookAnswer(ev("generic"), allow, "generic").exitCode, 0);
  // the kill switch also stops Claude Code's loop
  const k = JSON.parse(renderHookAnswer(ev("claude-code"), { ...block, killed: true, reason: "kill switch active" }, "claude-code").stdout);
  assert.equal(k.continue, false); assert.match(k.stopReason, /kytral-guard resume/);
  assert.equal(JSON.parse(renderHookAnswer(ev("codex"), { ...block, killed: true }, "codex").stdout).continue, undefined, "Codex fails on fields it does not support");
});

test("a confirmation is asked only where a human can answer; elsewhere it is refused", () => {
  const confirm = { action: "confirm" as const, rule: "shell-destructive", reason: "matched rule 'shell-destructive': git reset --hard" };
  const decision = (agent: any, extra: object = {}) => {
    const r = renderHookAnswer({ agent, tool: "Bash", args: {}, ...extra }, confirm, agent);
    return r.stdout ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision ?? JSON.parse(r.stdout).permission ?? JSON.parse(r.stdout).permissionDecision ?? JSON.parse(r.stdout).decision : `exit ${r.exitCode}`;
  };
  assert.equal(decision("claude-code", { mode: "default" }), "ask");
  assert.equal(decision("claude-code", { mode: "acceptEdits" }), "ask");
  assert.equal(decision("claude-code", { mode: "bypassPermissions" }), "deny");
  assert.equal(decision("claude-code", { mode: "dontAsk" }), "deny");
  assert.equal(decision("codex"), "deny");
  assert.equal(decision("gemini"), "deny");
  assert.equal(decision("windsurf"), "exit 2");
  assert.equal(decision("cursor", { native: "beforeShellExecution" }), "ask");
  assert.equal(decision("cursor", { native: "preToolUse" }), "deny");
  assert.equal(decision("copilot"), "ask");
  assert.equal(canAsk(null, "generic"), true);
  assert.equal(explain(confirm), "git reset --hard (rule shell-destructive)");
  assert.equal(explain({ action: "block", reason: "matched rule 'x'" }), "rule x");
});

/** A Grok Build event (xai-grok-hooks HookEventEnvelope): camelCase keys, plus the snake_case aliases of the builds since 2026-08-28. */
const grok = (toolName: string, toolInput: unknown, o: { aliases?: boolean; mode?: string; truncated?: boolean } = {}) => JSON.stringify({
  hookEventName: "pre_tool_use", sessionId: "s", cwd: "/home/u/p", workspaceRoot: "/home/u/p", timestamp: "2026-10-15T12:00:00Z",
  permissionMode: o.mode ?? "default", toolName, toolUseId: "t1", toolInput, toolInputTruncated: o.truncated ?? false,
  ...(o.aliases === false ? {} : { hook_event_name: "PreToolUse", session_id: "s", permission_mode: o.mode ?? "default", tool_name: toolName, tool_input: toolInput, tool_use_id: "t1" }),
});

test("Grok Build: its events are read and answered as Grok's, whatever hook command runs them", () => {
  // Grok Build also runs the hooks of Claude Code and Cursor (and `hook auto` must not read its events as Copilot's)
  for (const agent of ["grok", "auto", "claude-code", "cursor", "generic"]) {
    const r = run(agent, grok("run_terminal_command", { command: "rm -rf ~" })).r, out = JSON.parse(r.stdout);
    assert.equal(r.exitCode, 2, agent); assert.equal(out.decision, "deny", agent); assert.equal(out.hookSpecificOutput.permissionDecision, "deny", agent);
    assert.match(r.stderr, /rm -r ~ \(rule shell-catastrophic\)/);
    assert.deepEqual(run(agent, grok("run_terminal_command", { command: "npm test" })).r, { stdout: "", stderr: "", exitCode: 0 }, agent);
  }
  // builds before 2026-08-28 send the camelCase keys only
  assert.equal(run("grok", grok("run_terminal_command", { command: "rm -rf ~" }, { aliases: false })).r.exitCode, 2);
  assert.equal(run("cursor", grok("run_terminal_command", { command: "rm -rf ~" }, { aliases: false })).r.exitCode, 2);
  // edits: the path is checked, the new text is content, not a command; the guard's secret cannot be read
  assert.equal(run("grok", grok("search_replace", { file_path: "/home/u/.ssh/authorized_keys", old_string: "", new_string: "ssh-ed25519 AAAA" })).r.exitCode, 2);
  assert.equal(run("grok", grok("hashline_edit", { file_path: "/home/u/.bashrc", edits: [] })).r.exitCode, 2);
  assert.equal(run("grok", grok("write", { file_path: "/home/u/.grok/hooks/kytral-guard.json", content: "{}" })).r.exitCode, 2);
  assert.equal(run("grok", grok("search_replace", { file_path: "/home/u/p/clean.sh", old_string: "a", new_string: "rm -rf ~ # content" })).r.exitCode, 0);
  assert.equal(run("grok", grok("read_file", { target_file: "~/.kytral/secret" })).r.exitCode, 2);
  // MCP tools are server__tool: the MCP rules apply
  assert.equal(parseHookEvent("grok", JSON.parse(grok("github__delete_repository", { owner: "o", repo: "r" })))?.tool, "mcp__github__delete_repository");
  assert.equal(JSON.parse(run("grok", grok("github__delete_repository", { owner: "o", repo: "r" })).r.stdout).hookSpecificOutput.permissionDecision, "ask");
  // other events get no objection, and so do the tools the hook's matcher leaves out (search, web, plans), which Grok also
  // sends to Cursor's hook (no matcher there): a search for "rm -rf ~" is not a command
  assert.equal(parseHookEvent("grok", { hookEventName: "post_tool_use", workspaceRoot: "/p", toolName: "x" }), null);
  for (const [tool, input] of [["grep", { pattern: "rm -rf ~", path: "." }], ["web_search", { query: "DROP TABLE users" }], ["todo_write", { todos: [{ content: "rm -rf ~" }] }]] as const)
    assert.deepEqual(run("cursor", grok(tool, input)).r, { stdout: "", stderr: "", exitCode: 0 }, tool);
  assert.equal(run("auto", JSON.stringify({ toolName: "run_terminal_command", toolInput: { command: "ls" } })).r.exitCode, 2);
  assert.equal(detectAgent({ toolName: "bash", toolArgs: "{}" }), "copilot");
});

test("Grok Build: a confirmation is asked only where its build and mode prompt a human; a truncated call needs one", () => {
  const answer = (input: string) => { const r = run("grok", input).r; return [r.exitCode, JSON.parse(r.stdout).decision]; };
  const reset = (o: object = {}) => grok("run_terminal_command", { command: "git reset --hard" }, o);
  assert.deepEqual(answer(reset()), [0, "ask"]);
  assert.deepEqual(answer(reset({ mode: "auto" })), [0, "ask"]);   // Grok's classifier cannot approve a hook's ask
  assert.deepEqual(answer(reset({ mode: "bypassPermissions" })), [2, "deny"]);
  assert.deepEqual(answer(reset({ aliases: false })), [2, "deny"], "older builds count 'ask' as a failed hook and run the tool");
  // Grok sends the first 128 KB of a larger call, as text: what it holds can block, the rest needs a human
  const cut = (command: string) => grok("run_terminal_command", JSON.stringify({ command }).slice(0, 40) + " [truncated]", { truncated: true });
  assert.deepEqual(answer(cut("rm -rf ~ && echo " + "x".repeat(100))), [2, "deny"]);
  assert.deepEqual(answer(cut("ls -la && echo " + "y".repeat(100))), [0, "ask"]);
  assert.match(run("grok", cut("ls -la && echo " + "y".repeat(100))).r.stdout, /only the beginning of the call/);
  assert.deepEqual(truncatedArgs('{"a":"x","command":"rm -rf ~ \\u00 [truncated]'), { a: "x", command: "rm -rf ~ " });
  assert.deepEqual(truncatedArgs("[1,2 [truncated]"), { input: "[1,2" });
});

test("Kimi Code, TRAE and the opencode / MiMo Code plugin: each one's format, and each one's way to ask", () => {
  // Kimi Code: Claude Code's format, no permission mode; it reads any answer but deny as an approval, so nothing is asked
  const kimi = (command: string, extra: object = {}) => JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s", session_title: "t", client_type: "cli",
    cwd: "/home/u/p", tool_name: "Bash", tool_input: { command, ...extra }, tool_call_id: "c" });
  const k = run("kimi", kimi("rm -rf ~")).r;
  assert.equal(k.exitCode, 2); assert.equal(JSON.parse(k.stdout).hookSpecificOutput.permissionDecision, "deny");
  const kr = run("kimi", kimi("git reset --hard")).r;
  assert.equal(kr.exitCode, 2); assert.match(kr.stderr, /needs a human/);
  assert.equal(parseHookEvent("kimi", JSON.parse(kimi("ls", { cwd: "sub" })))?.cwd, resolve("/home/u/p", "sub"), "a command runs in its own folder");
  assert.equal(run("auto", kimi("git reset --hard")).r.exitCode, 2, "hook auto: a Kimi event is not answered as Claude Code's (ask)");
  // TRAE: RunCommand; it asks, and the kill switch also stops it
  const trae = (command: string) => JSON.stringify({ session_id: "s", cwd: "/home/u/p", hook_event_name: "PreToolUse", workspace_roots: ["/home/u/p"], tool_use_id: "t",
    tool_name: "RunCommand", llm_tool_name: "run_command", tool_input: { command } });
  assert.equal(run("trae", trae("rm -rf ~")).r.exitCode, 2);
  assert.equal(JSON.parse(run("trae", trae("git reset --hard")).r.stdout).hookSpecificOutput.permissionDecision, "ask");
  assert.equal(detectAgent(JSON.parse(trae("ls"))), "trae");
  assert.equal(JSON.parse(renderHookAnswer(null, { action: "block", reason: "x", killed: true }, "trae").stdout).continue, false);
  // the plugin: exit code 0 lets the call run, anything else blocks it
  const plug = (tool: string, args: object) => JSON.stringify({ tool, args, cwd: "/home/u/p", sessionID: "s" });
  assert.equal(run("opencode", plug("bash", { command: "rm -rf ~" })).r.exitCode, 2);
  assert.deepEqual(run("opencode", plug("bash", { command: "npm test" })).r, { stdout: "", stderr: "", exitCode: 0 });
  assert.equal(parseHookEvent("opencode", JSON.parse(plug("grep", { pattern: "rm -rf ~" }))), null);
  assert.equal(parseHookEvent("mimo", JSON.parse(plug("github_delete_repository", { repo: "r" })))?.tool, "mcp__github_delete_repository");
  const patch = "*** Begin Patch\n*** Update File: /home/u/.ssh/authorized_keys\n@@\n+k\n*** End Patch";
  assert.equal(run("opencode", plug("apply_patch", { patchText: patch })).r.exitCode, 2);
  assert.equal(run("mimo", plug("apply_patch", { patch_text: patch })).r.exitCode, 2);
  assert.equal(run("opencode", plug("write", { filePath: "/home/u/p/clean.sh", content: "rm -rf ~" })).r.exitCode, 0, "content is not a command");
});

test("Qwen Code, iFlow CLI, Qoder CLI and CodeBuddy Code: Claude Code's format, each with its own way to refuse", () => {
  const ev = (tool_name: string, command: string, extra: object = {}) => ({ session_id: "s", cwd: "/home/u/p", hook_event_name: "PreToolUse", tool_name, tool_input: { command }, ...extra });
  // Qwen Code: a JSON deny with exit code 0 (there, a refusal by exit code 2 loses to another hook's JSON allow)
  const q = run("qwen", JSON.stringify(ev("run_shell_command", "rm -rf ~", { permission_mode: "yolo", prompt_id: "p", tool_call_id: "c" }))).r;
  assert.equal(q.exitCode, 0); assert.equal(JSON.parse(q.stdout).hookSpecificOutput.permissionDecision, "deny");
  assert.equal(JSON.parse(run("qwen", JSON.stringify(ev("run_shell_command", "git reset --hard", { permission_mode: "default" }))).r.stdout).hookSpecificOutput.permissionDecision, "ask");
  assert.equal(detectAgent(ev("run_shell_command", "ls", { prompt_id: "p", tool_call_id: "c" })), "qwen");
  // iFlow CLI: only a top-level decision counts, and it cannot ask
  const iflow = (command: string, extra: object = {}) => JSON.stringify(ev("run_shell_command", command, { tool_name_alias: ["Bash"], tool_desc: "", tool_schema: {}, ...extra }));
  const i = run("iflow", iflow("rm -rf ~")).r;
  assert.equal(i.exitCode, 2); assert.deepEqual(JSON.parse(i.stdout), { decision: "block", reason: JSON.parse(i.stdout).reason }); assert.match(i.stderr, /rm -r ~/);
  assert.equal(JSON.parse(run("iflow", iflow("git reset --hard")).r.stdout).decision, "block");
  assert.equal(run("auto", iflow("git reset --hard")).r.exitCode, 2, "hook auto: an iFlow event is not answered as Claude Code's");
  assert.equal(parseHookEvent("iflow", JSON.parse(iflow("ls", { tool_input: { command: "ls", dir_path: "sub" } })))?.cwd, resolve("/home/u/p", "sub"));
  // Qoder CLI: Claude Code's answers
  const qo = run("qoder", JSON.stringify(ev("Bash", "rm -rf ~", { model: "m", permission_mode: "default", tool_use_id: "t" }))).r;
  assert.equal(qo.exitCode, 2); assert.equal(JSON.parse(qo.stdout).hookSpecificOutput.permissionDecision, "deny");
  // CodeBuddy Code: the reason it shows is a top-level reason; nobody answers in bypassPermissions
  const cb = run("codebuddy", JSON.stringify(ev("Bash", "rm -rf ~", { generation_id: "g", call_id: "c", permission_mode: "default" }))).r;
  assert.equal(cb.exitCode, 2); assert.match(JSON.parse(cb.stdout).reason, /rm -r ~/);
  assert.equal(detectAgent(ev("Bash", "ls", { generation_id: "g" })), "codebuddy");
  const bypass = run("codebuddy", JSON.stringify(ev("Bash", "git reset --hard", { permission_mode: "bypassPermissions", generation_id: "g" }))).r;
  assert.equal(JSON.parse(bypass.stdout).hookSpecificOutput.permissionDecision, "deny");
});

test("Factory Droid, Augment Auggie, Devin CLI, Kiro CLI, Amp and Cline: each one's event and answer", () => {
  const cc2 = (tool_name: string, tool_input: object, extra: object = {}) => JSON.stringify({ hook_event_name: "PreToolUse", cwd: "/home/u/p", tool_name, tool_input, ...extra });
  // Droid: Execute; its summary and risk note are notes; MCP tools are server___tool; it cannot ask
  const droid = (tool_input: object, tool = "Execute") => run("droid", cc2(tool, tool_input, { session_id: "s", permission_mode: "auto-medium" })).r;
  assert.equal(droid({ command: "rm -rf ~", summary: "clean", riskLevel: "high" }).exitCode, 2);
  assert.equal(droid({ command: "ls", summary: "rm -rf ~ is only mentioned", riskLevelReason: "rm -rf ~" }).exitCode, 0);
  assert.equal(parseHookEvent("droid", JSON.parse(cc2("github___delete_repo", {})))?.tool, "mcp__github___delete_repo");
  assert.equal(droid({ repo: "r" }, "github___delete_repo").exitCode, 2);
  // Auggie: launch-process, workspace_roots, MCP tools named tool_server (is_mcp_tool), not taken for TRAE
  const aug = (tool_name: string, tool_input: object, is_mcp_tool = false) => cc2(tool_name, tool_input, { conversation_id: "c", workspace_roots: ["/home/u/p"], tool_error: null, is_mcp_tool });
  assert.equal(detectAgent(JSON.parse(aug("launch-process", { command: "ls" }))), "auggie");
  assert.equal(run("auggie", aug("launch-process", { command: "rm -rf ~", wait: true, cwd: "/home/u/p" })).r.exitCode, 2);
  assert.equal(parseHookEvent("auggie", JSON.parse(aug("delete_repo_github", { repo: "r" }, true)))?.tool, "mcp__delete_repo_github");
  // Devin: exec; Kiro: execute_bash, and a confirmation is refused (headless runs would approve an ask)
  assert.equal(run("devin", cc2("exec", { command: "rm -rf ~", shell_id: "main" }, { session_id: "s", prompt_id: "p" })).r.exitCode, 2);
  const kiro = run("kiro", cc2("execute_bash", { command: "git reset --hard", description: null, cwd: null }, { session_id: "s" })).r;
  assert.equal(kiro.exitCode, 2); assert.match(kiro.stderr, /needs a human/);
  // Amp's plugin: Bash {cmd}; exit code 3 asks (Amp shows a dialog); tools it does not check get no objection
  const amp = (tool: string, args: object) => JSON.stringify({ tool, args, cwd: "/home/u/p", sessionID: "T" });
  assert.equal(run("amp", amp("Bash", { cmd: "rm -rf ~", cwd: "/home/u/p" })).r.exitCode, 2);
  assert.equal(run("amp", amp("Bash", { cmd: "git reset --hard" })).r.exitCode, 3);
  assert.equal(parseHookEvent("amp", JSON.parse(amp("Read", { path: "x" }))), null);
  // Cline: the extension sends parameters as JSON text, the SDK the call itself; a refusal is {cancel}
  const clineVsCode = (toolName: string, parameters: object) => JSON.stringify({ clineVersion: "4.1.24", hookName: "PreToolUse", taskId: "t", workspaceRoots: ["/home/u/p"], preToolUse: { toolName, parameters } });
  const c1 = run("cline", clineVsCode("run_commands", { commands: JSON.stringify(["npm test", "rm -rf ~"]) })).r;
  assert.equal(c1.exitCode, 0); assert.equal(JSON.parse(c1.stdout).cancel, true); assert.match(JSON.parse(c1.stdout).errorMessage, /rm -r ~/);
  assert.deepEqual(run("cline", clineVsCode("run_commands", { commands: JSON.stringify(["ls"]) })).r, { stdout: "", stderr: "", exitCode: 0 });
  assert.equal(detectAgent(JSON.parse(clineVsCode("run_commands", {}))), "cline");
  const sdk = JSON.stringify({ hookName: "tool_call", taskId: "t", workspaceRoots: ["/home/u/p"], tool_call: { id: "1", name: "run_commands", input: { commands: [{ command: "git", args: ["reset", "--hard"] }] } } });
  assert.equal(JSON.parse(run("cline", sdk).r.stdout).cancel, true, "a confirmation is refused there");
  assert.equal(JSON.parse(run("cline", clineVsCode("editor", { path: "/home/u/.ssh/authorized_keys", new_text: "k" })).r.stdout).cancel, true);
  assert.equal(run("cline", clineVsCode("editor", { path: "/home/u/p/a.sh", new_text: "rm -rf ~" })).r.stdout, "", "content is not a command");
  assert.equal(parseHookEvent("cline", JSON.parse(clineVsCode("use_mcp_tool", { server_name: "github", tool_name: "delete_repository", arguments: "{\"repo\":\"r\"}" })))?.tool, "mcp__github__delete_repository");
  assert.equal(parseHookEvent("cline", JSON.parse(clineVsCode("search_files", { regex: "rm -rf ~" }))), null);
});

test("the description an agent writes beside a shell command is a note, not a command", () => {
  const note = "Search for rm -rf ~ usages; DROP TABLE users is mocked in tests";
  assert.equal(run("claude-code", cc("Bash", { command: "grep -rn 'rm -rf' scripts/", description: note })).r.exitCode, 0);
  assert.equal(run("claude-code", cc("PowerShell", { command: "Get-ChildItem", description: note })).r.exitCode, 0);
  assert.equal(run("grok", grok("run_terminal_command", { command: "ls", description: note, is_background: false })).r.exitCode, 0);
  assert.equal(run("gemini", JSON.stringify({ hook_event_name: "BeforeTool", tool_name: "run_shell_command", tool_input: { command: "ls", description: note } })).r.exitCode, 0);
  // the command itself is analyzed, and so is every field of other tools (an MCP tool may run what it is given)
  assert.equal(run("claude-code", cc("Bash", { command: "rm -rf ~", description: "list the files" })).r.exitCode, 2);
  assert.equal(run("claude-code", cc("mcp__runner__run_task", { description: "rm -rf ~" })).r.exitCode, 2);
});

test("runHook decides with the policy and journals every outcome (never the arguments)", () => {
  const home = tmp();
  for (const [input, code] of [[cc("Bash", { command: "rm -rf ~" }), 2], [cc("Bash", { command: "npm test" }), 0], [cc("Bash", { command: "git reset --hard" }), 0],
    [cc("Write", { file_path: "/home/u/p/a.sh", content: "rm -rf / # in a file: content, not a command" }), 0]] as const) {
    assert.equal(run("claude-code", input, { home }).r.exitCode, code, input);
  }
  const lines = readFileSync(join(home, "audit.jsonl"), "utf8").trim().split("\n").map(l => JSON.parse(l));
  assert.deepEqual(lines.map(l => l.decision), ["block", "allow", "ask", "allow"]);
  assert.equal(lines[0].rule, "shell-catastrophic"); assert.match(lines[0].reason, /rm -r ~/); assert.equal(lines[0].server, "/home/u/p");
  assert.ok(!JSON.stringify(lines).includes("in a file"), "arguments are never journaled");
  assert.equal(verifyAuditFile(join(home, "audit.jsonl"), auditKey(S)).exitCode, 0);
});

test("runHook fails closed: bad input, unknown agent, broken policy, unwritable audit", () => {
  for (const input of ["", "not json", "[1,2]", "42"]) {
    const { r } = run("claude-code", input);
    assert.equal(r.exitCode, 2, input); assert.match(r.stderr, /fail closed/);
  }
  assert.equal(run("nope", cc("Bash", { command: "ls" })).r.exitCode, 2);
  const dir = tmp(), bad = join(dir, "policy.yaml"); writeFileSync(bad, "rules:\n  - name: x\n    action: maybe\n");
  const r = run("claude-code", cc("Bash", { command: "ls" }), { policyFile: bad }).r;
  assert.equal(r.exitCode, 2); assert.match(r.stderr, /bad action/);
  const cursor = run("cursor", "garbage").r;   // Cursor blocks on a deny JSON; the answer stays in its format
  assert.equal(JSON.parse(cursor.stdout).permission, "deny");
  // an allow that cannot be journaled is refused: no unjournaled call
  const home = tmp(), audit = new AuditLog(join(home, "audit.jsonl"), { key: auditKey(S) });
  audit.append = () => { throw new Error("disk full"); };
  const denied = runHook("claude-code", cc("Bash", { command: "ls" }), { secret: S, audit, killSwitchFile: join(home, "ks.json"), preset: "coding-agent" });
  assert.equal(denied.exitCode, 2); assert.match(denied.stderr, /audit log cannot be written.*disk full/);
});

test("the shared kill switch stops every hook, and only a signed resume lifts it", () => {
  const home = tmp(), ks = join(home, "kill-switch.json"), audit = new AuditLog(join(home, "audit.jsonl"), { key: auditKey(S) });
  const hook = (cmd: string) => runHook("claude-code", cc("Bash", { command: cmd }), { secret: S, audit, killSwitchFile: ks, preset: "coding-agent" });
  assert.equal(hook("ls").exitCode, 0);
  engageKillSwitch("ops", { path: ks, audit, key: killSwitchKey(S) });
  const r = hook("ls"); assert.equal(r.exitCode, 2); assert.equal(JSON.parse(r.stdout).continue, false);
  writeFileSync(ks, JSON.stringify({ v: 1, killed: false, gen: 99, at: "x", by: "agent", sig: "forged" }));
  assert.equal(hook("ls").exitCode, 2, "a forged resume does not lift the kill");
  releaseKillSwitch(S, "ops", { path: ks, audit });
  assert.equal(hook("ls").exitCode, 0);
});

test("HookGuard creates an owner-only secret when none exists", { skip: process.platform === "win32" && "POSIX file modes" }, () => {
  const home = tmp(), saved = { home: process.env.KYTRAL_HOME, secret: process.env.KYTRAL_SECRET };
  const restore = (k: string, v: string | undefined) => { if (v === undefined) delete process.env[k]; else process.env[k] = v; };
  try {
    process.env.KYTRAL_HOME = home; delete process.env.KYTRAL_SECRET;
    new HookGuard({ policy: presetPolicy("coding-agent"), audit: null });
    assert.equal(statSync(join(home, "secret")).mode & 0o777, 0o600);
  } finally { restore("KYTRAL_HOME", saved.home); restore("KYTRAL_SECRET", saved.secret); }
});

test("CLI: hook reads the event on stdin; check answers with an exit code", { timeout: 60000 }, () => {
  const home = tmp(), env = { ...process.env, KYTRAL_HOME: home, KYTRAL_SECRET: S };
  const cli = (args: string[], input = "") => spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...args], { cwd: ROOT, env, input, encoding: "utf8" });
  const h = cli(["hook", "claude-code"], cc("Bash", { command: "terraform destroy -auto-approve" }));
  assert.equal(h.status, 2); assert.equal(JSON.parse(h.stdout).hookSpecificOutput.permissionDecision, "deny"); assert.match(h.stderr, /terraform destroy/);
  assert.equal(cli(["hook", "auto"], cc("Bash", { command: "ls" })).status, 0);
  // Grok Build runs Cursor's hooks with its own events: answered in Grok's vocabulary, which Cursor's would not be
  const g = cli(["hook", "cursor"], grok("run_terminal_command", { command: "rm -rf ~" }));
  assert.equal(g.status, 2); assert.equal(JSON.parse(g.stdout).decision, "deny");
  assert.equal(cli(["hook", "claude-code", "--bogus"], cc("Bash", { command: "ls" })).status, 2, "a broken hook command refuses");
  assert.equal(cli(["check", "rm -rf ~"]).status, 2);
  assert.equal(cli(["check", "git reset --hard"]).status, 3);
  assert.equal(cli(["check", "--", "ls", "-la"]).status, 0);
  const j = cli(["check", "--json"], JSON.stringify({ tool: "query", args: { sql: "DELETE FROM users" } }));
  assert.equal(JSON.parse(j.stdout).action, "block");
  assert.match(cli(["check", "--preset", "strict", "rm -rf node_modules"]).stdout, /^BLOCK/);
  assert.match(cli(["--help"]).stdout, /anti-catastrophe guard/);
  assert.match(cli(["--version"]).stdout, /^\d+\.\d+\.\d+/);
  assert.match(cli(["policy", "presets"]).stdout, /coding-agent/);
  assert.match(cli(["policy", "show", "--preset", "coding-agent"]).stdout, /shell-catastrophic/);
});

test("Cursor: a shell command or a file path that is not text is a malformed event, refused", () => {
  for (const ev of [{ hook_event_name: "beforeShellExecution", command: { x: 1 } }, { hook_event_name: "beforeShellExecution" }, { hook_event_name: "beforeReadFile", file_path: 7 }])
    assert.match(runHook("cursor", JSON.stringify(ev), { secret: "5e9d2c8a1f7b4063d2e8a5f1c9b74d30e6a2f8b1", audit: null }).stdout, /"permission":"deny"/, JSON.stringify(ev));
  assert.equal(runHook("cursor", JSON.stringify({ hook_event_name: "beforeShellExecution", command: "ls" }), { secret: "5e9d2c8a1f7b4063d2e8a5f1c9b74d30e6a2f8b1", audit: null }).stdout, JSON.stringify({ permission: "allow" }));
});
