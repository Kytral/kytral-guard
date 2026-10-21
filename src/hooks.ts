// Agent hooks: `kytral-guard hook <agent>` reads one pre-tool event on stdin, decides with the policy, the shared kill switch
// and the audit log, and answers in the agent's own wire format (Claude Code, Cursor, Codex, Gemini CLI, Copilot CLI,
// Windsurf, Grok Build, or a generic JSON format). Every failure fails closed: an unreadable event, a broken policy or an
// internal error is answered with a refusal, never with silence (most agents run the tool when a hook fails).
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { Worker } from "node:worker_threads";
import { loadPolicy, policyProblem, presetPolicy, Decision, Policy } from "./policy.js";
import { argsSize, evaluateSyncBounded, MAX_ANALYSIS_BYTES, workerExecArgv } from "./evaluate-bounded.js";
import { AuditLog, auditKey } from "./audit.js";
import { KillSwitch, killSwitchKey, killSwitchPath, startingSwitch } from "./kill-switch.js";
import { NotRegularFile, readRegular, statePath } from "./store.js";
import { assertStrongSecret, resolveSecret } from "./secret.js";
import { flushPlugins, guardConfig, KytralPlugin, notifyPlugins, pluginConfirm, pluginKillReason, pluginPolicy } from "./plugins.js";
import { auditAllowsEnabled, exactText, HIDDEN_CHARACTERS, keepCall, keepCallsEnabled } from "./kept-calls.js";
import { FileConfirmQueue, nobodyToAsk } from "./confirm-queue.js";

export const HOOK_AGENTS = ["claude-code", "cursor", "codex", "gemini", "copilot", "windsurf", "grok", "kimi", "trae", "opencode", "mimo",
  "qwen", "iflow", "qoder", "codebuddy", "droid", "auggie", "devin", "kiro", "amp", "cline", "generic"] as const;
export type HookAgent = typeof HOOK_AGENTS[number];
/** One tool call an agent is about to make, in the agent-neutral shape the policy evaluates. */
export interface HookEvent {
  agent: HookAgent; tool: string; args: Record<string, unknown>;
  cwd?: string; session?: string;
  /** Claude Code / Codex / Grok Build permission mode: in bypassPermissions and dontAsk nobody answers a prompt. */
  mode?: string;
  /** The agent's own event name (PreToolUse, beforeShellExecution, BeforeTool...). */
  native?: string;
  /** The agent cut the arguments before sending them (Grok Build, over 128 KB): what is missing cannot be analyzed. */
  truncated?: boolean;
}
/**
 * `killed`: refused by the local kill switch (true) or by a plugin that refuses every call ("plugin": a fleet kill switch, a
 * revoked device...). `call`: the number of the kept call that holds the exact command, for `kytral-guard allow --call`.
 */
export interface HookVerdict extends Decision { killed?: boolean | "plugin"; call?: number }
export interface HookAnswer { stdout: string; stderr: string; exitCode: number }

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? { ...(v as Record<string, unknown>) } : {});
const isObjLike = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown) => (typeof v === "string" ? v : undefined);
/** Tool arguments that some agents send as a JSON string. */
const jsonArgs = (v: unknown): Record<string, unknown> => {
  if (typeof v !== "string") return obj(v);
  try { const o = JSON.parse(v); return o && typeof o === "object" && !Array.isArray(o) ? o : { input: o }; } catch { return { input: v }; }
};
/** Tool arguments of a pre-tool event: an object, a JSON string, or anything else kept as text (never silently dropped). */
function toolArgs(v: unknown): Record<string, unknown> {
  if (v === undefined || v === null) return {};
  if (typeof v === "string") return jsonArgs(v);
  if (typeof v === "object" && !Array.isArray(v)) return { ...(v as Record<string, unknown>) };
  return { input: JSON.stringify(v) };
}
/**
 * The string fields of tool arguments cut short (Grok Build sends a call over 128 KB as the first 128 KB of its JSON text,
 * plus " [truncated]"): the complete fields, and the beginning of the field that was cut, so that it can still be blocked.
 */
export function truncatedArgs(text: string): Record<string, unknown> {
  const s = text.replace(/ \[truncated\]$/, ""), out: Record<string, unknown> = {};
  for (const m of s.matchAll(/"((?:[^"\\]|\\.)*)"\s*:\s*"((?:[^"\\]|\\.)*)/g)) {
    // an escape sequence cut in the middle ends the value
    try { out[JSON.parse(`"${m[1]}"`)] = JSON.parse(`"${m[2].replace(/\\(u[0-9a-fA-F]{0,3})?$/, "")}"`); } catch { /* not a string field */ }
  }
  return Object.keys(out).length ? out : { input: s };
}
/** A pre-tool event the guard cannot read is refused (fail closed), never answered with "no objection". */
function malformed(what: string): never { throw new Error(`malformed pre-tool event: ${what}`); }
/** Files a Codex apply_patch adds, updates, deletes or moves: file rules (sensitive paths) see them, the patch text is content. */
export function patchFiles(patch: string): string[] {
  return [...patch.matchAll(/^\*\*\* (?:(?:Add|Update|Delete) File|Move to): (.+)$/gm)].map(m => m[1].trim());
}

export function isHookAgent(a: string): a is HookAgent { return (HOOK_AGENTS as readonly string[]).includes(a); }
/**
 * The Grok Build tools the guard checks, as the matcher of its hook (a regular expression Grok also tests against the Claude
 * Code names of its tools): the shell, file edits and reads, and MCP tools (server__tool). The others (search, listing, web,
 * plans, subagents, whose own calls come back through the hook) get no objection, also when Grok sends them to a hook
 * without a matcher, such as Cursor's.
 */
export const GROK_HOOK_MATCHER = "^(run_terminal_command|search_replace|hashline_edit|write|read_file|hashline_read|Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read)$|__";
const GROK_TOOLS = new RegExp(GROK_HOOK_MATCHER);
/**
 * A Grok Build event: camelCase keys (hookEventName "pre_tool_use", workspaceRoot, toolName, toolInput), plus snake_case
 * aliases in the builds since 2026-08-28. Grok Build sends it to every hook it runs, the ones it finds in Claude Code's and
 * Cursor's configuration included.
 */
export function isGrokEvent(raw: Record<string, unknown>): boolean {
  return typeof raw.hookEventName === "string" && typeof raw.workspaceRoot === "string";
}
/** The agent that sent an event, from its shape (field names and event names differ between agents). */
export function detectAgent(raw: Record<string, unknown>): HookAgent {
  const ev = str(raw.hook_event_name);
  if (isGrokEvent(raw)) return "grok";
  if (typeof raw.agent_action_name === "string") return "windsurf";
  // toolArgs too: an unknown event that only has a toolName is refused, not read as a Copilot call without arguments
  if (typeof raw.toolName === "string" && raw.toolArgs !== undefined) return "copilot";
  if (ev === "BeforeTool") return "gemini";
  if ((ev && /^(beforeShellExecution|beforeMCPExecution|beforeReadFile|preToolUse)$/.test(ev)) || raw.cursor_version !== undefined) return "cursor";
  if (raw.turn_id !== undefined) return "codex";
  // Claude Code's format, with their own fields. Answered as Claude Code, Kimi Code and iFlow would let a confirmation run
  // (Kimi reads "ask" as an approval, iFlow ignores an answer without a top-level decision)
  if (raw.client_type !== undefined && raw.session_title !== undefined) return "kimi";
  if (Array.isArray(raw.tool_name_alias) || raw.tool_schema !== undefined) return "iflow";
  if (raw.is_mcp_tool !== undefined && raw.conversation_id !== undefined) return "auggie";
  if (typeof raw.hookName === "string" && (raw.preToolUse !== undefined || raw.tool_call !== undefined || raw.clineVersion !== undefined)) return "cline";
  if (raw.llm_tool_name !== undefined || Array.isArray(raw.workspace_roots)) return "trae";
  if (raw.generation_id !== undefined) return "codebuddy";
  if (raw.prompt_id !== undefined && raw.tool_call_id !== undefined) return "qwen";
  if (ev === "PreToolUse") return "claude-code";
  return "generic";
}

/** The shell tools of the agents: their `command` runs; the description, summary or risk note beside it is for the user. */
const SHELL_TOOLS = /^(bash|powershell|pwsh|shell|shell_command|run_shell_command|run_terminal_command|run_terminal_cmd|run_command|runcommand|execute|execute_bash|execute_pwsh|execute_command|exec|exec_command|local_shell|launch-process)$/i;
/** A shell tool of an agent: its `command` runs. */
export const isShellTool = (tool: string) => SHELL_TOOLS.test(tool);
/** Can this agent show a human a prompt for a confirmation (outside the modes that skip prompts)? Install names too (trae-cn). */
export const agentCanAsk = (agent: string): boolean => CAN_ASK[(agent === "trae-cn" ? "trae" : agent) as HookAgent] ?? false;
const NOTES = ["description", "summary", "riskLevelReason"];
/**
 * The tool call an event asks about, or null when it is not a pre-tool decision (the answer is then "no objection"). The
 * description an agent writes beside a shell command is not analyzed as a command ("Search for rm -rf ~ usages"), and the
 * folder a shell command runs in (cwd, workdir, directory) is where the scripts it runs are read from.
 */
export function parseHookEvent(agent: HookAgent, raw: Record<string, unknown>): HookEvent | null {
  const ev = parseAgentEvent(agent, raw);
  if (!ev || !SHELL_TOOLS.test(ev.tool) || !(typeof ev.args.command === "string" || Array.isArray(ev.args.command))) return ev;
  const args = Object.fromEntries(Object.entries(ev.args).filter(([k, v]) => !(NOTES.includes(k) && typeof v === "string")));
  const dir = [args.cwd, args.workdir, args.directory, args.dir_path].find((d): d is string => typeof d === "string" && d.trim() !== "");
  return { ...ev, args, ...(dir ? { cwd: ev.cwd ? resolve(ev.cwd, dir) : dir } : {}) };
}
/**
 * The wire formats of agent hooks: several agents speak Claude Code's (Codex, Kimi Code, TRAE); opencode and MiMo Code have
 * no command hooks, so the plugin `kytral-guard init` writes for them sends {tool, args, cwd, sessionID} and blocks the call
 * unless the guard answers with exit code 0.
 */
type Dialect = "claude-code" | "cursor" | "gemini" | "copilot" | "windsurf" | "grok" | "plugin" | "cline" | "generic";
const DIALECT: Record<HookAgent, Dialect> = { "claude-code": "claude-code", codex: "claude-code", cursor: "cursor", gemini: "gemini", copilot: "copilot",
  windsurf: "windsurf", grok: "grok", kimi: "claude-code", trae: "claude-code", opencode: "plugin", mimo: "plugin",
  qwen: "claude-code", iflow: "claude-code", qoder: "claude-code", codebuddy: "claude-code",
  droid: "claude-code", auggie: "claude-code", devin: "claude-code", kiro: "claude-code", amp: "plugin", cline: "cline", generic: "generic" };
/** opencode's and MiMo Code's tools that only read or plan: their plugin skips them (a search for "rm -rf ~" is not a command). */
export const PLUGIN_READ_ONLY = ["glob", "grep", "list", "ls", "webfetch", "websearch", "codesearch", "todowrite", "todoread", "skill", "question", "task", "lsp", "invalid"];
/** Their tools; any other tool name is an MCP tool (server_tool) or a custom one. */
const PLUGIN_TOOLS = new Set(["bash", "edit", "write", "read", "multiedit", "apply_patch", "patch", ...PLUGIN_READ_ONLY]);
/** The Amp tools its plugin checks (its MCP tools are mcp__server__tool); the others run, as without a plugin. */
export const AMP_GUARDED = "^(Bash|shell_command|create_file|edit_file|apply_patch|undo_edit)$|^mcp__";
/** Cline's tools that only read, ask or report (the SDK's and the extension's names): no objection. */
const CLINE_NEUTRAL = new Set(["search_codebase", "fetch_web_content", "skills", "ask_question", "submit_and_exit", "list_files", "search_files",
  "list_code_definition_names", "ask_followup_question", "attempt_completion", "plan_mode_respond", "new_task", "load_mcp_documentation", "access_mcp_resource", "focus_chain"]);
/** A value Cline's extension sends as JSON text ("[\"rm -rf build\"]"), else the value itself. */
const unjson = (v: unknown) => { if (typeof v !== "string" || !/^\s*[\[{"]/.test(v)) return v; try { return JSON.parse(v); } catch { return v; } };
function parseAgentEvent(agent: HookAgent, raw: Record<string, unknown>): HookEvent | null {
  const info = obj(raw.tool_info);
  const roots = Array.isArray(raw.workspace_roots) ? raw.workspace_roots : Array.isArray(raw.workspaceRoots) ? raw.workspaceRoots : [];
  const base = { agent, cwd: str(raw.cwd) ?? str(info.cwd) ?? str(roots[0]),
    session: str(raw.session_id) ?? str(raw.conversation_id) ?? str(raw.sessionId) ?? str(raw.trajectory_id) ?? str(raw.taskId) };
  const ev = str(raw.hook_event_name);
  switch (DIALECT[agent]) {
    case "claude-code": {
      if (ev !== "PreToolUse") return null;
      if (typeof raw.tool_name !== "string") malformed("tool_name is not a string");
      const args = toolArgs(raw.tool_input);
      if (raw.tool_name === "apply_patch" && typeof args.command === "string") args.files = patchFiles(args.command);
      // MCP tools: tool_server for Auggie (is_mcp_tool), server___tool for Droid: the policy's MCP rules know them as mcp__…
      const mcp = (raw.is_mcp_tool === true || raw.tool_name.includes("___")) && !raw.tool_name.startsWith("mcp_");
      return { ...base, tool: mcp ? `mcp__${raw.tool_name}` : raw.tool_name, args, mode: str(raw.permission_mode), native: ev };
    }
    case "cursor": {
      // a command or path that is not text is a malformed event (refused), as a tool_name that is not a string elsewhere
      if (ev === "beforeShellExecution") { if (typeof raw.command !== "string") malformed("command is not a string"); return { ...base, tool: "Shell", args: { command: raw.command }, native: ev }; }
      if (ev === "beforeMCPExecution") return { ...base, tool: `mcp__${str(raw.mcp_server_name) ?? "unknown"}__${str(raw.tool_name) ?? "unknown"}`, args: jsonArgs(raw.tool_input), native: ev };
      if (ev === "beforeReadFile") { if (typeof raw.file_path !== "string") malformed("file_path is not a string"); return { ...base, tool: "Read", args: { file_path: raw.file_path }, native: ev }; }
      if (ev === "preToolUse") {
        if (typeof raw.tool_name !== "string") malformed("tool_name is not a string");
        const mcp = /^MCP:(.+)$/.exec(raw.tool_name);
        return { ...base, tool: mcp ? `mcp__cursor__${mcp[1]}` : raw.tool_name, args: toolArgs(raw.tool_input), native: ev };
      }
      return null;
    }
    case "gemini":
      if (ev !== "BeforeTool") return null;
      if (typeof raw.tool_name !== "string") malformed("tool_name is not a string");
      return { ...base, tool: raw.tool_name, args: toolArgs(raw.tool_input), native: ev };
    case "copilot":   // installed for preToolUse only: every event is a pre-tool event
      if (typeof raw.toolName !== "string") malformed("toolName is not a string");
      return { ...base, tool: raw.toolName, args: toolArgs(raw.toolArgs), native: "preToolUse" };
    case "windsurf": {
      const a = str(raw.agent_action_name);
      if (a === "pre_run_command") return { ...base, tool: "run_command", args: { command: str(info.command_line) ?? "" }, native: a };
      if (a === "pre_write_code") return { ...base, tool: "write_to_file", args: { file_path: str(info.file_path) ?? "" }, native: a };
      if (a === "pre_read_code") return { ...base, tool: "Read", args: { file_path: str(info.file_path) ?? "" }, native: a };
      if (a === "pre_mcp_tool_use") return { ...base, tool: `mcp__${str(info.mcp_server_name) ?? "unknown"}__${str(info.mcp_tool_name) ?? "unknown"}`, args: jsonArgs(info.mcp_tool_arguments), native: a };
      return null;
    }
    case "grok": {
      // "pre_tool_use" in the camelCase key (every build), "PreToolUse" in the snake_case alias (builds since 2026-08-28)
      const name = str(raw.hookEventName) ?? ev;
      if (name !== "pre_tool_use" && name !== "PreToolUse") return null;
      if (typeof raw.toolName !== "string") malformed("toolName is not a string");
      if (!GROK_TOOLS.test(raw.toolName)) return null;
      // MCP tools are named server__tool (built-in tools never hold "__"): the policy knows them as mcp__server__tool
      const tool = raw.toolName.includes("__") && !raw.toolName.startsWith("mcp__") ? `mcp__${raw.toolName}` : raw.toolName;
      const truncated = raw.toolInputTruncated === true;
      const args = truncated && typeof raw.toolInput === "string" ? truncatedArgs(raw.toolInput) : toolArgs(raw.toolInput);
      return { ...base, tool, args, mode: str(raw.permissionMode), native: ev ?? name, ...(truncated ? { truncated } : {}) };
    }
    case "plugin": {
      if (typeof raw.tool !== "string") malformed("tool is not a string");
      const t = raw.tool, amp = agent === "amp";
      if (amp ? !new RegExp(AMP_GUARDED).test(t) : PLUGIN_READ_ONLY.includes(t)) return null;
      const args = toolArgs(raw.args);
      if (t === "apply_patch" || t === "patch") { const p = str(args.patchText) ?? str(args.patch_text); if (p) args.files = patchFiles(p); }
      if (typeof args.cmd === "string" && args.command === undefined) { args.command = args.cmd; delete args.cmd; }   // Amp's Bash
      // opencode's MCP tools are named server_tool (one underscore): the policy's MCP rules know them as mcp__…
      return { ...base, tool: amp || t.startsWith("mcp__") || PLUGIN_TOOLS.has(t) ? t : `mcp__${t}`, args, session: str(raw.sessionID) ?? base.session };
    }
    case "cline": {
      if (raw.hookName !== "PreToolUse" && raw.hookName !== "tool_call") return null;
      // the SDK sends the call as it is (tool_call); the extension sends parameters as JSON text (preToolUse)
      const call = obj(raw.tool_call), pre = obj(raw.preToolUse);
      const name = str(call.name) ?? str(pre.toolName);
      if (!name) return malformed("no tool name");
      if (CLINE_NEUTRAL.has(name)) return null;
      let args: Record<string, unknown> = call.input !== undefined ? toolArgs(call.input) : Object.fromEntries(Object.entries(obj(pre.parameters)).map(([k, v]) => [k, unjson(v)]));
      let tool = name;
      if (name === "run_commands") {
        // a list of commands (strings or {command, args}), or one: analyzed as the lines of one script
        const list = Array.isArray(args.commands) ? args.commands : [args.commands ?? args.command ?? args.cmd ?? raw.tool_call];
        const lines = list.map(c => typeof c === "string" ? c : isObjLike(c) && typeof c.command === "string" ? [c.command, ...(Array.isArray(c.args) ? c.args.map(String) : [])].join(" ") : JSON.stringify(c));
        args = { command: lines.join("\n") };
      } else if (name === "use_mcp_tool") { tool = `mcp__${str(args.server_name) ?? "unknown"}__${str(args.tool_name) ?? "unknown"}`; args = toolArgs(unjson(args.arguments)); }
      else if (name.includes("__") && !name.startsWith("mcp__")) tool = `mcp__${name}`;
      if (name === "apply_patch") { const p = str(args.input) ?? str(args.patch); if (p) args.files = patchFiles(p); }
      return { ...base, tool, args, native: str(raw.hookName) };
    }
    case "generic": {
      if (typeof raw.tool === "string") return { ...base, tool: raw.tool, args: toolArgs(raw.args) };
      if (typeof raw.command === "string") return { ...base, tool: "shell", args: { command: raw.command } };
      // an agent's event that is not a pre-tool decision (AfterTool, SessionStart...) gets no objection
      if (typeof raw.hook_event_name === "string" || typeof raw.agent_action_name === "string") return null;
      return malformed('expected {"tool": "...", "args": {...}} or {"command": "..."}');
    }
  }
}

/** Claude-style agents whose hook answer may carry `continue: false` (the kill switch then also ends the agent's loop). */
const STOPS_LOOP = new Set<HookAgent>(["claude-code", "trae", "droid", "auggie"]);
/**
 * Agents whose hook can make a human confirm the call (elsewhere a confirmation is answered with a refusal). Kimi Code
 * reads any decision but "deny" as an approval, and opencode's plugins cannot ask.
 */
const CAN_ASK: Record<HookAgent, boolean> = { "claude-code": true, cursor: true, codex: false, gemini: false, copilot: true, windsurf: false, grok: true,
  kimi: false, trae: true, opencode: false, mimo: false, qwen: true, iflow: false, qoder: true, codebuddy: true,
  // Droid and Auggie ignore an "ask"; Kiro approves it in headless runs with --trust-all-tools; Devin does not document it;
  // Amp's plugin asks the user itself (ctx.ui.confirm); Cline's hooks cannot ask
  droid: false, auggie: false, devin: false, kiro: false, amp: true, cline: false, generic: true };
/**
 * Does the agent show the human a prompt for this event? Not in bypassPermissions / dontAsk, nor for Cursor's preToolUse
 * (ask is not enforced there), nor in Grok Build before its 2026-08-28 builds (the first to send the snake_case aliases,
 * hook_event_name "PreToolUse"): older builds count "ask" as a failed hook and run the tool.
 */
export function canAsk(ev: HookEvent | null, agent: HookAgent): boolean {
  return CAN_ASK[agent] && !(ev?.mode && /^(bypassPermissions|dontAsk)$/.test(ev.mode)) && !(agent === "cursor" && ev?.native === "preToolUse")
    && !(agent === "grok" && ev?.native !== "PreToolUse");
}
/** The final outcome of a verdict for this agent: allow, ask (a human confirms in the agent) or deny. */
export function outcome(ev: HookEvent | null, v: HookVerdict, agent: HookAgent): "allow" | "ask" | "deny" {
  return v.action === "allow" ? "allow" : v.action === "confirm" && canAsk(ev, agent) ? "ask" : "deny";
}
const clip = (s: string, n = 900) => (s.length > n ? s.slice(0, n) + "…" : s);
/** "rm -r ~ (rule shell-catastrophic)" from a policy decision's reason "matched rule 'shell-catastrophic': rm -r ~". */
export function explain(v: Decision): string {
  const m = /^matched rule '([^']*)'(?:: ([\s\S]*))?$/.exec(v.reason);
  return m ? (m[2] ? `${m[2]} (rule ${m[1]})` : `rule ${m[1]}`) : v.reason;
}

/** The answer in the agent's wire format. A refusal always also exits 2 where that blocks (Claude Code, Codex, Gemini, Copilot, Windsurf, Grok Build). */
export function renderHookAnswer(ev: HookEvent | null, v: HookVerdict, agent: HookAgent): HookAnswer {
  const out = outcome(ev, v, agent);
  // A confirmation of one shell command says how the user can stop being asked for it (never for a block: a catastrophe
  // is not something to allow in one keystroke, and agents cannot run 'kytral-guard allow' themselves).
  // The line to paste names the kept call (no quoting at all), else quotes the command for a POSIX shell when no shell can
  // read it differently (fish reads \' inside single quotes; cmd.exe and PowerShell have other rules: none on Windows).
  const command = typeof ev?.args?.command === "string" ? ev.args.command.trim() : "";
  const line = v.call !== undefined && isShellTool(ev?.tool ?? "") ? `kytral-guard allow --call ${v.call}`
    : process.platform !== "win32" && !command.includes("\\") && !HIDDEN_CHARACTERS.test(command) ? `kytral-guard allow '${command.replace(/'/g, "'\\''")}'` : null;
  const allowHint = v.action === "confirm" && !v.killed && command && command.length <= 300 && !/[\r\n]/.test(command)
    ? line ? ` The user can allow this exact command from now on by running, in their own terminal: ${line}` : " The user can allow this exact command from now on with kytral-guard allow, in their own terminal." : "";
  const reason = clip(v.killed === "plugin" ? `Kytral Guard refuses every tool call: ${v.reason}.`
    : v.killed ? `${v.reason === "kill switch active" ? "Kytral Guard: every agent is stopped (kill switch)" : `Kytral Guard kill switch: ${v.reason}`}. Every tool call is refused until a human resumes them: kytral-guard resume, or Resume in the dashboard.`
    : out === "ask" ? `Kytral Guard asks for confirmation: ${explain(v)}. Approve only if this is what you want.${allowHint}`
    : v.action === "confirm" ? `Kytral Guard needs a human to confirm this call: ${explain(v)}, and nobody can be asked here. Ask the user to run it.${allowHint}`
    : `Kytral Guard blocked this call: ${explain(v)}. Do not try to work around the block; tell the user what you wanted to do.`);
  const none: HookAnswer = { stdout: "", stderr: "", exitCode: 0 };
  switch (DIALECT[agent]) {
    case "claude-code": {
      if (out === "allow") return none;
      // iFlow reads only a top-level decision (block / approve) and ignores the rest
      if (agent === "iflow") return { stdout: JSON.stringify({ decision: "block", reason }), stderr: reason, exitCode: 2 };
      const body: Record<string, unknown> = { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: out, permissionDecisionReason: reason } };
      if (v.killed && STOPS_LOOP.has(agent)) Object.assign(body, { continue: false, stopReason: reason });   // Codex fails on fields it does not support
      if (agent === "codebuddy") body.reason = reason;   // the message CodeBuddy shows
      // Qwen Code: a refusal by exit code 2 loses to another hook's JSON "allow"; a JSON "deny" wins over it
      return { stdout: JSON.stringify(body), stderr: out === "deny" && agent !== "qwen" ? reason : "", exitCode: out === "deny" && agent !== "qwen" ? 2 : 0 };
    }
    case "cursor": return { stdout: JSON.stringify(out === "allow" ? { permission: "allow" } : { permission: out, user_message: reason, agent_message: reason }), stderr: "", exitCode: 0 };
    case "gemini": return out === "allow" ? none : { stdout: JSON.stringify({ decision: "deny", reason }), stderr: reason, exitCode: 2 };
    case "copilot":
      if (out === "allow") return none;
      return { stdout: JSON.stringify({ permissionDecision: out, permissionDecisionReason: reason }), stderr: out === "deny" ? reason : "", exitCode: out === "deny" ? 2 : 0 };
    case "windsurf": return out === "allow" ? none : { stdout: "", stderr: reason, exitCode: 2 };
    // the plugin lets the call run only on exit code 0, and gives the agent stderr as the reason; 3: it asks the user (Amp)
    case "plugin": return out === "allow" ? none : { stdout: JSON.stringify({ decision: out, reason }), stderr: reason, exitCode: out === "ask" ? 3 : 2 };
    // Cline: cancel stops the task (its hooks cannot refuse one call only)
    case "cline": return out === "allow" ? none : { stdout: JSON.stringify({ cancel: true, errorMessage: reason }), stderr: "", exitCode: 0 };
    case "grok": {
      if (out === "allow") return none;
      // "decision" for the builds before 2026-08-28, hookSpecificOutput for the later ones (it wins there); exit 2 refuses in both
      const body: Record<string, unknown> = { decision: out, reason, hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: out, permissionDecisionReason: reason } };
      if (v.killed) Object.assign(body, { continue: false, stopReason: reason });
      return { stdout: JSON.stringify(body), stderr: out === "deny" ? reason : "", exitCode: out === "deny" ? 2 : 0 };
    }
    case "generic": return { stdout: JSON.stringify({ action: v.action, ...(v.rule ? { rule: v.rule } : {}), reason: v.reason, ...(v.killed ? { killed: true } : {}) }) + "\n", stderr: "", exitCode: v.action === "allow" ? 0 : v.action === "confirm" ? 3 : 2 };
  }
}

/** Policy for hooks: --policy file, else $KYTRAL_POLICY, else $KYTRAL_HOME/policy.yaml, else the coding-agent preset (or --preset). */
export function loadHookPolicy(o: { policyFile?: string; preset?: string } = {}): { policy: Policy; source: string } {
  if (o.policyFile) return { policy: policyFromFile(o.policyFile), source: o.policyFile };
  if (o.preset) return { policy: presetPolicy(o.preset), source: `preset ${o.preset}` };
  if (process.env.KYTRAL_POLICY) return { policy: policyFromFile(process.env.KYTRAL_POLICY), source: process.env.KYTRAL_POLICY };
  const user = statePath(undefined, "policy.yaml");
  if (existsSync(user)) return { policy: policyFromFile(user), source: user };
  return { policy: presetPolicy("coding-agent"), source: "preset coding-agent" };
}
/**
 * A hook policy file that cannot be read or does not load. Its message names the file and repeats the parser's, for the
 * user's own terminal (check, doctor, policy show); `fixed` says why from a fixed list, without the path or a word of the
 * file (YAML's errors quote the line at fault, which may hold a secret): what a hook answers its agent, which the agent and
 * its model read.
 */
export class HookPolicyError extends Error {
  constructor(message: string, readonly fixed: string) { super(message); }
}
/** An error as its code (ENOENT, EACCES...): Node's message repeats the path. */
const errCode = (e: unknown) => { const c = (e as NodeJS.ErrnoException)?.code; return typeof c === "string" && /^[A-Z][A-Z0-9_]{1,39}$/.test(c) ? c : "error"; };
const SEE_DOCTOR = "'kytral-guard doctor' says which file and why";
/** A policy file; its errors name the file (a YAML or rule error alone does not say which file to fix). */
function policyFromFile(file: string): Policy {
  let text: string;
  try { text = readRegular(file).toString("utf8"); }   // never waits: a FIFO in its place is refused, not opened
  catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    throw new HookPolicyError(code === "ENOENT" ? `${file}: no such file` : code === "EISDIR" ? `${file} is a folder, not a file` : e instanceof NotRegularFile ? e.message : `${file}: ${(e as Error).message}`,
      `the hook policy cannot be read (${errCode(e)}): ${SEE_DOCTOR}`);
  }
  try { return loadPolicy(text); }
  catch (e) { throw new HookPolicyError(`${file}: ${(e as Error).message}`, `the hook policy is not a valid policy (${policyProblem(e)}): ${SEE_DOCTOR}`); }
}

export interface HookGuardOptions {
  policy?: Policy; policyFile?: string; preset?: string;
  /** Deployment secret (audit HMAC, kill switch signatures). Default: KYTRAL_SECRET, else $KYTRAL_HOME/secret, created if missing. */
  secret?: string;
  /** null: no audit. Default: $KYTRAL_AUDIT or $KYTRAL_HOME/audit.jsonl, HMAC-chained. */
  audit?: AuditLog | null;
  killSwitchFile?: string;
  /** Loaded plugins (loadPlugins()): central policy, extra kill switch, remote approvals, copies of decisions and audit entries. */
  plugins?: KytralPlugin[];
}
/** The decision engine behind every hook: the shared kill switch first, then the policy; every outcome is journaled. */
export class HookGuard {
  readonly policy: Policy; readonly audit: AuditLog | null; readonly plugins: KytralPlugin[]; private killSwitch: KillSwitch; private readonly secret: string;
  constructor(o: HookGuardOptions = {}) {
    this.plugins = o.plugins ?? [];
    this.policy = o.policy ?? pluginPolicy(this.plugins, "hook") ?? loadHookPolicy(o).policy;
    const secret = this.secret = assertStrongSecret(o.secret ?? resolveSecret({ create: true }));
    this.audit = o.audit === null ? null : o.audit ?? new AuditLog(statePath(process.env.KYTRAL_AUDIT, "audit.jsonl"), { key: auditKey(secret) });
    if (this.audit && this.plugins.length) this.audit.sinks.push(e => notifyPlugins(this.plugins, "onAudit", e));
    // A hook is a new process at each call, with no memory of the states seen before: it starts from the last kill or resume
    // the journal records (its signed tail marker, read under the log's lock: startingSwitch), so that kill-switch.json
    // deleted, or an older resume put back, does not lift a kill. A journal that cannot be read refuses the call (fail closed).
    const ksFile = o.killSwitchFile ?? killSwitchPath();
    this.killSwitch = new KillSwitch(ksFile, killSwitchKey(secret),
      why => this.audit?.append({ agentId: "unknown", tool: "-", decision: "kill-switch-invalid", rule: why.slice(0, 200) }), startingSwitch(secret, ksFile, this.audit));
  }
  /** The verdict, synchronously: the analysis runs in a reused worker thread with a deadline (evaluate-bounded.ts). */
  decide(ev: HookEvent): HookVerdict {
    const killed = this.killed(); if (killed) return killed;
    return partial(ev, evaluateSyncBounded(this.policy, { tool: ev.tool, args: ev.args, cwd: ev.cwd }));
  }
  /**
   * decide(), with a deadline: the call is analyzed in a worker thread stopped after `timeoutMs` (KYTRAL_ANALYSIS_TIMEOUT_MS,
   * default 8 s). A call that cannot be analyzed in time needs a human: a guard that runs past the agent's hook timeout
   * fails open, since most agents then run the tool. (decide() waits for a reused thread; this one starts its own, which
   * the agent's hook command starts ahead of time, see prewarmAnalysis.)
   */
  async decideAsync(ev: HookEvent, timeoutMs = Number(process.env.KYTRAL_ANALYSIS_TIMEOUT_MS) || 8000): Promise<HookVerdict> {
    const killed = this.killed(); if (killed) return killed;
    return partial(ev, await evaluateBounded(this.policy, { tool: ev.tool, args: ev.args, cwd: ev.cwd }, timeoutMs));
  }
  /**
   * A confirmation nobody can answer in the agent (it cannot show a prompt, or runs without prompts), put to the dashboard
   * of this machine while one is open (the confirmation queue, nobodyToAsk). The human's verdict, or null when there is none
   * (no dashboard, no answer in time, kill switch, invalid answer): the call is then refused as before.
   */
  async askDashboard(ev: HookEvent, v: HookVerdict, timeoutMs: number): Promise<{ allow: boolean; approver: string } | null> {
    if (nobodyToAsk()) return null;
    let q: FileConfirmQueue;
    try { q = new FileConfirmQueue({ secret: this.secret, timeoutMs: Math.max(1000, Math.round(timeoutMs)) }); } catch { return null; }
    const a = await q.ask({ server: ev.cwd ?? "", agentId: ev.agent, tool: ev.tool, rule: v.rule ?? "", reason: v.reason, args: ev.args, always: false }, () => this.killed() !== null);
    if (a.problem || !a.approver) return null;
    // the approver as the queue names it: "alice (dashboard)" from the page, "alice (os:alice)" from `kytral-guard confirm`
    return { allow: a.verdict !== "deny", approver: a.approver };
  }
  private killed(): HookVerdict | null {
    const local = this.killSwitch.check();   // first: wins over every rule
    if (local) return { action: "block", rule: "kill-switch", reason: local, killed: true };
    const remote = pluginKillReason(this.plugins);
    return remote ? { action: "block", rule: "kill-switch", reason: remote, killed: "plugin" } : null;
  }
  /**
   * Journals the final outcome (allow / ask / block, or confirmed by a remote approver), with the rule and its finding, never
   * the arguments. The text of a call that was refused, asked or confirmed is kept apart for the dashboard (masked; keepCalls).
   */
  /** Returns the number of the kept call when its text is the exact command (`kytral-guard allow --call` takes it). */
  journal(ev: HookEvent, v: HookVerdict, final: "allow" | "ask" | "deny", approver?: string): number | undefined {
    if (!this.audit || (final === "allow" && !approver && !auditAllowsEnabled())) return undefined;
    const e = this.audit.append({ agentId: ev.agent, tool: ev.tool, decision: approver ? (final === "allow" ? "confirmed" : "block") : final === "deny" ? "block" : final,
      ...(v.rule ? { rule: v.rule } : {}), ...(final === "allow" && !approver ? {} : { reason: v.reason.slice(0, 300) }), ...(ev.cwd ? { server: ev.cwd } : {}),
      ...(approver ? { approver } : {}) });
    if ((final === "allow" && !approver) || !keepCallsEnabled()) return undefined;
    const k = keepCall({ seq: e.seq, ts: e.ts, agent: ev.agent, tool: ev.tool, decision: e.decision, rule: v.rule, reason: v.reason, args: ev.args, cwd: ev.cwd }, this.secret);
    return k?.seq !== undefined && exactText(k.text) ? k.seq : undefined;
  }
}

const limitVerdict = (what: string): HookVerdict => ({ action: "confirm", rule: "analysis-limit", reason: `matched rule 'analysis-limit': ${what}` });
const tooLarge = (args: Record<string, unknown>) => limitVerdict(`the call is too large to analyze (${Math.round(argsSize(args) / 1024)} KB)`);
/** A call the agent cut: what was analyzed can block it, but nothing vouches for the missing part, so a human confirms. */
const partial = (ev: HookEvent, v: HookVerdict): HookVerdict =>
  ev.truncated && v.action !== "block" ? limitVerdict("the agent sent only the beginning of the call (it was too large), so the rest cannot be analyzed") : v;
const workerUrl = () => new URL(import.meta.url.endsWith(".ts") ? "./analysis-worker.ts" : "./analysis-worker.js", import.meta.url);
const WORKER_LIMITS = { maxOldGenerationSizeMb: 512 };
let warm: Worker | undefined;
/** A thread the command's entry point (cli-entry.ts) started before loading the CLI. */
const ENTRY_WORKER = Symbol.for("kytral-guard.analysis-worker");
/**
 * Starts the analysis thread ahead of time, or takes the one the entry point started: its start-up (most of a hook's own
 * cost) then overlaps loading the CLI and reading the event, the policy and the state, and the next evaluateBounded uses it.
 * It does not keep a process alive that ends without it.
 */
export function prewarmAnalysis(): void {
  if (warm) return;
  const g = globalThis as Record<symbol, unknown>, started = g[ENTRY_WORKER];
  delete g[ENTRY_WORKER];
  try {
    const w = started instanceof Worker ? started : new Worker(workerUrl(), { workerData: null, execArgv: workerExecArgv(), resourceLimits: WORKER_LIMITS });
    const drop = () => { if (warm === w) warm = undefined; };
    w.unref(); w.once("error", drop); w.once("exit", drop);
    warm = w;
  } catch { warm = undefined; }
}
/**
 * evaluate() in a worker thread with a deadline. Whatever the size of the call: a few dozen characters of SQL can make a
 * parser backtrack for minutes, and so can a slow regular expression in a custom policy. Costs about 40 ms.
 */
export function evaluateBounded(policy: Policy, call: { tool: string; args: Record<string, unknown>; cwd?: string }, timeoutMs: number): Promise<HookVerdict> {
  const size = argsSize(call.args);
  if (size > MAX_ANALYSIS_BYTES) return Promise.resolve(tooLarge(call.args));
  return new Promise(resolve => {
    let done = false;
    const end = (v: HookVerdict) => { if (done) return; done = true; clearTimeout(timer); void worker.terminate(); resolve(v); };
    const ready = warm; warm = undefined;
    const worker = ready ?? new Worker(workerUrl(), { workerData: { policy, call }, execArgv: workerExecArgv(), resourceLimits: WORKER_LIMITS });
    if (ready) { ready.ref(); ready.postMessage({ policy, call }); }
    const timer = setTimeout(() => end(limitVerdict(`the call could not be analyzed within ${Math.round(timeoutMs / 1000)} s (${Math.round(size / 1024)} KB)`)), timeoutMs);
    worker.once("message", (d: HookVerdict) => end(d && typeof d.action === "string" ? d : limitVerdict("the analysis returned nothing")));
    worker.once("error", e => end(limitVerdict(`the analysis failed (${e.message})`)));
    worker.once("exit", code => end(limitVerdict(`the analysis stopped (exit ${code})`)));
  });
}

/** matchingRules() in a worker thread with a deadline: every rule that matches the call, or null when it could not be told in time. */
export function matchingRulesBounded(policy: Policy, call: { tool: string; args: Record<string, unknown>; cwd?: string }, timeoutMs: number): Promise<Decision[] | null> {
  if (argsSize(call.args) > MAX_ANALYSIS_BYTES) return Promise.resolve(null);
  return new Promise(resolve => {
    let done = false;
    const end = (v: Decision[] | null) => { if (done) return; done = true; clearTimeout(timer); void worker.terminate(); resolve(v); };
    const worker = new Worker(workerUrl(), { workerData: { policy, call, all: true }, execArgv: workerExecArgv(), resourceLimits: WORKER_LIMITS });
    const timer = setTimeout(() => end(null), timeoutMs);
    worker.once("message", (d: { all?: Decision[] }) => end(Array.isArray(d?.all) ? d.all : null));
    worker.once("error", () => end(null));
    worker.once("exit", () => end(null));
  });
}

const NO_OBJECTION = (agent: HookAgent): HookAnswer => agent === "cursor" ? { stdout: JSON.stringify({ permission: "allow" }), stderr: "", exitCode: 0 } : { stdout: "", stderr: "", exitCode: 0 };
/** A refusal that says why the guard could not decide; a policy that does not load in fixed words (HookPolicyError), never its path or its text. */
const failClosed = (agent: HookAgent, e: unknown): HookAnswer =>
  renderHookAnswer(null, { action: "block", rule: "hook-error", reason: `refused because the guard could not decide (fail closed): ${e instanceof HookPolicyError ? e.fixed : (e as Error).message}` }, agent);
/** How long a hook waits for a remote verdict: explicit, KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS, config.json, else what is left of 20 s. */
export function remoteConfirmTimeoutMs(explicit: number | undefined, started = Date.now()): number {
  if (explicit !== undefined && Number.isFinite(explicit) && explicit > 0) return explicit;
  const env = Number(process.env.KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS);
  if (Number.isFinite(env) && env > 0) return env;
  const cfg = guardConfig().remoteConfirmTimeoutSeconds;
  if (cfg) return cfg * 1000;
  return Math.max(1000, 20_000 - (Date.now() - started));
}
/**
 * Reads one event and the agent that answers it: the one named, else detected. Grok Build also runs the hooks of Claude Code
 * and Cursor it finds, with its own event shape and answer vocabulary: its events are read and answered as Grok's, whatever
 * agent the hook command names. The tool call is parsed next (parseHookEvent), in the agent's format for any refusal.
 */
function readEvent(agentArg: string | undefined, input: string): { agent: HookAgent; raw: Record<string, unknown> } {
  if (agentArg && agentArg !== "auto" && !isHookAgent(agentArg)) throw new Error(`unknown agent '${agentArg}' (${HOOK_AGENTS.join(", ")}, auto)`);
  // a byte order mark (Windows PowerShell pipes add one) is not part of the event
  let raw: unknown; try { raw = JSON.parse(input.replace(/^\ufeff/, "")); } catch { throw new Error("the event on stdin is not JSON"); }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("the event on stdin is not a JSON object");
  const r = raw as Record<string, unknown>;
  return { agent: isGrokEvent(r) ? "grok" : !agentArg || agentArg === "auto" ? detectAgent(r) : agentArg as HookAgent, raw: r };
}
/** Journals (an allow that cannot be journaled is refused), tells plugins, and renders the answer. */
function finish(guard: HookGuard, ev: HookEvent, v: HookVerdict, agent: HookAgent, final: "allow" | "ask" | "deny", approver?: string): HookAnswer {
  let call: number | undefined;
  try { call = guard.journal(ev, v, final, approver); }
  catch (e) { if (final === "allow") throw new Error(`the audit log cannot be written (${(e as Error).message})`); }   // no unjournaled allow
  notifyPlugins(guard.plugins, "onDecision", { source: "hook", agent: ev.agent, tool: ev.tool, args: ev.args, rule: v.rule, reason: v.reason, cwd: ev.cwd, session: ev.session,
    action: v.action, outcome: approver && final === "allow" ? "confirmed" : final });
  // The final outcome decides the answer: a remote approval allows a "confirm", a remote refusal blocks it.
  return renderHookAnswer(ev, final === "allow" ? { ...v, action: "allow" } : final === "deny" && v.action !== "confirm" || approver ? { ...v, action: "block" } : { ...v, call }, agent);
}

/**
 * Runs one hook invocation: `agentArg` is an agent name or "auto" (detected from the event's shape). Never throws: any error
 * is a refusal in the agent's format (fail closed). Synchronous: plugins can refuse (kill switch) and observe, but not
 * answer confirmations; runHookAsync does.
 */
export function runHook(agentArg: string | undefined, input: string, o: HookGuardOptions = {}): HookAnswer {
  let agent: HookAgent = agentArg && isHookAgent(agentArg) ? agentArg : "generic";
  try {
    const r = readEvent(agentArg, input); agent = r.agent;
    const ev = parseHookEvent(agent, r.raw);
    if (!ev) return NO_OBJECTION(agent);
    const guard = new HookGuard(o), v = guard.decide(ev);
    return finish(guard, ev, v, agent, outcome(ev, v, agent));
  } catch (e) { return failClosed(agent, e); }
}
/**
 * runHook, plus remote approvals and a deadline on the analysis of large calls (decideAsync). A confirmation is first
 * offered to the plugins (Slack, a web page, an on-call approver), waiting at most `remoteConfirmTimeoutMs`
 * (KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS, else "remoteConfirmTimeoutSeconds" in $KYTRAL_HOME/config.json, else what is left of
 * 20 s); without a verdict the agent asks locally, or the call is refused. Keep the agent's hook timeout above it
 * ('kytral-guard init <agent> --timeout <seconds>'). Plugins are flushed before it returns.
 */
export async function runHookAsync(agentArg: string | undefined, input: string, o: HookGuardOptions & { remoteConfirmTimeoutMs?: number; hookTimeoutMs?: number; loadPlugins?: () => Promise<KytralPlugin[]> } = {}): Promise<HookAnswer> {
  const started = Date.now();
  let agent: HookAgent = agentArg && isHookAgent(agentArg) ? agentArg : "generic"; let guard: HookGuard | undefined;
  try {
    const r = readEvent(agentArg, input); agent = r.agent;
    const ev = parseHookEvent(agent, r.raw);
    if (!ev) return NO_OBJECTION(agent);
    guard = new HookGuard(o.loadPlugins ? { ...o, plugins: await o.loadPlugins() } : o);   // a plugin that does not load refuses (fail closed)
    // the agent's hook timeout (when the installed command gives it) bounds every wait, with 3 s left to answer and exit
    const budget = o.hookTimeoutMs ? (ms: number) => Math.max(1000, Math.min(ms, o.hookTimeoutMs! - (Date.now() - started) - 3000)) : (ms: number) => ms;
    const v = await guard.decideAsync(ev, budget(Number(process.env.KYTRAL_ANALYSIS_TIMEOUT_MS) || 8000));
    const final = outcome(ev, v, agent);
    if (v.action === "confirm" && guard.plugins.some(p => p.confirm)) {
      const wait = budget(remoteConfirmTimeoutMs(o.remoteConfirmTimeoutMs, started));
      const answer = await pluginConfirm(guard.plugins, { source: "hook", agent, tool: ev.tool, args: ev.args, rule: v.rule, reason: v.reason, cwd: ev.cwd,
        session: ev.session, localPrompt: final === "ask", timeoutMs: wait }, wait);
      if (answer) {
        const who = `${answer.approver ?? "unidentified"} (via ${answer.plugin})`;
        const verdict: HookVerdict = { ...v, reason: `${v.reason}; ${answer.verdict === "allow" ? "approved" : "refused"} by ${who}${answer.note ? `: ${answer.note}` : ""}` };
        return finish(guard, ev, verdict, agent, answer.verdict === "allow" ? "allow" : "deny", who);
      }
    }
    // Nobody can answer in the agent: an open dashboard can (within what is left of the remote approval time)
    if (v.action === "confirm" && final === "deny") {
      const a = await guard.askDashboard(ev, v, budget(remoteConfirmTimeoutMs(o.remoteConfirmTimeoutMs, started)));
      if (a) return finish(guard, ev, { ...v, reason: `${v.reason}; ${a.allow ? "approved" : "refused"} by ${a.approver}` }, agent, a.allow ? "allow" : "deny", a.approver);
    }
    return finish(guard, ev, v, agent, final);
  } catch (e) { return failClosed(agent, e); }
  finally { if (guard) await flushPlugins(guard.plugins); }
}
