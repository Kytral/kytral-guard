// `kytral-guard init <agent>` / `kytral-guard uninstall <agent>`: adds or removes the Kytral Guard pre-tool hook in an agent's
// configuration file. The file is merged, never replaced: other settings and hooks are kept, a backup of the previous file is
// written next to it, and a file that does not parse is left untouched. Installing twice replaces the previous Kytral entry.
// Hooks run the CLI by absolute paths (node and cli.js), so neither PATH nor a shell profile can change what runs, and they
// are set to fail closed where the agent supports it (Claude Code onFailure, Cursor failClosed).
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AMP_GUARDED, GROK_HOOK_MATCHER, PLUGIN_READ_ONLY } from "./hooks.js";

export const INSTALL_AGENTS = ["claude-code", "cursor", "codex", "gemini", "copilot", "windsurf", "grok", "kimi", "trae", "trae-cn", "opencode", "mimo",
  "qwen", "iflow", "qoder", "codebuddy", "droid", "auggie", "devin", "kiro", "amp", "cline"] as const;
export type InstallAgent = typeof INSTALL_AGENTS[number];
export const isInstallAgent = (a: string): a is InstallAgent => (INSTALL_AGENTS as readonly string[]).includes(a);
/** Each agent's name, and the folder of the home directory that says it is installed. */
export const AGENTS: Record<InstallAgent, { name: string; dir: string }> = {
  "claude-code": { name: "Claude Code", dir: ".claude" }, cursor: { name: "Cursor", dir: ".cursor" }, codex: { name: "Codex", dir: ".codex" },
  gemini: { name: "Gemini CLI", dir: ".gemini" }, copilot: { name: "Copilot CLI", dir: ".copilot" },
  windsurf: { name: "Windsurf", dir: join(".codeium", "windsurf") }, grok: { name: "Grok Build", dir: ".grok" },
  kimi: { name: "Kimi Code", dir: ".kimi-code" }, trae: { name: "TRAE", dir: ".trae" }, "trae-cn": { name: "TRAE CN", dir: ".trae-cn" },
  opencode: { name: "opencode", dir: join(".config", "opencode") }, mimo: { name: "MiMo Code", dir: join(".config", "mimocode") },
  qwen: { name: "Qwen Code", dir: ".qwen" }, iflow: { name: "iFlow CLI", dir: ".iflow" }, qoder: { name: "Qoder CLI", dir: ".qoder" },
  codebuddy: { name: "CodeBuddy Code", dir: ".codebuddy" }, droid: { name: "Factory Droid", dir: ".factory" }, auggie: { name: "Augment Auggie", dir: ".augment" },
  devin: { name: "Devin CLI", dir: process.platform === "win32" ? join("AppData", "Roaming", "devin") : join(".config", "devin") },
  kiro: { name: "Kiro CLI", dir: ".kiro" }, amp: { name: "Amp", dir: join(".config", "amp") }, cline: { name: "Cline", dir: join("Documents", "Cline") },
};
/** The `hook <agent>` each target answers as (TRAE CN speaks TRAE's format). */
const HOOK_AGENT: Partial<Record<InstallAgent, string>> = { "trae-cn": "trae" };
/**
 * How the hook is written: merged into a JSON file (default; Droid's hooks.json holds the events at its top level), an entry
 * of a TOML file, or a file of Kytral's own: a plugin, a hook file (Kiro), a hook script (Cline).
 */
const FORMAT: Partial<Record<InstallAgent, "toml" | "own">> = { kimi: "toml", opencode: "own", mimo: "own", kiro: "own", amp: "own", cline: "own" };
const FLAT = new Set<InstallAgent>(["droid"]);
/** The agents whose configuration folder exists in this home directory. */
export function detectAgents(home = homedir()): InstallAgent[] {
  return INSTALL_AGENTS.filter(a => existsSync(join(home, AGENTS[a].dir)));
}
export interface InstallOptions {
  /** Install in this project directory instead of the user's configuration. */
  project?: string;
  /** Absolute path of the CLI entry point (default: this package's dist/cli.js) and of node (default: this process's). */
  cliPath?: string; nodePath?: string;
  /** Home directory (tests). */
  home?: string;
  dryRun?: boolean;
  /** Seconds the agent waits for the guard (default 30). Raise it for remote approvals (Kytral Guard Pro), which wait for a human. */
  timeoutSeconds?: number;
}
export interface InstallResult { agent: InstallAgent; file: string; changed: boolean; backup?: string; content: string; notes: string[] }

/** This package's CLI entry point (dist/cli.js next to this module). */
export const defaultCliPath = () => fileURLToPath(new URL("./cli.js", import.meta.url));
/** Hook configurations of each agent, user-level or project-level. */
export function configFile(agent: InstallAgent, o: InstallOptions = {}): string {
  const home = o.home ?? homedir(), p = o.project ? resolve(o.project) : undefined;
  const env = (k: string) => (o.home ? undefined : process.env[k] || undefined);   // the agents' own overrides, for the real home only
  switch (agent) {
    // Kimi Code has no project hooks: always the user's file
    case "kimi": return join(env("KIMI_CODE_HOME") ?? join(home, ".kimi-code"), "config.toml");
    case "trae": return join(p ?? home, ".trae", "hooks.json");
    case "trae-cn": return p ? join(p, ".trae", "hooks.json") : join(home, ".trae-cn", "hooks.json");
    case "opencode": return p ? join(p, ".opencode", "plugins", "kytral-guard.js") : join(env("XDG_CONFIG_HOME") ?? join(home, ".config"), "opencode", "plugins", "kytral-guard.js");
    case "mimo": {
      const mimoHome = env("MIMOCODE_HOME");
      return p ? join(p, ".mimocode", "plugins", "kytral-guard.js") : join(mimoHome ? join(mimoHome, "config") : join(home, ".config", "mimocode"), "plugins", "kytral-guard.js");
    }
    case "qwen": return p ? join(p, ".qwen", "settings.json") : join(env("QWEN_HOME") ?? join(home, ".qwen"), "settings.json");
    case "iflow": return join(p ?? home, ".iflow", "settings.json");
    // project installs go to the local file, like Claude Code's: it holds this machine's paths and is not committed
    case "qoder": return p ? join(p, ".qoder", "settings.local.json") : join(env("QODER_CONFIG_DIR") ?? join(home, ".qoder"), "settings.json");
    case "codebuddy": return p ? join(p, ".codebuddy", "settings.local.json") : join(home, ".codebuddy", "settings.json");
    case "droid": return join(p ?? home, ".factory", "hooks.json");
    case "auggie": return p ? join(p, ".augment", "settings.local.json") : join(home, ".augment", "settings.json");
    case "devin": return p ? join(p, ".devin", "config.local.json")
      : join(process.platform === "win32" ? env("APPDATA") ?? join(home, "AppData", "Roaming") : env("XDG_CONFIG_HOME") ?? join(home, ".config"), "devin", "config.json");
    case "kiro": return join(p ?? home, ".kiro", "hooks", "kytral-guard.json");
    case "amp": return p ? join(p, ".amp", "plugins", "kytral-guard.js") : join(env("XDG_CONFIG_HOME") ?? join(home, ".config"), "amp", "plugins", "kytral-guard.js");
    // one hook file per event, run with no arguments: a script of Kytral's own (PowerShell on Windows)
    case "cline": return join(p ? join(p, ".clinerules", "hooks") : join(home, "Documents", "Cline", "Hooks"), process.platform === "win32" ? "PreToolUse.ps1" : "PreToolUse");
    case "claude-code": return p ? join(p, ".claude", "settings.local.json") : join(home, ".claude", "settings.json");
    case "cursor": return join(p ?? home, ".cursor", "hooks.json");
    case "codex": return join(p ?? home, ".codex", "hooks.json");
    case "gemini": return join(p ?? home, ".gemini", "settings.json");
    case "copilot": return p ? join(p, ".github", "hooks", "kytral-guard.json") : join(home, ".copilot", "hooks", "kytral-guard.json");
    case "windsurf": return p ? join(p, ".windsurf", "hooks.json") : join(home, ".codeium", "windsurf", "hooks.json");
    case "grok": return join(p ?? home, ".grok", "hooks", "kytral-guard.json");
  }
}

const posixQuote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
const psQuote = (s: string) => `'${s.replace(/'/g, "''")}'`;
interface Cmd { node: string; cli: string; agent: string; timeout: number }
/** Shell command for agents that run hooks through a shell: absolute paths, quoted for sh; on Windows, node from PATH and a forward-slash script path (valid in cmd, PowerShell and Git Bash). */
function shellCommand(c: Cmd, platform = process.platform): string {
  return platform === "win32" ? `node "${c.cli.replace(/\\/g, "/")}" hook ${c.agent} --timeout ${c.timeout}` : `${posixQuote(c.node)} ${posixQuote(c.cli)} hook ${c.agent} --timeout ${c.timeout}`;
}
const powershellCommand = (c: Cmd) => `& ${psQuote(c.node)} ${psQuote(c.cli)} hook ${c.agent} --timeout ${c.timeout}`;

/** A hook handler written by Kytral Guard (any version): it mentions kytral and runs the `hook` subcommand. */
/** A Kytral Guard handler: it runs "… hook <agent>" from a path naming kytral, or from a copy elsewhere (…/cli.js hook cursor). */
export function isKytralHandler(h: unknown): boolean {
  const s = JSON.stringify(h ?? "");
  return /(\s|")hook(\s|")/.test(s) && (/kytral/i.test(s) || /\bcli\.[cm]?[jt]s\b[^{}]{0,40}?\bhook\b[^{}]{0,12}?\b(claude-code|cursor|codex|gemini|copilot|windsurf|grok|kimi|trae|opencode|mimo|qwen|iflow|qoder|codebuddy|droid|auggie|devin|kiro|amp|cline|generic|auto)\b/.test(s));
}
/** Removes Kytral handlers from a list of matcher groups ({ matcher, hooks: [...] }) or of flat handlers; empty groups go too. */
function withoutKytral(list: unknown): unknown[] {
  if (!Array.isArray(list)) return [];
  const out: unknown[] = [];
  for (const g of list) {
    if (g && typeof g === "object" && Array.isArray((g as any).hooks)) {
      const kept = (g as any).hooks.filter((h: unknown) => !isKytralHandler(h));
      if (kept.length) out.push({ ...(g as object), hooks: kept });
    } else if (!isKytralHandler(g)) out.push(g);
  }
  return out;
}

/** The agent's hook entries for Kytral Guard, by event name. */
function entries(agent: InstallAgent, c: Cmd): Record<string, unknown[]> {
  const sh = shellCommand(c);
  switch (agent) {
    case "claude-code": return { PreToolUse: [{ matcher: "^(Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read)$|^mcp__",
      hooks: [{ type: "command", command: c.node, args: [c.cli, "hook", "claude-code", "--timeout", String(c.timeout)], timeout: c.timeout, onFailure: "block" }] }] };
    case "cursor": {
      const h = { command: sh, timeout: c.timeout, failClosed: true };
      return { beforeShellExecution: [h], beforeMCPExecution: [h], preToolUse: [{ ...h, matcher: "Write|Delete" }] };
    }
    case "codex": return { PreToolUse: [{ matcher: "^(Bash|apply_patch)$|^mcp__",
      hooks: [{ type: "command", command: shellCommand(c, "linux"), commandWindows: shellCommand(c, "win32"), timeout: c.timeout, statusMessage: "Kytral Guard" }] }] };
    case "gemini": return { BeforeTool: [{ matcher: "^(run_shell_command|write_file|replace)$|^mcp_",
      hooks: [{ name: "kytral-guard", type: "command", command: sh, timeout: c.timeout * 1000 }] }] };
    case "copilot": return { preToolUse: [{ type: "command", bash: shellCommand(c, "linux"), powershell: powershellCommand(c), timeoutSec: c.timeout }] };
    case "windsurf": { const h = { command: sh, show_output: true }; return { pre_run_command: [h], pre_mcp_tool_use: [h], pre_write_code: [h] }; }
    // Grok Build has no exec form: a command with a space runs through a shell (any other runs with no arguments)
    case "grok": return { PreToolUse: [{ matcher: GROK_HOOK_MATCHER, hooks: [{ type: "command", command: sh, timeout: c.timeout }] }] };
    // TRAE's tool names (RunCommand for the shell), Claude Code's format
    case "trae": case "trae-cn": return { PreToolUse: [{ matcher: "^(RunCommand|Write|Edit|Read)$|^mcp__", hooks: [{ type: "command", command: sh, timeout: c.timeout }] }] };
    case "kimi": case "opencode": case "mimo": case "kiro": case "amp": case "cline": return {};   // not JSON hooks (see FORMAT)
    // Factory Droid: hooks.json holds the events at its top level; MCP tools are server___tool
    case "droid": return { PreToolUse: [{ matcher: "^(Execute|Create|Edit|ApplyPatch|Read)$|___|^mcp__", hooks: [{ type: "command", command: sh, timeout: c.timeout }] }] };
    // Augment Auggie: a timeout in ms, node run directly (args), and MCP tools only through an "mcp:" matcher
    case "auggie": {
      const h = { type: "command", command: c.node, args: [c.cli, "hook", c.agent, "--timeout", String(c.timeout)], timeout: c.timeout * 1000 };
      return { PreToolUse: [{ matcher: "^(launch-process|bash|save-file|write|str-replace-editor|edit|apply_patch|remove-files|view|read)$", hooks: [h] }, { matcher: "mcp:*", hooks: [h] }] };
    }
    case "devin": return { PreToolUse: [{ matcher: "^(exec|write|edit|apply_patch|read)$|^mcp__", hooks: [{ type: "command", command: sh, timeout: c.timeout }] }] };
    // Qwen Code (a fork of Gemini CLI): its own tool names; MCP tools are mcp__server__tool
    case "qwen": return { PreToolUse: [{ matcher: "^(run_shell_command|write_file|edit|notebook_edit|read_file|exec)$|^mcp__",
      hooks: [{ type: "command", command: sh, name: "kytral-guard", timeout: c.timeout }] }] };
    // iFlow names MCP tools without a prefix: its MCP servers are protected by `kytral-guard mcp wrap iflow`
    case "iflow": return { PreToolUse: [{ matcher: "^(run_shell_command|write_file|replace|multi_edit|read_file|read_many_files)$",
      hooks: [{ type: "command", command: sh, timeout: c.timeout }] }] };
    // Qoder CLI runs a command with an args array directly, without a shell
    case "qoder": return { PreToolUse: [{ matcher: "^(Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read)$|^mcp__",
      hooks: [{ type: "command", command: c.node, args: [c.cli, "hook", c.agent, "--timeout", String(c.timeout)], timeout: c.timeout }] }] };
    case "codebuddy": return { PreToolUse: [{ matcher: "^(Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read)$|^mcp__",
      hooks: [{ type: "command", command: sh, timeout: c.timeout }] }] };
  }
}

// Kimi Code: [[hooks]] entries in config.toml, whose schema accepts exactly event, matcher, command and timeout.
const KIMI_HEADER = "# Kytral Guard checks each tool call before it runs ('kytral-guard uninstall kimi' removes this entry)";
const kimiEntry = (c: Cmd) => [KIMI_HEADER, "[[hooks]]", 'event = "PreToolUse"', `matcher = ${JSON.stringify("^(Bash|Write|Edit|Read)$|^mcp__")}`,
  `command = ${JSON.stringify(shellCommand(c))}`, `timeout = ${c.timeout}`].join("\n") + "\n";
/** The [[hooks]] tables of a TOML text: their lines [start, end) and their command. */
function tomlHooks(lines: string[]): { start: number; end: number; command?: string }[] {
  const out: { start: number; end: number; command?: string }[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*\[\[\s*hooks\s*\]\]\s*(#.*)?$/.test(lines[i])) continue;
    let j = i + 1; while (j < lines.length && !/^\s*\[/.test(lines[j])) j++;
    const v = lines.slice(i + 1, j).find(l => /^\s*command\s*=/.test(l))?.replace(/^\s*command\s*=\s*/, "");
    const m = v === undefined ? null : /^("(?:[^"\\]|\\.)*")|^'([^']*)'/.exec(v);
    let command: string | undefined;
    try { command = m ? (m[1] !== undefined ? JSON.parse(m[1]) : m[2]) : v; } catch { command = v; }
    out.push({ start: i, end: j, command });
    i = j - 1;
  }
  return out;
}
/** A TOML text without Kytral Guard's [[hooks]] entries (and the comment written above them). */
function withoutKytralToml(text: string): string {
  const lines = text.split(/\r?\n/), drop = new Set<number>();
  for (const h of tomlHooks(lines)) {
    if (h.command === undefined || !isKytralHandler({ command: h.command })) continue;
    for (let k = h.start; k < h.end; k++) drop.add(k);
    if (lines[h.start - 1] === KIMI_HEADER) drop.add(h.start - 1);
  }
  const kept = lines.filter((_, k) => !drop.has(k)).join("\n").trimEnd();
  return kept ? kept + "\n" : "";
}

// Files of Kytral's own. opencode, MiMo Code and Amp: no command hooks, a plugin (a JS module run by Bun) that runs the guard
// before each tool call. Kiro: a hook file of the CLI's V3 engine. Cline: one hook file per event, a script.
const OWN_MARK = /^(#![^\n]*\n)?(\/\/|#) Kytral Guard (plugin|hook)\b|"name": "kytral-guard"/;
const isOurFile = (text: string) => OWN_MARK.test(text);
const header = (c: Cmd, agent: InstallAgent, kind: string, comment: string) => [
  `${kind} for ${AGENTS[agent].name}: checks each tool call before it runs. Written by 'kytral-guard init ${agent}',`,
  `removed by 'kytral-guard uninstall ${agent}'. The guard runs as its own process: anything but its "no objection"`,
  `blocks the call, and so does a guard that cannot start or does not answer within ${c.timeout} s.`].map(l => `${comment} ${l}`).join("\n");
/** The guard run as a child process, its answer collected (shared by the plugins). */
const runGuardJs = (c: Cmd) => `import { spawn } from "node:child_process";
const NODE = ${JSON.stringify(c.node)}, CLI = ${JSON.stringify(c.cli)}, AGENT = ${JSON.stringify(c.agent)}, TIMEOUT = ${c.timeout};
const check = (event) => new Promise((done) => {
  let out = "", err = "", settled = false, timer, p;
  const finish = (code) => { if (settled) return; settled = true; clearTimeout(timer); done({ code, out, err, reason: (err || out).trim() || \`Kytral Guard refused this call (exit code \${code})\` }); };
  try { p = spawn(NODE, [CLI, "hook", AGENT, "--timeout", String(TIMEOUT)], { windowsHide: true }); } catch (e) { err = String(e); return finish(-1); }
  timer = setTimeout(() => { err = err || "the guard did not answer in time"; try { p.kill(); } catch {} finish(-1); }, TIMEOUT * 1000);
  p.stdout.on("data", (d) => { out += d; });
  p.stderr.on("data", (d) => { err += d; });
  p.on("error", (e) => { err = err || String(e); finish(-1); });
  p.on("close", (code) => finish(code));
  p.stdin.on("error", () => {});
  p.stdin.end(event);
});`;
function ownFile(c: Cmd, agent: InstallAgent): string {
  switch (agent) {
    case "opencode": case "mimo": return `${header(c, agent, "Kytral Guard plugin", "//")}
${runGuardJs(c)}
const SKIP = new Set(${JSON.stringify(PLUGIN_READ_ONLY)});
export const KytralGuard = async ({ directory, worktree }) => ({
  "tool.execute.before": async (input, output) => {
    if (SKIP.has(input.tool)) return;
    const r = await check(JSON.stringify({ tool: input.tool, args: output.args ?? {}, cwd: directory ?? worktree ?? process.cwd(), sessionID: input.sessionID }));
    if (r.code === 0) return;
${agent === "mimo" ? "    output.cancel = true; output.cancelReason = r.reason;" : "    throw new Error(r.reason);"}
  },
});
`;
    // exit code 3: the guard asks for a human, and Amp's plugins can show a dialog
    case "amp": return `${header(c, agent, "Kytral Guard plugin", "//")}
${runGuardJs(c)}
const GUARDED = new RegExp(${JSON.stringify(AMP_GUARDED)});
export default function (amp) {
  amp.on("tool.call", async (event, ctx) => {
    if (!GUARDED.test(event.tool)) return { action: "allow" };
    const r = await check(JSON.stringify({ tool: event.tool, args: event.input ?? {}, cwd: event.input?.cwd ?? process.cwd(), sessionID: event.thread?.id }));
    if (r.code === 0) return { action: "allow" };
    if (r.code === 3) {
      let ok = false;
      try { ok = await ctx.ui.confirm({ title: "Kytral Guard", message: r.reason, confirmButtonText: "Allow" }); } catch { ok = false; }
      if (ok === true) return { action: "allow" };
    }
    return { action: "reject-and-continue", message: r.reason };
  });
}
`;
    case "kiro": return JSON.stringify({ version: "v1", hooks: [{ name: "kytral-guard", trigger: "PreToolUse",
      matcher: "^(execute_bash|execute_pwsh|fs_write|str_replace|fs_append|delete_file|read_file)$|^mcp_", action: { type: "command", command: shellCommand(c) }, timeout: c.timeout }] }, null, 2) + "\n";
    case "cline": {
      const refuse = '{"cancel":true,"errorMessage":"Kytral Guard could not check this call, so it is refused (fail closed)"}';
      if (process.platform === "win32") return `${header(c, agent, "Kytral Guard hook", "#")}
$utf8 = New-Object System.Text.UTF8Encoding $false
$OutputEncoding = $utf8; [Console]::OutputEncoding = $utf8; [Console]::InputEncoding = $utf8
$event = [Console]::In.ReadToEnd()
$out = $null; $code = -1
try { $out = ($event | & ${psQuote(c.node)} ${psQuote(c.cli)} hook ${c.agent} --timeout ${c.timeout} 2>$null) -join "\`n"; $code = $LASTEXITCODE } catch { $code = -1 }
if ($code -eq 0) { [Console]::Out.Write($out) } else { [Console]::Out.Write(${psQuote(refuse)}) }
`;
      return `#!${c.node}
${header(c, agent, "Kytral Guard hook", "//")}
const { spawnSync } = require("node:child_process");
const r = spawnSync(${JSON.stringify(c.node)}, [${JSON.stringify(c.cli)}, "hook", ${JSON.stringify(c.agent)}, "--timeout", "${c.timeout}"], { input: require("node:fs").readFileSync(0), encoding: "utf8", timeout: ${c.timeout * 1000} });
process.stdout.write(r.status === 0 ? r.stdout : ${JSON.stringify(refuse)});
`;
    }
    default: throw new Error(`${agent} has no hook file of its own`);
  }
}
/** Notes printed after an install: what the user still has to do in the agent. */
function notes(agent: InstallAgent, o: InstallOptions): string[] {
  switch (agent) {
    case "claude-code": return ["Claude Code reloads its settings automatically; run /hooks to see the hook. onFailure 'block' needs Claude Code v2.1.295 or later."];
    case "cursor": return ["Cursor reloads hooks.json automatically. Do not also install the Claude Code hook in this project unless you want both to run: Cursor also reads .claude/settings*.json."];
    case "codex": return ["Codex runs a new hook only once you trust it: open /hooks in Codex and trust 'Kytral Guard'."];
    case "gemini": return [o.project ? "Gemini CLI asks you to trust a changed project hook on its next start." : "Restart Gemini CLI to load the hook."];
    case "copilot": return ["Copilot CLI reads ~/.copilot/hooks/*.json at startup; restart it."];
    case "windsurf": return ["Windsurf Cascade hooks only block via exit code 2: there is no 'ask', a confirmation is refused."];
    case "grok": return [o.project ? "Grok Build runs a project hook once you trust the folder: run /hooks-trust in Grok Build." : "Grok Build loads hooks when a session starts: restart running sessions.",
      "Grok Build also runs the hooks of Claude Code and Cursor. It cannot run Kytral's Claude Code hook (it drops the arguments) and shows it as failed: harmless, this hook decides."];
    case "kimi": return [...(o.project ? ["Kimi Code has no project hooks: installed for the user."] : []),
      "Kimi Code loads hooks when it starts: restart it. It reads any answer but a refusal as an approval, so a confirmation is refused."];
    case "trae": case "trae-cn": return [`Turn hooks on in ${AGENTS[agent].name}: Settings > Hooks, ${o.project ? "Project" : "Global"}, and choose 'Run Automatically Locally' (in the sandbox the guard cannot read its own state and refuses every call).`];
    case "opencode": case "mimo": return [`${AGENTS[agent].name} loads plugins when it starts: restart it. Plugins cannot ask, so a confirmation is refused; --pure starts it without plugins, so without the guard.`];
    case "qwen": return [`Qwen Code loads hooks when a session starts (or when /hooks opens): restart running sessions.${o.project ? " Project hooks run only in a trusted folder." : ""}`];
    case "iflow": return ["iFlow CLI loads hooks at startup: restart it. Its hooks cannot ask, so a confirmation is refused. iFlow names MCP tools without a prefix: protect its MCP servers with 'kytral-guard mcp wrap iflow'."];
    case "qoder": return ["Restart qodercli to load the hook. In interactive mode Qoder runs no hook at all in a folder you have not trusted: trust your project folders."];
    case "codebuddy": return ["CodeBuddy Code loads hooks at startup: restart it, and approve the hook in /hooks if it asks."];
    case "droid": return ["Factory Droid loads hooks at startup and skips them while it waits for you to trust the folder: trust it, then restart droid. Droid does not ask: a confirmation is refused."];
    case "auggie": return ["Restart auggie to load the hook. Its hooks can only refuse, so a confirmation is refused; another hook that fails (an exit code other than 0 and 2) cancels the refusal: keep other hooks working."];
    case "devin": return ["Restart Devin CLI to load the hook. Devin also runs the hooks of ~/.claude/settings.json, with its own tool names."];
    case "kiro": return ["Kiro CLI runs this hook with its V3 engine ('kiro-cli chat --v3', or chat.agentEngine v3), in trusted workspaces only; its default V2 engine reads hooks from agent profiles. A confirmation is refused (headless runs would approve it)."];
    case "amp": return ["Amp loads plugins at startup ('plugins: reload' in the command palette reloads them). A confirmation opens a dialog in Amp."];
    case "cline": return ["Cline runs this hook before each tool call (VS Code extension and CLI). Its hooks cannot refuse a single call: a refusal stops the task. A confirmation is refused."];
  }
}

function readJson(file: string): Record<string, any> {
  if (!existsSync(file)) return {};
  const text = readFileSync(file, "utf8");
  if (!text.trim()) return {};
  let v: unknown;
  try { v = JSON.parse(text); } catch (e) { throw new Error(`${file} is not valid JSON (${(e as Error).message}); fix it first, nothing was changed`); }
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error(`${file} does not hold a JSON object; nothing was changed`);
  return v as Record<string, any>;
}
const save = (file: string, before: string | null, data: unknown, dryRun?: boolean) => saveText(file, before, JSON.stringify(data, null, 2) + "\n", dryRun);
function saveText(file: string, before: string | null, content: string, dryRun?: boolean): { content: string; backup?: string; changed: boolean } {
  if (before === content) return { content, changed: false };
  if (dryRun) return { content, changed: true };
  mkdirSync(dirname(file), { recursive: true });
  let backup: string | undefined;
  if (before !== null) { backup = `${file}.kytral-backup`; copyFileSync(file, backup); }
  writeFileSync(file, content);
  return { content, backup, changed: true };
}
/** The hooks object of an agent's file: under "hooks" everywhere; Cursor and Copilot also need "version": 1. */
function apply(agent: InstallAgent, data: Record<string, any>, add: Record<string, unknown[]> | null): Record<string, any> {
  if (FLAT.has(agent)) {   // the events are the file's own keys
    const out: Record<string, any> = {};
    for (const [ev, list] of Object.entries(data)) { if (!Array.isArray(list)) { out[ev] = list; continue; } const kept = withoutKytral(list); if (kept.length) out[ev] = kept; }
    if (add) for (const [ev, list] of Object.entries(add)) out[ev] = [...(Array.isArray(out[ev]) ? out[ev] : []), ...list];
    return out;
  }
  const out = { ...data };
  const hooks: Record<string, unknown> = { ...(out.hooks && typeof out.hooks === "object" && !Array.isArray(out.hooks) ? out.hooks : {}) };
  for (const ev of Object.keys(hooks)) { const kept = withoutKytral(hooks[ev]); if (kept.length) hooks[ev] = kept; else delete hooks[ev]; }
  if (add) for (const [ev, list] of Object.entries(add)) hooks[ev] = [...withoutKytral(hooks[ev]), ...list];
  if (Object.keys(hooks).length) out.hooks = hooks; else delete out.hooks;
  if ((agent === "cursor" || agent === "copilot" || agent === "trae" || agent === "trae-cn") && out.hooks) out.version ??= 1;
  return out;
}

/**
 * The node that hooks and wrapped servers name: this one, unless it runs from the folder of its version in Homebrew's
 * Cellar (macOS gives the real path), which the next `brew upgrade node` removes: then a stable link of Homebrew to the
 * same program (<prefix>/opt/node/bin/node, else <prefix>/bin/node), which upgrades follow.
 */
export function stableNodePath(exec = process.execPath): string {
  const m = /^(.*)\/Cellar\/(node(?:@\d+)?)\/[^\/]+\/bin\/node$/.exec(exec);
  if (!m) return exec;
  for (const link of [`${m[1]}/opt/${m[2]}/bin/node`, `${m[1]}/bin/node`]) {
    try { if (realpathSync(link) === realpathSync(exec)) return link; } catch { /* no such link */ }
  }
  return exec;
}
/** Adds the Kytral Guard hook to an agent's configuration (replacing a previous Kytral entry). */
export function installHook(agent: InstallAgent, o: InstallOptions = {}): InstallResult {
  const file = configFile(agent, o);
  const before = existsSync(file) ? readFileSync(file, "utf8") : null;
  const c: Cmd = { node: o.nodePath ?? stableNodePath(), cli: o.cliPath ?? defaultCliPath(), agent: HOOK_AGENT[agent] ?? agent, timeout: o.timeoutSeconds ?? 30 };
  let r: { content: string; backup?: string; changed: boolean };
  if (FORMAT[agent] === "toml") {
    if (before !== null && /^\s*hooks\s*=/m.test(before)) throw new Error(`${file} defines hooks = [...] inline; add this entry to it by hand, nothing was changed:\n${kimiEntry(c)}`);
    const kept = before === null ? "" : withoutKytralToml(before);
    r = saveText(file, before, (kept ? kept + "\n" : "") + kimiEntry(c), o.dryRun);
  } else if (FORMAT[agent] === "own") {
    if (before !== null && !isOurFile(before)) throw new Error(`${file} exists and was not written by Kytral Guard; nothing was changed`);
    r = saveText(file, before, ownFile(c, agent), o.dryRun);
    // a hook script runs as a program (Cline, on POSIX): executable
    if (agent === "cline" && process.platform !== "win32" && !o.dryRun) chmodSync(file, 0o755);
  } else r = save(file, before, apply(agent, readJson(file), entries(agent, c)), o.dryRun);
  return { agent, file, ...r, notes: notes(agent, o) };
}
/** Removes every Kytral Guard hook from an agent's configuration; other hooks and settings are kept. */
export function uninstallHook(agent: InstallAgent, o: InstallOptions = {}): InstallResult {
  const file = configFile(agent, o);
  if (!existsSync(file)) return { agent, file, changed: false, content: "", notes: ["no configuration file"] };
  const before = readFileSync(file, "utf8");
  if (FORMAT[agent] === "own") {
    if (!isOurFile(before)) return { agent, file, changed: false, content: before, notes: ["not written by Kytral Guard: left as it is"] };
    if (!o.dryRun) rmSync(file);
    return { agent, file, changed: true, content: "", notes: [] };
  }
  if (FORMAT[agent] === "toml") return { agent, file, ...saveText(file, before, withoutKytralToml(before), o.dryRun), notes: [] };
  return { agent, file, ...save(file, before, apply(agent, readJson(file), null), o.dryRun), notes: [] };
}
/** The absolute paths a hook command names (quoted), or a plugin's NODE and CLI. */
function namedPaths(s: unknown): string[] {
  return typeof s === "string" ? [...s.matchAll(/'([^']+)'|"([^"]+)"/g)].map(m => m[1] ?? m[2]).filter(p => /^([A-Za-z]:[\\/]|\/)/.test(p)) : [];
}
/** A problem `doctor` reports and the dashboard says in the reader's language: a US English template and its values. */
export interface HookIssue { key: string; p: Record<string, string> }
/** A template the dashboard translates (test/i18n-keys.ts collects the texts given to issue). */
const issue = (key: string, p: Record<string, string> = {}): HookIssue => ({ key, p });
export const issueText = (i: HookIssue) => i.key.replace(/\{(\w+)\}/g, (m, k: string) => (Object.hasOwn(i.p, k) ? i.p[k] : m));
/** Kytral handlers found in an agent's configuration file, with the problems `doctor` reports (as text, and as issues). */
export function inspectHook(agent: InstallAgent, o: InstallOptions = {}): { file: string; installed: boolean; problems: string[]; issues: HookIssue[] } {
  const file = configFile(agent, o), issues: HookIssue[] = [];
  const result = (installed: boolean) => ({ file, installed, problems: issues.map(issueText), issues });
  if (!existsSync(file)) return result(false);
  if (FORMAT[agent]) {
    const text = readFileSync(file, "utf8");
    // a file of Kytral's own names node and the CLI as JSON strings or quoted words; a TOML entry, in its command
    const commands = FORMAT[agent] === "own" ? (isOurFile(text) ? [[...text.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(m => { try { return JSON.parse(`"${m[1]}"`); } catch { return ""; } })
      .concat([...text.matchAll(/'([^']+)'/g)].map(m => m[1])).filter(p => /(^|[\\/])(node(\.exe)?|cli\.[cm]?[jt]s)$/i.test(p)).map(p => `"${p}"`).join(" ") || "kytral"] : [])
      : tomlHooks(text.split(/\r?\n/)).map(h => h.command).filter((c): c is string => c !== undefined && isKytralHandler({ command: c }));
    for (const p of commands.flatMap(namedPaths)) if (!existsSync(p)) issues.push(issue("{file}: {path} does not exist (re-run 'kytral-guard init {agent}')", { file, path: p, agent }));
    return result(commands.length > 0);
  }
  let data: Record<string, any>;
  try { data = readJson(file); } catch (e) { issues.push({ key: "{error}", p: { error: (e as Error).message } }); return result(false); }
  const handlers: any[] = [];
  for (const list of Object.values(FLAT.has(agent) ? data : data.hooks ?? {})) for (const g of Array.isArray(list) ? list : []) for (const h of Array.isArray(g?.hooks) ? g.hooks : [g]) if (isKytralHandler(h)) handlers.push(h);
  if (agent === "claude-code" && data.disableAllHooks === true) issues.push(issue("{file} sets disableAllHooks: true, so no hook runs", { file }));
  for (const h of handlers) {
    // Exec form (command + args) names the files directly; a shell command quotes them.
    const quoted = (s: unknown) => typeof s === "string" ? [...s.matchAll(/'([^']+)'|"([^"]+)"/g)].map(m => m[1] ?? m[2]) : [];
    const paths = Array.isArray(h.args) ? [h.command, h.args[0]] : [...quoted(h.command), ...quoted(h.bash)];
    for (const p of paths) if (typeof p === "string" && /^([A-Za-z]:[\\/]|\/)/.test(p) && !existsSync(p)) issues.push(issue("{file}: {path} does not exist (re-run 'kytral-guard init {agent}')", { file, path: p, agent }));
    if (agent === "claude-code" && h.onFailure !== "block") issues.push(issue("{file}: the hook fails open (add \"onFailure\": \"block\", or re-run 'kytral-guard init {agent}')", { file, agent }));
    if (agent === "cursor" && h.failClosed !== true) issues.push(issue("{file}: the hook fails open (add \"failClosed\": true, or re-run 'kytral-guard init {agent}')", { file, agent }));
    // Grok hands the command to cmd.exe with its quotes escaped as \" (which cmd.exe keeps), so node cannot find the CLI and Grok runs the tool
    if (agent === "grok" && process.platform === "win32" && /^cmd(\.exe)?$/i.test(process.env.GROK_SHELL?.trim() ?? "") && /"/.test(String(h.command)))
      issues.push(issue("GROK_SHELL={shell}: Grok Build cannot run this hook through cmd.exe (it escapes the quotes of the command) and then runs the tool; unset GROK_SHELL or set it to pwsh, powershell or bash", { shell: process.env.GROK_SHELL ?? "" }));
  }
  if (agent === "claude-code" && handlers.length) {
    const m = (data.hooks?.PreToolUse ?? []).find((g: any) => Array.isArray(g?.hooks) && g.hooks.some(isKytralHandler))?.matcher ?? "";
    if (typeof m === "string" && m && !/PowerShell/.test(m) && m !== "*") issues.push(issue("{file}: the matcher does not include PowerShell (Windows routes shell commands through it)", { file }));
  }
  return result(handlers.length > 0);
}
