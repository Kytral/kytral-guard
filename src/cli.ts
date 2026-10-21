#!/usr/bin/env node
import { main } from "./proxy.js"; import { issueBadge } from "./badge.js"; import { assertStrongSecret, assertAudience, assertAuditSecret, resolveSecret, secretFilePath } from "./secret.js"; import { FileSet, stateDir, statePath } from "./store.js"; import { BAD_GRANT, cleanName, knownToolsKey, knownToolsPath, parseGrant, removeGrants, tombstonePath } from "./known-tools.js"; import { AuditLog, auditKey, auditTailPath, describeAudit, verifyAuditFile } from "./audit.js";
import { ARGS_SHOWN, ConfirmError, ConfirmVerdict, decide, listRequests, printable as show } from "./confirm-queue.js";
import { engageKillSwitch, KillSwitchChange, killSwitchKey, killSwitchPath, killSwitchState, releaseKillSwitch } from "./kill-switch.js";
import { evaluate, loadPolicy, matchingRules, Policy, PRESETS, ToolCall } from "./policy.js";
import { explain, HOOK_AGENTS, HookAgent, isGrokEvent, isHookAgent, isShellTool, loadHookPolicy, prewarmAnalysis, renderHookAnswer, runHookAsync } from "./hooks.js";
import { loadPlugins, pluginSpecs } from "./plugins.js";
import { AGENTS, defaultCliPath, detectAgents, INSTALL_AGENTS, inspectHook, installHook, isInstallAgent, uninstallHook } from "./install.js";
import { listMcp, MCP_CLIENTS, McpChange, McpFile, McpOptions, recordedFiles, unwrapMcp, wrapMcp } from "./mcp-config.js";
import { addException, hookPolicyFile, listExceptions, mcpPolicyPath, POLICY_TEMPLATE, removeRule, withoutExceptionsFor } from "./policy-file.js";
import { exceptionLock } from "./dashboard-rules.js";
import { HIDDEN_CHARACTERS, MASK, readKeptCalls, type KeptCall } from "./kept-calls.js";
import { openInBrowser, startDashboard, type DashboardHandle } from "./dashboard.js";
import { doctorReport } from "./bug-report.js";
import { existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync, writeSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir, userInfo } from "node:os";
import { join, resolve, sep } from "node:path";
import { stringify } from "yaml";
const VERSION: string = createRequire(import.meta.url)("../package.json").version;
const a = process.argv.slice(2);
const fail = (msg: string, code = 2): never => { console.error(msg.startsWith("usage:") ? msg : `kytral-guard: ${msg}`); process.exit(code); };
/** A file error in words (no such file, a folder, permission denied); any other error: its first line (YAML adds a snippet). */
function errText(e: unknown): string {
  const x = e as NodeJS.ErrnoException | undefined;
  if (x?.path && x.code === "ENOENT") return `${x.path}: no such file`;
  if (x?.path && x.code === "EISDIR") return `${x.path} is a folder, not a file`;
  if (x?.path && (x.code === "EACCES" || x.code === "EPERM")) return `${x.path}: permission denied`;
  return String(x?.message ?? e).split("\n")[0].replace(/:\s*$/, "");
}
/** Each command's usage: said by `<command> --help` (or -h, or `help <command>`), and after a usage error. */
const USAGE: Record<string, string> = {
  init: `usage: kytral-guard init [agent...] [--project] [--dry-run] [--timeout seconds] [--no-agents] [--force]\n  agents: ${INSTALL_AGENTS.join(", ")} (none named: every agent found)`,
  uninstall: `usage: kytral-guard uninstall <agent...> | --all [--project] [--dry-run]   (--all also takes the proxy off the MCP servers of the apps)\n  agents: ${INSTALL_AGENTS.join(", ")}`,
  doctor: "usage: kytral-guard doctor --report [--policy file]   (a diagnostic to paste into a bug report, redacted; --policy: the file the proxies are given)\n"
    + "       kytral-guard doctor   (checks the setup and runs a self-test)",
  hook: `usage: kytral-guard hook <${HOOK_AGENTS.join("|")}|auto> [--policy file | --preset name] [--timeout seconds]   (run by the agent: one event on stdin, the decision on stdout)`,
  mcp: `usage: kytral-guard mcp list | wrap | unwrap [app...] [--file config.json] [--preset name | --policy file] [--dry-run]\n  apps: ${MCP_CLIENTS.map(c => c.id).join(", ")}`,
  proxy: "usage: kytral-guard [proxy] [--policy file | --preset name] -- <mcp server command...>",
  badge: "usage: kytral-guard badge <agentId> <tool1,tool2|*> [lifetime] [--once]   (lifetime: seconds, or 90m, 12h, 30d, 1y; default 1h)",
  revoke: "usage: kytral-guard revoke <badgeId|agentId|nonce>   (an id that starts with '-': kytral-guard revoke -- <id>)",
  check: `usage: kytral-guard check [--policy file | --preset name] [--tool name] [--json] "<command>"   (or {"tool","args"} JSON on stdin)\n  exit code: 0 allowed, 3 a human must confirm, 2 blocked`,
  allow: `usage: kytral-guard allow "<command>" [--force] [--policy file] | allow --call <n> | allow --list | allow --remove <rule>   (agents may then run this exact command)`,
  policy: "usage: kytral-guard policy presets | show [--policy file | --preset name] | validate <file>",
  dashboard: "usage: kytral-guard dashboard [--port n] [--no-open]",
  kill: "usage: kytral-guard kill [--by <name>] | kytral-guard resume [--by <name>]   (every proxy and guard using this KYTRAL_HOME)\n"
    + "  exit code of kill: 0 stopped; 3 stopped, but the audit log could not be read or record it (stderr says why); 1 nothing written, NOT stopped\n"
    + "  exit code of resume: 0 done; 1 refused or failed, nothing written (the audit log cannot be read, among others)",
  confirm: "usage: kytral-guard confirm list [--full] | confirm approve <id> [--always] [--full] [--by <name>] | confirm deny <id> [--by <name>]",
  known: "usage: kytral-guard known list | known remove <tool> [agentId] [server] [--by <name>]   (every agent and server unless narrowed)",
  audit: "usage: kytral-guard audit verify [file]   (default: $KYTRAL_AUDIT, else $KYTRAL_HOME/audit.jsonl; exit 0 valid, 1 broken, 3 unverifiable lines)",
};
USAGE.resume = USAGE.kill;
const cmdName = a[0] ?? "";
const UNKNOWN_OPTION = "unknown option; run kytral-guard --help";
/**
 * Positional arguments (all of those after --), `--name value` options and `--flag` switches. Anything else that starts with
 * - is a usage error that repeats no part of it, neither its name nor a value: a typo (--polcy), the = form (--policy=file), an
 * option of another command, or a token typed where an option goes (--ghp_..., --<password>=...). An option given twice is an
 * error too: neither value is silently dropped.
 */
function parseArgs(args: string[], values: string[], flags: string[] = []) {
  const pos: string[] = [], opt: Record<string, string> = {}, on = new Set<string>();
  for (let i = 0; i < args.length; i++) {
    if (values.includes(args[i])) {
      if (i + 1 >= args.length) fail(`${args[i]} needs a value`);
      if (args[i] in opt) fail(`${args[i]} given more than once`);
      opt[args[i]] = args[++i];
    }
    else if (flags.includes(args[i])) on.add(args[i]);
    else if (args[i] === "--") { pos.push(...args.slice(i + 1)); break; }
    else if (args[i].length > 1 && args[i].startsWith("-")) {
      // `check git reset --hard`: the command's own options reach the parser when it is not quoted (said without repeating it)
      if (pos.length && (cmdName === "check" || cmdName === "allow")) fail(`${UNKNOWN_OPTION}\n  (a command that has options goes in quotes: kytral-guard ${cmdName} "<command>")`);
      fail(UNKNOWN_OPTION);
    }
    else pos.push(args[i]);
  }
  return { pos, opt, on };
}
/** Asked for help: --help or -h before any `--` (after it, they belong to the command checked or run). */
const helpAsked = (args: string[]) => { const k = args.indexOf("--"); return (k < 0 ? args : args.slice(0, k)).some(x => x === "--help" || x === "-h"); };
/** Edit distance (insertions, deletions, substitutions) of two short words: typos of a command or an agent name. */
function distance(x: string, y: string): number {
  let prev = Array.from({ length: y.length + 1 }, (_, j) => j);
  for (let i = 1; i <= x.length; i++) {
    const row = [i];
    for (let j = 1; j <= y.length; j++) row[j] = Math.min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + (x[i - 1] === y[j - 1] ? 0 : 1));
    prev = row;
  }
  return prev[y.length];
}
/** The closest name to a word (same letters in another case, a known alias, a prefix, or one or two typos), if any. */
function nearest(word: string, names: readonly string[], aliases: Record<string, string> = {}): string | undefined {
  const w = word.toLowerCase().replace(/^-+/, "");
  if (names.includes(w)) return w;
  if (aliases[w]) return aliases[w];
  const prefixed = names.filter(n => n.startsWith(w) || w.startsWith(n));
  if (w.length >= 3 && prefixed.length === 1) return prefixed[0];
  const close = names.map(n => [n, distance(w, n)] as const).filter(([, d]) => d <= (w.length > 4 ? 2 : 1)).sort((p, q) => p[1] - q[1]);
  return close[0]?.[0];
}
const COMMAND_ALIASES: Record<string, string> = { install: "init", setup: "init", status: "doctor", log: "dashboard", logs: "dashboard", stop: "kill",
  remove: "uninstall", v: "version", version: "version" };
const AGENT_ALIASES: Record<string, string> = { claude: "claude-code", "claude-cli": "claude-code", "gemini-cli": "gemini", "copilot-cli": "copilot",
  "github-copilot": "copilot", "codex-cli": "codex", factory: "droid", "factory-droid": "droid", augment: "auggie", "kiro-cli": "kiro", "devin-cli": "devin",
  "grok-build": "grok", "kimi-code": "kimi", "qwen-code": "qwen", "iflow-cli": "iflow", "qoder-cli": "qoder", "codebuddy-code": "codebuddy", "mimo-code": "mimo" };
/**
 * Refuses an agent name that is not one, before anything is written, naming the agent meant when it is clear. The name typed
 * is not repeated (it may be anything, a token pasted at the wrong place too): only names of the fixed list are.
 */
function checkAgentNames(names: string[]): void {
  for (const n of names) if (!isInstallAgent(n)) {
    const near = nearest(n, INSTALL_AGENTS, AGENT_ALIASES);
    fail(`unknown agent.${near ? ` Did you mean '${near}'?` : ""} Agents: ${INSTALL_AGENTS.join(", ")}`);
  }
}
/** A badge lifetime: seconds (3600), or a number with s, m, h, d or y (90m, 12h, 30d, 1y); null when it is not one. */
function lifetimeSeconds(s: string): number | null {
  const m = /^(\d+(?:\.\d+)?)([smhdy]?)$/i.exec(s.trim());
  if (!m) return null;
  const n = Number(m[1]) * ({ "": 1, s: 1, m: 60, h: 3600, d: 86400, y: 31536000 } as Record<string, number>)[m[2].toLowerCase()];
  return Number.isFinite(n) && n > 0 ? n : null;
}
/** A secret error in the words of where the secret comes from: KYTRAL_SECRET as it says, or the file 'init' writes. */
function secretError(e: unknown): string {
  const msg = (e as Error).message;
  if (process.env.KYTRAL_SECRET !== undefined) return msg;
  const file = secretFilePath();
  let text: string | null = null; try { text = readFileSync(file, "utf8"); } catch {}
  if (text === null) return `no secret yet (KYTRAL_SECRET is not set and ${file} does not exist): run 'kytral-guard init'`;
  if (!text.trim()) return `${file} is empty: run 'kytral-guard init' to write a new secret`;
  if (!msg.startsWith("KYTRAL_SECRET ")) return msg;   // not about the value (a link in place of the file...)
  return `${file} holds a weak secret (${msg.replace(/^KYTRAL_SECRET /, "")}): delete it and run 'kytral-guard init' to write a new one`;
}
/** KYTRAL_HOME exists but is not a folder (a file in its place): every command that writes there says so first. */
function stateDirProblem(): string | null {
  const home = stateDir();
  try { if (existsSync(home) && !statSync(home).isDirectory()) return `${home} (KYTRAL_HOME) is a file, not a folder: move it away, or point KYTRAL_HOME at a folder`; } catch {}
  return null;
}
/**
 * The files the kill switch is read from (kill-switch.json, the audit log, its tail marker) when none of them exists while
 * a default path that KYTRAL_HOME or KYTRAL_AUDIT replaces still holds one (`there`): this home was wiped, or redirected to
 * a blank one, and a kill in force there is not seen here. Null when neither variable is set, on a fresh install, and once
 * one of these files exists here. Existence checks only: nothing is opened, read, written or created, and no secret is
 * used. A warning for doctor and the hooks' stderr, never part of a decision.
 */
function stateLeftBehind(): { here: string[]; there: string[] } | null {
  try {
    const home = process.env.KYTRAL_HOME, audit = process.env.KYTRAL_AUDIT;
    if (!home && !audit) return null;
    const withTail = (log: string) => [log, auditTailPath(log)];
    const here = [killSwitchPath(), ...withTail(statePath(audit, "audit.jsonl"))];
    // gone: no such file (ENOENT, or a path through something that is no folder); any other error proves nothing
    const gone = (f: string) => { try { statSync(f); return false; } catch (e) { return ["ENOENT", "ENOTDIR"].includes((e as NodeJS.ErrnoException)?.code ?? ""); } };
    if (!here.every(gone)) return null;
    const kytral = join(homedir(), ".kytral");
    const replaced = [...(home ? [join(kytral, "kill-switch.json"), ...withTail(join(kytral, "audit.jsonl"))] : []), ...(audit ? withTail(join(stateDir(), "audit.jsonl")) : [])];
    const there = [...new Set(replaced)].filter(f => existsSync(f));
    return there.length ? { here, there } : null;
  } catch { return null; }
}
/** What a hook adds to its stderr, after its answer, when stateLeftBehind() finds something: fixed words, no path. */
const LEFT_BEHIND = "Kytral Guard: warning: no kill switch state where KYTRAL_HOME or KYTRAL_AUDIT points, although the default location still holds some (wiped or redirected?): a kill in force there is not seen here; 'kytral-guard doctor' says where";
/**
 * Root of the proxies' derived keys (known-tools signatures, confirmation queue): KYTRAL_AUDIT_SECRET if set, else the
 * deployment secret (KYTRAL_SECRET, else $KYTRAL_HOME/secret). Same rule as the Guard and the proxy: a weak value is refused,
 * never used. Optional for `known` (unverified listing).
 */
function rootSecret(required: boolean): string | undefined {
  try { const s = resolveSecret(); return assertAuditSecret() ?? (required || s !== undefined ? assertStrongSecret(s) : undefined); }
  catch (e) { return fail((e as Error).message); }
}
/** Audit HMAC key for a command that must work without a secret (kill, known remove): undefined says so on stderr (entry unauthenticated). */
function auditKeyOrWarn(root: string | undefined): Buffer | undefined {
  let key: Buffer | undefined; try { key = root === undefined ? undefined : auditKey(root); } catch {}
  if (!key) console.error("kytral-guard: no usable audit key (KYTRAL_SECRET / KYTRAL_AUDIT_SECRET): journaled without a MAC, 'audit verify' reports the entry as unverified");
  return key;
}
/** Who ran the command: the OS account, plus the name given with --by (declared, not verified). */
function cliApprover(by?: string): string {
  let os: string; try { os = userInfo().username; } catch { os = process.env.USERNAME ?? process.env.USER ?? "unknown"; }
  const name = by === undefined ? "" : cleanName(by);
  return name && name !== os ? `${name} (os:${os})` : os;
}
/**
 * A protection added or removed in this terminal (init, uninstall, mcp wrap / unwrap), journaled as the dashboard journals
 * its own changes and as kill and resume are (agent "*"): the log and the page then say who removed a hook, and when.
 * Best effort: without a usable secret (deleted before an uninstall) nothing is journaled; the change itself still happens.
 */
function journalChange(decision: "settings-change" | "mcp-wrap", reason: string, tool: string): void {
  try {
    const key = auditKey(assertStrongSecret(resolveSecret()));
    new AuditLog(statePath(process.env.KYTRAL_AUDIT, "audit.jsonl"), { key }).append({ agentId: "*", tool, decision, reason, approver: cliApprover() });
  } catch { /* no secret or no log: not journaled */ }
}
async function readStdin(limit = 64 * 1024 * 1024): Promise<string> {
  const chunks: Buffer[] = []; let n = 0;
  for await (const c of process.stdin) { n += c.length; if (n > limit) throw new Error("input larger than 64 MB"); chunks.push(c as Buffer); }
  return Buffer.concat(chunks).toString("utf8");
}

const HELP = `Kytral Guard ${VERSION} - the anti-catastrophe guard for AI agents.

Protect a coding agent (hooks):
  kytral-guard init [agent...] [--project] [--dry-run] [--timeout seconds] [--no-agents]
                                                    (no agent named: every agent found: ${INSTALL_AGENTS.join(", ")})
  kytral-guard uninstall <agent...> | --all [--project] [--dry-run]
                                                    (--all also takes the proxy off the MCP servers of the apps)
  kytral-guard doctor                               check the setup and run a self-test
  kytral-guard hook <${HOOK_AGENTS.join("|")}|auto> [--policy file | --preset name] [--timeout seconds]
                                                    (run by the agent: one event on stdin, the decision on stdout)
Protect the MCP servers of AI apps (stdio proxy):
  kytral-guard mcp list | wrap | unwrap [app...] [--file config.json] [--preset name | --policy file] [--dry-run]
                                                    (apps: ${MCP_CLIENTS.map(c => c.id).join(", ")})
  kytral-guard [proxy] [--policy file | --preset name] -- <mcp server command...>
  kytral-guard badge <agentId> <tool1,tool2|*> [lifetime] [--once]   (lifetime: seconds, or 90m, 12h, 30d, 1y; default 1h)
  kytral-guard revoke <badgeId|agentId|nonce>
Policies:
  kytral-guard check [--policy file | --preset name] [--tool name] [--json] "<command>"   (or {"tool","args"} JSON on stdin)
                                                    (exit code: 0 allowed, 3 a human must confirm, 2 blocked)
  kytral-guard allow "<command>" [--force] [--policy file] | allow --call <n> | allow --list | allow --remove <rule>   (agents may run this exact command)
  kytral-guard policy presets | show [--policy file | --preset name] | validate <file>
Control:
  kytral-guard dashboard [--port n] [--no-open]   a page on this computer: what agents did, rules, approvals, stop button
  kytral-guard kill [--by name]      stop every guarded agent and proxy using this KYTRAL_HOME, within 1 s
                                                    (exit code: 0 stopped; 3 stopped, but the audit log could not be read
                                                    or record it: stderr says why; 1 nothing written, NOT stopped)
  kytral-guard resume [--by name]
  kytral-guard confirm list [--full] | approve <id> [--always] [--full] [--by name] | deny <id> [--by name]
  kytral-guard known list | remove <tool> [agentId] [server] [--by name]
  kytral-guard audit verify [file]
Bug reports:
  kytral-guard doctor --report [--policy file]   a diagnostic to paste into a bug report, redacted: no secrets, variable
                                                 values, audit entries, tool arguments, user or host names, or full paths
One command's usage: kytral-guard <command> --help
An operand that starts with - (an agentId, a tool name) goes after --: kytral-guard revoke -- -agent-7

Environment: KYTRAL_HOME (default ~/.kytral), KYTRAL_SECRET (else $KYTRAL_HOME/secret), KYTRAL_POLICY,
KYTRAL_AUDIENCE (proxy), KYTRAL_BADGE (proxy). Docs: https://github.com/Kytral/kytral-guard
Security issues: never in a public issue, see SECURITY.md.`;

/** One-line view of a decision for humans: ACTION, the finding and rule, and the policy it came from. */
function showDecision(d: { action: "allow" | "confirm" | "block"; rule?: string; reason: string }, source: string): string {
  const home = homedir(), shown = home && source.startsWith(home) ? `~${source.slice(home.length)}` : source;   // one line, not a full path
  return `${d.action.toUpperCase().padEnd(8)}${d.reason === "default" ? "no rule matched" : explain(d)}   (${shown})`;
}
/** Runs the decision engine on two canonical calls (no audit, no kill switch): a catastrophe must be blocked, ls allowed. */
function selfTest(policySource: { policyFile?: string; preset?: string } = {}): string[] {
  const { policy } = loadHookPolicy(policySource), problems: string[] = [];
  for (const [command, want] of [["rm -rf ~", "block"], ["git push --force origin main", "block"], ["ls -la", "allow"]] as const) {
    const d = evaluate(policy, { tool: "Bash", args: { command } });
    if (d.action !== want) problems.push(`self-test: '${command}' is ${d.action}, expected ${want}`);
  }
  return problems;
}

async function cmdHook(args: string[]) {
  const { pos, opt } = parseArgs(args, ["--policy", "--preset", "--timeout"]);
  if (pos.length > 1) fail(`usage: kytral-guard hook <${HOOK_AGENTS.join("|")}|auto> [--policy file | --preset name] [--timeout seconds]`);
  prewarmAnalysis();   // the analysis thread starts while the event, the policy and the state are read
  // the agent's own hook timeout, written by 'init': no wait of the guard may outlast it
  const hookTimeout = Number(opt["--timeout"]);
  const agent = pos[0] ?? "auto";
  // Safety net: a process that ends without an answer (its event loop drained under a plugin that never settles) refuses.
  let answered = false, answerAs: HookAgent = isHookAgent(agent) ? agent : "generic";
  process.once("exit", () => {
    if (answered) return;
    const r = renderHookAnswer(null, { action: "block", rule: "hook-error", reason: "the guard stopped before deciding (fail closed)" }, answerAs);
    try { if (r.stdout) writeSync(1, r.stdout); writeSync(2, (r.stderr || "Kytral Guard refused this call: the guard stopped before deciding (fail closed)") + "\n"); } catch {}
    process.exitCode = r.exitCode || 2;
  });
  let input = ""; try { input = await readStdin(); } catch { input = ""; }   // an unreadable event is refused by runHook (not JSON)
  // Grok Build runs the hooks of Claude Code and Cursor too: its events are answered in its own vocabulary (see runHookAsync)
  try { const raw = JSON.parse(input); if (raw && typeof raw === "object" && !Array.isArray(raw) && isGrokEvent(raw)) answerAs = "grok"; } catch { /* refused below */ }
  // A home wiped or redirected to a blank one, seen before the guard reads or writes anything here (its own journal entry
  // would hide it): one line on stderr after the answer, which stays what it is
  const left = stateLeftBehind() ? LEFT_BEHIND : "";
  const r = await runHookAsync(agent, input, { policyFile: opt["--policy"], preset: opt["--preset"], hookTimeoutMs: Number.isFinite(hookTimeout) && hookTimeout > 0 ? hookTimeout * 1000 : undefined, loadPlugins: () => loadPlugins(pluginSpecs(), VERSION) });
  // The process ends by itself once the answer is written, unless a plugin left a request or a keep-alive connection open
  // (an abandoned remote approval): it is then ended after 1 s, so that the hook never outlives the agent's timeout. Not at
  // once: on Windows, process.exit() a few milliseconds after a fetch() aborts the process (libuv assertion, exit code
  // 0xC0000409), and the agent would lose the answer.
  answered = true;
  process.exitCode = r.exitCode;
  // the warning never changes the answer: a stderr that cannot take it (its reader gone) does not end the process
  if (left) process.stderr.on("error", () => {});
  const stderr = [r.stderr, left].filter(Boolean).join("\n");
  process.stderr.write(stderr ? stderr + "\n" : "", () => process.stdout.write(r.stdout, () => { setTimeout(() => process.exit(r.exitCode), 1000).unref(); }));
}
async function cmdCheck(args: string[]) {
  const k = args.indexOf("--");
  const { pos, opt, on } = parseArgs(k >= 0 ? args.slice(0, k) : args, ["--policy", "--preset", "--tool"], ["--json"]);
  const words = k >= 0 ? args.slice(k + 1) : pos;
  let loaded!: ReturnType<typeof loadHookPolicy>; try { loaded = loadHookPolicy({ policyFile: opt["--policy"], preset: opt["--preset"] }); } catch (e) { fail(errText(e), 1); }
  let call: ToolCall;
  if (words.length && !words.join(" ").trim()) fail(`nothing to check: give a command\n${USAGE.check}`);
  if (words.length) call = { tool: opt["--tool"] ?? "Bash", args: { command: words.join(" ") } };
  else {
    let raw: any; try { raw = JSON.parse(await readStdin()); } catch { return fail('usage: kytral-guard check "<command>" | echo \'{"tool":"Bash","args":{"command":"..."}}\' | kytral-guard check'); }
    call = { tool: String(raw?.tool ?? opt["--tool"] ?? "Bash"), args: raw?.args && typeof raw.args === "object" ? raw.args : typeof raw?.command === "string" ? { command: raw.command } : {} };
  }
  const d = evaluate(loaded.policy, { ...call, cwd: process.cwd() });   // the scripts a command runs are read from here
  console.log(on.has("--json") ? JSON.stringify({ ...d, policy: loaded.source }) : showDecision(d, loaded.source));
  process.exitCode = d.action === "allow" ? 0 : d.action === "confirm" ? 3 : 2;
  // the policy's answer, but right now the kill switch refuses every call whatever it says (stderr: stdout stays one line)
  try { const root = resolveSecret(); if (root && killSwitchState(root)) console.error("kytral-guard: the kill switch is ON: right now every tool call is refused, whatever the policy says ('kytral-guard resume' lifts it)"); } catch {}
}
function cmdInit(args: string[]) {
  const { pos, opt, on } = parseArgs(args, ["--timeout"], ["--all", "--project", "--dry-run", "--force", "--no-agents"]);
  const timeoutSeconds = opt["--timeout"] === undefined ? undefined : Number(opt["--timeout"]);
  if (timeoutSeconds !== undefined && !(Number.isInteger(timeoutSeconds) && timeoutSeconds >= 5 && timeoutSeconds <= 600)) fail("--timeout must be a whole number of seconds between 5 and 600");
  const home = stateDir(); const dry = on.has("--dry-run");
  // what to install is checked before anything is written: a misspelled agent name changes nothing
  // (no agent named: every agent installed on this machine, --all says the same; --no-agents: the secret and policy only)
  const named = pos.length > 0, agents = on.has("--no-agents") ? [] : named ? pos : detectAgents();
  checkAgentNames(agents);
  const cli = defaultCliPath();
  if (agents.length && cli.includes(`${sep}_npx${sep}`) && !on.has("--force"))
    fail(`this copy of kytral-guard runs from a temporary npx cache (${cli}), which npm may delete: the hook would then refuse every tool call.\n  Install it first: npm install -g kytral-guard, then run: kytral-guard init${named ? ` ${agents.join(" ")}` : ""}${on.has("--project") ? " --project" : ""}`);
  const where = stateDirProblem(); if (where) fail(where, 1);
  if (!dry) try { mkdirSync(home, { recursive: true, mode: 0o700 }); } catch (e) { fail(`cannot create ${home} (KYTRAL_HOME): ${errText(e)}`, 1); }
  const fromEnv = process.env.KYTRAL_SECRET !== undefined, file = secretFilePath(), had = existsSync(file);
  // an empty secret file (it signs nothing: an empty secret is always refused) is replaced by a new secret
  const empty = had && !fromEnv && (() => { try { return !readFileSync(file, "utf8").trim(); } catch { return false; } })();
  try { assertStrongSecret(dry ? (empty ? undefined : resolveSecret()) ?? "0123456789abcdef0123456789abcdef0123456789abcdef" : resolveSecret({ create: true })); } catch (e) { fail(secretError(e)); }
  console.log(`secret     ${fromEnv ? "KYTRAL_SECRET (environment)" : `${file} (${empty ? (dry ? "empty: would be replaced" : "was empty: replaced, owner-only") : had ? "kept" : dry ? "would be created" : "created, owner-only"})`}`);
  const policyFile = statePath(undefined, "policy.yaml");
  if (!existsSync(policyFile)) { if (!dry) writeFileSync(policyFile, POLICY_TEMPLATE, { mode: 0o600 }); console.log(`policy     ${policyFile} (${dry ? "would be created" : "created"}: extends the coding-agent preset)`); }
  else console.log(`policy     ${policyFile} (kept)`);
  const done: string[] = [], skipped: string[] = [];
  for (const ag of agents) {
    let r: ReturnType<typeof installHook>;
    // one agent's broken configuration (not valid JSON...) does not leave the others unprotected: said, skipped, exit code 1
    try { r = installHook(ag as (typeof INSTALL_AGENTS)[number], { project: on.has("--project") ? process.cwd() : undefined, dryRun: dry, timeoutSeconds }); }
    catch (e) { skipped.push(ag); console.log(`${"skipped".padEnd(11)}${ag.padEnd(12)} ${errText(e)}. Then run: kytral-guard init ${ag}${on.has("--project") ? " --project" : ""}`); continue; }
    done.push(ag);
    console.log(`${(dry ? (r.changed ? "would add" : "unchanged") : r.changed ? "installed" : "unchanged").padEnd(11)}${ag.padEnd(12)} ${r.file}${r.backup ? `   (previous file: ${r.backup})` : ""}`);
    if (!dry && r.changed) journalChange("settings-change", `installed the hook of ${AGENTS[ag as (typeof INSTALL_AGENTS)[number]].name}`, ag);
    for (const n of r.notes) console.log(`           ${n}`);
    if (dry && r.changed) console.log(r.content.split("\n").map(l => `           | ${l}`).join("\n"));
  }
  if (!agents.length && !on.has("--no-agents")) console.log(`agents     none found (${INSTALL_AGENTS.join(", ")}): name one with 'kytral-guard init <agent>' once it is installed`);
  // a policy that does not load (edited by hand) makes every hook refuse every call: said in one line, with how to check it
  let problems: string[];
  try { problems = selfTest(); }
  catch (e) { problems = [`policy does not load (${errText(e)}): every agent tool call is refused until it is fixed. Check it: kytral-guard policy validate ${process.env.KYTRAL_POLICY ?? policyFile}`]; }
  console.log(problems.length ? problems.map(p => `!! ${p}`).join("\n") : "self-test  rm -rf ~ and a force-push to main are blocked, ls is allowed");
  if (problems.length || skipped.length) process.exitCode = 1;
  if (problems.length) return;
  if (done.length && !dry) {
    const scope = on.has("--project") ? " --project" : "";
    console.log(`\nKytral Guard now checks every tool call of ${done.map(ag => AGENTS[ag as (typeof INSTALL_AGENTS)[number]].name).join(", ")}.
  Try it:         kytral-guard check "rm -rf ~"
  See and decide: kytral-guard dashboard
  A false alarm:  kytral-guard allow "<command>"
  Stop all:       kytral-guard kill        (and kytral-guard resume)
  Remove:         kytral-guard uninstall ${named ? done.join(" ") : "--all"}${scope}`);
  }
  if (skipped.length) console.log(`\nNot protected yet: ${skipped.map(ag => AGENTS[ag as (typeof INSTALL_AGENTS)[number]].name).join(", ")} (skipped above: fix the file it names, then run the command it gives).`);
  // apps whose MCP servers no hook checks (Claude Desktop, VS Code, Cline...): say how to protect them
  const apps = (() => { try { return listMcp(); } catch { return []; } })().filter(f => f.servers.some(s => !s.remote && !s.wrapped));
  if (apps.length && !on.has("--project"))
    console.log(`\nMCP servers of ${apps.map(f => f.name).join(", ")} are not checked yet: kytral-guard mcp list, then kytral-guard mcp wrap`);
}
const shQuote = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;
/**
 * kytral-guard allow "<command>": agents may run this exact command without asking (a rule matching the raw text, first in
 * the hook policy). It stays blocked if it ever turns catastrophic (a script it runs was changed), unless it already is
 * and --force says so. Agents cannot run this command (guard-tamper).
 */
function cmdAllow(args: string[]) {
  const usage = 'usage: kytral-guard allow "<command>" [--force] [--policy file] | kytral-guard allow --call <n> [--force] | kytral-guard allow --list | kytral-guard allow --remove <rule>';
  const { pos, opt, on } = parseArgs(args, ["--policy", "--remove", "--call"], ["--force", "--list"]);
  if (on.has("--list")) {
    if (pos.length) fail(usage);
    const file = opt["--policy"] ?? process.env.KYTRAL_POLICY ?? statePath(undefined, "policy.yaml");
    if (!existsSync(file)) return void console.log(`no allowed command (${file} does not exist)`);
    // a policy that does not load allows nothing at all: every call is refused, which "no allowed command" would hide
    try { loadPolicy(readFileSync(file, "utf8")); } catch (e) { fail(`${file} does not load (${errText(e)}): every agent tool call is refused until it is fixed (kytral-guard policy validate ${file})`, 1); }
    const allowed = listExceptions(file).filter(x => x.action === "allow");
    if (!allowed.length) console.log(`no allowed command in ${file}`);
    for (const r of allowed) console.log(`${r.name.padEnd(16)} ${r.command}${r.evenIfCatastrophic ? "   (even if catastrophic)" : ""}`);
    return;
  }
  if (opt["--remove"] !== undefined) {
    if (pos.length) fail(usage);
    const name = opt["--remove"], file = hookPolicyFile(opt["--policy"]);
    let found = false;
    try { found = removeRule(file, name); } catch (e) { fail((e as Error).message, 1); }
    if (!found) fail(`no rule named '${name}' in ${file} (see kytral-guard allow --list)`, 1);
    console.log(`removed    ${name} from ${file}`);
    return;
  }
  // the command: typed, or the exact text of a call the dashboard shows (--call <n>, the seq of its log entry: no quoting)
  let command = (pos[0] ?? "").trim(), cwd = process.cwd();
  if (opt["--call"] !== undefined) {
    const seq = Number(opt["--call"]);
    if (pos.length || !Number.isSafeInteger(seq) || seq < 0) fail(usage);
    // only a text this home's guard kept, signed for its file, can become an exception (one copied in is not read)
    let kept: KeptCall[] = [];
    try { kept = readKeptCalls(rootSecret(true)).filter(k => k.seq === seq); } catch (e) { fail(`the kept texts cannot be read (${errText(e)}): type the command instead: kytral-guard allow "<command>"`, 1); }
    if (!kept.length) fail(`no text is kept for call ${seq}: it is older than the kept texts, or keeping them is off. Type the command instead: kytral-guard allow "<command>"`, 1);
    if (kept.length > 1) fail(`call ${seq} is kept more than once: type the command instead`, 1);
    if (!isShellTool(kept[0].tool)) fail(`call ${seq} is not a shell command: exceptions are made for exact shell commands`, 1);
    if (kept[0].text.includes(MASK) || kept[0].text.endsWith("…")) fail(`the text of call ${seq} was masked (it held a secret) or cut: type the command instead`, 1);
    command = kept[0].text.trim(); if (kept[0].cwd) cwd = kept[0].cwd;
  } else if (pos.length !== 1 || !command) fail(usage);
  if (/[\r\n]/.test(command)) fail("allow takes a single command line", 1);
  if (HIDDEN_CHARACTERS.test(command)) fail("this command holds control or invisible characters, which can make it look like another command: no exception can be made for it", 1);
  const file = hookPolicyFile(opt["--policy"]);
  let d: ReturnType<typeof evaluate>, matched: ReturnType<typeof matchingRules>, base: Policy;
  try {
    const policy = loadPolicy(readFileSync(file, "utf8")), call = { tool: "Bash", args: { command }, cwd };
    d = evaluate(policy, call); base = withoutExceptionsFor(policy, command); matched = matchingRules(base, call);
  } catch (e) { return fail(`${file}: ${(e as Error).message}`, 1); }
  if (d.action === "allow") return void console.log(`already allowed: ${command}   (${d.reason === "default" ? "no rule matched" : explain(d)})`);
  // the exception goes first: every rule that matches counts, not only the one deciding now (an "always ask" exception)
  const lock = exceptionLock(matched, matched[0]?.action ?? base.default, "allow");
  if (lock === "self") fail(`not allowed: ${command} would turn Kytral Guard off or weaken it (rule guard-tamper), so it stays blocked, even with --force.\n  Edit ${file} by hand if you really mean it.`, 1);
  if (lock === "catastrophic" && !on.has("--force"))
    fail(`not allowed: ${explain(matched.find(m => m.action === "block") ?? matched[0] ?? d)}.\n  This is blocked because it can do irreversible damage. If agents really must run it without asking, run:\n  ${opt["--call"] !== undefined ? `kytral-guard allow --force --call ${opt["--call"]}` : `kytral-guard allow --force ${shQuote(command)}`}`, 1);
  let name = "";
  try { name = addException(file, command, "allow", { evenIfCatastrophic: lock === "catastrophic" }); } catch (e) { fail((e as Error).message, 1); }
  console.log(`allowed    ${command}
           was: ${explain(d)}
           rule ${name} in ${file}${lock === "catastrophic" ? "" : "; still blocked if it ever turns catastrophic"}
           undo: kytral-guard allow --remove ${name}`);
}
/**
 * kytral-guard uninstall <agent...> | --all: removes the hooks (and, with --all, takes the proxy off the MCP servers of the
 * apps, which would no longer start once the package is gone). Agents cannot run it (guard-tamper).
 */
function cmdUninstall(args: string[]) {
  const { pos, on } = parseArgs(args, [], ["--project", "--dry-run", "--all"]);
  const all = on.has("--all"), dry = on.has("--dry-run"), project = on.has("--project") ? process.cwd() : undefined;
  const agents = all ? [...INSTALL_AGENTS] : pos;
  if (!agents.length) fail(USAGE.uninstall);
  checkAgentNames(agents);   // before changing anything
  const absent: string[] = []; let removed = 0;
  for (const ag of agents) {
    let r!: ReturnType<typeof uninstallHook>;
    try { r = uninstallHook(ag as (typeof INSTALL_AGENTS)[number], { project, dryRun: dry }); } catch (e) { fail((e as Error).message, 1); }
    const note = r.notes.filter(n => n !== "no configuration file").join("; ");
    if (r.changed) {
      removed++; console.log(`${(dry ? "would remove" : "removed").padEnd(13)}${ag.padEnd(12)} ${r.file}${r.backup ? `   (previous file: ${r.backup})` : ""}`);
      if (!dry) journalChange("settings-change", `removed the hook of ${AGENTS[ag as (typeof INSTALL_AGENTS)[number]].name}`, ag);
    }
    else if (all && !note) absent.push(ag);   // --all: the agents without a hook fit on one line
    else console.log(`${"not found".padEnd(13)}${ag.padEnd(12)} ${r.file}${note ? `   (${note})` : ""}`);
  }
  if (absent.length) console.log(`${"not found".padEnd(13)}${absent.join(", ")}`);
  // the MCP servers of the apps, and of the files wrapped with --file (recorded), run Kytral Guard's proxy by its path:
  // they would no longer start without the package
  let unwrapped = 0;
  if (all && !project) {
    let changes: McpChange[] = [];
    const recorded = recordedFiles(), title = (c: McpChange) => c.client === "file" ? c.file : `${c.name}   ${c.file}`;
    try { changes = [...unwrapMcp({ dryRun: dry }), ...(recorded.length ? unwrapMcp({ files: recorded, dryRun: dry }) : [])]; }
    catch (e) { console.log(`!!           MCP servers: ${(e as Error).message}`); process.exitCode = 1; }
    for (const c of changes) {
      if (c.error) { console.log(`!!           ${title(c)}: ${c.error}`); process.exitCode = 1; continue; }
      if (!c.changed.length) continue;
      unwrapped += c.changed.length;
      console.log(`${(dry ? "would unwrap" : "unwrapped").padEnd(13)}${title(c)}: ${c.changed.join(", ")}${c.backup ? `   (previous file: ${c.backup})` : ""}`);
      if (!dry) journalChange("settings-change", `stopped running the MCP servers ${c.changed.join(", ")} of ${c.name} through Kytral Guard`, c.client);
    }
  }
  if (dry || !all || project) return;
  if (unwrapped) console.log("\nRestart the apps above: their MCP servers start without the proxy again.");
  console.log(`\n${removed || unwrapped ? "Kytral Guard no longer checks the agents and apps of this user." : "Kytral Guard was not installed in any agent or app of this user."}
  Remove the program:  npm uninstall -g kytral-guard
  (hooks installed in a project with --project stay: run 'kytral-guard uninstall --all --project' there first)
  Its settings, log and secret stay in ${stateDir()}: delete that folder to remove them too.`);
}
/** kytral-guard mcp list | wrap | unwrap: the MCP servers of the AI apps of this machine, run through the proxy or not. */
function cmdMcp(args: string[]) {
  const usage = `usage: kytral-guard mcp list | wrap | unwrap [app...] [--file config.json] [--preset name | --policy file] [--dry-run]\n  apps: ${MCP_CLIENTS.map(c => c.id).join(", ")}`;
  const [sub, ...rest] = args;
  const { pos, opt, on } = parseArgs(rest, ["--file", "--policy", "--preset"], ["--dry-run"]);
  if (sub !== "list" && sub !== "wrap" && sub !== "unwrap") fail(usage);
  if (opt["--policy"] !== undefined && opt["--preset"] !== undefined) fail("use --policy or --preset, not both");
  const o: McpOptions = { clients: pos, files: opt["--file"] ? [resolve(opt["--file"])] : undefined, dryRun: on.has("--dry-run"),
    policyArgs: opt["--policy"] ? ["--policy", resolve(opt["--policy"])] : opt["--preset"] ? ["--preset", opt["--preset"]] : undefined };
  if (o.policyArgs?.[0] === "--preset" && !Object.hasOwn(PRESETS, o.policyArgs[1])) fail(`unknown preset (${Object.keys(PRESETS).join(", ")})`);   // not repeated
  const none = () => console.log(`no MCP configuration found (${MCP_CLIENTS.map(c => c.name).join(", ")}): name a JSON file with --file`);
  // the commands to suggest name what this one named: the file given, or the apps
  const target = opt["--file"] ? ` --file ${opt["--file"]}` : pos.length ? ` ${pos.join(" ")}` : "";
  const title = (f: { client: string; name: string; file: string }) => f.client === "file" ? f.file : `${f.name}   ${f.file}`;
  if (sub === "list") {
    // with the secret, the badges of wrapped servers are checked too (a new secret refuses every call of the old ones)
    let secret: string | undefined; try { secret = assertStrongSecret(resolveSecret()); } catch {}
    // nothing named: the apps, and the files wrapped earlier with --file (recorded in KYTRAL_HOME)
    const recorded = o.files || pos.length ? [] : recordedFiles();
    let found: McpFile[] = []; try { found = [...listMcp({ ...o, secret }), ...(recorded.length ? listMcp({ files: recorded, secret }) : [])]; } catch (e) { fail((e as Error).message); }
    if (!found.length) return none();
    for (const f of found) {
      console.log(title(f));
      if (f.error) { console.log(`  !! ${f.error}`); process.exitCode = 1; }
      else if (!f.servers.length) console.log("  (no server)");
      for (const s of f.servers) {
        console.log(`  ${s.name.padEnd(20)} ${s.remote ? "remote   cannot be wrapped (a URL)" : s.problem ? "local    BROKEN         " : s.wrapped ? "local    protected      " : "local    NOT protected  "} ${s.command.length > 70 ? s.command.slice(0, 70) + "…" : s.command}`);
        if (s.problem) console.log(`  ${"".padEnd(20)} ${s.problem}: every call is refused, or it does not start`);
      }
    }
    // a file recorded earlier is repaired with its own --file; the apps (or the file named) with the target of this command
    const wrapCommand = (f: McpFile) => `kytral-guard mcp wrap${f.client === "file" && !o.files ? ` --file ${f.file}` : target}`;
    const lines = new Map<string, { open: number; broken: number }>();
    for (const f of found) {
      const open = f.servers.filter(s => !s.remote && !s.wrapped).length, broken = f.servers.filter(s => s.problem && !/revoked|revocation/.test(s.problem)).length;
      if (!open && !broken) continue;
      const k = wrapCommand(f), n = lines.get(k) ?? { open: 0, broken: 0 };
      lines.set(k, { open: n.open + open, broken: n.broken + broken });
    }
    if (lines.size) console.log("");
    for (const [cmd, n] of lines) {
      if (n.open) console.log(`${n.open} local server(s) not protected: ${cmd}`);
      if (n.broken) console.log(`${n.broken} wrapped server(s) no longer work: ${cmd} repairs them`);
    }
    return;
  }
  let secret = ""; let changes: McpChange[] = [];
  try {
    if (sub === "wrap") {
      secret = assertStrongSecret(o.dryRun ? resolveSecret() ?? "0123456789abcdef0123456789abcdef0123456789abcdef" : resolveSecret({ create: true }));
      const cli = defaultCliPath();
      if (cli.includes(`${sep}_npx${sep}`)) fail(`this copy of kytral-guard runs from a temporary npx cache (${cli}): install it first (npm install -g kytral-guard), then run: kytral-guard mcp wrap`);
      changes = wrapMcp(secret, o);
    } else changes = unwrapMcp(o);
  } catch (e) { fail((e as Error).message, 1); }
  if (!changes.length) return none();
  for (const c of changes) {
    const verb = sub === "wrap" ? (o.dryRun ? "would wrap" : "wrapped") : (o.dryRun ? "would unwrap" : "unwrapped");
    if (c.error) { console.log(`!!           ${title(c)}: ${c.error}`); process.exitCode = 1; continue; }
    console.log(`${(c.changed.length ? verb : "unchanged").padEnd(13)}${title(c)}${c.changed.length ? `: ${c.changed.join(", ")}` : ""}${c.backup ? `   (previous file: ${c.backup})` : ""}`);
    if (!o.dryRun && c.changed.length) journalChange(sub === "wrap" ? "mcp-wrap" : "settings-change",
      `${sub === "wrap" ? "ran" : "stopped running"} the MCP servers ${c.changed.join(", ")} of ${c.name} through Kytral Guard`, c.client);
    for (const r of c.renewed ?? []) console.log(`             ${r.name}: ${o.dryRun ? "would be repaired" : "repaired"} (${r.why})`);
    for (const s of c.skipped) console.log(`             ${s.name}: ${s.why}`);
  }
  if (sub === "wrap" && changes.some(c => c.changed.length) && !o.dryRun)
    console.log(`\nRestart these apps to load the change. Every tool call of these servers is now checked (${o.policyArgs ? o.policyArgs.join(" ") : `${mcpPolicyPath()}, else the strict preset`});
a call that needs a human waits for you in kytral-guard dashboard while it is open, and is refused otherwise (see docs/mcp-proxy.md). Undo: kytral-guard mcp unwrap${target}`);
}
/**
 * kytral-guard doctor: checks the setup of this machine and runs a self-test, in words for its owner (paths, files and errors
 * as they are). doctor --report [--policy file]: a diagnostic to paste into a public bug report, built from a whitelist of
 * formats (bug-report.ts) on stdout alone; --policy: the file the proxies are given.
 */
async function cmdDoctor(args: string[]) {
  const { pos, opt, on } = parseArgs(args, ["--policy"], ["--report"]);
  if (pos.length || (opt["--policy"] !== undefined && !on.has("--report"))) fail(USAGE.doctor);
  if (on.has("--report")) {
    // stdout: the report alone, for a pipe or a copy; the reminder goes to stderr
    console.log(doctorReport({ version: VERSION, policyFile: opt["--policy"] }));
    console.error("kytral-guard: redacted for a public bug report (no secrets, variable values, audit entries, tool arguments, user or host names, full paths), but a short password used as an MCP server name would still be shown: read it before posting");
    return;
  }
  let bad = 0, warned = 0, hooks = 0, wrapped = 0;
  const ok = (m: string) => console.log(`ok    ${m}`), warn = (m: string) => { warned++; console.log(`warn  ${m}`); }, err = (m: string) => { bad++; console.log(`FAIL  ${m}`); };
  const major = Number(process.versions.node.split(".")[0]);
  (major >= 22 ? ok : err)(`node ${process.versions.node}${major >= 22 ? "" : " (Node.js 22 or later is required)"}`);
  const home = stateDir(), homeProblem = stateDirProblem();
  if (homeProblem) err(homeProblem);
  else if (!existsSync(home)) warn(`${home} does not exist yet (run 'kytral-guard init')`);
  else { ok(`KYTRAL_HOME ${home}`); if (process.platform !== "win32" && (statSync(home).mode & 0o077)) warn(`${home} is readable by other users (chmod 700 it)`); }
  // a home wiped or redirected to a blank one: what the hooks say on stderr, here with the paths
  const left = stateLeftBehind();
  if (left) warn(`no kill switch state here: none of ${left.here.join(", ")} exists, although ${left.there.join(", ")} still exist${left.there.length > 1 ? "" : "s"} (wiped or redirected?): a kill in force there is not seen here`);
  let secret: string | undefined, policyLoads = true, killed = false;
  try { secret = assertStrongSecret(resolveSecret()); ok(`secret from ${process.env.KYTRAL_SECRET !== undefined ? "KYTRAL_SECRET" : secretFilePath()}`); }
  catch (e) { err(`secret: ${secretError(e)}`); }
  try { const { policy, source } = loadHookPolicy(); ok(`hook policy ${source} (${policy.rules.length} rules${policy.extends ? `, extends ${policy.extends}` : ""})`); }
  catch (e) { policyLoads = false; err(`hook policy: ${errText(e)} - every agent tool call is refused until it is fixed (kytral-guard policy validate <file> says why)`); }
  try { const specs = pluginSpecs(); if (specs.length) { const ps = await loadPlugins(specs, VERSION); ok(`plugins: ${ps.map(p => p.name).join(", ")}`); } }
  catch (e) { err(`plugins: ${(e as Error).message} - every agent tool call is refused until it is fixed`); }
  if (secret) {
    // as an agent hook finds it: kill-switch.json checked against the last kill or resume the audit log records
    try {
      const state = killSwitchState(secret);
      killed = !!state;
      (state ? warn : ok)(state ? `${state} ('kytral-guard resume' lifts it)` : "kill switch off");
    } catch (e) { err(`kill switch: the audit log cannot be read (${errText(e)}): every agent tool call is refused until it can be`); }
    try { const r = verifyAuditFile(statePath(process.env.KYTRAL_AUDIT, "audit.jsonl"), auditKey(secret)); (r.exitCode === 0 ? ok : r.exitCode === 3 ? warn : err)(describeAudit(r).join(" - ")); }
    catch (e) { err(`audit: ${(e as Error).message}`); }
  }
  const seen = new Set<string>(), real = (f: string) => { try { return realpathSync.native(f).toLowerCase(); } catch { return f.toLowerCase(); } };
  // disableAllHooks: true turns every Claude Code hook off, the guard's too: a failure wherever it is set, said once per file
  const hooksOff = (p: string) => /disableAllHooks: true/.test(p), offFiles = new Set<string>();
  for (const ag of INSTALL_AGENTS) for (const project of [undefined, process.cwd()]) {
    const r = inspectHook(ag, { project });
    if (seen.has(real(r.file))) continue; seen.add(real(r.file));   // the project may be the home directory
    const rest = r.problems.filter(p => !hooksOff(p));
    for (const p of r.problems.filter(hooksOff)) { offFiles.add(real(r.file)); err(p); }
    if (r.installed) { hooks++; (rest.length ? warn : ok)(`${ag} hook in ${r.file}${rest.length ? `: ${rest.join("; ")}` : ""}`); }
    else for (const p of rest) warn(p);
  }
  for (const f of [join(process.cwd(), ".claude", "settings.json"), join(process.cwd(), ".claude", "settings.local.json")]) {
    if (offFiles.has(real(f))) continue;
    try { if (JSON.parse(readFileSync(f, "utf8"))?.disableAllHooks === true) err(`${f} sets disableAllHooks: true: no hook runs in this project`); } catch {}
  }
  // the apps' MCP configurations, and the files wrapped earlier with --file (recorded in KYTRAL_HOME)
  const recorded = recordedFiles();
  for (const f of (() => { try { return [...listMcp({ secret }), ...(recorded.length ? listMcp({ files: recorded, secret }) : [])]; } catch { return []; } })()) {
    const open = f.servers.filter(s => !s.remote && !s.wrapped).map(s => s.name), done = f.servers.filter(s => s.wrapped && !s.problem).length;
    const wrapIt = `kytral-guard mcp wrap ${f.client === "file" ? `--file ${f.file}` : f.client}`;
    wrapped += done;
    for (const s of f.servers) if (s.problem) warn(`${f.name}: MCP server ${s.name}: ${s.problem}, so every call is refused or it does not start${/revoked|revocation/.test(s.problem) ? "" : ` ('${wrapIt}' repairs it)`}`);
    if (f.error) warn(`${f.name} MCP servers${f.client === "file" ? "" : ` (${f.file})`}: ${f.error}`);
    else if (open.length) warn(`${f.name}: MCP server(s) not protected: ${open.join(", ")} ('${wrapIt}')`);
    else if (done) ok(`${f.name}: ${done} MCP server(s) run through the proxy`);
  }
  // a working guard that no agent runs protects nothing: say so rather than "all good" (the SDK alone needs neither)
  if (!hooks && !wrapped) warn("no agent or app runs Kytral Guard yet: 'kytral-guard init' adds its hook to the agents of this machine, 'kytral-guard mcp wrap' protects the MCP servers of AI apps");
  // the self-test runs the hook policy: when it does not load, that FAIL above says it already
  if (policyLoads) {
    const failed = (() => { try { return selfTest(); } catch (e) { return [errText(e)]; } })();
    for (const p of failed) err(p);
    if (!failed.length) ok("self-test: catastrophes blocked, routine commands allowed");
  }
  const s = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
  // the last line says what matters most: something to fix, everything stopped, nothing protected, or how well it works
  console.log(bad ? `\n${s(bad, "problem")} to fix (FAIL above).`
    : killed ? "\nKill switch ON: every tool call of every guarded agent and MCP server is refused ('kytral-guard resume' lifts it)."
    : !hooks && !wrapped ? "\nNot protecting anything yet: 'kytral-guard init' protects the coding agents of this machine, 'kytral-guard mcp wrap' the MCP servers of AI apps."
    : `\n${warned ? `Works, with ${s(warned, "warning")} above` : "All good"}: ${s(hooks, "agent hook")}${wrapped ? `, ${s(wrapped, "MCP server")} through the proxy` : ""}.`);
  process.exitCode = bad ? 1 : 0;
}
/** kytral-guard dashboard: serves the page on 127.0.0.1 until Ctrl+C, and signs the person in with one-time links. */
async function cmdDashboard(args: string[]) {
  const { pos, opt, on } = parseArgs(args, ["--port"], ["--no-open"]);
  if (pos.length) fail("usage: kytral-guard dashboard [--port n] [--no-open]");
  const port = opt["--port"] === undefined ? 0 : Number(opt["--port"]);
  if (!Number.isInteger(port) || port < 0 || port > 65535) fail("--port must be a port number (1-65535)");
  let d!: DashboardHandle;
  try { d = await startDashboard({ port, version: VERSION, onWarn: m => console.error(`!! ${m}`) }); } catch (e) { fail((e as Error).message, 1); }
  const link = d.newLink(), opened = !on.has("--no-open") && openInBrowser(link), tty = !!process.stdin.isTTY;
  console.log(`Kytral Guard dashboard, on this computer only:\n  ${link}\n${opened ? "Opened in your browser." : "Open this link in your browser."} It signs you in once.${tty ? " Press Enter for a new link," : ""} Ctrl+C to stop.`);
  if (tty) { process.stdin.setEncoding("utf8"); process.stdin.on("data", () => console.log(`  ${d.newLink()}`)); }
  const stop = () => { void d.close().then(() => process.exit(0)); };
  process.once("SIGINT", stop); process.once("SIGTERM", stop);
}
function cmdPolicy(args: string[]) {
  const usage = "usage: kytral-guard policy presets | show [--policy file | --preset name] | validate <file>";
  if (args[0] === "presets") { if (parseArgs(args.slice(1), []).pos.length) fail(usage); for (const name of Object.keys(PRESETS)) console.log(name); return; }
  if (args[0] === "show") {
    const { pos, opt } = parseArgs(args.slice(1), ["--policy", "--preset"]); if (pos.length) fail(usage);
    try { const { policy, source } = loadHookPolicy({ policyFile: opt["--policy"], preset: opt["--preset"] }); console.log(`# ${source}\n${stringify(policy, { lineWidth: 0 })}`); } catch (e) { fail((e as Error).message, 1); }
    return;
  }
  if (args[0] === "validate") {
    const { pos } = parseArgs(args.slice(1), []);
    if (pos.length !== 1) fail(usage);
    // a file error in words; a YAML or rule error whole (its snippet points at the line), after the file's name
    try { const p = loadPolicy(readFileSync(pos[0], "utf8")); console.log(`ok: ${p.rules.length} rules${p.extends ? ` (extends ${p.extends})` : ""}`); }
    catch (e) { fail((e as NodeJS.ErrnoException).path ? errText(e) : `${pos[0]}: ${(e as Error).message}`, 1); }
    return;
  }
  fail(usage);
}

/**
 * The proxy: kytral-guard [proxy] [--policy file | --preset name] -- <mcp server command...>. Fail closed, before the proxy
 * reads a secret or a file or starts the server: an unknown option before -- (--polcy, --policy=file, -p) or an operand there
 * (a file without --policy) would leave the server running under another policy. After the first --, every argument is the
 * server's, passed as it is.
 */
function cmdProxy(args: string[]): Promise<void> {
  const k = args.indexOf("--"), { pos, opt } = parseArgs(k < 0 ? args : args.slice(0, k), ["--policy", "--preset"]);
  if (k < 0 || pos.length || !args[k + 1]) fail(USAGE.proxy);
  if (opt["--policy"] !== undefined && opt["--preset"] !== undefined) fail("use --policy or --preset, not both");
  if (opt["--preset"] !== undefined && !Object.hasOwn(PRESETS, opt["--preset"])) fail(`unknown preset (${Object.keys(PRESETS).join(", ")})`);   // not repeated
  return main(args.slice(k + 1), { policyFile: opt["--policy"], preset: opt["--preset"] });
}
const usageOf = (c: string | undefined) => c !== undefined && Object.hasOwn(USAGE, c) ? USAGE[c] : undefined;

if (a[0] === undefined || a[0] === "--help" || a[0] === "-h" || (a[0] === "help" && !usageOf(a[1]))) console.log(HELP);
else if (a[0] === "help") console.log(usageOf(a[1]));
// <command> --help: its usage, and nothing done. Not an answer for a hook: agents read exit code 0 with no output as
// "no objection", so a hook command that carries --help (a broken configuration) refuses, as any hook error does.
else if (usageOf(a[0]) && helpAsked(a.slice(1))) { if (a[0] === "hook") fail(USAGE.hook); else console.log(usageOf(a[0])); }
else if (a[0] === "--version" || a[0] === "-v" || a[0] === "version") console.log(VERSION);
else if (a[0] === "hook") await cmdHook(a.slice(1));
else if (a[0] === "check") await cmdCheck(a.slice(1));
else if (a[0] === "init") cmdInit(a.slice(1));
else if (a[0] === "allow") cmdAllow(a.slice(1));
else if (a[0] === "uninstall") cmdUninstall(a.slice(1));
else if (a[0] === "mcp") cmdMcp(a.slice(1));
else if (a[0] === "doctor") await cmdDoctor(a.slice(1));
else if (a[0] === "dashboard") await cmdDashboard(a.slice(1));
else if (a[0] === "policy") cmdPolicy(a.slice(1));
else if (a[0] === "proxy") await cmdProxy(a.slice(1));
else if (a[0] === "badge") { // kytral-guard badge <agentId> <tool1,tool2|*> [lifetime] [--once]
  const { pos, on } = parseArgs(a.slice(1), [], ["--once"]);
  if (pos.length < 2 || pos.length > 3) fail(USAGE.badge);
  const ttl = lifetimeSeconds(pos[2] ?? "1h");
  if (ttl === null) fail("invalid lifetime: seconds (3600), or a number with m, h, d or y (90m, 12h, 30d, 1y)");   // not repeated: it may be anything
  let secret: string, aud: string; try { secret = assertStrongSecret(resolveSecret()); aud = assertAudience(process.env.KYTRAL_AUDIENCE); } catch (e) { console.error(`kytral-guard: ${(e as Error).message}`); process.exit(2); }
  console.log(issueBadge(secret, pos[0], pos[1].split(","), ttl!, Date.now(), { aud, once: on.has("--once") }));
  // on stderr: the badge alone on stdout goes into $(...) and configuration files
  console.error(`kytral-guard: badge valid until ${new Date(Date.now() + ttl! * 1000).toISOString()}; every call is refused (badge: expired) after that`);
} else if (a[0] === "revoke") { // kytral-guard revoke <badgeId|agentId|nonce>
  // an option given by mistake (revoke --all) is refused, not revoked as an id (proxies never forget a revocation): an id that starts with - goes after --
  const { pos } = parseArgs(a.slice(1), []);
  if (pos.length !== 1 || !pos[0]) fail(USAGE.revoke);
  new FileSet(statePath(process.env.KYTRAL_REVOCATIONS, "revocations.json")).add(pos[0]); console.log(`revoked ${pos[0]}`);
} else if (a[0] === "kill" || a[0] === "resume") { // kytral-guard kill [--by <name>] | resume [--by <name>]
  const { pos, opt } = parseArgs(a.slice(1), ["--by"]);
  if (pos.length) fail(USAGE.kill);
  const where = stateDirProblem(); if (where) fail(where, 1);
  // kill needs no secret: an emergency stop must not depend on configuration. resume is signed with the proxies' key.
  const secret = a[0] === "resume" ? rootSecret(true)! : undefined, by = cliApprover(opt["--by"]);
  let r!: KillSwitchChange;
  // what an agent hook found before a resume: anything but null blocked every call (a kill, or a state this version does not
  // accept: a v1 state, another id, a replay), even when the file says "off"
  let blocked: string | null | undefined;
  if (secret !== undefined) try { blocked = killSwitchState(secret); } catch { /* the resume says why below */ }
  // kill is signed with the proxies' key when a strong secret is set (its generation then orders it) and its audit entry is
  // HMAC-chained with the same secret; it works without one (unsigned kill, unauthenticated entry).
  let key: Buffer | undefined, journalKey: Buffer | undefined;
  if (secret === undefined) {
    let root: string | undefined; try { root = process.env.KYTRAL_AUDIT_SECRET ?? resolveSecret(); } catch {}
    try { key = killSwitchKey(root as string); journalKey = auditKey(root as string); } catch {}
  }
  try { r = secret === undefined ? engageKillSwitch(by, { key, auditKey: journalKey }) : releaseKillSwitch(secret, by); } catch (e) { fail(errText(e), 1); }
  if (secret === undefined && !key) console.error("kytral-guard: no usable secret (KYTRAL_SECRET / KYTRAL_AUDIT_SECRET): the kill was written unsigned and journaled without a MAC; it still stops every proxy");
  if (r.unlocked) console.error(`kytral-guard: lock not taken (${show(r.unlocked)}): written without it, atomically (a kill never waits for a lock)`);
  // the record first (scripts read it), then what it means
  console.log([`kill switch ${r.state.killed ? "ON" : "OFF"}`, `by=${r.state.by}`, `at=${r.state.at}`, `was=${r.was}`,
    `generation=${"gen" in r.state ? r.state.gen : "none (unsigned)"}`, r.path].map(show).join("\t"));
  console.log(r.state.killed ? `\nEvery guarded agent and MCP proxy using ${stateDir()} now refuses tool calls, within 1 s. Lift it with: kytral-guard resume`
    : blocked === null ? "\nThe kill switch was already off: nothing was stopped."
    : "\nAgents and MCP proxies run again: every tool call is checked as before.");
  // A kill written while the audit log could not be read or record it: in force, said last, exit code 3. Not 0: a script
  // would take it for a clean kill and the broken log would go unseen (resume is refused until it is fixed); not 1: that
  // says nothing was written.
  for (const w of r.warnings ?? []) console.error(`kytral-guard: warning: ${show(w)}`);
  if (r.warnings?.length) process.exitCode = 3;
} else if (a[0] === "audit") { // kytral-guard audit verify [file]
  const usage = "usage: kytral-guard audit verify [file]   (default: $KYTRAL_AUDIT, else $KYTRAL_HOME/audit.jsonl; exit 0 valid, 1 broken, 3 unverifiable lines)";
  if (a[1] !== "verify") fail(usage);
  const { pos } = parseArgs(a.slice(2), []);
  if (pos.length > 1) fail(usage);
  // Verified with the proxies' key (KYTRAL_AUDIT_SECRET, else the deployment secret): without it nothing can be verified.
  const key = auditKey(rootSecret(true)!);
  let r!: ReturnType<typeof verifyAuditFile>;
  try { r = verifyAuditFile(statePath(pos[0] ?? process.env.KYTRAL_AUDIT, "audit.jsonl"), key); } catch (e) { fail((e as Error).message, 1); }
  for (const line of describeAudit(r)) console.log(show(line));
  if (r.exitCode === 1) console.log("\nKeep a copy of this log as it is: it was changed outside Kytral Guard, or written with another key. docs/audit-log.md says what to do next.");
  process.exit(r.exitCode);
} else if (a[0] === "known") { // kytral-guard known list | known remove <tool> [agentId] [server] [--by <name>]
  const usage = "usage: kytral-guard known list | known remove <tool> [agentId] [server] [--by <name>]   (every agent and server unless narrowed)";
  const root = rootSecret(false), path = knownToolsPath();
  const corrupt = (why: string) => console.error(`kytral-guard: ${path} is corrupt (${why}): it grants nothing; fix or delete it`);
  if (a[1] === "list") {
    if (parseArgs(a.slice(2), []).pos.length) fail(usage);
    // Signatures are checked with the proxies' key (KYTRAL_AUDIT_SECRET, else the deployment secret); without it entries are listed unverified.
    const list = new FileSet(path, root ? { signKey: knownToolsKey(root, path), onReject: k => console.error(`kytral-guard: rejected (${BAD_GRANT}): ${k}`), onCorrupt: corrupt } : { onCorrupt: corrupt });
    if (!root) console.error("kytral-guard: KYTRAL_SECRET not set, signatures NOT verified (listing raw entries)");
    let shown = 0;
    for (const [k, v] of list.entries()) {
      let key: unknown[] = ["?", "?", "?"]; try { key = JSON.parse(k); } catch {}
      const g = root ? parseGrant(k, v) : null;
      console.log([...key, ...(!root ? ["unverified"] : g ? [g.approver, g.approvedAt] : ["INVALID (not an exact tool name)"])].map(show).join("\t")); shown++;
    }
    if (!shown && !list.corrupt) console.error("kytral-guard: no MCP tool is approved for good");   // stderr: stdout stays one line per grant
    if (list.corrupt) process.exit(1);
  } else if (a[1] === "remove") {
    const { pos, opt } = parseArgs(a.slice(2), ["--by"]);
    const [tool, agentId, server] = pos;
    if (!tool || pos.length > 3) fail(usage);
    // Removing only restricts: no secret needed, and other entries are rewritten untouched (a different secret must not wipe them).
    // Each removed grant is tombstoned first (anti-replay): restoring a backup of known-tools.json does not bring it back.
    let removed: [string, string, string][] = [];
    try { removed = removeGrants(new FileSet(path, { onCorrupt: corrupt }), new FileSet(tombstonePath(path), { monotonic: true, onMissing: "keep" }), tool, { agentId, server }); }
    catch (e) { fail((e as Error).message, 1); }
    const approver = cliApprover(opt["--by"]); const audit = new AuditLog(statePath(process.env.KYTRAL_AUDIT, "audit.jsonl"), { key: auditKeyOrWarn(root) });
    for (const [s, t, ag] of removed) { audit.append({ agentId: ag, tool: t, decision: "known-remove", server: s, approver }); console.log(["removed", s, t, ag].map(show).join("\t")); }
    if (!removed.length) {
      audit.append({ agentId: agentId ?? "(any)", tool, decision: "known-remove", rule: "absent", server: server ?? "(any)", approver });
      console.log(["not found", server ?? "(any server)", tool, agentId ?? "(any agent)"].map(show).join("\t")); process.exit(1);
    }
  } else fail(usage);
} else if (a[0] === "confirm") { // kytral-guard confirm list [--full] | approve <id> [--always] [--full] [--by <name>] | deny <id> [--by <name>]
  const usage = "usage: kytral-guard confirm list [--full] | confirm approve <id> [--always] [--full] [--by <name>] | confirm deny <id> [--by <name>]";
  // The proxies' key: requests are verified and decisions signed with it (an unsigned decision is a refusal).
  const secret = rootSecret(true)!;
  if (a[1] === "list") {
    const { pos, on } = parseArgs(a.slice(2), [], ["--full"]);
    if (pos.length) fail(usage);
    const { requests, invalid } = listRequests(secret);
    const now = Date.now(), live = requests.filter(r => Date.parse(r.expiresAt) > now);
    for (const r of live) {
      // Long arguments are cut for display, and said so loudly: approving them then needs --full (decide refuses otherwise).
      const cut = r.args.length > ARGS_SHOWN && !on.has("--full");
      console.log(`${r.id}\ttool=${show(r.tool)}\tagent=${show(r.agentId)}\tserver=${show(r.server)}\trule=${show(r.rule)}\tchoices=${r.always ? "once,always,deny" : "once,deny"}\texpires in ${Math.ceil((Date.parse(r.expiresAt) - now) / 1000)}s\n  reason: ${show(r.reason)}\n  args ${r.argsHash}: ${show(cut ? r.args.slice(0, ARGS_SHOWN) : r.args)}` + (cut
        ? `\n  !! ARGUMENTS TRUNCATED: first ${ARGS_SHOWN} of ${r.args.length} characters shown. See them all with 'kytral-guard confirm list --full'; approving needs --full.` : ""));
    }
    if (requests.length > live.length) console.error(`kytral-guard: ${requests.length - live.length} expired request(s) ignored`);
    for (const n of invalid) console.error(`kytral-guard: ignored ${show(n)}: not signed with this secret (forged, edited, or another deployment)`);
    if (!live.length) console.error("kytral-guard: no confirmation is waiting");   // stderr: stdout stays one request per entry
  } else if (a[1] === "approve" || a[1] === "deny") {
    const { pos, opt, on } = parseArgs(a.slice(2), ["--by"], a[1] === "approve" ? ["--always", "--full"] : []);
    if (pos.length !== 1) fail(usage);
    const verdict: ConfirmVerdict = a[1] === "deny" ? "deny" : on.has("--always") ? "approve_always" : "approve";
    try {
      const r = decide(secret, pos[0], verdict, cliApprover(opt["--by"]), undefined, { full: on.has("--full") });
      console.log(`${verdict}\t${r.id}\ttool=${show(r.tool)}\tagent=${show(r.agentId)}\tserver=${show(r.server)}${verdict === "approve_always" ? "\t(the proxy adds it to known-tools.json)" : ""}`);
    } catch (e) { fail((e as Error).message, e instanceof ConfirmError ? e.exitCode : 1); }
  } else fail(usage);
} else if (a[0].startsWith("-") || a.includes("--")) await cmdProxy(a);   // the proxy: [--policy f | --preset n] -- <server>, and any other option
else {
  // anything else is a typo or a command that does not exist (it used to get the proxy's usage line); the word typed is not
  // repeated (it may be anything, a token pasted at the wrong place too): only a command of the fixed list is named
  const near = nearest(a[0], [...Object.keys(USAGE), "help", "version"], COMMAND_ALIASES);
  fail(`unknown command.${near ? ` Did you mean '${near}'?` : ""} See: kytral-guard --help`);
}
