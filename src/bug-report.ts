// `kytral-guard doctor --report`: a diagnostic to paste into a public bug report, in Markdown. It says which versions run
// here, which coding agents run the guard's hook (agent ids, and what is wrong with a hook in fixed words), which MCP servers
// the MCP clients and AI apps of this machine run through the proxy (names only), what the policies of the proxies and of the
// hooks hold (counts of rules, the preset they build on), whether the kill switch is on and whether there is an audit log (its
// number of entries only). It is built from a whitelist of formats: fixed labels, numbers, and values checked against a fixed
// list or format (versions, error codes, states, agent ids, preset names). No text is copied from a configuration, a policy,
// the environment or a file, except MCP server names that pass serverName() (else <name>). It writes nothing: KYTRAL_HOME is
// not created, no lock is taken, nothing is journaled.
import { closeSync, existsSync, readFileSync, readSync, realpathSync, statSync } from "node:fs";
import { homedir, hostname, release, type, userInfo } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { configFile, detectAgents, INSTALL_AGENTS, inspectHook } from "./install.js";
import { killSwitchKey, killSwitchPath, killSwitchState } from "./kill-switch.js";
import { MCP_CLIENTS, withoutComments } from "./mcp-config.js";
import { Action, DEFAULT_POLICY, loadPolicy, Policy, policyProblem, PRESETS } from "./policy.js";
import { mcpPolicyPath } from "./policy-file.js";
import { parseQuietly } from "./quiet-yaml.js";
import { assertAuditSecret, assertStrongSecret, resolveSecret } from "./secret.js";
import { openRegular, readRegular, stateDir, statePath } from "./store.js";

const isObj = (v: unknown): v is Record<string, any> => !!v && typeof v === "object" && !Array.isArray(v);
/** A value as the report shows it: itself if it has the expected format, else `otherwise`. */
const checked = (v: unknown, format: RegExp, otherwise = "unknown") => typeof v === "string" && format.test(v) ? v : otherwise;
/** An error as a code (ENOENT, EACCES...): its message may hold a path, or the text that failed to parse. */
const errCode = (e: unknown) => checked((e as NodeJS.ErrnoException)?.code, /^[A-Z][A-Z0-9_]{1,39}$/, "error");
/** A section that cannot be checked says so instead of stopping the report. */
const safely = (f: () => string[]): string[] => { try { return f(); } catch (e) { return [`- could not be checked (${errCode(e)})`]; } };

const real = (p: string) => { try { return realpathSync.native(p); } catch { return p; } };
/** A folder as the report shows it: ~ for the home folder and what is inside it (either one reached through links or not), <path> for anything else. */
export function shortPath(p: string, home = homedir()): string {
  for (const h of new Set([resolve(home), real(home)])) for (const q of new Set([resolve(p), real(p)])) {
    const rel = relative(h, q);
    if (!rel.startsWith("..") && !isAbsolute(rel)) return rel === "" ? "~" : `~/${rel.split(sep).join("/")}`;
  }
  return "<path>";
}
/** KYTRAL_HOME in one of three forms, never the names of its folders: ~/.kytral (default), under ~ (custom), or <path>. */
function homeShown(dir: string): string {
  const p = shortPath(dir);
  return p === "~/.kytral" ? "~/.kytral (default)" : p.startsWith("~") ? "under ~ (custom)" : "<path>";
}

/** The KYTRAL_ variables this version reads (test/bug-report.test.ts checks the list against src/): the only ones named. */
export const KYTRAL_VARS: readonly string[] = ["KYTRAL_ANALYSIS_TIMEOUT_MS", "KYTRAL_AUDIENCE", "KYTRAL_AUDIT", "KYTRAL_AUDIT_ALLOWS", "KYTRAL_AUDIT_SECRET",
  "KYTRAL_BADGE", "KYTRAL_CONFIRMATIONS", "KYTRAL_CONFIRM_QUEUE", "KYTRAL_CONFIRM_TIMEOUT_MS", "KYTRAL_HOME", "KYTRAL_KEEP_CALLS", "KYTRAL_KEPT_CALLS",
  "KYTRAL_KILL", "KYTRAL_KNOWN_TOOLS", "KYTRAL_NONCES", "KYTRAL_PLUGINS", "KYTRAL_POLICY", "KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS", "KYTRAL_REVOCATIONS",
  "KYTRAL_SECRET", "KYTRAL_SECRET_FILE", "KYTRAL_SERVER_ID", "KYTRAL_SQL_TIMEOUT_MS"];
/** The known KYTRAL_ variables that are set, by name; any other is only counted (its name may be a typo, or hold anything). */
function kytralVars(): string {
  const known = (k: string) => KYTRAL_VARS.includes(process.platform === "win32" ? k.toUpperCase() : k);   // Windows: names ignore case
  const others = Object.keys(process.env).filter(k => /^KYTRAL_/i.test(k) && !known(k)).length;
  return (KYTRAL_VARS.filter(k => process.env[k] !== undefined).join(", ") || "none") + (others ? `; plus ${others} unknown to this version (not named)` : "");
}

/** Why secret.ts refuses a secret, as one of its fixed reasons (anything else: "not usable"). */
const REFUSALS: [RegExp, string][] = [[/too short/, "too short: at least 32 non-whitespace bytes"], [/leading\/trailing whitespace/, "leading or trailing whitespace"],
  [/not enough distinct characters/, "too weak: not enough distinct characters"], [/dictionary\/placeholder/, "too weak: dictionary or placeholder value"]];
/** Whether a secret variable is usable, in words that never quote it. */
function secretState(name: string, check: (v: string) => unknown): string {
  const v = process.env[name];
  if (v === undefined) return "not set";
  if (v === "") return "set but empty";
  try { check(v); return "set, usable"; } catch (e) { const m = String((e as Error)?.message); return `set, refused (${REFUSALS.find(([re]) => re.test(m))?.[1] ?? "not usable"})`; }
}

/** An editor's settings folder as a label names it (an app kept in several editors, such as Cline, is labeled with the editor's name). */
const EDITOR_LABELS: Record<string, string> = { Code: "VS Code", "Code - Insiders": "VS Code Insiders", VSCodium: "VSCodium", Cursor: "Cursor", Windsurf: "Windsurf",
  Trae: "Trae", "Trae CN": "Trae CN", Kiro: "Kiro", Qoder: "Qoder" };
interface McpClientFile { label: string; file: string; local?: boolean; key?: "mcpServers" | "servers" }
/**
 * The MCP client configurations this version documents: Claude Code (project, user and local scopes), Cursor (project and
 * user), and the AI apps `kytral-guard mcp wrap` protects (Claude Desktop, VS Code, Cline, Roo Code, Kilo Code, LM Studio,
 * Continue, iFlow CLI). Labels come from fixed names only, never from a path.
 */
function mcpClients(cwd: string, home: string): McpClientFile[] {
  const appData = process.platform === "win32" ? process.env.APPDATA || join(home, "AppData", "Roaming")
    : process.platform === "darwin" ? join(home, "Library", "Application Support") : process.env.XDG_CONFIG_HOME || join(home, ".config");
  const apps = MCP_CLIENTS.filter(c => c.id !== "claude-desktop").flatMap(c => {
    const files = c.paths(appData, home);
    return files.map(file => {
      const editor = EDITOR_LABELS[relative(appData, file).split(sep)[0]] ?? "another editor";
      return { label: files.length === 1 ? c.name : c.id === "vscode" ? editor : `${c.name} (${editor})`, file, key: c.key };
    });
  });
  return [
    { label: "Claude Code, project .mcp.json", file: join(cwd, ".mcp.json") },
    { label: "Claude Code, user (~/.claude.json)", file: join(home, ".claude.json") },
    { label: "Claude Code, local (~/.claude.json, this project)", file: join(home, ".claude.json"), local: true },
    { label: "Cursor, project .cursor/mcp.json", file: join(cwd, ".cursor", "mcp.json") },
    { label: "Cursor, user (~/.cursor/mcp.json)", file: join(home, ".cursor", "mcp.json") },
    { label: "Claude Desktop", file: join(appData, "Claude", "claude_desktop_config.json") },
    ...apps,
  ];
}
/**
 * A server that runs Kytral Guard's proxy: before the "--" that starts the server's own command, kytral-guard (the command,
 * an npx package, a folder of that name) or a cli.js that is given KYTRAL_ variables.
 */
export function runsGuard(e: unknown): boolean {
  if (!isObj(e) || typeof e.command !== "string") return false;
  const argv = [e.command, ...(Array.isArray(e.args) ? e.args : [])].map(String), end = argv.indexOf("--");
  const kytralEnv = isObj(e.env) && Object.keys(e.env).some(k => /^KYTRAL_/i.test(k));
  return end > 0 && argv.slice(0, end).some(x => /(^|[\\/@])kytral-guard($|[\\/@.])/i.test(x) || (kytralEnv && /(^|[\\/])cli\.[cm]?[jt]s$/i.test(x)));
}
/** Prefixes of common credentials (OpenAI and Stripe keys, GitHub, GitLab and Slack tokens, AWS key ids, Google API keys, JWTs), at the start of a name or of one of its parts. */
const TOKEN_PREFIX = /(?:^|[._-])(?:(?:sk|pk|rk)[-_]|gh[pousr]_|github_pat_|glpat-|xox|AKIA|ASIA|AIza|eyJ)/;
const charKind = (c: string) => (c >= "0" && c <= "9" ? 0 : c >= "a" && c <= "z" ? 1 : 2);
/**
 * A name that may be a credential: a known token prefix, 16 hexadecimal digits or more (separators aside), or a long name (16
 * characters or more) that looks random: inside its parts (between . _ -), the character changes between digits, lowercase
 * and uppercase at 40% of its positions or more when it mixes both cases, at 30% when it mixes letters of one case and
 * digits, or digits sit between letters in two places or more (words, words that end with a number, and dates pass).
 */
export function tokenLike(name: string): boolean {
  const parts = name.split(/[._-]/), s = parts.join("");
  if (TOKEN_PREFIX.test(name) || /[0-9a-f]{16,}/i.test(s)) return true;
  if (name.length < 16) return false;
  let changes = 0;
  for (const p of parts) for (let i = 1; i < p.length; i++) if (charKind(p[i]) !== charKind(p[i - 1])) changes++;
  const lower = /[a-z]/.test(s), upper = /[A-Z]/.test(s), digits = /\d/.test(s);
  const inner = parts.reduce((n, p) => n + (p.match(/(?<=[A-Za-z])\d+(?=[A-Za-z])/g)?.length ?? 0), 0);
  return changes / Math.max(1, s.length - 1) >= (lower && upper ? 0.4 : digits && (lower || upper) ? 0.3 : Infinity) || inner >= 2;
}
/**
 * A server name as the report shows it: a plain name (a letter or a digit, then letters, digits, . _ -, 64 characters at most)
 * that does not look like a token and holds no secret of the environment, user or host name (redact() leaves it as it is).
 * Any other name is <name>: a name can be any text, a URL with a password or a key=value pair included.
 */
export function serverName(name: string): string {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name) && !tokenLike(name) && redact(name) === name ? name : "<name>";
}
/** Each configuration found: its servers by name, wrapped or not. Nothing else is read from them (commands, arguments and env hold paths and secrets). */
function mcpSection(cwd = process.cwd(), home = homedir()): string[] {
  const out: string[] = [], seen = new Set<string>(), parsed = new Map<string, { j?: unknown; error?: string }>();
  const names = (xs: string[]) => xs.length ? xs.slice(0, 50).map(serverName).join(", ") + (xs.length > 50 ? `, and ${xs.length - 50} more` : "") : "none";
  const read = (file: string) => {
    try {
      if (statSync(file).size > 64 * 2 ** 20) return { error: "larger than 64 MB" };
      const text = readFileSync(file, "utf8");
      if (/\.ya?ml$/i.test(file)) { try { return { j: parseQuietly(text) }; } catch { return { error: "not valid YAML" }; } }   // Continue; its errors quote the file too
      try { return { j: JSON.parse(text) as unknown }; } catch { return { j: JSON.parse(withoutComments(text)) as unknown }; }   // VS Code's files may hold comments
    } catch (e) { return { error: e instanceof SyntaxError ? "not valid JSON" : errCode(e) }; }   // a JSON error quotes the file
  };
  for (const c of mcpClients(cwd, home)) {
    const id = `${resolve(c.file)}|${c.local ? "local" : ""}`;
    if (seen.has(id) || !existsSync(c.file)) continue;
    seen.add(id);
    if (!parsed.has(c.file)) parsed.set(c.file, read(c.file));
    const { j, error } = parsed.get(c.file)!;
    if (error !== undefined) { if (!c.local) out.push(`- ${c.label}: cannot be read (${error})`); continue; }
    // Claude Code keeps a project's local servers under its folder's path, written with / on Windows; Continue, a list of
    // servers that carry their name
    const servers = !isObj(j) ? undefined : c.local
      ? isObj(j.projects) ? [cwd, cwd.replaceAll("\\", "/")].map(p => Object.hasOwn(j.projects, p) ? j.projects[p]?.mcpServers : undefined).find(isObj) : undefined
      : Array.isArray(j.mcpServers) ? Object.fromEntries(j.mcpServers.filter(isObj).map((e, i) => [String(e.name ?? `server-${i + 1}`), e]))
      : j[c.key ?? "mcpServers"];
    if (c.local && !isObj(servers)) continue;   // no local server for this project: nothing to say
    const all = isObj(servers) ? Object.entries(servers) : [];
    out.push(`- ${c.label}: ${all.length ? `wrapped: ${names(all.filter(([, e]) => runsGuard(e)).map(([n]) => n))}; not wrapped: ${names(all.filter(([, e]) => !runsGuard(e)).map(([n]) => n))}` : "no MCP server"}`);
  }
  return out.length ? out : [`- MCP clients: no configuration found (looked for Claude Code, Cursor, Claude Desktop, ${MCP_CLIENTS.filter(c => c.id !== "claude-desktop").map(c => c.name).join(", ")})`];
}

/** Fixed words for each problem inspectHook finds in a hook (its own texts name files and paths): chosen by the problem's template, never by its text. */
const HOOK_PROBLEMS: [RegExp, string][] = [[/does not exist/, "a file it runs is missing"], [/disableAllHooks/, "disabled by disableAllHooks"], [/fails open/, "fails open"],
  [/^GROK_SHELL=/, "the Grok shell setting (cmd) breaks it"], [/does not include PowerShell/, "its matcher leaves out PowerShell"], [/^\{error\}$/, "its configuration does not parse"]];
const hookProblem = (key: string) => HOOK_PROBLEMS.find(([re]) => re.test(key))?.[1] ?? "another problem";
/**
 * The coding agents whose configuration (the user's, or this project's) runs the guard's hook, the agents found on this
 * machine without it, and what is wrong with a hook: agent ids from the fixed list and fixed words only.
 */
function hooksLine(cwd = process.cwd()): string {
  const installed: string[] = [], problems: string[] = [], seen = new Set<string>();
  for (const ag of INSTALL_AGENTS) for (const project of [undefined, cwd]) {
    const at = project ? `${ag} (this project)` : ag, id = real(configFile(ag, { project })).toLowerCase();
    if (seen.has(id)) continue;   // the project may be the home folder, and some agents have no project file
    seen.add(id);
    let r: ReturnType<typeof inspectHook>;
    try { r = inspectHook(ag, { project }); } catch { problems.push(`${at}: its configuration cannot be read`); continue; }   // a folder or no permission in place of a file
    if (r.installed) installed.push(at);
    const what = [...new Set(r.issues.map(i => hookProblem(i.key)))];
    if (what.length) problems.push(`${at}: ${what.join(", ")}`);
  }
  // disableAllHooks in the project's shared settings turns the hooks of the local file off too
  try { if (!problems.some(p => p.startsWith("claude-code (this project):")) && JSON.parse(readFileSync(join(cwd, ".claude", "settings.json"), "utf8"))?.disableAllHooks === true) problems.push("claude-code (this project): disabled by disableAllHooks"); } catch {}
  const without = detectAgents().filter(ag => !installed.includes(ag) && !installed.includes(`${ag} (this project)`));
  return `- Agent hooks: ${installed.length ? `installed for ${installed.join(", ")}` : "none installed"}; ${without.length ? `found without the hook: ${without.join(", ")}` : installed.length ? "no other agent found" : "no agent found"}${problems.length ? `; problems: ${problems.join("; ")}` : ""}`;
}

const ACTIONS = ["allow", "block", "confirm"];
/** A policy: where it comes from (never a file's name), how many rules decide what, and the preset it builds on (`preset`: it is that built-in preset). */
function policyLines(source: string, read: () => string, preset?: string): string[] {
  let text: string;
  try { text = read(); } catch (e) { return [`- Source: ${source}, cannot be read (${errCode(e)})`]; }
  let p: Policy;
  try { p = loadPolicy(text); } catch (e) { return [`- Source: ${source}, does not load: ${policyProblem(e)}`]; }
  const n = (a: Action) => p.rules.filter(r => r.action === a).length, action = (a: unknown) => ACTIONS.includes(a as string) ? a : "unknown";
  const base = preset ? `the built-in ${preset} preset` : typeof p.extends === "string" && Object.hasOwn(PRESETS, p.extends) ? `extends ${p.extends}` : "none (extends no preset)";
  return [`- Source: ${source}`, `- Rules: ${p.rules.length} (block ${n("block")}, confirm ${n("confirm")}, allow ${n("allow")})`,
    `- Default: ${action(p.default)}; unknownTools: ${action(p.unknownTools)}`, `- Presets: ${base}; built in: ${Object.keys(PRESETS).join(", ")}`];
}
/** The proxies' policy: the file given with --policy (as the proxy reads it), else $KYTRAL_HOME/mcp-policy.yaml, else the built-in default (the strict preset). */
function policySection(file?: string): string[] {
  if (file !== undefined) return policyLines("the file given with --policy (name redacted)", () => readFileSync(file, "utf8"));
  const mcp = mcpPolicyPath();
  if (existsSync(mcp)) return policyLines("the mcp policy file in the kytral home folder (what a proxy started without --policy or --preset uses)", () => readFileSync(mcp, "utf8"));
  return policyLines("built-in default (what a proxy started without --policy or --preset uses)", () => DEFAULT_POLICY, "strict");
}
/** The agent hooks' policy, found as loadHookPolicy finds it: $KYTRAL_POLICY, else $KYTRAL_HOME/policy.yaml, else the coding-agent preset. */
function hookPolicySection(): string[] {
  const named = process.env.KYTRAL_POLICY, own = statePath(undefined, "policy.yaml");
  if (named) return policyLines("the file the policy variable names (name redacted)", () => readFileSync(named, "utf8"));
  if (existsSync(own)) return policyLines("the policy file in the kytral home folder (what kytral-guard init writes)", () => readFileSync(own, "utf8"));
  return policyLines("built-in coding-agent preset (what agent hooks use without a policy file)", () => PRESETS["coding-agent"], "coding-agent");
}

/**
 * yes or no, as an agent hook started now finds it: kill-switch.json checked against the last kill or resume the audit log
 * records (fail closed: a corrupt, forged or replayed state stops it too). Nothing is written, nothing is journaled.
 */
function killed(): string {
  const path = killSwitchPath();
  // the secret a hook started in this shell would use: KYTRAL_SECRET, else the secret file (read, never created)
  let secret: string | undefined, key: Buffer | undefined; try { secret = resolveSecret(); key = killSwitchKey(secret as string); } catch {}
  if (key) return killSwitchState(secret!) === null ? "no" : "yes";
  if (!existsSync(path)) return "no";
  // without the proxies' key the signature cannot be checked: only a resume is in doubt (a proxy that finds it forged stays stopped)
  let s: unknown; try { s = JSON.parse(readRegular(path).toString("utf8")); } catch {}
  return isObj(s) && s.killed === false ? "no (signature not checked: no usable secret in this shell)" : "yes";
}
/** Lines of a file (one audit entry each), counted in 1 MiB pieces: a log can be large, and none of it is kept. */
function lineCount(path: string): number {
  const fd = openRegular(path), buf = Buffer.alloc(1 << 20);
  try {
    let n = 0, last = 10;
    for (let k: number; (k = readSync(fd, buf, 0, buf.length, null)) > 0;) {
      const chunk = buf.subarray(0, k);
      for (let i = chunk.indexOf(10); i >= 0; i = chunk.indexOf(10, i + 1)) n++;
      last = chunk[k - 1];
    }
    return last === 10 ? n : n + 1;   // a last line without its newline (a torn write) counts too
  } finally { closeSync(fd); }
}
function auditLine(): string {
  const path = statePath(process.env.KYTRAL_AUDIT, "audit.jsonl");
  if (!existsSync(path)) return "no";
  try { const n = lineCount(path); return `yes, ${n} entr${n === 1 ? "y" : "ies"}`; } catch (e) { return `yes, cannot be read (${errCode(e)})`; }
}

/** The OS from fixed lists and formats: its kind, the version number its release starts with (a custom kernel adds any text after it), WSL or not, platform, arch. */
function osShown(): string {
  const r = release(), wsl = process.platform === "linux" && /microsoft/i.test(r) ? " (WSL)" : "";
  return `${checked(type(), /^(Linux|Darwin|Windows_NT|FreeBSD|OpenBSD|NetBSD|SunOS|AIX)$/, "other")} ${/^\d+(\.\d+){0,3}/.exec(r)?.[0] ?? "unknown"}${wsl}, ` +
    `platform ${checked(process.platform, /^[a-z0-9]+$/)}, arch ${checked(process.arch, /^[a-z0-9]+$/)}`;
}

/** The report, every line from a whitelist of formats. `policyFile`: the policy the proxies are given with --policy (default: what they use without it). */
export function doctorReport(o: { version: string; policyFile?: string }): string {
  return [
    "### Kytral Guard diagnostic (kytral-guard doctor --report)",
    "Redacted: fixed labels, versions, counts and states only; no secret, variable value, file content, audit entry, tool argument or path. <name> is a server name that is not shown, <path> a folder outside the home folder (~).",
    "",
    "#### Versions",
    `- kytral-guard: ${checked(o.version, /^\d+\.\d+\.\d+(-[0-9A-Za-z.]{1,32})?$/)}`,
    `- Node.js: ${checked(process.versions.node, /^\d+\.\d+\.\d+$/)}`,
    `- OS: ${osShown()}`,
    "",
    "#### Setup (this shell)",
    ...safely(() => { const state = stateDir(); return [
      `- KYTRAL_HOME: ${homeShown(state)}, ${existsSync(state) ? "exists" : "does not exist yet"}`,
      `- KYTRAL_ variables set (names only): ${kytralVars()}`,
      `- KYTRAL_SECRET: ${secretState("KYTRAL_SECRET", v => assertStrongSecret(v))}`,
      `- KYTRAL_AUDIT_SECRET: ${secretState("KYTRAL_AUDIT_SECRET", v => assertAuditSecret(v))}`]; }),
    "",
    "#### Agents and MCP servers",
    ...safely(() => [hooksLine()]),
    ...safely(() => mcpSection()),
    "",
    "#### Policy (MCP proxies)",
    ...safely(() => policySection(o.policyFile)),
    "",
    "#### Policy (agent hooks)",
    ...safely(() => hookPolicySection()),
    "",
    "#### Kill switch",
    ...safely(() => [`- Killed: ${killed()}`]),
    "",
    "#### Audit log",
    ...safely(() => [`- Present: ${auditLine()}`]),
  ].join("\n");   // not redact() as a whole: it checks each server name, and over fixed labels it only breaks them (a user named node: "<user>.js")
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** Variables whose value is a secret, whatever it looks like (KYTRAL_SECRET, KYTRAL_BADGE, *_TOKEN, *_API_KEY, *PASSWORD...). */
const SECRET_NAME = /SECRET|TOKEN|PASSW|PASSPHRASE|API_?KEY|ACCESS_?KEY|PRIVATE|CREDENTIAL|AUTH|COOKIE|SESSION|BADGE|SIGNATURE|(^|_)KEY(_|$)/i;
const PATHLIKE = /^([\/~]|[A-Za-z]:[\\/]|\\\\)/;
/** Any other value shaped like a credential: long, without spaces, mixing letters and digits, not a path. */
const credentialLike = (v: string) => v.length >= 20 && !PATHLIKE.test(v) && /^[\w+=.\/-]+$/.test(v) && /\d/.test(v) && /[A-Za-z]/.test(v) && new Set(v).size >= 10;
/** A word that changes between lowercase, uppercase and digits at most of its characters, as random tokens do (names and words rarely do). */
function randomLike(m: string): boolean {
  const s = m.replace(/[_-]/g, ""), kind = (c: string) => (c >= "0" && c <= "9" ? 0 : c >= "a" && c <= "z" ? 1 : 2);
  let changes = 0; for (let i = 1; i < s.length; i++) if (kind(s[i]) !== kind(s[i - 1])) changes++;
  return /[a-z]/.test(s) && /[A-Z]/.test(s) && /\d/.test(s) && changes >= 0.55 * s.length;
}
/** Credentials whatever holds them: PEM private keys, common token formats, badges and other JWT-like tokens, long hex, long base64 mixing cases and digits, random-looking words. */
const TOKENS: [RegExp, ((m: string) => boolean)?][] = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g],
  [/\b(?:sk|pk|rk)[-_][\w-]{16,}/g], [/\bgh[pousr]_[A-Za-z0-9]{20,}/g], [/\bgithub_pat_\w{20,}/g], [/\bxox[abposr]-[\w-]{10,}/g],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g], [/\bAIza[\w-]{30,}/g], [/\bglpat-[\w-]{20,}/g], [/\bnpm_[A-Za-z0-9]{30,}/g],
  [/\beyJ[\w-]{8,}(?:\.[\w-]+){1,2}/g],
  [/(?<![A-Za-z0-9])[0-9a-fA-F]{32,}(?![A-Za-z0-9])/g],
  [/[A-Za-z0-9+\/_=-]{40,}/g, m => /[a-z]/.test(m) && /[A-Z]/.test(m) && /\d/.test(m)],
  [/[\w-]{20,}/g, randomLike],
];
/**
 * What must not leave this machine, replaced in any text: secret values (<redacted>), the home folder (~), any other absolute
 * path (<path>), user and host names (<user>, <host>, as whole words, whatever the case), then token-like text (<redacted>).
 * Secrets come first, so that no other replacement can cut one into pieces that no longer match.
 */
export function redact(text: string, env: NodeJS.ProcessEnv = process.env): string {
  const secrets = [...new Set(Object.entries(env).filter(([k, v]) => !!v && v.length >= 8 && (SECRET_NAME.test(k) ? !PATHLIKE.test(v) : credentialLike(v))).map(([, v]) => v!))];
  for (const s of secrets.sort((p, q) => q.length - p.length)) text = text.replaceAll(s, "<redacted>");
  const fold = process.platform === "win32" || process.platform === "darwin";   // case-insensitive file systems
  const home = homedir(), homes = new Set([home]);
  try { homes.add(realpathSync.native(home)); } catch {}
  if (process.platform === "win32") for (const h of [...homes]) homes.add(h.replaceAll("\\", "/"));
  for (const h of [...homes].filter(h => h.replace(/[\\/]+$/, "").length > 2).sort((p, q) => q.length - p.length))
    text = text.replace(new RegExp(`${esc(h.replace(/[\\/]+$/, ""))}(?=$|[\\\\/\\s"'\`,;:)\\]>])`, fold ? "gim" : "gm"), "~");
  // a / that starts a path: not inside a word, a relative path, ~/..., a URL (scheme:) or a placeholder; then Windows and UNC paths
  text = text.replace(/(?<![\w.~\/\\<>@-])(?<![A-Za-z]:)\/[^\s"'`,;()<>|\]]+/g, "<path>")
    .replace(/(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s"'`,;()<>|\]]*/g, "<path>")
    .replace(/\\\\[^\s\\"'`]+\\[^\s"'`,;()<>|\]]*/g, "<path>");
  let user: string | undefined, host: string | undefined;
  try { user = userInfo().username; } catch {}
  try { host = hostname(); } catch {}
  const who = new Map<string, string>();
  for (const u of [user, env.USER, env.USERNAME, env.LOGNAME]) if (u && u.trim().length >= 2) who.set(u.trim().toLowerCase(), "<user>");
  for (const h of [host, env.HOSTNAME, env.COMPUTERNAME].flatMap(h => h ? [h, h.split(".")[0]] : [])) if (h.trim().length >= 2) who.set(h.trim().toLowerCase(), "<host>");
  for (const [w, to] of [...who].sort((p, q) => q[0].length - p[0].length)) text = text.replace(new RegExp(`(?<![A-Za-z0-9])${esc(w)}(?![A-Za-z0-9])`, "gi"), to);
  for (const [re, keep] of TOKENS) text = text.replace(re, m => !keep || keep(m) ? "<redacted>" : m);
  return text;
}
