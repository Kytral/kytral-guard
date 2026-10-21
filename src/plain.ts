// Plain words for people who do not read commands (the dashboard's Simple view): who tried what, from an audit entry, the
// finding behind it and the text kept for it. A few dozen patterns name the usual disasters; every rule has a fallback.
// A sentence is built from parts (plainParts): its template, the agent, what it did, where, and who decided. The page says
// those parts in the reader's language (src/dashboard/i18n.js, with the same templates as keys); plainSentence says them in
// US English.
import { homedir } from "node:os";
import { AGENTS, isInstallAgent } from "./install.js";
import { MCP_CLIENTS } from "./mcp-config.js";

/** An agent's name for people: "Claude Code", or for an MCP server run through the proxy, its app and the server. */
export function agentName(id: string): { name: string; server?: string; key?: "You" | "An agent" } {
  const m = /^mcp:([^:]+):(.+)$/.exec(id);
  if (m) return { name: MCP_CLIENTS.find(c => c.id === m[1])?.name ?? m[1], server: m[2] };
  if (isInstallAgent(id)) return { name: AGENTS[id].name };
  if (id === "*" || id === "dashboard") return { name: "You", key: "You" };
  return !id || id === "generic" || id === "unknown" ? { name: "An agent", key: "An agent" } : { name: id };
}

/** What a finding or a call does, in a few words, most specific first (tested on the finding, then on the call's text). */
const PHRASES: [RegExp, string][] = [
  [/\brm -\w*r\w* +(~|\$home|\/home\/[^\/\s]+|\/users\/[^\/\s]+|[a-z]:[\\\/]users[\\\/][^\\\/\s]+)[\\\/]?\*?(\s|\(|$)/i, "erase your whole home folder"],
  [/\brm -\w*r\w* +\/\*?(\s|\(|$)/i, "erase everything on the computer"],
  [/\b(mkfs(\.\w+)?|wipefs)\b|\bdd\b[^\n]*\bof=\/dev\/|\bformat [a-z]:/i, "erase a disk"],
  [/\bterraform\b[^\n]*\bdestroy\b|\btofu\b[^\n]*\bdestroy\b|\bpulumi\b[^\n]*\bdestroy\b|\bcdk\b[^\n]*\bdestroy\b/i, "destroy cloud infrastructure"],
  [/\bkubectl\b[^\n]*\bdelete\b[^\n]*\b(ns|namespaces?)\b/i, "delete a whole Kubernetes namespace"],
  [/\bkubectl\b[^\n]*\bdelete\b|\bhelm\b[^\n]*\b(uninstall|delete)\b/i, "remove a service running in Kubernetes"],
  [/\baws\s+s3\s+(rm|rb)\b|\bgsutil\b[^\n]*\b(rm|rb)\b|\bs3cmd\b[^\n]*\b(del|rb)\b|\brclone\b[^\n]*\b(purge|delete)\b/i, "delete files in cloud storage"],
  [/\b(aws|gcloud|az)\b[^\n]*\b(delete|terminate|destroy)\b/i, "delete cloud resources"],
  [/\bgit push\b[^\n]*(--force|\s-f\b|--mirror|--delete)/i, "overwrite code that others share on the repository"],
  [/\bgit reset --hard\b/i, "throw away your latest changes"],
  [/\bgit clean\b/i, "delete the files git does not track"],
  [/\bgit (checkout|restore)\b[^\n]*\s(--\s+)?\.(\s|$)/i, "throw away your uncommitted changes"],
  [/\bdrop (database|schema)\b|\bdropdb\b/i, "delete a whole database"],
  [/\bdrop table\b|\(drops it\)/i, "delete a table of your database"],
  [/\btruncate\b|\(empties it\)/i, "empty a table of your database"],
  [/\b(flushall|flushdb)\b/i, "wipe a database"],
  [/no where that pins rows|delete from \S+\s*(;|$)/i, "change or delete every row of a table"],
  [/\b(shutdown|reboot|halt|poweroff)\b/i, "shut down or restart the computer"],
  [/\bcrontab\b/i, "install a task that runs on its own"],
  [/\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n]*\|/i, "run a program downloaded from the internet"],
  [/piped into|written or downloaded by the same command|cannot analyze the script/i, "run a script whose content cannot be read in advance"],
  [/authorized_keys/i, "change who can log in to this computer"],
  [/[\\\/]\.ssh\b|\bid_(rsa|ed25519|ecdsa)\b/i, "touch your SSH keys"],
  [/\.(bash|zsh)rc\b|\.(bash_)?profile\b|\.zprofile\b|\bprofile\.ps1\b/i, "change what your terminal runs when it starts"],
  [/\.git[\\\/]+hooks/i, "install a program that runs with every git command"],
  [/[\\\/]\.aws[\\\/]|[\\\/]\.azure[\\\/]|gcloud[\\\/]|credentials|\.npmrc\b|\.netrc\b|\.docker[\\\/]config/i, "touch your cloud or account credentials"],
  [/(^|[\s'":])\/etc[\\\/]|[a-z]:[\\\/]windows[\\\/]/i, "change a system file"],
  [/\.kytral\b|\bkytral-guard\b|kytral_secret|kill-switch/i, "change or turn off Kytral Guard"],
  [/\brm -\w*r|\bremove-item\b[^\n]*-recurse|\b(rd|rmdir) \/s\b|\bfind\b[^\n]*\s-delete\b|\brimraf\b|\brmtree\b|\bshred\b/i, "delete a folder and everything in it"],
  [/\b(chmod|chown)\s+-\w*r/i, "change the permissions of many files"],
  [/\beval\b|unresolved command word|expanded path|cannot analyze/i, "run a command whose content cannot be read in advance"],
];
/** What a rule is about, when no phrase above names the finding. */
const RULE_PHRASES: Record<string, string> = {
  "guard-tamper": "change or turn off Kytral Guard",
  "shell-catastrophic": "run a command that does damage that cannot be undone",
  "shell-destructive": "run a command that deletes work or data",
  "shell-unresolved": "run a command whose content cannot be read in advance",
  "shell-unparseable": "run a command Kytral Guard cannot read",
  "sql-destructive": "delete or overwrite data in a database",
  "sql-unrestricted-write": "delete or overwrite data in a database",
  "destructive-sql": "delete or overwrite data in a database",
  "sql-opaque": "run database code whose effect cannot be known in advance",
  "sql-unparseable": "run database code Kytral Guard cannot read",
  "sensitive-file-write": "change a sensitive file",
  "sensitive-path": "touch a sensitive file",
  "rm-rf": "delete a folder and everything in it",
  "recursive-delete-other-commands": "delete many files at once",
  "kill-switch": "act while every agent was stopped",
  "analysis-limit": "make a call too large to check in time",
  "hook-error": "act while Kytral Guard could not decide",
};
/** Rules about a whole tool: the tool's name tells more than any pattern. */
const TOOL_RULES: Record<string, string> = {
  "mcp-destructive-tool": "use a tool that deletes ({tool})", "delete-files-or-backups": "use a tool that deletes ({tool})",
  "mcp-destructive-hint": "use a tool its server marks as destructive ({tool})",
  "mcp-money": "move money ({tool})", "money-transfer": "move money ({tool})",
  "mcp-mass-message": "send a message to many people at once ({tool})", "mass-email": "send a message to many people at once ({tool})",
  "unknown-tool": "use a tool its server never announced ({tool})",
};
const SOMETHING_RISKY = "do something risky";
/** Every phrase a sentence can say what a call did with (the page translates each one). */
export const ACTION_PHRASES: readonly string[] = [...new Set([...PHRASES.map(p => p[1]), ...Object.values(RULE_PHRASES), ...Object.values(TOOL_RULES), SOMETHING_RISKY])];
/** The tool's own name, without the prefix of MCP tools (mcp__github__delete_repo: delete_repo). */
const shortTool = (tool: string) => tool.replace(/^mcp__[^_]+(?:_[^_]+)*?__/, "").replace(/^[^_]+___/, "");
const fill = (text: string, vars: Record<string, string>) => text.replace(/\{(\w+)\}/g, (m, k: string) => (Object.hasOwn(vars, k) ? vars[k] : m));

/** What the call does, in a few words (`what`, a key of ACTION_PHRASES; `tool` fills its {tool}). */
export function plainActionParts(e: { rule?: string; reason?: string; text?: string; tool?: string }): { what: string; tool?: string } {
  const rule = e.rule ?? "";
  if (TOOL_RULES[rule]) return { what: TOOL_RULES[rule], tool: shortTool(e.tool ?? "") };
  // the finding and the call together: "piped into bash" is a download only when the call fetches something
  const source = `${e.reason ?? ""}\n${e.text ?? ""}`;
  for (const [re, phrase] of PHRASES) if (re.test(source)) return { what: phrase };
  return { what: RULE_PHRASES[rule] ?? SOMETHING_RISKY };
}
/** What the call does, in a few words: "erase your whole home folder". */
export function plainAction(e: { rule?: string; reason?: string; text?: string; tool?: string }): string {
  const a = plainActionParts(e);
  return fill(a.what, { tool: a.tool ?? "" });
}
/** A folder for people: under the home folder, its last two names ("projects/api"). */
export function shortPlace(dir: string | undefined): string | undefined {
  if (!dir || /^kytral-guard:/.test(dir)) return undefined;
  const p = dir.replace(/\\/g, "/"), home = homedir().replace(/\\/g, "/");
  const rel = p.toLowerCase().startsWith(home.toLowerCase() + "/") ? p.slice(home.length + 1) : p;
  const parts = rel.split("/").filter(Boolean);
  return parts.length ? parts.slice(-2).join("/") : undefined;
}

export interface PlainEvent {
  agent: string; tool: string; decision: string; rule?: string; reason?: string; text?: string; cwd?: string; approver?: string;
  /** The rule asks a human, but this agent could not ask one: it was blocked instead. */
  cannotAsk?: boolean;
}
/**
 * The parts of a sentence: `s`, its template, and `more`, the sentences that follow (keys of the page's translations, where
 * a "|you" variant says the same when the reader decided: "{by} stopped all agents.|you"); the agent (`who`, or `whoKey`
 * to translate); what it did (`what` with its `tool`); where (`where`); who decided (`by`, or `byKey`); for a change made
 * on the dashboard, `reason` (a key and its values, or a text as it was journaled).
 */
export interface PlainParts {
  s: string; more?: string[];
  who?: string; whoKey?: "You" | "An agent";
  what?: string; tool?: string;
  where?: { k: string; place?: string; server?: string };
  by?: string; byKey?: "You" | "Someone";
  reason?: { k: string; p?: Record<string, string>; t?: Record<string, string> } | { text: string };
  decision?: string;
}
/** The templates of the sentences, the words they hold and the reasons of the dashboard's own changes (keys the page translates). */
export const SENTENCES = {
  block: "{who} tried to {what}{where}.", ask: "{who} wanted to {what}{where}, and asked you first.", request: "{who} wants to {what}{where}.",
  confirmed: "{by} allowed {who} to {what}{where}.", confirmedAlways: "{by} allowed {who} to {what}{where} from now on.",
  allow: "{who} used {tool}{where}.", kill: "{by} stopped all agents.", resume: "{by} let the agents run again.",
  knownAdd: "{by} approved {tool} for good.", knownRemove: "{by} withdrew the approval of {tool}.", change: "{by} {reason}.",
  damaged: "Kytral Guard found a damaged or forged file and refused what depended on it.", other: "{who}: {decision}.",
  noAnswer: " Nobody could answer in time, so it was blocked.", cannotAsk: " It cannot ask you, so it was blocked.", refused: " {by} refused it.",
  inPlace: " in {place}", throughServer: " through its {server} server",
} as const;
/**
 * The reasons the dashboard journals (src/dashboard.ts) and the changes made in a terminal (init, uninstall, mcp wrap and
 * unwrap: src/cli.ts), read back as keys and values; any other reason is shown as it is.
 */
const REASONS: [RegExp, (m: RegExpExecArray) => { k: string; p?: Record<string, string>; t?: Record<string, string> }][] = [
  // one whole sentence per scope: a word put into a sentence cannot take the case or the form each language needs
  [/^set "(.+)" to (Allow|Ask|Block) for (coding agents|AI apps)$/, m => ({ k: `set "{rule}" to {action} for ${m[3]}`, t: { rule: m[1], action: m[2] } })],
  [/^set protection to (Relaxed|Balanced|Strict)$/, m => ({ k: "set protection to {level}", t: { level: m[1] } })],
  [/^added the exception (\S+) \(always (allow|ask|block) one exact command\)$/, m => ({ k: `added the exception {name} (always ${m[2]} one exact command)`, p: { name: m[1] } })],
  [/^removed the exception (\S+)$/, m => ({ k: "removed the exception {name}", p: { name: m[1] } })],
  [/^installed the hook of (.+)$/, m => ({ k: "installed the hook of {agent}", p: { agent: m[1] } })],
  [/^removed the hook of (.+)$/, m => ({ k: "removed the hook of {agent}", p: { agent: m[1] } })],
  [/^ran the MCP servers (.+) of (.+) through Kytral Guard$/, m => ({ k: "ran the MCP servers {servers} of {app} through Kytral Guard", p: { servers: m[1], app: m[2] } })],
  [/^stopped running the MCP servers (.+) of (.+) through Kytral Guard$/, m => ({ k: "stopped running the MCP servers {servers} of {app} through Kytral Guard", p: { servers: m[1], app: m[2] } })],
  [/^turned (on|off) (keeping the text of refused calls|journaling allowed calls)$/, m => ({ k: `turned ${m[1]} ${m[2]}` })],
  [/^deleted the kept command texts$/, () => ({ k: "deleted the kept command texts" })],
];
export const REASON_KEYS: readonly string[] = [
  'set "{rule}" to {action} for coding agents', 'set "{rule}" to {action} for AI apps', "set protection to {level}", "added the exception {name} (always allow one exact command)",
  "added the exception {name} (always ask one exact command)", "added the exception {name} (always block one exact command)",
  "removed the exception {name}", "installed the hook of {agent}", "removed the hook of {agent}", "ran the MCP servers {servers} of {app} through Kytral Guard",
  "stopped running the MCP servers {servers} of {app} through Kytral Guard",
  "turned on keeping the text of refused calls", "turned off keeping the text of refused calls", "turned on journaling allowed calls",
  "turned off journaling allowed calls", "deleted the kept command texts", "changed a setting",
];
/** The parts of the sentence about an event. `me`: the OS account of the person reading (their own actions say "You"). */
export function plainParts(e: PlainEvent, me = ""): PlainParts {
  const who = agentName(e.agent), place = shortPlace(e.cwd);
  const agent = who.key ? { whoKey: who.key } : { who: who.name };
  const where = who.server ? { where: { k: SENTENCES.throughServer, server: who.server } } : place ? { where: { k: SENTENCES.inPlace, place } } : {};
  // "alice (dashboard) (via the dashboard)", "bob (os:bob)": the name only; the reader's own account is "You"
  const by = (approver?: string): Pick<PlainParts, "by" | "byKey"> => {
    const name = (approver ?? "").replace(/\s*\((?:os:[^)]*|dashboard|via [^)]*)\)/g, "").trim();
    return !name ? { byKey: "Someone" } : me && name.toLowerCase() === me.toLowerCase() ? { byKey: "You" } : { by: name };
  };
  const did = () => plainActionParts(e), tool = { tool: shortTool(e.tool) };
  switch (e.decision) {
    case "block": {
      const more = [...(e.cannotAsk ? [who.server ? SENTENCES.noAnswer : SENTENCES.cannotAsk] : []), ...(e.approver ? [SENTENCES.refused] : [])];
      return { s: SENTENCES.block, ...(more.length ? { more } : {}), ...agent, ...did(), ...where, ...(e.approver ? by(e.approver) : {}) };
    }
    case "ask": return { s: SENTENCES.ask, ...agent, ...did(), ...where };
    case "request": return { s: SENTENCES.request, ...agent, ...did(), ...where };
    case "confirmed": case "confirmed-always":
      return { s: e.decision === "confirmed" ? SENTENCES.confirmed : SENTENCES.confirmedAlways, ...agent, ...did(), ...where, ...by(e.approver) };
    case "allow": return { s: SENTENCES.allow, ...agent, ...tool, ...where };
    case "kill": return { s: SENTENCES.kill, ...by(e.approver) };
    case "resume": return { s: SENTENCES.resume, ...by(e.approver) };
    case "known-add": return { s: SENTENCES.knownAdd, ...tool, ...by(e.approver) };
    case "known-remove": return { s: SENTENCES.knownRemove, ...tool, ...by(e.approver) };
    case "policy-change": case "settings-change": case "mcp-wrap": {
      const r = e.reason ?? "";
      for (const [re, read] of REASONS) { const m = re.exec(r); if (m) return { s: SENTENCES.change, ...by(e.approver), reason: read(m) }; }
      return { s: SENTENCES.change, ...by(e.approver), reason: r ? { text: r } : { k: "changed a setting" } };
    }
    case "kill-switch-invalid": case "known-tools-corrupt": case "known-reject": case "confirm-invalid": return { s: SENTENCES.damaged };
    default: return { s: SENTENCES.other, ...agent, decision: e.decision };
  }
}
/** The sentence said with `say(key, values)`: in US English here, in the reader's language on the page (same logic there). */
export function sayParts(x: PlainParts, say: (key: string, values: Record<string, string>) => string = fill): string {
  const values: Record<string, string> = {
    who: x.who ?? say(x.whoKey ?? "An agent", {}), by: x.by ?? say(x.byKey ?? "Someone", {}), tool: x.tool ?? "", decision: x.decision ?? "",
    what: x.what ? say(x.what, { tool: x.tool ?? "" }) : "",
    where: x.where ? say(x.where.k, { place: x.where.place ?? "", server: x.where.server ?? "" }) : "",
  };
  if (x.reason) values.reason = "text" in x.reason ? x.reason.text : say(x.reason.k, { ...x.reason.p, ...Object.fromEntries(Object.entries(x.reason.t ?? {}).map(([k, v]) => [k, say(v, {})])) });
  return [x.s, ...(x.more ?? [])].map(k => say(k, values)).join("");
}
/** One sentence about an event, for the Simple view, in US English. `me`: the OS account of the person reading. */
export function plainSentence(e: PlainEvent, me = ""): string {
  return sayParts(plainParts(e, me));
}
