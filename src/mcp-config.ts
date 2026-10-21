// `kytral-guard mcp list | wrap | unwrap`: the MCP servers configured in the AI apps of this machine (Claude Desktop, VS Code,
// Cline, Roo Code, Kilo Code, LM Studio, Continue, or any JSON or YAML file given) and the switch that runs each local (stdio) server through
// the guard's MCP proxy, or back. A wrapped server gets its own audience and a long-lived badge in its environment; the
// secret stays in KYTRAL_HOME. Coding agents with a Kytral hook (Claude Code, Cursor, Codex, Gemini CLI...) already check
// their MCP tools, so their files are not listed here. A remote server (a URL) cannot be wrapped by a local proxy.
// Files are merged like the hook installer does: other content kept, a backup written, an unreadable file left untouched.
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { isMap, isSeq, YAMLMap } from "yaml";
import { issueBadge, verifyBadge } from "./badge.js";
import { defaultCliPath, stableNodePath } from "./install.js";
import { parseDocumentQuietly } from "./quiet-yaml.js";
import { assertAudience } from "./secret.js";
import { stateDir, statePath } from "./store.js";

export interface McpClient { id: string; name: string; key: "mcpServers" | "servers"; paths: (appData: string, home: string) => string[] }
/** VS Code and its forks keep an extension's settings in User/globalStorage/<extension>/settings. */
const EDITORS = ["Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf", "Trae", "Trae CN", "Kiro", "Qoder"];
const extensionSettings = (appData: string, ext: string, file: string) => EDITORS.map(e => join(appData, e, "User", "globalStorage", ext, "settings", file));
export const MCP_CLIENTS: McpClient[] = [
  { id: "claude-desktop", name: "Claude Desktop", key: "mcpServers", paths: a => [join(a, "Claude", "claude_desktop_config.json")] },
  { id: "vscode", name: "VS Code", key: "servers", paths: a => ["Code", "Code - Insiders", "VSCodium"].map(e => join(a, e, "User", "mcp.json")) },
  { id: "cline", name: "Cline", key: "mcpServers", paths: a => extensionSettings(a, "saoudrizwan.claude-dev", "cline_mcp_settings.json") },
  { id: "roo", name: "Roo Code", key: "mcpServers", paths: a => extensionSettings(a, "rooveterinaryinc.roo-cline", "mcp_settings.json") },
  { id: "kilo", name: "Kilo Code", key: "mcpServers", paths: a => extensionSettings(a, "kilocode.kilo-code", "mcp_settings.json") },
  { id: "lmstudio", name: "LM Studio", key: "mcpServers", paths: (_a, h) => [join(h, ".lmstudio", "mcp.json")] },
  { id: "continue", name: "Continue", key: "mcpServers", paths: (_a, h) => [join(h, ".continue", "config.yaml")] },
  // iFlow CLI's hooks cannot tell its MCP tools (named without a prefix) from its own: its servers go through the proxy
  { id: "iflow", name: "iFlow CLI", key: "mcpServers", paths: (_a, h) => [join(h, ".iflow", "settings.json")] },
];
export const isMcpClient = (id: string) => MCP_CLIENTS.some(c => c.id === id);
/** Where apps keep their settings: %APPDATA%, ~/Library/Application Support, or $XDG_CONFIG_HOME (~/.config). */
export function appDataDir(home = homedir(), env: NodeJS.ProcessEnv = process.env, platform = process.platform): string {
  return platform === "win32" ? env.APPDATA ?? join(home, "AppData", "Roaming") : platform === "darwin" ? join(home, "Library", "Application Support") : env.XDG_CONFIG_HOME ?? join(home, ".config");
}

export interface McpOptions {
  /** Only these apps (ids of MCP_CLIENTS); `files` instead: these JSON files. Default: every app found. */
  clients?: string[]; files?: string[];
  home?: string; appData?: string; cliPath?: string; nodePath?: string;
  /** Policy options for the proxy (--policy file / --preset name); default: the proxy's own default. */
  policyArgs?: string[];
  dryRun?: boolean; now?: number;
  /** listMcp: also checks the badges of wrapped servers against this secret (else only that their node and CLI exist). */
  secret?: string;
}
/** `problem`: why a wrapped server refuses every call or does not start (see wrapProblem). */
export interface McpServer { name: string; remote: boolean; wrapped: boolean; command: string; problem?: string }
export interface McpFile { client: string; name: string; file: string; servers: McpServer[]; error?: string }
/** `renewed`: wrapped servers that no longer worked, given this installation's node and CLI and a new badge (in `changed` too). */
export interface McpChange { client: string; name: string; file: string; changed: string[]; skipped: { name: string; why: string }[]; renewed?: { name: string; why: string }[]; backup?: string; error?: string }

type Entry = Record<string, any>;
const isObj = (v: unknown): v is Entry => !!v && typeof v === "object" && !Array.isArray(v);
const isRemote = (e: Entry) => typeof e.url === "string" || typeof e.serverUrl === "string" || typeof e.httpUrl === "string"
  || /^(https?|sse|streamable-?https?|streamablehttp|ws)$/i.test(String(e.type ?? ""));
/** A server this command wrapped: node + Kytral's cli.js + "--" + the server's own command, with a badge. */
export const isWrapped = (e: Entry) => Array.isArray(e.args) && e.args.includes("--") && /(^|[\\/])cli\.[cm]?[jt]s$/i.test(String(e.args[0] ?? "")) && isObj(e.env) && typeof e.env.KYTRAL_BADGE === "string";
const describe = (e: Entry) => isRemote(e) ? String(e.url ?? e.serverUrl ?? e.type)
  : (isWrapped(e) ? e.args.slice(e.args.indexOf("--") + 1) : [e.command, ...(Array.isArray(e.args) ? e.args : [])]).join(" ");

/** The configuration files to look at: the ones given, else those of the apps (named or all) that exist. */
function targets(o: McpOptions): { client: string; name: string; file: string; key?: McpClient["key"] }[] {
  if (o.files?.length) return o.files.map(f => ({ client: "file", name: f, file: f }));
  const home = o.home ?? homedir(), appData = o.appData ?? appDataDir(home);
  const unknown = (o.clients ?? []).filter(c => !isMcpClient(c));
  if (unknown.length) throw new Error(`unknown app '${unknown[0]}' (${MCP_CLIENTS.map(c => c.id).join(", ")}), or give a file with --file`);
  return MCP_CLIENTS.filter(c => !o.clients?.length || o.clients.includes(c.id))
    .flatMap(c => c.paths(appData, home).filter(f => existsSync(f)).map(file => ({ client: c.id, name: c.name, file, key: c.key })));
}
/** JSON with comments and trailing commas (VS Code's own files allow them) read as plain JSON, strings left as they are. */
export function withoutComments(text: string): string {
  let out = "", i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') { const end = /"(?:[^"\\]|\\.)*"/y; end.lastIndex = i; const m = end.exec(text); const s = m ? m[0] : text.slice(i); out += s; i += s.length; continue; }
    if (c === "/" && text[i + 1] === "/") { while (i < text.length && text[i] !== "\n") i++; continue; }
    if (c === "/" && text[i + 1] === "*") { const end = text.indexOf("*/", i + 2); i = end < 0 ? text.length : end + 2; continue; }
    out += c; i++;
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}
function readJson(text: string): Entry {
  if (!text.trim()) return {};
  let v: unknown;
  try { v = JSON.parse(text); } catch (e) {
    // comments or trailing commas: rewriting the file would drop them, so it is left to the person (and said why)
    let jsonc = false; try { jsonc = isObj(JSON.parse(withoutComments(text))); } catch {}
    if (jsonc) throw new Error("has comments or trailing commas (VS Code allows them, JSON does not): Kytral Guard would drop them by rewriting it, so nothing was changed. Remove them, or wrap its servers by hand (docs/mcp-proxy.md)");
    throw new Error(`not valid JSON (${(e as Error).message}): edit it by hand, nothing was changed`);
  }
  if (!isObj(v)) throw new Error("does not hold a JSON object: nothing was changed");
  return v;
}
/** The servers map of a JSON file (the object itself, edited in place): its app's key, else whichever of mcpServers / servers it has. */
function serversOf(data: Entry, key?: McpClient["key"]): Entry {
  const k = key ?? (isObj(data.servers) && !isObj(data.mcpServers) ? "servers" : "mcpServers");
  return isObj(data[k]) ? data[k] : {};
}
/** A configuration file's servers, as plain entries to read or edit, and the file's new text with the edited entries. */
interface Loaded { entries: [string, Entry][]; text: (changed: Set<string>) => string }
function load(file: string, key?: McpClient["key"]): Loaded {
  let before: string;   // the file is named by the caller: the error says what is wrong with it, not the path again
  try { before = readFileSync(file, "utf8"); }
  catch (e) { const code = (e as NodeJS.ErrnoException).code; throw new Error(code === "ENOENT" ? "no such file" : code === "EISDIR" ? "a folder, not a file" : (e as Error).message); }
  if (/\.ya?ml$/i.test(file)) {
    // Continue: a YAML list of { name, command, args, env }; comments and layout are kept
    const doc = parseDocumentQuietly(before);
    if (doc.errors.length) throw new Error(`not valid YAML (${doc.errors[0].message}): edit it by hand, nothing was changed`);
    const seq = doc.get("mcpServers");
    const maps = isSeq(seq) ? seq.items.filter((m): m is YAMLMap => isMap(m)) : [];
    const entries = maps.map((m, i) => [String(m.get("name") ?? `server-${i + 1}`), m.toJSON() as Entry] as [string, Entry]);
    return { entries, text: changed => {
      entries.forEach(([name, e], i) => {
        if (!changed.has(name)) return;
        const m = maps[i];
        m.set("command", e.command); m.set("args", doc.createNode(e.args));
        if (e.env) m.set("env", doc.createNode(e.env)); else m.delete("env");
      });
      return doc.toString({ lineWidth: 0 });
    } };
  }
  const data = readJson(before), servers = serversOf(data, key);
  return { entries: Object.entries(servers).filter(([, e]) => isObj(e)), text: () => JSON.stringify(data, null, before.includes("\t") ? "\t" : 2) + "\n" };
}

export function listMcp(o: McpOptions = {}): McpFile[] {
  const now = o.now ?? Date.now(), revoked = revocations();
  return targets(o).map(t => {
    try {
      return { ...t, servers: load(t.file, t.key).entries.map(([name, e]) => {
        const problem = isWrapped(e) ? wrapProblem(e, o.secret, now, revoked) : undefined;
        return { name, remote: isRemote(e), wrapped: isWrapped(e), command: describe(e), ...(problem ? { problem } : {}) };
      }) };
    } catch (e) { return { ...t, servers: [], error: (e as Error).message }; }
  });
}

const audienceOf = (client: string, name: string) => `kytral-guard:mcp:${client}:${name}`.replace(/[^\w.:@\/-]/g, "-").slice(0, 128);
const BADGE_SECONDS = 5 * 365 * 24 * 3600;   // `mcp wrap` renews a badge in its last 30 days
const RENEW_WITHIN_MS = 30 * 24 * 3600 * 1000;
/** Revoked badge ids, agents and nonces ($KYTRAL_REVOCATIONS or $KYTRAL_HOME/revocations.json), read only. */
function revocations(): { has(x: string): boolean; broken?: string } {
  const f = statePath(process.env.KYTRAL_REVOCATIONS, "revocations.json");
  if (!existsSync(f)) return { has: () => false };
  try {
    const raw = JSON.parse(readFileSync(f, "utf8"));
    const keys = new Set<string>(Array.isArray(raw) ? raw.map(String) : Object.keys(raw ?? {}));
    return { has: x => keys.has(x) };
  } catch { return { has: () => true, broken: `the revocation list ${f} does not parse` }; }   // nothing is renewed
}
const badgeBody = (token: string): Record<string, unknown> => { try { return JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString()); } catch { return {}; } };
/**
 * Why a wrapped server no longer works, or undefined: the node or CLI it runs is gone (a Node.js upgrade, another global
 * folder), or its badge is revoked, not signed by this secret (a new secret), expired or about to (30 days), or made for
 * another audience. Each one refuses every call, or keeps the server from starting. Without a secret: the paths only.
 */
export function wrapProblem(e: Entry, secret: string | undefined, now = Date.now(), revoked: { has(x: string): boolean; broken?: string } = revocations()): string | undefined {
  // a revoked badge first: whatever else is wrong, it is never renewed (that would undo the revocation)
  const body = badgeBody(String(e.env?.KYTRAL_BADGE ?? ""));
  if (revoked.broken) return revoked.broken;
  if ([body.id, body.agentId, body.nonce].some(x => typeof x === "string" && revoked.has(x))) return "its badge is revoked";
  if (typeof e.command === "string" && isAbsolute(e.command) && !existsSync(e.command)) return `node is no longer at ${e.command}`;
  const cli = String(e.args?.[0] ?? "");
  if (isAbsolute(cli) && !existsSync(cli)) return `Kytral Guard is no longer at ${cli}`;
  return badgeProblem(e, secret, now);
}
/**
 * A server wrapped for another KYTRAL_HOME (its own, written in its environment, or the default one when this command runs
 * with a custom one) uses that home's secret: its badge cannot be checked, nor renewed, with this one.
 */
const otherHome = (e: Entry) => {
  const own = resolve(typeof e.env?.KYTRAL_HOME === "string" && e.env.KYTRAL_HOME ? e.env.KYTRAL_HOME : join(homedir(), ".kytral")), here = stateDir();
  return process.platform === "win32" ? own.toLowerCase() !== here.toLowerCase() : own !== here;
};
/** Why the badge of a wrapped server no longer works with this secret (see wrapProblem), or undefined. */
function badgeProblem(e: Entry, secret: string | undefined, now: number): string | undefined {
  if (!secret || otherHome(e)) return undefined;
  const token = String(e.env?.KYTRAL_BADGE ?? ""), body = badgeBody(token);
  try {
    const b = verifyBadge(secret, token, { has: () => false }, now + RENEW_WITHIN_MS);
    if (b.aud !== e.env?.KYTRAL_AUDIENCE) return "its badge is for another audience";
  } catch (err) {
    const m = (err as Error).message;
    return /expired/.test(m) ? (typeof body.expiresAt === "number" && body.expiresAt < now ? "its badge expired" : "its badge expires within 30 days")
      : /signature|malformed/.test(m) ? "its badge is not signed by this secret (a new secret?)" : m.replace(/^badge: /, "its badge: ");
  }
  return undefined;
}
type Edit = string | null | { renewed: string };   // a reason to skip ("" says nothing), changed, or renewed
function change(o: McpOptions, edit: (name: string, e: Entry, client: string) => Edit): McpChange[] {
  return targets(o).map(t => {
    const result: McpChange = { client: t.client, name: t.name, file: t.file, changed: [], skipped: [] };
    let loaded: Loaded;
    try { loaded = load(t.file, t.key); } catch (e) { return { ...result, error: (e as Error).message }; }
    for (const [name, e] of loaded.entries) {
      const why = edit(name, e, t.client);
      if (why === null) result.changed.push(name);
      else if (typeof why === "object") { result.changed.push(name); (result.renewed ??= []).push({ name, why: why.renewed }); }
      else if (why) result.skipped.push({ name, why });
    }
    if (result.changed.length && !o.dryRun) {
      const text = loaded.text(new Set(result.changed));
      result.backup = `${t.file}.kytral-backup`; copyFileSync(t.file, result.backup);
      writeFileSync(t.file, text);
    }
    return result;
  });
}
/**
 * Runs every local server of the files through the proxy. `secret` signs the badges. Returns, per file, the servers
 * wrapped, the wrapped ones renewed because they no longer worked (wrapProblem), and the ones left as they were (remote,
 * already wrapped and working, or revoked: a revocation is never undone here).
 */
export function wrapMcp(secret: string, o: McpOptions = {}): McpChange[] {
  const node = o.nodePath ?? stableNodePath(), cli = o.cliPath ?? defaultCliPath(), now = o.now ?? Date.now(), revoked = revocations();
  const results = change(o, (name, e, client) => {
    if (isRemote(e)) return "remote server (a URL): a local proxy cannot wrap it";
    if (typeof e.command !== "string" || !e.command) return "no command";
    if (isWrapped(e)) {
      const problem = wrapProblem(e, secret, now, revoked);
      if (!problem) return "";   // already protected and working: left as it is
      if (/revoked|revocation/.test(problem)) return `${problem}: left as it is`;
      // this installation's node and CLI where the old ones are gone (not with a copy that is not installed either: it would
      // be "repaired" again at every run), and a new badge for the same audience only when the badge itself no longer works
      const cliGone = isAbsolute(String(e.args[0])) && !existsSync(String(e.args[0]));
      if (cliGone && !existsSync(cli)) return `${problem}: this copy of Kytral Guard cannot replace it (${cli} does not exist)`;
      if (isAbsolute(e.command) && !existsSync(e.command)) e.command = node;
      if (cliGone) e.args[0] = cli;
      if (badgeProblem(e, secret, now)) {
        let aud: string; try { aud = assertAudience(e.env.KYTRAL_AUDIENCE); } catch { aud = audienceOf(client, name); }
        e.env = { ...e.env, KYTRAL_AUDIENCE: aud, KYTRAL_BADGE: issueBadge(secret, `mcp:${client}:${name}`, ["*"], BADGE_SECONDS, now, { aud }) };
      }
      return { renewed: problem };
    }
    const aud = audienceOf(client, name);
    e.args = [cli, ...(o.policyArgs ?? []), "--", e.command, ...(Array.isArray(e.args) ? e.args.map(String) : [])];
    e.command = node;
    e.env = { ...(isObj(e.env) ? e.env : {}), KYTRAL_AUDIENCE: aud, KYTRAL_BADGE: issueBadge(secret, `mcp:${client}:${name}`, ["*"], BADGE_SECONDS, now, { aud }),
      ...(process.env.KYTRAL_HOME ? { KYTRAL_HOME: process.env.KYTRAL_HOME } : {}) };
    return null;
  });
  // a file given with --file that runs servers through the proxy (wrapped now, or already): recorded (see recordedFiles)
  const wrapsSome = (r: McpChange) => r.changed.length > 0 || !!listMcp({ files: [r.file] })[0]?.servers.some(s => s.wrapped);
  if (!o.dryRun) remember(results.filter(r => r.client === "file" && !r.error && wrapsSome(r)).map(r => r.file), true);
  return results;
}
/**
 * The configuration files wrapped with --file, kept in KYTRAL_HOME: no app names them, so without this record `mcp list`,
 * doctor and `uninstall --all` would not know them, and their servers would no longer start once the package is removed.
 */
const filesRecord = () => statePath(undefined, "mcp-files.json");
export function recordedFiles(): string[] {
  try { const v = JSON.parse(readFileSync(filesRecord(), "utf8")); return Array.isArray(v) ? v.filter((f): f is string => typeof f === "string" && existsSync(f)) : []; }
  catch { return []; }
}
function remember(files: string[], add: boolean): void {
  if (!files.length) return;
  const key = (f: string) => process.platform === "win32" ? resolve(f).toLowerCase() : resolve(f), drop = new Set(files.map(key));
  const kept = recordedFiles().filter(f => !drop.has(key(f))), next = add ? [...kept, ...files.map(f => resolve(f))] : kept;
  try {
    if (!next.length) rmSync(filesRecord(), { force: true });
    else { mkdirSync(dirname(filesRecord()), { recursive: true, mode: 0o700 }); writeFileSync(filesRecord(), JSON.stringify(next, null, 2) + "\n", { mode: 0o600 }); }
  } catch { /* the change itself is done; only the record is missing */ }
}
/** Gives every wrapped server its own command back. */
export function unwrapMcp(o: McpOptions = {}): McpChange[] {
  const results = unwrapAll(o);
  if (!o.dryRun) remember(results.filter(r => r.client === "file" && !r.error).map(r => r.file), false);
  return results;
}
function unwrapAll(o: McpOptions): McpChange[] {
  return change(o, (_name, e) => {
    if (!isWrapped(e)) return "";
    const rest = e.args.slice(e.args.indexOf("--") + 1);
    e.command = String(rest[0]); e.args = rest.slice(1);
    const { KYTRAL_AUDIENCE: _a, KYTRAL_BADGE: _b, ...env } = e.env;
    if (env.KYTRAL_HOME !== undefined && env.KYTRAL_HOME === process.env.KYTRAL_HOME) delete env.KYTRAL_HOME;   // added by wrap
    if (Object.keys(env).length) e.env = env; else delete e.env;
    return null;
  });
}
