// Minimal MCP stdio proxy: sits between an MCP client (Claude Code, Cursor, n8n) and a real MCP server.
// Usage: KYTRAL_BADGE=... KYTRAL_SECRET=... kytral-guard [proxy] [--policy file | --preset name] -- <server cmd...>
import { spawn } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { basename, resolve } from "node:path";
import { createInterface } from "node:readline";
import { Guard } from "./guard.js";
import { prewarmEvaluate } from "./evaluate-bounded.js";
import { loadPolicy, policyErrorLine, presetPolicy, DEFAULT_POLICY, Policy, PRESETS, tamperFindings } from "./policy.js";
import { AuditLog, auditKey } from "./audit.js";
import { assertStrongSecret, assertAudience, assertAuditSecret, resolveSecret } from "./secret.js";
import { readRegular, statePath } from "./store.js";
import { ARGS_SHOWN, confirmMode, FileConfirmQueue, nobodyToAsk, printable } from "./confirm-queue.js";
import { KytralPlugin, loadPlugins, pluginPolicy, pluginSpecs } from "./plugins.js";
import { mcpPolicyPath } from "./policy-file.js";
import { keepCallsEnabled } from "./kept-calls.js";
import { serverCommand, serverEnv } from "./spawn.js";

/** The policy of a proxy started without --policy or --preset: $KYTRAL_HOME/mcp-policy.yaml (the dashboard edits it), else the strict preset. */
export function defaultProxyPolicy(): Policy {
  const f = mcpPolicyPath();
  return existsSync(f) ? loadPolicy(readRegular(f).toString("utf8")) : loadPolicy(DEFAULT_POLICY);
}
/** What a proxy enforces while its policy file does not load: every call refused, with a rule that says why. */
export const BROKEN_POLICY = (): Policy => loadPolicy("default: block\nunknownTools: block\nrules:\n  - name: invalid-policy-file\n    action: block\n");
const fileSig = (f: string) => { try { const s = statSync(f); return `${s.size}:${s.mtimeMs}:${s.ino}`; } catch { return "-"; } };
/**
 * Follows a policy file: `apply` gets its new policy each time it changes (checked every `intervalMs`), `fail` gets why it no
 * longer loads, `gone` is called when it is deleted. A file that appears later is loaded then. `since` is the file's signature
 * when its policy was read (taken before reading, so that a change made meanwhile is not missed). Returns a stop function.
 */
export function followPolicyFile(file: string, on: { apply: (p: Policy) => void; fail: (why: string) => void; gone: () => void }, intervalMs = 1000, since = fileSig(file)): () => void {
  let last = since;
  const timer = setInterval(() => {
    const now = fileSig(file);
    if (now === last) return;
    last = now;
    if (now === "-") return on.gone();
    let p: Policy;
    try { p = loadPolicy(readRegular(file).toString("utf8")); } catch (e) { return on.fail((e as Error).message); }   // never waits on a FIFO
    on.apply(p);
  }, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}

const rpcError = (id: unknown, code: number, message: string) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });
const denied = (id: unknown, why: string) => ({ jsonrpc: "2.0", id, result: { isError: true, content: [{ type: "text", text: `Kytral Guard: ${why}` }] } });
const isObj = (m: unknown): m is Record<string, any> => !!m && typeof m === "object" && !Array.isArray(m);
/** The file a resource URI names (file:///C:/x, file:///home/u/x, file://host/x, percent-encoded), else the URI itself. */
export function resourcePath(uri: string): string {
  let p = uri.replace(/^file:(\/\/[^\/]*)?/i, "");
  if (p !== uri && /^\/[A-Za-z]:/.test(p)) p = p.slice(1);
  try { p = decodeURIComponent(p); } catch {}
  return p;
}
/** An error as its code (ENOENT, EACCES...): Node's own message and report repeat the path or the command line, a value of which may be a secret. */
const errCode = (e: unknown) => { const c = (e as NodeJS.ErrnoException)?.code; return typeof c === "string" && /^[A-Z][A-Z0-9_]{1,39}$/.test(c) ? c : "error"; };

type Verdict = object | null | undefined;   // null = forward, object = reply to client, undefined = drop silently
/** Synchronous inspection. Returns a verdict, or a promise only when a human confirmation is pending. */
function inspect(guard: Guard, badge: string, msg: unknown): Verdict | Promise<Verdict> {
  if (!isObj(msg)) return rpcError(null, -32600, "Kytral Guard: invalid JSON-RPC message");
  if (msg.method === "tools/list" && "id" in msg) expectToolsListPage(guard, msg.id, isObj(msg.params) ? msg.params.cursor : undefined);
  // A resource naming the guard's secret or keys (they sign approvals and kill switch states) is refused, as a tool call
  // reading them is: a server may expose the home folder as resources.
  if (msg.method === "resources/read" && isObj(msg.params) && typeof msg.params.uri === "string") {
    const found = tamperFindings({ uri: resourcePath(msg.params.uri) });
    if (found.length) {
      try { guard.refuse(badge, "resources/read", "guard-tamper", `blocked: ${found[0]} is the guard's own secret`, { uri: msg.params.uri }); }
      catch (e) { return "id" in msg ? rpcError(msg.id, -32000, `Kytral Guard: ${(e as Error).message}`) : undefined; }
    }
    return null;
  }
  if (msg.method !== "tools/call") return null;
  if (!isObj(msg.params) || typeof msg.params.name !== "string") return rpcError(msg.id, -32602, "Kytral Guard: tools/call without a tool name");
  // MCP arguments are an object. Anything else would be analyzed as no argument while the server receives it as sent (a
  // server outside the SDKs may read an array or a string): refused. Absent or null: no argument.
  const a = msg.params.arguments;
  if (a !== undefined && a !== null && !isObj(a)) return "id" in msg ? rpcError(msg.id, -32602, "Kytral Guard: tools/call arguments must be an object") : undefined;
  const refuse = (e: unknown) => ("id" in msg ? denied(msg.id, (e as Error).message) : undefined);
  try {
    const pending = guard.checkSync(badge, { tool: msg.params.name, args: isObj(a) ? a : {} });
    return pending ? pending.confirm().then(() => null, refuse) : null;
  } catch (e) { return refuse(e); }
}

/**
 * Handles one client line. Fully synchronous (returns undefined) unless a human confirmation is pending,
 * in which case it returns a promise; callers must not process the next line before it settles (see ClientPipeline).
 */
export function handleClientLineSync(guard: Guard, badge: string, line: string, toServer: (s: string) => void, toClient: (s: string) => void): void | Promise<void> {
  if (!line.trim()) return;
  let msg: unknown;
  try { msg = JSON.parse(line); } catch { toClient(JSON.stringify(rpcError(null, -32700, "Kytral Guard: parse error, non-JSON input refused"))); return; }
  if (Array.isArray(msg)) {
    // Batch: every element is checked; if anything is refused, nothing of the batch is forwarded.
    if (!msg.length) { toClient(JSON.stringify(rpcError(null, -32600, "Kytral Guard: empty batch"))); return; }
    const raw = msg.map(m => inspect(guard, badge, m));
    const finish = (verdicts: Verdict[]) => {
      if (verdicts.every(v => v === null)) { toServer(line); return; }
      const replies = msg.map((m: unknown, i: number) => verdicts[i] ?? (isObj(m) && "id" in m ? rpcError(m.id, -32600, "Kytral Guard: batch rejected (another element was refused)") : undefined)).filter(Boolean);
      if (replies.length) toClient(JSON.stringify(replies));
    };
    return raw.some(v => v instanceof Promise) ? Promise.all(raw).then(finish) : finish(raw as Verdict[]);
  }
  const deliver = (v: Verdict) => { if (v === null) toServer(line); else if (v) toClient(JSON.stringify(v)); };
  const v = inspect(guard, badge, msg);
  return v instanceof Promise ? v.then(deliver) : deliver(v);
}
export async function handleClientLine(guard: Guard, badge: string, line: string, toServer: (s: string) => void, toClient: (s: string) => void): Promise<void> {
  await handleClientLineSync(guard, badge, line, toServer, toClient);
}

/** Strict FIFO: a line is never forwarded before every earlier line has been decided and forwarded/answered. */
export class ClientPipeline {
  private queue: string[] = []; private busy = false; private idle: (() => void)[] = [];
  constructor(private guard: Guard, private badge: string, private toServer: (s: string) => void, private toClient: (s: string) => void) {}
  push(line: string) { this.queue.push(line); if (!this.busy) this.drain(); }
  /** Runs `f` once every line pushed so far has been decided and forwarded or answered (at once if none is waiting). */
  whenIdle(f: () => void) { if (this.busy || this.queue.length) this.idle.push(f); else f(); }
  private drain() {
    while (this.queue.length) {
      const r = handleClientLineSync(this.guard, this.badge, this.queue.shift()!, this.toServer, this.toClient);
      if (r instanceof Promise) { this.busy = true; r.finally(() => { this.busy = false; this.drain(); }); return; }
    }
    for (const f of this.idle.splice(0)) f();
  }
  get pending() { return this.queue.length + (this.busy ? 1 : 0); }
}

/** Upper bound on learned server tool names: a server paging forever cannot grow memory without limit (extra names stay unknown = confirm). */
export const MAX_SERVER_TOOLS = 4096;
const MAX_PENDING_CURSORS = 1024;
/** Upper bound on remembered destructiveHint names. Never shrinks; beyond the cap the set fails closed. */
export const MAX_DESTRUCTIVE_TOOLS = 4096;
/**
 * destructiveTools only ever escalates (allow -> confirm). Capped without ever forgetting a name: once a new
 * destructive name cannot be stored, has() answers true for EVERY tool, so every otherwise-allowed call needs confirmation.
 */
export class CappedDestructiveSet extends Set<string> {
  overflowed = false;
  constructor(init: Iterable<string> = [], readonly cap = MAX_DESTRUCTIVE_TOOLS) { super(); for (const x of init) this.add(x); }
  add(x: string) {
    if (super.has(x)) return this;
    if (this.size >= this.cap) {
      if (!this.overflowed) {   // logged once per process, on stderr (stdout carries the MCP protocol)
        this.overflowed = true;
        console.error(`kytral-guard: STRICT MODE - the server announced more than ${this.cap} destructive tools; every otherwise-allowed call now needs confirmation until restart`);
      }
      return this;
    }
    return super.add(x);
  }
  has(x: string) { return this.overflowed || super.has(x); }
  delete(_x: string) { return false; }   // never forget a destructive tool
  clear() {}
}
const destructiveOf = (g: Guard): Set<string> => (g.destructiveTools instanceof CappedDestructiveSet ? g.destructiveTools : (g.destructiveTools = new CappedDestructiveSet(g.destructiveTools)));
/** Pagination state per Guard: the cursor each pending tools/list request carried, and the last nextCursor received. */
interface Paging { cursors: Map<string, string | undefined>; lastNext: string | null }
const paging = new WeakMap<Guard, Paging>();
const pagingOf = (g: Guard): Paging => { let p = paging.get(g); if (!p) paging.set(g, p = { cursors: new Map(), lastNext: null }); return p; };
/** Records a client tools/list request: its id (correlation) and the cursor it carries (pagination). */
export function expectToolsListPage(guard: Guard, id: unknown, cursor: unknown) {
  guard.expectToolsList(id);
  const p = pagingOf(guard); const k = JSON.stringify(id);
  p.cursors.delete(k); p.cursors.set(k, typeof cursor === "string" ? cursor : undefined);
  while (p.cursors.size > MAX_PENDING_CURSORS) p.cursors.delete(p.cursors.keys().next().value!);
}

/**
 * Learns tool names (and destructiveHint) ONLY from the response to a tools/list the client sent (same id).
 * Pagination: a page is merged into the list ONLY if its request carried exactly the last nextCursor received;
 * any other reply (no cursor, other cursor) starts a new listing and replaces the list. An error, or a reply
 * without a tools array, resets the pagination state. destructiveHint only ever escalates. A hostile server can
 * still advertise its own tools: unknownTools=confirm protects against unadvertised tools, not a hostile server.
 */
export function observeServerLine(guard: Guard, line: string) {
  // Only a reply to a pending tools/list teaches (or consumes) anything. Every such reply is parsed, whatever it holds: an
  // error or a result without tools releases its id too, so a second reply for the same id is ignored.
  if (guard.pendingToolsList.size === 0) return;
  try {
    const msgs = ([] as any[]).concat(JSON.parse(line));
    const p = pagingOf(guard);
    for (const m of msgs) {
      if (!isObj(m) || !("id" in m)) continue;
      const key = JSON.stringify(m.id);
      if (!guard.pendingToolsList.has(key)) continue;
      guard.pendingToolsList.delete(key);   // one reply per id, success or error
      const cursor = p.cursors.get(key); p.cursors.delete(key);
      if (!isObj(m.result) || !Array.isArray(m.result.tools)) { p.lastNext = null; continue; }   // error / malformed: reset
      const continues = cursor !== undefined && p.lastNext !== null && cursor === p.lastNext;
      if (!continues) guard.serverTools = new Set();                                           // new listing: replace
      const next = m.result.nextCursor;
      p.lastNext = typeof next === "string" && next !== "" ? next : null;
      for (const t of m.result.tools) {
        if (typeof t?.name !== "string") continue;
        if (guard.serverTools.size < MAX_SERVER_TOOLS) guard.serverTools.add(t.name);
        const a = t?.annotations ?? {};
        if (a.destructiveHint === true && a.readOnlyHint !== true) destructiveOf(guard).add(t.name);
      }
    }
  } catch {}
}

/** Where a proxy's policy comes from: a file (--policy), else a built-in preset (--preset), else defaultProxyPolicy(). */
export interface ProxyOptions { policyFile?: string; preset?: string }
/**
 * The proxy in front of `server` (the MCP server command and its arguments, passed as they are). The CLI parses the options
 * first (cli.ts): an unknown one stops it before this runs. Loads the plugins (a plugin that does not load refuses to start),
 * then serves.
 */
export async function main(server: string[], o: ProxyOptions = {}): Promise<void> {
  let plugins: KytralPlugin[] = [];
  try { plugins = await loadPlugins(pluginSpecs()); } catch (e) { console.error(`kytral-guard: refusing to start: ${(e as Error).message}`); process.exit(2); }
  serve(server, o, plugins);
}
function serve(server: string[], o: ProxyOptions, plugins: KytralPlugin[]) {
  let secret: string, audience: string, policy: Policy;
  try { secret = assertStrongSecret(resolveSecret()); audience = assertAudience(process.env.KYTRAL_AUDIENCE); assertAuditSecret(); } catch (e) { console.error(`kytral-guard: refusing to start: ${(e as Error).message}`); process.exit(2); }
  // The policy file is named by what it is, never by its path. Not a policy (a YAML syntax error, a .env, a schema error, an
  // empty or binary file): one fixed line, before anything is created or started. The parser's message and Node's report quote
  // the file, which may hold a secret: a YAML syntax error is given by its line only.
  const policyFile = o.policyFile !== undefined ? resolve(o.policyFile) : o.preset !== undefined ? null : mcpPolicyPath(), sig = policyFile ? fileSig(policyFile) : "-";
  const shown = o.policyFile !== undefined ? "the --policy file" : basename(mcpPolicyPath());
  function refuse(why: string): never { console.error(`kytral-guard: refusing to start: ${why}`); process.exit(2); }
  function invalid(e: unknown): never { const line = policyErrorLine(e); refuse(`${shown} is not a valid policy${line ? ` (line ${line})` : ""}`); }
  if (o.policyFile !== undefined) {
    let text = "";
    try { text = readRegular(o.policyFile).toString("utf8"); } catch (e) { refuse(`the --policy file cannot be read (${errCode(e)})`); }
    try { policy = loadPolicy(text); } catch (e) { invalid(e); }
  } else if (o.preset !== undefined) {
    try { policy = presetPolicy(o.preset); } catch { refuse(`unknown preset (${Object.keys(PRESETS).join(", ")})`); }
  } else {
    try { policy = defaultProxyPolicy(); } catch (e) { invalid(e); }
  }
  // A plugin's policy (central, signed) replaces the local one. One that does not load: one line, in fixed words (pluginPolicy).
  let central: Policy | undefined;
  try { central = pluginPolicy(plugins, "proxy"); } catch (e) { refuse((e as Error).message); }
  // Confirmation queue: a human answers in the dashboard or with `kytral-guard confirm ...`, instead of every confirmation
  // being refused. KYTRAL_CONFIRM_QUEUE=1: always; unset: while a dashboard is open; 0: never (confirmMode).
  let confirmQueue: FileConfirmQueue | null = null;
  const mode = confirmMode();
  if (mode !== "off") {
    const t = process.env.KYTRAL_CONFIRM_TIMEOUT_MS;
    try {
      confirmQueue = new FileConfirmQueue({ secret, timeoutMs: t === undefined ? undefined : Number(t), unanswerable: nobodyToAsk,
        notify: r => console.error(`kytral-guard: confirmation needed ${r.id} tool=${printable(r.tool)} agent=${printable(r.agentId)} rule=${printable(r.rule)}: answer in kytral-guard dashboard, or kytral-guard confirm approve ${r.id}${r.always ? " [--always]" : ""} | deny ${r.id}`
          + (r.args.length > ARGS_SHOWN ? ` (arguments: ${r.args.length} characters, review them with 'kytral-guard confirm list --full'; approving needs --full)` : "")) });
    } catch (e) {
      // asked for (KYTRAL_CONFIRM_QUEUE=1): refuse to start; automatic: go on without it, confirmations are refused
      if (mode === "on") { console.error(`kytral-guard: refusing to start: ${(e as Error).message}`); process.exit(2); }
      console.error(`kytral-guard: no confirmation queue (${(e as Error).message}): calls that need a human are refused`);
    }
    if (confirmQueue?.orphansRemoved) console.error(`kytral-guard: removed ${confirmQueue.orphansRemoved} orphaned confirmation request(s) left by stopped proxies`);
  }
  // The guard starts from the last kill or resume the audit log records (a kill-switch.json deleted after a kill still
  // stops it): a log, or another state file, that cannot be read stops the proxy here, in fixed words (fail closed).
  let guard: Guard;
  try {
    guard = new Guard({ policy: central ?? policy, secret, audience, audit: new AuditLog(statePath(process.env.KYTRAL_AUDIT, "audit.jsonl"), { key: auditKey(secret) }),
      confirmQueue, plugins, source: "proxy", keepCalls: keepCallsEnabled() });
  } catch (e) { refuse(`the audit log, the kill switch or another state file of KYTRAL_HOME cannot be read (${errCode(e)}): run 'kytral-guard doctor'`); }
  // A local policy file (--policy, else mcp-policy.yaml, which the dashboard edits) applies from the next call when it
  // changes. One that no longer loads refuses every call until it is fixed (fail closed); mcp-policy.yaml deleted: the
  // strict preset again. A preset is fixed, and a plugin's policy is the plugin's.
  const followed = central ? null : policyFile;
  if (followed) followPolicyFile(followed, {
    apply: p => { guard.setPolicy(p); console.error(`kytral-guard: ${shown} changed: its rules apply from the next call`); },
    fail: () => { guard.setPolicy(BROKEN_POLICY()); console.error(`kytral-guard: ${shown} does not load: every call is refused until it is fixed ('kytral-guard policy validate <file>' says why)`); },
    gone: () => {
      if (followed === mcpPolicyPath()) { guard.setPolicy(loadPolicy(DEFAULT_POLICY)); console.error(`kytral-guard: ${shown} was deleted: the strict preset applies`); }
      else { guard.setPolicy(BROKEN_POLICY()); console.error(`kytral-guard: ${shown} was deleted: every call is refused until it is back`); }
    },
  }, 1000, sig);
  if (process.env.KYTRAL_KILL === "1") guard.kill();
  prewarmEvaluate();   // the analysis thread (evaluate-bounded.ts) starts now, not at the first tool call
  // Kill switch shared with `kytral-guard kill` / `resume`: read before every tool call, and also polled while idle, so that
  // stderr says within 1 s that this proxy stopped or runs again. Nothing the poll meets is thrown out of it (that would end
  // the proxy): killReason() never throws, and whatever else fails is ignored until the next poll.
  let killNote = guard.killReason();
  if (killNote) console.error(`kytral-guard: ${killNote}`);
  setInterval(() => {
    try {
      const now = guard.killReason();
      if (now !== killNote) console.error(now ? `kytral-guard: ${now}` : "kytral-guard: kill switch lifted, tool calls are checked again");
      killNote = now;
    } catch { /* the next poll tries again; tool calls check the switch themselves */ }
  }, 250).unref();
  const [cmd, ...rest] = server;
  // started as its client would (npx and other .cmd shims on Windows), without the guard's secrets in its environment
  const run = serverCommand(cmd, rest);
  const child = spawn(run.file, run.args, { stdio: ["pipe", "pipe", "inherit"], env: serverEnv(), windowsVerbatimArguments: run.verbatim });
  child.on("error", e => { console.error(`kytral-guard: the MCP server command cannot be started (${errCode(e)})`); process.exit(1); });   // not Node's report: it lists the arguments
  createInterface({ input: child.stdout }).on("line", l => { observeServerLine(guard, l); process.stdout.write(l + "\n"); });
  const pipeline = new ClientPipeline(guard, process.env.KYTRAL_BADGE ?? "", s => child.stdin.write(s + "\n"), s => process.stdout.write(s + "\n"));
  const input = createInterface({ input: process.stdin });
  input.on("line", l => pipeline.push(l));
  // MCP's stdio shutdown: the client closes the proxy's input and waits for it to exit. The server gets the same end of
  // input once every line received before is decided, and the proxy exits with it (it used to wait for a kill).
  input.on("close", () => pipeline.whenIdle(() => child.stdin.end()));
  child.stdin.on("error", () => {});   // a server that stopped reading: its exit ends the proxy
  // A proxy stopped by a signal stops its server (Windows ends processes without one: the server then sees its input end).
  for (const s of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.on(s, () => { child.kill(s); setTimeout(() => process.exit(1), 3000).unref(); });
  child.on("exit", (c, s) => process.exit(c ?? (s ? 1 : 0)));
}
