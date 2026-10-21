// `kytral-guard dashboard`: a page on this computer only to see what the agents did and to change what they may do, without
// an account. The person who starts it in a terminal signs in with a one-time link the command opens in the browser.
//
// Security (docs/dashboard.md):
// - The server listens on 127.0.0.1 and answers only requests addressed to it by its own address and port (DNS rebinding).
// - The link carries a one-time key in its fragment, which browsers never send in requests nor in Referer headers. The page
//   trades it for a session key kept in sessionStorage, which belongs to this exact origin (port included), and sends it in an
//   Authorization header. No cookie: browsers send the cookies of 127.0.0.1 to every port, so a local server an agent starts
//   would receive them; and no request from another site can act (no ambient credential, no CORS header).
// - Changes also need a JSON body and, when the browser sends them, this Origin and Sec-Fetch-Site: same-origin.
// - The page renders text only (calls are written by agents) under a strict Content-Security-Policy; a catastrophe cannot be
//   allowed from it, guard-tamper stays block; agents cannot start it (guard-tamper); every change is journaled.
//
// Updates: the page asks for the state with the ETag it has; the answer waits until something changes (long polling, at
// most 25 s), so a request for approval shows at once. Changes are noticed from a cheap fingerprint of the files involved.
import { spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { closeSync, existsSync, readdirSync, readFileSync, readSync, statSync, unlinkSync, writeFileSync } from "node:fs";
// node:http is loaded when the dashboard starts: every agent hook runs this same bundle, and must not pay for it
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { hostname, userInfo } from "node:os";
import { sep } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { Worker } from "node:worker_threads";
import { AuditLog, auditKey, describeAudit, verifyAuditFile, type Entry } from "./audit.js";
import { ConfirmError, confirmDir, confirmMode, dashboardPath, decide, listRequests, type ConfirmVerdict, type DashboardPresence } from "./confirm-queue.js";
import { exceptionLock, forceAllowCommand, LEVEL_NAMES, LEVELS, lockReason, RULE_INFO, UNKNOWN_TOOL, type Level, type RuleInfo, type Scope } from "./dashboard-rules.js";
import { agentCanAsk, isShellTool, loadHookPolicy, matchingRulesBounded } from "./hooks.js";
import { AGENTS, defaultCliPath, detectAgents, INSTALL_AGENTS, inspectHook, installHook, isInstallAgent } from "./install.js";
import { auditAllowsEnabled, callText, exactText, forgetKeptCalls, HIDDEN_CHARACTERS, keepCallsEnabled, keptCallsPath, MASK, readKeptCalls, type KeptCall } from "./kept-calls.js";
import { engageKillSwitch, journaledSwitch, KillSwitch, killSwitchKey, killSwitchPath, releaseKillSwitch } from "./kill-switch.js";
import { knownToolsKey, knownToolsPath, parseGrant, removeGrants, tombstonePath } from "./known-tools.js";
import { listMcp, MCP_CLIENTS, wrapMcp } from "./mcp-config.js";
import { agentName, plainParts, sayParts, type PlainParts } from "./plain.js";
import { guardConfig, updateGuardConfig } from "./plugins.js";
import { DEFAULT_POLICY, loadPolicy, presetPolicy, type Action, type Policy } from "./policy.js";
import { addException, basePolicy, hookPolicyFile, listExceptions, mcpPolicyFile, mcpPolicyPath, removeRule, setOverrides, setPolicyField, withoutExceptionsFor } from "./policy-file.js";
import { assertStrongSecret, resolveSecret } from "./secret.js";
import { FileSet, openRegular, readFileRetry, readRegular, renameReplace, stateDir, statePath } from "./store.js";

type Values = Record<string, string | number>;
const fill = (key: string, v: Values) => key.replace(/\{(\w+)\}/g, (m, k: string) => (Object.hasOwn(v, k) ? String(v[k]) : m));
/**
 * What the page is told after a change, or why a change is refused: the text in US English (`message`), and its key with
 * its values, so that the page can say it in the reader's language (`p`: values as they are, `t`: words it translates
 * too, such as rule names). `parts`: a message made of several sentences.
 */
interface Said { message: string; key?: string; p?: Values; t?: Record<string, string>; parts?: Said[] }
function said(key: string, p: Values = {}, t: Record<string, string> = {}): Said {
  return { message: fill(key, { ...p, ...t }), key, ...(Object.keys(p).length ? { p } : {}), ...(Object.keys(t).length ? { t } : {}) };
}
const joined = (parts: Said[]): Said => ({ message: parts.map(x => x.message).join(" "), parts });
/** A refusal the person can act on (bad input, locked rule...): sent with its HTTP status and what it says. */
class UserError extends Error {
  readonly said: Said;
  constructor(readonly status: number, s: Said | string) { const v = typeof s === "string" ? said(s) : s; super(v.message); this.said = v; }
}
const ACTION_LABEL: Record<Action, string> = { allow: "Allow", confirm: "Ask", block: "Block" };
const ACTIONS: readonly Action[] = ["allow", "confirm", "block"];
const isAction = (v: unknown): v is Action => typeof v === "string" && (ACTIONS as readonly string[]).includes(v);
const osUser = () => { try { return userInfo().username; } catch { return process.env.USERNAME ?? process.env.USER ?? "unknown"; } };
const auditPath = () => statePath(process.env.KYTRAL_AUDIT, "audit.jsonl");
const configPath = () => statePath(undefined, "config.json");
/** The hooks' policy file, without creating it. */
const hookPolicyPath = () => process.env.KYTRAL_POLICY ?? statePath(undefined, "policy.yaml");
const firstActions = (p: Policy) => { const m = new Map<string, Action>(); for (const r of p.rules) if (!m.has(r.name)) m.set(r.name, r.action); return m; };
const safeJson = (s: string): Record<string, unknown> => { try { const v = JSON.parse(s); return v && typeof v === "object" && !Array.isArray(v) ? v : { input: v }; } catch { return { input: s }; } };
/** Size, time and identity of a file: it changed when this changed ("-" when it does not exist). */
const fileSig = (f: string) => { try { const s = statSync(f); return `${s.size}:${s.mtimeMs}:${s.ino}`; } catch { return "-"; } };
/** The text of an event, cut for the page: the exception it can become is made from the kept text, never from this. */
const EVENT_TEXT_MAX = 1000;
const MATCHED = /^matched rule '[^']*'(:\s*)?/;

// ---------- the audit log, read as it grows ----------
const MAX_INITIAL_BYTES = 16 * 1024 * 1024, RECENT = 400, TODAY_MAX = 100_000;
const dayOf = (t: number) => { const d = new Date(t); return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`; };
/** Reads only what was appended since the last call: today's entries (counts, chart) and the last RECENT entries (the log). */
class AuditReader {
  today: Entry[] = []; recent: Entry[] = [];
  private offset = 0; private decoder = new StringDecoder("utf8"); private carry = ""; private skipFirst = false; private day = dayOf(Date.now());
  private identity?: string;
  constructor(readonly path: string) {}
  private reset() { this.offset = 0; this.decoder = new StringDecoder("utf8"); this.carry = ""; this.skipFirst = false; this.today = []; this.recent = []; }
  refresh(now = Date.now()) {
    const day = dayOf(now);
    if (day !== this.day) { this.day = day; this.today = this.today.filter(e => dayOf(Date.parse(e.ts)) === day); }
    let size: number, identity: string;
    // a log that is no regular file (a FIFO, a device, a folder) is never opened: shown as no log
    try { const st = statSync(this.path); if (!st.isFile()) throw new Error("not a regular file"); size = st.size; identity = `${st.ino}:${st.birthtimeMs}`; } catch { this.reset(); this.identity = undefined; return; }
    // another file now (replaced, rotated, restored) or shorter (truncated): read it again from the start
    if ((this.identity !== undefined && identity !== this.identity) || size < this.offset) this.reset();
    this.identity = identity;
    if (this.offset === 0 && size > MAX_INITIAL_BYTES) { this.offset = size - MAX_INITIAL_BYTES; this.skipFirst = true; }
    if (size === this.offset) return;
    let fd: number; try { fd = openRegular(this.path); } catch { this.reset(); this.identity = undefined; return; }
    try {
      while (this.offset < size) {
        const n = Math.min(size - this.offset, 4 * 1024 * 1024), buf = Buffer.alloc(n);
        const got = readSync(fd, buf, 0, n, this.offset); if (got <= 0) break;
        this.offset += got;
        const lines = (this.carry + this.decoder.write(buf.subarray(0, got))).split("\n");
        this.carry = lines.pop() ?? "";
        for (const line of lines) { if (this.skipFirst) { this.skipFirst = false; continue; } this.add(line, day); }
      }
    } finally { closeSync(fd); }
  }
  private add(line: string, day: string) {
    let e: Entry; try { e = JSON.parse(line); } catch { return; }
    if (!e || typeof e !== "object" || typeof e.ts !== "string" || typeof e.decision !== "string" || typeof e.agentId !== "string" || typeof e.tool !== "string") return;
    this.recent.push(e); if (this.recent.length > RECENT) this.recent.splice(0, this.recent.length - RECENT);
    if (dayOf(Date.parse(e.ts)) === day && this.today.length < TODAY_MAX) this.today.push(e);
  }
}
/** Decisions about a tool call (the others are control events: kill, resume, policy changes...). */
const CALL_DECISIONS = new Set(["allow", "ask", "block", "confirmed", "confirmed-always"]);
function todayStats(today: Entry[]) {
  const asked = new Array(24).fill(0), blocked = new Array(24).fill(0); let nAllowed = 0, nAsked = 0, nBlocked = 0;
  for (const e of today) {
    if (!CALL_DECISIONS.has(e.decision) || e.agentId === "*") continue;
    const h = new Date(e.ts).getHours();
    if (e.decision === "allow") nAllowed++;
    else if (e.decision === "block") { nBlocked++; blocked[h]++; }
    else { nAsked++; asked[h]++; }
  }
  return { checked: nAllowed + nAsked + nBlocked, allowed: nAllowed, asked: nAsked, blocked: nBlocked, hours: { asked, blocked } };
}

// ---------- the static files of the page ----------
/** The languages of the page (src/dashboard/locales/<language>.json; US English is in the page itself). */
export const LANGUAGES = ["en", "fr", "es", "de", "it", "pt-BR", "ru", "ja", "ko", "zh-CN"] as const;
const ASSETS: Record<string, { file: string; type: string }> = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/app.js": { file: "app.js", type: "text/javascript; charset=utf-8" },
  "/i18n.js": { file: "i18n.js", type: "text/javascript; charset=utf-8" },
  ...Object.fromEntries(LANGUAGES.filter(l => l !== "en").map(l => [`/locales/${l}.json`, { file: `locales/${l}.json`, type: "application/json; charset=utf-8" }])),
  "/app.css": { file: "app.css", type: "text/css; charset=utf-8" },
  "/wordmark.svg": { file: "wordmark.svg", type: "image/svg+xml" },
  "/mark.svg": { file: "mark.svg", type: "image/svg+xml" },
  "/fonts/space-grotesk.woff2": { file: "fonts/space-grotesk.woff2", type: "font/woff2" },
  "/fonts/jetbrains-mono.woff2": { file: "fonts/jetbrains-mono.woff2", type: "font/woff2" },
};
/** The folder of the page: dist/dashboard next to the bundle, or src/dashboard when run from the sources. */
export const assetsDir = () => new URL("./dashboard/", import.meta.url);
const PAGE_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
/** An SVG shown as an image cannot run scripts; the wordmark carries its own font and style. */
const SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:";
const BASE_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Cache-Control": "no-store",
  "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};
function send(res: ServerResponse, status: number, type: string, body: string | Buffer, csp = PAGE_CSP, extra: Record<string, string> = {}) {
  if (res.destroyed || res.headersSent) return;
  res.writeHead(status, { ...BASE_HEADERS, ...extra, "Content-Security-Policy": csp, "Content-Type": type, "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}
const json = (res: ServerResponse, status: number, data: unknown) => send(res, status, "application/json; charset=utf-8", JSON.stringify(data));
async function readBody(req: IncomingMessage, limit = 64 * 1024): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []; let n = 0;
  for await (const c of req) { n += (c as Buffer).length; if (n > limit) throw new UserError(413, "request too large"); chunks.push(c as Buffer); }
  let v: unknown; try { v = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); } catch { throw new UserError(400, "the request is not JSON"); }
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new UserError(400, "the request must be a JSON object");
  return v as Record<string, unknown>;
}

export interface DashboardOptions {
  /** 0 or absent: a free port. */
  port?: number;
  /** Things the person running the command should know (a link used twice...). */
  onWarn?: (message: string) => void;
  /** The version shown on the page. */
  version?: string;
}
export interface DashboardHandle {
  port: number;
  /** A new one-time sign-in link (valid 10 minutes, once). */
  newLink(): string;
  close(): Promise<void>;
}
type Body = { etag: string; json: string };
type IntegrityView = { state: "checking" | "empty" | "ok" | "unverified" | "broken" | "error"; text: string; tail?: number };

/** The dashboard's state and actions, behind the HTTP server. */
class Dashboard {
  port = 0;
  private readonly startedAt = new Date().toISOString();
  private readonly tokens = new Map<string, { at: number; used: boolean }>();
  private readonly sessions: Buffer[] = [];
  private failures = 0;
  private readonly reader = new AuditReader(auditPath());
  private readonly audit: AuditLog;
  private readonly killSwitch: KillSwitch;
  private readonly assets = new Map<string, Buffer>();
  private integrity: { size: number; at: number; running: boolean; view: IntegrityView } = { size: -2, at: 0, running: false, view: { state: "checking", text: "Checking the log…" } };
  private slow: { at: number; agents: AgentView[]; apps: AppView[] } | null = null;
  private readonly cache = new Map<string, { sig: string; value: unknown }>();
  /** Requests waiting for a change, the timer that looks for one, and a counter bumped by changes no file shows. */
  private readonly waiters = new Set<(b: Body) => void>();
  private ticker: NodeJS.Timeout | null = null;
  private lastPrint = ""; private bump = 0;
  constructor(private readonly secret: string, private readonly o: DashboardOptions) {
    this.audit = new AuditLog(auditPath(), { key: auditKey(secret) });
    // from the last kill or resume the journal records, as agent hooks do: kill-switch.json deleted shows the kill still in force
    let last: ReturnType<typeof journaledSwitch> | undefined; try { last = journaledSwitch(secret); } catch { /* an unreadable log is shown elsewhere */ }
    this.killSwitch = new KillSwitch(killSwitchPath(), killSwitchKey(secret), undefined, last);
    for (const a of Object.values(ASSETS)) { try { this.assets.set(a.file, readFileSync(new URL(a.file, assetsDir()))); } catch { /* a missing file is answered 404 */ } }
    if (!this.assets.has("index.html")) throw new Error(`the dashboard page is missing (${new URL("index.html", assetsDir()).pathname}): reinstall kytral-guard`);
  }

  // ----- sign-in -----
  newLink(): string {
    const now = Date.now();
    for (const [t, v] of this.tokens) if (now - v.at > 10 * 60_000) this.tokens.delete(t);
    const token = randomBytes(32).toString("base64url");
    this.tokens.set(token, { at: now, used: false });
    return `http://127.0.0.1:${this.port}/#k=${token}`;
  }
  private signIn(body: Record<string, unknown>): { session: string } {
    const token = typeof body.token === "string" ? body.token : "", t = this.tokens.get(token);
    if (!t || t.used || Date.now() - t.at > 10 * 60_000) {
      if (t?.used) this.o.onWarn?.("a sign-in link was used a second time: if your browser shows an error, someone else opened it first; stop the dashboard (Ctrl+C) and check what runs on this computer");
      else if (++this.failures % 20 === 0) this.o.onWarn?.(`${this.failures} sign-in attempts with a wrong link`);
      throw new UserError(403, "This link was already used, or it is wrong. In the terminal that runs kytral-guard dashboard, press Enter for a new link.");
    }
    t.used = true;
    const session = randomBytes(32).toString("base64url");
    this.sessions.push(Buffer.from(session)); if (this.sessions.length > 8) this.sessions.shift();
    return { session };
  }
  private signedIn(req: IncomingMessage): boolean {
    const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization ?? "");
    if (!m) return false;
    const got = Buffer.from(m[1]);
    return this.sessions.some(s => s.length === got.length && timingSafeEqual(s, got));
  }

  // ----- presence (the proxies and hooks send confirmations here while it runs) -----
  announce() {
    const body: DashboardPresence = { v: 1, pid: process.pid, host: hostname(), port: this.port, startedAt: this.startedAt, beat: new Date().toISOString() };
    try { const p = dashboardPath(), tmp = `${p}.${process.pid}.tmp`; writeFileSync(tmp, JSON.stringify(body), { mode: 0o600 }); renameReplace(tmp, p); } catch { /* retried at the next beat */ }
  }
  withdraw() {
    try { const d = JSON.parse(readFileRetry(dashboardPath()).toString("utf8")); if (d?.pid === process.pid) unlinkSync(dashboardPath()); } catch { /* already gone */ }
  }
  /** Wakes waiting requests now (the server is closing, or a check finished). */
  stop() { if (this.ticker) { clearInterval(this.ticker); this.ticker = null; } for (const w of [...this.waiters]) w({ etag: "", json: "" }); }

  // ----- HTTP -----
  async handle(req: IncomingMessage, res: ServerResponse) {
    const host = (req.headers.host ?? "").toLowerCase();
    if (host !== `127.0.0.1:${this.port}` && host !== `localhost:${this.port}`) return send(res, 421, "text/plain; charset=utf-8", "This page answers only at its own address.");
    const url = new URL(req.url ?? "/", `http://127.0.0.1:${this.port}`), path = url.pathname, asset = ASSETS[path];
    if (asset && (req.method === "GET" || req.method === "HEAD")) {
      const body = this.assets.get(asset.file);
      return body ? send(res, 200, asset.type, body, asset.type === "image/svg+xml" ? SVG_CSP : PAGE_CSP) : send(res, 404, "text/plain; charset=utf-8", "Not found");
    }
    if (!path.startsWith("/api/")) return send(res, 404, "text/plain; charset=utf-8", "Not found");
    try {
      if (req.method === "POST" || req.method === "PUT" || req.method === "DELETE") this.checkOrigin(req);
      if (path === "/api/session" && req.method === "POST") return json(res, 200, this.signIn(await readBody(req)));
      if (!this.signedIn(req)) throw new UserError(401, "Not signed in: open the link that kytral-guard dashboard printed (press Enter in its terminal for a new one).");
      if (path === "/api/state" && req.method === "GET") return await this.answerState(req, res, url);
      if (req.method !== "POST") throw new UserError(405, "method not allowed");
      const act = this.actions[path];
      if (!act) throw new UserError(404, "unknown action");
      const r = await act(await readBody(req));
      this.bump++;
      return json(res, 200, { ok: true, ...r });
    } catch (e) {
      const status = e instanceof UserError ? e.status : e instanceof ConfirmError ? 409 : 500;
      const s = e instanceof UserError ? e.said : said((e as Error).message);
      return json(res, status, { error: s.message, ...(s.key ? { key: s.key } : {}), ...(s.p ? { p: s.p } : {}), ...(s.t ? { t: s.t } : {}) });
    }
  }
  /** Changes come from this page only: a JSON body (no form can send one), and this Origin when the browser tells it. */
  private checkOrigin(req: IncomingMessage) {
    const origin = req.headers.origin, site = req.headers["sec-fetch-site"];
    if (origin !== undefined && origin !== `http://127.0.0.1:${this.port}` && origin !== `http://localhost:${this.port}`) throw new UserError(403, "request from another site");
    if (site !== undefined && site !== "same-origin") throw new UserError(403, "request from another site");
    if (!/^application\/json\b/i.test(req.headers["content-type"] ?? "")) throw new UserError(415, "a JSON body is required");
  }
  /** GET /api/state[?wait=s] with If-None-Match: 304 when unchanged; with `wait`, the answer comes when something changes. */
  private async answerState(req: IncomingMessage, res: ServerResponse, url: URL) {
    const seen = req.headers["if-none-match"], wait = Math.min(25, Math.max(0, Number(url.searchParams.get("wait")) || 0));
    let body = this.body();
    if (seen && seen === body.etag && wait > 0) body = (await this.nextChange(seen, wait * 1000, res)) ?? body;
    if (res.destroyed) return;
    if (seen && (seen === body.etag || !body.etag)) { res.writeHead(304, { ...BASE_HEADERS, ETag: seen }); res.end(); return; }
    send(res, 200, "application/json; charset=utf-8", body.json, PAGE_CSP, { ETag: body.etag });
  }
  /** The state, with an ETag over everything but the clock. */
  private body(): Body {
    const { now, ...rest } = this.state(), stable = JSON.stringify(rest);
    return { etag: `"${createHash("sha1").update(stable).digest("base64url")}"`, json: JSON.stringify({ now, ...rest }) };
  }
  private nextChange(etag: string, ms: number, res: ServerResponse): Promise<Body | null> {
    return new Promise(resolve => {
      let done = false;
      const finish = (b: Body | null) => { if (done) return; done = true; clearTimeout(timer); this.waiters.delete(wake); res.off("close", gone); resolve(b); };
      const wake = (b: Body) => { if (!b.etag || b.etag !== etag) finish(b.etag ? b : null); };
      const gone = () => finish(null);
      const timer = setTimeout(() => finish(null), ms);
      res.on("close", gone);
      this.waiters.add(wake); this.watch();
    });
  }
  /** Looks for a change every 300 ms while requests wait (and every 10 s anyway: clock, expired approvals, agents). */
  private watch() {
    if (this.ticker) return;
    let full = Date.now();
    this.ticker = setInterval(() => {
      if (!this.waiters.size) { clearInterval(this.ticker!); this.ticker = null; return; }
      const print = this.fingerprint(), now = Date.now();
      if (print === this.lastPrint && now - full < 10_000) return;
      this.lastPrint = print; full = now;
      let b: Body; try { b = this.body(); } catch { return; }
      for (const wake of [...this.waiters]) wake(b);
    }, 300);
    this.ticker.unref();
  }
  /** A cheap fingerprint of what the page shows: the files involved, the pending requests, and changes made here. */
  private fingerprint(): string {
    const parts = [auditPath(), keptCallsPath(), killSwitchPath(), hookPolicyPath(), mcpPolicyPath(), configPath(), knownToolsPath()].map(fileSig);
    try { parts.push(readdirSync(confirmDir()).filter(n => n.endsWith(".request.json")).sort().join(",")); } catch { parts.push("-"); }
    parts.push(String(this.bump));
    return parts.join("|");
  }
  /** `compute()` again only when one of `files` changed. */
  private cached<T>(key: string, files: string[], compute: () => T): T {
    const sig = files.map(fileSig).join("|"), hit = this.cache.get(key);
    if (hit && hit.sig === sig) return hit.value as T;
    const value = compute(); this.cache.set(key, { sig, value }); return value;
  }

  // ----- state -----
  state() {
    const now = Date.now(), me = osUser();
    this.reader.refresh(now);
    const kept = this.cached("kept", [keptCallsPath()], () => {
      const m = new Map<string, KeptCall>();
      let all: KeptCall[] = []; try { all = readKeptCalls(this.secret); } catch { /* unreadable: no text shown */ }
      for (const k of all) { if (k.seq !== undefined) m.set(`s${k.seq}`, k); m.set(`t${k.ts}|${k.agent}|${k.tool}`, k); }
      return m;
    });
    const rules = this.cached("rules", [hookPolicyPath(), mcpPolicyPath()], () => this.rulesView());
    const actionsOf: Record<Scope, Map<string, Action>> = { agents: rules.agents.actions, apps: rules.apps.actions };
    const slow = this.slowViews(now);
    return {
      v: 1, now: new Date(now).toISOString(), me, host: hostname(), version: this.o.version ?? null,
      status: this.statusView(),
      stats: todayStats(this.reader.today),
      integrity: this.integrityView(),
      events: this.reader.recent.slice().reverse().map(e => this.eventView(e, kept, actionsOf, me)),
      rules: { agents: rules.agents.view, apps: rules.apps.view, level: rules.level },
      exceptions: this.cached("exceptions", [hookPolicyPath(), knownToolsPath(), tombstonePath(knownToolsPath())!], () => this.exceptionsView()),
      approvals: this.approvalsView(me, now),
      agents: slow.agents, apps: slow.apps,
      settings: {
        keepCalls: { on: keepCallsEnabled(), env: process.env.KYTRAL_KEEP_CALLS ?? null },
        auditAllows: { on: auditAllowsEnabled(), env: process.env.KYTRAL_AUDIT_ALLOWS ?? null },
        confirmMode: confirmMode(), plugins: (() => { try { return guardConfig().plugins ?? []; } catch { return []; } })(),
      },
      paths: { home: stateDir(), policy: hookPolicyPath(), mcpPolicy: mcpPolicyPath(), audit: auditPath(), kept: keptCallsPath(), known: knownToolsPath() },
      page: { port: this.port, startedAt: this.startedAt, windows: process.platform === "win32" },
    };
  }
  private statusView() {
    const verdict = this.killSwitch.check();
    let by: string | undefined, at: string | undefined;
    try { const s = JSON.parse(readRegular(killSwitchPath()).toString("utf8")); if (typeof s?.by === "string") by = s.by; if (typeof s?.at === "string") at = s.at; } catch { /* no state yet, or no regular file */ }
    return { killed: verdict !== null, reason: verdict, by: by ?? null, at: at ?? null };
  }
  /** The log's integrity, checked in a worker thread when the log grew (at most every 30 s): the page never waits for it. */
  private integrityView(): IntegrityView {
    let size = -1; try { size = statSync(auditPath()).size; } catch { /* no log yet */ }
    const it = this.integrity;
    if (size < 0) { it.size = size; it.view = { state: "empty", text: "No entry yet." }; return it.view; }
    if (!it.running && size !== it.size && (it.size < 0 || Date.now() - it.at >= 30_000)) this.checkIntegrity(size);
    return it.view;
  }
  private checkIntegrity(size: number) {
    const it = this.integrity; it.running = true; it.at = Date.now();
    const done = (view: IntegrityView) => { if (!it.running) return; it.view = view; it.size = size; it.running = false; this.bump++; };
    const fromReport = (exitCode: number, text: string): IntegrityView => {
      const tail = /tail marker: seq (\d+)/.exec(text);
      return { state: exitCode === 0 ? "ok" : exitCode === 3 ? "unverified" : "broken", text, ...(tail ? { tail: Number(tail[1]) } : {}) };
    };
    try {
      const w = new Worker(new URL(import.meta.url.endsWith(".ts") ? "./audit-worker.ts" : "./audit-worker.js", import.meta.url), { workerData: { path: auditPath(), key: auditKey(this.secret) } });
      w.once("message", (m: { error?: string; exitCode: number; text: string }) => done(m.error ? { state: "error", text: m.error } : fromReport(m.exitCode, m.text)));
      w.once("error", e => done({ state: "error", text: e.message }));
      w.once("exit", () => done({ state: "error", text: "the check stopped before it finished" }));
      w.unref();
    } catch {
      // no worker (it could not start): checked here, the page waits this once
      try { const r = verifyAuditFile(auditPath(), auditKey(this.secret)); done(fromReport(r.exitCode, describeAudit(r).slice(1).join(" "))); }
      catch (e) { done({ state: "error", text: (e as Error).message }); }
    }
  }
  private eventView(e: Entry, kept: Map<string, KeptCall>, actionsOf: Record<Scope, Map<string, Action>>, me: string) {
    const k = (e.seq !== undefined ? kept.get(`s${e.seq}`) : undefined) ?? kept.get(`t${e.ts}|${e.agentId}|${e.tool}`);
    const who = agentName(e.agentId), mcp = e.agentId.startsWith("mcp:");
    const finding = (e.reason ?? k?.reason ?? "").replace(MATCHED, "") || undefined;
    const ruleAction = e.rule ? actionsOf[mcp ? "apps" : "agents"].get(e.rule === UNKNOWN_TOOL ? "" : e.rule) : undefined;
    // the rule asks a human, but nobody could be asked (the agent cannot, it ran without prompts, or no dashboard was open)
    const cannotAsk = e.decision === "block" && !e.approver && ruleAction === "confirm";
    const full = k?.text, where = mcp ? undefined : e.server;
    const exceptionable = !mcp && isShellTool(e.tool) && !!full && exactText(full) && /^(block|ask|confirmed)$/.test(e.decision);
    const lock = e.rule ? RULE_INFO.agents.find(r => r.id === e.rule)?.lock : undefined;
    return {
      seq: e.seq ?? null, ts: e.ts, agent: e.agentId, agentName: who.name, server: who.server ?? null, tool: e.tool, decision: e.decision,
      rule: e.rule ?? null, finding: finding ?? null, where: where ?? null, approver: e.approver ?? null, cannotAsk,
      text: full === undefined ? null : full.length > EVENT_TEXT_MAX ? `${full.slice(0, EVENT_TEXT_MAX)}…` : full,
      // the sentence in US English (search, notifications) and its parts, which the page says in the reader's language
      ...((x: PlainParts) => ({ plain: sayParts(x), say: x }))(plainParts({ agent: e.agentId, tool: e.tool, decision: e.decision, rule: e.rule, reason: finding, text: full, cwd: where, approver: e.approver, cannotAsk }, me)),
      // exact commands can become exceptions (a masked or cut text cannot: it is not the command that ran)
      // what the page offers (the server checks every rule the command matches): Block only for the guard's own rule, no Allow for a catastrophe
      exception: exceptionable ? { catastrophic: !!lock, self: lock === "all" } : null,
    };
  }
  private rulesView() {
    const scopeView = (scope: Scope, load: () => { policy: Policy; base: Policy; file: string; exists: boolean }) => {
      let l: ReturnType<typeof load> | null = null, error: string | null = null;
      try { l = load(); } catch (e) { error = (e as Error).message; }
      const actions = l ? firstActions(l.policy) : new Map<string, Action>(), base = l ? firstActions(l.base) : new Map<string, Action>();
      if (l) { actions.set("", l.policy.unknownTools ?? "confirm"); base.set("", l.base.unknownTools ?? "confirm"); }
      const groups: { name: string; rules: unknown[] }[] = [];
      for (const r of RULE_INFO[scope]) {
        let g = groups.find(x => x.name === r.group); if (!g) groups.push(g = { name: r.group, rules: [] });
        const key = r.id === UNKNOWN_TOOL ? "" : r.id;
        g.rules.push({ ...r, action: actions.get(key) ?? null, base: base.get(key) ?? null, present: actions.has(key) });
      }
      return { actions, view: { file: l?.file ?? null, exists: l?.exists ?? false, error, groups } };
    };
    const agents = scopeView("agents", () => {
      const file = hookPolicyPath(), exists = existsSync(file), { policy } = loadHookPolicy();
      return { policy, base: exists ? basePolicy(file) : presetPolicy("coding-agent"), file, exists };
    });
    const apps = scopeView("apps", () => {
      const file = mcpPolicyPath(), exists = existsSync(file);
      return { policy: exists ? loadPolicy(readFileSync(file, "utf8")) : loadPolicy(DEFAULT_POLICY), base: exists ? basePolicy(file, ["unknownTools"]) : loadPolicy(DEFAULT_POLICY), file, exists };
    });
    const matches = (lv: Level) => (["agents", "apps"] as Scope[]).every(s => Object.entries(LEVELS[lv][s]).every(([id, a]) => {
      const cur = (s === "agents" ? agents : apps).actions.get(id === UNKNOWN_TOOL ? "" : id);
      return cur === undefined || cur === a;
    }));
    const level: Level | "custom" = agents.view.error || apps.view.error ? "custom" : (["relaxed", "balanced", "strict"] as Level[]).find(matches) ?? "custom";
    return { agents, apps, level };
  }
  private exceptionsView() {
    let commands: ReturnType<typeof listExceptions> = [], error: string | null = null;
    try { commands = listExceptions(hookPolicyPath()); } catch (e) { error = (e as Error).message; }
    const tools: unknown[] = [];
    try {
      const set = new FileSet(knownToolsPath(), { signKey: knownToolsKey(this.secret, knownToolsPath()), onCorrupt: why => { error = error ?? `${knownToolsPath()} is corrupt (${why}): it grants nothing` }, lazyCorrupt: true });
      for (const [k, v] of set.entries()) {
        const g = parseGrant(k, v); if (!g) continue;
        const who = agentName(g.agentId);
        tools.push({ ...g, agentName: who.name, serverName: who.server ?? g.server });
      }
    } catch (e) { error = error ?? (e as Error).message; }
    return { commands, tools, error };
  }
  private approvalsView(me: string, now: number) {
    let requests: ReturnType<typeof listRequests>["requests"] = [];
    try { requests = listRequests(this.secret).requests; } catch { /* no queue yet */ }
    return requests.filter(r => Date.parse(r.expiresAt) > now).map(r => {
      const who = agentName(r.agentId), mcp = r.agentId.startsWith("mcp:"), args = safeJson(r.args), reason = r.reason.replace(MATCHED, "");
      return {
        id: r.id, agent: r.agentId, agentName: who.name, server: who.server ?? null, tool: r.tool, rule: r.rule, reason, args: r.args,
        // what the call does, in one line (masked): the full arguments are in `args`
        summary: callText(r.tool, args), always: r.always, createdAt: r.createdAt, expiresAt: r.expiresAt, where: mcp ? null : r.server || null,
        ...((x: PlainParts) => ({ plain: sayParts(x), say: x }))(plainParts({ agent: r.agentId, tool: r.tool, decision: "request", rule: r.rule, reason, text: callText(r.tool, args), cwd: mcp ? undefined : r.server }, me)),
      };
    });
  }
  /** Agents and apps: their configuration files are read at most every 10 s. */
  private slowViews(now: number) {
    if (this.slow && now - this.slow.at < 10_000) return this.slow;
    let detected: string[] = []; try { detected = detectAgents(); } catch { /* none */ }
    const agents: AgentView[] = [];
    for (const id of INSTALL_AGENTS) {
      let insp: ReturnType<typeof inspectHook> | null = null; try { insp = inspectHook(id); } catch { /* unreadable: shown as not protected */ }
      const found = detected.includes(id);
      if (!insp?.installed && !found) continue;
      agents.push({ id, name: AGENTS[id].name, installed: !!insp?.installed, problems: (insp?.issues ?? []).map(i => said(i.key, i.p)), detected: found, canAsk: agentCanAsk(id) });
    }
    let apps: AppView[] = [];
    // a wrapped server that no longer works (a new secret, a moved CLI) is shown as not checked: protecting it repairs it
    try { apps = listMcp({ secret: this.secret }).map(f => ({ client: f.client, app: f.name, file: f.file, error: f.error ?? null, servers: f.servers.map(s => ({ name: s.name, remote: s.remote, wrapped: s.wrapped && !s.problem })) })); }
    catch { apps = []; }
    return (this.slow = { at: now, agents, apps });
  }

  // ----- actions (each one journaled with the OS account) -----
  private by() { return `${osUser()} (dashboard)`; }
  private journal(decision: string, reason: string, o: { rule?: string; tool?: string } = {}) {
    this.audit.append({ agentId: "dashboard", tool: o.tool ?? "-", decision, ...(o.rule ? { rule: o.rule } : {}), reason, approver: this.by() });
  }
  private notFromNpx() {
    const cli = defaultCliPath();
    if (cli.includes(`${sep}_npx${sep}`)) throw new UserError(409, said("this copy of kytral-guard runs from a temporary npx cache ({path}): install it first (npm install -g kytral-guard)", { path: cli }));
  }
  /** Installs the hook of one agent; the message part, or null when it was already there. */
  private protectAgent(id: string): string | null {
    if (!isInstallAgent(id)) throw new UserError(400, "unknown agent");
    const r = installHook(id);
    if (!r.changed) return null;
    this.journal("settings-change", `installed the hook of ${AGENTS[id].name}`, { tool: id });
    return [AGENTS[id].name, ...r.notes].join(": ");
  }
  /** Runs the local MCP servers of one app through the proxy; the servers wrapped. */
  private protectApp(clientId: string): { app: string; changed: string[]; errors: string[] } {
    const client = MCP_CLIENTS.find(c => c.id === clientId);
    if (!client) throw new UserError(400, "unknown app");
    const changes = wrapMcp(this.secret, { clients: [client.id] });
    const changed = changes.flatMap(c => c.changed), errors = changes.filter(c => c.error).map(c => `${c.file}: ${c.error}`);
    if (changed.length) this.journal("mcp-wrap", `ran the MCP servers ${changed.join(", ")} of ${client.name} through Kytral Guard`, { tool: client.id });
    return { app: client.name, changed, errors };
  }
  private readonly actions: Record<string, (b: Record<string, unknown>) => Promise<object>> = {
    "/api/kill": async () => {
      // a kill is never refused: one written while the audit log could not be read or record it says so after the sentence
      const r = engageKillSwitch(this.by(), { key: killSwitchKey(this.secret), auditKey: auditKey(this.secret) });
      const stopped = said("All agents are stopped: every tool call is refused until you resume.");
      return r.warnings?.length ? joined([stopped, ...r.warnings.map(w => said(w.charAt(0).toUpperCase() + w.slice(1)))]) : stopped;
    },
    "/api/resume": async () => {
      releaseKillSwitch(this.secret, this.by());
      return said("Agents run again. Every call is checked as before.");
    },
    "/api/rule": async b => {
      const scope = b.scope === "apps" ? "apps" : b.scope === "agents" ? "agents" : null, action = b.action;
      if (!scope || typeof b.rule !== "string" || !isAction(action)) throw new UserError(400, "scope, rule and action (allow, confirm, block) are required");
      const info = RULE_INFO[scope].find(r => r.id === b.rule), locked = lockReason(info, action);
      if (locked) throw new UserError(409, locked);
      const before = this.setRule(scope, info!, action);
      const who = scope === "agents" ? "coding agents" : "AI apps";
      this.journal("policy-change", `set "${info!.name}" to ${ACTION_LABEL[action]} for ${who}`, { rule: info!.id });
      // whole sentences: a word put into a sentence cannot take the case or the form each language needs
      return { before, ...said(scope === "agents" ? "{rule}: {action} for coding agents, from the next tool call." : "{rule}: {action} for AI apps, from the next tool call.", {}, { rule: info!.name, action: ACTION_LABEL[action] }) };
    },
    "/api/level": async b => {
      const level = b.level as Level;
      if (!Object.hasOwn(LEVELS, level)) throw new UserError(400, "level must be relaxed, balanced or strict");
      for (const scope of ["agents", "apps"] as Scope[]) this.setLevel(scope, level);
      this.journal("policy-change", `set protection to ${LEVEL_NAMES[level]}`, { rule: "level" });
      return said("Protection set to {level}. Disasters stay blocked.", {}, { level: LEVEL_NAMES[level] });
    },
    "/api/exception": async b => {
      const action = b.action;
      if (!isAction(action)) throw new UserError(400, "action must be allow, confirm or block");
      let command: string, cwd: string | undefined;
      if (typeof b.seq === "number") {
        let k: KeptCall | undefined; try { k = readKeptCalls(this.secret).find(x => x.seq === b.seq); } catch { /* unreadable */ }
        if (!k) throw new UserError(404, "this call's text is no longer kept: make the exception in your terminal with kytral-guard allow");
        command = k.text; cwd = k.cwd;
      } else if (typeof b.command === "string") command = b.command;
      else throw new UserError(400, "seq or command is required");
      command = command.trim();
      if (!command || command.length > 10_000 || /[\r\n]/.test(command)) throw new UserError(400, "an exception takes a single command line");
      if (command.includes(MASK) || command.endsWith("…")) throw new UserError(409, "this command held a secret, or was too long, so its text was not kept as it ran: make the exception in your terminal with kytral-guard allow");
      if (HIDDEN_CHARACTERS.test(command)) throw new UserError(409, "this command holds control or invisible characters, which can make it look like another command: no exception can be made for it");
      // An exception goes first in the policy: every rule that matches the command counts, not only the one that decides
      // now (which can be an earlier exception for the same command: "Always ask", then "Always allow")
      const full = loadHookPolicy().policy, policy = withoutExceptionsFor(full, command), hadException = policy.rules.length !== full.rules.length;
      const matched = await matchingRulesBounded(policy, { tool: "Bash", args: { command }, cwd }, 8000);
      if (!matched) throw new UserError(409, "this command could not be analyzed in time: make the exception in your terminal with kytral-guard allow");
      const decided = matched[0]?.action ?? policy.default, lock = exceptionLock(matched, decided, action);
      if (lock === "self") throw new UserError(409, "This command would turn Kytral Guard off or weaken it, so it stays blocked: no exception can change that.");
      if (lock === "catastrophic") {
        const hint = forceAllowCommand({ seq: typeof b.seq === "number" ? b.seq : null, command, windows: process.platform === "win32" });
        throw new UserError(409, hint ? said("This command can do damage that cannot be undone, so it cannot be allowed from the dashboard. If an agent really must run it, run this in your own terminal: {command}", { command: hint })
          : said("This command can do damage that cannot be undone, so it cannot be allowed from the dashboard. If an agent really must run it, allow it in your own terminal with kytral-guard allow --force and this exact command."));
      }
      if (action === "allow" && decided === "allow" && !hadException) return said("This command is already allowed.");
      const name = addException(hookPolicyFile(), command, action);
      this.journal("policy-change", `added the exception ${name} (always ${ACTION_LABEL[action].toLowerCase()} one exact command)`, { rule: name });
      return { name, ...said(action === "allow" ? "From the next call, this exact command is always allowed."
        : action === "confirm" ? "From the next call, this exact command is always asked." : "From the next call, this exact command is always blocked.") };
    },
    "/api/exception/remove": async b => {
      if (typeof b.name !== "string" || !/^[\w.-]{1,128}$/.test(b.name)) throw new UserError(400, "name is required");
      const file = hookPolicyPath(), had = existsSync(file) ? listExceptions(file).find(x => x.name === b.name) : undefined;
      if (!had || !removeRule(file, b.name)) throw new UserError(404, said("no rule named {name}", { name: b.name }));
      this.journal("policy-change", `removed the exception ${b.name}`, { rule: b.name });
      // Undo adds it back from the page, which cannot allow a catastrophe: an `allow --force` exception gets no undo
      if (had.evenIfCatastrophic) return { removed: null, ...said("Exception removed: the rules decide again. Only kytral-guard allow --force, in your terminal, can add it back.") };
      return { removed: { command: had.command, action: had.action }, ...said("Exception removed: the rules decide again.") };
    },
    "/api/known/remove": async b => {
      if (typeof b.tool !== "string" || typeof b.agentId !== "string" || typeof b.server !== "string") throw new UserError(400, "tool, agentId and server are required");
      const path = knownToolsPath();
      const removed = removeGrants(new FileSet(path, { onCorrupt: () => {} }), new FileSet(tombstonePath(path), { monotonic: true, onMissing: "keep" }), b.tool, { agentId: b.agentId, server: b.server });
      for (const [s, t, ag] of removed) this.audit.append({ agentId: ag, tool: t, decision: "known-remove", server: s, approver: this.by() });
      if (!removed.length) throw new UserError(404, "this approval no longer exists");
      return said("{tool} will be asked about again.", { tool: b.tool });
    },
    "/api/approval": async b => {
      const verdict = b.verdict as ConfirmVerdict;
      if (typeof b.id !== "string" || !["approve", "approve_always", "deny"].includes(verdict)) throw new UserError(400, "id and verdict (approve, approve_always, deny) are required");
      // the page shows the arguments in full: approving them here is approving with --full
      decide(this.secret, b.id, verdict, this.by(), undefined, { full: true });
      return said(verdict === "deny" ? "Refused. The agent was told why." : verdict === "approve_always" ? "Approved for good." : "Approved once.");
    },
    "/api/settings": async b => {
      const patch: { keepCalls?: boolean; auditAllows?: boolean } = {};
      for (const k of ["keepCalls", "auditAllows"] as const) { if (b[k] === undefined) continue; if (typeof b[k] !== "boolean") throw new UserError(400, said("{setting} must be true or false", { setting: k })); patch[k] = b[k] as boolean; }
      if (!Object.keys(patch).length) throw new UserError(400, "nothing to change");
      updateGuardConfig(patch);
      for (const [k, v] of Object.entries(patch)) this.journal("settings-change", `turned ${v ? "on" : "off"} ${k === "keepCalls" ? "keeping the text of refused calls" : "journaling allowed calls"}`, { rule: k });
      const env = (patch.keepCalls !== undefined && process.env.KYTRAL_KEEP_CALLS) || (patch.auditAllows !== undefined && process.env.KYTRAL_AUDIT_ALLOWS);
      return said(env ? "Saved. An environment variable set for the agents can still override it." : "Saved.");
    },
    "/api/forget": async () => {
      forgetKeptCalls();
      this.journal("settings-change", "deleted the kept command texts", { rule: "keepCalls" });
      return said("Kept command texts deleted. The log is unchanged.");
    },
    "/api/protect-agent": async b => {
      if (typeof b.agent !== "string") throw new UserError(400, "agent is required");
      this.notFromNpx();
      const done = this.protectAgent(b.agent); this.slow = null;
      const name = isInstallAgent(b.agent) ? AGENTS[b.agent].name : b.agent;
      return done ? said("Protected. {details}", { details: done }) : said("{agent} was already protected.", { agent: name });
    },
    "/api/protect-app": async b => {
      if (typeof b.client !== "string") throw new UserError(400, "client is required");
      this.notFromNpx();
      const r = this.protectApp(b.client); this.slow = null;
      if (r.errors.length && !r.changed.length) throw new UserError(409, r.errors.join("; "));
      return r.changed.length ? said("{app}: {servers} now run through Kytral Guard. Restart {app} to apply.", { app: r.app, servers: r.changed.join(", ") }) : said("{app}: nothing to protect.", { app: r.app });
    },
    /** Everything found and not protected yet: the hooks of the agents installed here, and the local MCP servers of the apps. */
    "/api/protect-all": async () => {
      this.notFromNpx();
      const done: string[] = [], failed: string[] = [], restart: string[] = [];
      let detected: string[] = []; try { detected = detectAgents(); } catch { /* none */ }
      for (const id of detected) {
        try { if (inspectHook(id as (typeof INSTALL_AGENTS)[number]).installed) continue; const r = this.protectAgent(id); if (r) done.push(r); }
        catch (e) { failed.push(`${isInstallAgent(id) ? AGENTS[id].name : id}: ${(e as Error).message}`); }
      }
      let apps: ReturnType<typeof listMcp> = []; try { apps = listMcp({ secret: this.secret }); } catch { /* none */ }
      for (const f of apps) {
        if (f.error || !f.servers.some(s => !s.remote && (!s.wrapped || s.problem))) continue;
        try { const r = this.protectApp(f.client); if (r.changed.length) { done.push(`${r.app} (${r.changed.join(", ")})`); restart.push(r.app); } failed.push(...r.errors); }
        catch (e) { failed.push(`${f.name}: ${(e as Error).message}`); }
      }
      this.slow = null;
      if (!done.length && failed.length) throw new UserError(409, said("Nothing could be protected: {list}", { list: failed.join("; ") }));
      if (!done.length) return said("Everything found is already protected.");
      return joined([said("Protected: {list}.", { list: done.join("; ") }), ...(restart.length ? [said("Restart {apps} to apply.", { apps: restart.join(", ") })] : []),
        ...(failed.length ? [said("Not done: {list}.", { list: failed.join("; ") })] : [])]);
    },
  };
  /** Sets one rule; the action it had before (for an undo). */
  private setRule(scope: Scope, info: RuleInfo, action: Action): Action {
    const file = scope === "agents" ? hookPolicyFile() : mcpPolicyFile();
    if (info.id === UNKNOWN_TOOL) {
      const before = loadPolicy(readFileSync(file, "utf8")).unknownTools ?? "confirm", base = basePolicy(file, ["unknownTools"]).unknownTools ?? "confirm";
      setPolicyField(file, "unknownTools", action === base ? null : action);
      return before;
    }
    const base = firstActions(basePolicy(file)).get(info.id), before = firstActions(loadPolicy(readFileSync(file, "utf8"))).get(info.id);
    if (!base || !before) throw new UserError(409, said('"{rule}" is not in your policy ({file}): it does not build on the {preset} preset', { file, preset: scope === "agents" ? "coding-agent" : "strict" }, { rule: info.name }));
    setOverrides(file, { [info.id]: action === base ? null : action });
    return before;
  }
  private setLevel(scope: Scope, level: Level) {
    const file = scope === "agents" ? hookPolicyFile() : mcpPolicyFile(), base = basePolicy(file, ["unknownTools"]), actions = firstActions(base);
    const changes: Record<string, Action | null> = {};
    for (const [id, a] of Object.entries(LEVELS[level][scope])) {
      if (id === UNKNOWN_TOOL) continue;
      const b = actions.get(id); if (b) changes[id] = a === b ? null : a;
    }
    setOverrides(file, changes);
    const unknown = LEVELS[level][scope][UNKNOWN_TOOL];
    if (unknown) setPolicyField(file, "unknownTools", unknown === (base.unknownTools ?? "confirm") ? null : unknown);
  }
}
interface AgentView { id: string; name: string; installed: boolean; problems: Said[]; detected: boolean; canAsk: boolean }
interface AppView { client: string; app: string; file: string; error: string | null; servers: { name: string; remote: boolean; wrapped: boolean }[] }

/** Starts the dashboard on 127.0.0.1. The secret (KYTRAL_SECRET, else $KYTRAL_HOME/secret) is created when missing, as `init` does. */
export async function startDashboard(o: DashboardOptions = {}): Promise<DashboardHandle> {
  const secret = assertStrongSecret(resolveSecret({ create: true }));
  const d = new Dashboard(secret, o);
  const { createServer } = await import("node:http");
  const server = createServer((req, res) => { d.handle(req, res).catch(e => { try { json(res, 500, { error: (e as Error).message }); } catch { /* the client is gone */ } }); });
  server.headersTimeout = 10_000; server.requestTimeout = 60_000; server.keepAliveTimeout = 30_000;
  await new Promise<void>((resolve, reject) => {
    server.once("error", (e: NodeJS.ErrnoException) => reject(e.code === "EADDRINUSE" ? new Error(`port ${o.port} is already in use: pick another one with --port, or leave it out to use a free port`)
      : e.code === "EACCES" ? new Error(`port ${o.port} cannot be used here (permission denied): pick another one with --port`) : e));
    server.listen(o.port ?? 0, "127.0.0.1", () => resolve());
  });
  d.port = (server.address() as AddressInfo).port;
  d.announce();
  const beat = setInterval(() => d.announce(), 5000); beat.unref();
  let closed = false;
  return {
    port: d.port,
    newLink: () => d.newLink(),
    close: () => new Promise<void>(resolve => {
      if (closed) return resolve();
      closed = true; clearInterval(beat); d.stop(); d.withdraw();
      server.closeAllConnections?.(); server.close(() => resolve());
    }),
  };
}

/** Opens a link in the default browser; false when that cannot be done here (the link is then only printed). */
export function openInBrowser(url: string): boolean {
  let cmd: string, args: string[], verbatim = false;
  if (process.platform === "win32") { cmd = "cmd.exe"; args = ["/d", "/s", "/c", `start "" "${url}"`]; verbatim = true; }
  else if (process.platform === "darwin") { cmd = "open"; args = [url]; }
  else if (process.env.WSL_DISTRO_NAME) { cmd = "cmd.exe"; args = ["/c", "start", "", url.replace(/&/g, "^&")]; }   // WSL: the Windows browser
  else if (process.env.DISPLAY || process.env.WAYLAND_DISPLAY) { cmd = "xdg-open"; args = [url]; }
  else return false;   // no screen here (SSH, server): the link is printed
  try {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true, windowsVerbatimArguments: verbatim });
    child.on("error", () => {}); child.unref();
    return true;
  } catch { return false; }
}
