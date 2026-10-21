// Local confirmation queue, written from scratch, for the stdio proxy and for the hooks of agents that cannot ask a human.
// A waiting process writes one HMAC-signed request file per pending call; a human answers in the dashboard
// (`kytral-guard dashboard`) or from another terminal with `kytral-guard confirm approve <id> [--always]` or
// `kytral-guard confirm deny <id>`, which writes a signed decision file (the first one wins). Both are signed for their queue
// directory (confirmKey): copied into another home's queue, they do not verify there. Only the process that waits acts on a
// decision, for the request it holds in memory: a forged, edited or misdirected file can at worst cause a refusal. No valid
// answer before the timeout => deny. When the queue is used: confirmMode().
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, linkSync, mkdirSync, readdirSync, realpathSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { join, resolve } from "node:path";
import { deriveKey, readRegular, renameReplace, stateDir, statePath } from "./store.js";
import { assertAuditSecret, assertStrongSecret } from "./secret.js";

/**
 * When calls that need a human wait in the queue: "on" (KYTRAL_CONFIRM_QUEUE=1: always, someone answers with
 * `kytral-guard confirm`), "off" (KYTRAL_CONFIRM_QUEUE=0: never, they are refused), else "auto": while a dashboard of this
 * machine is open (dashboardLive), refused at once otherwise.
 */
export function confirmMode(): "on" | "off" | "auto" {
  const v = process.env.KYTRAL_CONFIRM_QUEUE;
  return v === "1" ? "on" : v === "0" ? "off" : "auto";
}
/** Where the dashboard of this machine says it is open (its process, port and a heartbeat every few seconds). */
export const dashboardPath = () => statePath(undefined, "dashboard.json");
export interface DashboardPresence { v: 1; pid: number; host: string; port: number; startedAt: string; beat: string }
/** Seconds after its last heartbeat when a dashboard counts as closed. */
export const DASHBOARD_BEAT_SECONDS = 20;
/** Is a dashboard of this machine open: a recent heartbeat, from a process of this host that still runs? */
export function dashboardLive(now = Date.now()): boolean {
  try {
    const d = JSON.parse(readRegular(dashboardPath()).toString("utf8")) as DashboardPresence;   // never waits: agent hooks read it
    const beat = Date.parse(d.beat);
    return d.v === 1 && d.host === hostname() && alive(d.pid) && Number.isFinite(beat) && now - beat < DASHBOARD_BEAT_SECONDS * 1000 && beat - now < 60_000;
  } catch { return false; }
}
/** Should a call that needs a human wait in the queue now? Null: yes. Else why nobody can answer (it is refused at once). */
export function nobodyToAsk(): string | null {
  const mode = confirmMode();
  if (mode === "on") return null;
  if (mode === "off") return "confirmations are turned off (KYTRAL_CONFIRM_QUEUE=0)";
  return dashboardLive() ? null : "nobody can answer: no dashboard is open (kytral-guard dashboard)";
}

/** approve = this call only (bound to its argsHash); approve_always = also add the tool to known-tools.json (unknown-tool rule only). */
export type ConfirmVerdict = "approve" | "approve_always" | "deny";
export interface ConfirmRequest {
  v: 1; id: string; server: string; agentId: string; tool: string; rule: string; reason: string;
  /** SHA-256 of the canonical JSON arguments: a decision is bound to it. */
  argsHash: string;
  /** Canonical JSON arguments, complete: `confirm list` shows the first ARGS_SHOWN characters unless --full. */
  args: string;
  /** approve_always is allowed (unknown-tool rule, plain tool name). */
  always: boolean;
  createdAt: string; expiresAt: string;
  /** The waiting proxy (startup cleanup of requests left by a proxy of this host that is gone). */
  pid: number; host: string;
}
export interface ConfirmDecision { v: 1; id: string; verdict: ConfirmVerdict; argsHash: string; approver: string; decidedAt: string }
/** `problem` is set when the refusal does not come from a valid human decision (timeout, stopped, invalid decision). */
export interface QueueAnswer { verdict: ConfirmVerdict; approver?: string; problem?: string }
export interface QueueQuestion { server: string; agentId: string; tool: string; rule: string; reason: string; args: unknown; always: boolean }
export interface ConfirmQueue { ask(q: QueueQuestion, stopped: () => boolean): Promise<QueueAnswer> }

/**
 * Signing key of the requests and decisions of the queue directory `dir`: from KYTRAL_AUDIT_SECRET if set, else the proxy
 * secret (same strong-secret rule as the Guard), bound to the directory's real path, as kill-switch.json's id is. A request
 * or a decision signed for one queue never verifies in another (copied from another KYTRAL_HOME using the same secret, or
 * this one reached through another path): a request moved to another home's queue is never shown or answered there, and a
 * decision made there is never taken here.
 */
export function confirmKey(secret: string, dir: string): Buffer {
  const key = deriveKey(assertAuditSecret() ?? assertStrongSecret(secret), "confirm/v1");
  let real = resolve(dir); try { real = realpathSync(real); } catch { /* not created yet: nothing is signed for it */ }
  return createHmac("sha256", key).update(`confirm/dep\n${real}`).digest();
}
export const confirmDir = () => resolve(process.env.KYTRAL_CONFIRMATIONS || join(stateDir(), "confirmations"));
const ID = /^[0-9a-f]{32}$/;
/** Characters of the arguments that `confirm list` shows; longer arguments can only be approved with --full. */
export const ARGS_SHOWN = 2000;
const VERDICTS: ConfirmVerdict[] = ["approve", "approve_always", "deny"];

/** Agent-controlled text shown to a human: control and bidi characters are escaped, so a call cannot disguise itself. */
export const printable = (s: unknown) => String(s).replace(/[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
/** JSON with object keys sorted at every level: the same arguments always give the same text and hash. */
export function canonicalJson(v: unknown): string {
  return JSON.stringify(v, (_k, x) => x && typeof x === "object" && !Array.isArray(x)
    ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) : x);
}
/** Binding hash of a call's arguments. Throws for arguments that are not JSON (e.g. BigInt, cycles): the call is refused. */
export function argsHash(args: unknown): string { return "sha256:" + createHash("sha256").update(canonicalJson(args ?? {})).digest("hex"); }

const sign = (key: Buffer, kind: "request" | "decision", body: object) => createHmac("sha256", key).update(`${kind}\n${canonicalJson(body)}`).digest("base64url");
/** The object without its signature if `sig` is valid for this kind, else null. */
function verified<T>(key: Buffer, kind: "request" | "decision", raw: unknown): T | null {
  if (!raw || typeof raw !== "object") return null;
  const { sig, ...body } = raw as Record<string, unknown>;
  if (typeof sig !== "string") return null;
  const a = Buffer.from(sig), b = Buffer.from(sign(key, kind, body));
  return a.length === b.length && timingSafeEqual(a, b) ? (body as T) : null;
}
function readRequest(key: Buffer, path: string): ConfirmRequest | null {
  try { const r = verified<ConfirmRequest>(key, "request", JSON.parse(readRegular(path).toString("utf8"))); return r && r.v === 1 && ID.test(r.id) ? r : null; }
  catch { return null; }
}

export interface FileConfirmQueueOptions {
  /** Proxy secret (KYTRAL_SECRET); the signing key is derived from KYTRAL_AUDIT_SECRET if set, else from it. */
  secret: string;
  /** Default: $KYTRAL_CONFIRMATIONS or $KYTRAL_HOME/confirmations. */
  dir?: string;
  /** How long a request waits for a human, in ms. Default 60000. */
  timeoutMs?: number;
  pollMs?: number;
  /** Called once the request file is written (the proxy logs the id on stderr). */
  notify?: (req: ConfirmRequest) => void;
  /** Checked before each request: a reason makes ask() refuse at once without writing anything (nobodyToAsk). Default: always ask. */
  unanswerable?: () => string | null;
}
export class FileConfirmQueue implements ConfirmQueue {
  readonly dir: string; readonly timeoutMs: number; private readonly key: Buffer; private readonly pollMs: number;
  /** Requests left behind by proxies that are gone, removed at startup. */
  readonly orphansRemoved: number;
  constructor(private o: FileConfirmQueueOptions) {
    this.dir = resolve(o.dir ?? confirmDir());
    this.timeoutMs = o.timeoutMs ?? 60_000; this.pollMs = o.pollMs ?? 100;
    if (!Number.isInteger(this.timeoutMs) || this.timeoutMs <= 0) throw new Error(`confirmation timeout must be a positive number of ms, got '${o.timeoutMs}'`);
    // Owner-only directory (0700), also when it already existed with wider permissions.
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") chmodSync(this.dir, 0o700);
    this.key = confirmKey(o.secret, this.dir);   // once the directory exists: bound to its real path
    this.orphansRemoved = removeOrphans(this.key, this.dir);
  }
  /** Writes a signed request, then waits for a valid decision. Timeout, `stopped()` (kill switch) or an invalid decision => deny. */
  async ask(q: QueueQuestion, stopped: () => boolean): Promise<QueueAnswer> {
    const nobody = this.o.unanswerable?.();
    if (nobody) return { verdict: "deny", problem: nobody };
    let hash: string; try { hash = argsHash(q.args); } catch { return { verdict: "deny", problem: "invalid: arguments are not JSON" }; }
    const now = Date.now(), id = randomBytes(16).toString("hex");
    const req: ConfirmRequest = { v: 1, id, server: q.server, agentId: q.agentId, tool: q.tool, rule: q.rule, reason: q.reason, argsHash: hash,
      args: canonicalJson(q.args ?? {}), always: q.always,
      createdAt: new Date(now).toISOString(), expiresAt: new Date(now + this.timeoutMs).toISOString(), pid: process.pid, host: hostname() };
    const reqPath = join(this.dir, `${id}.request.json`), decPath = join(this.dir, `${id}.decision.json`);
    try {
      const tmp = `${reqPath}.tmp`;
      writeFileSync(tmp, JSON.stringify({ ...req, sig: sign(this.key, "request", req) }, null, 1), { mode: 0o600 }); renameReplace(tmp, reqPath);
      this.o.notify?.(req);
      for (const deadline = now + this.timeoutMs; ;) {
        if (stopped()) return { verdict: "deny", problem: "stopped (kill switch)" };
        let raw: string | undefined;
        // a decision that is no regular file (a FIFO planted there) is refused, never waited on
        try { raw = readRegular(decPath).toString("utf8"); } catch (e: any) { if (e.code !== "ENOENT") return { verdict: "deny", problem: `invalid: decision unreadable (${e.code})` }; }
        if (raw !== undefined) return this.check(req, raw);
        if (Date.now() >= deadline) return { verdict: "deny", problem: "timeout" };
        await new Promise(r => setTimeout(r, this.pollMs));
      }
    } finally { for (const f of [reqPath, decPath]) try { unlinkSync(f); } catch {} }
  }
  /** A decision counts only if it is signed, made for this very request (id + argsHash), and allowed for it. */
  private check(req: ConfirmRequest, raw: string): QueueAnswer {
    let parsed: unknown; try { parsed = JSON.parse(raw); } catch { return { verdict: "deny", problem: "invalid: decision is not JSON" }; }
    const d = verified<ConfirmDecision>(this.key, "decision", parsed);
    if (!d) return { verdict: "deny", problem: "invalid: bad decision signature" };
    if (d.v !== 1 || d.id !== req.id || d.argsHash !== req.argsHash) return { verdict: "deny", problem: "invalid: decision made for another request" };
    if (!VERDICTS.includes(d.verdict)) return { verdict: "deny", problem: "invalid: unknown verdict" };
    if (d.verdict === "approve_always" && !req.always) return { verdict: "deny", problem: "invalid: approve_always is only valid for the unknown-tool rule" };
    if (typeof d.approver !== "string" || !d.approver) return { verdict: "deny", problem: "invalid: decision without approver" };
    return { verdict: d.verdict, approver: d.approver };
  }
}

const alive = (pid: unknown) => {
  if (!Number.isInteger(pid) || (pid as number) <= 0) return false;
  try { process.kill(pid as number, 0); return true; } catch (e: any) { return e.code === "EPERM"; }
};
/**
 * Startup cleanup: removes the requests no proxy waits for any more (expired, or left by a proxy of this host that is gone:
 * crash, kill) with their decision, decisions whose request is gone, and stale temp files. Files that do not verify with
 * this secret for this directory are left alone. Returns the number of requests removed.
 */
function removeOrphans(key: Buffer, dir: string): number {
  const rm = (f: string) => { try { unlinkSync(join(dir, f)); return true; } catch { return false; } };
  const now = Date.now(), host = hostname(); let removed = 0;
  for (const f of readdirSync(dir).filter(f => f.endsWith(".request.json"))) {
    const r = readRequest(key, join(dir, f));
    if (!r || f !== `${r.id}.request.json`) continue;
    if (Date.parse(r.expiresAt) <= now || (r.host === host && !alive(r.pid))) { if (rm(f)) removed++; rm(`${r.id}.decision.json`); }
  }
  const names = new Set(readdirSync(dir));
  for (const f of names) {
    const m = /^([0-9a-f]{32})\.decision\.json$/.exec(f);
    if (m && !names.has(`${m[1]}.request.json`)) rm(f);
    else if (f.endsWith(".tmp")) { try { if (now - statSync(join(dir, f)).mtimeMs > 60_000) rm(f); } catch {} }
  }
  return removed;
}

export class ConfirmError extends Error { constructor(readonly exitCode: number, message: string) { super(message); } }
/** Pending requests of the queue directory that verify with this secret for this directory, and the file names that do not. */
export function listRequests(secret: string, dir = confirmDir()): { requests: ConfirmRequest[]; invalid: string[] } {
  const key = confirmKey(secret, dir); const requests: ConfirmRequest[] = [], invalid: string[] = [];
  let names: string[] = []; try { names = readdirSync(dir); } catch (e: any) { if (e.code !== "ENOENT") throw e; }
  for (const n of names.filter(n => n.endsWith(".request.json")).sort()) {
    const r = readRequest(key, join(dir, n));
    if (r && n === `${r.id}.request.json`) requests.push(r); else invalid.push(n);
  }
  return { requests: requests.sort((a, b) => a.createdAt.localeCompare(b.createdAt)), invalid };
}
/**
 * Writes a signed decision for a pending, unexpired request (CLI). The first decision wins: the complete file is linked exclusively.
 * Arguments longer than ARGS_SHOWN are not fully shown by `confirm list`: approving them needs `full` (reviewed with --full).
 */
export function decide(secret: string, id: string, verdict: ConfirmVerdict, approver: string, dir = confirmDir(), opts: { full?: boolean } = {}): ConfirmRequest {
  if (!ID.test(id)) throw new ConfirmError(2, "invalid request id: 32 hexadecimal characters, as 'kytral-guard confirm list' shows them");   // not repeated: it may be anything, a secret too
  if (!VERDICTS.includes(verdict)) throw new ConfirmError(2, `invalid verdict '${verdict}'`);
  const key = confirmKey(secret, dir); const reqPath = join(dir, `${id}.request.json`);
  const req = readRequest(key, reqPath);
  if (!req || req.id !== id) throw new ConfirmError(1, `no pending request ${id} (unknown, already answered, expired, or not signed with this secret)`);
  if (Date.parse(req.expiresAt) <= Date.now()) throw new ConfirmError(1, `request ${id} has expired`);
  if (verdict !== "deny" && req.args.length > ARGS_SHOWN && !opts.full)
    throw new ConfirmError(2, `the arguments of request ${id} are ${req.args.length} characters long and 'confirm list' shows only the first ${ARGS_SHOWN}: review them all with 'kytral-guard confirm list --full', then approve with --full`);
  if (verdict === "approve_always" && !req.always)
    throw new ConfirmError(2, `--always is not allowed for this request (rule '${req.rule}'): it exists only for unknown tools with a plain name that the server does not flag as destructive; use 'approve' (this call only) or 'deny'`);
  const body: ConfirmDecision = { v: 1, id, verdict, argsHash: req.argsHash, approver, decidedAt: new Date().toISOString() };
  const path = join(dir, `${id}.decision.json`), tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ ...body, sig: sign(key, "decision", body) }), { mode: 0o600 });
  try { linkSync(tmp, path); }
  catch (e: any) { if (e.code === "EEXIST") throw new ConfirmError(1, `request ${id} was already answered`); throw e; }
  finally { try { unlinkSync(tmp); } catch {} }
  return req;
}
