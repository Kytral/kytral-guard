// Audit log: one JSON line per decision, chained with HMAC-SHA256 under a key derived from KYTRAL_AUDIT_SECRET (else
// KYTRAL_SECRET) that is never written anywhere. Writers (proxies, the CLI) append under the inter-process lock after
// re-reading the tail, so they extend one chain, and a signed tail marker (<log>.tail) certifies the last entry, so lines
// removed from the end are detected too. verifyAuditFile (`kytral-guard audit verify`) reports the first broken line.
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { closeSync, fstatSync, mkdirSync, readSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { canonicalJson } from "./confirm-queue.js";
import { assertAuditSecret, assertStrongSecret } from "./secret.js";
import { appendRegular, assertRegular, deriveKey, NotRegularFile, openRegular, readRegular, realFilePath, withFileLock, writeReplace } from "./store.js";

/**
 * One decision. Written with the audit key, an entry has `seq` (its position), `prev` (link of the previous line: its mac,
 * or its hash if it has none), `hash` (unkeyed SHA-256 of the entry, so verifyChain still works without the key) and
 * `mac` = HMAC-SHA256(auditKey, prev || canonical JSON of the entry without mac). The first entry of an HMAC segment
 * carries `segment`, plus `legacy` (count and SHA-256 of the lines before it, which then cannot change unnoticed) or
 * `anomaly` (what its writer found wrong with the log). Written without the key, an entry has no mac: `unauthenticated`
 * inside a segment, a legacy SHA-256 line (no seq) otherwise, as before HMAC chains. A kill or resume written with the key
 * also signs `dep`, the id of the log it was written in (tailDep): copied into another log, it is not that log's.
 */
export interface Entry {
  ts: string; agentId: string; tool: string; decision: string; rule?: string; reason?: string; approver?: string; server?: string; generation?: number; state?: string;
  dep?: string; segment?: string; legacy?: { lines: number; sha256: string }; anomaly?: string; unauthenticated?: true;
  seq?: number; prev: string; hash: string; mac?: string;
}
/**
 * What callers journal. `approver`: who took a human decision (confirmed, known-add, known-remove, kill, resume); `server`:
 * for known-tools entries (the working directory for agent hooks); `generation`: the kill switch generation a kill or resume
 * wrote; `state`: SHA-256 of the kill-switch.json content it wrote; `reason`: the finding behind a refusal (agent hooks),
 * never the arguments themselves.
 */
export type AuditFields = Pick<Entry, "agentId" | "tool" | "decision" | "rule" | "reason" | "approver" | "server" | "generation" | "state">;
export const AUDIT_SEGMENT = "hmac-sha256/v1";
/** HMAC key of the audit chain: KYTRAL_AUDIT_SECRET if set, else the proxy secret, same strong-secret rule as the Guard; label audit/v1. */
export const auditKey = (secret: string) => deriveKey(assertAuditSecret() ?? assertStrongSecret(secret), "audit/v1");
/** Signed tail marker of a log: seq and link of the last entry a keyed writer appended. */
export const auditTailPath = (log: string) => `${resolve(log)}.tail`;
/**
 * Id of a log, signed into its tail marker and into every kill and resume it journals with the key (`dep`): an HMAC, with
 * the audit key, of the log's real path (realFilePath), cut to 32 hex digits, derived as kill-switch.json's id is. A marker
 * or an entry copied next to another log (the log of another KYTRAL_HOME using the same secret, or this one reached through
 * another real path) carries an id that is not that log's, and computing the right one needs the secret.
 */
export const tailDep = (key: Buffer, log: string) => createHmac("sha256", key).update(`audit-tail/dep\n${realFilePath(resolve(log))}`).digest("hex").slice(0, 32);

const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");
const link = (e: Entry) => e.mac ?? e.hash;
/** Unkeyed SHA-256 of an entry: every field but hash and mac, in written order (as before HMAC chains). */
const digest = (e: Entry) => { const { hash: _h, mac: _m, ...base } = e; return sha256(JSON.stringify(base)); };
const entryMac = (key: Buffer, e: Entry) => { const { mac: _m, ...body } = e; return createHmac("sha256", key).update(e.prev).update(canonicalJson(body)).digest("hex"); };
const same = (a: unknown, b: string) => typeof a === "string" && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
/** True if `e` is an HMAC entry that verifies with `key` (its mac covers its link to the previous line and every field, `generation` and `state` included). */
export const entryAuthentic = (key: Buffer, e: Entry): boolean => isEntry(e) && same(e.mac, entryMac(key, e));
const isEntry = (e: any): e is Entry => !!e && typeof e === "object" && typeof e.hash === "string" && typeof e.prev === "string";

/**
 * The last `n` lines of a file (fewer if it is shorter), reading only its tail, and whether it ends with a newline. The log
 * is only ever opened as a regular file, without waiting (openRegular): a FIFO, a device or a folder in its place throws.
 */
function tail(path: string, n: number): { lines: string[]; complete: boolean } {
  let fd: number;
  try { fd = openRegular(path); } catch (e: any) { if (e.code === "ENOENT") return { lines: [], complete: true }; throw e; }
  try {
    const size = fstatSync(fd).size;
    for (let k = Math.min(size, 4096); ; k = Math.min(size, k * 4)) {
      const buf = Buffer.alloc(k); readSync(fd, buf, 0, k, size - k);
      const text = buf.toString("utf8"), lines = text.trimEnd().split("\n"), complete = size === 0 || text.endsWith("\n");
      if (k === size) return { lines: lines.filter(l => l).slice(-n), complete };
      if (lines.length > n) return { lines: lines.slice(-n), complete };   // the first line may be cut: never returned
    }
  } finally { closeSync(fd); }
}
/** Last entry of a file; undefined when it is missing or empty. A torn or rewritten last line throws: nothing is appended after it (fail closed). */
function lastEntry(path: string): Entry | undefined {
  const { lines: [line], complete } = tail(path, 1); if (line === undefined) return undefined;
  let e: any; try { e = JSON.parse(line); } catch {}
  if (!isEntry(e) || (e.seq !== undefined && !Number.isSafeInteger(e.seq)) || !complete) throw new Error(`audit: last line of ${path} is not a valid entry (torn or rewritten)`);
  return e;
}
/** Last entry of a log file that `match` accepts, reading it backward; only lines containing `hint` are parsed. Never throws. */
export function findLastEntry(path: string, match: (e: Entry) => boolean, hint = ""): Entry | undefined {
  let fd: number;
  try { fd = openRegular(path); } catch { return undefined; }
  const pick = (line: Buffer): Entry | undefined => {
    if (!line.includes(hint)) return undefined;
    try { const e = JSON.parse(line.toString("utf8")); return e && typeof e === "object" && match(e) ? e : undefined; } catch { return undefined; }
  };
  try {
    let pos = fstatSync(fd).size, carry = Buffer.alloc(0);   // carry: start of a line whose end was in the chunk read before
    while (pos > 0) {
      const n = Math.min(pos, 1 << 16); pos -= n;
      const chunk = Buffer.alloc(n); readSync(fd, chunk, 0, n, pos);
      const buf = Buffer.concat([chunk, carry]);
      let end = buf.length;
      while (end > 0) {
        const nl = buf.lastIndexOf(10, end - 1); if (nl < 0) break;
        const e = pick(buf.subarray(nl + 1, end)); if (e) return e;
        end = nl;
      }
      carry = buf.subarray(0, end);
    }
    return pick(carry);
  } catch { return undefined; } finally { closeSync(fd); }
}
/** The lines before a new segment (legacy SHA-256 lines, or written without the key): count and SHA-256 of their bytes. */
function prefix(path: string): { lines: number; sha256: string } {
  const b = readRegular(path); let lines = 0;
  for (let i = b.indexOf(10); i >= 0; i = b.indexOf(10, i + 1)) lines++;
  return { lines, sha256: sha256(b) };
}
/** An entry is a few hundred bytes: a line longer than this is no entry, and it is skipped as it streams by, never held whole. */
export const MAX_ENTRY_LINE = 16 << 20;
/**
 * Calls `each` with the bytes of every line of a file that contains `hint` (without its newline), in order, reading 1 MB at a
 * time: memory stays flat whatever the size of the log (a whole log read into one string fails past about 512 MB). Only the
 * lines holding `hint` are looked at and copied; a line longer than MAX_ENTRY_LINE is skipped. The bytes given are only valid
 * during the call. A missing file has no line. Any other error throws: a caller that takes the log for a fact (the kill
 * switch's generation floor) must never take a part of it for the whole. So does a log that is no regular file (a FIFO, a
 * device, a folder: never opened, openRegular).
 */
export function eachLine(path: string, each: (line: Buffer) => void, hint = ""): void {
  let fd: number;
  try { fd = openRegular(path); } catch (e) { if ((e as NodeJS.ErrnoException)?.code === "ENOENT") return; throw e; }
  const want = Buffer.from(hint), chunk = Buffer.alloc(1 << 20);
  let head: Buffer[] = [], size = 0;   // the start of a line whose end is not read yet (beyond MAX_ENTRY_LINE: counted, not kept)
  const ends = (tail: Buffer) => {       // the line in `head` ends with `tail`
    if (size + tail.length <= MAX_ENTRY_LINE) { const line = head.length ? Buffer.concat([...head, tail]) : tail; if (line.includes(want)) each(line); }
    head = []; size = 0;
  };
  try {
    for (let got: number; (got = readSync(fd, chunk, 0, chunk.length, null)) > 0;) {
      const data = chunk.subarray(0, got), first = data.indexOf(10);
      if (first < 0) { if (size <= MAX_ENTRY_LINE) head.push(Buffer.from(data)); size += got; continue; }
      ends(data.subarray(0, first));
      // the lines that start and end in this piece: from one occurrence of `hint` to the next, the others are not looked at
      const last = data.lastIndexOf(10);
      for (let from = first + 1; from < last;) {
        const at = data.indexOf(want, from);
        if (at < 0 || at >= last) break;
        const start = data.lastIndexOf(10, at - 1) + 1, end = data.indexOf(10, at);
        if (end - start <= MAX_ENTRY_LINE) each(data.subarray(start, end));
        from = end + 1;
      }
      if (last + 1 < got) { head = [Buffer.from(data.subarray(last + 1))]; size = got - last - 1; }
    }
    if (size) ends(Buffer.alloc(0));   // a last line without its newline
  } finally { closeSync(fd); }
}
/**
 * Calls `each` with every line of a log file that contains `hint` and parses as JSON other than a plain value (an entry, or
 * anything else a chain check must see), in order (eachLine: a stream, a missing file has none, any other error throws).
 */
export function eachEntry(path: string, each: (e: Entry) => void, hint = ""): void {
  eachLine(path, line => {
    let e: unknown; try { e = JSON.parse(line.toString("utf8")); } catch { return; }
    if (e && typeof e === "object") each(e as Entry);
  }, hint);
}
/** Every entry of a log file that `match` accepts, in order; only lines containing `hint` are parsed. A missing file has none; a log that cannot be read throws (eachLine). */
export function findEntries(path: string, match: (e: Entry) => boolean, hint = ""): Entry[] {
  const out: Entry[] = [];
  eachEntry(path, e => { try { if (match(e)) out.push(e); } catch {} }, hint);
  return out;
}

/** Largest generation a kill or resume may carry (kill-switch.ts writes no larger one): a forged entry cannot push the counter to overflow. */
export const MAX_GENERATION = 2 ** 40;
/**
 * The last kill or resume of a log (see lastSwitch): its generation, whether it is a kill, and the SHA-256 of the
 * kill-switch.json content it wrote. A keyed writer records it in the tail marker with every entry it appends.
 */
export interface SwitchMark { killed: boolean; gen: number; state: string }
/**
 * Why the last kill or resume of a log cannot be known. Its tail marker was written by an older version (`older`: it carries
 * no log id), for another log (`foreign`: the log of another KYTRAL_HOME using the same secret, or this one reached through
 * another real path), or it does not verify (`invalid`: edited, forged, written with another key, unreadable). Or the log
 * holds a kill or resume more recent than what speaks for it that is not its own: written by an older version, which signed
 * no log id (`older-entry`), or for another log (`foreign-entry`, copied in).
 */
export type Doubt = "older" | "foreign" | "invalid" | "older-entry" | "foreign-entry";
const DOUBTS: readonly unknown[] = ["older", "foreign", "invalid", "older-entry", "foreign-entry"];
/**
 * A switch held because of a Doubt (switchState): every guard that starts from it refuses every call. `gen`: the highest
 * generation known then; `state`: the digest of the state this log's own last kill wrote, when its last kill or resume is
 * a kill older than what is in doubt (a `resume` chains to it, so a guard started held lifts on that single resume). The
 * marker written after the one in doubt records it, and so does every marker after that, until a kill or resume is
 * journaled with the key.
 */
export interface Held { held: Doubt; gen: number; state?: string }
/** What a log says of its kill switch: its last kill or resume, or a held switch. */
export type SwitchRecord = SwitchMark | Held;
export const isHeld = (r: SwitchRecord | null | undefined): r is Held => !!r && "held" in r;
/** A kill or resume entry that can be recorded: a valid generation and the digest of the state it wrote. */
const switchOf = (e: Entry): SwitchMark | null => (e.decision === "kill" || e.decision === "resume") && Number.isSafeInteger(e.generation) && e.generation! >= 1
  && e.generation! <= MAX_GENERATION && typeof e.state === "string" && /^[0-9a-f]{64}$/.test(e.state) ? { killed: e.decision === "kill", gen: e.generation!, state: e.state } : null;
/** The later of two records: the higher generation (generations only grow), `b` at the same one. */
function later<A extends SwitchRecord, B extends SwitchRecord>(a: A | null, b: B | null): A | B | null { return !a ? b : !b ? a : b.gen >= a.gen ? b : a; }
/**
 * What a guard starts from when two logs speak for its kill switch (startingSwitch): the later of the two records, held if
 * either is (a doubt about one log is not settled by the other), at the higher generation.
 */
export function laterSwitch(a: SwitchRecord | null, b: SwitchRecord | null): SwitchRecord | null {
  const held = isHeld(a) ? a : isHeld(b) ? b : null, l = later(a, b);
  return held && l ? { held: held.held, gen: l.gen, ...(held.state ? { state: held.state } : {}) } : l;
}
/** `killSwitch`: undefined in a marker written before it was recorded there; `dep`: the id of the log it was written for (tailDep), none in a marker of an older version. */
type Tail = { seq: number; link: string; killSwitch?: SwitchRecord | null; dep?: string };
const TAIL_INVALID = "the tail marker does not verify (forged, edited, or written with another key)";
const tailMac = (key: Buffer, body: object) => createHmac("sha256", key).update(`audit-tail\n${canonicalJson(body)}`).digest("hex");
/** A marker's record: a kill or resume, a held switch, or null; anything else, in a marker that verifies, is held as invalid (fail closed). */
function recordOf(k: any): SwitchRecord | null {
  if (k === null) return null;
  if (k && typeof k === "object" && "held" in k)
    return DOUBTS.includes(k.held) && Number.isSafeInteger(k.gen) && k.gen >= 0 && k.gen <= MAX_GENERATION
      ? { held: k.held, gen: k.gen, ...(typeof k.state === "string" && /^[0-9a-f]{64}$/.test(k.state) ? { state: k.state } : {}) } : { held: "invalid", gen: 0 };
  const mark = k && typeof k === "object" ? switchOf({ decision: k.killed === true ? "kill" : k.killed === false ? "resume" : "", generation: k.gen, state: k.state } as Entry) : null;
  return mark ?? { held: "invalid", gen: 0 };
}
/**
 * The tail marker of a log: null when it is missing, "invalid" when it does not verify with this key (or cannot be read). A
 * marker that verifies is returned whatever log it was written for (`dep`): it still certifies the entries it names (append,
 * verifyAuditFile, an archive renamed with its log), but only a marker of this log speaks for its kill switch (switchState).
 * One that is no regular file (a FIFO, a device, a folder) is never opened: NotRegularFile is thrown, so that whoever starts
 * from it refuses (agent hooks, guards, `resume`).
 */
function readTail(path: string, key: Buffer): Tail | null | "invalid" {
  let t: any;
  try { t = JSON.parse(readRegular(auditTailPath(path)).toString("utf8")); }
  catch (e: any) { if (e instanceof NotRegularFile) throw e; return e?.code === "ENOENT" ? null : "invalid"; }
  // v1: written by an older version, without the log's id; v2 always carries both the id and the record
  if (!t || !(t.v === 1 || (t.v === 2 && typeof t.dep === "string" && "killSwitch" in t)) || !Number.isSafeInteger(t.seq) || typeof t.link !== "string") return "invalid";
  const { mac, ...body } = t;
  if (!same(mac, tailMac(key, body))) return "invalid";
  return { seq: t.seq, link: t.link, ...(t.killSwitch !== undefined ? { killSwitch: recordOf(t.killSwitch) } : {}), ...(t.v === 2 ? { dep: t.dep } : {}) };
}
/**
 * 0600 temp file + atomic rename (writeReplace: it also takes the place of a FIFO or a folder put there), under the log's lock.
 * Signed with the id of the log (tailDep).
 */
function writeTail(path: string, key: Buffer, seq: number, last: string, killSwitch: SwitchRecord | null) {
  const body = { v: 2, seq, link: last, at: new Date().toISOString(), killSwitch, dep: tailDep(key, path) };
  writeReplace(auditTailPath(path), JSON.stringify({ ...body, mac: tailMac(key, body) }));
}
/**
 * Whether the tail marker certifies the log as it is now: the entry it names is in place, and every line after it was written
 * without a key (a keyed writer moves the marker to its own entry: a keyed line after it means the marker was put back, or its
 * writer stopped in between).
 */
function certifies(path: string, t: Tail, last: Entry | undefined): boolean {
  if (last?.seq === undefined) return false;
  const behind = last.seq - t.seq;
  if (behind < 0 || behind > 1000) return false;
  if (behind === 0) return link(last) === t.link;
  const lines = tail(path, behind + 1).lines.map(l => { try { return JSON.parse(l); } catch { return undefined; } });
  return lines.length === behind + 1 && isEntry(lines[0]) && lines[0].seq === t.seq && link(lines[0]) === t.link && lines.slice(1).every(e => isEntry(e) && e.mac === undefined);
}
/**
 * The kills and resumes of a log whose MAC verifies with `key`, read whole, as a stream (throws when the log cannot be read):
 * `own`, the last (highest generation) of those that sign this log's id, null when there is none; `other`, the highest
 * generation among the rest (copied in from another log, or written by an older version that signed no id), which never
 * speak for this log's kill switch: at most they hold it (Held). Lines are taken one by one, wherever they are: an
 * authentic line can be copied anywhere, so only its id says whose it is.
 */
function scanSwitch(path: string, key: Buffer): { own: SwitchMark | null; other: Held | null } {
  const dep = tailDep(key, path);
  let own: SwitchMark | null = null, other: Held | null = null;
  eachEntry(path, e => {
    const s = switchOf(e); if (!s || !entryAuthentic(key, e)) return;
    if (e.dep === dep) own = later(own, s);
    else if (!other || s.gen > other.gen) other = { held: e.dep === undefined ? "older-entry" : "foreign-entry", gen: s.gen };
  }, '"agentId":"*"');
  return { own, other };
}
/**
 * What a log's tail marker gives the generation floor of a writer (kill, resume): `gen`, the highest generation it records
 * when it verifies, whatever log it was written for (generations only grow: a higher floor never lets anything in); `mark`,
 * its last kill or resume when it is a marker of this log (a resume may chain to it). A marker that is no regular file throws
 * (NotRegularFile), and so does one built so that checking it fails.
 */
export function tailSwitch(path: string, key: Buffer): { gen: number; mark: SwitchMark | null } {
  path = resolve(path);
  const t = readTail(path, key), k = t && t !== "invalid" ? t.killSwitch ?? null : null;
  return { gen: k?.gen ?? 0, mark: k && !isHeld(k) && t && t !== "invalid" && t.dep === tailDep(key, path) ? k : null };
}
/**
 * What a log at `path` and its tail marker `t` say of the kill switch (null: no kill or resume), as a guard starts from it
 * (lastSwitch) and as a writer records it in the next marker (append). `last`: the log's last entry; `torn`: its last line is
 * torn. Only what this log wrote speaks for it: its marker (its id), and its own kills and resumes (they sign its id too,
 * scanSwitch); a marker or an entry of another log, or of an older version, never lifts a kill and is never taken for a
 * resume. Fail safe: whatever is in doubt holds the switch (Held), unless a kill of this log stands (a kill only restricts,
 * as much as a held switch, and a resume chains to it) at least as recent as what is in doubt.
 * - A marker of this log is believed while it certifies the log as it is. Otherwise (put back, entries appended after it by
 *   a writer that stopped, a log cut short, replaced or renamed) its record stands, and the log can only add a later kill of
 *   its own: a later resume in it proves nothing, since a resume whose marker was never written never took effect (it is
 *   journaled before its state is written). A kill or resume of another log, or of an older version, more recent than that
 *   record holds the switch, unless the record is a kill.
 * - Without a marker, the log's own last kill or resume decides (read whole, as a stream), held in the same way.
 * - A marker in doubt (Doubt: an older version's, another log's, one that does not verify or cannot be read) never speaks for
 *   the switch, and neither does a resume found in the log: the switch is held (every guard refuses every call until a kill
 *   or resume is journaled), unless the last kill or resume this log wrote is a kill at least as recent as what the marker
 *   and the entries in doubt say, which stands.
 */
function switchState(path: string, key: Buffer, t: Tail | null | "invalid", last: Entry | undefined, torn: boolean): SwitchRecord | null {
  const doubt: Doubt | null = t === null ? null : t === "invalid" ? "invalid" : t.dep === undefined ? "older" : t.dep !== tailDep(key, path) ? "foreign" : null;
  const said = t === null || t === "invalid" ? null : t.killSwitch ?? null;
  if (t !== null && !doubt && !torn && certifies(path, t as Tail, last)) return said;
  const { own, other } = scanSwitch(path, key);
  if (doubt) {
    const gen = Math.max(said?.gen ?? 0, other?.gen ?? 0);
    return own?.killed && own.gen >= gen ? own : { held: doubt, gen: Math.max(gen, own?.gen ?? 0), ...(own?.killed ? { state: own.state } : {}) };
  }
  const base = t === null ? own : own?.killed && own.gen > (said?.gen ?? 0) ? own : said;
  if (!other || other.gen <= (base?.gen ?? 0) || (base && !isHeld(base) && base.killed)) return base;
  return isHeld(base) && base.state ? { ...other, state: base.state } : other;
}
/**
 * The last kill or resume the log records with this key (null: none), or a held switch (Held), for a process with no memory
 * of its own: an agent hook, a new process at each call (switchState). The tail marker's record when the marker is this log's
 * and certifies it as it is: two small reads. A rollback of the log and its marker together is not seen (it needs an anchor
 * off the machine). Throws when the log cannot be read, and when the log or its marker is no regular file (a FIFO, a device,
 * a folder: never opened).
 */
export function lastSwitch(path: string, key: Buffer): SwitchRecord | null {
  path = resolve(path);
  const t = readTail(path, key);
  let last: Entry | undefined, torn = false;
  try { last = lastEntry(path); } catch (e) { if ((e as NodeJS.ErrnoException)?.code) throw e; torn = true; }   // a read error, or a torn last line
  return switchState(path, key, t, last, torn);
}
/** Why a log no longer matches its tail marker `t` (lines removed from the end, rolled back, rewritten; marker missing or forged), or null. */
function tailProblem(path: string, t: Tail | null | "invalid", last: Entry): string | null {
  if (t === null) return "the tail marker is missing";
  if (t === "invalid") return TAIL_INVALID;
  const behind = last.seq! - t.seq;   // > 0 when entries written without the key (which do not move the marker) follow it
  if (behind < 0) return `the log ends at seq ${last.seq} but its tail marker certifies seq ${t.seq} (lines removed from the end, or rolled back)`;
  if (behind > 1000) return `its tail marker certifies seq ${t.seq}, more than 1000 entries before the end`;
  let e: any = last;
  if (behind > 0) { e = undefined; try { e = JSON.parse(tail(path, behind + 1).lines[0]); } catch {} }
  return isEntry(e) && e.seq === t.seq && link(e) === t.link ? null : `the entry its tail marker certifies (seq ${t.seq}) is missing or was rewritten`;
}

export class AuditLog {
  /** HMAC key (auditKey). Without it entries are written unauthenticated, and `audit verify` never reports them as valid. */
  key?: Buffer;
  /** Last entry of a log kept in memory (a file is re-read before every append). */
  private last?: Entry;
  /** Called with every entry once it is written (plugins: SIEM, dashboards). Their errors are ignored: a copy never blocks the log. */
  sinks: ((e: Entry) => void)[] = [];
  constructor(private path?: string, opts: { key?: Buffer } = {}) {
    this.key = opts.key;
    // A torn last line throws. Read under the lock: unlocked, another process's append in progress could look torn.
    if (path) { const p = this.path = path = resolve(path); mkdirSync(dirname(p), { recursive: true, mode: 0o700 }); withFileLock(p, () => lastEntry(p)); }
  }
  entries: Entry[] = [];
  /**
   * Appends one chained entry. With a file, runs under the inter-process lock and first re-reads the file's last entry, so
   * several writers (proxies, the CLI) extend one chain instead of forking it. A keyed writer also checks the tail marker:
   * if the log no longer matches it (lines removed from the end, rolled back, marker missing or forged), the entry starts a
   * new segment that records the anomaly, so the evidence stays in the log; then it moves the marker to its entry.
   */
  append(e: AuditFields): Entry {
    const write = () => {
      // A marker that is no regular file (a FIFO, a folder...) is never read: for a writer it is a marker that does not verify,
      // recorded as an anomaly, and replaced by this entry's.
      const path = this.path, key = this.key, last = path ? lastEntry(path) : this.last;
      let t: Tail | null | "invalid" = null;
      try { t = key && path ? readTail(path, key) : null; } catch (e) { if (!(e instanceof NotRegularFile)) throw e; t = "invalid"; }
      let mark: Pick<Entry, "segment" | "legacy" | "anomaly" | "unauthenticated"> = {};
      if (key && last?.seq === undefined) {
        // New log, or no HMAC entry yet (legacy lines): this entry starts the HMAC segment and binds the lines before it.
        const anomaly = t === null ? undefined : t === "invalid" ? TAIL_INVALID : `the log has no HMAC entry but its tail marker certifies seq ${t.seq} (replaced, emptied or truncated)`;
        mark = { segment: AUDIT_SEGMENT, ...(path && last ? { legacy: prefix(path) } : {}), ...(anomaly ? { anomaly } : {}) };
      } else if (key && path) { const anomaly = tailProblem(path, t, last!); if (anomaly) mark = { segment: AUDIT_SEGMENT, anomaly }; }
      else if (!key && last?.seq !== undefined) mark = { unauthenticated: true };
      // The last kill or resume, recorded in the marker with this entry, as a guard would start from it (switchState): carried
      // over from the marker when it is this log's and certifies it, else read from the log (once: the marker then carries it
      // again), held while something in doubt leaves it unknown; this entry if it is one. A kill or resume signs this log's id.
      const switched = key && path ? switchState(path, key, t, last, false) : null;
      const dep = key && path && (e.decision === "kill" || e.decision === "resume") ? { dep: tailDep(key, path) } : {};
      const base = { ts: new Date().toISOString(), ...e, ...dep, ...mark, ...(key || last?.seq !== undefined ? { seq: (last?.seq ?? 0) + 1 } : {}), prev: last ? link(last) : "GENESIS" };
      let full: Entry = { ...base, hash: sha256(JSON.stringify(base)) };
      if (key) full = { ...full, mac: entryMac(key, full) };
      if (path) { appendRegular(path, JSON.stringify(full) + "\n"); if (key) writeTail(path, key, full.seq!, full.mac!, later(switched, switchOf(full))); }
      this.last = full; this.entries.push(full);
      return full;
    };
    const full = this.path ? withFileLock(this.path, write) : write();
    for (const sink of this.sinks) { try { sink(full); } catch {} }
    return full;
  }
  /** Last entry `match` accepts: in the file, read backward (lines that do not parse are skipped), or in memory. Never throws. */
  findLast(match: (e: Entry) => boolean, hint = ""): Entry | undefined {
    if (this.path) return findLastEntry(this.path, match, hint);
    for (let i = this.entries.length - 1; i >= 0; i--) if (match(this.entries[i])) return this.entries[i];
    return undefined;
  }
  /** Every entry `match` accepts, in order: in the file (lines that do not parse are skipped), or in memory. A file that exists but cannot be read throws (eachLine). */
  findAll(match: (e: Entry) => boolean, hint = ""): Entry[] {
    return this.path ? findEntries(this.path, match, hint) : this.entries.filter(match);
  }
  /** Calls `each` with every entry, in order: in the file, read as a stream (eachEntry; a file that exists but cannot be read throws), or in memory. */
  each(visit: (e: Entry) => void, hint = ""): void {
    if (this.path) eachEntry(this.path, visit, hint); else for (const e of this.entries) visit(e);
  }
  /** The file, if the log has one. */
  get file(): string | undefined { return this.path; }
}

/**
 * Checks entries in order. Without the key: links and unkeyed SHA-256 only, which detects accidental damage, not tampering
 * (anyone can recompute them). With the audit key: true only if every entry is an HMAC entry that verifies, in sequence,
 * without a recorded anomaly; legacy lines and entries written without the key are never valid. For a file, verifyAuditFile.
 */
export function verifyChain(entries: Entry[], key?: Buffer): boolean {
  const v = chainVerifier(key);
  for (const e of entries) if (!v.add(e)) return false;
  return true;
}
/** verifyChain one entry at a time, for a log read as a stream: add() says whether the entries given so far still verify. */
export function chainVerifier(key?: Buffer): { add: (e: Entry) => boolean } {
  let prev = "GENESIS", seq: number | undefined, ok = true;
  const check = (e: Entry): boolean => {
    if (!isEntry(e) || e.prev !== prev || digest(e) !== e.hash) return false;
    if (key) {
      if (!Number.isSafeInteger(e.seq) || (seq !== undefined && e.seq !== seq + 1) || e.anomaly !== undefined || !same(e.mac, entryMac(key, e))) return false;
      seq = e.seq;
    }
    prev = link(e);
    return true;
  };
  return { add: e => (ok &&= check(e)) };
}

/** Result of verifyAuditFile. `broken.line` is lines + 1 for a problem at the end of the log (truncation, marker). */
export interface AuditReport {
  path: string; exitCode: 0 | 1 | 3; lines: number; hmac: number; legacy: number; unauthenticated: number[];
  broken?: { line: number; why: string }; tailSeq?: number;
}
/**
 * Verifies a log file with the audit key. exitCode 0: every line is an HMAC entry, in sequence, unmodified, and the tail
 * marker certifies an entry that is still there (nothing removed from the end). 1: `broken` is the first broken line:
 * modified, deleted, inserted, reordered, truncated, written with another key, or an anomaly recorded by a writer. 3: nothing
 * broken, but some lines cannot be verified: legacy SHA-256 lines, or entries written without the key. No log, no marker: 0.
 */
export function verifyAuditFile(path: string, key: Buffer): AuditReport {
  path = resolve(path);
  // Snapshot under the lock when it can be taken: the marker, then the size (a writer appends its entry before moving the marker).
  const snap = () => { const t = readTail(path, key); let size = 0; try { assertRegular(path); size = statSync(path).size; } catch (e: any) { if (e.code !== "ENOENT") throw e; } return { t, size }; };
  let s: ReturnType<typeof snap>;
  try { s = withFileLock(path, snap, 1000); } catch { s = snap(); }
  const r: AuditReport = { path, exitCode: 0, lines: 0, hmac: 0, legacy: 0, unauthenticated: [] };
  const broken = (line: number, why: string): AuditReport => ({ ...r, exitCode: 1, broken: { line, why } });
  const t = s.t, certified = t !== null && t !== "invalid" ? t.seq : undefined;
  let prev = "GENESIS", seq: number | undefined, tailLink: string | undefined;
  // Read 1 MB at a time, so that memory stays flat whatever the size of the log (a whole log in one string fails past
  // about 512 MB). The bytes of the legacy lines before the HMAC chain are hashed as they go by.
  const legacyBytes = createHash("sha256");
  const line = (n: number, raw: Buffer): string | undefined => {
    let e: any; try { e = JSON.parse(raw.toString("utf8")); } catch {}
    if (!isEntry(e)) return "not an audit entry (corrupt or modified)";
    if (seq === undefined && e.seq === undefined) { r.legacy++; legacyBytes.update(raw).update("\n"); prev = link(e); return; }   // legacy SHA-256 line: kept, never verified
    if (!Number.isSafeInteger(e.seq)) return "invalid seq";
    if (seq === undefined) {
      // First line of the HMAC chain: a keyed segment entry that binds every line before it.
      if (typeof e.mac !== "string" || e.segment !== AUDIT_SEGMENT) return "the HMAC chain does not start with a keyed segment entry (lines deleted, inserted or moved)";
      if ((r.legacy || e.legacy) && !(e.legacy?.lines === r.legacy && e.legacy?.sha256 === legacyBytes.digest("hex")))
        return `the ${r.legacy} legacy line(s) before the HMAC chain were changed after it started`;
    } else if (e.seq !== seq + 1) return `out of sequence (seq ${e.seq} after ${seq}): a line was deleted, inserted or moved`;
    if (e.prev !== prev) return "does not follow the previous line: a line was deleted, inserted or moved";
    if (digest(e) !== e.hash) return "modified: the content does not match its hash";
    if (typeof e.mac === "string") {
      if (!same(e.mac, entryMac(key, e))) return "the MAC does not verify: modified, forged, or written with another key";
      if (typeof e.anomaly === "string") return `when this entry was written, the log no longer matched its tail marker: ${e.anomaly}`;
      r.hmac++;
    } else r.unauthenticated.push(n);   // written without the key: in the chain, never verified
    seq = e.seq as number; prev = link(e); if (seq === certified) tailLink = prev;
    return undefined;
  };
  if (s.size) {
    const fd = openRegular(path), chunk = Buffer.alloc(1 << 20);
    const newlines = (b: Buffer, from = 0) => { let k = 0; for (let i = b.indexOf(10, from); i >= 0; i = b.indexOf(10, i + 1)) k++; return k; };
    /** Calls `each` with every chunk of the snapshot, in order; stops when it returns true. */
    const chunks = (each: (b: Buffer) => boolean | void) => {
      for (let pos = 0; pos < s.size;) { const got = readSync(fd, chunk, 0, Math.min(chunk.length, s.size - pos), pos); if (got <= 0) return; pos += got; if (each(chunk.subarray(0, got))) return; }
    };
    try {
      // A torn or cut last line is reported first, as the line after the last complete one.
      const end = Buffer.alloc(1); readSync(fd, end, 0, 1, s.size - 1);
      if (end[0] !== 10) { let lines = 1; chunks(b => { lines += newlines(b); }); r.lines = lines; return broken(lines, "incomplete last line (torn write, or cut in the middle)"); }
      // after the first broken line, the rest is only counted: the report gives the number of lines of the log
      let n = 0, carry = Buffer.alloc(0), bad: { line: number; why: string } | undefined;
      chunks(b => {
        if (bad) { n += newlines(b); return; }
        const data = carry.length ? Buffer.concat([carry, b]) : b;
        let start = 0;
        for (let nl = data.indexOf(10); nl >= 0; start = nl + 1, nl = data.indexOf(10, start)) {
          const why = line(++n, data.subarray(start, nl));
          if (why) { bad = { line: n, why }; n += newlines(data, nl + 1); carry = Buffer.alloc(0); return; }
        }
        carry = Buffer.from(data.subarray(start));   // copied: the chunk is read into again
      });
      r.lines = n;
      if (bad) return broken(bad.line, bad.why);
      if (carry.length) { r.lines = n + 1; return broken(n + 1, "incomplete last line (torn write, or cut in the middle)"); }   // shortened meanwhile
    } finally { closeSync(fd); }
  }
  // Lines removed from the end: the signed marker must certify an entry that is still in the log.
  if (seq === undefined) { if (t !== null) return broken(r.lines + 1, "the log has no HMAC entry but has a tail marker (replaced, emptied or truncated)"); }
  else if (t === null) return broken(r.lines + 1, "the tail marker is missing: lines removed from the end cannot be ruled out");
  else if (t === "invalid") return broken(r.lines + 1, TAIL_INVALID);
  else if (tailLink !== t.link) return broken(r.lines + 1, t.seq > seq ? `truncated: the tail marker certifies seq ${t.seq}, the log ends at seq ${seq}` : `the entry the tail marker certifies (seq ${t.seq}) was replaced`);
  else r.tailSeq = t.seq;
  return { ...r, exitCode: r.legacy || r.unauthenticated.length ? 3 : 0 };
}
/** Human-readable lines for `kytral-guard audit verify`. */
export function describeAudit(r: AuditReport): string[] {
  if (r.broken) return [`${r.path}`, `BROKEN ${r.broken.line > r.lines ? `at the end of the log (after line ${r.lines})` : `at line ${r.broken.line}`}: ${r.broken.why}`];
  const nums = (l: number[]) => l.length > 20 ? `${l.slice(0, 20).join(", ")}, ...` : l.join(", ");
  const counts = `${r.lines} line(s): ${r.hmac} HMAC entr${r.hmac === 1 ? "y" : "ies"} verified, ${r.legacy} legacy, ${r.unauthenticated.length} written without the audit key`;
  if (r.exitCode === 3) return [`${r.path}: ${counts}`, `UNVERIFIED: nothing in the HMAC chain was modified, deleted, reordered or truncated, but ${[
    r.legacy ? `lines 1-${r.legacy} are legacy SHA-256 entries (unkeyed)` : "", r.unauthenticated.length ? `line(s) ${nums(r.unauthenticated)} were written without the audit key` : ""].filter(Boolean).join(", and ")}: they cannot be verified`];
  return [`${r.path}: ${counts}`, r.lines ? `OK: nothing modified, deleted, reordered or truncated (tail marker: seq ${r.tailSeq})` : "OK: empty log"];
}
