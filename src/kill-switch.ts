// Kill switch shared by every proxy and Guard of one KYTRAL_HOME: $KYTRAL_HOME/kill-switch.json.
// `kytral-guard kill` engages it and `kytral-guard resume` lifts it, from any terminal. A Guard reads the file before every
// tool call (re-parsed when its content changes) and while a confirmation is pending, so a kill stops proxies that are
// already running. Replay protection does not depend on the clock: every kill or resume carries a generation, the previous
// one + 1, signed with the proxies' key, and a Guard accepts a state only if its generation is greater than the last one it
// saw. Fail closed: an unreadable or corrupt file, an unsigned or forged resume and a replayed (older) state block every
// call; deleting the file neither lifts a kill nor lets an older generation back in for a running Guard. A Guard that starts
// with no memory, an agent hook above all (a new process at each call), starts from the last kill or resume the audit log
// records in its signed tail marker (lastSwitch, KillSwitch's `last`), so the same holds for it. The marker signs the id of
// its log (tailDep, derived from the log's real path as `dep` below is): a marker taken from another home with the same
// secret, written by an older version or that does not verify never lifts a kill nor says "resumed"; with nothing as recent
// in the log itself, the guard starts held (every call refused) until a resume. Kills and resumes journaled with the key sign
// the same id: those of another log (copied in) or of an older version are never this log's, never taken for a resume, and
// one more recent than what speaks for the log holds the switch too.
// A state also says which one it replaces: it signs `after` (SHA-256 of the file content it replaced) and `dep` (the id of
// this deployment). The id is derived, never stored: an HMAC, with the states' key, of the state file's real path (see
// deploymentId), so only a holder of the secret can compute it and a state signed for one file is foreign to every other one,
// even once copied there. The Guard computes it once at startup and this pin never changes while it runs. A resume lifts a kill
// only if it carries the pinned id, has a generation greater than the last one seen, AND chains to a kill the Guard holds
// (`after` is the digest of one). Unsigned or refused content that arrives while a signed kill is in force is never added to
// what a resume may chain to, so a pair (kill, chained resume) copied from another home or built over corrupt content cannot
// lift it; and since a writer signs the id of the file it writes, a resume run in another home over a copy of our kill (same
// secret) carries that home's id and cannot lift it here either. A kill is "of this deployment" (moving the generation) only
// if it carries the pinned id: a foreign kill, or one that merely chains to an anchor placed by an attacker (unsigned kill,
// corrupt or forged content), is honoured but never moves the generation. Fail safe: a state the Guard missed leaves it killed
// until the next legitimate kill and resume, or a restart; states written through another real path (moved directory, bind
// mount) or by an older install carry another id: they block until a kill and a resume written through the Guard's path.
// Only v2 states exist: v1 (never published) is refused.
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { AuditLog, auditKey, chainVerifier, Doubt, eachEntry, Entry, entryAuthentic, isHeld, lastSwitch, laterSwitch, MAX_GENERATION, SwitchMark, SwitchRecord, tailDep, tailSwitch } from "./audit.js";
import { canonicalJson } from "./confirm-queue.js";
import { assertAuditSecret, assertStrongSecret } from "./secret.js";
import { deriveKey, NotRegularFile, readProblem, readRegular, realFilePath, statePath, withFileLock, writeReplace } from "./store.js";

export const killSwitchPath = () => statePath(undefined, "kill-switch.json");
/** Signing key of the states: from KYTRAL_AUDIT_SECRET if set, else the proxy secret; same strong-secret rule as the Guard. */
export const killSwitchKey = (secret: string) => deriveKey(assertAuditSecret() ?? assertStrongSecret(secret), "kill-switch/v1");
/**
 * A state written with the key: `gen` = previous generation + 1 (a counter, not a time), signed with `killed`, `at` (write
 * time, for display and audit only) and `by`. v2 also signs `dep` (id of the deployment, derived from the key and the state
 * file's real path) and `after` (digest of the file content it replaced, "none" when there was none).
 */
export interface KillState { v: 2; killed: boolean; gen: number; at: string; by: string; sig: string; dep?: string; after?: string }
/**
 * Written by `kytral-guard kill` without a usable key: honoured (a kill only restricts) but never trusted for ordering.
 * `last` is the signed state it replaced, so a Guard started meanwhile still learns the current generation.
 */
export interface UnsignedKill { v: 1; killed: true; at: string; by: string; last?: KillState }
/** How often a pending confirmation re-reads the kill switch, in ms. */
export const KILL_POLL_MS = 100;
/** Largest generation a journal entry may carry (and a writer produce): a sane bound, far above any real use, so a forged entry cannot push the counter to overflow. */
export { MAX_GENERATION };
const validGen = (g: unknown): g is number => Number.isSafeInteger(g) && (g as number) >= 1 && (g as number) <= MAX_GENERATION;
const NO_STATE = "none";   // `after` of a state written when the file did not exist
const isDep = (d: unknown) => typeof d === "string" && /^[0-9a-f]{32}$/.test(d);
const isAfter = (a: unknown) => typeof a === "string" && (a === NO_STATE || a === "unreadable" || /^[0-9a-f]{64}$/.test(a));
const sha256 = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const sign = (key: Buffer, body: object) => createHmac("sha256", key).update(`kill-switch\n${canonicalJson(body)}`).digest("base64url");
const sameSig = (a: string, b: string) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); };
/** Deepest nesting a state file may hold (an unsigned kill carries the state it replaced, one level down), with room to spare. */
const STATE_DEPTH = 8;
/**
 * Whether `v` nests objects or arrays more than `max` levels deep, found without recursion: JSON.parse reads any depth, but
 * signing it again (JSON.stringify) overflows the stack a few thousand levels down.
 */
function nestedDeeper(v: unknown, max: number): boolean {
  const todo: [unknown, number][] = [[v, 0]];
  for (let next = todo.pop(); next; next = todo.pop()) {
    const [x, depth] = next;
    if (!x || typeof x !== "object") continue;
    if (depth > max) return true;
    for (const y of Object.values(x)) if (y && typeof y === "object") todo.push([y, depth + 1]);
  }
  return false;
}
/** A signed state's fields are plain values: an object or array among them makes it no state. */
const flat = (o: object) => Object.values(o).every(v => v === null || typeof v !== "object");
/** `o` if it is a state signed with this key, with a valid generation; else null. */
function verified(key: Buffer, o: any): KillState | null {
  if (!o || typeof o !== "object" || Array.isArray(o) || typeof o.sig !== "string") return null;
  const { sig, ...body } = o;
  if (!flat(body)) return null;   // never signed again: nested content is no state, and deep enough it would overflow the stack
  const shape = body.v === 2 && isDep(body.dep) && isAfter(body.after);
  return sameSig(sig, sign(key, body)) && shape && typeof body.killed === "boolean" && validGen(body.gen) ? o : null;
}

/** What is in doubt in the audit log, when a Doubt holds the switch: its tail marker, or a kill or resume it holds. */
const OTHER_LOG = "another audit log (another KYTRAL_HOME using the same secret, or this one through another path)";
const DOUBTFUL: Record<Doubt, string> = {
  older: "the audit log's tail marker was written by an older version of Kytral Guard",
  foreign: `the audit log's tail marker was written for ${OTHER_LOG}`,
  invalid: "the audit log's tail marker does not verify (edited, forged, written with another key, or unreadable)",
  "older-entry": "the audit log holds a kill or resume written by an older version of Kytral Guard",
  "foreign-entry": `the audit log holds a kill or resume written for ${OTHER_LOG}`,
};
const heldReason = (d: Doubt) => `${DOUBTFUL[d]}, so the last kill or resume is not known`;
/** Why every call is refused while the switch is held (Held), and what lifts it. */
const heldVerdict = (d: Doubt) => `kill switch active: ${heldReason(d)}, every tool call is refused (fail closed): a single 'kytral-guard resume' lifts it`;

/** Reader used by the Guard. `check()` never throws: null = calls go on, otherwise why every call is refused. */
export class KillSwitch {
  readonly path: string;
  private digest: string | null = null;     // sha256 of the content last evaluated
  private verdict: string | null = null;    // its verdict, kept while the file is missing (a deletion never lifts a kill)
  private gen = 0;                          // last generation accepted: the next state must carry a greater one (anti-replay)
  private readonly dep: string;             // this deployment's id, derived once at startup and never changed (the pin): a resume must carry it
  private anchors = new Set<string>();      // digests a resume may chain to: the kills in force, or what blocked the Guard while no kill was
  private killing = false;                  // a kill (signed or not) is in force
  private trusted = false;                 // a signed kill of this deployment is in force: nothing unsigned or refused arriving meanwhile is added to the anchors
  private resumed: string | null = null;    // digest of the resume in force: read again after a bad read, it is still valid
  private reported: string | null = null;   // last problem journaled: once per content (or read error), not once per call
  private held: Doubt | null = null;        // started held (Held): no resume lifts anything until one chains to what this guard read
  /**
   * `report` journals an unusable state (unreadable, corrupt, forged or replayed). `last`: the last kill or resume the audit
   * log records (lastSwitch), for a guard that starts with no memory, an agent hook above all (a new process at each call): it
   * starts as a guard that has read that state, so kill-switch.json deleted, or an older state put back (a resume of an earlier
   * generation), does not lift a kill journaled after it. A held switch (something in doubt in the log, and no kill of its
   * own as recent): every call is refused, and only a resume of this deployment that chains to what the guard reads (the
   * content of kill-switch.json, or none, read at once), to a kill it reads later, or to the kill the log wrote last (the
   * held record's `state`) lifts it; never the first resume it reads.
   */
  constructor(path: string, private key: Buffer, private report?: (why: string) => void, last?: SwitchRecord | null) {
    this.path = resolve(path);
    try { mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 }); } catch {}
    this.dep = deploymentId(key, this.path);
    if (isHeld(last)) {
      // what a resume may chain to: what this guard reads now, and the kill this log wrote last when it is held over it
      this.gen = last.gen; this.held = last.held; this.verdict = heldVerdict(last.held);
      if (last.state) this.anchors.add(last.state);
      this.check();
    }
    else if (last && validGen(last.gen)) {
      this.gen = last.gen; this.digest = last.state;   // that state's file content, read again, keeps its verdict
      if (last.killed) { this.killing = this.trusted = true; this.anchors.add(last.state); this.verdict = "kill switch active"; }
      else this.resumed = last.state;
    }
  }
  check(): string | null {
    try { return this.read(); }
    catch (e) {
      // Never thrown out (a proxy polls this every 250 ms): what cannot be checked blocks every call, the file deleted
      // meanwhile too, and the same content is checked again next time.
      this.digest = null;
      return (this.verdict = this.invalid(`cannot be checked (${(e as NodeJS.ErrnoException)?.code ?? "error"})`));
    }
  }
  private read(): string | null {
    let buf: Buffer;
    // a regular file only, opened without waiting: a FIFO, a socket, a device or a folder in its place is unreadable
    try { buf = readRegular(this.path); }
    catch (e: any) {
      // No content to chain to: a resume written over a missing or unreadable file says so in its `after`, accepted if no kill is in force (only a refused state blocks).
      if (e?.code === "ENOENT") { if (this.verdict !== null && !this.killing) this.anchors.add(NO_STATE); return this.held && !this.killing ? this.doubt() : this.verdict; }
      if (!this.trusted) this.anchors.add("unreadable");
      return this.invalid(`unreadable (${readProblem(e)})`);
    }
    const h = sha256(buf);
    if (h !== this.digest) { this.digest = null; this.verdict = this.evaluate(buf.toString("utf8"), h); this.digest = h; }
    return this.verdict;
  }
  private evaluate(text: string, h: string): string | null {
    let s: any; try { s = JSON.parse(text); } catch { return this.refused("corrupt (not JSON)", h); }
    if (!s || typeof s !== "object" || Array.isArray(s)) return this.refused("corrupt (not a JSON object)", h);
    if (nestedDeeper(s, STATE_DEPTH)) return this.refused("corrupt (JSON nested too deep to be a state)", h);
    if (s.killed !== true && s.killed !== false) return this.refused("corrupt ('killed' is neither true nor false)", h);
    if (s.killed && s.sig === undefined) {
      // A kill written without the key: honoured, but not trusted for ordering. Unless a signed kill of this deployment is in force, it is what a
      // resume must chain to (its `after` is this content's digest). The signed state it carries tells a Guard started meanwhile
      // the current generation, if it is of this deployment.
      if (!this.killing) {
        const last = verified(this.key, s.last);
        if (last && last.dep === this.dep && last.gen > this.gen) this.gen = last.gen;
      }
      if (!this.trusted) this.anchors.add(h);
      this.killing = true; this.resumed = null; this.reported = null;
      return "kill switch active";
    }
    const st = verified(this.key, s);
    // A v1 state (signed, without the deployment id) was written by an older version: an installation that upgrades finds it
    // and stops; one `resume` replaces it (it chains to this content), no kill is needed first.
    if (!st) return s.v === 1 && typeof s.sig === "string"
      ? this.refused(`holds a ${s.killed ? "kill" : "resume"} not signed with this deployment's key (a v1 state, written by an older version of Kytral Guard, or forged)`, h, "a single 'kytral-guard resume' lifts it")
      : this.refused(`holds a ${s.killed ? "kill" : "resume"} not signed with this deployment's key (forged, edited, another secret, or written by an older version)`, h);
    if (!st.killed && st.gen === this.gen && h === this.resumed) { this.reported = null; return null; }   // the resume in force, read again
    if (st.gen <= this.gen) {
      // held: a resume written over it may chain to it, and the switch says why it is held (the state may be the very kill or
      // resume it is held at: an upgrade meets one, journaled in an older format, which holds the switch at its generation)
      if (this.held && !this.trusted) { this.anchors.add(h); return this.doubt(); }
      return this.invalid(`holds a replayed ${st.killed ? "kill" : "resume"} (generation ${st.gen}, not newer than ${this.gen})`, h);
    }
    if (st.killed) {
      // Always honoured (a kill only restricts). It is "of this deployment" (and moves the generation) only if it carries the
      // pinned id. Nothing else makes it "mine": not chaining to the resume in force, and not chaining to a mere anchor (an
      // unsigned kill, or corrupt/forged content, the only things an attacker without the secret can place). The pin itself
      // never moves, so a kill signed for another file (another home, even with our kill copied there, or an older install)
      // never makes that home's resumes lift anything here. A foreign or anchor-chained kill still blocks and, when no kill
      // was in force, is anchored, so that a resume of this deployment written over it lifts it.
      const mine = st.dep === this.dep;
      if (mine) this.gen = st.gen;
      if (mine || !this.killing) this.anchors.add(h);
      if (mine) this.trusted = true;
      this.killing = true; this.resumed = null; this.reported = null;
      return "kill switch active";
    }
    // A resume lifts what is in force only with this deployment's id and a newer generation (checked above) and if it chains to
    // it. With nothing held (a kill that was missed has already been replaced) the id is enough, unless the switch started held:
    // then it is refused and anchored, so that a resume written over it lifts. A resume of another deployment never lifts: with
    // nothing in force it blocks (fail closed) until a resume of this one.
    const lifts = st.dep === this.dep && (this.anchors.size === 0 ? !this.held : this.anchors.has(st.after!));
    if (!lifts && this.held && !this.trusted) { this.anchors.add(h); return this.doubt(); }
    if (!lifts)
      return this.invalid(`holds a resume that does not chain to the kill in force (generation ${st.gen}: taken from another state or deployment, written by an older version, or the kill it follows was missed)`, h);
    this.gen = st.gen; this.anchors.clear(); this.killing = this.trusted = false; this.resumed = h; this.reported = null; this.held = null;
    return null;
  }
  /** Every call refused while the switch is held (Held): journaled once. */
  private doubt(): string {
    const why = heldReason(this.held!);
    if (why !== this.reported) { this.reported = why; try { this.report?.(why); } catch {} }
    return heldVerdict(this.held!);
  }
  /** Content that is no valid state (corrupt, unsigned or forged): everything stays blocked, so a resume run over it may chain to it, unless a signed kill of this deployment is in force. */
  private refused(why: string, h: string, then?: string): string { if (!this.trusted) this.anchors.add(h); return this.invalid(why, h, then); }
  /** `then`: what lifts it, said after the refusal. */
  private invalid(why: string, h = "", then?: string): string {
    if (`${h}:${why}` !== this.reported) { this.reported = `${h}:${why}`; try { this.report?.(why); } catch {} }
    return `kill switch active: ${basename(this.path)} ${why}, every tool call is refused (fail closed)${then ? `: ${then}` : ""}`;
  }
}

/**
 * What an agent hook started now finds (null: calls go on; else why every call is refused), read without writing anything:
 * kill-switch.json checked against the last kill or resume the audit log records (lastSwitch). For doctor, check, doctor
 * --report and the dashboard. Throws when the audit log cannot be read (hooks then refuse every call).
 */
export function killSwitchState(secret: string, path = killSwitchPath()): string | null {
  const last = lastSwitch(auditPath(), auditKey(secret));
  if (!existsSync(path)) return isHeld(last) ? heldVerdict(last.held) : last?.killed ? "kill switch active" : null;   // no KillSwitch: it would create KYTRAL_HOME
  return new KillSwitch(path, killSwitchKey(secret), undefined, last).check();
}
/** The last kill or resume the default audit log records with this secret's audit key, or a held switch (lastSwitch): what a KillSwitch of an agent hook starts from. */
export const journaledSwitch = (secret: string): SwitchRecord | null => lastSwitch(auditPath(), auditKey(secret));
/**
 * The last kill or resume a guard that starts with no memory begins with (KillSwitch's `last`): an agent hook, an MCP proxy
 * or an SDK guard started after kill-switch.json was deleted or an older resume was put back still finds the kill. The later,
 * by generation, of what its own audit log records (`audit`, when it has a file and a key) and, for the default
 * kill-switch.json, of what the default audit log records (where `kytral-guard kill` and the dashboard journal); each log is
 * read under its lock (lastSwitch). Held when either log's tail marker is in doubt with nothing as recent in that log
 * (laterSwitch). Null when none records one. Throws when a log cannot be read: the guard then does not start (fail closed).
 */
export function startingSwitch(secret: string, killSwitchFile: string, audit?: AuditLog | null): SwitchRecord | null {
  const logs = new Map<string, Buffer>();
  if (audit?.file && audit.key) logs.set(resolve(audit.file), audit.key);
  if (resolve(killSwitchFile) === killSwitchPath() && !logs.has(auditPath())) logs.set(auditPath(), auditKey(secret));
  let last: SwitchRecord | null = null;
  for (const [file, key] of logs) if (existsSync(dirname(file))) last = laterSwitch(last, withFileLock(file, () => lastSwitch(file, key)));
  return last;
}

/**
 * Result of `kytral-guard kill` / `resume`: the state written, the previous one (for a human) and, for a kill, why the lock
 * was skipped, and `warnings`: what went wrong with the audit log (it could not be read, or could not record the kill) or
 * with what kill-switch.json held (content that could not be checked), the kill being written and in force all the same.
 */
export interface KillSwitchChange { state: KillState | UnsignedKill; path: string; was: string; unlocked?: string; warnings?: string[] }
/**
 * What the file holds: for a human (`was`); the generation it proves with this key (its own, or that of the signed state an
 * unsigned kill carries); the signed state an unsigned kill written now carries along (not verified here: Guards verify it);
 * `problem`: what a kill says it replaced, when the file held something that cannot be checked: JSON nested too deep, or no
 * regular file at all (`notFile`, its kind: a FIFO, a device, a folder... never read; a resume refuses it). Never throws.
 */
function current(path: string, key?: Buffer): { gen: number; was: string; digest: string; killed: boolean; last?: KillState; problem?: string; notFile?: string } {
  let buf: Buffer, s: any;
  try { buf = readRegular(path); }
  catch (e: any) {
    if (e instanceof NotRegularFile)
      return { gen: 0, killed: false, digest: "unreadable", was: `unreadable (${readProblem(e)})`, notFile: e.kind, problem: `${basename(path)} was not a regular file (${e.kind}): the kill was written in its place` };
    return { gen: 0, killed: false, digest: e?.code === "ENOENT" ? NO_STATE : "unreadable", was: e?.code === "ENOENT" ? "absent" : e?.code ? `unreadable (${e.code})` : "corrupt" };
  }
  const digest = sha256(buf);
  try { s = JSON.parse(buf.toString("utf8")); } catch { return { gen: 0, digest, killed: false, was: "corrupt" }; }
  if (nestedDeeper(s, STATE_DEPTH))
    return { gen: 0, digest, killed: false, was: "corrupt (JSON nested too deep)", problem: `${basename(path)} held JSON nested too deep to be a state (content built so that checking it fails): the kill was written over it` };
  const signed = (o: any) => !!o && typeof o === "object" && !Array.isArray(o) && typeof o.sig === "string" && flat(o);
  const proven = key ? verified(key, s) ?? verified(key, s?.last) : null;
  const who = typeof s?.by === "string" ? ` by ${s.by}` : "", when = typeof s?.at === "string" ? ` at ${s.at}` : "";
  return { gen: proven?.gen ?? 0, digest, killed: s?.killed === true, last: signed(s) ? s : signed(s?.last) ? s.last : undefined,
    was: s?.killed === true ? `on${who}${when}` : s?.killed === false ? `off${who}${when}` : "corrupt" };
}
/**
 * Id of the deployment of a state file, signed into every state written to it: HMAC, with the states' key, of the file's real
 * path (its directory's real path, links resolved, joined with its name; a link put in place of the file itself is not
 * followed), cut to 32 hex digits. Derived, never stored: there is no file to copy, and computing it needs the secret. The
 * Guard and the writers compute it the same way, so the same file reached through another real path (bind mount, moved
 * directory) has another id: its states are foreign there (fail closed). If the path cannot be resolved, the path as given
 * is used: at worst the ids differ, which only blocks.
 */
function deploymentId(key: Buffer, path: string): string {
  return createHmac("sha256", key).update(`kill-switch/dep\n${realFilePath(path)}`).digest("hex").slice(0, 32);
}
const auditPath = () => statePath(process.env.KYTRAL_AUDIT, "audit.jsonl");
const defaultAudit = (key?: Buffer) => new AuditLog(auditPath(), { key });
const isGeneration = (e: Entry) => (e.decision === "kill" || e.decision === "resume") && validGen(e.generation);
const isChange = (e: Entry) => e.decision === "kill" || e.decision === "resume";
/**
 * What the journal says of the kill switch, read once, as a stream (memory stays flat whatever its size): `floor`, the highest
 * generation journaled by a kill or a resume, which survives a kill-switch.json deleted, corrupt or rolled back (the maximum,
 * not the last line; entries beyond MAX_GENERATION are ignored); `last`, its last kill or resume; `chained`, whether its hash
 * chain is intact (read without a key only). With the audit key (the CLI and the dashboard always have it; so has any AuditLog
 * that carries one) only entries whose MAC verifies count: a line appended without the key, with a huge or a low generation,
 * is skipped, and so are lines written before HMAC chains or without the key. Without a key (an AuditLog built by hand without
 * one) the entries are not authenticated and whoever can append to the log can raise the floor, up to MAX_GENERATION.
 * A log that exists but cannot be read (permissions, a folder in its place, an I/O error): a floor taken from part of it, or
 * from none, could make the generation go back, so `resume` throws (nothing written). A kill is never refused: for it the
 * floor is then the highest known without the whole log, and `unreadable` says why the log was not read (`code`) and what
 * that floor comes from: `read`, the highest generation of the lines read before the error (0: none), and `mark`, the
 * generation the log's signed tail marker records (null: none).
 */
interface Journal {
  floor: number; last?: Pick<Entry, "decision" | "generation" | "state">; chained: boolean;
  /** The highest generation among what `last` is taken from: `last` is used only if it reaches it. */
  lastFloor: number;
  unreadable?: { code: string; read: number; mark: number | null };
  /** The tail marker is not a regular file (its kind): not read. */
  marker?: string;
}
function readJournal(what: "kill" | "resume", audit?: AuditLog, akey?: Buffer): Journal {
  const j: Journal = { floor: 0, lastFloor: 0, chained: true }, chain = akey ? null : chainVerifier();
  // kills and resumes are written with agentId "*": with the key, only those lines are parsed; without it, every line (the chain)
  const hint = akey ? '"agentId":"*"' : "", file = audit ? audit.file : auditPath();
  // With the key, `last` is only ever this log's own (an entry signs the id of the log it was written in): a kill or resume
  // copied in from another log, or written by an older version, raises the floor (generations only grow) but is never what a
  // resume chains to. A log kept in memory has no id: its entries are this process's own.
  const own = akey && file ? tailDep(akey, file) : undefined;
  const visit = (e: Entry) => {
    if (chain && !chain.add(e)) j.chained = false;
    if (!isChange(e) || (akey && !entryAuthentic(akey, e))) return;
    if (isGeneration(e)) j.floor = Math.max(j.floor, e.generation!);
    if (own !== undefined && e.dep !== own) return;
    j.last = e; if (isGeneration(e)) j.lastFloor = Math.max(j.lastFloor, e.generation!);
  };
  const refused = (e: unknown) => new Error(`resume refused: the audit log cannot be read (${readProblem(e)}) and it holds the kill switch's last generation, so nothing was written (a state written without it could go back to an older generation): the kill switch is unchanged. Make the log readable, then run resume again`);
  let unreadable: string | undefined;
  try { if (audit) audit.each(visit, hint); else eachEntry(auditPath(), visit, hint); }
  catch (e) { if (what === "resume") throw refused(e); unreadable = readProblem(e); }
  const read = j.floor;
  // The tail marker's record of the last kill or resume (what agent hooks start from, lastSwitch) counts too: a log cut
  // short, or renamed without its marker, keeps it there, and a state written below it would stay refused by every hook.
  // Only a marker of this log is a record a resume may chain to; the generation of any marker that verifies (another log's,
  // an older version's, a held switch) raises the floor. A marker that cannot be checked (content built to make that fail)
  // refuses a resume, and is no record for a kill; one that is no regular file (a FIFO, a folder...) is never read: a resume
  // refuses it, a kill says so.
  let mark: SwitchMark | null = null, markGen = 0;
  try { if (file && akey) ({ gen: markGen, mark } = tailSwitch(file, akey)); }
  catch (e) {
    if (e instanceof NotRegularFile && what === "resume") throw new Error(`resume refused: the audit log's tail marker is not a regular file (${e.kind}), so nothing was written: the kill switch is unchanged. Remove it (the next entry of the log writes a new one), then run resume again`);
    if (what === "resume") throw refused(e);
    if (e instanceof NotRegularFile) j.marker = e.kind;
  }
  j.floor = Math.max(j.floor, markGen);
  if (mark && mark.gen > j.lastFloor) { j.lastFloor = mark.gen; j.last = { decision: mark.killed ? "kill" : "resume", generation: mark.gen, state: mark.state }; }
  return unreadable === undefined ? j : { ...j, chained: false, unreadable: { code: unreadable, read, mark: markGen || null } };
}
/**
 * Digest of the content a state written now replaces, for its `after`: the file's own when it is a kill. When it is not
 * (deleted, corrupt, or a resume put back over a kill), the kill the journal says is in force, if its last change is a kill,
 * so that a resume run after such a tampering still chains to the kill. The journal only picks what a legitimate writer signs;
 * it never makes a Guard accept anything. The entry is used only if it is trustworthy. With the audit key only entries whose
 * MAC verifies and that this log wrote count (a line appended without the key, forged or edited, or copied in from another
 * log, never steers `after`; a kill written without a secret is journaled without a MAC, so after a deleted file the resume
 * then does not chain to it: it stays refused until the next kill and resume, fail closed), and only if no such entry has a
 * higher generation. Without a key (an AuditLog built by hand) the journal's hash chain must be intact and the entry not
 * below the highest generation journaled; whoever can rewrite such a journal whole can still choose that digest.
 */
function replaced(c: { digest: string; killed: boolean }, j: Journal, akey?: Buffer): string {
  if (c.killed) return c.digest;
  const last = j.last;
  return (akey || j.chained) && last?.decision === "kill" && (last.generation === undefined || (validGen(last.generation) && last.generation >= j.lastFloor)) && isAfter(last.state) ? last.state! : c.digest;
}
const stateDigest = (state: object) => sha256(Buffer.from(JSON.stringify(state, null, 1)));
/** A state signed with the key, one generation after `prev`, bound to this deployment and to the content it replaces. */
function signedState(key: Buffer, killed: boolean, by: string, prev: number, dep: string, after: string): KillState {
  if (prev >= MAX_GENERATION) throw new Error("kill switch: generation overflow");
  const body = { v: 2 as const, killed, gen: prev + 1, at: new Date(Date.now()).toISOString(), by, dep, after };
  return { ...body, sig: sign(key, body) };
}
/**
 * 0600 temp file (created exclusively, under a random name) + atomic rename (writeReplace): it takes the place of a FIFO, a
 * device or a link put there; a folder there is moved aside first, and where it went is added to `moved`.
 */
function write<T extends object>(path: string, state: T, moved: string[] = []): T {
  moved.push(...writeReplace(path, JSON.stringify(state, null, 1)));
  return state;
}

/**
 * `kytral-guard kill`: every proxy and Guard using this file refuses every tool call from its next check, and ends its
 * pending confirmations. With `key` it is signed with the next generation after both the file's and the journal's highest
 * (read first); without one (no usable secret) it is written unsigned, with no generation, and carries the last signed
 * state. Written under the lock; a lock that cannot be taken within 1 s (stuck or hostile process) never stops a kill: it is
 * then written without it, still atomically. Journaled once in force (`kill`, approver = by, its generation), HMAC-chained
 * with `auditKey` when there is one; without it the entry is kept but unauthenticated (`audit verify` flags it).
 * A kill is never refused because of the audit log: one that cannot be read leaves the floor to what is known without it
 * (the log's signed tail marker, the file, the lines read before the error), and one that cannot record the kill leaves it
 * unjournaled; nor because of what kill-switch.json holds: content built so that it cannot be checked is written over, and
 * what is no regular file (a FIFO, a socket, a device, a link to one) is replaced by the rename that puts the kill in place
 * (a folder, which a rename cannot replace, is moved aside first). The kill is written and in force all the same, and
 * `warnings` says what went wrong (the CLI then exits 3).
 */
export function engageKillSwitch(by: string, o: { path?: string; audit?: AuditLog; key?: Buffer; auditKey?: Buffer } = {}): KillSwitchChange {
  const path = resolve(o.path ?? killSwitchPath()); mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const engage = (): KillSwitchChange => {
    const c = current(path, o.key), moved: string[] = [];
    const done = (state: KillState | UnsignedKill, more: string[]): KillSwitchChange => {
      const warnings = [...(c.problem ? [`${c.problem}${moved.length ? ` (the folder was moved aside to ${moved.map(m => basename(m)).join(", ")})` : ""}`] : []), ...more];
      return { state, path, was: c.was, ...(warnings.length ? { warnings } : {}) };
    };
    if (!o.key) return done(write<UnsignedKill>(path, { v: 1, killed: true, at: new Date(Date.now()).toISOString(), by, ...(c.last ? { last: c.last } : {}) }, moved), []);
    // One generation after the file's and the journal's highest (file deleted, corrupt or rolled back: the journal's), so
    // that the generation never goes back; linked to the content it replaces.
    const akey = o.auditKey ?? o.audit?.key, j = readJournal("kill", o.audit, akey);
    const state = write(path, signedState(o.key, true, by, Math.max(c.gen, j.floor), deploymentId(o.key, path), replaced(c, j, akey)), moved);
    const marker = j.marker ? [`the audit log's tail marker was not a regular file (${j.marker}): it was not read, the kill's generation comes from the log`] : [];
    const u = j.unreadable;
    if (!u) return done(state, marker);
    // Without a marker the log may hold a higher generation than what was known: running guards that saw it take this
    // kill for a replay, which blocks every call too (fail closed).
    const known = [`tail marker: ${u.mark ?? "none"}`, `kill-switch.json: ${c.gen || "none"}`, ...(u.read ? [`lines read before the error: ${u.read}`] : [])].join(", ");
    return done(state, [...marker, `the audit log cannot be read (${u.code}): the kill was written all the same, at generation ${state.gen}, one after the highest generation known without the log (${known})`
      + `${u.mark ? "" : "; the log may hold a higher one: running guards that saw it take this kill for a replay, which blocks every call too"}. Make the log readable: 'kytral-guard resume' is refused until then`]);
  };
  let r!: KillSwitchChange, ran = false;
  try { r = withFileLock(path, () => { ran = true; return engage(); }, 1000); }
  catch (e) { if (ran) throw e; r = { ...engage(), unlocked: (e as Error).message }; }
  try { (o.audit ?? defaultAudit(o.auditKey)).append({ agentId: "*", tool: "*", decision: "kill", approver: by, state: stateDigest(r.state), ...("gen" in r.state ? { generation: r.state.gen } : {}) }); }
  catch (e) { r = { ...r, warnings: [...(r.warnings ?? []), `kill switch ON, but the kill could not be journaled: ${(e as Error).message}`] }; }
  return r;
}
/**
 * `kytral-guard resume`: lifts the kill with a resume signed with the proxies' key (they refuse an unsigned or forged one),
 * one generation after both the file's and the journal's highest, so a kill-switch.json deleted, corrupt or rolled back
 * cannot make the generation go back, and chained to the content it replaces (`after`). A journal that cannot be read refuses
 * it, nothing written (readJournal), and so does a kill-switch.json that is no regular file (a FIFO, a device, a folder: never
 * read; every guard refuses every call while it is there). Under the lock, and journaled before it is written: no resume
 * without its audit entry.
 */
export function releaseKillSwitch(secret: string, by: string, o: { path?: string; audit?: AuditLog } = {}): KillSwitchChange {
  const key = killSwitchKey(secret), path = resolve(o.path ?? killSwitchPath()); mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  return withFileLock(path, () => {
    const akey = o.audit ? o.audit.key : auditKey(secret), c = current(path, key);
    if (c.notFile) throw new Error(`resume refused: ${basename(path)} is not a regular file (${c.notFile}), so nothing was written: the kill switch is unchanged (every guard refuses every call while it is there). Remove it, then run resume again`);
    const j = readJournal("resume", o.audit, akey);
    const state = signedState(key, false, by, Math.max(c.gen, j.floor), deploymentId(key, path), replaced(c, j, akey));
    (o.audit ?? defaultAudit(auditKey(secret))).append({ agentId: "*", tool: "*", decision: "resume", approver: by, state: stateDigest(state), generation: state.gen });
    return { state: write(path, state), path, was: c.was };
  });
}
