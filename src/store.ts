// Small persistent string sets (revocations, consumed nonces), shared between proxy processes via a JSON file.
// Paths are always absolute; re-read when the file changes; writes are done under an inter-process lock
// (O_EXCL lock file) with read-modify-write and an atomic rename, so concurrent revocations are never lost.
import { closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, statSync, unlinkSync, writeFileSync, writeSync, type Stats } from "node:fs";
import { homedir } from "node:os";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

/** Directory for Kytral Guard state: $KYTRAL_HOME, else ~/.kytral (absolute). */
export function stateDir(): string { return resolve(process.env.KYTRAL_HOME || join(homedir(), ".kytral")); }
/** Absolute path for a state file: explicit value (resolved against cwd) or <stateDir>/<name>. */
export function statePath(explicit: string | undefined, name: string): string {
  const p = explicit ? resolve(explicit) : join(stateDir(), name);
  if (!isAbsolute(p)) throw new Error(`state path must be absolute: ${p}`);
  return p;
}

const sha256 = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const sleep = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
/** Windows reports a file held open by another process (a reader, an antivirus) or being deleted as EPERM/EACCES/EBUSY: transient. */
const winBusy = (e: any) => process.platform === "win32" && ["EPERM", "EACCES", "EBUSY"].includes(e?.code);
/** readFileSync that retries briefly on Windows while another process is replacing the file. */
export function readFileRetry(path: string): Buffer {
  for (let i = 0; ; i++) {
    try { return readFileSync(path); }
    catch (e) { if (!winBusy(e) || i >= 40) throw e; sleep(5 + 2 * i); }
  }
}
/** A file descriptor to read the file with, retrying briefly like readFileRetry while Windows holds the file. */
export function openRetry(path: string): number {
  for (let i = 0; ; i++) {
    try { return openSync(path, "r"); }
    catch (e) { if (!winBusy(e) || i >= 40) throw e; sleep(5 + 2 * i); }
  }
}
/** Atomic replace by rename; on Windows, retries briefly while the target is held open, then removes the temp file and throws. */
export function renameReplace(from: string, to: string) {
  for (let i = 0; ; i++) {
    try { renameSync(from, to); return; }
    catch (e) { if (!winBusy(e) || i >= 40) { try { unlinkSync(from); } catch {} throw e; } sleep(5 + 2 * i); }
  }
}

/** What a path holds when it is not a regular file, said in a message. */
const kindOf = (s: Stats) => s.isDirectory() ? "a folder" : s.isFIFO() ? "a FIFO" : s.isSocket() ? "a socket" : s.isCharacterDevice() || s.isBlockDevice() ? "a device" : "not a file";
/**
 * A path that holds something other than a regular file: a FIFO (opening it waits for a writer), a socket, a device (it can
 * be read forever), a folder. Such a path is never read. `code`: EISDIR for a folder, as Node says it; else EFTYPE.
 */
export class NotRegularFile extends Error {
  readonly code: string;
  constructor(readonly path: string, readonly kind: string) { super(`${path} is not a regular file (${kind})`); this.code = kind === "a folder" ? "EISDIR" : "EFTYPE"; }
}
/** Why a file could not be read, for a message: its error code (ENOENT, EACCES, EISDIR...), or what it is when it is not a regular file. */
export const readProblem = (e: unknown): string => e instanceof NotRegularFile && e.code === "EFTYPE" ? `not a regular file: ${e.kind}` : (e as NodeJS.ErrnoException)?.code ?? "error";
/** Throws NotRegularFile unless `path` (what it points to, for a link) is a regular file; checked without opening it. Missing: ENOENT. */
export function assertRegular(path: string): void {
  const l = lstatSync(path), s = l.isSymbolicLink() ? statSync(path) : l;
  if (!s.isFile()) throw new NotRegularFile(path, kindOf(s));
}
const NONBLOCK = constants.O_NONBLOCK ?? 0;   // none on Windows, whose named pipes are not in the file system
/**
 * A descriptor of a regular file, obtained without ever waiting: the type is checked before the open (lstat, and what a link
 * points to), the open does not wait (O_NONBLOCK: a FIFO put in place meanwhile cannot hold it), and the type is checked
 * again on what was opened (fstat). Anything but a regular file throws NotRegularFile; other errors (ENOENT...) are thrown as
 * they are. `flags`: read only by default; with O_CREAT (an append), a missing file is created (0600). Retries briefly while
 * Windows holds the file.
 */
export function openRegular(path: string, flags: number = constants.O_RDONLY): number {
  for (let i = 0; ; i++) {
    try {
      try { assertRegular(path); } catch (e) { if (!(flags & constants.O_CREAT) || (e as NodeJS.ErrnoException)?.code !== "ENOENT") throw e; }
      const fd = openSync(path, flags | NONBLOCK, 0o600);
      try { const s = fstatSync(fd); if (!s.isFile()) throw new NotRegularFile(path, kindOf(s)); } catch (e) { closeSync(fd); throw e; }
      return fd;
    } catch (e) { if (!winBusy(e) || i >= 40) throw e; sleep(5 + 2 * i); }
  }
}
/** The bytes of a regular file, read without ever waiting (openRegular): a FIFO, a device, a folder... throws NotRegularFile. */
export function readRegular(path: string): Buffer {
  const fd = openRegular(path);
  try { return readFileSync(fd); } finally { closeSync(fd); }
}
/** Appends to a regular file, created if missing (0600), without ever waiting (openRegular). */
export function appendRegular(path: string, data: string): void {
  const fd = openRegular(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT);
  try { writeFileSync(fd, data); } finally { closeSync(fd); }
}
/**
 * Replaces `path` with `data`, atomically: written to a temp file next to it, created under a random name and exclusively
 * (0600: nothing planted there, a FIFO or a link, is ever opened or followed), then renamed in place. A rename replaces a
 * FIFO, a socket, a device or a link put in place of the file; a folder, which it cannot replace, is first moved aside to
 * `<path>.<random>.moved-aside`. Returns where such folders went.
 */
export function writeReplace(path: string, data: string): string[] {
  const moved: string[] = [], isFolder = () => { try { return lstatSync(path).isDirectory(); } catch { return false; } };
  for (let attempt = 0; ; attempt++) {
    const tmp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(tmp, data, { mode: 0o600, flag: "wx" });
    try {
      if (isFolder()) { const aside = `${path}.${randomBytes(4).toString("hex")}.moved-aside`; renameSync(path, aside); moved.push(aside); }
      renameReplace(tmp, path);
      return moved;
    } catch (e) { try { unlinkSync(tmp); } catch {} if (attempt >= 2 || !isFolder()) throw e; }
  }
}
export function withFileLock<T>(path: string, fn: () => T, timeoutMs = 5000, staleMs = 10000): T {
  const lock = `${path}.lock`; const t0 = Date.now();
  for (;;) {
    try { const fd = openSync(lock, "wx", 0o600); writeSync(fd, String(process.pid)); closeSync(fd); break; }
    catch (e: any) {
      if (e.code !== "EEXIST" && !winBusy(e)) throw e;
      try { if (Date.now() - statSync(lock).mtimeMs > staleMs) { unlinkSync(lock); continue; } } catch {}
      if (Date.now() - t0 > timeoutMs) throw new Error(`lock timeout on ${lock}`);
      sleep(5 + Math.random() * 10);
    }
  }
  try { return fn(); } finally { try { unlinkSync(lock); } catch {} }
}

/**
 * The real path of a file, from which the deployment ids of kill-switch.json and of an audit log's tail marker are derived: its
 * directory's real path (links resolved) joined with its name (a link put in place of the file itself is not followed). The
 * path as given when it cannot be resolved: at worst the ids differ, which only blocks.
 */
export function realFilePath(path: string): string {
  try { return join(realpathSync(dirname(path)), basename(path)); } catch { return path; }
}
/** Derives a per-domain HMAC key from a root secret (HMAC with a domain label), e.g. "kytral-guard/known-tools/v1". */
export function deriveKey(root: string, domain: string): Buffer { return createHmac("sha256", root).update(`kytral-guard:derive:${domain}`).digest(); }

export interface FileSetOptions {
  /** Sign every entry (HMAC over key+value with this derived key). Entries whose signature fails are dropped and reported. */
  signKey?: Buffer;
  /** Called once per rejected entry, each time a changed file is loaded. */
  onReject?: (key: string, why: string) => void;
  /** File deleted while running: "clear" forgets in-memory entries (grants), "keep" keeps the last known state (restrictions). */
  onMissing?: "clear" | "keep";
  /** Never forget an entry seen by this process (revocations): a rewritten/truncated file cannot remove entries already known. */
  monotonic?: boolean;
  /** Do not throw on a corrupt file at construction; refuse on each access instead. */
  lazyCorrupt?: boolean;
  /**
   * Grants: an unparsable or invalid file holds no entry (fail closed) instead of throwing, and is reported once per content
   * change; writes refuse to replace it (fix or delete the file). Combined with lazyCorrupt, construction never throws either.
   */
  onCorrupt?: (why: string) => void;
}
export interface StringSet { has(x: string): boolean; add(x: string): void }
export class FileSet implements StringSet {
  private data = new Map<string, string>(); private digest: string | null = null;   // sha256 of the content last loaded (null = no file seen)
  /** The file exists but cannot be used (only with onCorrupt). */
  corrupt = false;
  readonly path: string | null;
  constructor(path: string | null, private opts: FileSetOptions = {}) {
    this.path = path === null ? null : resolve(path);
    if (this.path) mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    // Corrupt file: throws at construction by default (proxy refuses to start). With lazyCorrupt, construction succeeds
    // and every access re-reads and throws instead (fail closed per call); with onCorrupt as well, it holds no entry (grants).
    if (this.opts.lazyCorrupt) { try { this.reload(); } catch {} } else this.reload();
  }
  private sig(k: string, v: string) { return createHmac("sha256", this.opts.signKey!).update(JSON.stringify([k, v])).digest("base64url"); }
  private seal(k: string, v: string): string { return this.opts.signKey ? JSON.stringify({ v, sig: this.sig(k, v) }) : v; }
  private verify(k: string, raw: unknown): string | null {
    if (!this.opts.signKey) return typeof raw === "string" ? raw : JSON.stringify(raw);
    try {
      const o = typeof raw === "string" ? JSON.parse(raw) : raw;
      if (!o || typeof o.v !== "string" || typeof o.sig !== "string") return null;
      const a = Buffer.from(o.sig), b = Buffer.from(this.sig(k, o.v));
      return a.length === b.length && timingSafeEqual(a, b) ? o.v : null;
    } catch { return null; }
  }
  private reload(force = false) {
    if (!this.path) return;
    if (!existsSync(this.path)) {
      if (this.digest !== null && (this.opts.onMissing ?? "keep") === "clear" && !this.opts.monotonic) this.data = new Map();
      this.digest = null; this.corrupt = false; return;
    }
    // Reload decided on a hash of the content, not on mtime/size/inode (an in-place write with restored mtime is seen).
    // Read without ever waiting: a FIFO, a device or a folder in its place throws (NotRegularFile), as an unreadable file does.
    const buf = readRegular(this.path); const h = sha256(buf);
    if (h === this.digest && !force) return;
    let raw: any;
    try {
      raw = JSON.parse(buf.toString("utf8"));                      // corrupt file => throw, or no entry with onCorrupt (fail closed)
      if (!raw || typeof raw !== "object") throw new Error("not a JSON object or array");
    } catch (e) {
      if (!this.opts.onCorrupt) throw e;
      if (!this.opts.monotonic) this.data = new Map();             // a corrupt grant file grants nothing
      this.corrupt = true; this.digest = h;                         // reported once per content change
      this.opts.onCorrupt((e as Error).message); return;
    }
    this.corrupt = false;
    const fresh = new Map<string, string>();
    for (const [k, v] of Array.isArray(raw) ? raw.map((k: string) => [k, ""] as [string, unknown]) : Object.entries(raw)) {
      if (this.opts.signKey) { const ok = this.verify(k, v); if (ok === null) { this.opts.onReject?.(k, "bad signature"); continue; } }
      fresh.set(k, v as string);
    }
    if (this.opts.monotonic) for (const [k, v] of this.data) if (!fresh.has(k)) fresh.set(k, v);
    this.data = fresh; this.digest = h;
  }
  get(x: string) { this.reload(); const r = this.data.get(x); return r === undefined ? undefined : this.opts.signKey ? this.verify(x, r) ?? undefined : r; }
  has(x: string) { this.reload(); return this.data.has(x); }
  entries(): [string, string][] { this.reload(); return [...this.data.entries()].map(([k, r]) => [k, this.opts.signKey ? this.verify(k, r) ?? "" : r]); }
  /** Under the lock: re-reads the file, applies `change` to the entries, writes them back (0600 temp file + atomic rename). */
  private update<T>(change: () => T): T {
    if (!this.path) return change();
    const path = this.path;
    return withFileLock(path, () => {
      this.reload(true);
      if (this.corrupt) throw new Error(`${path} is corrupt: fix or delete it`);
      const r = change();
      const body = JSON.stringify(Object.fromEntries(this.data), null, 1);
      writeReplace(path, body);
      this.digest = sha256(Buffer.from(body));   // what was written: any later change, by anyone, is reloaded
      return r;
    });
  }
  /** Removes an entry (under the same inter-process lock). Returns true if it existed. */
  remove(x: string): boolean { return this.removeWhere(k => k === x).length > 0; }
  /** Removes every entry whose key matches, in one locked read-modify-write. Returns the removed keys. */
  removeWhere(match: (key: string) => boolean): string[] {
    if (this.opts.monotonic) throw new Error("cannot remove from a monotonic set");   // before touching memory
    return this.update(() => { const keys = [...this.data.keys()].filter(match); for (const k of keys) this.data.delete(k); return keys; });
  }
  add(x: string, v = new Date().toISOString()) { this.update(() => { this.data.set(x, this.seal(x, v)); }); }
}
