// The text of the calls that were refused or needed a human, kept apart from the audit log (which never stores arguments),
// so that the dashboard can show what an agent tried and turn it into an exception. Passwords, tokens and keys are masked
// before anything is written, only about the last thousand calls are kept, and it can be turned off ("keepCalls": false in
// $KYTRAL_HOME/config.json, or KYTRAL_KEEP_CALLS=0). Keeping a text never changes a decision: keepCall does not throw.
// Every kept call is signed for its file (keptCallsKey): only a text the guard of this home kept can become an exception
// (`kytral-guard allow --call`, the dashboard); one copied from another home, edited or forged is not read.
import { createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, statSync, unlinkSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { canonicalJson } from "./confirm-queue.js";
import { guardConfig } from "./plugins.js";
import { assertAuditSecret, assertStrongSecret, resolveSecret } from "./secret.js";
import { appendRegular, deriveKey, readRegular, realFilePath, statePath, withFileLock, writeReplace } from "./store.js";

export interface KeptCall {
  v: 1;
  /** seq of the audit entry written for the same decision (absent when that entry has none). */
  seq?: number;
  ts: string; agent: string; tool: string; decision: string; rule?: string;
  /** The finding behind the decision, masked. */
  reason?: string;
  /** The command, the file, the SQL or the arguments of the call, masked and cut to TEXT_MAX characters. */
  text: string;
  /** Working directory (hooks) or MCP server key (proxy). */
  cwd?: string;
  /** HMAC of every other field (canonical JSON) with the key of its file (keptCallsKey). */
  mac: string;
}
export const keptCallsPath = () => statePath(process.env.KYTRAL_KEPT_CALLS, "kept-calls.jsonl");
/**
 * Signing key of the kept calls of the file `file`: from KYTRAL_AUDIT_SECRET if set, else the deployment secret (same
 * strong-secret rule as the Guard), bound to the file's real path (realFilePath), as kill-switch.json's id is: a kept call
 * signed for one file never verifies in another (copied from another KYTRAL_HOME using the same secret, or this one reached
 * through another path), and neither does one an older version kept, unsigned.
 */
export const keptCallsKey = (secret: string, file: string) =>
  createHmac("sha256", deriveKey(assertAuditSecret() ?? assertStrongSecret(secret), "kept-calls/v1")).update(`kept-calls/dep\n${realFilePath(resolve(file))}`).digest();
const keptMac = (key: Buffer, body: Omit<KeptCall, "mac">) => createHmac("sha256", key).update(`kept-call\n${canonicalJson(body)}`).digest("base64url");
const sameMac = (a: unknown, b: string) => typeof a === "string" && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
/** The deployment secret, when none is given: KYTRAL_SECRET, else $KYTRAL_HOME/secret (resolveSecret); missing, it is refused. */
const theSecret = (secret?: string) => assertStrongSecret(secret ?? resolveSecret());
/** Calls kept at most after a trim (the file is trimmed when it grows past TRIM_BYTES). */
export const KEPT_MAX = 1000;
const TRIM_BYTES = 256 * 1024;
const TEXT_MAX = 4000;
export const MASK = "••••••";
/**
 * Control characters, and the invisible ones that change how a text reads (bidirectional overrides, zero-width
 * characters): an exception is refused for a command that holds one, since it can look like another command.
 */
export const HIDDEN_CHARACTERS = /[\u0000-\u0008\u000a-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;
/** The kept text is the command as it ran: nothing masked, nothing cut, no hidden character. Only such a text makes an exception. */
export const exactText = (text: string) => !text.includes(MASK) && !text.endsWith("…") && !HIDDEN_CHARACTERS.test(text);

/** Keep the text of refused and confirmed calls? KYTRAL_KEEP_CALLS=0|1, else "keepCalls" in config.json, else yes. */
export function keepCallsEnabled(): boolean {
  const env = process.env.KYTRAL_KEEP_CALLS;
  if (env === "0" || env === "1") return env === "1";
  try { return guardConfig().keepCalls ?? true; } catch { return false; }
}
/** Journal the calls agent hooks allow? KYTRAL_AUDIT_ALLOWS=0 says no; else "auditAllows" in config.json, else yes. */
export function auditAllowsEnabled(): boolean {
  if (process.env.KYTRAL_AUDIT_ALLOWS === "0") return false;
  try { return guardConfig().auditAllows ?? true; } catch { return true; }
}

// Every pattern here takes a time linear in the text, whatever the text: no two quantifiers in a row can match the same
// characters. Hooks mask the calls they keep before they answer, so a text built to make a regular expression backtrack
// would otherwise hold the answer back past the agent's hook timeout (and some agents run the tool then).
const NAMES = String.raw`password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credentials?|client[_-]?secret|session|cookie`;
/** A word that names a secret (DB_PASSWORD, apiKey, x-api-key, aws_secret_access_key), an option (--db-pass), a JSON key. */
const NAMED = new RegExp(NAMES, "i"), OPTION_NAMED = new RegExp(String.raw`${NAMES}|pass`, "i"), KEY_NAMED = new RegExp(String.raw`${NAMES}|authorization`, "i");
/** After such a word: `= value` or `: value` (4 characters or more: max_tokens=100 stays), the value of an option, a JSON string, a long token. */
const ASSIGNED = /(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s;&|"',}]{4,})/y;
const OPTION_VALUE = /(=|\s+)("[^"]*"|'[^']*'|[^\s;&|]+)/y;
const JSON_STRING = /(\s*:\s*)("(?:[^"\\]|\\.)*")/y;
const LONG_TOKEN = /(\s+)([A-Za-z0-9\/+=_.-]{16,})/y;
const at = (re: RegExp, text: string, i: number) => { re.lastIndex = i; return re.exec(text); };
/**
 * --password=x, --db-pass "x", DB_PASSWORD=x, export GITHUB_TOKEN="x", api_key: x, "password": "x", aws configure set
 * aws_secret_access_key <long token>: the values of the words that name a secret. One pass over the words of the text
 * (a pattern looking for a name inside longer words backtracks for seconds on a few thousand characters). A value already
 * masked is left as it is: the rest of a URL stays readable.
 */
function maskNamedValues(text: string): string {
  let out = "", last = 0;
  const words = /[A-Za-z0-9_.-]+/g;
  for (let m: RegExpExecArray | null; (m = words.exec(text)); ) {
    const word = m[0], end = m.index + word.length;
    let v: RegExpExecArray | null = null, from = end, json = false;
    if (text[m.index - 1] === '"' && text[end] === '"' && KEY_NAMED.test(word)) { from = end + 1; v = at(JSON_STRING, text, from); json = !!v; v ??= at(ASSIGNED, text, from); }
    else if (word.startsWith("-")) { if (OPTION_NAMED.test(word)) v = at(OPTION_VALUE, text, end); }
    else if (NAMED.test(word)) v = at(ASSIGNED, text, end) ?? at(LONG_TOKEN, text, end);
    if (!v) continue;
    const start = from + v[1].length, stop = from + v[0].length;
    if (text.startsWith(MASK, start)) continue;
    out += text.slice(last, start) + (json ? `"${MASK}"` : MASK);
    last = stop; words.lastIndex = stop;
  }
  return out + text.slice(last);
}
/** Masks, in order: private keys, URL credentials, Authorization headers, named secrets, known token shapes, passwords of known commands. */
const SECRETS: [RegExp, string][] = [
  [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g, `-----BEGIN PRIVATE KEY----- ${MASK}`],
  // scheme://user:password@host, scheme://:password@host (redis), a password holding an @
  [/\b([a-z][a-z0-9+.-]{1,20}:\/\/)([^\s:@\/'"]{0,200}):([^\s\/'"]{1,400})@/gi, `$1$2:${MASK}@`],
  [/\b(authorization\s*[:=][\s"']*(?:(?:bearer|basic|token|digest)\s+)?)[^\s"',;]{4,}/gi, `$1${MASK}`],
];
const TOKENS = /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[abposr]-[A-Za-z0-9-]{10,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|A[KS]IA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30,}|eyJ[A-Za-z0-9_-]{8,2000}\.[A-Za-z0-9_-]{8,2000}\.[A-Za-z0-9_-]{8,})/g;
/** Passwords given to known commands: mysql -pS3cret, sshpass -p x, redis-cli -a x, docker login -p x, curl -u user:x. */
const COMMAND_PASSWORDS: RegExp[] = [
  /(\b(?:mysql|mysqladmin|mysqldump|mariadb)\S{0,40}\s(?:[^|;&\n]{0,2000}\s)?-p)([^\s-]\S*)/g,
  /(\bsshpass\b[^|;&\n]{0,2000}?\s-p\s*)(\S+)/g,
  /(\bredis-cli\b[^|;&\n]{0,2000}?\s-a\s+)(\S+)/g,
  /(\bdocker\s+login\b[^|;&\n]{0,2000}?\s-p\s+)(\S+)/g,
  /(\bcurl\b[^|;&\n]{0,2000}?\s(?:-u|--user)(?:\s+|=)["']?[^\s:"']{0,200}:)([^\s"';&|]+)/g,
];
/** The text with the passwords, tokens and keys it shows replaced by ••••••. */
export function maskSecrets(text: string): string {
  let out = text;
  for (const [re, by] of SECRETS) out = out.replace(re, by);
  out = maskNamedValues(out).replace(TOKENS, MASK);
  for (const re of COMMAND_PASSWORDS) out = out.replace(re, (all, opt: string, value: string) => value.startsWith(MASK) ? all : opt + MASK);
  return out;
}

const PATH_FIELDS = ["file_path", "filePath", "path", "target_file", "notebook_path", "absolute_path", "file"];
const SQL_FIELDS = ["sql", "query", "statement"];
/** What a person reads of a call: its command, else the file it touches, else its SQL, else its arguments (JSON). Masked and cut. */
export function callText(_tool: string, args: Record<string, unknown>): string {
  const a = args ?? {}, cmd = a.command;
  const field = (names: string[]) => names.map(k => a[k]).find((v): v is string => typeof v === "string" && v.trim() !== "");
  let text: string;
  if (typeof cmd === "string") text = cmd;
  else if (Array.isArray(cmd) && cmd.every(x => typeof x === "string")) text = cmd.join(" ");
  else text = field(PATH_FIELDS) ?? field(SQL_FIELDS) ?? canonicalJson(a);
  // cut before masking (a call can be megabytes long), with a margin so that a secret at the cut is still recognized
  const long = text.length > TEXT_MAX;
  text = maskSecrets(long ? text.slice(0, TEXT_MAX + 400) : text);
  return long || text.length > TEXT_MAX ? `${text.slice(0, TEXT_MAX)}…` : text;
}

/**
 * Keeps the text of one call, signed for the file (keptCallsKey, with `secret`, else the deployment's), and returns what was
 * kept. Best effort: an error is ignored, the decision stands. `path`: the file, keptCallsPath() by default.
 */
export function keepCall(c: { seq?: number; ts?: string; agent: string; tool: string; decision: string; rule?: string; reason?: string; args: Record<string, unknown>; cwd?: string },
  secret?: string, path = keptCallsPath()): KeptCall | undefined {
  try {
    const body: Omit<KeptCall, "mac"> = { v: 1, ...(c.seq !== undefined ? { seq: c.seq } : {}), ts: c.ts ?? new Date().toISOString(), agent: c.agent, tool: c.tool,
      decision: c.decision, ...(c.rule ? { rule: c.rule } : {}), ...(c.reason ? { reason: maskSecrets(c.reason.slice(0, 900)).slice(0, 500) } : {}),
      text: callText(c.tool, c.args), ...(c.cwd ? { cwd: c.cwd } : {}) };
    const root = theSecret(secret);   // no usable secret: nothing is kept, and no folder created
    // the folder before the key: the key is bound to the folder's real path (keptCallsKey), which only a folder that exists
    // has; derived from the path as given, it would differ wherever a link leads there (/var on macOS), and no reader would
    // ever verify the call
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const entry: KeptCall = { ...body, mac: keptMac(keptCallsKey(root, path), body) };
    // agent hooks keep the calls they refuse: nothing here may wait (a FIFO in place of the file is refused, not opened)
    withFileLock(path, () => {
      appendRegular(path, JSON.stringify(entry) + "\n");
      if (statSync(path).size <= TRIM_BYTES) return;
      const lines = readRegular(path).toString("utf8").split("\n").filter(Boolean).slice(-KEPT_MAX);
      writeReplace(path, lines.join("\n") + "\n");
    }, 2000);
    return entry;
  } catch { return undefined; /* the decision does not depend on it */ }
}
/**
 * The kept calls whose signature verifies for the file (keptCallsKey, with `secret`, else the deployment's: missing, it
 * throws), oldest first. Lines that do not parse or do not verify (copied from another home, edited, forged, or kept unsigned
 * by an older version) are skipped. `path`: the file, keptCallsPath() by default.
 */
export function readKeptCalls(secret?: string, path = keptCallsPath()): KeptCall[] {
  const key = keptCallsKey(theSecret(secret), path);
  if (!existsSync(path)) return [];
  const out: KeptCall[] = [];
  for (const line of readRegular(path).toString("utf8").split("\n")) {
    if (!line) continue;
    try {
      const e = JSON.parse(line), { mac, ...body } = e ?? {};
      if (e && e.v === 1 && typeof e.text === "string" && typeof e.ts === "string" && sameMac(mac, keptMac(key, body))) out.push(e);
    } catch { /* skipped */ }
  }
  return out;
}
/** Deletes every kept text (the audit log is not touched). */
export function forgetKeptCalls(): void {
  const path = keptCallsPath();
  withFileLock(path, () => { try { unlinkSync(path); } catch (e: any) { if (e.code !== "ENOENT") throw e; } });
}
