// Input normalization before policy matching: every string value (and key) of the arguments is decoded
// and canonicalized into several "views"; rules are matched against each view.
const CONFUSABLES: Record<string, string> = {
  "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l",
  "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w", "ζ": "z",
  "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ß": "ss", "ſ": "s",
};
const INVISIBLE = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF]/g;

export function canonical(s: string, keepCase = false): string {
  let t = s.normalize("NFKC").replace(INVISIBLE, "");
  t = t.normalize("NFKD").replace(/\p{M}/gu, "");
  if (!keepCase) t = t.toLowerCase();         // strip accents / combining marks
  t = [...t].map(c => CONFUSABLES[c] ?? c).join("");                       // homoglyphs -> latin
  return t;
}
function urlDecode(s: string): string {
  let t = s;
  for (let i = 0; i < 3 && /%[0-9a-f]{2}/i.test(t); i++) { try { t = decodeURIComponent(t); } catch { t = t.replace(/%([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))); } }
  return t.replace(/\+/g, " ");
}
function base64Views(s: string): string[] {
  const out: string[] = [];
  for (const tok of s.match(/[A-Za-z0-9+/_-]{12,}={0,2}/g) ?? []) {
    const d = Buffer.from(tok, /[-_]/.test(tok) ? "base64url" : "base64").toString("utf8");
    if (d && !d.includes("\uFFFD") && /^[\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]+$/.test(d) && /[a-z]{2}/i.test(d)) out.push(d);
  }
  return out;
}
/**
 * SQL without its comments (/* … *\/, -- …, # …): strings are copied as they are, so '#ff0000' and 'a--b' are not read as
 * comments. One pass. The canonical view only adds what the raw text hides; the raw text is always analyzed too.
 * `backslash`: a backslash escapes a quote inside a string, as in MySQL; in standard SQL (PostgreSQL, SQLite, SQL Server)
 * 'a\' is a whole string. Both readings are analyzed (sqlCanonicals): each could hide a statement from the other.
 */
function withoutSqlComments(s: string, backslash: boolean): string {
  let out = "", i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === "'" || c === '"' || c === "`") {
      let j = i + 1;
      while (j < s.length && !(s[j] === c && s[j + 1] !== c)) j += s[j] === c || (backslash && s[j] === "\\" && c !== "`") ? 2 : 1;
      out += s.slice(i, j + 1); i = j + 1; continue;
    }
    if (c === "/" && s[i + 1] === "*") { const e = s.indexOf("*/", i + 2); out += " "; i = e < 0 ? s.length : e + 2; continue; }
    if ((c === "-" && s[i + 1] === "-") || c === "#") { const e = s.indexOf("\n", i); out += " "; i = e < 0 ? s.length : e; continue; }
    out += c; i++;
  }
  return out;
}
/** SQL-oriented canonicalization: comments, CHAR()/hex literals, string concatenation (standard SQL strings). */
export function sqlCanonical(s: string, backslash = false): string {
  let t = withoutSqlComments(s, backslash);
  t = t.replace(/\b(?:n?char|chr)\s*\(([\d\s,]+)\)/gi, (_, l: string) => "'" + l.split(",").map(n => String.fromCharCode(Number(n.trim()))).join("") + "'");
  t = t.replace(/\b0x([0-9a-f]{4,})\b/gi, (m, h: string) => { const d = Buffer.from(h.length % 2 ? "0" + h : h, "hex").toString("latin1"); return /^[\x20-\x7E]+$/.test(d) ? "'" + d + "'" : m; });
  // concat('DR', 'OP') of strings only (also "DR", "OP": strings in MySQL and BigQuery): one string. A comma elsewhere
  // separates values: VALUES ('a', 'b') stays as it is.
  t = t.replace(/\bconcat\s*\(\s*((?:'[^']*'\s*,\s*)*'[^']*')\s*\)/gi, (_, l: string) => l.replace(/'\s*,\s*'/g, ""));
  t = t.replace(/\bconcat\s*\(\s*((?:"[^"]*"\s*,\s*)*"[^"]*")\s*\)/gi, (_, l: string) => l.replace(/"\s*,\s*"/g, ""));
  t = t.replace(/(['"])\s*(?:\+|\|\|)\s*\1/g, "");                        // 'DR'+'OP'  'DR'||'OP'
  t = t.replace(/\bconcat\s*\(/gi, "(");
  return t;
}
/** Both canonical readings of SQL: standard strings ('a\' is whole) and MySQL strings (a backslash escapes the quote). */
export function sqlCanonicals(s: string): string[] {
  const std = sqlCanonical(s), my = s.includes("\\") ? sqlCanonical(s, true) : std;
  return my === std ? [std] : [std, my];
}
/** Shell-oriented canonicalization: line continuations, empty quotes, $IFS, $(echo x)/`echo x`, escapes. */
export function shellCanonical(s: string): string {
  let t = s.replace(/\\\r?\n/g, " ");
  t = t.replace(/\$\{?ifs\}?/gi, " ");
  t = t.replace(/\$\(\s*(?:echo|printf)\s+(['"]?)([^)'"]*)\1\s*\)/gi, "$2").replace(/`\s*(?:echo|printf)\s+(['"]?)([^`'"]*)\1\s*`/gi, "$2");
  t = t.replace(/(['"])\1/g, "").replace(/\\([a-z\-\/])/gi, "$1");
  return t;
}
const squash = (s: string) => s.replace(/\s+/g, " ").trim();

/** All views of one string: raw, canonical, url-decoded, base64-decoded, sql-canonical, whitespace-squashed. */
/** Decoded variants of a raw string: itself, URL-decoded, base64-decoded tokens. */
export function seedsOf(s: string): string[] { return [...new Set([s, urlDecode(s), ...base64Views(s)])]; }
export function views(s: string): string[] {
  const set = new Set<string>();
  const seeds = seedsOf(s);
  for (const seed of seeds) {
    const c = canonical(seed);
    for (const v of [seed, c, ...sqlCanonicals(c), shellCanonical(c)]) { set.add(v); set.add(squash(v)); }
  }
  return [...set];
}
/** Recursively collects every string, number and key of the arguments. */
export function collectStrings(v: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 32) return out;
  if (typeof v === "string") out.push(v);
  else if (typeof v === "number" || typeof v === "boolean") out.push(String(v));
  else if (Array.isArray(v)) v.forEach(x => collectStrings(x, out, depth + 1));
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) { out.push(k); collectStrings(x, out, depth + 1); }
  return out;
}
export function argViews(args: unknown): string[] {
  const set = new Set<string>();
  for (const s of collectStrings(args)) for (const v of views(s)) set.add(v);
  try { set.add(JSON.stringify(args ?? {})); } catch {}                    // backward compat with JSON-text rules
  return [...set];
}
