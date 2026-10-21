// Structural analysis of arguments: a real SQL parser (node-sql-parser) and a shell tokenizer (shell-quote).
// Regex rules stay as a safety net; these analyzers decide on the AST / argv instead of on text patterns.
// Principle: what can be resolved statically is decided (allow/block); what cannot (placeholders, variables,
// aliases, scripts read from stdin, procedure calls, unparseable input) goes to human confirmation.
// Shell findings carry a severity: "catastrophic" (broad and irreversible: rm -rf ~, terraform destroy, DROP DATABASE via
// psql, kubectl delete namespace) is a subset of "destructive" (scoped data loss: rm -rf src, git reset --hard).
import { parse as shellParse } from "shell-quote";
import { collectStrings, seedsOf, canonical, sqlCanonicals } from "./normalize.js";
import { CLEANUP_NAMES, VAR, unq, sensitivePath, criticalPath, broadPath, deletionSeverity, Severity } from "./paths.js";
import { catalogFinding, clientSql, inCatalog, positionals, optValues, SQL_CLIENTS_READ } from "./catalog.js";
import { join } from "node:path";
import { analyzeWindows, looksWindows } from "./windows.js";
import { changeScriptDir, gitHooksDir, inScript, justRecipes, makeRecipes, packageScripts, programImports, readScript, restoreScriptDir, scriptDir, scriptLanguage, shownPath, taskCommands, withoutScripts } from "./scripts.js";
export { sensitivePath, broadPath, cleanupPath, deletionSeverity } from "./paths.js";

// ================= SQL =================
// The parser and the verdicts on syntax trees live in sql.ts; parsing runs with a deadline (sql-bounded.ts).
import { DEFAULT_SQL_DIALECT, type SqlVerdict } from "./sql.js";
import { parseSqlBounded } from "./sql-bounded.js";
export { SQL_DIALECTS, DEFAULT_SQL_DIALECT, restrictiveness, restrictive, type SqlVerdict } from "./sql.js";

// SQL-shaped statement heads (avoid treating prose like "delete the old files" as SQL).
const HEAD = String.raw`(?:delete\s+(?:from\b|[\w."\x60\[\]]+\s+from\b)|update\s+[\w."\x60\[\]]+(?:\s+(?:as\s+)?\w+)?\s+set\b|insert\s+overwrite\b|insert\s+into\s+[\w."\x60\[\]]+\s*(?:\(|values\b|select\b|default\b|;|$)|replace\s+into\s+[\w."\x60\[\]]+\s*(?:\(|values\b|select\b|;|$)|merge\s+into\s+[\w."\x60\[\]]+(?:\s+(?:as\s+)?\w+)?\s+using\b|upsert\s+into\b|call\s+[\w.]+\s*\(|exec(?:ute)?\s+[\w.]+\s*(?:\(|;|$|@|')|copy\s+[\w."]+\s*(?:\([^)]*\)\s*)?(?:from|to)\b|(?:grant|revoke)\s+(?:all|select|insert|update|delete|usage|execute|create|connect|references|trigger|truncate|temporary|alter|drop|maintain)\b[^;]{0,20000}?\s(?:on|to|from)\b|alter\s+(?:table|database|schema|view|index|user|role|sequence)\b|truncate\s+(?:table\s+)?[\w."]+\s*(?:;|$)|drop\s+(?:table|database|schema|view|index|user|role|function|procedure|trigger)\b)`;
const EXPLAIN = String.raw`(?:explain\s+(?:\([^)]*\)\s*)?(?:analy[sz]e\s+)?(?:verbose\s+)?)?`;
const START_RE = new RegExp(String.raw`^\s*(?:with\b[\s\S]*?\)\s*)?` + EXPLAIN + HEAD, "i");
const ANY_RE = new RegExp(EXPLAIN + HEAD, "gi");
const stripExplain = (t: string) => t.replace(/^\s*explain\s+(\([^)]*\)\s*)?(analy[sz]e\s+)?(verbose\s+)?/i, "");
/** Statements embedded after other text (see sqlFindingsDetailed): the characters and the number of statements read in all. */
const EMBEDDED_BUDGET = 4 * 1024 * 1024, EMBEDDED_COUNT = 20000;

/** Head-level decisions for statements the AST does not (fully) model. */
function headVerdict(t: string): SqlVerdict | null {
  // DROP / TRUNCATE are decided by their head: a dialect feature the parser lacks (CASCADE, IF EXISTS lists) must not soften them.
  if (/^\s*drop\s+(table|database|schema|view|index|user|role|function|procedure|trigger|materialized|sequence|type|extension|keyspace|collection|owned)\b/i.test(t)) return "unrestricted-write";
  if (/^\s*truncate\b/i.test(t)) return "unrestricted-write";
  if (/^\s*delete\s+from\s+[\w."\x60\[\]]+(\s+(as\s+)?\w+)?\s+using\b/i.test(t)) return "unrestricted-write";   // multi-table DELETE … USING
  if (/^\s*insert\s+overwrite\b/i.test(t)) return "unrestricted-write";
  // MERGE … WHEN … THEN DELETE, read from the first WHEN (one expression with two [\s\S]* backtracked quadratically on
  // a long MERGE holding many WHENs)
  if (/^\s*merge\b/i.test(t)) { const w = t.search(/\bwhen\b/i); if (w >= 0 && /\bthen\s+delete\b/i.test(t.slice(w))) return "unrestricted-write"; }
  if (/^\s*copy\b[\s\S]*\bprogram\b/i.test(t)) return "unrestricted-write";       // COPY … PROGRAM runs a shell command
  if (/^\s*copy\b/i.test(t)) return "opaque";                                     // bulk load / server-side file write
  if (/^\s*(grant|revoke)\b/i.test(t)) return "opaque";                           // privilege change
  if (/^\s*alter\b[\s\S]*\brename\b/i.test(t)) return "opaque";                   // rename breaks dependents
  return null;
}
/**
 * Parentheses the parser should not see: unbalanced (a syntax error anyway, and what makes the parser backtrack
 * exponentially) or nested deeper than 1000 (the parser's stack). Quotes are skipped; comments are already gone (sqlCanonical).
 */
function hostileParens(t: string): boolean {
  let depth = 0, quote = "";
  for (const c of t) {
    if (quote) { if (c === quote) quote = ""; continue; }
    if (c === "'" || c === '"' || c === "`") quote = c;
    else if (c === "(") { if (++depth > 1000) return true; }
    else if (c === ")" && --depth < 0) return true;
  }
  return depth !== 0;
}
export function analyzeSql(text: string, dialect = DEFAULT_SQL_DIALECT): SqlVerdict {
  const t = stripExplain(text);                          // EXPLAIN ANALYZE executes the statement: analyze the inner one
  const h = headVerdict(t); if (h) return h;
  if (hostileParens(t)) return "unparseable";
  return parseSqlBounded(t, dialect);
}
/** Database clients whose command line can carry SQL (cheap pre-filter before tokenizing a string as a shell command). */
const DB_CLIENT_HINT = /\b(psql|mysql|mariadb|sqlite3|duckdb|clickhouse(-client)?|sqlcmd|cockroach|snowsql|usql|mssql-cli|trino|presto|databricks|bq|turso|wrangler|heroku)\b/;
/** Database client options that read SQL from a file. */
const SQL_FILE_OPTS = ["-f", "--file", "-i", "--input-file", "--queries-file", "--filename", "-init"];
const SQL_CLIENT_NAME = /^(psql|mysql|mariadb|sqlite3|duckdb|clickhouse(-client)?|sqlcmd|cockroach|snowsql|usql|mssql-cli|trino|presto)$/;
/**
 * SQL given to database clients in a shell command line (psql -c, mysql -e, sqlite3 db "...", behind sudo/docker exec, in
 * sh -c), and `opaque` sources whose SQL cannot be read here: a file (psql -f), stdin (mysql < dump.sql, cat x | psql), or a
 * command substitution (psql -c "$(cat x)").
 */
export function shellSql(text: string, depth = 0, remote = false): { sql: string[]; opaque: string[]; files: string[] } {
  const out = { sql: [] as string[], opaque: [] as string[], files: [] as string[] };
  if (depth > 3 || !DB_CLIENT_HINT.test(text)) return out;
  // lines as written, and lines where quotes keep newlines inside (psql -c "\nDELETE FROM users\n")
  const joined = text.replace(/\\\r?\n/g, " ");
  for (const line of new Set([...joined.split(/\r?\n/), ...quotedLines(joined)])) {
    let toks: any[]; try { toks = shellParse(decodeAnsiC(line), (k: string) => (k === "IFS" ? " " : VAR)) as any[]; } catch { continue; }
    let argv: string[] = [], stdin = false, sub = 0, stdinFile: string | null = null;
    const flush = (pipedNext: boolean) => {
      const { sql, more } = clientSql(argv); out.sql.push(...sql.filter(s => !s.includes(VAR)));
      if (more) out.opaque.push(`more than ${SQL_CLIENTS_READ} database clients in one command: they are not all read`);
      const k = argv.findIndex(w => SQL_CLIENT_NAME.test(w.replace(/^.*[\/\\]/, "").toLowerCase()));
      if (k >= 0) {
        const rest = argv.slice(k + 1), elsewhere = remote || programOf(argv).remote;
        // SQL files in the working directory are read like scripts (psql -f migrate.sql, mysql app < seed.sql) and judged
        // whole. Any other file stays unknown: missing or not a regular file here (written by this same line, stdin, a
        // device), too large, or read by a client that runs on another host or in a container (it never reads local files)
        let unread = false;
        for (const f of [...optValues(rest, SQL_FILE_OPTS), ...(stdinFile !== null && !sql.length ? [stdinFile] : [])]) {
          const r = f.includes(VAR) || elsewhere || f === "-" || /^\/dev\//.test(f) || writtenByLine(f, text) ? null : readScript(f);
          if (r?.kind === "text") out.files.push(r.text); else if (r?.kind !== "seen") unread = true;
        }
        if (unread || sql.some(s => s.includes(VAR)) || sub > 0 || (stdin && stdinFile === null && !sql.length) || rest.some(a => /^\.read\b|^source\b/i.test(a)))
          out.opaque.push(`${argv[k]}: SQL from a file, stdin or a command substitution`);
      }
      // where the command runs is the same for every word: worked out once (once per word was quadratic)
      let away: boolean | undefined;
      for (const w of argv) if (/\s/.test(w) && DB_CLIENT_HINT.test(w)) {
        away ??= remote || programOf(argv).remote;
        const r = shellSql(w, depth + 1, away); out.sql.push(...r.sql); out.opaque.push(...r.opaque); out.files.push(...r.files);
      }
      argv = []; stdin = pipedNext; sub = 0; stdinFile = null;
    };
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (typeof t === "string") { argv.push(t); continue; }
      if (t?.op === "glob") { argv.push(t.pattern); continue; }
      if (t?.comment !== undefined) continue;
      if (t?.op === "<") { if (typeof toks[i + 1] === "string") { stdinFile = toks[i + 1]; i++; } else stdin = true; continue; }
      if (t?.op === "(" && (argv.at(-1) === VAR || argv.at(-1) === "$")) { sub++; continue; }
      if (t?.op === "(" || t?.op === ")") continue;
      if (t?.op === ">" || t?.op === ">>" || t?.op === ">&" || t?.op === "&>") { if (typeof toks[i + 1] === "string") i++; continue; }
      flush(t?.op === "|" || t?.op === "|&");
    }
    flush(false);
  }
  return out;
}
/** Splits shell text into command lines at newlines outside quotes; a # comment ends at its line (its quotes do not count). */
function quotedLines(t: string): string[] {
  const out: string[] = []; let cur = "", q = "";
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) { if (c === "\\" && q === '"' && i + 1 < t.length) { cur += c + t[++i]; continue; } if (c === q) q = ""; cur += c; continue; }
    if (c === "#" && (!cur || /\s$/.test(cur))) { const e = t.indexOf("\n", i); cur += e < 0 ? t.slice(i) : t.slice(i, e); i = e < 0 ? t.length : e - 1; continue; }
    if (c === "'" || c === '"') { q = c; cur += c; continue; }
    if (c === "\n") { out.push(cur.replace(/\r$/, "")); cur = ""; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
}
/** Every string (and JSON inside strings): a statement at the start is fully analyzed (unparseable => confirm);
 *  a statement embedded after other text is cut at ';'/newline and only escalates when it parses; SQL passed to a database
 *  client on a command line (psql -c "...") is fully analyzed. */
export function sqlFindings(args: unknown, dialect = DEFAULT_SQL_DIALECT): Set<SqlVerdict> {
  return new Set(sqlFindingsDetailed(args, dialect).keys());
}
/** The SQL verdicts of the arguments, each with the first statement (or SQL source) that produced it. */
export function sqlFindingsDetailed(args: unknown, dialect = DEFAULT_SQL_DIALECT): Map<SqlVerdict, string> {
  const out = new Map<SqlVerdict, string>();
  const add = (v: SqlVerdict, what: string) => { if (!out.has(v)) out.set(v, what); };
  const done = () => out.has("unrestricted-write");
  /** The canonical readings of a text (standard SQL strings, and MySQL's when a backslash could escape a quote). */
  const readings = (s: string) => sqlCanonicals(canonical(s)).map(v => v.replace(/\s+/g, " ").trim());
  /** A statement at the start of a reading is fully analyzed; returns the readings. */
  const full = (s: string) => { const vs = readings(s); for (const v of vs) if (START_RE.test(v)) add(analyzeSql(v, dialect), v); return vs; };
  /**
   * Statements embedded after other text: cut at ';' or a newline, they only escalate when they parse. Each statement
   * used to take the whole rest of the text (sliced, then split): text holding thousands of statement heads was
   * quadratic (800 KB: 30 s). Past EMBEDDED_BUDGET characters or EMBEDDED_COUNT statements in all, the rest is not
   * searched and a human confirms (opaque), as for any analysis limit.
   */
  const embedded = (v: string) => {
    let budget = EMBEDDED_BUDGET, nextStop: Int32Array | undefined;
    const stopFrom = (i: number) => {
      if (!nextStop) {
        nextStop = new Int32Array(v.length + 1); nextStop[v.length] = v.length;
        for (let k = v.length - 1; k >= 0; k--) { const c = v.charCodeAt(k); nextStop[k] = c === 59 || c === 10 ? k : nextStop[k + 1]; }
      }
      return nextStop[i];
    };
    let count = 0;
    for (const m of v.matchAll(ANY_RE)) {
      if (!m.index) continue;
      // each statement is read whole (a MERGE … THEN DELETE far down a line is still one); the budget counts at most 64 KB
      // of each, so that a long line with a few statement words (minified code) is read as before, and only text built
      // with dozens of statements that each run to its end reaches it
      const end = stopFrom(m.index);
      if ((budget -= Math.min(end - m.index, 64 * 1024)) < 0 || ++count > EMBEDDED_COUNT) { add("opaque", "statements after other text: too many to check them all"); return; }
      const frag = v.slice(m.index, end);
      const r = analyzeSql(frag, dialect);
      if (r === "unrestricted-write" || r === "opaque") add(r, frag);
      if (done()) return;
    }
  };
  for (const s of allStrings(args)) {
    if (done()) break;
    const fromShell = shellSql(s);
    // SQL a client gets on its command line: fully analyzed when it starts with a statement, and searched for statements
    // after other text (SELECT 'a\'; DROP TABLE users: a whole string in PostgreSQL, so the DROP runs)
    for (const q of fromShell.sql) { for (const v of full(q)) { embedded(v); if (done()) return out; } }
    // a SQL file a client runs is judged whole, whatever it starts with (BEGIN; SET ...; then DROP TABLE), and its client
    // commands (\! rm -rf ~, \i other.sql, system, .shell) do not parse: a human confirms
    for (const f of fromShell.files) for (const v of readings(f)) {
      if (v) { add(analyzeSql(v, dialect), v.length > 300 ? `${v.slice(0, 300)}…` : v); if (!done()) embedded(v); }
      if (done()) return out;
    }
    if (fromShell.opaque.length) add("opaque", fromShell.opaque[0]);
    for (const seed of seedsOf(s)) { for (const v of full(seed)) embedded(v); if (done()) return out; }
  }
  return out;
}

/** All strings of the arguments, plus strings of JSON documents embedded in strings (recursively). */
export function allStrings(v: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 16) return out;
  for (const s of collectStrings(v)) {
    out.push(s);
    const t = s.trim();
    if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) { try { allStrings(JSON.parse(t), out, depth + 1); } catch {} }
  }
  return out;
}

// ================= shell =================
/** Decode bash ANSI-C quoting $'...' into an ordinary single-quoted word. */
export function decodeAnsiC(s: string): string {
  return s.replace(/\$'((?:[^'\\]|\\.)*)'/g, (_, body: string) => {
    const d = body.replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|c.|.)/g, (_m, e: string) => {
      if (e[0] === "x" || e[0] === "u" || e[0] === "U") return String.fromCodePoint(parseInt(e.slice(1), 16));
      if (/^[0-7]/.test(e)) return String.fromCharCode(parseInt(e, 8));
      if (e[0] === "c") return String.fromCharCode(e.charCodeAt(1) & 31);
      return ({ n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", v: "\v" } as Record<string, string>)[e] ?? e;
    });
    return "'" + d.replace(/'/g, `'"'"'`) + "'";
  });
}
/** `catastrophic` lists the subset of `destructive` findings that are broad and irreversible. */
export interface ShellReport { destructive: string[]; unresolved: string[]; catastrophic?: string[] }
const hit = (rep: ShellReport, sev: Severity, what: string) => { rep.destructive.push(what); if (sev === "catastrophic") (rep.catastrophic ??= []).push(what); };
/** Variables with a known meaning for a deletion target; any other expansion is unresolved (VAR). */
// Kytral Guard's own state variables resolve to its default location, so that a write through them is seen as tampering.
const KNOWN_VARS: Record<string, string> = { IFS: " ", HOME: "~", USERPROFILE: "~", PWD: ".", OLDPWD: VAR,
  KYTRAL_HOME: "~/.kytral", KYTRAL_AUDIT: "~/.kytral/audit.jsonl", KYTRAL_POLICY: "~/.kytral/policy.yaml", KYTRAL_SECRET_FILE: "~/.kytral/secret" };
/**
 * Shell variables the analyzed text sets with a plain assignment (OUT=dist, then rm -rf "$OUT"), and the positional
 * parameters of a script run with known arguments. Only assignments that always run count: inside if / while / for /
 * case / functions or after && and ||, a second different value, or any other way to set the name (read, for, unset,
 * +=, let, printf -v...) leaves it unknown; text that evals or sources code is not tracked at all. `written`: what the
 * analyzed command wrote to files so far (echo … > x.sh, cat > x.sh <<EOF), for when it runs them.
 */
interface VarScope { vals: Map<string, string | null>; nest: number; text: string; off: boolean; written: Map<string, string> }
let vars: VarScope | undefined;
const envLookup = (k: string) => Object.hasOwn(KNOWN_VARS, k) ? KNOWN_VARS[k]
  : /^(TMPDIR|TMP|TEMP|TEMPDIR)(:?[-=])\/[\w./-]*$/.test(k) ? "/tmp"            // ${TMPDIR:-/tmp}: a temporary directory either way
  : vars && !vars.off ? vars.vals.get(k) ?? VAR : VAR;
/**
 * Variable values put into one parsed line, in all: a few hundred characters that double a variable on each line
 * (v1=$v0$v0, v2=$v1$v1...) grew to gigabytes and stopped the guard. Past this, values are unknown and the line is an
 * expansion bomb: catastrophic, like a fork bomb (a shell running it would exhaust memory the same way).
 */
const EXPANSION_BUDGET = 256 * 1024;
let expansionLeft = EXPANSION_BUDGET, expansionBomb = false;
const boundedLookup = (k: string) => {
  const v = envLookup(k);
  if (v === VAR || v.length <= expansionLeft) { if (v !== VAR) expansionLeft -= v.length; return v; }
  expansionBomb = true; return VAR;
};
/** shell-quote's parse with the variables known so far, within the expansion budget (see boundedLookup). */
function parseWithVars(text: string): any[] {
  expansionLeft = EXPANSION_BUDGET; expansionBomb = false;
  return shellParse(text, boundedLookup) as any[];
}
/** How a nested analysis sees variables: a child process starts afresh, a subshell inherits without leaking back, eval shares. */
type VarMode = "fresh" | "inherit" | "shared";
const UNTRACKED_TEXT = /(^|[\s;&|(`])(eval|source)(\s|$)|(^|[;&|(\n])[ \t]*\.[ \t]+[^\s.]/;
const VOLATILE: RegExp[] = [
  /\b(?:for|select)[ \t]+([A-Za-z_]\w*)/g, /\bgetopts[ \t]+\S+[ \t]+([A-Za-z_]\w*)/g, /\b([A-Za-z_]\w*)(?:\[[^\]]*\])?\+?=\(/g, /\b([A-Za-z_]\w*)\+=/g,
  /\bprintf[ \t]+-v[ \t]+([A-Za-z_]\w*)/g, /\$\{([A-Za-z_]\w*):?[=?]/g, /\b([A-Za-z_]\w*)\[[^\]]*\]=/g,
  /\b(?:declare|typeset|local|readonly|export)[ \t]+-[a-zA-Z]*[naAi][a-zA-Z]*[ \t]+([A-Za-z_]\w*)/g,
];
const VOLATILE_REGIONS = /\b(?:read|mapfile|readarray|let|unset)\b([^;&|\n]*)|\(\(([^)]*)\)\)/g;
function markVolatile(s: VarScope, text: string): void {
  if (UNTRACKED_TEXT.test(text)) { s.off = true; return; }
  for (const re of VOLATILE) for (const m of text.matchAll(re)) s.vals.set(m[1], null);
  for (const m of text.matchAll(VOLATILE_REGIONS)) for (const n of (m[1] ?? m[2] ?? "").matchAll(/[A-Za-z_]\w*/g)) s.vals.set(n[0], null);
}
function withVars<T>(text: string, mode: VarMode, args: string[] | undefined, fn: () => T): T {
  const prev = vars;
  if (mode === "shared" && prev) { markVolatile(prev, text); return fn(); }
  const inherit = mode === "inherit" && prev;
  const next: VarScope = inherit ? { vals: new Map(prev.vals), nest: 0, text: prev.text, off: prev.off, written: prev.written } : { vals: new Map(), nest: 0, text, off: false, written: new Map() };
  if (args) {
    for (let k = 1; k <= 9; k++) next.vals.set(String(k), args[k - 1] ?? "");
    next.vals.set("#", String(args.length)); next.vals.set("@", args.join(" ")); next.vals.set("*", args.join(" "));
  }
  markVolatile(next, text);
  vars = next;
  try { return fn(); } finally { vars = prev; }
}
/** A plain assignment that ran (cond: after && or ||): its value counts when it is the only one, and always runs. */
function assignVar(name: string, value0: string, cond: boolean): void {
  const s = vars;
  if (!s || s.off || Object.hasOwn(KNOWN_VARS, name) || /^\d$/.test(name)) return;
  const value = value0.includes("`") ? value0.replace(/`([^`]*)`?/g, (_m, c: string) => substWord(c)) : value0;
  const prev = s.vals.get(name);
  // a value past the expansion budget is not kept (unknown): see boundedLookup
  s.vals.set(name, cond || s.nest > 0 || prev === null || (prev !== undefined && prev !== value) || value.includes(VAR) || value.length > EXPANSION_BUDGET ? null : value);
}
const nestUp = () => { if (vars) vars.nest++; };
const nestDown = () => { if (vars) vars.nest = Math.max(0, vars.nest - 1); };
/** What a file holds when the analyzed command wrote it before running it (echo … > x.sh, cat > x.sh <<EOF). */
const fileKey = (p: string) => unq(p).replace(/\\/g, "/").replace(/^(\.\/)+/, "");
function recordWrite(target: string, content: string, append: boolean): void {
  if (!vars || target.includes(VAR)) return;
  const k = fileKey(target), prev = vars.written.get(k);
  vars.written.set(k, append && prev !== undefined ? `${prev}\n${content}` : content);
}
/** What $(mktemp …) stands for: a fresh path in the temporary directory, or the template when it names another folder. */
function mktempWord(words: string[]): string | undefined {
  if (base(words[0] ?? "") !== "mktemp") return undefined;
  const rest = words.slice(1);
  const dir = optValues(rest, ["-p", "--tmpdir"])[0], tpl = positionals(rest, ["-p", "--tmpdir", "--suffix"])[0];
  if (dir !== undefined) return dir.includes(VAR) ? undefined : `${dir.replace(/\/+$/, "")}/${tpl ?? "tmp.XXXXXXXXXX"}`;
  if (!tpl || rest.some(a => /^(-t|--tmpdir)$/.test(a))) return `/tmp/${tpl?.replace(/^.*\//, "") ?? "tmp.XXXXXXXXXX"}`;
  return tpl.includes(VAR) ? undefined : tpl;
}

/**
 * Commands that run their remaining arguments as a command (sudo rm ..., timeout 10 rm ...): the options that take a value
 * (so `sudo -u root rm` is not read as the command `root`), the fixed operands before the command (timeout's duration),
 * the options whose value is a whole command line (`env -S "..."`), those that run the rest as one shell string (watch),
 * and those whose every argument is a shell command (concurrently 'npm start' 'npm run worker').
 */
interface Wrapper { value?: string[]; operands?: number; shell?: string[]; joins?: boolean; each?: boolean; stdin?: boolean }
const WRAPPERS: Record<string, Wrapper> = {
  sudo: { value: ["-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "--user", "--group", "--host", "--prompt", "--chdir", "--role", "--type", "--other-user", "--command-timeout", "--close-from"] },
  doas: { value: ["-u", "-C"] }, env: { value: ["-u", "--unset", "-C", "--chdir"], shell: ["-S", "--split-string"] },
  nohup: {}, time: { value: ["-f", "--format", "-o", "--output"] }, command: {}, exec: { value: ["-a"] }, builtin: {}, unbuffer: {}, busybox: {},
  nice: { value: ["-n", "--adjustment"] }, ionice: { value: ["-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u", "--uid"] },
  timeout: { value: ["-s", "--signal", "-k", "--kill-after"], operands: 1 }, watch: { value: ["-n", "--interval", "-c", "--color"], joins: true },
  stdbuf: { value: ["-i", "-o", "-e", "--input", "--output", "--error"] }, chroot: { value: ["--userspec", "--groups"], operands: 1 },
  xargs: { value: ["-I", "-L", "-n", "-P", "-d", "-E", "-s", "-a", "--max-args", "--max-procs", "--delimiter", "--arg-file", "--replace", "--max-lines", "--eof"], stdin: true },
  parallel: { value: ["-j", "--jobs", "-S", "--sshlogin", "--joblog", "--delay", "--timeout"], stdin: true },
  setsid: {}, chrt: { operands: 1 }, taskset: { operands: 1 },
  strace: { value: ["-o", "-e", "-p", "-s", "-u", "-E", "-P", "-I", "-b", "-a", "-X"] }, ltrace: { value: ["-o", "-e", "-p", "-s", "-u", "-n"] },
  caffeinate: { value: ["-t", "-w"] }, firejail: {}, proxychains: {}, proxychains4: {}, torsocks: {}, tsocks: {}, nsenter: { value: ["-t", "--target"] },
  "cross-env": {}, catchsegv: {},
  // Privilege, isolation and resource wrappers (container entrypoints, schedulers, test runners)
  unshare: { value: ["-S", "-G", "-R", "-w", "--setuid", "--setgid", "--root", "--wd"] },
  gosu: { operands: 1 }, "su-exec": { operands: 1 }, setuidgid: { operands: 1 }, envuidgid: { operands: 1 }, pkexec: { value: ["--user"] },
  setpriv: { value: ["--reuid", "--regid", "--ruid", "--rgid", "--euid", "--egid", "--groups", "--inh-caps", "--ambient-caps", "--bounding-set", "--securebits", "--pdeathsig", "--selinux-label", "--apparmor-profile"] },
  eatmydata: {}, fakeroot: { value: ["-l", "-f", "-s", "-i", "-b"] }, "dumb-init": { value: ["-r", "--rewrite"] },
  numactl: { value: ["-i", "-m", "-N", "-C", "-p", "--interleave", "--membind", "--cpunodebind", "--physcpubind", "--preferred"] },
  cpulimit: { value: ["-l", "--limit", "-c", "--cpu"] }, setarch: { operands: 1 }, arch: { value: ["-arch"] }, faketime: { operands: 1 }, prlimit: { value: ["-p", "--pid"] },
  "xvfb-run": { value: ["-n", "-s", "-f", "-e", "-w", "--server-num", "--server-args", "--auth-file", "--error-file", "--wait"] },
  chpst: { value: ["-u", "-U", "-b", "-e", "-n", "-l", "-L", "-m", "-d", "-o", "-p", "-f", "-c", "-r", "-t"] },
  daemonize: { value: ["-a", "-c", "-e", "-o", "-p", "-l", "-u", "-E"] },
  "systemd-run": { value: ["-p", "--property", "-u", "--unit", "--description", "-E", "--setenv", "--uid", "--gid", "--nice", "--working-directory", "-M", "--machine", "-H", "--host", "--slice", "--on-calendar", "--on-active", "--timer-property", "--service-type"] },
  mpirun: { value: ["-np", "-n", "-c", "--np", "-H", "--host", "--hostfile", "-x", "--map-by", "--bind-to", "--mca"] },
  srun: { value: ["-N", "-n", "-p", "-t", "-c", "-J", "-o", "-e", "--nodes", "--ntasks", "--partition", "--time", "--job-name"] },
  entr: {}, concurrently: { value: ["-n", "--names", "-c", "--prefix-colors", "-p", "--prefix", "-s", "--success", "-m", "--max-processes", "--restart-tries", "--restart-after", "-t", "--timestamp-format", "--default-input-target"], each: true },
};
/** Commands that run a package binary or a tool they resolve (npx prisma ..., bundle exec rails ..., uv run alembic ...). */
const JS_BUILTINS: Record<string, Set<string>> = {
  pnpm: new Set(["add", "install", "i", "update", "up", "upgrade", "remove", "rm", "uninstall", "un", "link", "ln", "unlink", "import", "rebuild", "rb", "prune", "fetch", "install-test", "it", "patch", "patch-commit", "patch-remove", "audit", "list", "ls", "outdated", "why", "licenses", "create", "test", "t", "start", "publish", "pack", "recursive", "server", "store", "root", "bin", "setup", "init", "deploy", "doctor", "config", "c", "env", "self-update", "help", "ci", "clean", "approve-builds", "version", "info", "view", "login", "logout", "whoami", "owner", "dist-tag", "search", "cache", "completion", "dedupe", "catalog"]),
  yarn: new Set(["add", "bin", "cache", "config", "constraints", "dedupe", "explain", "info", "init", "install", "link", "node", "npm", "pack", "patch", "patch-commit", "plugin", "rebuild", "remove", "search", "set", "stage", "unlink", "unplug", "up", "upgrade", "upgrade-interactive", "version", "why", "workspace", "workspaces", "global", "list", "ls", "outdated", "owner", "publish", "tag", "team", "test", "audit", "autoclean", "check", "create", "generate-lock-entry", "help", "import", "licenses", "login", "logout", "policy", "start", "self-update"]),
  bun: new Set(["test", "repl", "install", "i", "add", "a", "remove", "rm", "update", "outdated", "link", "unlink", "pm", "build", "init", "create", "c", "upgrade", "publish", "patch", "audit", "info", "why", "help"]),
};
function runnerTarget(cmd: string, rest: string[]): string[] | null {
  const fromPositional = (args: string[], valueOpts: string[] = []) => {
    for (let k = 0; k < args.length; k++) {
      if (args[k] === "--") return args.slice(k + 1);
      if (args[k].startsWith("-")) { if (valueOpts.includes(args[k])) k++; continue; }
      return args.slice(k);
    }
    return null;
  };
  const afterWord = (words: string[], valueOpts: string[] = []) => { const p = fromPositional(rest, valueOpts); return p && words.includes(p[0]) ? fromPositional(p.slice(1), valueOpts) : null; };
  switch (cmd) {
    case "npx": case "pnpx": case "bunx": case "uvx": return fromPositional(rest, ["-p", "--package", "-w", "--workspace", "--from", "--with", "--python"]);
    case "npm": return afterWord(["exec", "x"], ["-p", "--package", "-w", "--workspace", "-c", "--call"]) ?? afterWord(["run", "run-script"], ["-w", "--workspace"]);
    case "pnpm": case "yarn": case "bun": {
      if (cmd === "bun" && rest.some(a => /^(-e|--eval|-p|--print)$/.test(a))) return null;   // bun -e '<code>': an interpreter one-liner
      const p = fromPositional(rest, ["-C", "--dir", "--cwd", "--filter", "-F", "-w", "--workspace"]); if (!p) return null;
      if (["exec", "dlx", "x", "run"].includes(p[0])) return fromPositional(p.slice(1), ["-p", "--package"]);
      return JS_BUILTINS[cmd].has(p[0]) ? null : p;
    }
    case "uv": return afterWord(["run"], ["--with", "--python", "-p", "--project", "--directory", "--package", "--env-file"]) ?? (fromPositional(rest)?.[0] === "tool" ? afterWord(["tool"])?.[0] === "run" ? fromPositional(afterWord(["tool"])!.slice(1)) : null : null);
    case "poetry": case "pipenv": case "pdm": case "hatch": case "rye": case "pipx": return afterWord(["run"], ["--spec", "--python"]);
    case "conda": case "mamba": case "micromamba": return afterWord(["run"], ["-n", "--name", "-p", "--prefix", "--cwd"]);
    case "bundle": case "bundler": return afterWord(["exec"]);
    case "corepack": return fromPositional(rest);
    case "nix": { const k = rest.findIndex(a => a === "-c" || a === "--command"); return rest.includes("develop") && k >= 0 ? rest.slice(k + 1) : null; }
    case "devbox": case "flox": return afterWord(["run"]);
    case "direnv": return rest[0] === "exec" ? rest.slice(2) : null;
    case "op": case "doppler": case "infisical": case "mise": case "rtx": case "dotenv": case "dotenvx": case "aws-vault": case "teller": case "chamber": case "retry": case "tini": case "watchexec": case "distrobox": {
      const k = rest.indexOf("--"); return k >= 0 ? rest.slice(k + 1) : null;
    }
  }
  return null;
}
/** Interpreters that run a script file: the script's name is the command (manage.py, artisan, bin/console, ace, rails). */
const SCRIPT_HOSTS = /^(python[\d.]*|php[\d.]*|node|nodejs|ruby|bun|deno|perl)$/;

const SHELLS = /^(sh|bash|zsh|dash|ksh|fish|ash|csh|tcsh|mksh|yash)$/;
/** Interpreter one-liners: the options that carry code. Clusters ending with the code flag also count (perl -ne, node -pe). */
const INTERP: Record<string, string[]> = { node: ["-e", "--eval", "-p", "--print"], nodejs: ["-e", "--eval", "-p", "--print"], deno: ["eval"], bun: ["-e", "--eval"],
  python: ["-c"], python2: ["-c"], python3: ["-c"], perl: ["-e", "-E"], ruby: ["-e"], php: ["-r"], osascript: ["-e"], lua: ["-e"], luajit: ["-e"],
  R: ["-e"], Rscript: ["-e"], julia: ["-e", "--eval"], groovy: ["-e"], tclsh: [], pwsh: ["-c", "-command"], powershell: ["-c", "-command"] };
const CLUSTER: Record<string, RegExp> = { perl: /^-[a-zA-Z]*[eE]$/, ruby: /^-[a-zA-Z]*e$/, node: /^-[a-zA-Z]*[ep]$/, nodejs: /^-[a-zA-Z]*[ep]$/, python: /^-[a-zA-Z]*c$/, python3: /^-[a-zA-Z]*c$/ };
const AWK = /^(awk|gawk|mawk|nawk|busybox-awk)$/;
const STDIN_RUNNERS = /^(sh|bash|zsh|dash|ksh|fish|ash|node|nodejs|python[23]?|perl|ruby|php|pwsh|powershell|source|\.|lua|Rscript|tclsh|at|batch|crontab)$/;
const DELETE_API = /\b(rmSync|rmdirSync|unlinkSync|rimraf|fs\s*\.\s*(rm|rmdir|unlink)\b|fs\/promises|rmtree|os\s*\.\s*(remove|unlink|rmdir|removedirs)|Path\s*\(.*\)\s*\.\s*unlink|File\s*\.\s*delete|FileUtils\s*\.\s*rm|rm_r?f?\s*\(|Remove-Item|\bunlink\b|\brmdir\b|truncateSync|writeFileSync\s*\(\s*['"]\/|Deno\s*\.\s*remove(Sync)?|Dir\s*\.\s*(rmdir|delete|unlink)|remove_dir_all|deleteRecursively|Files\s*\.\s*delete|unlink\s*\(|file\s*\.\s*remove)/i;
/** A deletion API aimed at the root or a home directory: catastrophic rather than destructive. */
const BROAD_LITERAL = /['"`](\/|~\/?|\/home\/?|\/Users\/?|[A-Za-z]:[\\\/]{0,2})['"`]|homedir\s*\(|expanduser\s*\(\s*['"]~['"]\s*\)|Path\s*\.\s*home\s*\(|process\s*\.\s*env\s*\.\s*(HOME|USERPROFILE)|\$ENV\s*\{\s*HOME|ENV\s*\[\s*['"]HOME|getenv\s*\(\s*['"]HOME|Dir\s*\.\s*home|System\s*\.\s*getProperty\s*\(\s*['"]user\.home|\$env:USERPROFILE|Deno\s*\.\s*env\s*\.\s*get\s*\(\s*['"]HOME/;
const SPAWN_API = /\b(child_process|execSync|spawnSync|exec\s*\(|spawn\s*\(|system2?\s*\(|subprocess|os\s*\.\s*(system|popen|exec\w*|execute)|eval\s*\(|Function\s*\(|qx|IO\s*\.\s*popen|io\s*\.\s*popen|shell_exec|passthru|proc_open|Start-Process|Invoke-Expression|Deno\s*\.\s*(run|Command)|Bun\s*\.\s*(spawn|\$)|run\s*\(\s*`|Runtime\s*\.\s*getRuntime|ProcessBuilder|popen|execFile)|`[^`]*`/i;
const SAFE_REDIRECT = /^(\/dev\/(null|stdout|stderr|tty|fd\/\d)|\/tmp\/|\/var\/tmp\/)/;
const DISK_TOOLS = /^(mkfs(\..+)?|mke2fs|mkswap|wipefs|fdisk|sfdisk|cfdisk|gdisk|sgdisk|parted|blkdiscard|hdparm|nvme|diskutil|zpool|lvremove|vgremove|pvremove|badblocks)$/;
const FILE_WIPERS = /^(shred|srm|wipe)$/;
// Command names are case-sensitive in a shell: keep case (prose "Truncate the table" is not the truncate command),
// but still fold Unicode compatibility forms, invisibles and homoglyphs.
const base = (s: string) => canonical(s, true).replace(/^.*\//, "").replace(/\\/g, "");
const pathLike = (p0: string) => { const p = unq(p0); return /[\/~]/.test(p) || /^\.?[\w-]+\.[\w]{1,8}$/.test(p); };
const hasFlag = (args: string[], short: string, long: string[] = []) =>
  args.some(a => (/^-[a-z]+$/i.test(a) && a.slice(1).includes(short)) || long.includes(a));
/** Branches whose force-push or deletion rewrites or removes shared history. */
const PROTECTED_BRANCH = /^(refs\/heads\/)?(main|master|trunk|production|prod|release|develop|development|stable|live)$/;
const SSH_VALUE_OPTS = ["-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w", "-B"];
const EXEC_VALUE_OPTS = ["-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir", "--detach-keys", "--index", "-c", "--container", "-n", "--namespace", "--context", "--kubeconfig", "--pod-running-timeout"];
/** git options before the subcommand that take a value (git -C dir, git -c key=value). */
const GIT_GLOBAL_VALUE = ["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env", "--super-prefix", "--list-cmds", "--attr-source"];
/** git configuration keys whose value is a command git runs (core.sshCommand, alias.x = '!cmd', credential helpers...). */
const GIT_EXEC_KEY = /^(core\.(sshcommand|pager|editor|fsmonitor|askpass|hookspath)|sequence\.editor|credential(\..+)?\.helper|alias\..+|diff\..+\.(command|textconv)|diff\.external|merge\..+\.driver|filter\..+\.(clean|smudge|process)|gpg(\..+)?\.program|uploadpack\.packobjectshook|pager\..+|interactive\.difffilter|ssh\.variant|remote\..+\.(receivepack|uploadpack)|protocol\.ext\..+)$/i;
/** Environment variables holding a command that tools run (GIT_SSH_COMMAND='…' git fetch, EDITOR='…' git commit). */
const EXEC_ENV = /^(GIT_SSH_COMMAND|GIT_SSH|GIT_EDITOR|GIT_PAGER|GIT_ASKPASS|GIT_SEQUENCE_EDITOR|GIT_EXTERNAL_DIFF|SSH_ASKPASS|EDITOR|VISUAL|PAGER|MANPAGER|LESSOPEN|PROMPT_COMMAND|BASH_ENV|ENV|DOCKER_HOST_CMD)$/;
/** Scripts that only set up an environment: sourcing them is routine (venv activate, nvm, cargo env, conda hooks, rc files). */
const ENV_SCRIPT = /(^|\/)(activate(\.(fish|csh|ps1|nu|bat))?|nvm\.sh|env|\.env(\.[\w-]+)?|\.envrc|conda\.sh|mamba\.sh|virtualenvwrapper(_lazy)?\.sh|asdf\.sh|sdkman-init\.sh|\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile|profile|rvm|chruby\.sh|z\.sh|completion\.(bash|zsh))$/;
/** Shell-init idioms: eval "$(<tool> …)" where the tool prints environment setup (ssh-agent -s, direnv hook, rbenv init -). */
const INIT_TOOLS = /^(ssh-agent|gpg-agent|keychain|direnv|rbenv|pyenv|nodenv|goenv|jenv|plenv|phpenv|tfenv|fnm|nvm|zoxide|starship|mise|rtx|asdf|conda|mamba|micromamba|brew|minikube|docker-machine|opam|luarocks|thefuck|atuin|mcfly|oh-my-posh|fzf|kubectl|helm|gh|npm|pip|poetry|pdm|register-python-argcomplete|aws-vault|devbox|flox|nix|tmuxifier|dircolors|lesspipe|lesspipe\.sh|hub|scmpuff|batman|navi|broot|carapace|fasd|pyenv-virtualenv-init|rustup|cargo|uv|rye|zellij|tea|frum)$/;
/** Commands that take text, patterns or file names as arguments: a destructive-looking word among them is data, not a command. */
const TEXT_COMMANDS = /^(pv|echo|printf|print|grep|egrep|fgrep|rg|ag|ack|cat|less|more|head|tail|wc|sort|uniq|cut|tr|jq|yq|man|info|help|which|type|whatis|apropos|whereis|test|\[|true|false|:|export|set|unset|declare|local|readonly|history|notify-send|say|logger|wall|write|mail|ls|stat|file|du|df|tree|diff|cmp|comm|basename|dirname|realpath|readlink|date|sleep|cd|pushd|popd|exit|return|read|trap|let|getopts|open|xdg-open|start|code|vi|vim|nvim|nano|emacs|bat|column|fold|fmt|nl|pr|rev|tac|paste|join|split|expand|od|hexdump|xxd|strings|iconv|base64|md5sum|sha\d*sum|cksum|gzip|gunzip|zcat|tar|zip|unzip|7z|touch|mkdir|tee|alias|complete|compgen|bind|fc|hash|wait|disown|jobs)$/;
/** Commands worth re-analyzing when they appear inside the arguments of an unknown command (gosu app rm -rf /, systemd-run … terraform destroy). */
const DANGER_START = /^(rm|dd|mkfs(\..+)?|wipefs|shred|srm|wipe|badblocks|find|truncate|unlink|chmod|chown|chgrp|rsync|mv|cp|ln|git|terraform|tofu|terragrunt|pulumi|cdk|kubectl|oc|helm|aws|gcloud|gsutil|az|docker|podman|dropdb|redis-cli|mongosh|mongo|psql|mysql|mysqladmin|sqlite3|prisma|rails|rake|sh|bash|zsh|dash|ksh|sudo|doas|env|xargs|eval|python[\d.]*|node|perl|ruby|php|kill|killall5|shutdown|reboot|halt|poweroff|systemctl|crontab|iptables|heroku|fly|flyctl|vercel|netlify|firebase|wrangler|supabase|gh|vault|etcdctl|consul|mc|rclone|s3cmd|azcopy|curl|npx|bunx)$/;

interface ArgvCtx {
  piped: boolean; line: string;
  /** Targets come from stdin (xargs, parallel). */
  viaStdin?: boolean;
  /** Second pass over the same words split on whitespace: no generic re-analysis of unknown commands there (quoted text would look like commands). */
  split?: boolean;
  /** The previous stage of the pipeline (what xargs reads from). */
  producer?: string[];
  /** Runs only if the previous command succeeded or failed (after && or ||): its assignments may not happen. */
  cond?: boolean;
}
/** How broad the file list a pipeline producer prints is: find / | xargs rm, echo /etc | xargs rm, ls | xargs rm -rf. */
/**
 * The start points of a find command (. when none), its expression, and whether it follows symbolic links (-L: out of the
 * folder it starts in). Its global options come first: -H -L -P -D <debug> -O<level> (GNU), -E -X -d -s -x and -f <path>
 * (BSD, a start point): find -L / … starts at /, not at the current folder.
 */
function findArgs(args: string[]): { starts: string[]; expr: string[]; follow: boolean } {
  const starts: string[] = []; let i = 0, follow = false;
  for (; i < args.length; i++) {
    const a = args[i];
    if (a === "-L") follow = true;
    else if (/^-(H|P|E|X|d|s|x|O\d*)$/.test(a)) { /* a global option */ }
    else if (a === "-D") i++;
    else if (a === "-f" && i + 1 < args.length) starts.push(args[++i]);
    else break;
  }
  for (; i < args.length && !/^[-(!]/.test(args[i]); i++) starts.push(args[i]);
  return { starts: starts.length ? starts : ["."], expr: args.slice(i), follow };
}
function producerSeverity(producer: string[] | undefined, recursive: boolean): Severity {
  if (!producer?.length) return "destructive";
  const p = base(producer[0]), args = producer.slice(1);
  if (p === "find") {
    const { starts } = findArgs(args);
    const filtered = args.some(a => /^-(i?name|i?path|i?wholename|i?regex|newer\w*|[acm](time|min)|size|user|group|empty)$/.test(a));
    return starts.some(s => broadPath(s) && !/^\.{1,2}\/?$/.test(unq(s)) && !/^~/.test(unq(s))) || (!filtered && starts.some(broadPath)) ? "catastrophic" : "destructive";
  }
  if (/^(echo|printf|ls|fd|fdfind|locate|realpath|readlink)$/.test(p)) {
    const ops = args.filter(a => !a.startsWith("-"));
    if (ops.some(broadPath)) return "catastrophic";
    return p === "ls" && !ops.length && recursive ? "catastrophic" : "destructive";   // ls | xargs rm -rf: everything here
  }
  return "destructive";
}
/** The command lines inside the string literals of interpreter code that spawns processes (os.system('…'), execSync("…")). */
function codeCommands(code: string): string[] { return [...code.matchAll(/'((?:[^'\\]|\\.){2,})'|"((?:[^"\\]|\\.){2,})"|`([^`]{2,})`/g)].map(m => (m[1] ?? m[2] ?? m[3]).replace(/\\(['"\\])/g, "$1")); }

/**
 * Unresolved findings that still count inside files (scripts, package.json scripts, recipes): there, variable commands,
 * redirections to computed paths, eval and sourcing are routine; remote code, blind spots and broad targets are not.
 */
const KEEP_IN_FILES = /script piped into|runs the output of|written or downloaded|too large to analyze|too many scripts|is a binary|cannot analyze the (makefile|justfile|Taskfile)|sed e runs|Invoke-Expression|on a broad path/;
interface RunOpts { mode?: VarMode; args?: string[]; perLine?: boolean; inline?: boolean }
/**
 * Analyzes shell text a command runs (a script file, a package.json script, recipes, a here-document); findings carry
 * `label`. `perLine`: every line runs in a shell of its own (make, just). `inline`: text from the command itself.
 */
function analyzeRun(text: string, label: string, depth: number, rep: ShellReport, opts: RunOpts = {}): void {
  const inner: ShellReport = { destructive: [], unresolved: [], catastrophic: [] };
  if (opts.perLine) for (const l of text.split("\n")) analyzeShell(l, depth + 1, inner, "fresh");
  else analyzeShell(text, depth + 1, inner, opts.mode ?? "fresh", opts.args);
  for (const f of inner.destructive) hit(rep, inner.catastrophic?.includes(f) ? "catastrophic" : "destructive", `${f} (${label})`);
  for (const u of inner.unresolved) if (opts.inline || KEEP_IN_FILES.test(u)) rep.unresolved.push(`${u} (${label})`);
}
/** PowerShell or cmd.exe text a command runs (pwsh -File x.ps1, x.bat). */
function analyzeWindowsRun(text: string, label: string, rep: ShellReport): void {
  const w = analyzeWindows(text);
  for (const f of w.catastrophic ?? []) hit(rep, "catastrophic", `${f} (${label})`);
  for (const f of w.destructive) if (!(w.catastrophic ?? []).includes(f)) hit(rep, "destructive", `${f} (${label})`);
  for (const u of w.unresolved) if (KEEP_IN_FILES.test(u)) rep.unresolved.push(`${u} (${label})`);
}
/** The commands of a crontab: each line without its schedule (5 fields, or @reboot / @daily...) and environment lines. */
function cronCommands(text: string): string {
  return text.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#") && !/^[A-Za-z_]\w*\s*=/.test(l))
    .map(l => /^@\w+\s+([\s\S]*)$/.exec(l)?.[1] ?? /^(?:\S+\s+){5}([\s\S]*)$/.exec(l)?.[1] ?? "").filter(Boolean).join("\n");
}
/** Expressions that stand for the root or a home directory in program code, as a whole argument. */
const BROAD_ARG = /^(['"`](\/|~\/?|\/home\/?|\/Users\/?|[A-Za-z]:[\\\/]{0,2})['"`]|(os\s*\.\s*)?homedir\s*\(\s*\)|(os\s*\.\s*path\s*\.\s*)?expanduser\s*\(\s*['"]~\/?['"]\s*\)|(pathlib\s*\.\s*)?Path\s*\.\s*home\s*\(\s*\)|Path\s*\(\s*['"]~['"]\s*\)\s*\.\s*expanduser\s*\(\s*\)|process\s*\.\s*env\s*(\.\s*(HOME|USERPROFILE)|\[\s*['"](HOME|USERPROFILE)['"]\s*\])|os\s*\.\s*environ\s*\[\s*['"]HOME['"]\s*\]|os\s*\.\s*(environ\s*\.\s*get|getenv)\s*\(\s*['"]HOME['"]\s*\)|Dir\s*\.\s*home|ENV\s*\[\s*['"]HOME['"]\s*\]|\$ENV\s*\{\s*['"]?HOME['"]?\s*\}|getenv\s*\(\s*['"]HOME['"]\s*\)|Deno\s*\.\s*env\s*\.\s*get\s*\(\s*['"]HOME['"]\s*\)|System\s*\.\s*getProperty\s*\(\s*['"]user\.home['"]\s*\)|\$env:USERPROFILE)$/;
const RECURSIVE_API = /rmtree|rm_rf|rm_r\b|remove_dir_all|deleteRecursively|rimraf|removedirs/i;
/** The arguments of a call, from \`i\` (just after its opening parenthesis) to the matching one; bounded. */
function callArgs(code: string, i: number): string {
  let depth = 1, q = "";
  for (let k = i; k < code.length && k < i + 2000; k++) {
    const c = code[k];
    if (q) { if (c === "\\") k++; else if (c === q) q = ""; continue; }
    if (c === "'" || c === '"' || c === "`") q = c;
    else if (c === "(" || c === "[" || c === "{") depth++;
    else if ((c === ")" || c === "]" || c === "}") && --depth === 0) return code.slice(i, k);
  }
  return code.slice(i, i + 2000);
}
/** Arguments split at top-level commas. */
function splitArgs(args: string): string[] {
  const out: string[] = [];
  let depth = 0, q = "", from = 0;
  for (let k = 0; k < args.length; k++) {
    const c = args[k];
    if (q) { if (c === "\\") k++; else if (c === q) q = ""; continue; }
    if (c === "'" || c === '"' || c === "`") q = c;
    else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "," && depth === 0) { out.push(args.slice(from, k).trim()); from = k + 1; }
  }
  out.push(args.slice(from).trim());
  return out.filter(Boolean);
}
/** Splits an expression at a top-level operator character (outside quotes and brackets). */
function splitTop(e: string, op: string): string[] {
  const out: string[] = [];
  let depth = 0, q = "", from = 0;
  for (let k = 0; k < e.length; k++) {
    const c = e[k];
    if (q) { if (c === "\\") k++; else if (c === q) q = ""; continue; }
    if (c === "'" || c === '"' || c === "`") q = c;
    else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === op && depth === 0) { out.push(e.slice(from, k)); from = k + 1; }
  }
  out.push(e.slice(from));
  return out.map(x => x.trim());
}
const joinParts = (parts: string[]) => parts.reduce((acc, p) => /^([\/~]|[A-Za-z]:)/.test(p) || !acc ? p : `${acc.replace(/\/+$/, "")}/${p.replace(/^\.\//, "")}`, "").replace(/\/{2,}/g, "/");
/**
 * The path a program expression stands for, when it is built from literals and home or root expressions only:
 * 'dist', os.path.join(os.path.expanduser('~'), '.cache'), os.homedir() + '/x', `${os.homedir()}/x`, Path.home() / 'x'.
 */
function literalPath(e0: string, depth = 0): string | undefined {
  const e = e0.trim();
  if (depth > 4 || !e || e.length > 400) return undefined;
  const lit = /^([rRbB]?)(['"`])((?:(?!\2)[^\\]|\\.)*)\2$/s.exec(e);
  if (lit) {
    if (lit[2] !== "`" || !lit[3].includes("$" + "{")) return lit[3];
    const parts = lit[3].split(/\$\{([^{}]*)\}/).map((p, k) => k % 2 ? literalPath(p, depth + 1) : p);
    return parts.every(p => p !== undefined) ? parts.join("") : undefined;
  }
  if (BROAD_ARG.test(e)) return "~";
  const tilde = /^(?:os\s*\.\s*path\s*\.\s*)?expanduser\s*\(\s*(['"])(~[^'"]*)\1\s*\)$/.exec(e);
  if (tilde) return tilde[2];
  const call = /^(?:(?:os\s*\.\s*)?path\s*\.\s*(?:posix\s*\.\s*)?(?:join|resolve)|posixpath\s*\.\s*join|File\s*\.\s*join)\s*\(([\s\S]*)\)$/.exec(e);
  if (call) { const parts = splitArgs(call[1]).map(a => literalPath(a, depth + 1)); return parts.length && parts.every(p => p !== undefined) ? joinParts(parts as string[]) : undefined; }
  const slash = splitTop(e, "/");
  if (slash.length > 1 && /^(pathlib\s*\.\s*)?Path\b/.test(slash[0])) {
    const head = /^(?:pathlib\s*\.\s*)?Path\s*\(\s*\)$/.test(slash[0]) ? "." : /^(?:pathlib\s*\.\s*)?Path\s*\(([\s\S]*)\)$/.exec(slash[0]) ? literalPath(/^(?:pathlib\s*\.\s*)?Path\s*\(([\s\S]*)\)$/.exec(slash[0])![1], depth + 1) : undefined;
    const parts = [head, ...slash.slice(1).map(p => literalPath(p, depth + 1))];
    return parts.every(p => p !== undefined) ? joinParts(parts as string[]) : undefined;
  }
  const plus = splitTop(e, "+");
  if (plus.length > 1) { const parts = plus.map(p => literalPath(p, depth + 1)); return parts.every(p => p !== undefined) ? parts.join("") : undefined; }
  return undefined;
}
interface DeletionCall { sev: Severity | "unknown" | null; target: string; args: string; at: number }
/** DELETE_API as calls, for program text whose strings are blanked (writeFileSync('/…') is judged by its target there). */
const DELETE_CALL = new RegExp(DELETE_API.source.replace("writeFileSync\\s*\\(\\s*['\"]\\/", "writeFileSync\\s*\\("), "gi");
/**
 * The deletion calls of interpreter code, judged by their target: a literal path like rm's, the root or a home directory,
 * or unknown. `view`: the same text with strings and comments blanked (calls are looked for there, arguments read in `code`).
 */
function deletionCalls(code: string, view?: string): DeletionCall[] {
  const out: DeletionCall[] = [];
  for (const m of (view ?? code).matchAll(view ? DELETE_CALL : new RegExp(DELETE_API.source, "gi"))) {
    if (out.length >= 200) break;
    const paren = m[0].indexOf("(");
    let i = m.index! + m[0].length, args: string;
    if (paren >= 0) args = callArgs(code, m.index! + paren + 1);
    else {
      const gap = /^[\w.]*[ \t]*/.exec(code.slice(i, i + 64))![0];
      i += gap.length;
      if (code[i] === "(") args = callArgs(code, i + 1);
      else if (/['"]/.test(code[i] ?? "") && /[ \t]$/.test(gap)) args = /^[^\n;]*/.exec(code.slice(i, i + 400))![0];   // Ruby, Perl: FileUtils.rm_rf 'tmp'
      else continue;                                                                                                    // a mention, not a call (fs/promises)
    }
    const target = splitArgs(args)[0] ?? "";
    const literal = literalPath(target);
    // writing or truncating a file only matters for a known system or credential path
    if (/^(writeFileSync|truncateSync)/i.test(m[0]) && literal === undefined && !BROAD_ARG.test(target)) continue;
    const recursive = RECURSIVE_API.test(m[0]) || /recursive\s*[:=]\s*(true|True)|-Recurse/.test(args);
    const sev = BROAD_ARG.test(target) ? "catastrophic" : literal !== undefined ? deletionSeverity([literal], recursive) : "unknown";
    out.push({ sev, target, args, at: m.index! });
  }
  return out;
}
/** Programs that can run commands: only then are their command lines looked for. */
const SPAWN_GATE: Record<string, RegExp> = {
  node: /child_process|\bexeca\b|shelljs|\bzx\b|cross-spawn|Bun\s*\.\s*(spawn|\$)|Deno\s*\.\s*(run|Command)|\$\s*`/,
  python: /\bsubprocess\b|\bos\s*\.\s*(system|popen|exec\w*|spawn\w*)|\bpty\s*\.\s*spawn|\bcommands\s*\.|\bplumbum\b|\bpexpect\b|\bsh\s*\.\s*\w+\s*\(/,
  ruby: /\bsystem\b|\bexec\b|\bspawn\b|popen|Open3|`|%x/,
  perl: /\bsystem\b|\bexec\b|\bqx\b|`|\bopen\s*\(?[^;\n]*\|/,
  php: /\b(exec|shell_exec|system|passthru|proc_open|popen)\s*\(|`/,
};
/** Calls that run a command line (their arguments are analyzed), and backtick commands where backticks run one. */
const SPAWN_CALL: Record<string, RegExp> = {
  node: /\b(execSync|execFileSync|spawnSync|exec|execFile|spawn|fork|execa|execaSync|execaCommand|execaCommandSync)\s*\(|(Bun\s*\.\s*)?\$\s*`|\bshell\s*\.\s*exec\s*\(|Bun\s*\.\s*spawn(Sync)?\s*\(|new\s+Deno\s*\.\s*Command\s*\(/g,
  python: /\b(os\s*\.\s*(system|popen|exec\w*|spawn\w*)|subprocess\s*\.\s*\w+|check_output|check_call|Popen|run|call|getoutput|getstatusoutput)\s*\(/g,
  ruby: /\b(system|exec|spawn|IO\s*\.\s*popen|Open3\s*\.\s*\w+)\s*[\(\['"]|%x[\(\[{]|`[^`\n]+`/g,
  perl: /\b(system|exec|qx)\s*[\(\{'"\/]|`[^`\n]+`/g,
  php: /\b(exec|shell_exec|system|passthru|proc_open|popen)\s*\(|`[^`\n]+`/g,
};
/** Placeholders of interpolated values (\${x}, {x}, %s) become an unknown variable for the shell analysis. */
const unknownArgs = (s: string) => s.replace(/\$\{([^{}]*)\}|\{([A-Za-z_][\w.[\]'"()]*)\}|%[sdr]/g, (_m, a?: string, b?: string) => BROAD_ARG.test((a ?? b ?? "").trim()) ? "~" : "$KYTRAL_ARG");
/** Code inside dependency folders: run by tools, not written by the agent; not analyzed (too large, and full of deletions). */
const THIRD_PARTY = /(^|[\\/])(node_modules|site-packages|dist-packages|vendor|\.venv|venv|\.tox|bower_components|\.cargo|\.rustup|\.yarn|\.pnpm-store)[\\/]/;
/**
 * A program run by an interpreter (python x.py, node x.js), and the local modules it imports: a deletion of the root or a
 * home directory, or of a literal path rm would be asked about, counts like the command; deletions of computed paths are
 * routine in programs (temporary files, caches) unless a home or root directory is in sight. The command lines it can
 * run (spawn calls, string literals that start like a command) are analyzed like any command line; only those with known
 * targets count when they are destructive, catastrophic ones always do.
 */
/**
 * The text of a program with the contents of its string literals and its comments blanked (same length, quotes kept):
 * what runs, not what is quoted or explained. A security tool's test data ("rm -rf ~") or a docstring is not a call.
 */
function codeView(text: string, lang: string): string {
  const out = text.split("");
  const blank = (from: number, to: number) => { for (let k = from; k < to && k < out.length; k++) if (out[k] !== "\n") out[k] = " "; };
  const hash = lang !== "node", slashes = lang === "node" || lang === "php";
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const lineComment = (slashes && c === "/" && text[i + 1] === "/") || (hash && c === "#" && (lang !== "perl" || text[i - 1] !== "$"));
    if (lineComment) { const e = text.indexOf("\n", i); const end = e < 0 ? text.length : e; blank(i, end); i = end - 1; continue; }
    if (slashes && c === "/" && text[i + 1] === "*") { const e = text.indexOf("*/", i + 2); const end = e < 0 ? text.length : e + 2; blank(i, end); i = end - 1; continue; }
    if (c === "'" || c === '"' || c === "`") {
      const q = lang === "python" && text.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
      let j = i + q.length;
      for (; j < text.length; j++) {
        if (text[j] === "\\") { j++; continue; }
        if (text.startsWith(q, j)) break;
        if (q.length === 1 && c !== "`" && text[j] === "\n") break;   // an unterminated one-line string (a regex literal's quote)
      }
      blank(i + q.length, j);
      i = j + q.length - 1;
    }
  }
  return out.join("");
}
function analyzeProgram(text: string, lang: string, label: string, path: string, depth: number, rep: ShellReport, level = 0): void {
  if (THIRD_PARTY.test(path)) return;
  const shortArg = (s: string) => s.length > 60 ? s.slice(0, 57) + "..." : s;
  const view = codeView(text, lang);
  for (const c of deletionCalls(text, view)) {
    if (c.sev === "catastrophic" || c.sev === "destructive") hit(rep, c.sev, `${label}: deletes ${shortArg(literalPath(c.target) ?? c.target)}`);
    else if (c.sev === "unknown" && BROAD_LITERAL.test(text.slice(Math.max(0, c.at - 300), c.at) + c.args)) hit(rep, "destructive", `${label}: may delete files under a home or root directory (${shortArg(c.target)})`);
  }
  if (SPAWN_GATE[lang]?.test(text)) {   // the gate reads imports, which are strings
    const inner: ShellReport = { destructive: [], unresolved: [], catastrophic: [] }, checked = new Set<string>();
    const check = (line: string) => { const l = unknownArgs(line).trim(); if (l.length > 1 && !checked.has(l) && checked.size < 2000) { checked.add(l); analyzeShell(l, depth + 1, inner); } };
    /** String literals assigned to a name (cmd = 'rm -rf ~'), for spawn calls that pass the name. */
    const assigned = (name: string) => [...text.matchAll(new RegExp(`(?:^[ \\t]*|\\b(?:const|let|var|my|our|local)\\s+|;\\s*)${name.replace(/\$/g, "\\$")}\\s*(?::[^=\\n]{1,40})?=\\s*(['"\`])((?:(?!\\1)[^\\\\]|\\\\.){1,2000})\\1`, "gm"))]
      .filter(m => view[m.index! + m[0].indexOf(name)] === name[0]).map(m => m[2]);
    for (const m of view.matchAll(SPAWN_CALL[lang])) {
      if (checked.size >= 2000) break;
      const s = m[0], end = m.index! + s.length;
      if (s.endsWith("(")) {
        const args = callArgs(text, end);
        for (const c of codeCommands(args)) check(c);
        // argv lists: ["rm", "-rf", path] -> rm -rf $KYTRAL_ARG
        for (const a of args.matchAll(/\[([^\[\]]{1,800})\]/g)) check(splitArgs(a[1]).map(e => { const l = /^(['"`])((?:(?!\1)[^\\]|\\.)*)\1$/s.exec(e); return BROAD_ARG.test(e) ? "~" : l ? (/[\s'"]/.test(l[2]) ? `'${l[2].replace(/'/g, "")}'` : l[2]) : "$KYTRAL_ARG"; }).join(" "));
        // a command line kept in a variable: execSync(cmd) after cmd = '…'
        for (const id of new Set(callArgs(view, end).match(/(?<![\w$.'"])[A-Za-z_$][\w$]*(?![\w$(])/g) ?? [])) if (!/^(true|false|null|None|undefined|this|self|shell|check|cwd|env|stdio|encoding|text)$/.test(id)) for (const v of assigned(id)) check(v);
      } else if (s.endsWith("`")) { const close = text.indexOf("`", end); check(text.slice(end, close < 0 ? end + 2000 : Math.min(close, end + 2000))); }
      else if (s.startsWith("`")) check(text.slice(m.index! + 1, end - 1));
      else check(/^[^\n;]*/.exec(text.slice(end - 1, end + 2000))![0].replace(/^[(\[{]|[)\]}]$/g, ""));
    }
    for (const f of inner.destructive) {
      const cat = inner.catastrophic?.includes(f);
      if (cat || !f.includes("$?")) hit(rep, cat ? "catastrophic" : "destructive", `${label} running: ${f}`);
    }
  }
  if (level < 6) for (const imp of programImports(text, path, lang, view)) {
    const r = readScript(imp, true);
    if (r?.kind === "text") analyzeProgram(r.text, lang, `${label} > ${shownPath(r.path)}`, r.path, depth, rep, level + 1);
  }
}
/** Is this file written or downloaded by the same command line (echo … > x.sh && bash x.sh, curl -o x.sh …)? */
function writtenByLine(file: string, line: string): boolean {
  const name = unq(file).replace(/^\.[\\/]/, "");
  if (!name || name.length > 200 || !/\w/.test(name)) return false;
  // a redirection, a download, a copy or an extraction that names the file
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const write = new RegExp(`>>?\\s*['"]?(\\./)?${n}\\b|\\b(tee|cp|mv|install|ln|rsync|scp|curl|wget|aria2c|http|xh|tar|unzip|bsdtar|7z|cpio|git|gh|svn|patch|base64|openssl|xxd|dd|sed|awk|perl|python3?|node)\\b[^\\n;|&]*${n}`);
  // an interpreter running the file itself does not write it: python manage.py, node app.js (python gen.py x.sh still writes x.sh)
  const runs = new RegExp(`\\b(python[0-9.]*|node|perl|ruby|php|bash|sh|zsh|deno|bun)\\s+(-\\S+\\s+)*['"]?(\\./)?${n}\\b`, "g");
  return write.test(line.replace(runs, " ")) || (!!vars && write.test(vars.text.replace(runs, " ")));
}
/**
 * find . -name '__pycache__' -exec rm -rf {} +, find . -name '*.pyc' -delete: routine cleanup when it starts inside the
 * project, every test of the expression must hold (no -o, !, parentheses), one of them names a file tools write again,
 * and the only action is -delete or -exec rm [-rf] {}.
 */
function findCleanup(rest: string[]): boolean {
  // global options come before the start points (find -L / … starts at /); following links (-L) leaves the project
  const { starts, expr, follow } = findArgs(rest);
  const inside = (s: string) => { const p = unq(s).replace(/\\/g, "/"); return !!p && !p.includes(VAR) && !/^[\/~$]/.test(p) && !/^[A-Za-z]:/.test(p) && !/(^|\/)\.\.(\/|$)/.test(p); };
  if (follow || !starts.every(inside) || expr.some(a => /^(-o|-or|!|-not|\(|\)|,)$/.test(a))) return false;
  if (!expr.some((a, i) => /^-i?name$/.test(a) && CLEANUP_NAMES.has(unq(expr[i + 1] ?? "").toLowerCase()))) return false;
  const execs = expr.flatMap((a, i) => (/^-(exec|execdir|ok|okdir)$/.test(a) ? [i] : []));
  if (expr.includes("-delete")) return execs.length === 0;
  if (execs.length !== 1 || !/^-exec(dir)?$/.test(expr[execs[0]])) return false;
  // the words of -exec run to the end; without its terminator (another view of the line can lose a +), find does not run
  const tail = expr.slice(execs[0] + 1), words = tail.at(-1) === ";" || tail.at(-1) === "+" ? tail.slice(0, -1) : tail;
  return base(words[0] ?? "") === "rm" && words.at(-1) === "{}" && words.slice(1, -1).every(w => /^-[rRf]+$/.test(w) || w === "--");
}
/**
 * Runs the analysis of a file the command runs. "none": scripts cannot be read here (no working directory: MCP proxy,
 * SDK); "missing": no such file (the command fails); "done": analyzed, or judged unresolved.
 */
function runScript(file: string, lang: "auto" | Lang, label: string, ctx: ArgvCtx, depth: number, rep: ShellReport, args?: string[], mode: VarMode = "fresh", optional = false): "none" | "missing" | "done" {
  if (THIRD_PARTY.test(unq(file).replace(/\\/g, "/"))) return "done";
  const r = readScript(file);
  if (!r) return "none";
  if (r.kind === "seen") return "done";
  if (r.kind === "missing") {
    // written by this same command before it runs it: its content is known
    const content = vars?.written.get(fileKey(file));
    if (content !== undefined) {
      const language = lang === "auto" ? scriptLanguage(content) : lang;
      if (language === "shell") analyzeRun(content, label, depth, rep, { mode, args, inline: true });
      else if (language === "cron") analyzeRun(cronCommands(content), label, depth, rep, { perLine: true, inline: true });
      else if (language === "powershell") analyzeWindowsRun(content, label, rep);
      else if (language !== "other") analyzeProgram(content, language, label, unq(file), depth, rep);
      return "done";
    }
    if (writtenByLine(file, ctx.line)) {
      // echo 'rm -rf ~' > x.sh && bash x.sh: what the line writes is analyzed as the script; anything else stays unknown
      const inner: ShellReport = { destructive: [], unresolved: [], catastrophic: [] };
      for (const c of codeCommands(ctx.line)) analyzeShell(c, depth + 1, inner);
      for (const f of inner.destructive) hit(rep, inner.catastrophic?.includes(f) ? "catastrophic" : "destructive", `${f} (${label}, written by the same command)`);
      rep.unresolved.push(`${label}: runs a script written or downloaded by the same command`);
      return "done";
    }
    // an earlier command of the line may write it (python gen.py && python out.py, make && ./bin/app, a build then node
    // dist/x.js): unknown. Alone on its line, a missing script only makes the command fail; an optional file (a git hook,
    // the module of python -m) that is not there runs nothing.
    const at = ctx.line.indexOf(unq(file).replace(/^\.[\\/]/, ""));
    if (!optional && (ctx.cond || ctx.piped || (at > 0 && /[;&|\n]/.test(ctx.line.slice(0, at))))) {
      rep.unresolved.push(`${label}: runs a file that does not exist yet (an earlier command of the line may write it)`);
      return "done";
    }
    return "missing";
  }
  if (r.kind === "text" && THIRD_PARTY.test(r.path)) return "done";
  const ext = /\.(ps1|psm1|bat|cmd)$/i.exec(r.kind === "text" ? r.path : unq(file))?.[1]?.toLowerCase();
  const language = ext ? "powershell" : lang === "auto" ? r.kind === "text" ? scriptLanguage(r.text) : "shell" : lang;
  if (r.kind === "unreadable") {
    // a shell script nobody can read is unknown; a program is analyzed on a best-effort basis (a bundle, a binary);
    // source "$X" (no path at all) is a name nobody can know, like before scripts were read
    if (/not known statically/.test(r.why) && !pathLike(file)) return "done";
    if ((language === "shell" || language === "powershell" || language === "cron") && !(lang === "auto" && /binary/.test(r.why))) rep.unresolved.push(`${label}: cannot analyze the script, ${r.why}`);
    return "done";
  }
  inScript(r.path, () => {
    if (language === "shell") analyzeRun(r.text, label, depth, rep, { mode, args });
    else if (language === "cron") analyzeRun(cronCommands(r.text), label, depth, rep, { perLine: true });
    else if (language === "powershell") analyzeWindowsRun(r.text, label, rep);
    else if (language !== "other") analyzeProgram(r.text, language, label, r.path, depth, rep);
  });
  return "done";
}
/**
 * The package.json scripts a package manager or monorepo runner runs, the folder to look for package.json from, and
 * whether workspace packages run too (npm -w, pnpm --filter / -r, yarn workspace, turbo, lerna, nx run-many).
 */
function packageRun(cmd: string, rest: string[]): { dir: string; names: string[]; label: string; workspaces: boolean } | null {
  const life = (n: string) => [`pre${n}`, n, `post${n}`];
  if (cmd === "turbo" || cmd === "lerna") {
    const p = positionals(rest, ["--filter", "-F", "--scope", "--ignore", "--concurrency", "--cache-dir", "--team", "--token", "--graph"]);
    const names = (p[0] === "run" || p[0] === "exec" ? p.slice(1) : p).filter(n => !/[\\/]/.test(n));
    return p[0] === "exec" || !names.length ? null : { dir: ".", names: names.flatMap(life), label: `${cmd} run ${names.join(" ")}`, workspaces: true };
  }
  if (cmd === "nx") {
    const p = positionals(rest, ["-p", "--projects", "--exclude", "--parallel", "-c", "--configuration"]);
    const t = p[0] === "run-many" || p[0] === "affected" ? optValues(rest, ["-t", "--target", "--targets"]).flatMap(v => v.split(",")) : p[0] === "run" ? [p[1]?.split(":")[1] ?? ""] : p[0] ? [p[0]] : [];
    const names = t.filter(Boolean);
    return names.length ? { dir: ".", names: names.flatMap(life), label: `nx ${names.join(" ")}`, workspaces: true } : null;
  }
  if (!/^(npm|pnpm|yarn|bun)$/.test(cmd)) return null;
  const dir = optValues(rest, ["--prefix", "-C", "--dir", "--cwd"])[0] ?? ".";
  const ws = rest.some(a => /^(-w|--workspace|--workspaces|-ws|--filter|-F|-r|--recursive|--include-workspace-root)(=|$)/.test(a)) || /^(--filter|-F)./.test(rest.find(a => a.startsWith("-F") || a.startsWith("--filter")) ?? "");
  let p = positionals(rest, ["--prefix", "-C", "--dir", "--cwd", "-w", "--workspace", "--filter", "-F"]);
  let workspaces = ws;
  if (cmd === "yarn" && p[0] === "workspace") { p = p.slice(2); workspaces = true; }
  else if (cmd === "yarn" && p[0] === "workspaces" && p[1] === "foreach") { p = positionals(p.slice(2), ["--from", "--include", "--exclude", "-j", "--jobs"]); workspaces = true; }
  const install = ["preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare"];
  const sub = p[0];
  if (sub === undefined) return cmd === "yarn" ? { dir, names: install, label: "yarn install", workspaces: true } : null;
  if (/^(run|run-script|rum|urn)$/.test(sub)) return p[1] ? { dir, names: life(p[1]), label: `${cmd} run ${p[1]}`, workspaces } : null;
  if (/^(test|t|tst|start|stop|restart)$/.test(sub)) { const n = sub.startsWith("t") ? "test" : sub; return { dir, names: life(n), label: `${cmd} ${n}`, workspaces }; }
  // an install runs the project's (and its workspace packages') lifecycle scripts; adding a package runs that package's
  if (/^(install|i|in|ins|inst|insta|instal|isnt|isntall|ci|clean-install|add)$/.test(sub)) return p.length === 1 ? { dir, names: install, label: `${cmd} ${sub}`, workspaces: true } : null;
  if (cmd !== "npm" && !JS_BUILTINS[cmd as "pnpm" | "yarn" | "bun"].has(sub)) return { dir, names: life(sub), label: `${cmd} ${sub}`, workspaces };
  return null;
}
/** `label` of a package script: `npm run x: script 'x'` (with the package folder for workspace packages). */
function pkgLabel(label: string, file: string, name: string): string {
  const where = shownPath(file).replace(/(^|\/)package\.json$/, "");
  return `${label}: script '${name}'${where && !/^[A-Za-z]:|^\//.test(where) ? ` in ${where}` : ""}`;
}

function checkArgv(argv: string[], ctx: ArgvCtx, depth: number, rep: ShellReport): void {
  if (depth > 8) return;
  let i = 0;
  // Reserved words: the command after if / then / do / ... is a command; loop, case and function bodies run conditionally.
  for (; i < argv.length; i++) {
    const w = argv[i];
    if (w === "for" || w === "select" || w === "case") { if (!ctx.split) nestUp(); return; }   // for x in …, case $x in: data
    if (w === "function") { i++; continue; }                                                  // function name { …
    if (!/^(if|while|until|then|else|elif|do|!|coproc|fi|done|esac|\{|\})$/.test(w)) break;
    if (ctx.split) continue;
    if (/^(if|while|until|\{)$/.test(w)) nestUp(); else if (/^(fi|done|esac|\})$/.test(w)) nestDown();
  }
  // Assignments (VAR=value) and wrappers (sudo, env, timeout 10, nice -n 5, xargs -I{} ...) before the command.
  const env: Record<string, string> = {}; let viaStdin = !!ctx.viaStdin, wrapped = false;
  for (;;) {
    if (i >= argv.length) {
      // VAR=value alone: a shell variable from now on
      if (!ctx.split && !wrapped) for (const [k, v] of Object.entries(env)) assignVar(k, v, !!ctx.cond);
      return;
    }
    const m = /^([A-Za-z_]\w*)=([\s\S]*)$/.exec(argv[i]);
    if (m) { env[m[1]] = m[2]; if (EXEC_ENV.test(m[1]) && m[2].trim()) analyzeShell(m[2], depth + 1, rep); i++; continue; }
    const name = base(argv[i]);
    if (name === "su" || name === "runuser" || name === "sg") {     // su [user] -c 'cmd' | runuser -u user -- cmd | sg group -c 'cmd'
      const rest = argv.slice(i + 1);
      for (const c of optValues(rest, ["-c", "--command"])) analyzeShell(c, depth + 1, rep);
      const k = rest.indexOf("--"); if (k >= 0) checkArgv(rest.slice(k + 1), ctx, depth + 1, rep);
      return;
    }
    const w = Object.hasOwn(WRAPPERS, name) ? WRAPPERS[name] : undefined; if (!w) break;
    i++; wrapped = true; if (w.stdin) viaStdin = true;
    while (i < argv.length && argv[i].startsWith("-") && argv[i] !== "-") {
      const o = argv[i++]; if (o === "--") break;
      const eq = o.indexOf("="), key = eq > 0 ? o.slice(0, eq) : o;
      if (w.shell?.includes(key)) { const v = eq > 0 ? o.slice(eq + 1) : argv[i++]; if (v !== undefined) analyzeShell(v, depth + 1, rep); }
      else if (eq < 0 && w.value?.includes(o)) i++;
    }
    i += w.operands ?? 0;
    if (w.joins) { if (i < argv.length) analyzeShell(argv.slice(i).join(" "), depth + 1, rep); return; }
    if (w.each) { for (const s of argv.slice(i)) analyzeShell(s, depth + 1, rep); return; }
  }
  const word = argv[i]; const rest = argv.slice(i + 1);
  // brace expansion in command position: {rm,-rf,/} -> rm -rf /
  const brace = /^\{([^{}]*)\}$/.exec(word);
  if (brace?.[1].includes(",")) return checkArgv([...brace[1].split(","), ...rest], { ...ctx, viaStdin }, depth, rep);
  if (word.includes(VAR) || /[`]|\$\(/.test(word) || braceList(word)) {
    // $DRY_RUN rm -rf "$dir", ${SUDO} apt-get …: a prefix variable (empty, echo, sudo) before the real command,
    // which is analyzed as if the variable were empty
    if (word === VAR && /^[\w][\w.\/+-]*$/.test(rest[0] ?? "") && !ctx.split) return checkArgv(rest, { ...ctx, viaStdin }, depth + 1, rep);
    // Expansion in command position. Prose such as "$5 off today" or "`npm test` runs…" has no shell-looking
    // arguments, so it is only flagged when an argument looks like an option or a path.
    if (rest.some(a => /^[-\/~.]|\u0001/.test(a)) || rest.length === 0 && /\u0001|\$\(/.test(word) && /[;|&]/.test(ctx.line))
      rep.unresolved.push(`unresolved command word '${word.split(VAR).join("$?")}'${rest.some(a => /^(\/\*?|~\/?\*?|\/(home|Users|root)\/?\*?|[A-Za-z]:[\\\/]?\*?)$/.test(unq(a))) ? " on a broad path" : ""}`);
    return;
  }
  const cmd = base(word).replace(/\.exe$/i, "");
  if (cmd === "cd" || cmd === "pushd" || cmd === "popd" || cmd === "chdir") {
    if (!ctx.split) changeScriptDir(cmd === "popd" ? null : positionals(rest).filter(a => a !== "-L" && a !== "-P")[0]);
    return;
  }
  if (/^(export|readonly|local|declare|typeset)$/.test(cmd)) {
    if (!ctx.split) for (const a of rest) { const m = /^([A-Za-z_]\w*)=([\s\S]*)$/.exec(a); if (m) assignVar(m[1], m[2], !!ctx.cond); }
    return;
  }
  // trap 'cmd' EXIT: the handler is a command line the shell runs later
  if (cmd === "trap") { const p = rest.filter(a => !/^-[lpP]$/.test(a) && a !== "--"); if (p.length > 1 && p[0] && p[0] !== "-") analyzeShell(p[0], depth + 1, rep, "inherit"); return; }
  if ((cmd === "at" || cmd === "batch") && rest.includes("-f")) { const f = optValues(rest, ["-f"])[0]; if (f) runScript(f, "shell", `${cmd} -f ${f}`, ctx, depth, rep); return; }
  if (cmd === "crontab" && !rest.some(a => /^-[lre]$/.test(a))) {
    const f = positionals(rest, ["-u"]).filter(a => a !== "-")[0];
    if (f) { if (runScript(f, "cron", `crontab ${f}`, ctx, depth, rep) === "none") rep.unresolved.push(`crontab ${f}: installs a crontab nobody can read beforehand`); return; }
  }
  const sub: ArgvCtx = { ...ctx, viaStdin, producer: undefined };
  // What package managers and make run: their scripts are commands too.
  const pkg = packageRun(cmd, rest);
  if (pkg) {
    const all = packageScripts(pkg.dir, pkg.workspaces);
    for (const { file, scripts } of all ?? []) for (const n of pkg.names) if (Object.hasOwn(scripts, n)) inScript(file, () => analyzeRun(scripts[n], pkgLabel(pkg.label, file, n), depth, rep));
  }
  if (cmd === "make" || cmd === "gmake") {
    // make -n prints recipes without running them, except the lines marked +
    const dry = rest.some(a => /^(-n|--dry-run|--just-print|--recon|-q|--question|-t|--touch)$/.test(a));
    const dir = optValues(rest, ["-C", "--directory"])[0] ?? ".", file = optValues(rest, ["-f", "--file", "--makefile"])[0];
    const words = positionals(rest, ["-C", "--directory", "-f", "--file", "--makefile", "-j", "--jobs", "-l", "--load-average", "-o", "-W", "-I", "--include-dir", "--eval", "-E", "--old-file", "--what-if", "--new-file", "--assume-new", "--assume-old"]);
    const assigns = Object.fromEntries(words.filter(w => /^[A-Za-z_][\w.-]*=/.test(w)).map(w => [w.slice(0, w.indexOf("=")), w.slice(w.indexOf("=") + 1)]));
    const targets = words.filter(w => !w.includes("="));
    const m = makeRecipes(targets, file, assigns, dir, optValues(rest, ["--eval", "-E"]));
    if (m) {
      if ("error" in m) rep.unresolved.push(`make: cannot analyze the makefile, ${m.error}`);
      else inScript(m.file, () => analyzeRun(m.lines.filter(l => !dry || l.forced).map(l => l.text).join("\n"), `make ${targets.join(" ") || "(default target)"} in ${shownPath(m.file)}`, depth, rep, { perLine: true }));
      return;
    }
  }
  if (cmd === "just") {
    const dir = optValues(rest, ["-d", "--working-directory"])[0] ?? ".", file = optValues(rest, ["-f", "--justfile"])[0];
    if (!rest.some(a => /^(-l|--list|--summary|--show|-s|--dump|--evaluate|--fmt|--init|--choose|--variables|--help|-h|--version|-V|--dry-run|-n)$/.test(a))) {
      const words = positionals(rest, ["-d", "--working-directory", "-f", "--justfile", "--set", "--shell", "--shell-arg", "--dotenv-filename", "--dotenv-path", "--color", "--command-color", "--list-heading", "--list-prefix"]);
      const j = justRecipes(words.filter(w => !/^[A-Za-z_][\w-]*=/.test(w)), file, dir);
      if (j) {
        if ("error" in j) rep.unresolved.push(`just: cannot analyze the justfile, ${j.error}`);
        else inScript(j.file, () => { for (const b of j.bodies) {
          const label = `just ${words.join(" ") || "(default recipe)"} in ${shownPath(j.file)}`;
          const lang = b.kind === "script" ? scriptLanguage(b.text) : "shell";
          if (lang === "shell") analyzeRun(b.text, label, depth, rep, { perLine: b.kind === "shell" }); else if (lang !== "other") analyzeProgram(b.text, lang, label, j.file, depth, rep);
        } });
        return;
      }
    }
  }
  if (cmd === "task" || cmd === "go-task") {
    const dir = optValues(rest, ["-d", "--dir"])[0] ?? ".", file = optValues(rest, ["-t", "--taskfile"])[0];
    if (!rest.some(a => /^(-l|--list|-a|--list-all|--summary|-n|--dry|--help|-h|--version|--init|-i)$/.test(a))) {
      const words = positionals(rest, ["-d", "--dir", "-t", "--taskfile", "-o", "--output", "-c", "--color", "-C", "--concurrency", "--interval", "--sort"]);
      const t = taskCommands(words.filter(w => !w.includes("=") && w !== "--"), file, dir);
      if (t) {
        if ("error" in t) rep.unresolved.push(`task: cannot analyze the Taskfile, ${t.error}`);
        else inScript(t.file, () => analyzeRun(t.lines.join("\n"), `task ${words.join(" ") || "default"} in ${shownPath(t.file)}`, depth, rep, { perLine: true }));
        return;
      }
    }
  }
  // A script run by its path (./deploy.sh, scripts/clean, ~/bin/x): its content, by its shebang. The catalog still sees its name.
  if (/^[\w.~\/\\:+@,=-]+$/.test(word) && /\w/.test(word) && !/[\\/]$/.test(word) && (/^(\.{1,2}[\\/]|[\\/~]|[A-Za-z]:[\\/])/.test(word) || (/[\\/]/.test(word) && !/^[a-z][\w+.-]*:\/\//i.test(word)))) runScript(word, "auto", word, ctx, depth, rep, rest);
  // Runners (npx prisma ..., pnpm exec ..., bundle exec ...) and remote / container execution (ssh, docker exec, kubectl exec).
  const target = runnerTarget(cmd, rest);
  if (target) {
    // uv run x.py, bun x.ts, pipx run x.py: a program file named directly
    const lang = /\.py$/i.test(target[0] ?? "") ? "python" : /\.(m?[jt]s|c[jt]s|[jt]sx)$/i.test(target[0] ?? "") ? "node" : undefined;
    return checkArgv(lang ? [lang, ...target] : target, sub, depth + 1, rep);
  }
  if (cmd === "ssh" || cmd === "autossh" || cmd === "mosh") {
    const p = positionals(rest, SSH_VALUE_OPTS);
    if (p.length > 1) withoutScripts(() => analyzeShell(p.slice(1).join(" "), depth + 1, rep));
    return;
  }
  if (/^(docker|podman|nerdctl|kubectl|oc)$/.test(cmd)) {
    const k = rest.indexOf("exec");
    if (k >= 0 && (k === 0 || (rest[k - 1] === "compose" && k === 1) || positionals(rest.slice(0, k), EXEC_VALUE_OPTS).length === 0)) {
      const tail = rest.slice(k + 1), dd = tail.indexOf("--");
      // kubectl exec POD [-c C] -- CMD...; docker exec [OPTIONS] CONTAINER CMD... (the command keeps its own options)
      let j = 0; while (j < tail.length && tail[j].startsWith("-") && tail[j] !== "--") { if (EXEC_VALUE_OPTS.includes(tail[j])) j++; j++; }
      const inner = dd >= 0 && /^(kubectl|oc)$/.test(cmd) ? tail.slice(dd + 1) : tail.slice(j + 1);
      return withoutScripts(() => checkArgv(inner, sub, depth + 1, rep));
    }
    const r = rest.findIndex(a => a === "run" || a === "create");
    if (/^(docker|podman|nerdctl)$/.test(cmd) && r >= 0 && positionals(rest.slice(0, r), ["-H", "--host", "--context", "-c", "--config"]).length === 0) return withoutScripts(() => containerRun(cmd, rest.slice(r + 1), sub, depth, rep));
  }
  if (cmd === "gcloud" && rest.includes("ssh")) { withoutScripts(() => { for (const c of optValues(rest, ["--command"])) analyzeShell(c, depth + 1, rep); }); return; }
  if (cmd === "vagrant" && rest[0] === "ssh") { withoutScripts(() => { for (const c of optValues(rest, ["-c", "--command"])) analyzeShell(c, depth + 1, rep); }); return; }
  if (cmd === "wsl") { const k = rest.findIndex(a => a === "-e" || a === "--exec" || a === "--"); if (k >= 0) checkArgv(rest.slice(k + 1), sub, depth + 1, rep); return; }
  if (cmd === "nix-shell") { for (const c of optValues(rest, ["--run", "--command"])) analyzeShell(c, depth + 1, rep); return; }
  if (cmd === "script") { for (const c of optValues(rest, ["-c", "--command"])) analyzeShell(c, depth + 1, rep); return; }
  if (cmd === "flock") {   // flock [options] file -c 'cmd' | flock [options] file cmd [args]
    const cs = optValues(rest, ["-c", "--command"]);
    if (cs.length) { for (const c of cs) analyzeShell(c, depth + 1, rep); return; }
    const p = positionals(rest, ["-w", "--timeout", "-E", "--conflict-exit-code"]);
    if (p.length > 1) checkArgv(rest.slice(rest.indexOf(p[1])), sub, depth + 1, rep);
    return;
  }
  // Fleet tools that run a shell command on many hosts at once.
  if (cmd === "ansible") { withoutScripts(() => { for (const c of optValues(rest, ["-a", "--args"])) analyzeShell(c, depth + 1, rep); }); return; }
  if (cmd === "salt" || cmd === "salt-ssh") { const p = positionals(rest, ["-t", "--timeout", "-G", "--grain", "-N", "--nodegroup", "-L", "--list"]); const k = p.findIndex(x => /^cmd\.(run|shell|script|exec_code)/.test(x)); if (k >= 0) withoutScripts(() => { for (const c of p.slice(k + 1)) analyzeShell(c, depth + 1, rep); }); return; }
  if (/^(pdsh|pssh|parallel-ssh|clush|mussh)$/.test(cmd)) { for (const c of positionals(rest, ["-w", "-g", "-x", "-h", "-H", "-l", "-p", "-t", "-o", "-e", "-O", "-x", "-f", "-R"])) withoutScripts(() => analyzeShell(c, depth + 1, rep)); return; }
  if (cmd === "alias" && rest.some(a => a.includes("="))) { rep.unresolved.push("alias"); return; }
  if ((cmd === "source" || cmd === ".") && rest[0]) {
    if (procSubst(rest[0])) { runOutput(rest[0], "shell", cmd, ctx, depth, rep); return; }
    if (ENV_SCRIPT.test(unq(rest[0]).replace(/\\/g, "/")) && !/(^|\/)(\.env(\.[\w-]+)?|\.envrc|env)$/.test(unq(rest[0]))) return;
    const r = runScript(rest[0], "shell", `source ${rest[0]}`, ctx, depth, rep, rest.length > 1 ? rest.slice(1) : undefined, "shared");
    if (r === "none" && pathLike(rest[0])) rep.unresolved.push("source");
    if (r === "none" || r === "missing" || !pathLike(rest[0])) { /* a name looked up in PATH, or a file that is not there: nothing runs */ }
    return;
  }
  if (ctx.piped && STDIN_RUNNERS.test(cmd) && stdinIsProgram(cmd, rest)) { rep.unresolved.push(`script piped into ${cmd}`); return; }
  if (cmd === "eval") {
    const t = rest.join(" ");
    const init = /^\u0001VAR\u0001([\w.-]+)\u0001$/.exec(t.trim());   // eval "$(ssh-agent -s)": a shell-init idiom
    if (init && INIT_TOOLS.test(init[1])) return;
    if (t.includes(VAR)) rep.unresolved.push("eval of expansion"); else if (depth < 4) analyzeShell(t, depth + 1, rep, "shared");
    return;
  }
  if (SHELLS.test(cmd)) {
    const k = rest.indexOf("-c");
    if (k >= 0) { if (depth < 4) analyzeShell(rest.slice(k + 1).join(" "), depth + 1, rep); return; }
    const file = positionals(rest, ["-o", "+o", "-O", "+O", "--rcfile", "--init-file"])[0];
    if (file && procSubst(file)) runOutput(file, "shell", cmd, ctx, depth, rep);
    else if (file && file !== "-" && !ctx.piped) runScript(file, "shell", `${cmd} ${file}`, ctx, depth, rep, rest.slice(rest.indexOf(file) + 1));
    return;
  }
  if (cmd === "pwsh" || cmd === "powershell") {
    const f = rest.findIndex(a => /^-(f|file)$/i.test(a));
    if (f >= 0 && rest[f + 1]) { runScript(rest[f + 1], "powershell", `${cmd} -File ${rest[f + 1]}`, ctx, depth, rep); return; }
    const k = rest.findIndex(a => /^-(c|command|encodedcommand|ec|e)$/i.test(a));
    if (k >= 0) {
      const code = /^-(encodedcommand|ec|e)$/i.test(rest[k]) ? decodeUtf16(rest[k + 1] ?? "") : rest.slice(k + 1).join(" ");
      const w = analyzeWindows(code);
      for (const f of w.catastrophic ?? []) hit(rep, "catastrophic", f);
      for (const f of w.destructive) if (!(w.catastrophic ?? []).includes(f)) hit(rep, "destructive", f);
      rep.unresolved.push(...w.unresolved);
    }
    return;
  }
  // A script run by an interpreter: its name is the command (python manage.py flush, php artisan migrate:fresh, node ace ...).
  const iflags = INTERP[cmd] ?? INTERP[cmd.replace(/[\d.]+$/, "")];
  const codeAt = iflags ? rest.findIndex(a => iflags.includes(a) || iflags.includes(a.toLowerCase()) || iflags.some(f => f.startsWith("--") && a.toLowerCase().startsWith(f + "="))
    || (CLUSTER[cmd] ?? CLUSTER[cmd.replace(/[\d.]+$/, "")])?.test(a)) : -1;
  if (SCRIPT_HOSTS.test(cmd) && codeAt < 0) {
    const mod = optValues(rest, ["-m"])[0];
    if (cmd.startsWith("python") && mod) {
      const k = rest.indexOf(mod); const f = catalogFinding(mod === "django" ? "django-admin" : mod, rest.slice(k + 1), env); if (f) hit(rep, f.sev, f.what);
      // a module of the project: python -m tools.cleanup runs tools/cleanup.py (or tools/cleanup/__main__.py)
      const p = mod.replace(/\./g, "/");
      // (optional files: python -m pytest is an installed module when the project has no pytest.py)
      if (/^[\w.]+$/.test(mod) && runScript(`${p}.py`, "python", `${cmd} -m ${mod}`, ctx, depth, rep, undefined, "fresh", true) === "missing") runScript(`${p}/__main__.py`, "python", `${cmd} -m ${mod}`, ctx, depth, rep, undefined, "fresh", true);
    }
    const script = positionals(rest, ["-m", "-W", "-X", "-c", "-e", "-r", "-d", "-I", "--require", "--import", "--loader", "-C", "--conditions", "--env-file"])[0];
    if (script && !mod) {
      const f = catalogFinding(base(script), rest.slice(rest.indexOf(script) + 1), env); if (f) hit(rep, f.sev, f.what);
      const t = runnerTarget(base(script), rest.slice(rest.indexOf(script) + 1)); if (t) checkArgv(t, sub, depth + 1, rep);
      // deno run x.ts / bun run x.ts: the program is the next word
      const prog = (cmd === "deno" || cmd === "bun") && script === "run" ? positionals(rest.slice(rest.indexOf(script) + 1))[0] : script;
      const lang = cmd.startsWith("python") ? "python" : /^(node|nodejs|bun|deno)$/.test(cmd) ? "node" : cmd === "ruby" ? "ruby" : cmd === "perl" ? "perl" : "php";
      if (prog && procSubst(prog)) runOutput(prog, lang, cmd, ctx, depth, rep);
      else if (prog && pathLike(prog)) runScript(prog, lang, `${cmd} ${prog}`, ctx, depth, rep);
    }
  }
  if (/^(tsx|ts-node|ts-node-esm|esno|esrun|vite-node|zx)$/.test(cmd)) {
    const prog = positionals(rest, ["--tsconfig", "-P", "--project", "-r", "--require", "--import"])[0];
    if (prog && pathLike(prog)) runScript(prog, "node", `${cmd} ${prog}`, ctx, depth, rep);
    return;
  }
  const awkCode = AWK.test(cmd) && !rest.some(a => a === "-f" || a.startsWith("--file")) ? positionals(rest, ["-v", "-F", "--assign", "--field-separator"])[0] : undefined;
  if (codeAt >= 0 || awkCode !== undefined) {
    const a0 = codeAt >= 0 ? rest[codeAt] : "", eq = a0.indexOf("=");
    const code = awkCode ?? [...(eq > 0 && a0.startsWith("--") ? [a0.slice(eq + 1)] : []), ...rest.slice(codeAt + 1)].join(" ");
    const label = `${cmd} one-liner`;
    if (DELETE_API.test(code)) {
      // judged by their targets: fs.rmSync('dist', …) is the cleanup rm -rf dist is; a computed target is unknown
      const calls = deletionCalls(code), broad = BROAD_LITERAL.test(code);
      const sev = !calls.length ? (broad ? "catastrophic" : "destructive")
        : calls.some(c => c.sev === "catastrophic") || (broad && calls.some(c => c.sev === "unknown")) ? "catastrophic"
        : calls.some(c => c.sev === "destructive" || c.sev === "unknown") ? "destructive" : null;
      if (sev) hit(rep, sev, `${label} deleting files`);
    }
    if (SPAWN_API.test(code)) {
      // The command lines it runs are analyzed like any other: os.system('rm -rf ~') is a catastrophe, not just "unresolved".
      const inner: ShellReport = { destructive: [], unresolved: [], catastrophic: [] };
      for (const c of codeCommands(code)) analyzeShell(c, depth + 1, inner);
      for (const f of inner.destructive) hit(rep, inner.catastrophic?.includes(f) ? "catastrophic" : "destructive", `${label} running: ${f}`);
      if (!inner.destructive.length) rep.unresolved.push(`${label} spawning processes`);
    }
    return;
  }
  if (iflags) return;
  const d = (what: string, sev: Severity = "destructive") => { hit(rep, sev, what); };
  const ops = positionals(rest);
  if (cmd === "rm") {
    const recursive = hasFlag(rest, "r", ["--recursive"]) || hasFlag(rest, "R");
    if (rest.includes("--no-preserve-root")) return d("rm --no-preserve-root", "catastrophic");
    // Targets read from stdin (xargs) or given by find ({}) are judged by what produces them; known targets by themselves.
    const known = ops.filter(o => o !== "{}" && o !== "{}+");
    const unknown = (ops.length === 0 && viaStdin) || known.length < ops.length;
    const sevKnown = deletionSeverity(known, recursive), sevUnknown = unknown ? producerSeverity(ctx.producer, recursive) : null;
    const sev = sevKnown === "catastrophic" || sevUnknown === "catastrophic" ? "catastrophic" : sevKnown ?? sevUnknown;
    if (sev) return d(`rm${recursive ? " -r" : ""} ${ops.map(o => o.split(VAR).join("$?")).join(" ") || "(targets from stdin)"}`.trim(), sev);
    return;
  }
  // A size change only matters outside the project: truncating a log or a build artifact is routine.
  if (cmd === "truncate") { if ((hasFlag(rest, "s", ["--size"]) || rest.some(a => a.startsWith("--size="))) && ops.some(o => criticalPath(o) || /^[\/~]/.test(unq(o)) && !SAFE_REDIRECT.test(unq(o)))) return d("truncate", ops.some(criticalPath) ? "catastrophic" : "destructive"); return; }
  if (cmd === "unlink") { if (rest.some(pathLike)) return d("unlink", ops.some(criticalPath) ? "catastrophic" : "destructive"); return; }
  if (DISK_TOOLS.test(cmd)) {
    if (cmd === "diskutil" && !/^(erase\w*|zero\w*|randomdisk|secureerase|partitiondisk|reformat|apfs)$/i.test(ops[0] ?? "")) return;
    if (cmd === "zpool" && ops[0] !== "destroy") return;
    if (cmd === "badblocks" && !hasFlag(rest, "w")) return;
    if ((cmd === "hdparm" && !rest.some(a => /^--(security-erase|trim-sector-ranges|sanitize)/.test(a))) || (cmd === "nvme" && !/^(format|sanitize)$/.test(ops[0] ?? ""))) return;
    return d(cmd, "catastrophic");
  }
  // macOS: Time Machine backups and snapshots (like vssadmin delete shadows), System Integrity Protection, system services,
  // all the preferences of an app (defaults delete <domain>; one key is routine)
  if (cmd === "tmutil" && /^(delete|deletelocalsnapshots|removedestination|thinlocalsnapshots|deleteinprogress|disable)$/i.test(ops[0] ?? ""))
    return d(`tmutil ${ops[0]}`, /^(delete|deletelocalsnapshots|removedestination)$/i.test(ops[0]) ? "catastrophic" : "destructive");
  if (cmd === "csrutil" && /^(disable|clear)$/i.test(ops[0] ?? "")) return d(`csrutil ${ops[0]}`);
  if (cmd === "launchctl" && /^(unload|bootout|disable|remove)$/i.test(ops[0] ?? "") && rest.some(a => /^\/System\/|^system(\/|$)/.test(unq(a)))) return d(`launchctl ${ops[0]} of a system service`);
  if (cmd === "defaults" && ops[0] === "delete" && ops.length === 2) return d(`defaults delete ${ops[1]}`);
  if (FILE_WIPERS.test(cmd)) return d(cmd, ops.some(o => criticalPath(o) || /^\/dev\//.test(unq(o)) || broadPath(o)) ? "catastrophic" : "destructive");
  const fileOps = rest.filter(a => !a.startsWith("-"));
  // Overwrites only matter on critical files (a project's .env or .npmrc is the project's business).
  if (cmd === "tee" && fileOps.some(a => criticalPath(a) || (/^[\/~]/.test(unq(a)) && !SAFE_REDIRECT.test(unq(a)) && !hasFlag(rest, "a", ["--append"])))) return d("tee onto a system path", fileOps.some(criticalPath) ? "catastrophic" : "destructive");
  if (cmd === "cp" && (fileOps.some(a => /^\/dev\/(null|zero|u?random)$/.test(unq(a))) || (fileOps.length > 1 && criticalPath(fileOps.at(-1)!)))) return d("cp over a system path", fileOps.length > 1 && criticalPath(fileOps.at(-1)!) ? "catastrophic" : "destructive");
  if (cmd === "install" && fileOps.length > 1 && criticalPath(fileOps.at(-1)!)) return d("install over a system path", "catastrophic");
  if (cmd === "sed") {
    if ((hasFlag(rest, "i", ["--in-place"]) || rest.some(a => a.startsWith("--in-place") || /^-i./.test(a))) && fileOps.some(criticalPath)) return d("sed -i on a system path", "catastrophic");
    // GNU sed runs the pattern space as a command with the e command or the s///e flag.
    for (const s of [...optValues(rest, ["-e", "--expression"]), ...fileOps.slice(0, 1)]) {
      const sm = /^s(.)(?:(?!\1)[\s\S]|\\\1)*\1((?:(?!\1)[\s\S]|\\\1)*)\1([a-zA-Z0-9]*)$/.exec(s);
      if ((sm && sm[3].includes("e")) || /(^|;|\n)\s*e(\s|$)/.test(s)) {
        const inner = analyzeShell(sm ? sm[2] : s.replace(/^[\s\S]*?\be\s+/, ""), depth + 1);
        if (inner.destructive.length) inner.destructive.forEach(f => hit(rep, inner.catastrophic?.includes(f) ? "catastrophic" : "destructive", `sed e running: ${f}`));
        else rep.unresolved.push("sed e runs text as a command");
      }
    }
    return;
  }
  if (cmd === "ln") {
    if (hasFlag(rest, "f", ["--force"]) && (fileOps.some(a => unq(a) === "/dev/null") || (fileOps.length && criticalPath(fileOps.at(-1)!)))) return d("ln -f over a system path", "catastrophic");
    // A link to a credential or system file turns a later "harmless" write through the link into an overwrite of it.
    if (hasFlag(rest, "s", ["--symbolic"]) && fileOps.length > 1 && fileOps.slice(0, -1).some(a => criticalPath(a) && !/^\/(usr|bin|sbin|lib\w*|opt|System|Library|Applications)\//.test(unq(a)))) return d("ln -s to a system or credential file");
    return;
  }
  if (cmd === "dd") {
    const of = rest.find(a => a.startsWith("of="))?.slice(3);
    if (of && /^\/dev\/(?!null$|zero$|stdout$|stderr$)/.test(of)) return d("dd of=/dev/*", "catastrophic");
    if (of && criticalPath(of)) return d(`dd of=${of}`, "catastrophic");
    return;
  }
  if (cmd === "find") {
    const execAt = rest.findIndex(a => /^-(exec|execdir|ok|okdir)$/.test(a));
    const execRm = execAt >= 0 && ["rm", "shred", "unlink", "srm", "rmdir"].includes(base(rest[execAt + 1] ?? ""));
    const { starts } = findArgs(rest);
    const filtered = rest.some(a => /^-(i?name|i?path|i?wholename|i?regex|newer\w*|[acm](time|min)|size|user|group|uid|gid|perm|empty|links|inum|samefile|i?lname)$/.test(a));
    const systemWide = starts.some(s => broadPath(s) && !/^\.{1,2}\/?$/.test(unq(s)) && !/^~/.test(unq(s)));
    const sev: Severity = systemWide || (!filtered && starts.some(broadPath)) ? "catastrophic" : "destructive";
    if ((rest.includes("-delete") || execRm) && findCleanup(rest)) return;
    if (rest.includes("-delete") || execRm) return d(`find ${starts.join(" ")} ${execRm ? "-exec rm" : "-delete"}`, sev);
    // Any other -exec command runs once per file found: analyze it like a command of its own. Its words run up to the
    // terminator (; or +): an -exec among them is an argument of that command, and is not scanned again (linear time).
    for (let k = 0; k < rest.length; k++) {
      if (!/^-(exec|execdir|ok|okdir)$/.test(rest[k])) continue;
      let end = -1;
      for (let n = k + 1; n < rest.length; n++) if (rest[n] === ";" || rest[n] === "+" || rest[n] === "\\;") { end = n; break; }
      const inner: ShellReport = { destructive: [], unresolved: [], catastrophic: [] };
      checkArgv(rest.slice(k + 1, end < 0 ? undefined : end), { piped: false, line: ctx.line }, depth + 1, inner);
      for (const f of inner.destructive) hit(rep, inner.catastrophic?.includes(f) || sev === "catastrophic" ? "catastrophic" : "destructive", `find -exec: ${f}`);
      rep.unresolved.push(...inner.unresolved);
      if (end < 0) break;
      k = end;
    }
    return;
  }
  // Recursive permission changes: routine inside the project, destructive on absolute paths, catastrophic on broad ones.
  if (/^(chmod|chown|chgrp|setfacl)$/.test(cmd) && hasFlag(rest, "R", ["--recursive"])) {
    const targets = fileOps.slice(cmd === "setfacl" ? 0 : 1);
    if (targets.some(broadPath)) return d(`${cmd} -R`, "catastrophic");
    if (targets.some(t => /^[\/~]/.test(unq(t)) || unq(t).includes(VAR))) return d(`${cmd} -R`);
    return;
  }
  if (cmd === "rsync" && rest.some(a => /^--(delete|remove-source-files)/.test(a))) return d("rsync --delete", fileOps.length && broadPath(fileOps.at(-1)!) ? "catastrophic" : "destructive");
  if (cmd === "mv") {
    if (fileOps.some(a => /^(\/|\/\*|~\/?|\/(etc|usr|bin|boot|var|home|root|lib\w*|sbin|opt|srv)\/?)$/.test(unq(a))) || unq(fileOps.at(-1) ?? "") === "/dev/null" || (fileOps.length > 1 && criticalPath(fileOps.at(-1)!))) return d("mv of a system path", "catastrophic");
    return;
  }
  if (cmd === "git") return checkGit(rest, sub, depth, rep);
  const f = catalogFinding(cmd, rest, env);
  if (f) { hit(rep, f.sev, f.what); return; }
  // An unknown command followed by a dangerous one is most likely a wrapper we do not know (gosu app rm -rf /, unshare ...,
  // systemd-run ... terraform destroy): analyze from that command on. Not on text commands, nor on split words (quoted text).
  if (!ctx.split && !inCatalog(cmd) && !TEXT_COMMANDS.test(cmd) && !DANGER_START.test(cmd)) {
    const j = rest.findIndex(a => !a.startsWith("-") && DANGER_START.test(base(a)));
    if (j >= 0) checkArgv(rest.slice(j), sub, depth + 1, rep);
  }
}
/** git: global options (-C dir, -c key=value) come before the subcommand; some configuration values are commands git runs. */
/** The client-side hooks each git command runs; --no-verify (and commit -n) skips those in VERIFY_HOOKS. */
const GIT_HOOKS: Record<string, string[]> = {
  commit: ["pre-commit", "prepare-commit-msg", "commit-msg", "post-commit", "post-rewrite"], merge: ["pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-merge"],
  pull: ["pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-merge", "pre-rebase", "post-rewrite", "post-checkout"], push: ["pre-push"],
  checkout: ["post-checkout"], switch: ["post-checkout"], rebase: ["pre-rebase", "post-rewrite", "post-checkout"], am: ["applypatch-msg", "pre-applypatch", "post-applypatch"],
  "cherry-pick": ["prepare-commit-msg", "commit-msg", "post-commit"], revert: ["prepare-commit-msg", "commit-msg", "post-commit"], worktree: ["post-checkout"],
};
const VERIFY_HOOKS = new Set(["pre-commit", "commit-msg", "pre-merge-commit", "pre-push", "applypatch-msg", "pre-applypatch"]);
function checkGit(rest: string[], ctx: ArgvCtx, depth: number, rep: ShellReport): void {
  const d = (what: string, sev: Severity = "destructive") => { hit(rep, sev, what); };
  let k = 0; const config: [string, string][] = [];
  for (; k < rest.length && rest[k].startsWith("-"); k++) {
    const o = rest[k], eq = o.indexOf("=");
    if (o === "-c" && rest[k + 1] !== undefined) { const kv = rest[++k]; const e = kv.indexOf("="); if (e > 0) config.push([kv.slice(0, e), kv.slice(e + 1)]); continue; }
    if (o.startsWith("--config-env")) continue;
    if (GIT_GLOBAL_VALUE.includes(o) && eq < 0) k++;
  }
  // git config alias.nuke '!rm -rf ~', git config core.sshCommand '…': the value is a command git will run later.
  const gsub = rest[k] ?? "", sa = rest.slice(k + 1);
  if (gsub === "config") { const p = sa.filter(a => !a.startsWith("-")); if (p.length >= 2) config.push([p[0], p[1]]); }
  for (const [key, value] of config) if (GIT_EXEC_KEY.test(key) && value.trim()) {
    const inner = analyzeShell(value.replace(/^\s*!/, ""), depth + 1);
    for (const f of inner.destructive) hit(rep, inner.catastrophic?.includes(f) ? "catastrophic" : "destructive", `git ${key} runs: ${f}`);
    rep.unresolved.push(...inner.unresolved);
  }
  // The client-side hooks this command runs (.git/hooks, core.hooksPath, husky) are scripts like any other.
  const hooks = GIT_HOOKS[gsub];
  if (hooks) {
    const noVerify = sa.includes("--no-verify") || ((gsub === "commit" || gsub === "push") && hasFlag(sa, "n"));
    const where = gitHooksDir(optValues(rest.slice(0, k), ["-C"]).at(-1) ?? ".", config.find(([key]) => /^core\.hookspath$/i.test(key))?.[1]);
    if (where) for (const h of hooks) {
      if (noVerify && VERIFY_HOOKS.has(h)) continue;
      const file = where.husky ? join(where.husky, h) : join(where.dir, h);
      runScript(file, where.husky ? "shell" : "auto", `git ${gsub} runs the ${h} hook`, ctx, depth, rep, undefined, "fresh", true);   // a hook that is not there runs nothing
    }
  }
  if (gsub === "clean" && hasFlag(sa, "f", ["--force"])) return d("git clean -f (deletes untracked files)");
  if (gsub === "reset" && sa.includes("--hard")) return d("git reset --hard (discards uncommitted work)");
  if (gsub === "push") {
    const refs = positionals(sa, ["--repo", "-o", "--push-option", "--receive-pack", "--exec"]).slice(1).map(r => r.replace(/^\+/, "").split(":").pop() ?? "");
    const forced = hasFlag(sa, "f", ["--force", "--delete", "--prune"]) || sa.some(a => a.startsWith("--force") || /^\+/.test(a) || /^:/.test(a));
    if (sa.includes("--mirror") || (forced && (sa.includes("--all") || refs.some(r => PROTECTED_BRANCH.test(r))))) return d(`git push ${sa.includes("--mirror") ? "--mirror" : "--force/--delete"} on a shared branch`, "catastrophic");
    if (forced) return d("git push --force/--delete");
    return;
  }
  if (gsub === "branch" && hasFlag(sa, "D")) return d("git branch -D");
  if ((gsub === "checkout" || gsub === "restore") && (sa.includes(".") || hasFlag(sa, "f", ["--force"]))) return d(`git ${gsub} discarding changes`);
  if (gsub === "stash" && (sa[0] === "clear" || sa[0] === "drop")) return d(`git stash ${sa[0]}`);
  if (gsub === "rm" && hasFlag(sa, "r") && !sa.includes("--cached")) return d("git rm -r");
  if (gsub === "gc" && sa.some(a => /^--prune=(now|all)$/.test(a))) return d("git gc --prune=now (drops unreachable commits)");
  if (gsub === "filter-branch" || gsub === "filter-repo" || (gsub === "update-ref" && sa.includes("-d")) || (gsub === "reflog" && sa[0] === "expire")) return d(`git ${gsub}`);
}
/**
 * docker / podman run: a container is a sandbox, unless it mounts the host. With a bind mount (or the Docker socket), the
 * command it runs reaches the host's files: its findings count, and they are catastrophic when the mount is broad (/, ~, /etc).
 */
function containerRun(cmd: string, args: string[], ctx: ArgvCtx, depth: number, rep: ShellReport): void {
  const VALUE = ["-v", "--volume", "--mount", "-e", "--env", "--env-file", "-w", "--workdir", "-u", "--user", "--name", "-p", "--publish", "--network", "--net",
    "--entrypoint", "-l", "--label", "--platform", "--hostname", "-h", "--cpus", "-m", "--memory", "--restart", "--pull", "--gpus", "--device", "--add-host", "--dns",
    "--cap-add", "--cap-drop", "--security-opt", "--tmpfs", "--ulimit", "--log-driver", "--log-opt", "--pid", "--ipc", "--uts", "--userns", "--shm-size",
    "--stop-signal", "--stop-timeout", "-a", "--attach", "--cidfile", "--volumes-from", "--link", "--runtime", "--isolation", "--health-cmd", "--group-add", "--expose"];
  let k = 0; const mounts: string[] = []; let entry: string | undefined;
  for (; k < args.length; k++) {
    const a = args[k], eq = a.indexOf("="), key = eq > 0 ? a.slice(0, eq) : a;
    if (!a.startsWith("-")) break;
    const v = eq > 0 ? a.slice(eq + 1) : VALUE.includes(a) ? args[++k] : undefined;
    if ((key === "-v" || key === "--volume") && v) mounts.push(v.split(":")[0]);
    else if (key === "--mount" && v) { const src = /(?:^|,)(?:source|src)=([^,]+)/.exec(v)?.[1]; if (src && /type=bind/.test(v)) mounts.push(src); }
    else if (key === "--entrypoint" && v) entry = v;
    else if (/^-v./.test(a)) mounts.push(a.slice(2).split(":")[0]);
  }
  if (!mounts.length) return;
  const command = [...(entry ? [entry] : []), ...args.slice(k + 1)];
  if (!command.length) return;
  const inner: ShellReport = { destructive: [], unresolved: [], catastrophic: [] };
  checkArgv(command, { piped: false, line: ctx.line }, depth + 1, inner);
  const broad = mounts.some(m => broadPath(m) || /docker\.sock$/.test(m) || /^\/(etc|var|usr|home|Users|root|opt|srv|mnt|media)\/?$/.test(unq(m)));
  for (const f of inner.destructive) hit(rep, broad || inner.catastrophic?.includes(f) ? "catastrophic" : "destructive", `${cmd} run with ${mounts.join(", ")} mounted: ${f}`);
  rep.unresolved.push(...inner.unresolved);
}
/** PowerShell -EncodedCommand: base64 of UTF-16LE. */
function decodeUtf16(b64: string): string { try { return Buffer.from(b64, "base64").toString("utf16le"); } catch { return ""; } }

/** Text a pipeline feeds into a shell or interpreter: echo 'rm -rf ~' | sh, echo cm0gLXJmIH4= | base64 -d | bash, printf '…' | xxd -r -p | sh. */
function pipedScript(stages: string[][]): string | undefined {
  if (stages.length < 1) return undefined;
  const first = stages[0], b0 = base(first[0] ?? "");
  if (!/^(echo|printf)$/.test(b0)) return undefined;
  let data = first.slice(1).filter(a => !/^-[neE]+$/.test(a)).join(" ");
  // printf (and echo -e) interpret escapes: printf '\x72\x6d\x20…' | sh
  if (b0 === "printf" || first.slice(1).some(a => /^-[nE]*e[nE]*$/.test(a)))
    data = data.replace(/\\(x[0-9a-fA-F]{1,2}|0?[0-7]{1,3}|u[0-9a-fA-F]{4}|[ntr\\])/g, (_m, e: string) =>
      e[0] === "x" || e[0] === "u" ? String.fromCharCode(parseInt(e.slice(1), 16)) : /^[0-7]/.test(e) ? String.fromCharCode(parseInt(e, 8)) : ({ n: "\n", t: "\t", r: "\r", "\\": "\\" } as Record<string, string>)[e]);
  for (const s of stages.slice(1)) {
    const b = base(s[0] ?? ""), args = s.slice(1);
    if (b === "base64" && args.some(a => /^(-d|--decode|-D)$/.test(a))) data = Buffer.from(data.trim(), "base64").toString("utf8");
    else if (b === "openssl" && args.includes("base64") && args.includes("-d")) data = Buffer.from(data.trim(), "base64").toString("utf8");
    else if (b === "xxd" && args.some(a => /^-r/.test(a))) data = Buffer.from(data.replace(/\s+/g, ""), "hex").toString("utf8");
    else if (b === "rev") data = [...data].reverse().join("");
    else if (b === "tr" || b === "sed") return undefined;   // transformations we do not model: stay unresolved
    else return undefined;
  }
  return data;
}

/** What a command substitution stands for as a word: "." for $(pwd), the text of $(echo …), else a named VAR sentinel. */
function substWord(inner: string): string {
  const w = inner.trim().split(/\s+/), b = base(w[0] ?? "");
  if (b === "pwd" || (b === "git" && w.includes("--show-toplevel"))) return ".";
  if (/^(echo|printf)$/.test(b) && !inner.includes(VAR)) return w.slice(1).join(" ").replace(/^['"]|['"]$/g, "");
  return mktempWord(w.map(x => x.replace(/^['"]|['"]$/g, ""))) ?? `${VAR}${b}\u0001`;
}
/**
 * Inside double quotes shell-quote keeps "$(cmd)" as text (VAR followed by "(cmd)"): the command still runs, so it is
 * analyzed, and the word gets what the substitution stands for.
 */
/** The text of $((…)) without its outer $( ): arithmetic, unless the expression starts with a command that could do harm. */
function arithmetic(inner: string): boolean {
  const m = /^\(([\s\S]*)\)$/.exec(inner.trim());
  if (!m || /[;&|`]|\$\(/.test(m[1]) || m[1].includes(VAR + "(")) return false;   // a command substitution inside runs
  const first = /^\s*([A-Za-z_][\w.-]*)/.exec(m[1])?.[1];
  return !first || !DANGER_START.test(first);
}
function expandQuotedSubst(w: string, depth: number, rep: ShellReport): string {
  let out = "", i = 0;
  for (let k = w.indexOf(VAR + "("); k >= 0; k = w.indexOf(VAR + "(", i)) {
    let j = k + VAR.length + 1, lvl = 1;
    for (; j < w.length && lvl; j++) { if (w[j] === "(") lvl++; else if (w[j] === ")") lvl--; }
    const inner = w.slice(k + VAR.length + 1, j - 1);
    // "$((x / 2))" is arithmetic, not a command (unless it reads like one: "$((rm -rf ~))" stays analyzed)
    if (arithmetic(inner)) { out += w.slice(i, k) + `${VAR}arith\u0001`; i = j; continue; }
    analyzeShell(inner, depth + 1, rep, "inherit");
    out += w.slice(i, k) + substWord(inner); i = j;
  }
  return out + w.slice(i);
}
/** Commands in backticks that the shell runs: unquoted or inside double quotes (single quotes keep them literal). */
function backtickCommands(line: string): string[] {
  const out: string[] = []; let q: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "\\" && q !== "'") { i++; continue; }
    if (q === "'") { if (c === "'") q = null; continue; }
    if (c === "'" && q === null) { q = "'"; continue; }
    if (c === '"') { q = q === '"' ? null : '"'; continue; }
    if (c === "`") { const j = line.indexOf("`", i + 1); if (j < 0) break; out.push(line.slice(i + 1, j)); i = j; }
  }
  return out;
}

/** Does the word hold a brace expansion list ({a,b})? Linear: a regex search for it backtracks quadratically on '{{{…'. */
function braceList(w: string): boolean {
  const segs = w.split("}");
  for (let k = 0; k < segs.length - 1; k++) { const o = segs[k].indexOf("{"); if (o >= 0 && segs[k].indexOf(",", o + 1) > 0) return true; }
  return false;
}

/**
 * `name(){ … name | name & }` (`:(){ :|:& };:`). Found from each `(){` with bounded scans: a single regex with a
 * backreference on a greedy name backtracks quadratically on long runs of name characters, and a guard that takes longer
 * than the agent's hook timeout fails open.
 */
function forkBomb(line: string): boolean {
  const def = /\(\s*\)\s*\{/g;
  for (let m = def.exec(line), n = 0; m && n < 200; m = def.exec(line), n++) {
    let j = m.index; while (j > 0 && m.index - j < 256 && /\s/.test(line[j - 1])) j--;
    let i = j; while (i > 0 && j - i < 1024 && /[\w:.-]/.test(line[i - 1])) i--;
    const name = line.slice(i, j);
    if (!name) continue;
    const end = line.indexOf("}", def.lastIndex), body = line.slice(def.lastIndex, end < 0 ? def.lastIndex + 4096 : Math.min(end, def.lastIndex + 4096));
    const q = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(`(^|[^\\w:.-])${q}\\s*\\|\\s*${q}\\s*&`).test(body)) return true;
  }
  return false;
}

/** Tokenizes `text` and records destructive commands and unresolvable indirections into `rep`. */
export function analyzeShell(text: string, depth = 0, rep: ShellReport = { destructive: [], unresolved: [], catastrophic: [] }, mode: VarMode = "fresh", args?: string[]): ShellReport {
  if (depth > 8) return rep;
  withVars(text, mode, args, () => analyzeLines(text, depth, rep));
  return rep;
}
interface Heredoc { delim: string; dash: boolean; toks: any[]; at: number }
/** A here-document started by this line: `cmd <<EOF`, `cmd <<-'EOF'` (tokens, so quoted or arithmetic << are not). */
function heredocOf(line: string): Heredoc | undefined {
  if (!line.includes("<<")) return undefined;
  let toks: any[];
  try { toks = parseWithVars(decodeAnsiC(line)); } catch { return undefined; }
  let lvl = 0;
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    if (t?.op === "(" || t?.op === "<(") lvl++; else if (t?.op === ")") lvl = Math.max(0, lvl - 1);
    else if (lvl === 0 && t?.op === "<<" && typeof toks[k + 1] === "string" && /^-?[A-Za-z_][\w.-]*$/.test(toks[k + 1])) {
      const d = toks[k + 1] as string;
      return { delim: d.replace(/^-/, ""), dash: d.startsWith("-"), toks, at: k };
    }
  }
  return undefined;
}
/** Commands whose here-document is data (a file's content, a message, a manifest, SQL): nothing in it runs here. */
const HEREDOC_DATA = /^(git|gh|glab|hub|jj|hg|svn|curl|wget|http|https|xh|httpie|jq|yq|psql|mysql|mariadb|sqlite3|mongosh|mongo|redis-cli|kubectl|oc|helm|terraform|tofu|aws|gcloud|az|docker|podman|mail|mailx|sendmail|msmtp|wall|logger|envsubst|install|dd|sponge|base64|gpg|openssl|python[\d.]*-config)$/;
/** The body of a here-document: the program of the shell or interpreter that reads it, the content of the file it writes, or (unknown reader) lines analyzed as commands. */
function heredocBody(hd: Heredoc, body: string, line: string, depth: number, rep: ShellReport): void {
  // the command holding the heredoc, and the commands its output is piped into
  type Seg = { argv: string[]; outs: [string, boolean][]; piped: boolean };
  const segs: Seg[] = [{ argv: [], outs: [], piped: false }];
  let mine = 0, lvl = 0;
  for (let k = 0; k < hd.toks.length; k++) {
    const t = hd.toks[k], cur = segs.at(-1)!;
    if (k === hd.at) { mine = segs.length - 1; k++; continue; }
    if (t?.op === "(" || t?.op === "<(") { lvl++; continue; }
    if (t?.op === ")") { lvl = Math.max(0, lvl - 1); continue; }
    if (lvl) continue;
    if (typeof t === "string") { cur.argv.push(t); continue; }
    if (t?.op === "glob") { cur.argv.push(t.pattern); continue; }
    if ((t?.op === ">" || t?.op === ">>" || t?.op === ">|" || t?.op === "&>") && typeof hd.toks[k + 1] === "string") { cur.outs.push([hd.toks[++k], t.op === ">>"]); continue; }
    if (t?.op === "<" || t?.op === "<<" || t?.op === "<<<" || t?.op === ">&" || t?.op === "<&") { if (typeof hd.toks[k + 1] === "string") k++; continue; }
    segs.push({ argv: [], outs: [], piped: t?.op === "|" || t?.op === "|&" });
  }
  const label = `here-document of ${base(segs[mine].argv[0] ?? "")}`.trim();
  const ctx: ArgvCtx = { piped: false, line };
  // a reader that runs it as a program: the command itself (bash <<EOF) or what its output is piped into (cat <<EOF | sh)
  const readers = [segs[mine]];
  for (let k = mine + 1; k < segs.length && segs[k].piped; k++) readers.push(segs[k]);
  for (const s of readers) {
    const { cmd, rest, remote } = programOf(s.argv);
    if (remote) { withoutScripts(() => analyzeRun(body, `${label} (on another host)`, depth, rep, { inline: true })); return; }
    if (cmd && STDIN_RUNNERS.test(cmd) && stdinIsProgram(cmd, rest)) { runText(cmd, body, label, ctx, depth, rep); return; }
  }
  const { cmd, rest } = programOf(segs[mine].argv);
  if (cmd && (TEXT_COMMANDS.test(cmd) || HEREDOC_DATA.test(cmd))) {
    for (const [f, append] of segs[mine].outs) recordWrite(f, body, append);
    if (cmd === "tee") for (const f of positionals(rest)) recordWrite(f, body, rest.some(a => a === "-a" || a === "--append"));
    return;
  }
  // a reader nobody knows: the body is analyzed as commands, as a script would be (in a subshell: its words change no state)
  analyzeShell(body, depth + 1, rep, "inherit");
}
/** The program an argv runs once wrappers are removed (sudo -u x env A=1 nohup …), and whether it runs on another host. */
function programOf(argv: string[]): { cmd: string; rest: string[]; remote: boolean } {
  let i = 0;
  while (i < argv.length) {
    if (/^[A-Za-z_]\w*=/.test(argv[i])) { i++; continue; }
    const w = Object.hasOwn(WRAPPERS, base(argv[i])) ? WRAPPERS[base(argv[i])] : undefined;
    if (!w || w.joins || w.each) break;
    i++;
    while (i < argv.length && argv[i].startsWith("-") && argv[i] !== "-") { const o = argv[i++]; if (o === "--") break; if (!o.includes("=") && w.value?.includes(o)) i++; }
    i += w.operands ?? 0;
  }
  const cmd = base(argv[i] ?? "").replace(/\.exe$/i, ""), rest = argv.slice(i + 1);
  const remote = /^(ssh|autossh|mosh)$/.test(cmd) || (/^(docker|podman|nerdctl|kubectl|oc)$/.test(cmd) && rest.includes("exec"));
  return { cmd, rest, remote };
}
/** Is a quote still open at the end of this text (a quoted string that goes on on the next line)? Comments and escapes count. */
function openQuote(s: string): boolean {
  let q = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q === "'") { if (c === "'") q = ""; continue; }
    if (c === "\\") { i++; continue; }
    if (q) { if (c === q) q = ""; continue; }
    if (c === "'" || c === '"' || c === "`") q = c;
    else if (c === "#" && (i === 0 || /[\s;&|(]/.test(s[i - 1]))) { const e = s.indexOf("\n", i); if (e < 0) return false; i = e; }
  }
  return q !== "";
}
function analyzeLines(text: string, depth: number, rep: ShellReport): void {
  const lines = text.replace(/\\\r?\n/g, " ").split(/\r?\n/);
  for (let n = 0; n < lines.length; n++) {
    let line = lines[n];
    // a quoted string over several lines is one command line (its text is not a command of its own)
    for (let k = 0; k < 500 && n + 1 < lines.length && openQuote(line); k++) line += "\n" + lines[++n];
    analyzeLine(line, depth, rep);
    const hd = heredocOf(line);
    if (!hd) continue;
    // the body runs up to the delimiter line, or to the end of the text (bash then reads it all as the document)
    let end = n + 1;
    while (end < lines.length && (hd.dash ? lines[end].replace(/^\t+/, "") : lines[end]) !== hd.delim) end++;
    heredocBody(hd, lines.slice(n + 1, end).join("\n"), line, depth, rep);
    n = end;
  }
}
function analyzeLine(line: string, depth: number, rep: ShellReport): void {
  if (forkBomb(line)) hit(rep, "catastrophic", "fork bomb");
  for (const c of backtickCommands(line)) analyzeShell(c, depth + 1, rep, "inherit");
  const pre = decodeAnsiC(line);
  const parsed = parseWithVars(pre);
  if (expansionBomb) hit(rep, "catastrophic", "variable expansion bomb (values grow past 256 KB)");
  const toks = parsed.map(t => typeof t === "string" && t.includes(VAR + "(") ? expandQuotedSubst(t, depth, rep)
    : t?.op === "glob" && String(t.pattern).includes(VAR + "(") ? { ...t, pattern: expandQuotedSubst(t.pattern, depth, rep) } : t);
  analyzeTokens(toks, line, depth, rep);
}
/** A process substitution as a word: <(cmd …) is a file holding cmd's output; the marker keeps the command's words. */
const procMarker = (words: string[]) => `${VAR}<(${encodeURIComponent(JSON.stringify(words))})\u0001`;
function procSubst(w: string): string[] | undefined {
  const m = /^\u0001VAR\u0001<\(([^)]*)\)\u0001$/.exec(w);
  if (!m) return undefined;
  try { const v = JSON.parse(decodeURIComponent(m[1])); return Array.isArray(v) ? v.map(String) : undefined; } catch { return undefined; }
}
type Lang = "shell" | "python" | "node" | "ruby" | "perl" | "php" | "powershell" | "cron";
/** The language a runner reads as its program (bash, python3, node...), or undefined (lua, Rscript...: not analyzed). */
function runnerLang(cmd: string): Lang | undefined {
  if (SHELLS.test(cmd) || cmd === "source" || cmd === "." || cmd === "at" || cmd === "batch") return "shell";
  if (cmd === "crontab") return "cron";
  if (/^python[\d.]*$/.test(cmd)) return "python";
  if (/^(node|nodejs|deno|bun)$/.test(cmd)) return "node";
  if (cmd === "ruby" || cmd === "perl") return cmd;
  if (/^php[\d.]*$/.test(cmd)) return "php";
  if (cmd === "pwsh" || cmd === "powershell") return "powershell";
  return undefined;
}
const INLINE_FLAG: Record<Lang, string> = { shell: "-c", python: "-c", node: "-e", ruby: "-e", perl: "-e", php: "-r", powershell: "-Command", cron: "" };
/** Does this runner read its program from stdin (no script file, no inline code)? `bash -s args` does; `python x.py` does not. */
function stdinIsProgram(cmd: string, rest: string[]): boolean {
  if (cmd === "at" || cmd === "batch") return !rest.some(a => /^-[fldrcV]$/.test(a));
  if (cmd === "crontab") return !rest.some(a => /^-[lre]$/.test(a)) && !positionals(rest, ["-u"]).filter(a => a !== "-").length;
  if (rest.some(a => a === "-c" || INTERP[cmd]?.includes(a) || (CLUSTER[cmd] ?? CLUSTER[cmd.replace(/[\d.]+$/, "")])?.test(a))) return false;
  if (SHELLS.test(cmd)) return rest.includes("-s") || !positionals(rest, ["-o", "+o", "-O", "+O", "--rcfile", "--init-file"]).length;
  if (cmd.startsWith("python") && rest.includes("-m")) return false;
  return !positionals(rest, ["-m", "-W", "-X", "-c", "-e", "-r", "-d", "-I", "--require", "--import", "--loader", "-C", "--conditions", "--env-file"]).filter(a => a !== "-").length;
}
/** Program text a runner gets on stdin or from a substitution: analyzed in its language, as a one-liner would be. */
function runText(cmd: string, text: string, label: string, ctx: ArgvCtx, depth: number, rep: ShellReport): void {
  const lang = runnerLang(cmd);
  if (lang === "shell") analyzeRun(text, label, depth, rep, { inline: true });
  else if (lang === "cron") analyzeRun(cronCommands(text), label, depth, rep, { perLine: true, inline: true });
  else if (lang) checkArgv([cmd, INLINE_FLAG[lang], text], { ...ctx, piped: false }, depth + 1, rep);
  else rep.unresolved.push(`script piped into ${cmd}`);
}
/**
 * A shell or an interpreter running what a command prints (source <(kubectl completion bash), bash <(curl …)): known
 * shell-setup tools are fine, `cat file` runs the file and echo/printf their text; anything else runs code nobody can
 * read beforehand.
 */
function runOutput(w: string, lang: string, cmd: string, ctx: ArgvCtx, depth: number, rep: ShellReport): void {
  const words = procSubst(w) ?? [], b = base(words[0] ?? "");
  if (b === "cat") { for (const f of positionals(words.slice(1))) if (f !== "-") runScript(f, lang as Lang, `${cmd} <(cat ${f})`, ctx, depth, rep); return; }
  if (INIT_TOOLS.test(b)) return;
  const s = /^(echo|printf)$/.test(b) ? pipedScript([words]) : undefined;
  if (s !== undefined) { runText(cmd, s, `${cmd} <(${b} …)`, ctx, depth, rep); return; }
  rep.unresolved.push(`${cmd} runs the output of ${b || "a command"} (<(…))`);
}
/** Splits a tokenized line into commands (pipelines, lists, subshells) and analyzes each one. */
function analyzeTokens(toks: any[], line: string, depth: number, rep: ShellReport): void {
  /** `input`: < file; `here`: <<< word; `after`: the operator before it; `pattern`: a case pattern; `fn`: name() { … */
  type Cmd = { argv: string[]; piped: boolean; input?: string; here?: string; after?: string; pattern?: boolean; fn?: boolean; outs?: [string, boolean][] };
  const cmds: Cmd[] = [{ argv: [], piped: false }];
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]; const cur = cmds.at(-1)!;
    if (typeof t === "string") { cur.argv.push(t); continue; }
    if (t?.op === "(" || t?.op === "<(") {
      let j = i + 1, lvl = 1; const inner: any[] = [];
      for (; j < toks.length && lvl; j++) { if (toks[j]?.op === "(" || toks[j]?.op === "<(") lvl++; if (toks[j]?.op === ")") lvl--; if (lvl) inner.push(toks[j]); }
      const words = inner.filter(x => typeof x === "string") as string[];
      // $(…) is shell-quote's "$" or VAR word followed by "(": alone, or at the end of a word (tmp=$(mktemp -d))
      const last = cur.argv.at(-1) ?? "", subst = t.op === "(" && (last === "$" || last.endsWith(VAR));
      const prefix = subst && last !== "$" ? last.slice(0, -VAR.length) : "";
      if (subst) cur.argv.pop();
      // A subshell or a substitution holds a command list of its own: (cd x && rm -rf ~) is two commands, not cd with
      // arguments. Its cd does not move the shell that runs the rest of the line.
      // name() { …: a function definition, whose body runs when it is called
      if (t.op === "(" && !inner.length && !subst && cur.argv.length === 1) { cur.fn = true; i = j - 1; continue; }
      // $((x / 2)): arithmetic (its words are not commands), unless it reads like a command that could do harm
      if (subst && inner[0]?.op === "(" && inner.at(-1)?.op === ")" && !inner.some(x => x?.op && !["(", ")"].includes(x.op)) && !DANGER_START.test(base(words[0] ?? ""))
        && !inner.some((x, k) => typeof x === "string" && (x === "$" || x.endsWith(VAR)) && inner[k + 1]?.op === "(") && !words.some(x => x.includes("`"))) {
        cur.argv.push(prefix + `${VAR}arith\u0001`); i = j - 1; continue;
      }
      const dir = scriptDir(), outer = vars;
      if (outer) vars = { ...outer, vals: new Map(outer.vals), nest: 0 };   // a subshell sees the variables; its assignments stay inside
      try { if (depth < 8) analyzeTokens(inner, line, depth + 1, rep); } finally { vars = outer; }
      restoreScriptDir(dir);
      if (t.op === "<(") cur.argv.push(procMarker(words));
      else if (subst) {
        const single = inner.every(x => typeof x === "string" || x?.op === "glob");
        const mk = single ? mktempWord(words) : undefined;
        const out = mk !== undefined ? [mk]
          : single && /^(echo|printf)$/.test(base(words[0] ?? "")) && !words.some(w => w.includes(VAR)) ? words.slice(1).join(" ").split(/\s+/).filter(Boolean)
          : single && (base(words[0] ?? "") === "pwd" || (base(words[0] ?? "") === "git" && words.includes("--show-toplevel"))) ? ["."]   // $(pwd): the current directory
          : [`${VAR}${base(words[0] ?? "")}\u0001`];   // $(cmd): output unknown statically (the command's name is kept for eval idioms)
        if (prefix) cur.argv.push(prefix + out.join(" ")); else cur.argv.push(...out);
      }
      i = j - 1; continue;
    }
    if (t?.op === "glob") { cur.argv.push(t.pattern); continue; }
    if (t?.comment !== undefined) continue;
    if (t?.op === ">" || t?.op === ">|" || t?.op === "&>" || t?.op === ">>") {
      const target = typeof toks[i + 1] === "string" ? toks[i + 1] as string : "";
      const append = t.op === ">>";
      if (target) (cur.outs ??= []).push([target, append]);
      if (target.includes(VAR) && !sensitivePath(target)) { if (cur.argv.length) rep.unresolved.push("redirection to an expanded path"); }
      else if (criticalPath(target)) hit(rep, "catastrophic", `${t.op} onto ${target}`);
      else if (sensitivePath(target)) { /* a project's .env, .npmrc or hosts inventory: the project's business */ }
      else if (!append && /^(\/|~)/.test(target) && !SAFE_REDIRECT.test(target)) hit(rep, "destructive", `truncating redirection > ${target}`);
      // "> file" with no command truncates the file; Markdown quotes ("> Note: …") have no path-like target
      else if (!append && cur.argv.length === 0 && cmds.length === 1 && pathLike(target) && !SAFE_REDIRECT.test(target)) hit(rep, "destructive", `truncation > ${target}`);
      i++; continue;
    }
    if (t?.op === "<") { if (typeof toks[i + 1] === "string") cur.input = toks[++i] as string; continue; }
    if (t?.op === "<<<") { if (typeof toks[i + 1] === "string") cur.here = toks[++i] as string; continue; }
    // <<EOF: the body lines are analyzed as lines of their own (conservative: bash <<EOF … runs them)
    if (t?.op === "<<" || t?.op === ">&" || t?.op === "<&") { if (typeof toks[i + 1] === "string") i++; continue; }
    // a ")" no "(" opened: the end of a case pattern (with its alternatives: a | b)
    if (t?.op === ")") { cur.pattern = true; for (let j = cmds.length - 1; j > 0 && cmds[j].piped; j--) cmds[j - 1].pattern = true; }
    cmds.push({ argv: [], piped: t?.op === "|" || t?.op === "|&", after: t?.op });
  }
  for (let k = 0; k < cmds.length; k++) {
    const c = cmds[k], producer = c.piped ? cmds[k - 1]?.argv : undefined;
    // case patterns are not commands (a "case … in" before one still opens the case)
    if (c.pattern) { if (/^(case)$/.test(c.argv[0] ?? "") || c.argv.includes("case")) nestUp(); continue; }
    const cond = c.after === "&&" || c.after === "||" || cmds[k + 1]?.after === "&";
    // echo … > x.sh: what the file holds from now on (for when this command runs it)
    if (c.outs?.length && /^(echo|printf)$/.test(base(c.argv[0] ?? ""))) { const data = pipedScript([c.argv]); if (data !== undefined) for (const [f, append] of c.outs) recordWrite(f, data, append); }
    if (c.fn) { nestUp(); checkArgv(c.argv.slice(1), { piped: false, line, cond }, depth, rep); continue; }
    const runner = base(c.argv[0] ?? "").replace(/\.exe$/i, ""), ctx: ArgvCtx = { piped: c.piped, line, producer, cond };
    if (STDIN_RUNNERS.test(runner) && stdinIsProgram(runner, c.argv.slice(1))) {
      // python3 <<< 'code', bash < x.sh: what the runner reads on stdin is its program
      if (c.here !== undefined) { runText(runner, c.here, `${runner} <<< …`, ctx, depth, rep); continue; }
      if (c.input !== undefined && !c.piped) { const lang = runnerLang(runner); if (lang) runScript(c.input, lang, `${runner} < ${c.input}`, ctx, depth, rep); else rep.unresolved.push(`script piped into ${runner}`); continue; }
      if (c.piped) {
        let s = k; while (s > 0 && cmds[s].piped) s--;
        const stages = cmds.slice(s, k).map(x => x.argv);
        // cat x.sh | bash: the file is the script
        const files = stages.length === 1 && base(stages[0][0] ?? "") === "cat" ? positionals(stages[0].slice(1)) : [];
        const lang = runnerLang(runner);
        if (files.length && lang && !files.includes("-") && !cmds[s].input) { for (const f of files) runScript(f, lang, `cat ${f} | ${runner}`, ctx, depth, rep); continue; }
        // A script assembled by the pipeline itself (echo …, base64 -d, xxd -r) and fed to a runner is analyzed as such.
        const script = pipedScript(stages);
        if (script !== undefined) { runText(runner, script, `piped into ${runner}`, ctx, depth, rep); continue; }
      }
    }
    // Words are analyzed as tokenized (a quoted 'rm -rf /' after su -c, ssh or env -S is one argument), and again split on
    // whitespace when a word contains some: an expansion such as rm${IFS}-rf${IFS}/ yields one word that bash splits.
    checkArgv(c.argv, ctx, depth, rep);
    if (c.argv.some(a => /\s/.test(a))) checkArgv(c.argv.flatMap(a => a.split(/\s+/).filter(Boolean)), { ...ctx, split: true }, depth, rep);
  }
}

/** Back-compat helper: description of the first destructive command, or null. */
export function shellDestructive(text: string): string | null { return analyzeShell(text).destructive[0] ?? null; }

/** Every string, every array of strings (as an argv), recursively, including JSON documents inside strings. */
function shellTexts(v: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 32) return out;
  if (typeof v === "string") {
    out.push(v);
    const t = v.trim();
    if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) { try { shellTexts(JSON.parse(t), out, depth + 1); } catch {} }
  } else if (Array.isArray(v)) {
    if (v.length && v.every(x => typeof x === "string")) out.push(v.map(x => /[\s'"$;|&<>(){}`\\]/.test(x as string) ? `'${(x as string).replace(/'/g, `'"'"'`)}'` : x).join(" "));
    v.forEach(x => shellTexts(x, out, depth + 1));
  } else if (v && typeof v === "object") for (const x of Object.values(v)) shellTexts(x, out, depth + 1);
  return out;
}
export interface ShellFindings { destructive: string[]; unresolved: string[]; catastrophic: string[]; unparseable: boolean }
/**
 * Shell analysis applies to every string, whatever the tool or field name (neutral names like task/input are not trusted).
 * PowerShell / cmd.exe analysis runs on every string of a Windows shell tool, and on strings that look like Windows commands.
 */
/**
 * A PowerShell tool's command, for its POSIX reading (aliases such as rm and curl run there too): PowerShell's own
 * conditions and environment assignments are not commands (if ($?) { … }, if ($LASTEXITCODE -ne 0) { … }, $env:X = 'y').
 * The Windows analyzer reads the text as it is.
 */
const psForPosix = (t: string) => t.replace(/\bif\s*\(\s*(-not\s+|!\s*)?\$\?\s*\)/gi, "if true").replace(/\bif\s*\(\s*\$LASTEXITCODE\b[^()]*\)/gi, "if true")
  // $env:X = 'value' (a literal) or $env:X = $y (a variable) is an assignment; $env:X = Remove-Item … and $env:X = $(…) run
  // the command on their right: left as they are (a command word nobody can resolve here: confirmed)
  .replace(/\$env:(\w+)\s*=\s*(?=['"\d]|\$(?!\())/gi, "$1=");
export function shellFindings(args: unknown, tool = ""): ShellFindings {
  const rep: ShellReport = { destructive: [], unresolved: [], catastrophic: [] }; let unparseable = false;
  const windowsTool = /powershell|pwsh|^cmd$|cmd\.exe|windows/i.test(tool);
  for (const s of shellTexts(args)) for (const seed of seedsOf(s)) {
    for (const v of new Set([seed, canonical(seed, true)])) {
      try { analyzeShell(windowsTool ? psForPosix(v) : v, 0, rep); } catch { unparseable = true; }
      if (windowsTool || looksWindows(v)) {
        try { const w = analyzeWindows(v); rep.destructive.push(...w.destructive); rep.unresolved.push(...w.unresolved); (rep.catastrophic ??= []).push(...(w.catastrophic ?? [])); } catch { unparseable = true; }
      }
    }
  }
  return { destructive: rep.destructive, unresolved: rep.unresolved, catastrophic: rep.catastrophic ?? [], unparseable };
}
