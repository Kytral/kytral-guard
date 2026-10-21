import { YAMLParseError } from "yaml";
import { argViews, canonical, collectStrings } from "./normalize.js";
import { parseQuietly } from "./quiet-yaml.js";
import { sqlFindingsDetailed, shellFindings, SQL_DIALECTS, DEFAULT_SQL_DIALECT, ShellFindings, SqlVerdict } from "./analyze.js";
import { criticalPath, customStateDir, guardConfigPath, normPath } from "./paths.js";
import { withScriptContext } from "./scripts.js";
export type Action = "allow" | "block" | "confirm";
export type Analyzer = "sql-unrestricted-write" | "sql-opaque" | "sql-unparseable" | "shell-destructive" | "shell-catastrophic" | "shell-unresolved"
  | "shell-unparseable" | "path-sensitive" | "guard-tamper";
export const ANALYZERS: readonly Analyzer[] = ["sql-unrestricted-write", "sql-opaque", "sql-unparseable", "shell-destructive", "shell-catastrophic",
  "shell-unresolved", "shell-unparseable", "path-sensitive", "guard-tamper"];
export interface Rule {
  name: string; action: Action;
  tool?: string;          // glob on the (canonicalized) tool name
  toolMatches?: string;   // regex on the (canonicalized) tool name
  toolNotMatches?: string; // regex on the (canonicalized) tool name: the rule does not apply to these tools
  argMatches?: string;    // regex tested on every normalized view of every argument value
  /** An argument value equal to this text, exactly (surrounding whitespace aside): `kytral-guard allow "<command>"`. */
  argEquals?: string;
  /** The rule does not apply to a call the shell analysis finds catastrophic (an allowed script that turned destructive). */
  exceptCatastrophic?: boolean;
  /** Only these top-level arguments are looked at (argMatches, analyzers, counts), e.g. [command] or [file_path, path]. */
  argFields?: string[];
  maxCount?: number;      // count threshold
  countArg?: string;      // legacy single field name
  countArgs?: string[];   // fields to sum (arrays, or strings split on , ;)
  /** Structural analyzer (see ANALYZERS). */
  analyzer?: Analyzer;
}
export interface Policy {
  default: Action; rules: Rule[];
  /** Decision for a tool that no rule matched AND that is unknown (not advertised by the server's tools/list, not in knownTools). Default: confirm. */
  unknownTools?: Action;
  /** SQL dialect used by the parser (node-sql-parser database name). Default: postgresql. */
  sqlDialect?: string;
  /** Globs of tool names considered known even if the server never advertised them. */
  knownTools?: string[];
  /** Name of a built-in preset this policy builds on: its rules come first, the preset's after; other fields override the preset's. */
  extends?: string;
  /**
   * A new action for rules named here (a preset's included): `shell-destructive: block`. Every name must be a rule of the
   * policy. guard-tamper stays block: it keeps agents from turning the guard off. The dashboard writes this map.
   */
  overrides?: Record<string, Action>;
}
/** `cwd`: the working directory of the call (agent hooks give it): the scripts a command runs are read from there. */
export interface ToolCall { tool: string; args: Record<string, unknown>; cwd?: string }
export interface Decision { action: Action; rule?: string; reason: string }
const ACTIONS = ["allow", "block", "confirm"];

/** Throws if the text is not a valid policy (read with parseQuietly: nothing of it is printed). The error may quote the text (a YAML error, a rule name, a value, a regex): never show its message. */
export function loadPolicy(text: string): Policy {
  let p = parseQuietly(text) as Policy;
  if (!p || typeof p !== "object" || Array.isArray(p)) throw new Error("policy: a YAML mapping is required");
  if (p.extends !== undefined) {
    if (typeof p.extends !== "string" || !Object.hasOwn(PRESETS, p.extends)) throw new Error(`policy: unknown preset in extends '${String(p.extends)}' (${Object.keys(PRESETS).join(", ")})`);
    const base = parseQuietly(PRESETS[p.extends]) as Policy;
    if (p.rules !== undefined && !Array.isArray(p.rules)) throw new Error("policy: 'rules' must be a list");
    p = { ...base, ...p, rules: [...(p.rules ?? []), ...base.rules], knownTools: [...(base.knownTools ?? []), ...(p.knownTools ?? [])] };
  }
  if (!Array.isArray(p.rules)) throw new Error("policy: 'rules' list required");
  if (p.overrides !== undefined && p.overrides !== null) {
    if (typeof p.overrides !== "object" || Array.isArray(p.overrides)) throw new Error("policy: 'overrides' must map rule names to actions");
    for (const [name, action] of Object.entries(p.overrides)) {
      if (!ACTIONS.includes(action)) throw new Error(`policy: bad action for '${name}' in overrides (allow|confirm|block)`);
      if (name === "guard-tamper" && action !== "block") throw new Error("policy: guard-tamper cannot be overridden: it keeps agents from turning the guard off");
      const hits = p.rules.filter(r => r && typeof r === "object" && r.name === name);
      if (!hits.length) throw new Error(`policy: overrides names no rule '${name}'`);
      for (const r of hits) r.action = action;
    }
  }
  p.default ??= "allow";
  if (!ACTIONS.includes(p.default)) throw new Error(`policy: bad default '${String(p.default)}' (allow, confirm or block)`);
  p.unknownTools ??= "confirm";
  p.sqlDialect ??= DEFAULT_SQL_DIALECT;
  if (!SQL_DIALECTS.includes(p.sqlDialect)) throw new Error(`policy: unsupported sqlDialect '${p.sqlDialect}' (${SQL_DIALECTS.join(", ")})`);
  if (!ACTIONS.includes(p.unknownTools)) throw new Error("policy: bad unknownTools (allow|confirm|block)");
  if (p.knownTools !== undefined && (!Array.isArray(p.knownTools) || p.knownTools.some(t => typeof t !== "string"))) throw new Error("policy: knownTools must be a list of globs");
  for (const r of p.rules) {
    if (!r || typeof r !== "object" || typeof r.name !== "string" || !r.name) throw new Error("policy: every rule needs a name");
    if (!ACTIONS.includes(r.action)) throw new Error(`policy: bad action '${String(r.action)}' in rule '${r.name}' (allow, confirm or block)`);
    if (r.analyzer !== undefined && !ANALYZERS.includes(r.analyzer)) throw new Error(`policy: bad analyzer in ${r.name} (${ANALYZERS.join(", ")})`);
    if (r.argFields !== undefined && (!Array.isArray(r.argFields) || !r.argFields.length || r.argFields.some(f => typeof f !== "string"))) throw new Error(`policy: argFields must be a list of argument names in ${r.name}`);
    if (r.argEquals !== undefined && (typeof r.argEquals !== "string" || !r.argEquals.trim())) throw new Error(`policy: argEquals must be a non-empty text in ${r.name}`);
    if (r.exceptCatastrophic !== undefined && typeof r.exceptCatastrophic !== "boolean") throw new Error(`policy: exceptCatastrophic must be true or false in ${r.name}`);
    // fail fast on a bad regex, naming the rule and the field (the engine's message names neither)
    for (const field of ["argMatches", "toolMatches", "toolNotMatches"] as const) {
      const re = r[field];
      if (re) try { new RegExp(re, "iu"); } catch (e) { throw new Error(`policy: ${field} of rule '${r.name}' is not a valid regular expression: ${(e as Error).message}`); }
    }
  }
  return p;
}
/** The line (from 1) of a YAML syntax error that loadPolicy() threw, if the parser located it: the one detail of the error that quotes nothing. */
export function policyErrorLine(e: unknown): number | undefined {
  const line = e instanceof YAMLParseError ? e.linePos?.[0]?.line : undefined;
  return Number.isSafeInteger(line) && line! > 0 ? line : undefined;
}
export const glob = (pat: string, s: string) => new RegExp("^" + pat.split("*").map(x => x.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$", "i").test(s);
/** A built-in preset (see PRESETS), parsed and validated. */
export function presetPolicy(name: string): Policy {
  if (!Object.hasOwn(PRESETS, name)) throw new Error(`policy: unknown preset (${Object.keys(PRESETS).join(", ")})`);   // the name is not repeated: it may be anything
  return loadPolicy(PRESETS[name]);
}

/** loadPolicy's messages that quote nothing from the policy. */
const POLICY_ERRORS = ["policy: 'rules' list required", "policy: bad default", "policy: bad unknownTools (allow|confirm|block)", "policy: knownTools must be a list of globs",
  "policy: a YAML mapping is required", "policy: 'rules' must be a list", "policy: 'overrides' must map rule names to actions"];
/** loadPolicy's messages that quote a value or a rule name, by their fixed beginning, and how they are said instead. */
const POLICY_ERROR_SHAPES: [RegExp, string][] = [[/^policy: bad default /, "policy: bad default"], [/^policy: unsupported sqlDialect /, "policy: unsupported sqlDialect"],
  [/^policy: unknown preset in extends /, "policy: unknown preset in extends"], [/^policy: bad action for .* in overrides /, "policy: bad action in overrides"],
  [/^policy: guard-tamper cannot be overridden/, "policy: the guard tamper rule cannot be overridden"], [/^policy: overrides names no rule /, "policy: overrides names a rule that does not exist"],
  [/^policy: (argMatches|toolMatches|toolNotMatches) of rule .* is not a valid regular expression/, "a rule has an invalid regular expression"],
  [/^policy: bad action /, "policy: bad action in a rule"], [/^policy: bad analyzer in /, "policy: bad analyzer in a rule"]];
/**
 * Why a policy does not load, from a fixed list: YAML errors and invalid regular expressions show the text at fault, other
 * errors a rule name or a value, any of which may be a secret. For what leaves the machine or the user's terminal
 * (`doctor --report`, a hook's refusal, which its agent and the agent's model read, a plugin's invalid policy);
 * `kytral-guard policy validate` gives the whole message.
 */
export function policyProblem(e: unknown): string {
  if (e instanceof YAMLParseError) { const line = policyErrorLine(e); return `YAML syntax error${line ? ` at line ${line}` : ""}`; }
  if (e instanceof SyntaxError) return "a rule has an invalid regular expression";
  const m = String((e as { message?: unknown } | null)?.message ?? "").split("\n")[0];
  if (POLICY_ERRORS.includes(m)) return m;
  return POLICY_ERROR_SHAPES.find(([re]) => re.test(m))?.[1] ?? "not a valid policy";
}

function count(args: Record<string, unknown>, fields: string[]): number {
  let n = 0;
  for (const f of fields) {
    const v = args?.[f];
    if (Array.isArray(v)) n += v.length;
    else if (typeof v === "number") n += v;
    else if (typeof v === "string") n += v.split(/[,;\n]/).filter(x => x.trim()).length;
  }
  return n;
}

const ADDRESS = /^(?:[^<>@,;]*<)?\s*[^\s@<>,;"'()]+@[^\s@<>,;"'()]+\s*>?$/;
/**
 * Recipients hidden in any argument (list, emails, members…): addresses in strings that are nothing but address lists
 * ("a@x.io, Bob <b@x.io>"), counted with repeats. A message body that mentions addresses is prose, not a recipient list.
 */
function countEmails(args: unknown): number {
  let n = 0;
  for (const s of collectStrings(args)) {
    const parts = s.split(/[,;\n]/).map(x => x.trim()).filter(Boolean);
    if (parts.length && parts.every(x => ADDRESS.test(x))) n += parts.length;
  }
  return n;
}

/** Argument names that hold a filesystem location (file tools of coding agents, MCP filesystem servers). */
const PATH_KEY = /(^|_)(file_?path|path|paths|file|files|filename|notebook_path|dest(ination)?|target(_?path)?|dir(ectory)?|output(_?path)?|out_?file|new_?path|old_?path|source|to|from)$/i;
/** Locations in path-like arguments (every string when `all`) that are system, credential or guard-configuration files. */
export function pathFindings(args: unknown, all = false): string[] {
  const out: string[] = [];
  const visit = (v: unknown, key: string, depth: number) => {
    if (depth > 8) return;
    if (typeof v === "string") { if ((all || PATH_KEY.test(key)) && v.length < 4096 && !/[\r\n]/.test(v) && (criticalPath(v.trim()) || guardConfigPath(v.trim()))) out.push(`${key}: ${v.trim()}`); }
    else if (Array.isArray(v)) v.forEach(x => visit(x, key, depth + 1));
    else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) visit(x, k, depth + 1);
  };
  if (args && typeof args === "object") for (const [k, v] of Object.entries(args)) visit(v, k, 0);
  return out;
}
/**
 * Attempts to disable or impersonate the guard: reading its secret (which signs badges, approvals and kill switch states),
 * setting it, or running the CLI commands that lift a kill switch, approve a pending confirmation, mint a badge, remove hooks,
 * take the proxy off MCP servers (`mcp unwrap`, the CLI form of the configuration edits guardConfigPath refuses)
 * or open the dashboard (its one-time link signs in to a page that changes the rules and answers confirmations),
 * and the commands of a control plane plugin (Kytral Guard Pro) that enroll the machine elsewhere or remove the plugin.
 * Quantifiers are bounded: these patterns run over every argument, and an unbounded scan from each match start is quadratic.
 */
const TAMPER = [
  /\$\{?KYTRAL_(AUDIT_)?SECRET\b/, /\bKYTRAL_(AUDIT_)?SECRET\s*=/, /(\$\{?|%|\$env:)KYTRAL_SECRET_FILE\b/i,
  /(\$\{?|%|\$env:)KYTRAL_HOME\b\}?%?[\/\\]+(secret|[\w.-]*\.key)\b/i, /\bprintenv\b[^\n;|&]{0,300}?\bKYTRAL_/i, /(^|[\s'"=:(\/\\~])\.kytral[\/\\]+(secret|[\w.-]*\.key)\b/i,
  /\bkytral-guard\b[^\n;|&]{0,300}?\b(resume|uninstall|badge|known\s+add|dashboard|mcp\s+unwrap)\b/i, /\bkytral-guard\b[^\n;|&]{0,300}?\bconfirm\s+approve\b/i,
  /\bkytral-guard(\.cmd|\.exe|\.ps1)?['"]?\s+allow\b/i,
  /\bkytral-pro\b[^\n;|&]{0,300}?\b(enroll|unenroll|uninstall)\b/i,
  // removing the globally installed guard, which every hook runs (a project's own dependency on the SDK is not it)
  /\b(npm|pnpm|bun)\b(?=[^\n;|&]{0,300}?\s(-g|--global)\b)(?=[^\n;|&]{0,300}?\s(uninstall|remove|rm|un|r|unlink)\b)(?=[^\n;|&]{0,300}?(\bkytral-guard\b|@kytral\/))/i,
  /\byarn\s+global\s+(remove|rm)\b[^\n;|&]{0,200}?(\bkytral-guard\b|@kytral\/)/i, /\bvolta\s+uninstall\b[^\n;|&]{0,200}?(\bkytral-guard\b|@kytral\/)/i,
  // the same CLIs run by their script path (node …/kytral-guard/dist/cli.js resume, node dist/cli.js confirm approve <id>)
  /(\bkytral[\w-]{0,40}[\/\\]\S{0,300}?\bcli\.[cm]?[jt]s|(^|[\s'"\/\\])dist[\/\\]cli\.[cm]?js)\b[^\n;|&]{0,300}?\s(resume|uninstall|badge|known\s+add|confirm\s+approve|allow|dashboard|mcp\s+unwrap)(\s|$)/i,
  /\bguard-pro[\/\\]\S{0,300}?\bcli\.[cm]?[jt]s\b[^\n;|&]{0,300}?\s(enroll|unenroll|uninstall)(\s|$)/i,
];
export function tamperFindings(args: unknown): string[] {
  const out: string[] = [];
  // the secret and the *.key files of a custom KYTRAL_HOME, named by their absolute path
  const home = customStateDir();
  for (const v of argViews(args)) {
    // also without quotes: the shell removes them, so kytral-guard mcp 'unwrap', "kytral-guard" 'allow' or npm -g 'uninstall'
    // run the same commands as the words alone
    for (const view of new Set([v, v.replace(/["'`]/g, "")])) for (const re of TAMPER) { const m = re.exec(view); if (m) out.push(m[0].trim()); }
    if (home) for (const tok of v.split(/[\s'"=(,;|&<>]+/)) {
      if (!/^([\\/~]|[A-Za-z]:)/.test(tok)) continue;
      const q = normPath(tok);
      if (q.startsWith(home + "/") && /\/(secret|[\w.-]*\.key)$/.test(q)) out.push(tok);
    }
  }
  return [...new Set(out)];
}

/** Lazily computed analyses of one set of arguments (all of them, or the argFields of a rule). */
interface Scope { args: Record<string, unknown>; views?: string[]; sql?: Map<SqlVerdict, string>; sh?: ShellFindings; paths?: string[]; tamper?: string[] }
/** Every string value of the arguments, recursively (keys excluded). */
function stringValues(v: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 32) return out;
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) v.forEach(x => stringValues(x, out, depth + 1));
  else if (v && typeof v === "object") for (const x of Object.values(v)) stringValues(x, out, depth + 1);
  return out;
}
function pick(args: Record<string, unknown>, fields: string[]): Record<string, unknown> {
  const want = new Set(fields.map(f => f.toLowerCase()));
  return Object.fromEntries(Object.entries(args ?? {}).filter(([k]) => want.has(k.toLowerCase())));
}

export function evaluate(policy: Policy, call: ToolCall): Decision {
  return withScriptContext(call.cwd, () => evaluateRules(policy, call));
}
/** Every rule that matches a call, in the policy's order (evaluate stops at the first): what an exception would override. */
export function matchingRules(policy: Policy, call: ToolCall): Decision[] {
  const all: Decision[] = [];
  withScriptContext(call.cwd, () => evaluateRules(policy, call, all));
  return all;
}
function evaluateRules(policy: Policy, call: ToolCall, all?: Decision[]): Decision {
  // camelCase -> snake_case before canonicalizing so that "rmFile" exposes the "rm" token
  const tool = canonical(String(call.tool ?? "").replace(/([a-z0-9])([A-Z])/g, "$1_$2"));
  const scopes = new Map<string, Scope>();
  const scopeOf = (r: Rule): Scope => {
    const key = r.argFields ? JSON.stringify(r.argFields) : "";
    let s = scopes.get(key);
    if (!s) scopes.set(key, s = { args: r.argFields ? pick(call.args, r.argFields) : (call.args ?? {}) });
    return s;
  };
  for (const r of policy.rules) {
    if (r.tool && !glob(r.tool, tool) && !glob(r.tool, call.tool)) continue;
    if (r.toolMatches && !new RegExp(r.toolMatches, "iu").test(tool)) continue;
    if (r.toolNotMatches && new RegExp(r.toolNotMatches, "iu").test(tool)) continue;
    if (r.analyzer) {
      const s = scopeOf(r);
      if (r.analyzer.startsWith("sql")) { s.sql ??= sqlFindingsDetailed(s.args, policy.sqlDialect); if (!s.sql.has(r.analyzer.slice(4) as SqlVerdict)) continue; }
      else if (r.analyzer.startsWith("shell")) {
        s.sh ??= shellFindings(s.args, String(call.tool ?? ""));
        const hit = r.analyzer === "shell-destructive" ? s.sh.destructive.length > 0 : r.analyzer === "shell-catastrophic" ? s.sh.catastrophic.length > 0
          : r.analyzer === "shell-unresolved" ? s.sh.unresolved.length > 0 : s.sh.unparseable;
        if (!hit) continue;
      }
      else if (r.analyzer === "path-sensitive") { s.paths ??= pathFindings(s.args, !!r.argFields); if (!s.paths.length) continue; }
      else if (r.analyzer === "guard-tamper") { s.tamper ??= tamperFindings(s.args); if (!s.tamper.length) continue; }
    }
    if (r.argMatches) {
      const re = new RegExp(r.argMatches, "iu"); const s = scopeOf(r);
      s.views ??= argViews(s.args);
      if (!s.views.some(v => re.test(v))) continue;
    }
    // the raw text, not a normalized view: allowing "npm run deploy" must not allow "npm run dеploy" (Cyrillic e)
    if (r.argEquals !== undefined && !stringValues(scopeOf(r).args).some(v => v.trim() === r.argEquals!.trim())) continue;
    if (r.exceptCatastrophic) {
      const s = scopeOf(r);
      s.sh ??= shellFindings(s.args, String(call.tool ?? ""));
      if (s.sh.catastrophic.length) continue;
    }
    if (r.maxCount !== undefined) {
      const s = scopeOf(r);
      const fields = r.countArgs ?? (r.countArg ? [r.countArg] : ["recipients", "to", "cc", "bcc"]);
      // explicit fields, plus every e-mail address found anywhere in the arguments (catches list/emails/... aliases)
      if (Math.max(count(s.args, fields), countEmails(s.args)) <= r.maxCount) continue;
    }
    const d: Decision = { action: r.action, rule: r.name, reason: describe(r, scopes.get(r.argFields ? JSON.stringify(r.argFields) : "")) };
    if (!all) return d;
    all.push(d);
  }
  return { action: policy.default, reason: "default" };
}
/** The statement behind a SQL finding, and what is wrong with it. */
function sqlWhy(v: SqlVerdict, stmt: string | undefined): string | undefined {
  const head = (stmt ?? "").trim().split(/\s+/)[0]?.toLowerCase();
  const why = v === "unrestricted-write" ? (head === "drop" ? "drops it" : head === "truncate" ? "empties it" : head === "alter" ? "drops a column"
      : head === "delete" || head === "update" ? "no WHERE that pins rows" : "DROP/TRUNCATE, or DELETE/UPDATE without a WHERE that pins rows")
    : v === "opaque" ? "effect unknown: procedure call, bind parameters, or SQL from a file or stdin"
    : v === "unparseable" ? "SQL that cannot be parsed" : undefined;
  if (!why) return undefined;
  if (!stmt) return why;
  const shown = stmt.length > 120 ? stmt.slice(0, 120) + "…" : stmt;
  return /^[\w-]+: /.test(stmt) ? shown : `${shown} (${why})`;   // shellSql's opaque sources already say why ("psql: SQL from a file…")
}
/** Why a rule matched, for the human and the agent: the analyzer's first finding when there is one. */
function describe(r: Rule, s?: Scope): string {
  const first = r.analyzer === "shell-catastrophic" ? s?.sh?.catastrophic[0] : r.analyzer === "shell-destructive" ? s?.sh?.destructive[0]
    : r.analyzer === "shell-unresolved" ? s?.sh?.unresolved[0] : r.analyzer === "path-sensitive" ? s?.paths?.[0] : r.analyzer === "guard-tamper" ? s?.tamper?.[0]
    : r.analyzer?.startsWith("sql-") ? sqlWhy(r.analyzer.slice(4) as SqlVerdict, s?.sql?.get(r.analyzer.slice(4) as SqlVerdict))
    : undefined;
  return first ? `matched rule '${r.name}': ${first.split("\u0001VAR\u0001").join("$?")}` : `matched rule '${r.name}'`;
}

// Block rules first. Structural analyzers (SQL AST, shell argv) decide; regex rules remain a safety net. They run in linear
// time on text an agent writes: an open-ended scan stops at the next occurrence of its own head (rm-rf,
// recursive-delete-other-commands), where "find . -name x " or "rm -rrr…r!" repeated made them quadratic (100 KB: 1 s).
// Rules are matched against normalized views (lowercase, NFKC, homoglyphs, URL/base64-decoded, SQL comments
// stripped, CHAR()/hex decoded, string concatenation collapsed, whitespace squashed).
/** Preset "strict" (the default): MCP servers and SDK tools. Every destructive finding is blocked, deletions/payments/mass e-mail confirmed. */
export const DEFAULT_POLICY = String.raw`default: allow
unknownTools: confirm
sqlDialect: postgresql
rules:
  - name: guard-tamper
    analyzer: guard-tamper
    action: block
  - name: destructive-sql
    argMatches: '\b(drop\s+(table|database|schema|view|index|user|role|function|procedure|trigger|materialized)|truncate\s+table\s+[\w."\x60\[]|truncate\s+[\w."\x60\[\]]+\s*(;|$)|alter\s+table\s+\S+\s+drop\b|delete\s+(?!from\b)[\w."\x60\[\]]+\s*(;|$)|delete\s+from\s+\S+\s*(;|$|where\s+((\d+|''\w*'')\s*(=|<|>|<=|>=|<>|!=)|\w+\s*(>|<|>=|<=|<>|!=)|true|not\s+false|1\s*=\s*1|(?<l>\w+)\s*=\s*\k<l>(\s|;|$)|''(?<q>\w*)''\s*=\s*''\k<q>''))|delete\s+from\s+\S+\s+where\s.{0,2000}?\bor\s+(1\s*=\s*1|true)\b)'
    action: block
  - name: rm-rf
    argMatches: '\brm(\s+[^\s;|&]+){0,64}?\s+(-(?=[a-z]*r)[a-z]+|--recursive)(\s|$)'
    action: block
  - name: recursive-delete-other-commands
    argMatches: '\bfind\b(?:(?!\bfind\b)[^;|&\n])*\s-delete\b|\bfind\b(?:(?!\bfind\b)[^;|&\n])*-exec\s+rm\b|\b(shutil\.)?rmtree\b|\brimraf\b|\bfs\.(rm|rmdir)(sync)?\b(?:(?!\bfs\.(?:rm|rmdir)(?:sync)?\b)[^;\n])*recursive|\bremove-item\b(?:(?!\bremove-item\b)[^;\n])*-recurse|\b(rd|rmdir|del)\s+/s\b|\bshred\b'
    action: block
  - name: sensitive-path
    analyzer: path-sensitive
    action: block
  - name: sql-unrestricted-write
    analyzer: sql-unrestricted-write
    action: block
  - name: shell-destructive
    analyzer: shell-destructive
    action: block
  - name: sql-opaque
    analyzer: sql-opaque
    action: confirm
  - name: sql-unparseable
    analyzer: sql-unparseable
    action: confirm
  - name: shell-unresolved
    analyzer: shell-unresolved
    action: confirm
  - name: shell-unparseable
    analyzer: shell-unparseable
    action: confirm
  - name: delete-files-or-backups
    toolMatches: '(^|[^a-z])(rm|rmdir|rmtree|del|unlink|unset)([^a-z]|$)|delet|remov|eras|destroy|purg|wipe|trash|drop|shred|truncat|obliterat|discard|clear_?all|reset'
    action: confirm
  - name: money-transfer
    argMatches: '\b(transfer|payout|wire|refund)'
    action: confirm
  - name: mass-email
    toolMatches: 'send|mail|email|message|blast|newsletter|notify|campaign|bulk|broadcast'
    maxCount: 20
    countArgs: [recipients, to, cc, bcc]
    action: confirm
`;
/** Tools of coding agents that write file contents: their contents (code, docs, scripts) are not commands being run. */
const WRITE_TOOLS = String.raw`^(write|edit|multi_edit|multiedit|notebook_edit|str_replace_editor|str-replace-editor|str_replace_based_edit_tool|str_replace|create_file|write_file|edit_file|apply_patch|patch|replace|replace_in_file|write_to_file|save_file|save-file|create|search_replace|hashline_edit|editor|fs_write|fs_append)$`;
/**
 * Preset "coding-agent": Claude Code, Cursor, Codex, Gemini CLI, Copilot CLI... behind `kytral-guard hook`. Blocks what is
 * catastrophic (rm -rf ~, terraform destroy, DROP TABLE, force-push to main, writing ~/.ssh), asks before scoped destruction
 * (rm -rf src, git reset --hard, kubectl delete deployment), and stays silent on routine work (rm -rf node_modules, edits).
 */
export const CODING_AGENT_POLICY = String.raw`default: allow
unknownTools: allow
sqlDialect: postgresql
rules:
  - name: guard-tamper
    analyzer: guard-tamper
    toolNotMatches: '${WRITE_TOOLS}'
    action: block
  - name: sensitive-file-write
    analyzer: path-sensitive
    toolNotMatches: '(^|_)(read|get|list|search(?!_replace)|grep|glob|view|ls|find|stat|info|fetch|describe|show|cat|head|tail|tree|diff)(_|$)'
    action: block
  - name: shell-catastrophic
    analyzer: shell-catastrophic
    toolNotMatches: '${WRITE_TOOLS}'
    action: block
  - name: sql-destructive
    analyzer: sql-unrestricted-write
    toolNotMatches: '${WRITE_TOOLS}'
    action: block
  - name: shell-destructive
    analyzer: shell-destructive
    toolNotMatches: '${WRITE_TOOLS}'
    action: confirm
  - name: shell-unresolved
    analyzer: shell-unresolved
    toolNotMatches: '${WRITE_TOOLS}'
    action: confirm
  - name: sql-opaque
    analyzer: sql-opaque
    toolNotMatches: '${WRITE_TOOLS}'
    action: confirm
  - name: sql-unparseable
    analyzer: sql-unparseable
    toolNotMatches: '${WRITE_TOOLS}'
    action: confirm
  - name: mcp-destructive-tool
    toolMatches: '^mcp_.*?(^|_)(delete|del|remove|rm|destroy|drop|purge|wipe|truncate|reset|terminate|revoke|unpublish|erase|clear|cancel|kill)(_|$)'
    action: confirm
  - name: mcp-money
    toolMatches: '^mcp_.*?(^|_)(payouts?|transfers?|refunds?|charges?|payments?|pay|withdraw(al)?s?|wire|send_money|capture)(_|$)'
    toolNotMatches: '^mcp_.*?(^|_)(list|get|read|search|find|retrieve|fetch|describe|count|show)(_|$)'
    action: confirm
  - name: mcp-mass-message
    toolMatches: '^mcp_.*?(^|_)(send|post|mail|email|message|blast|newsletter|notify|campaign|broadcast)(_|$)'
    maxCount: 20
    countArgs: [recipients, to, cc, bcc]
    action: confirm
`;
/** Built-in presets, by name: usable with `extends:` in a policy file, `--preset` on the CLI, or presetPolicy(). */
export const PRESETS: Record<string, string> = { strict: DEFAULT_POLICY, "coding-agent": CODING_AGENT_POLICY };
