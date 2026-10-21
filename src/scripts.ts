// The files a command runs: shell scripts (bash x.sh, ./x.sh, source x.sh), package.json scripts (npm run x, yarn x,
// pnpm x, bun run x, install lifecycle scripts, workspace and monorepo runners), Makefile, justfile and Taskfile recipes
// (make x, just x, task x), and programs run by an interpreter (python x.py, node x.js...) with the local modules they
// import. Their content is analyzed like the command line itself, so that writing a destructive script and then running
// it is no way around the guard. Reading needs the call's working directory (agent hooks give it). Every read is bounded:
// regular text files only, 1 MB each, 64 files and 4 MB per call (imported modules: 48 files and 3 MB of those at most).
import { closeSync, openSync, readdirSync, readFileSync, readSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { parseQuietly } from "./quiet-yaml.js";

/** `dir`: where relative paths resolve now (`cd` moves it); null after a `cd` to a directory not known statically. */
interface Context {
  cwd: string; dir: string | null; script?: string;
  /** Files being analyzed (a script that runs itself is entered 3 times at most); modules imported so far; contents read. */
  active: Map<string, number>; imported: Set<string>; texts: Map<string, string | null>;
  files: number; bytes: number; optionalFiles: number; optionalBytes: number; manifests: number;
}
let current: Context | undefined;
const MAX_FILE = 1024 * 1024, MAX_FILES = 64, MAX_BYTES = 4 * 1024 * 1024, MAX_OPTIONAL_FILES = 48, MAX_OPTIONAL_BYTES = 3 * 1024 * 1024, MAX_MANIFESTS = 256;

/** A path as this platform reads it: ~ is the home directory; on Windows, /c/Users (Git Bash, MSYS) is C:/Users. */
function native(p: string): string {
  const h = p.replace(/^~(?=[\\/]|$)/, homedir());
  const m = process.platform === "win32" ? /^\/([a-zA-Z])(\/.*)?$/.exec(h) : null;
  return m ? `${m[1]}:${m[2] ?? "/"}` : h;
}
const unquote = (p: string) => p.replace(/^['"]|['"]$/g, "");
const unknownPath = (p: string) => /[\u0001*?[\]]/.test(p);

/** Runs `fn` with the files of `cwd` readable by the analyzers (without a cwd, scripts are not read). */
export function withScriptContext<T>(cwd: string | undefined, fn: () => T): T {
  if (!cwd) return fn();
  const prev = current;
  let dir = resolve(native(cwd));
  try { dir = realpathSync.native(dir); } catch {}
  current = { cwd: dir, dir, active: new Map(), imported: new Set(), texts: new Map(), files: 0, bytes: 0, optionalFiles: 0, optionalBytes: 0, manifests: 0 };
  try { return fn(); } finally { current = prev; }
}
/** Runs `fn` without reading local files: the commands of another host or a container (ssh host …, docker exec …). */
export function withoutScripts<T>(fn: () => T): T {
  const prev = current;
  current = undefined;
  try { return fn(); } finally { current = prev; }
}
export const scriptContextActive = () => !!current;

/** Where the analysis stands (to restore after a subshell). */
export const scriptDir = () => current?.dir;
export function restoreScriptDir(dir: string | null | undefined): void { if (current && dir !== undefined) current.dir = dir; }
/**
 * `cd target` in the analyzed command (undefined: `cd` alone, the home directory; null: popd, or a directory not known
 * statically). Inside a script, `cd "$(dirname "$0")/.."` style idioms mean the script's own directory.
 */
export function changeScriptDir(target: string | null | undefined): void {
  const c = current;
  if (!c) return;
  if (target === undefined) { c.dir = homedir(); return; }
  const p = target === null ? "" : unquote(target);
  if (p && c.script && /^\u0001VAR\u0001(dirname|cd|realpath|readlink)\u0001/.test(p)) {
    const tail = p.replace(/^(\u0001VAR\u0001(dirname|cd|realpath|readlink)\u0001)+/, "");
    if (!unknownPath(tail)) { c.dir = resolve(dirname(c.script), "./" + tail); return; }
  }
  if (!p || p === "-" || unknownPath(p)) { c.dir = null; return; }
  const full = native(p);
  c.dir = isAbsolute(full) ? resolve(full) : c.dir === null ? null : resolve(c.dir, full);
}
/** Runs `fn` as the analysis of the script at `path`, run in a child process: its `cd` does not move the caller. */
export function inScript<T>(path: string, fn: () => T): T {
  const c = current;
  if (!c) return fn();
  const { dir, script } = c;
  c.script = path;
  c.active.set(path, (c.active.get(path) ?? 0) + 1);
  try { return fn(); } finally { c.dir = dir; c.script = script; c.active.set(path, (c.active.get(path) ?? 1) - 1); }
}
/** The directories a relative path may resolve from: the current one, or after a `cd` nobody can follow, the likely ones. */
function bases(c: Context): string[] {
  return c.dir !== null ? [c.dir] : [...new Set([c.script ? dirname(c.script) : "", c.cwd].filter(Boolean))];
}

export type ScriptRead =
  | { kind: "text"; path: string; text: string }
  | { kind: "missing" }                          // no such file (or not a regular file): the command will fail
  | { kind: "unreadable"; why: string }          // exists but cannot be judged: too large, binary, over budget
  | { kind: "seen" };                            // being analyzed already (a script that runs itself), or a module imported already

/**
 * Reads a file the command runs, relative to the call's working directory. Undefined without a context. `optional`
 * reads (the modules a program imports) have a smaller budget, so they never crowd out the scripts a command names.
 */
export function readScript(p0: string, optional = false): ScriptRead | undefined {
  const c = current;
  if (!c) return undefined;
  const p = native(unquote(p0));
  if (!p || unknownPath(p)) return { kind: "unreadable", why: "its path is not known statically" };
  let full = "", size = -1;
  for (const b of isAbsolute(p) ? [""] : bases(c)) {
    const f = b ? resolve(b, p) : resolve(p);
    try { const st = statSync(f); if (st.isFile()) { full = f; size = st.size; break; } } catch {}
  }
  if (size < 0) return { kind: "missing" };
  try { full = realpathSync.native(full); } catch {}
  if (optional ? c.imported.has(full) : (c.active.get(full) ?? 0) >= 3) return { kind: "seen" };
  const cached = c.texts.get(full);
  if (cached !== undefined) { if (optional) c.imported.add(full); return cached === null ? { kind: "unreadable", why: "it is a binary file" } : { kind: "text", path: full, text: cached }; }
  if (size > MAX_FILE) {
    // a large program run by its path is usually a binary (perl, python3): its first bytes tell
    let head = Buffer.alloc(0);
    try { const fd = openSync(full, "r"); try { head = Buffer.alloc(4096); head = head.subarray(0, readSync(fd, head, 0, 4096, 0)); } finally { closeSync(fd); } } catch {}
    return { kind: "unreadable", why: head.includes(0) ? "it is a binary file" : `it is too large to analyze (${Math.round(size / 1024)} KB)` };
  }
  if (c.files >= MAX_FILES || c.bytes + size > MAX_BYTES || (optional && (c.optionalFiles >= MAX_OPTIONAL_FILES || c.optionalBytes + size > MAX_OPTIONAL_BYTES)))
    return { kind: "unreadable", why: "this call runs too many scripts to analyze" };
  let buf: Buffer;
  try { buf = readFileSync(full); } catch { return { kind: "missing" }; }
  c.files++; c.bytes += buf.length;
  if (optional) { c.optionalFiles++; c.optionalBytes += buf.length; c.imported.add(full); }
  const binary = buf.subarray(0, 8192).includes(0);
  c.texts.set(full, binary ? null : buf.toString("utf8"));
  if (binary) return { kind: "unreadable", why: "it is a binary file" };
  return { kind: "text", path: full, text: c.texts.get(full)! };
}
/** A small project file (package.json, pnpm-workspace.yaml): read whole, outside the script budget (at most 256 per call). */
function readManifest(path: string): string | undefined {
  const c = current;
  if (!c || c.manifests >= MAX_MANIFESTS) return undefined;
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > MAX_FILE) return undefined;
    c.manifests++;
    return readFileSync(path, "utf8");
  } catch { return undefined; }
}
/** The nearest of `names` in `dir` or its parents (how npm finds package.json and just its justfile). */
function findUp(dir: string, names: string[]): string | undefined {
  const c = current;
  if (!c) return undefined;
  const d0 = native(unquote(dir));
  if (unknownPath(d0)) return undefined;
  for (const b of isAbsolute(d0) ? [""] : bases(c)) {
    let d = b ? resolve(b, d0) : resolve(d0);
    for (let k = 0; k < 32; k++) {
      for (const n of names) { const f = join(d, n); try { if (statSync(f).isFile()) return f; } catch {} }
      const up = dirname(d);
      if (up === d) break;
      d = up;
    }
  }
  return undefined;
}

/** The language of a script run directly (./x): from its shebang, else a shell script. */
export function scriptLanguage(text: string): "shell" | "python" | "node" | "ruby" | "perl" | "php" | "other" {
  const m = /^#!\s*(\S+)(?:\s+(\S+))?(?:\s+(\S+))?/.exec(text);
  if (!m) return "shell";
  let prog = (m[1].replace(/^.*\//, "") === "env" ? (m[2] === "-S" ? m[3] : m[2]) ?? "" : m[1]).replace(/^.*\//, "");
  if (/^-/.test(prog)) prog = m[3] ?? "";
  if (/^(sh|bash|zsh|dash|ksh|ash|mksh|yash|busybox)$/.test(prog)) return "shell";
  if (/^python[\d.]*$/.test(prog)) return "python";
  if (/^(node|nodejs|deno|bun|tsx|ts-node|zx)$/.test(prog)) return "node";
  if (prog === "ruby") return "ruby";
  if (prog === "perl") return "perl";
  if (/^php[\d.]*$/.test(prog)) return "php";
  return "other";
}

export interface PackageScripts { file: string; scripts: Record<string, string> }
function scriptsOf(file: string): PackageScripts | undefined {
  const text = readManifest(file);
  if (text === undefined) return undefined;
  try {
    const s = JSON.parse(text)?.scripts;
    return { file, scripts: s && typeof s === "object" ? Object.fromEntries(Object.entries(s).filter((e): e is [string, string] => typeof e[1] === "string")) : {} };
  } catch { return undefined; }
}
/**
 * The package.json scripts a package manager command runs: the nearest package.json from `dir` up (npm's rule), and with
 * `workspaces`, those of every workspace package too (a run by workspace name, filter or recursion).
 */
export function packageScripts(dir: string, workspaces: boolean): PackageScripts[] | undefined {
  const root = findUp(dir, ["package.json"]);
  if (!root) return undefined;
  const top = scriptsOf(root);
  if (!top) return undefined;
  const out = [top];
  if (workspaces) for (const d of workspaceDirs(dirname(root))) { const s = scriptsOf(join(d, "package.json")); if (s) out.push(s); }
  return out;
}
/** The workspace packages of a JS monorepo: package.json "workspaces" and pnpm-workspace.yaml "packages" (dir, dir/*, dir/**). */
function workspaceDirs(root: string): string[] {
  const patterns: unknown[] = [];
  try { const w = JSON.parse(readManifest(join(root, "package.json")) ?? "{}")?.workspaces; patterns.push(...(Array.isArray(w) ? w : Array.isArray(w?.packages) ? w.packages : [])); } catch {}
  try { const y = (parseQuietly(readManifest(join(root, "pnpm-workspace.yaml")) ?? "") as { packages?: unknown } | null)?.packages; if (Array.isArray(y)) patterns.push(...y); } catch {}
  const dirs = new Set<string>();
  const subdirs = (d: string) => { try { return readdirSync(d, { withFileTypes: true }).filter(e => e.isDirectory() && e.name !== "node_modules" && !e.name.startsWith(".")).map(e => join(d, e.name)); } catch { return []; } };
  for (const p of patterns) {
    if (typeof p !== "string" || p.startsWith("!") || dirs.size > 400) continue;
    const m = /^(.*?)\/?(\*\*?)$/.exec(p.replace(/\\/g, "/"));
    if (!m) { dirs.add(resolve(root, p)); continue; }
    for (const d of subdirs(resolve(root, m[1] || "."))) { dirs.add(d); if (m[2] === "**") for (const e of subdirs(d)) dirs.add(e); }
  }
  return [...dirs].filter(d => { try { return statSync(join(d, "package.json")).isFile(); } catch { return false; } }).slice(0, 200);
}

/** Make's predefined variables that recipes commonly use. */
const MAKE_DEFAULTS: Record<string, string> = { RM: "rm -f", MAKE: "make", CC: "cc", CXX: "g++", CPP: "cc -E", AR: "ar", AS: "as", LD: "ld", INSTALL: "install", SHELL: "/bin/sh", MKDIR_P: "mkdir -p" };
/** A recipe line, and whether it runs even under `make -n` (a `+` prefix). */
export interface RecipeLine { text: string; forced: boolean }
export type Recipes = { lines: RecipeLine[]; file: string } | { error: string } | undefined;

/**
 * The recipe lines `make` runs for these targets (the first target when none is given) and their prerequisites, with the
 * makefile's own variables expanded. Variables it does not define stay shell variables (unknown statically): an empty
 * one in `rm -rf $(BUILD_DIR)/*` deletes everything, so the analysis must not assume a value. `evals`: --eval snippets.
 */
export function makeRecipes(targets: string[], file: string | undefined, assigns: Record<string, string>, dir = ".", evals: string[] = []): Recipes {
  if (!current) return undefined;
  let r: ScriptRead | undefined;
  let used = "";
  for (const f of file ? [file] : ["GNUmakefile", "makefile", "Makefile"]) { used = isAbsolute(native(f)) ? f : join(dir, f); r = readScript(used); if (r?.kind !== "missing") break; }
  if (!r || r.kind === "missing") return evals.length ? makeParse("", targets, assigns, evals, "--eval") : undefined;
  if (r.kind === "seen") return { lines: [], file: used };
  if (r.kind === "unreadable") return { error: `${used}: ${r.why}` };
  return makeParse(r.text, targets, assigns, evals, r.path);
}
function makeParse(text: string, targets: string[], assigns: Record<string, string>, evals: string[], file: string): Recipes {
  const vars: Record<string, string> = { ...MAKE_DEFAULTS };
  const rules = new Map<string, { deps: string[]; recipe: string[] }>();
  let first: string | undefined, cur: { deps: string[]; recipe: string[] }[] = [];
  const lines = [text, ...evals].join("\n").replace(/\\\r?\n/g, " ").split(/\r?\n/);
  for (const raw of lines) {
    if (/^\t/.test(raw)) { for (const rule of cur) rule.recipe.push(raw.slice(1)); continue; }
    const line = raw.replace(/(^|[^\\])#.*$/, "$1").trimEnd();
    if (!line.trim()) continue;
    if (/^\s*(-?include|sinclude|ifn?eq|ifn?def|else|endif|define|endef|vpath|unexport)\b/.test(line)) { cur = []; continue; }
    const a = /^\s*(?:override\s+|export\s+)?([A-Za-z_][\w.-]*)\s*(\?|:{1,3}|\+|!)?=\s*(.*)$/.exec(line);
    if (a) { vars[a[1]] = a[2] === "+" && vars[a[1]] ? `${vars[a[1]]} ${a[3]}` : vars[a[1]] && a[2] === "?" ? vars[a[1]] : a[3]; cur = []; continue; }
    const t = /^([^:=\s][^:=]*?)\s*::?\s*([^=]*)$/.exec(line);
    if (t) {
      const names = t[1].split(/\s+/).filter(Boolean), [deps, inline] = t[2].split(/;(.*)/s);
      cur = names.filter(n => !n.startsWith(".")).map(n => { const e = rules.get(n) ?? { deps: [], recipe: [] }; rules.set(n, e); return e; });
      for (const rule of cur) { rule.deps.push(...deps.split(/\s+/).filter(Boolean)); if (inline?.trim()) rule.recipe.push(inline.trim()); }
      first ??= names.find(n => !n.startsWith(".") && !n.includes("%"));
      continue;
    }
    cur = [];
  }
  Object.assign(vars, assigns);
  const expand = (s: string, target: string, depth = 0): string => s.replace(/\$\$|\$\(([^()]+)\)|\$\{([^{}]+)\}|\$([@<^?*+|%])/g, (m, a, b, auto) => {
    if (m === "$$") return "$";
    if (auto) return auto === "@" ? target : "file";
    const name = (a ?? b) as string;
    if (/\s/.test(name)) return "$MAKE_FUNCTION";                      // $(shell ...), $(wildcard ...): unknown statically
    if (Object.hasOwn(vars, name) && depth < 8) return expand(vars[name], target, depth + 1);
    return `$${name.replace(/\W/g, "_")}`;                                // not defined here: a shell variable for the analysis
  });
  const out: RecipeLine[] = [], done = new Set<string>();
  const visit = (t: string, depth: number) => {
    if (done.has(t) || done.size > 200 || depth > 20) return;
    done.add(t);
    const rule = rules.get(t);
    if (!rule) return;
    for (const d of rule.deps) visit(expand(d, t), depth + 1);
    for (const l of rule.recipe) {
      const body = l.trimStart(), prefix = /^[@+-]*/.exec(body)![0];
      out.push({ text: expand(body.slice(prefix.length), t), forced: prefix.includes("+") });
    }
  };
  for (const t of targets.length ? targets : first ? [first] : []) visit(t, 0);
  return { lines: out, file };
}

/** A justfile recipe body: shell lines, or a whole script in another language (a shebang recipe). */
export interface JustBody { kind: "shell" | "script"; text: string }
/**
 * The recipe bodies `just` runs for these arguments (recipe names and their parameters; the first recipe by default) and
 * their dependencies, with the justfile's variables and the given parameters interpolated. Other expressions stay unknown.
 */
export function justRecipes(args: string[], file: string | undefined, dir = "."): { bodies: JustBody[]; file: string } | { error: string } | undefined {
  if (!current) return undefined;
  const path = file ? (isAbsolute(native(file)) ? file : join(dir, file)) : findUp(dir, ["justfile", "Justfile", "JUSTFILE", ".justfile"]);
  if (!path) return undefined;
  const r = readScript(path);
  if (!r || r.kind === "missing") return undefined;
  if (r.kind === "seen") return { bodies: [], file: path };
  if (r.kind === "unreadable") return { error: `${path}: ${r.why}` };
  const vars: Record<string, string> = {};
  const recipes = new Map<string, { params: { name: string; variadic: boolean; def?: string }[]; deps: string[]; body: string[] }>();
  const order: string[] = [];
  let cur: { body: string[] } | undefined;
  for (const raw of r.text.split(/\r?\n/)) {
    if (cur && (/^[ \t]+\S/.test(raw) || (!raw.trim() && cur.body.length))) { cur.body.push(raw.replace(/^[ \t]+/, "")); continue; }
    cur = undefined;
    const line = raw.replace(/\s+#.*$/, "");
    if (!line.trim() || /^\s*(#|\[|set\s|alias\s|import\s|mod\s)/.test(line)) continue;
    const v = /^(?:export\s+)?([A-Za-z_][\w-]*)\s*:=\s*(.*)$/.exec(line);
    if (v) { const val = v[2].trim(); vars[v[1]] = /^(['"]).*\1$/.test(val) ? val.slice(1, -1) : /^`/.test(val) ? "$JUST_EXPR" : val; continue; }
    const h = /^@?([A-Za-z_][\w-]*)((?:\s+[+*$]?[A-Za-z_][\w-]*(?:=(?:'[^']*'|"[^"]*"|\S+))?)*)\s*:(?!=)(.*)$/.exec(line);
    if (h) {
      const params = [...h[2].matchAll(/([+*$]?)([A-Za-z_][\w-]*)(?:=('[^']*'|"[^"]*"|\S+))?/g)].map(m => ({ name: m[2], variadic: m[1] === "+" || m[1] === "*", def: m[3]?.replace(/^['"]|['"]$/g, "") }));
      const deps = [...h[3].replace(/\(([^()]*)\)/g, (_m, inner: string) => inner.trim().split(/\s+/)[0] ?? "").matchAll(/[A-Za-z_][\w-]*/g)].map(m => m[0]);
      const recipe = { params, deps, body: [] as string[] };
      recipes.set(h[1], recipe); order.push(h[1]); cur = recipe;
    }
  }
  const interp = (s: string, scope: Record<string, string>) => s.replace(/\{\{\s*([^{}]*?)\s*\}\}/g, (_m, e: string) => Object.hasOwn(scope, e) ? scope[e] : Object.hasOwn(vars, e) ? vars[e] : "$JUST_EXPR");
  const bodies: JustBody[] = [], done = new Set<string>();
  const run = (name: string, given: string[], depth: number) => {
    const rec = recipes.get(name);
    if (!rec || done.has(name) || depth > 20) return;
    done.add(name);
    for (const d of rec.deps) run(d, [], depth + 1);
    const scope: Record<string, string> = {};
    rec.params.forEach((p, k) => { scope[p.name] = p.variadic ? given.slice(k).join(" ") : given[k] ?? p.def ?? "$JUST_PARAM"; });
    const body = rec.body.join("\n").trimEnd();
    if (/^#!/.test(body)) bodies.push({ kind: "script", text: interp(body, scope) });
    else bodies.push({ kind: "shell", text: rec.body.map(l => interp(l.replace(/^[@-]+/, ""), scope)).join("\n") });
  };
  const realPath = r.path;
  if (!args.length && order[0]) run(order[0], [], 0);
  for (let k = 0; k < args.length;) {
    const rec = recipes.get(args[k]);
    if (!rec) { k++; continue; }
    const n = rec.params.some(p => p.variadic) ? args.length - k - 1 : Math.min(rec.params.length, args.length - k - 1);
    run(args[k], args.slice(k + 1, k + 1 + n), 0);
    k += 1 + n;
  }
  return { bodies, file: realPath };
}

/** The commands a Taskfile (go-task) runs for these tasks (the `default` task when none is given) and their dependencies. */
export function taskCommands(tasks: string[], file: string | undefined, dir = "."): { lines: string[]; file: string } | { error: string } | undefined {
  if (!current) return undefined;
  const path = file ? (isAbsolute(native(file)) ? file : join(dir, file)) : findUp(dir, ["Taskfile.yml", "taskfile.yml", "Taskfile.yaml", "taskfile.yaml", "Taskfile.dist.yml", "Taskfile.dist.yaml"]);
  if (!path) return undefined;
  const r = readScript(path);
  if (!r || r.kind === "missing") return undefined;
  if (r.kind === "seen") return { lines: [], file: path };
  if (r.kind === "unreadable") return { error: `${path}: ${r.why}` };
  let doc: any;
  try { doc = parseQuietly(r.text); } catch (e) { return { error: `${path} is not valid YAML (${(e as Error).message.split("\n")[0]})` }; }
  const all = doc?.tasks && typeof doc.tasks === "object" ? doc.tasks : {};
  const vars: Record<string, string> = {};
  for (const [k, v] of Object.entries(doc?.vars ?? {})) if (typeof v === "string" || typeof v === "number") vars[k] = String(v);
  const interp = (s: string) => s.replace(/\{\{\s*\.(\w+)\s*\}\}/g, (_m, n: string) => Object.hasOwn(vars, n) ? vars[n] : `$TASK_${n}`).replace(/\{\{[^{}]*\}\}/g, "$TASK_EXPR");
  const lines: string[] = [], done = new Set<string>();
  const run = (name: unknown, depth: number) => {
    if (typeof name !== "string" || done.has(name) || depth > 20 || !Object.hasOwn(all, name)) return;
    done.add(name);
    const t = all[name], task = typeof t === "string" ? { cmds: [t] } : Array.isArray(t) ? { cmds: t } : t;
    for (const d of Array.isArray(task?.deps) ? task.deps : []) run(typeof d === "string" ? d : d?.task, depth + 1);
    for (const c of Array.isArray(task?.cmds) ? task.cmds : typeof task?.cmd === "string" ? [task.cmd] : []) {
      if (typeof c === "string") lines.push(interp(c));
      else if (typeof c?.cmd === "string") lines.push(interp(c.cmd));
      else if (typeof c?.task === "string") run(c.task, depth + 1);
    }
  };
  for (const t of tasks.length ? tasks : ["default"]) run(t, 0);
  return { lines, file: r.path };
}

/**
 * The local files of the modules a program imports by a relative path (or a sibling module, in Python). `view`: the text
 * with strings and comments blanked: an import statement quoted in a string or a comment is not one.
 */
export function programImports(text: string, from: string, lang: string, view?: string): string[] {
  const dir = dirname(from), out: string[] = [];
  const found = (re: RegExp) => [...text.matchAll(re)].filter(m => { const k = m.index! + m[0].search(/\S/); return !view || view[k] === text[k]; });
  const exists = (p: string) => { try { return statSync(p).isFile(); } catch { return false; } };
  const first = (cands: string[]) => cands.find(exists);
  const add = (p: string | undefined) => { if (p && out.length < 100 && !out.includes(p)) out.push(p); };
  if (lang === "node") {
    for (const m of found(/(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)['"](\.{1,2}\/[^'"\n]+)['"]/g)) {
      const s = resolve(dir, m[1]), noExt = s.replace(/\.(m?js|cjs|jsx)$/, "");
      add(first([s, ...[".ts", ".tsx", ".mts", ".cts"].map(e => noExt + e), ...[".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".jsx"].map(e => s + e), ...["index.js", "index.ts", "index.mjs"].map(i => join(s, i))]));
    }
  } else if (lang === "python") {
    for (const m of found(/^[ \t]*from[ \t]+(\.*)([\w.]*)[ \t]+import[ \t]+\(?([\w, \t]+)/gm)) {
      const up = m[1].length, base = up ? resolve(dir, ...Array<string>(Math.max(0, up - 1)).fill("..")) : dir, mod = m[2].replace(/\./g, "/");
      if (mod) add(first([join(base, mod + ".py"), join(base, mod, "__init__.py")]));
      else for (const n of m[3].split(",").map(x => x.trim()).filter(Boolean)) add(first([join(base, n + ".py")]));
    }
    for (const m of found(/^[ \t]*import[ \t]+([\w., \t]+)/gm)) for (const n of m[1].split(",").map(x => x.trim().split(/\s+/)[0]).filter(Boolean)) {
      const mod = n.replace(/\./g, "/");
      add(first([join(dir, mod + ".py"), join(dir, mod, "__init__.py")]));
    }
  } else if (lang === "ruby") {
    for (const m of found(/\brequire_relative\s*\(?\s*['"]([^'"\n]+)['"]/g)) { const s = resolve(dir, m[1]); add(first([s, s + ".rb"])); }
  } else {
    for (const m of found(/\b(?:require|include|require_once|include_once|do)\s*\(?\s*['"]([^'"\n]+\.(?:php|inc|pl|pm))['"]/g)) add(first([resolve(dir, m[1])]));
  }
  return out;
}
/** A path for messages: relative to the call's working directory when it is inside it. */
export function shownPath(p: string): string {
  const c = current;
  if (!c) return p;
  const r = relative(c.cwd, p);
  return r && !r.startsWith("..") && !isAbsolute(r) ? r.replace(/\\/g, "/") : p;
}

/**
 * The client-side hooks directory of the repository holding `dir` (git -C), or the working directory: core.hooksPath
 * (-c on the command line, the repository's config, then ~/.gitconfig), else <git dir>/hooks; with husky, its folder.
 */
export function gitHooksDir(dir = ".", hooksPath?: string): { dir: string; husky?: string } | undefined {
  const c = current;
  if (!c) return undefined;
  const dot = findUpAny(dir, ".git");
  if (!dot) return undefined;
  const top = dirname(dot);
  let gitDir = dot;
  try { if (statSync(dot).isFile()) { const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(dot, "utf8")); if (!m) return undefined; gitDir = resolve(top, m[1].trim()); } } catch { return undefined; }
  let common = gitDir;
  try { common = resolve(gitDir, readFileSync(join(gitDir, "commondir"), "utf8").trim()); } catch {}
  const configured = hooksPath ?? [join(common, "config"), join(homedir(), ".gitconfig"), join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "git", "config")]
    .map(f => { try { return iniValue(readFileSync(f, "utf8"), "core", "hookspath"); } catch { return undefined; } }).find(v => v !== undefined);
  if (configured === undefined) return { dir: join(common, "hooks") };
  const hooks = resolve(top, native(configured));
  return { dir: hooks, husky: /(^|[\\/])\.husky([\\/]_)?[\\/]?$/.test(hooks) ? hooks.replace(/[\\/]_[\\/]?$/, "") : undefined };
}
/** The nearest `name` (a file or a folder) in `dir` or its parents. */
function findUpAny(dir: string, name: string): string | undefined {
  const c = current;
  if (!c) return undefined;
  const d0 = native(unquote(dir));
  if (unknownPath(d0)) return undefined;
  for (const b of isAbsolute(d0) ? [""] : bases(c)) {
    let d = b ? resolve(b, d0) : resolve(d0);
    for (let k = 0; k < 32; k++) {
      try { statSync(join(d, name)); return join(d, name); } catch {}
      const up = dirname(d);
      if (up === d) break;
      d = up;
    }
  }
  return undefined;
}
/** A value of a git config file (INI): the last `key = value` of `[section]`, case-insensitive. */
function iniValue(text: string, section: string, key: string): string | undefined {
  let cur = "", out: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const s = /^\[\s*([^\]\s"]+)/.exec(line);
    if (s) { cur = s[1].toLowerCase(); continue; }
    const kv = /^([A-Za-z][\w-]*)\s*=\s*(.*)$/.exec(line);
    if (kv && cur === section && kv[1].toLowerCase() === key) out = kv[2].replace(/\s[#;].*$/, "").trim().replace(/^"(.*)"$/, "$1");
  }
  return out;
}
