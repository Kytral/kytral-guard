// The SQL parser (node-sql-parser) and the verdict of a statement's syntax tree. Kept apart from the other analyzers so
// that parsing can run in a worker thread with a deadline (sql-bounded.ts): a PEG parser can take exponential time on a
// few dozen characters (unbalanced parentheses), and a guard that outlasts the agent's hook timeout fails open.
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
export const SQL_DIALECTS = ["postgresql", "mysql", "mariadb", "transactsql", "sqlite", "bigquery", "snowflake", "redshift", "hive", "db2", "flinksql", "athena", "trino", "noql"];
export const DEFAULT_SQL_DIALECT = "postgresql";
/** One parser per dialect, loaded on first use from its own build (the all-dialects bundle is several times larger to load). */
const parsers = new Map<string, any>();
function sqlParser(dialect: string): any {
  let p = parsers.get(dialect);
  if (!p) {
    let mod: any;
    try { mod = SQL_DIALECTS.includes(dialect) ? require(`node-sql-parser/build/${dialect}`) : require("node-sql-parser"); } catch { mod = require("node-sql-parser"); }
    p = new (mod.Parser ?? mod.default.Parser)(); parsers.set(dialect, p);
  }
  return p;
}

/** ok | unrestricted-write (block) | opaque (confirm: value or effect unknown statically) | unparseable (confirm) */
export type SqlVerdict = "ok" | "unrestricted-write" | "opaque" | "unparseable";

// Only real constants pin rows. Placeholders ($1, ?, @v, :v) are unknown statically; booleans match half the table.
const CONSTANT = ["number", "string", "single_quote_string", "natural_string", "hex_string", "full_hex_string", "bit_string"];
const PLACEHOLDER = ["param", "var", "origin"];
const isColumn = (n: any) => n?.type === "column_ref";
const colName = (n: any) => JSON.stringify(n?.column);
function hasSubquery(n: any): boolean {
  if (!n || typeof n !== "object") return false;
  if (n.ast || n.type === "select" || Array.isArray(n.tableList)) return true;
  return Object.values(n).some(v => Array.isArray(v) ? v.some(hasSubquery) : hasSubquery(v));
}
/** "yes" = pins rows with constants, "placeholder" = would pin rows but the value is a bind parameter, "no" otherwise. */
export function restrictiveness(w: any): "yes" | "placeholder" | "no" {
  if (!w || w.type !== "binary_expr") return "no";
  const op = String(w.operator).toUpperCase();
  const rank = { no: 0, placeholder: 1, yes: 2 } as const; const names = ["no", "placeholder", "yes"] as const;
  if (op === "AND") return names[Math.max(rank[restrictiveness(w.left)], rank[restrictiveness(w.right)])];
  if (op === "OR") return names[Math.min(rank[restrictiveness(w.left)], rank[restrictiveness(w.right)])];
  const value = (n: any) => CONSTANT.includes(n?.type) ? "yes" : PLACEHOLDER.includes(n?.type) ? "placeholder" : "no";
  if (op === "=") {
    const [c, l] = isColumn(w.left) ? [w.left, w.right] : [w.right, w.left];
    if (!isColumn(c) || (isColumn(l) && colName(l) === colName(c))) return "no";
    return value(l);
  }
  if (op === "IN" && isColumn(w.left) && w.right?.type === "expr_list" && Array.isArray(w.right.value) && w.right.value.length) {
    const vs = w.right.value.map(value);
    return vs.includes("no") ? "no" : vs.includes("placeholder") ? "placeholder" : "yes";
  }
  return "no";                                             // LIKE, >, <, IS NOT NULL, bare literal, booleans, functions...
}
export const restrictive = (w: any) => restrictiveness(w) === "yes";
function stmtVerdict(a: any): SqlVerdict {
  const t = String(a?.type ?? "").toLowerCase();
  if (t === "drop" || t === "truncate") return "unrestricted-write";
  if (t === "alter" && JSON.stringify(a).toLowerCase().includes('"drop"')) return "unrestricted-write";
  if (t === "call" || t === "exec" || t === "execute") return "opaque";                     // stored procedure: effect unknown
  if (t === "replace" && (a.values?.type === "select" || hasSubquery(a.values) || a.select)) return "unrestricted-write"; // bulk overwrite from a query
  if (t !== "delete" && t !== "update") return "ok";
  const from = a.from ?? [];
  const tables = [...(a.table ?? []), ...from];
  if (tables.some((x: any) => x?.join) || from.length > 1 || (t === "update" && from.length > 0)) return "unrestricted-write";
  if (t === "delete" && a.table?.some((x: any) => !from.some((f: any) => f.table === x.table || f.as === x.table))) return "unrestricted-write";
  if (!a.where || hasSubquery(a.where)) return "unrestricted-write";
  const r = restrictiveness(a.where);
  return r === "yes" ? "ok" : r === "placeholder" ? "opaque" : "unrestricted-write";
}
/** The verdict of a SQL text from its syntax tree, without a deadline: use parseSqlBounded (sql-bounded.ts). */
export function parseVerdict(text: string, dialect: string): SqlVerdict {
  try {
    const ast = sqlParser(dialect).astify(text, { database: dialect });
    const vs = (Array.isArray(ast) ? ast : [ast]).map(stmtVerdict);
    return vs.includes("unrestricted-write") ? "unrestricted-write" : vs.includes("opaque") ? "opaque" : "ok";
  } catch { return "unparseable"; }
}
