// Every text of the dashboard that a language must say, collected from the sources: the page (elements marked data-i18n and
// the attributes listed in data-i18n-attr), its script (the texts given to t, tn and N), the server's messages (said and
// UserError) and the words of the sentences (src/plain.ts) and rules (src/dashboard-rules.ts). Used by test/i18n.test.ts,
// and to list what a new language has to translate: node --import tsx test/i18n-keys.ts
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { lockReason, RULE_INFO } from "../src/dashboard-rules.js";
import { ACTION_PHRASES, REASON_KEYS, SENTENCES } from "../src/plain.js";

export const ROOT = resolve(import.meta.dirname, "..");
const read = (f: string) => readFileSync(join(ROOT, f), "utf8");
const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"]);
const decode = (s: string) => s.replace(/&(amp|lt|gt|quot|#39);/g, (_m, e: string) => ({ amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'" })[e]!);

interface Node { tag: string; attrs: Record<string, string>; kids: (Node | string)[] }
/** The page's texts: the template of each data-i18n element ({0}, {1}... for its child elements), and the listed attributes. */
export function htmlKeys(html: string): string[] {
  const root: Node = { tag: "", attrs: {}, kids: [] }, stack = [root], keys: string[] = [];
  const token = /<!--[\s\S]*?-->|<!doctype[^>]*>|<(\/?)([a-zA-Z][\w-]*)((?:\s+[^\s=>/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(\/?)>|([^<]+)/gi;
  for (const m of html.matchAll(token)) {
    if (m[5] !== undefined) { stack.at(-1)!.kids.push(m[5]); continue; }
    if (!m[2]) continue;
    const tag = m[2].toLowerCase();
    if (m[1]) { while (stack.length > 1 && stack.pop()!.tag !== tag) { /* unclosed elements end here */ } continue; }
    const attrs: Record<string, string> = {};
    for (const a of (m[3] ?? "").matchAll(/([^\s=>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) attrs[a[1].toLowerCase()] = decode(a[2] ?? a[3] ?? a[4] ?? "");
    const node: Node = { tag, attrs, kids: [] };
    stack.at(-1)!.kids.push(node);
    if (!m[4] && !VOID.has(tag)) stack.push(node);
  }
  const visit = (n: Node) => {
    if ("data-i18n" in n.attrs) {
      let i = 0;
      keys.push(n.kids.map(k => (typeof k === "string" ? decode(k) : `{${i++}}`)).join("").replace(/\s+/g, " ").trim());
    }
    for (const a of (n.attrs["data-i18n-attr"] ?? "").split(/\s+/).filter(Boolean)) keys.push(n.attrs[a] ?? "");
    for (const k of n.kids) if (typeof k !== "string") visit(k);
  };
  visit(root);
  return keys;
}

/** The arguments of each call to `name(` in a script: the double-quoted strings of each argument (ternaries give several). */
function calls(src: string, name: string): string[][][] {
  const out: string[][][] = [];
  // `name(` called directly or spread (...said(...)), not a method of another object (x.said)
  for (const m of src.matchAll(new RegExp(String.raw`(?:(?<![\w$.])|(?<=\.\.\.))${name}\(`, "g"))) {
    const args: string[][] = [[]];
    let depth = 1, i = m.index! + m[0].length;
    while (i < src.length && depth > 0) {
      const c = src[i];
      if (c === '"' || c === "'" || c === "`") {
        let j = i + 1;
        while (j < src.length && src[j] !== c) j += src[j] === "\\" ? 2 : 1;
        if (c === '"' && depth === 1) args.at(-1)!.push(JSON.parse(src.slice(i, j + 1)));
        i = j + 1; continue;
      }
      if (c === "(" || c === "[" || c === "{") depth++;
      else if (c === ")" || c === "]" || c === "}") depth--;
      else if (c === "," && depth === 1) args.push([]);
      i++;
    }
    out.push(args);
  }
  return out;
}
/** A string compared or used as an identifier ("deny", "approve_always"), not a text. */
const word = (s: string) => /^[a-z_]+$/.test(s);

export interface Keys {
  /** Every text, US English. */
  all: Set<string>;
  /** Texts said with a count (tn): their translation can be an object of plural forms; `other` is the English plural. */
  plurals: Map<string, string>;
  /** Sentences whose subject is who decided ("{by} ..."): a language can give them a "|you" variant. */
  you: Set<string>;
  /** The phrases that say what a call did, placed after "tried to", "wants to"... */
  phrases: Set<string>;
}
export function collectKeys(): Keys {
  const all = new Set<string>(), plurals = new Map<string, string>();
  const add = (k: string) => { if (k && !word(k)) all.add(k); };
  htmlKeys(read("src/dashboard/index.html")).forEach(add);
  const app = read("src/dashboard/app.js");
  for (const [a] of calls(app, "t")) a?.forEach(add);
  for (const [a] of calls(app, "N")) a?.forEach(add);
  for (const [, one, other] of calls(app, "tn")) if (one?.[0] && other?.[0]) { all.add(one[0]); plurals.set(one[0], other[0]); }
  const server = read("src/dashboard.ts");
  for (const [a] of calls(server, "said")) a?.forEach(add);
  for (const [a] of calls(read("src/install.ts"), "issue")) a?.forEach(add);   // hook problems shown on the page
  for (const [, b] of calls(server, "new UserError")) b?.forEach(add);
  for (const scope of Object.values(RULE_INFO)) for (const r of scope) { add(r.name); add(r.group); }
  for (const lock of [undefined, "allow", "all"] as const) add(lockReason(lock ? { lock } as never : undefined, "allow") ?? "");
  for (const s of Object.values(SENTENCES)) all.add(s);
  for (const p of ACTION_PHRASES) all.add(p);
  for (const r of REASON_KEYS) all.add(r);
  for (const w of ["You", "An agent", "Someone"]) all.add(w);
  const you = new Set<string>([SENTENCES.confirmed, SENTENCES.confirmedAlways, SENTENCES.kill, SENTENCES.resume, SENTENCES.knownAdd, SENTENCES.knownRemove, SENTENCES.refused, SENTENCES.change, ...REASON_KEYS]);
  return { all, plurals, you, phrases: new Set(ACTION_PHRASES) };
}

// as a script: the texts to translate, as a JSON dictionary (English: English), plural texts as { one, other }
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const k = collectKeys();
  const dict = Object.fromEntries([...k.all].sort().map(key => [key, k.plurals.has(key) ? { one: key, other: k.plurals.get(key) } : key]));
  console.log(JSON.stringify(dict, null, 1));
  console.error(`${k.all.size} texts, ${k.plurals.size} with a count, ${k.phrases.size} action phrases`);
}
