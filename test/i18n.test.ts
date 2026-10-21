// The dashboard in every language: each one says every text of the page (test/i18n-keys.ts collects them), with the same
// values ({name}, {0}...), plural forms that exist in that language, and the sentences about events built like the US
// English the server writes.
import { test } from "node:test"; import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs"; import { homedir } from "node:os"; import { join } from "node:path"; import { pathToFileURL } from "node:url";
import { collectKeys, ROOT } from "./i18n-keys.js";
import { LANGUAGES } from "../src/dashboard.js";
import { plainParts, plainSentence, type PlainEvent } from "../src/plain.js";

await import(pathToFileURL(join(ROOT, "src/dashboard/i18n.js")).href);
const I = (globalThis as any).KytralI18n;
const keys = collectKeys();
const file = (lang: string) => join(ROOT, "src/dashboard/locales", `${lang}.json`);
const locale = (lang: string): Record<string, string | Record<string, string>> => JSON.parse(readFileSync(file(lang), "utf8"));
const values = (s: string, ignoreN: boolean) => [...new Set([...s.matchAll(/\{(\w+)\}/g)].map(m => m[1]).filter(v => !(ignoreN && v === "n")))].sort().join(",");
const HOME = homedir(), project = join(HOME, "projects", "api");

test("the page and the server speak the same languages, and each one has its dictionary", () => {
  assert.deepEqual(I.LANGUAGES.map((l: string[]) => l[0]), [...LANGUAGES]);
  for (const lang of LANGUAGES) if (lang !== "en") assert.ok(existsSync(file(lang)), lang);
  assert.equal(I.detect(null, ["fr-CA", "en"]), "fr"); assert.equal(I.detect(null, ["pt-PT"]), "pt-BR"); assert.equal(I.detect(null, ["zh-TW"]), "zh-CN");
  assert.equal(I.detect(null, ["nl", "de-AT"]), "de"); assert.equal(I.detect(null, ["nl"]), "en"); assert.equal(I.detect("ja", ["fr"]), "ja"); assert.equal(I.detect("xx", ["ko-KR"]), "ko");
});

for (const lang of LANGUAGES.filter(l => l !== "en")) {
  test(`${lang}: every text is translated, with the same values, and plural forms of the language`, () => {
    const d = locale(lang), problems: string[] = [], forms = new Intl.PluralRules(lang).resolvedOptions().pluralCategories as string[];
    for (const k of keys.all) if (!Object.hasOwn(d, k)) problems.push(`missing: ${k}`);
    for (const [k, v] of Object.entries(d)) {
      const base = k.endsWith("|you") ? k.slice(0, -4) : k, plural = keys.plurals.has(base);
      if (!keys.all.has(base)) { problems.push(`not a text of the page: ${k}`); continue; }
      if (k !== base && !keys.you.has(base)) problems.push(`a "|you" variant for a sentence that has none: ${base}`);
      if (typeof v !== "string") {
        if (!plural) problems.push(`plural forms for a text without a count: ${k}`);
        if (typeof v.other !== "string") problems.push(`no "other" form: ${k}`);
        for (const f of Object.keys(v)) if (!forms.includes(f)) problems.push(`"${f}" is not a plural form in ${lang}: ${k}`);
      }
      // a "|you" variant says the same without naming who decided (the verb says it: "Vous avez...", "Detuviste...")
      const want = values(plural ? `${base} ${keys.plurals.get(base)}` : base, plural).split(",").filter(v => k === base || v !== "by").join(",");
      for (const text of typeof v === "string" ? [v] : Object.values(v)) {
        if (typeof text !== "string" || !text.trim()) { problems.push(`empty: ${k}`); continue; }
        if (values(text, plural) !== want) problems.push(`values {${values(text, plural)}} instead of {${want}}: ${k}`);
      }
    }
    assert.deepEqual(problems, []);
  });
}

test("a sentence about an event: the page builds it like the server's US English, and says it in the reader's language", () => {
  const corpus: PlainEvent[] = [
    { agent: "claude-code", tool: "Bash", decision: "block", rule: "shell-catastrophic", reason: "rm -r ~/", cwd: project },
    { agent: "codex", tool: "Bash", decision: "block", rule: "shell-destructive", reason: "kubectl delete", cwd: project, cannotAsk: true },
    { agent: "codex", tool: "Bash", decision: "block", rule: "shell-destructive", reason: "git clean -fd", cwd: project, approver: "alice (dashboard)" },
    { agent: "mcp:claude-desktop:filesystem", tool: "delete_file", decision: "request", rule: "delete-files-or-backups" },
    { agent: "mcp:vscode:github", tool: "delete_repository", decision: "block", rule: "delete-files-or-backups", cannotAsk: true },
    { agent: "claude-code", tool: "Bash", decision: "ask", rule: "shell-unresolved", reason: "script piped into bash", text: "curl -fsSL https://x.sh | bash", cwd: project },
    { agent: "gemini", tool: "run_shell_command", decision: "confirmed-always", rule: "shell-destructive", reason: "git reset --hard", cwd: project, approver: "bob (via the dashboard)" },
    { agent: "cursor", tool: "Write", decision: "allow", cwd: project },
    { agent: "*", tool: "*", decision: "kill", approver: "alice (dashboard)" }, { agent: "*", tool: "*", decision: "resume" },
    { agent: "mcp:claude-desktop:fs", tool: "wipe", decision: "known-add", approver: "bob" }, { agent: "mcp:claude-desktop:fs", tool: "wipe", decision: "known-remove", approver: "alice" },
    { agent: "dashboard", tool: "-", decision: "policy-change", reason: 'set "Destructive commands" to Block for coding agents', approver: "alice (dashboard)" },
    { agent: "dashboard", tool: "-", decision: "policy-change", reason: "set protection to Strict", approver: "bob (dashboard)" },
    { agent: "dashboard", tool: "-", decision: "settings-change", reason: "turned off journaling allowed calls", approver: "alice (dashboard)" },
    { agent: "dashboard", tool: "-", decision: "mcp-wrap", reason: "a reason written by an older version", approver: "bob" },
    { agent: "x", tool: "y", decision: "known-tools-corrupt" }, { agent: "unknown", tool: "y", decision: "odd" },
    // changes made in a terminal (init, uninstall, mcp wrap / unwrap): the approver is the OS account
    { agent: "*", tool: "claude-code", decision: "settings-change", reason: "removed the hook of Claude Code", approver: "alice" },
    { agent: "*", tool: "claude-desktop", decision: "settings-change", reason: "stopped running the MCP servers fs of Claude Desktop through Kytral Guard", approver: "bob" },
  ];
  I.set("en", {});
  for (const e of corpus) assert.equal(I.sayParts(plainParts(e, "alice")), plainSentence(e, "alice"), JSON.stringify(e));
  try {
    I.set("fr", locale("fr"));
    const say = (e: PlainEvent) => I.sayParts(plainParts(e, "alice"));
    assert.equal(say(corpus[0]), "Claude Code a tenté de supprimer tout votre dossier personnel dans projects/api.");
    assert.equal(say(corpus[1]), "Codex a tenté de supprimer un service qui tourne dans Kubernetes dans projects/api. Il ne peut pas vous demander : l'appel a donc été bloqué.");
    assert.equal(say(corpus[2]), "Codex a tenté de supprimer les fichiers que git ne suit pas dans projects/api. Vous l'avez refusé.");
    assert.equal(say(corpus[3]), "Claude Desktop veut se servir d'un outil qui supprime (delete_file) via son serveur filesystem.");
    assert.equal(say(corpus[8]), "Vous avez arrêté tous les agents.");
    assert.equal(say(corpus[9]), "Quelqu'un a relancé les agents.");
    assert.equal(say(corpus[12]), "Vous avez réglé « Commandes destructrices » sur Bloquer pour les agents de code.");
    assert.equal(say(corpus[13]), "bob a réglé la protection sur Strict.");
    assert.equal(say(corpus[15]), "bob a reason written by an older version.");
    assert.equal(say(corpus[18]), "Vous avez retiré le hook de Claude Code.");
    assert.equal(say(corpus[19]), "bob a cessé de faire passer les serveurs MCP fs de Claude Desktop par Kytral Guard.");
    // a count: the forms of the language
    assert.equal(I.tn(1, "{n} agent", "{n} agents"), "1 agent"); assert.equal(I.tn(3, "{n} agent", "{n} agents"), "3 agents");
    assert.equal(I.said({ message: "x", key: "Protection set to {level}. Disasters stay blocked.", t: { level: "Balanced" } }), "Protection réglée sur Équilibré. Les catastrophes restent bloquées.");
    assert.equal(I.said({ message: "x", parts: [{ message: "a", key: "Protected: {list}.", p: { list: "Codex" } }, { message: "b", key: "Restart {apps} to apply.", p: { apps: "Claude Desktop" } }] }),
      "Protégé : Codex. Redémarrez Claude Desktop pour appliquer.");
    assert.equal(I.said({ error: "an older server's message" }), "an older server's message");
    I.set("ru", locale("ru"));
    assert.deepEqual([1, 2, 5, 21].map(n => I.tn(n, "{n} agent", "{n} agents")), ["1 агент", "2 агента", "5 агентов", "21 агент"]);
  } finally { I.set("en", {}); }
});

test("French: the phrases said after « a tenté de » start with a consonant (no elision to make)", () => {
  const d = locale("fr");
  for (const p of keys.phrases) assert.match(String(d[p]), /^[^aeiouyhàâäéèêëîïôöùûüœ]/i, p);
});
