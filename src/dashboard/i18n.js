// Kytral Guard dashboard, its languages. The page is written in US English; these functions say it in the reader's language
// with one dictionary per language (/locales/<language>.json), whose keys are the English texts themselves: {name} marks a
// value the text holds, a plural is an object of Intl.PluralRules forms ({ one, few, many, other }), and "<key>|you" is the
// same sentence when the reader is the one who acted (verbs agree with "you" differently in many languages). The tests
// (Node) load this file too, and check that every language says every text with the same values.
"use strict";
(() => {
  const LANGUAGES = [["en", "English"], ["fr", "Français"], ["es", "Español"], ["de", "Deutsch"], ["it", "Italiano"], ["pt-BR", "Português (Brasil)"],
    ["ru", "Русский"], ["ja", "日本語"], ["ko", "한국어"], ["zh-CN", "简体中文"]];
  const CODES = LANGUAGES.map(l => l[0]);
  let lang = "en", dict = {};
  const has = key => Object.hasOwn(dict, key);
  const fill = (text, values = {}) => String(text).replace(/\{(\w+)\}/g, (m, k) => (Object.hasOwn(values, k) ? String(values[k]) : m));
  const number = n => Number(n || 0).toLocaleString(lang);
  /** The text in the reader's language, with its values. */
  function t(key, values) {
    const v = has(key) ? dict[key] : key;
    return fill(typeof v === "string" ? v : v.other ?? key, values);
  }
  /** A text that depends on a count n: `one` and `other` are the English forms ({n} is the count, written for this language). */
  function tn(n, one, other, values = {}) {
    const all = { ...values, n: number(n) }, v = has(one) ? dict[one] : undefined;
    if (v && typeof v === "object") return fill(v[new Intl.PluralRules(lang).select(n)] ?? v.other, all);
    if (typeof v === "string") return fill(v, all);
    return fill(n === 1 ? one : other, all);
  }
  /** The language to show: the one picked before, else the first of the browser's languages the page speaks, else English. */
  function detect(saved, wanted = []) {
    if (saved && CODES.includes(saved)) return saved;
    for (const w of wanted) {
      const code = String(w).toLowerCase(), primary = code.split("-")[0];
      const found = CODES.find(c => c.toLowerCase() === code) ?? CODES.find(c => c.toLowerCase().split("-")[0] === primary);
      if (found) return found;
    }
    return "en";
  }
  /** Loads a language (US English needs nothing). */
  async function use(code) {
    if (!CODES.includes(code)) code = "en";
    if (code === "en") { lang = "en"; dict = {}; return; }
    const r = await fetch(`/locales/${code}.json`, { cache: "no-store" });
    if (!r.ok) throw new Error(`language ${code}: ${r.status}`);
    dict = await r.json(); lang = code;
  }
  /**
   * Says the page's own text in the language in use: the elements marked data-i18n (their text, where {0}, {1}... stand for
   * their child elements, which stay as they are), and the attributes listed in data-i18n-attr. The English text is
   * remembered the first time, so that the page can change language again.
   */
  function translatePage(root = document) {
    for (const el of root.querySelectorAll("[data-i18n]")) {
      if (!el.kgI18n) {
        const kids = [], parts = [];
        for (const n of el.childNodes) {
          if (n.nodeType === 3) parts.push(n.nodeValue);
          else if (n.nodeType === 1) { parts.push(`{${kids.length}}`); kids.push(n); }
        }
        el.kgI18n = { key: parts.join("").replace(/\s+/g, " ").trim(), kids };
      }
      const { key, kids } = el.kgI18n, text = t(key), nodes = [];
      let last = 0;
      for (const m of text.matchAll(/\{(\d+)\}/g)) {
        if (m.index > last) nodes.push(document.createTextNode(text.slice(last, m.index)));
        if (kids[Number(m[1])]) nodes.push(kids[Number(m[1])]);
        last = m.index + m[0].length;
      }
      if (last < text.length) nodes.push(document.createTextNode(text.slice(last)));
      el.replaceChildren(...nodes);
    }
    for (const el of root.querySelectorAll("[data-i18n-attr]")) {
      el.kgI18nAttr ??= {};
      for (const a of el.dataset.i18nAttr.split(/\s+/).filter(Boolean)) {
        el.kgI18nAttr[a] ??= el.getAttribute(a) ?? "";
        el.setAttribute(a, t(el.kgI18nAttr[a]));
      }
    }
  }
  /** The words a text names (rule names, actions, levels...), said in the reader's language too. */
  const words = o => Object.fromEntries(Object.entries(o ?? {}).map(([k, v]) => [k, t(String(v))]));
  /** One sentence about an event, from its parts (the same logic as sayParts in src/plain.ts, which says it in US English). */
  function sayParts(x) {
    const you = x.byKey === "You", pick = key => (you && has(`${key}|you`) ? `${key}|you` : key);
    const values = {
      who: x.who ?? t(x.whoKey ?? "An agent"), by: x.by ?? t(x.byKey ?? "Someone"), tool: x.tool ?? "", decision: x.decision ?? "",
      what: x.what ? t(x.what, { tool: x.tool ?? "" }) : "",
      where: x.where ? t(x.where.k, { place: x.where.place ?? "", server: x.where.server ?? "" }) : "",
    };
    if (x.reason) values.reason = "text" in x.reason ? x.reason.text : t(pick(x.reason.k), { ...x.reason.p, ...words(x.reason.t) });
    return [x.s, ...(x.more ?? [])].map(k => t(pick(k), values)).join("");
  }
  /** What the server said ({ message, key, p, t, parts }, or { error, key, p, t }), in the reader's language. */
  function said(j) {
    if (Array.isArray(j.parts)) return j.parts.map(said).join(" ");
    if (j.key) return t(j.key, { ...j.p, ...words(j.t) });
    return t(j.message ?? j.error ?? "");
  }
  globalThis.KytralI18n = {
    LANGUAGES, t, tn, number, fill, detect, use, translatePage, sayParts, said,
    get lang() { return lang; },
    /** For the tests: a language and its dictionary, without loading them. */
    set(code, d) { lang = code; dict = d ?? {}; },
  };
})();
