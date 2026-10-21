// Kytral Guard dashboard, the page: it shows what the local server reports and sends changes (POST /api/...). The state
// comes by long polling (GET /api/state?wait=25 with the ETag the page has: the answer comes as soon as something changes).
// Everything agents wrote (commands, tool names, folders, arguments) is shown as text, never as HTML. The session key lives
// in sessionStorage, which belongs to this page's exact origin, and travels in an Authorization header (no cookie). Every
// text goes through t() / tn() (i18n.js): the page speaks the reader's language; what agents wrote stays as it is.
"use strict";
(() => {
  const I = globalThis.KytralI18n, { t, tn } = I;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  // control characters and the invisible ones that change how a text reads (bidirectional overrides, zero-width
  // characters) are shown as \u codes: a command an agent wrote cannot look like another one
  const HIDDEN = /[\u{0}-\u{8}\u{a}-\u{1f}\u{7f}-\u{9f}\u{200b}-\u{200f}\u{2028}-\u{202e}\u{2060}-\u{2064}\u{2066}-\u{2069}\u{feff}]/gu;
  const visible = s => String(s).replace(HIDDEN, c => `\\u${c.codePointAt(0).toString(16).padStart(4, "0")}`);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = visible(text); return e; };
  const button = (cls, text, data = {}) => { const b = el("button", cls, text); b.type = "button"; for (const [k, v] of Object.entries(data)) b.dataset[k] = String(v); return b; };
  /** A translated text where {0}, {1}... are elements (a bold word, a command): built from nodes, never from HTML. */
  const rich = (text, ...nodes) => {
    const out = []; let last = 0;
    for (const m of text.matchAll(/\{(\d+)\}/g)) { if (m.index > last) out.push(text.slice(last, m.index)); if (nodes[Number(m[1])]) out.push(nodes[Number(m[1])]); last = m.index + m[0].length; }
    if (last < text.length) out.push(text.slice(last));
    return out;
  };
  const safe = (fn, fallback) => { try { return fn(); } catch { return fallback; } };
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const session = {
    get: () => safe(() => sessionStorage.getItem("kg-session"), null),
    set: v => safe(() => sessionStorage.setItem("kg-session", v)),
    clear: () => safe(() => sessionStorage.removeItem("kg-session")),
  };
  const pref = { get: (k, d) => safe(() => localStorage.getItem(k), null) ?? d, set: (k, v) => safe(() => localStorage.setItem(k, v)) };
  const ICONS = {
    lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v4h1"/></svg>',
    ok: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>',
    needs: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M12 8v4.5M12 16h.01"/></svg>',
    stopped: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><rect x="9" y="9" width="6" height="6" rx="1"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
    warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l9.5 17h-19z"/><path d="M12 10v4M12 17h.01"/></svg>',
  };
  const icon = name => { const tpl = document.createElement("template"); tpl.innerHTML = ICONS[name]; return tpl.content.firstElementChild; };
  /** Marks a text that is translated later, with t() (the tests collect every text to translate from t, tn and N). */
  const N = s => s;
  const PILL = { block: ["block", N("Blocked")], ask: ["ask", N("Asked you")], confirmed: ["confirmed", N("Approved")], "confirmed-always": ["confirmed", N("Approved for good")], allow: ["allow", N("Allowed")] };
  const pill = d => { const [cls, text] = PILL[d] ?? ["change", N("Change")]; return el("span", "pill " + cls, t(text)); };
  const ACT = { block: N("Block"), confirm: N("Ask"), allow: N("Allow") };
  const ALWAYS = { allow: N("Always allowed"), confirm: N("Always asked"), block: N("Always blocked") };
  const LEVELS = [
    ["relaxed", N("Relaxed"), N("Blocks disasters. Everything else runs without asking, except payments and mass messages.")],
    ["balanced", N("Balanced"), N("Blocks disasters. Asks you before anything that deletes work or data."), N("Recommended")],
    ["strict", N("Strict"), N("Blocks disasters and anything that deletes work or data. Asks you before other risky actions.")],
  ];
  const LEVEL_NAMES = { relaxed: N("Relaxed"), balanced: N("Balanced"), strict: N("Strict"), custom: N("Custom") };
  const CHANGES = new Set(["kill", "resume", "policy-change", "settings-change", "mcp-wrap", "known-add", "known-remove"]);
  const fmt = n => I.number(n);
  const pad = n => String(n).padStart(2, "0");
  const timeOf = ts => { const d = new Date(ts); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; };
  const longTime = ts => new Date(ts).toLocaleString(I.lang, { weekday: "short", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const isToday = ts => new Date(ts).toDateString() === new Date().toDateString();
  const keyOf = e => e.seq != null ? `s${e.seq}` : `t${e.ts}|${e.agent}|${e.tool}`;
  const shQuote = s => `'${s.replace(/'/g, "'\\''")}'`;
  /** The sentence about an event or a request, in the reader's language (its parts come from the server). */
  const plainOf = x => (x.say ? I.sayParts(x.say) : x.plain);

  let token = session.get(), state = null, etag = null, skew = 0, failures = 0;
  let mode = pref.get("kg-mode", "simple"), tab = safe(() => sessionStorage.getItem("kg-tab"), null) || "activity", scope = "agents", filterDec = "all", openKey = null;
  // a link can open a view directly: ?view=advanced&tab=rules&scope=apps
  const wanted = new URLSearchParams(location.search);
  if (/^(simple|advanced)$/.test(wanted.get("view") || "")) mode = wanted.get("view");
  if (/^(activity|rules|exceptions|approvals|agents|settings)$/.test(wanted.get("tab") || "")) { mode = "advanced"; tab = wanted.get("tab"); }
  if (wanted.get("scope") === "apps") scope = "apps";
  const seen = new Set(), known = new Set(), memo = new Map();
  let firstRender = true, shownTab = null;
  /**
   * Runs a renderer only when the data it shows changed: nothing on the page moves under the reader. When it rebuilt the
   * control that had the focus, the focus goes back to the new one (same data attributes), else to the heading of its
   * section: keyboard and screen-reader users would otherwise be sent back to the top of the page at every update.
   */
  const once = (key, data, fn) => {
    const s = JSON.stringify([I.lang, data]); if (memo.get(key) === s) return; memo.set(key, s);
    const f = document.activeElement, keep = f && f !== document.body ? focusKey(f) : null;
    fn();
    if (keep && !f.isConnected) restoreFocus(keep);
  };
  /** How to find a control again after its list was rebuilt: its tag and data attributes, and its section. */
  function focusKey(node) {
    const attrs = [...node.attributes].filter(a => a.name.startsWith("data-") && a.name !== "data-expires");
    return { sel: attrs.length ? node.localName + attrs.map(a => `[${a.name}="${CSS.escape(a.value)}"]`).join("") : null, section: node.closest("section, main") };
  }
  function restoreFocus(k) {
    // the first visible one: the same control can also be in the view that is hidden (a request in both views)
    const again = k.sel ? $$(k.sel).find(x => !x.closest("[hidden]")) : null;
    if (again && !again.disabled) { again.focus({ preventScroll: true }); return; }
    focusHeading(k.section?.isConnected ? k.section : null);
  }
  /** Gives the focus to the first heading of a part of the page (made focusable for that), or of the visible view. */
  function focusHeading(part) {
    const h = (part && !part.closest("[hidden]") ? part : document.querySelector(mode === "simple" ? "#simpleView" : `[data-view="${tab}"]`))?.querySelector("h1, h2");
    if (h) { h.tabIndex = -1; h.focus({ preventScroll: true }); }
  }

  // ---------- server ----------
  async function api(path, body) {
    const r = await fetch(path, { method: body ? "POST" : "GET", cache: "no-store",
      headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) }, body: body ? JSON.stringify(body) : undefined });
    let j = {}; try { j = await r.json(); } catch { /* empty */ }
    const why = j.error ? I.said({ ...j, message: j.error }) : null;
    if (r.status === 401) { signedOut(why); throw new Error(why || t("Not signed in.")); }
    if (!r.ok) throw new Error(why || t("The dashboard answered {status}.", { status: r.status }));
    return j;
  }
  /** A change: what the server said in a toast, with an Undo when `undo` gives one. The new state comes by itself (long polling). */
  async function act(path, body = {}, undo) {
    try {
      const j = await api(path, body);
      toast(j.message ? I.said(j) : t("Done."), { action: undo ? undo(j) : null });
      return j;
    } catch (e) { if (token) toast(e.message, { error: true }); return null; }
  }
  /** Long polling: the answer comes when the state changes, or after 25 s (304). One loop at a time. */
  let polling = false;
  async function poll() {
    if (polling) return;
    polling = true;
    try { await pollLoop(); } finally { polling = false; }
  }
  async function pollLoop() {
    while (token) {
      try {
        const r = await fetch(`/api/state?wait=${etag ? 25 : 0}`, { cache: "no-store", headers: { Authorization: `Bearer ${token}`, ...(etag ? { "If-None-Match": etag } : {}) } });
        if (r.status === 401) { let j = {}; try { j = await r.json(); } catch { /* empty */ } signedOut(j.error ? I.said({ ...j, message: j.error }) : null); return; }
        if (r.status === 200) { const s = await r.json(); etag = r.headers.get("ETag"); state = s; skew = Date.parse(s.now) - Date.now(); render(); }
        else if (r.status !== 304) throw new Error(`state ${r.status}`);
        failures = 0; $("#offlineBanner").hidden = true;
      } catch {
        if (!token) return;
        if (++failures >= 2) { $("#offlineBanner").hidden = false; setLive(t("Dashboard stopped"), "wait"); }
        await sleep(Math.min(5000, 800 * failures));
      }
    }
  }
  function signedOut(why) {
    token = null; etag = null; session.clear();
    $("#loading").hidden = true; $("#signin").hidden = false; $("#simpleView").hidden = true; $("#advancedView").hidden = true;
    $("#signinText").textContent = why || t("This page belongs to the person who started it, on this computer.");
    setLive(t("Not signed in"), "wait"); document.title = "Kytral Guard";
  }
  async function signIn() {
    const m = /^#k=([A-Za-z0-9_-]{20,})$/.exec(location.hash);
    if (m) {
      history.replaceState(null, "", location.pathname + location.search);   // the one-time key leaves the address bar
      try {
        const r = await fetch("/api/session", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: m[1] }) });
        const j = await r.json().catch(() => ({}));
        if (r.ok && j.session) { token = j.session; etag = null; session.set(token); } else return signedOut(j.error ? I.said({ ...j, message: j.error }) : null);
      } catch { return signedOut(t("The dashboard does not answer. Is kytral-guard dashboard still running?")); }
    }
    if (!token) return signedOut();
    void poll();
  }

  // ---------- small pieces ----------
  let toastTimer = 0, toastRun = null, toastFrom = null;
  function toast(msg, { error = false, action = null } = {}) {
    const box = $("#toast"), a = $("#toastAction");
    $("#toastText").textContent = visible(msg); $("#toastIcon").replaceChildren(icon(error ? "warn" : "check"));
    box.classList.toggle("error", error); box.classList.add("show");
    toastRun = action?.run ?? null; a.hidden = !action; if (action) a.textContent = action.label;
    const hide = () => {
      // kept while the pointer or the focus is on it (someone is about to press Undo); once hidden, Undo leaves the tab order
      if (box.matches(":hover, :focus-within")) { toastTimer = setTimeout(hide, 1500); return; }
      box.classList.remove("show"); toastRun = null; a.hidden = true;
    };
    clearTimeout(toastTimer); toastTimer = setTimeout(hide, error ? 8000 : action ? 7000 : 3800);
  }
  const undo = run => ({ label: t("Undo"), run });
  // the focus goes back where it was before Undo
  $("#toastAction").addEventListener("focusin", ev => { toastFrom = ev.relatedTarget instanceof HTMLElement ? ev.relatedTarget : null; });
  $("#toastAction").addEventListener("click", () => {
    const run = toastRun, back = toastFrom; toastRun = null; toastFrom = null; $("#toast").classList.remove("show"); $("#toastAction").hidden = true;
    if (back?.isConnected && !back.closest("[hidden]")) back.focus({ preventScroll: true }); else focusHeading(null);
    if (run) void run();
  });
  // the exact height of the sticky top bar (it wraps at 200% zoom): a focused control never scrolls under it
  const topbar = $(".topbar");
  if (topbar && "ResizeObserver" in window) new ResizeObserver(() => { document.documentElement.style.scrollPaddingTop = `${topbar.offsetHeight + 8}px`; }).observe(topbar);
  function setLive(text, cls) { $("#statusText").textContent = text; const d = $("#statusDot"); for (const c of ["off", "wait", "warn"]) d.classList.toggle(c, cls === c); }
  function empty(title, text) { const d = el("div", "empty"); d.append(el("b", "", title), document.createTextNode(text)); return d; }
  function note(kind, text, code) {
    const n = el("div", "note " + kind); n.append(icon(kind === "lock" ? "lock" : "info"));
    const s = el("span", "", text);
    if (code) s.append(el("br"), el("code", "", code), button("copy", t("Copy"), { copy: code }));
    n.append(s); return n;
  }
  const leftText = iso => t("Refused automatically in {s} s", { s: Math.max(0, Math.round((Date.parse(iso) - (Date.now() + skew)) / 1000)) });
  setInterval(() => { for (const x of $$("[data-expires]")) x.textContent = leftText(x.dataset.expires); }, 1000);
  const protectedAgents = () => state.agents.filter(a => a.installed && !a.problems.length);
  const watchedApps = () => state.apps.filter(f => f.servers.some(s => s.wrapped));
  const unprotected = () => state.agents.filter(a => !a.installed).length + state.apps.filter(f => !f.error && f.servers.some(s => !s.remote && !s.wrapped)).length;
  const counts = (n, m) => ({ agents: tn(n, "{n} agent", "{n} agents"), apps: tn(m, "{n} app", "{n} apps") });

  // ---------- title and icon: a waiting request shows in the browser's tab ----------
  const markImg = new Image(); markImg.src = "/mark.svg";
  let faviconKind = "ok";
  function badge(kind) {
    if (kind === faviconKind) return; faviconKind = kind;
    const link = $("link[rel=icon]");
    if (kind === "ok") { link.type = "image/svg+xml"; link.href = "/mark.svg"; return; }
    const draw = () => {
      const c = document.createElement("canvas"); c.width = c.height = 64; const x = c.getContext("2d");
      x.drawImage(markImg, 0, 0, 64, 64); x.beginPath(); x.arc(50, 14, 12, 0, Math.PI * 2);
      x.fillStyle = kind === "stopped" ? "#fb7185" : "#818cf8"; x.fill(); x.lineWidth = 4; x.strokeStyle = "#05070d"; x.stroke();
      link.type = "image/png"; link.href = c.toDataURL("image/png");
    };
    if (markImg.complete) draw(); else markImg.addEventListener("load", draw, { once: true });
  }
  function title() {
    const n = state.approvals.length;
    document.title = n ? t("({n}) Kytral Guard needs you", { n }) : state.status.killed ? t("Stopped · Kytral Guard") : "Kytral Guard";
    badge(n ? "needs" : state.status.killed ? "stopped" : "ok");
  }

  // ---------- page ----------
  function render() {
    $("#loading").hidden = true; $("#signin").hidden = true;
    document.body.dataset.mode = mode;
    $("#simpleView").hidden = mode !== "simple"; $("#advancedView").hidden = mode !== "advanced";
    for (const b of $$("#modeSwitch [data-mode]")) b.setAttribute("aria-checked", String(b.dataset.mode === mode));
    const st = state.status, n = protectedAgents().length, m = watchedApps().length;
    // the green dot says "protected": with nothing protected yet it is amber, like the hero card that says so
    setLive(st.killed ? t("All agents stopped") : t("Protecting {agents} · {apps}", counts(n, m)), st.killed ? "off" : n + m ? "" : "warn");
    $("#killBanner").hidden = !st.killed; $("#killBtn").disabled = st.killed;
    const who = st.by ? st.by.replace(/\s*\((?:os:[^)]*|dashboard)\)/g, "") : null, at = st.at ? timeOf(st.at) : null;
    $("#killText").textContent = !st.killed ? "" : `${who && at ? t("Stopped by {who} at {time}.", { who, time: at }) : who ? t("Stopped by {who}.", { who }) : at ? t("Stopped at {time}.", { time: at }) : t("Stopped.")} ${t("Every tool call of every guarded agent and MCP server on this computer is refused until you resume.")}`;
    const today = t("Today · {date}", { date: new Date().toLocaleDateString(I.lang, { weekday: "long", month: "short", day: "numeric" }) });
    $("#heroDate").textContent = $("#actDate").textContent = today;
    const hide = unprotected() === 0; $("#protectAll").hidden = hide || st.killed; $("#protectAll2").hidden = hide;
    if (mode === "simple") renderSimple(); else renderAdvanced();
    title(); notifyNew();
    for (const e of state.events) known.add(keyOf(e));
    firstRender = false;
  }
  const isFresh = e => !firstRender && !known.has(keyOf(e));

  // ---------- simple view ----------
  function renderSimple() {
    const s = state, pending = s.approvals.length, killed = s.status.killed, n = protectedAgents().length, m = watchedApps().length;
    const view = killed ? "stopped" : pending || (!n && !m) ? "needs" : "ok";
    once("hero", [view, pending, n, m, s.stats.blocked, s.stats.asked], () => {
      $("#hero").dataset.state = view; $("#heroIcon").replaceChildren(icon(view));
      $("#heroTitle").textContent = t(killed ? "All agents are stopped" : pending ? "Kytral Guard needs you" : !n && !m ? "Nothing is protected yet" : "You're protected");
      const lines = [];
      if (killed) lines.push(t("Every action of your agents is refused until you let them run again."));
      else {
        if (pending) lines.push(tn(pending, "One action is waiting for your answer below.", "{n} actions are waiting for your answer below."));
        if (!n && !m) lines.push(t("Kytral Guard does not watch any agent or app on this computer yet. Protect what it found, or run kytral-guard init in a terminal."));
        else lines.push(t("{agents} and {apps} are watched.", counts(n, m)), t("Today Kytral Guard blocked {actions} and asked you {times}.",
          { actions: tn(s.stats.blocked, "{n} dangerous action", "{n} dangerous actions"), times: tn(s.stats.asked, "{n} time", "{n} times") }));
      }
      $("#heroSub").textContent = lines.join(" ");
      const hb = $("#heroStop"); hb.textContent = t(killed ? "Let agents run again" : "Stop all agents"); hb.className = `btn big ${killed ? "primary" : "danger"}`; hb.dataset.act = killed ? "resume" : "kill";
    });
    once("simpleApprovals", s.approvals.map(a => a.id), () => renderApprovalCards($("#simpleApprovals"), true));
    const feed = s.events.filter(e => e.decision !== "allow" && isToday(e.ts)).slice(0, 60);
    once("feed", feed.map(e => [keyOf(e), e.plain]), () => {
      const root = $("#feed"); root.replaceChildren();
      if (!feed.length) { const li = el("li"); li.append(empty(t("Nothing to report today"), t("Every call your agents made so far was routine."))); root.append(li); }
      for (const e of feed) {
        const li = el("li", "feed-item" + (isFresh(e) ? " fresh" : "")), body = el("div"), meta = el("div", "feed-meta"), time = el("span", "feed-time", timeOf(e.ts));
        time.title = longTime(e.ts); li.append(time);
        body.append(el("p", "feed-text", plainOf(e)));
        meta.append(pill(e.decision));
        if (!CHANGES.has(e.decision)) meta.append(button("linkbtn", t("Details"), { details: keyOf(e) }));
        body.append(meta); li.append(body); root.append(li);
      }
    });
    $("#safeCount").textContent = s.stats.allowed ? tn(s.stats.allowed, "{n} other action was safe and went through.", "{n} other actions were safe and went through.") : "";
    once("levels", s.rules.level, () => {
      const root = $("#levels"); root.replaceChildren();
      for (const [id, name, text, badgeText] of LEVELS) {
        const b = button("level", null, { level: id }); b.setAttribute("role", "radio"); b.setAttribute("aria-checked", String(s.rules.level === id));
        b.tabIndex = s.rules.level === id || (s.rules.level === "custom" && id === "balanced") ? 0 : -1;
        const top = el("span", "level-name", t(name)); if (badgeText) top.append(el("span", "level-badge", t(badgeText)));
        b.append(top, el("span", "level-text", t(text))); root.append(b);
      }
      $("#levelCustom").hidden = s.rules.level !== "custom";
    });
    once("watched", [s.agents, s.apps], renderWatched);
    $("#notifyBtn").hidden = !("Notification" in window) || Notification.permission !== "default";
  }
  function renderWatched() {
    const root = $("#watched"), ok = el("div", "watched-ok"); root.replaceChildren(ok);
    for (const a of protectedAgents()) ok.append(el("span", "watch-chip", a.name));
    for (const f of watchedApps()) ok.append(el("span", "watch-chip", f.app));
    if (!ok.children.length) ok.append(el("span", "hint", t("Nothing is watched yet.")));
    const issue = (text, fix, btn, off) => {
      const row = el("div", "watch-issue" + (off ? " off" : "")), box = el("div");
      box.append(el("p", "", text)); if (fix) box.append(el("p", "fix", fix)); row.append(box); if (btn) row.append(btn); root.append(row);
    };
    for (const a of state.agents) {
      if (a.installed && a.problems.length) issue(t("{agent}: Kytral Guard is installed, but needs a setting.", { agent: a.name }), a.problems.map(I.said).join(" "));
      else if (!a.installed) issue(t("{agent} is on this computer, but Kytral Guard does not watch it yet.", { agent: a.name }), null, button("btn small primary", t("Protect it"), { protectAgent: a.id }));
    }
    for (const f of state.apps) {
      if (f.error) { issue(t("{app}: its settings file cannot be read ({error}).", { app: f.app, error: f.error }), null, null, true); continue; }
      const open = f.servers.filter(x => !x.remote && !x.wrapped), remote = f.servers.filter(x => x.remote);
      if (open.length) issue(tn(open.length, "{app}: {servers} is not watched yet.", "{app}: {servers} are not watched yet.", { app: f.app, servers: open.map(x => x.name).join(", ") }), null,
        button("btn small primary", tn(open.length, "Watch it", "Watch them"), { protectApp: f.client }));
      if (remote.length) issue(tn(remote.length, "{app}: {servers} is an online server. Kytral Guard cannot watch it from this computer.", "{app}: {servers} are online servers. Kytral Guard cannot watch them from this computer.",
        { app: f.app, servers: remote.map(x => x.name).join(", ") }), null, null, true);
    }
  }
  function renderApprovalCards(root, simple) {
    root.replaceChildren();
    if (!state.approvals.length) {
      root.append(empty(t("Nothing is waiting for you"), simple ? t("When an agent or an app needs your answer, it shows up here at once.")
        : t("Calls that need you, from your apps' MCP servers and from agents that cannot show a prompt, show up here while this page is open.")));
      return;
    }
    for (const a of state.approvals) {
      const actions = [button("btn primary", t(simple ? "Allow once" : "Approve once"), { ap: a.id, verdict: "approve" })];
      if (a.always) actions.push(button("btn", t(simple ? "Always allow this tool" : "Approve for good"), { ap: a.id, verdict: "approve_always" }));
      actions.push(button("btn danger", t("Refuse"), { ap: a.id, verdict: "deny" }));
      const timer = el("span", "timer", leftText(a.expiresAt)); timer.dataset.expires = a.expiresAt;
      if (simple) {
        // a group named by its request: "Allow once" and "Refuse" are not the same buttons from one card to the next
        const card = el("div", "ask-card" + (seen.has(a.id) ? "" : " fresh")), main = el("div"), side = el("div", "ask-actions"), text = el("p", "ask-text", plainOf(a));
        text.id = `ask-${a.id}`; card.setAttribute("role", "group"); card.setAttribute("aria-labelledby", text.id);
        main.append(text);
        if (a.summary && a.summary !== "{}") { const what = el("pre", "ask-what", a.summary); what.tabIndex = 0; main.append(what); }   // scrolls: reachable with the keyboard
        const tech = el("p", "ask-tech", [a.server, a.tool].filter(Boolean).join(" · ") + (a.where ? ` · ${a.where}` : ""));
        tech.append(" ", button("linkbtn", t("See the details"), { goto: "approvals" })); main.append(tech);
        side.append(...actions, timer); card.append(main, side); root.append(card);
      } else {
        const card = el("div", "approval"), main = el("div"), side = el("div", "side"), src = el("div", "src"), tool = el("div", "ap-tool", a.tool), args = el("pre", "term", prettyArgs(a.args));
        tool.id = `ap-${a.id}`; card.setAttribute("role", "group"); card.setAttribute("aria-labelledby", tool.id); args.tabIndex = 0;
        src.append(el("span", "pill ask", t("Waiting for you")), el("span", "", [a.agentName, a.server ? t("MCP server {server}", { server: a.server }) : null, a.where].filter(Boolean).join(" · ")));
        main.append(src, tool, args,
          el("div", "ap-why", a.reason ? (a.rule ? t("{reason} (rule {rule})", { reason: a.reason, rule: a.rule }) : a.reason) : t("Rule {rule}", { rule: a.rule })));
        side.append(...actions, timer); card.append(main, side); root.append(card);
      }
    }
  }
  const prettyArgs = s => safe(() => JSON.stringify(JSON.parse(s), null, 2), s);

  // ---------- advanced view ----------
  function renderAdvanced() {
    for (const s of $$("[data-view]")) s.hidden = s.dataset.view !== tab;
    for (const b of $$(".rail [data-tab]")) { if (b.dataset.tab === tab) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current"); }
    if (shownTab !== tab) {
      // on a phone the sections are a row that scrolls sideways: the open one comes into view
      shownTab = tab; const rail = $(".rail"), cur = $(".rail [aria-current]");
      if (cur && rail.scrollWidth > rail.clientWidth) { const a = cur.getBoundingClientRect(), r = rail.getBoundingClientRect(); if (a.left < r.left || a.right > r.right) rail.scrollLeft += a.left - r.left - 12; }
    }
    const s = state, nExc = s.exceptions.commands.length + s.exceptions.tools.length;
    const warn = s.agents.filter(a => !a.installed || a.problems.length).length + s.apps.filter(f => f.servers.some(x => !x.remote && !x.wrapped)).length;
    for (const [id, n] of [["#excCount", nExc], ["#apprCount", s.approvals.length], ["#agentWarn", warn]]) { $(id).textContent = fmt(n); $(id).hidden = !n; }
    if (tab === "activity") renderActivity();
    if (tab === "rules") once("rules", [scope, s.rules, s.settings.plugins], renderRules);
    if (tab === "exceptions") once("exceptions", s.exceptions, renderExceptions);
    if (tab === "approvals") once("approvals", s.approvals.map(a => a.id), () => renderApprovalCards($("#approvals"), false));
    if (tab === "agents") once("agents", [s.agents, s.apps], renderAgents);
    if (tab === "settings") once("settings", [s.settings, s.paths, s.page, s.version], renderSettings);
  }
  const INTEGRITY = { ok: N("Log intact"), unverified: N("Log partly unverified"), broken: N("Log damaged"), error: N("Log unreadable"), empty: N("Log empty"), checking: N("Checking the log…") };
  function integrityText(i) {
    if (i.state === "ok") return i.tail != null ? t("Nothing was modified, deleted, reordered or cut (last entry: {seq}).", { seq: i.tail }) : t("Nothing was modified, deleted, reordered or cut.");
    if (i.state === "empty") return t("No entry yet.");
    if (i.state === "checking") return t("Checking the log…");
    return i.text;   // the details of a damaged log, as the verification wrote them
  }
  function renderActivity() {
    const s = state;
    once("stats", [s.stats, s.integrity, new Date().getHours()], () => {
      for (const [id, k] of [["#nChecked", "checked"], ["#nAllowed", "allowed"], ["#nAsked", "asked"], ["#nBlocked", "blocked"]]) $(id).textContent = fmt(s.stats[k]);
      const box = $("#integrity"); box.className = `integrity ${s.integrity.state}`;
      $("#integrityTitle").textContent = t(INTEGRITY[s.integrity.state] ?? "Log");
      $("#integrityText").textContent = integrityText(s.integrity);
      renderChart();
    });
    const names = [...new Set(s.events.map(e => e.agentName))].sort();
    once("agentFilter", names, () => {
      const sel = $("#agentFilter"), cur = sel.value; sel.replaceChildren(new Option(t("All agents"), ""));
      for (const n of names) sel.append(new Option(n, n));
      sel.value = names.includes(cur) ? cur : "";
    });
    once("events", [s.events.map(e => keyOf(e) + e.decision + (e.text ? 1 : 0)), filterDec, $("#q").value, $("#agentFilter").value, openKey, s.rules.level], renderEvents);
  }
  function renderChart() {
    const svg = $("#chart"), W = Math.max(300, Math.round(svg.getBoundingClientRect().width) || 720), H = 132;
    const { asked, blocked } = state.stats.hours, peak = Math.max(...asked.map((a, i) => a + blocked[i]), 0), max = Math.max(3, Math.ceil(peak / 3) * 3);
    const top = 12, bottom = 22, left = 30, right = 8, slot = (W - left - right) / 24, bw = Math.max(3, slot * .6);
    const y = v => H - bottom - (v / max) * (H - bottom - top), NS = "http://www.w3.org/2000/svg";
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.replaceChildren();
    const add = (tag, attrs, text) => { const n = document.createElementNS(NS, tag); for (const k in attrs) n.setAttribute(k, attrs[k]); if (text != null) n.textContent = text; svg.append(n); return n; };
    for (const v of [0, max / 3, (2 * max) / 3, max]) {
      add("line", { x1: left, x2: W - right, y1: y(v), y2: y(v), class: v ? "ch-grid dashed" : "ch-grid" });
      add("text", { x: left - 8, y: y(v) + 3.5, "text-anchor": "end", class: "ch-label" }, fmt(Math.round(v)));
    }
    const now = new Date(), hour = now.getHours();
    for (let h = 0; h < 24; h++) {
      const x = left + h * slot + (slot - bw) / 2, b = blocked[h], a = asked[h];
      if (h > hour) add("rect", { x, y: y(0) - 2, width: bw, height: 2, rx: 1, class: "ch-future" });
      else {
        if (b) add("rect", { x, y: y(b), width: bw, height: y(0) - y(b), rx: 2, class: "ch-blocked" });
        if (a) add("rect", { x, y: y(b + a), width: bw, height: Math.max(1, y(b) - y(b + a) - (b ? 1 : 0)), rx: 2, class: "ch-asked" });
        if (!a && !b) add("rect", { x, y: y(0) - 2, width: bw, height: 2, rx: 1, class: "ch-zero" });
      }
      if (h % 6 === 0) add("text", { x: left + h * slot + slot / 2, y: H - 6, "text-anchor": "middle", class: "ch-label" }, `${pad(h)}:00`);
    }
    const nx = left + (hour + now.getMinutes() / 60) * slot;
    add("line", { x1: nx, x2: nx, y1: top - 6, y2: y(0), class: "ch-now" });
    add("text", { x: Math.min(nx + 5, W - 70), y: top + 2, class: "ch-label now" }, t("now {time}", { time: timeOf(now) }));
  }
  function eventMatches(e) {
    const q = $("#q").value.trim().toLowerCase(), ag = $("#agentFilter").value;
    const dec = filterDec === "all" || (filterDec === "blocked" && e.decision === "block") || (filterDec === "allowed" && e.decision === "allow")
      || (filterDec === "asked" && /^(ask|confirmed|confirmed-always)$/.test(e.decision)) || (filterDec === "changes" && CHANGES.has(e.decision));
    const hay = [e.text, e.finding, e.tool, e.agentName, e.where, e.rule, e.plain, plainOf(e), e.server].filter(Boolean).join(" ").toLowerCase();
    return dec && (!ag || e.agentName === ag) && (!q || hay.includes(q));
  }
  function renderEvents() {
    const body = $("#events"), rows = state.events.filter(eventMatches);
    body.replaceChildren();
    for (const e of rows) {
      const key = keyOf(e), tr = el("tr", "ev" + (openKey === key ? " open" : "") + (isFresh(e) ? " fresh" : ""));
      tr.dataset.key = key;
      const time = el("td", "time", isToday(e.ts) ? timeOf(e.ts) : `${new Date(e.ts).toLocaleDateString(I.lang, { month: "short", day: "numeric" })} ${timeOf(e.ts)}`);
      time.title = longTime(e.ts); tr.append(time);
      const a = el("td", "agent", e.agentName); a.append(el("span", "tool", [e.server, e.tool !== "-" ? e.tool : null].filter(Boolean).join(" · ") || "—")); tr.append(a);
      // the call is a button that opens its details, as screen readers and keyboards expect (a click anywhere on the row too)
      const c = el("td", "call"), open = button("rowbtn", null, { key }); open.setAttribute("aria-expanded", String(openKey === key));
      if (CHANGES.has(e.decision)) open.append(el("span", "why", plainOf(e)));
      else if (e.text) { open.append(el("span", "cmd", e.text)); if (e.finding) open.append(el("span", "why", e.finding)); }
      else if (e.finding) open.append(el("span", "why", e.finding));
      else open.append(el("span", "none", t(e.decision === "allow" ? "Arguments not recorded" : "Text not kept")));
      c.append(open); tr.append(c);
      const d = el("td"); d.append(pill(e.decision)); tr.append(d);
      tr.append(el("td", "rule", e.rule || "—"));
      body.append(tr);
      if (openKey === key) body.append(detailRow(e));
    }
    if (!rows.length) {
      const tr = el("tr"), td = el("td"); td.colSpan = 5;
      td.append(empty(t("No call matches"), state.events.length ? t("Clear the search or pick another filter.") : t("Nothing was journaled yet. Once your agents work, their calls show up here.")));
      tr.append(td); body.append(tr);
    }
    $("#tableFoot").textContent = t("{shown} of the last {total} entries. The log never stores arguments: the text of blocked and asked calls is kept apart, masked, so that you can make exceptions here.",
      { shown: fmt(rows.length), total: fmt(state.events.length) });
  }
  function detailRow(e) {
    const tr = el("tr", "detail"), td = el("td"), box = el("div", "detail-box"); td.colSpan = 5;
    const kv = (k, v) => { const d = el("div", "kv"); d.append(el("span", "", t(k)), el("b", "", v)); return d; };
    box.append(kv(N("In plain words"), plainOf(e)));
    if (e.finding) box.append(kv(N("Finding"), e.finding));
    if (e.server) box.append(kv(N("Server"), e.server)); else if (e.where) box.append(kv(N("Folder"), e.where));
    if (e.approver) box.append(kv(N("Decided by"), e.approver));
    box.append(kv(N("When"), longTime(e.ts)));
    const actions = el("div", "actions");
    if (e.cannotAsk) actions.append(note("info", t(e.server ? "The rule asks you, but nobody could answer (no dashboard was open, or no answer in time): the call was blocked."
      : "The rule asks you, but this agent could not show a prompt: the call was blocked, and the agent was told to ask you to run it yourself.")));
    if (e.text && e.text.includes("••••••")) actions.append(note("info", t("A secret in this command was masked before its text was kept. To make an exception for it, use kytral-guard allow in your terminal.")));
    if (e.exception) {
      actions.append(el("p", "hint", t("Next time, for exactly this command:")));
      const data = a => ({ exc: e.seq ?? "", command: e.seq == null ? e.text : "", action: a });
      const row = el("div", "btns"), locked = (b, why) => { b.disabled = true; b.prepend(icon("lock")); b.title = why; return b; };
      const allow = button("btn small", t("Always allow"), data("allow")), ask = button("btn small", t("Always ask"), data("confirm"));
      if (e.exception.catastrophic) locked(allow, t("Catastrophic: not from this page"));
      if (e.exception.self) locked(ask, t("It would weaken the guard: it stays blocked"));
      row.append(allow, ask, button("btn small danger", t("Always block"), data("block")));
      actions.append(row);
      if (e.exception.self) actions.append(note("lock", t("This command would turn Kytral Guard off or weaken it, so it stays blocked: no exception can change that.")));
      else if (e.exception.catastrophic) {
        // by the number of its kept call: nothing an agent wrote is pasted in a terminal
        const cmd = e.seq != null ? `kytral-guard allow --force --call ${e.seq}` : state.page.windows ? null : `kytral-guard allow --force ${shQuote(e.text)}`;
        actions.append(note("lock", cmd ? t("This command can do damage that cannot be undone, so it cannot be allowed from this page. If an agent really must run it, run this in your own terminal:")
          : t("This command can do damage that cannot be undone, so it cannot be allowed from this page. If an agent really must run it, allow it in your own terminal with kytral-guard allow --force and this exact command."), cmd));
      }
    } else if (e.decision === "allow") actions.append(el("p", "hint", t("Allowed calls are recorded without their arguments, so there is no exact command to make an exception for. To ask or block such calls, use Rules.")));
    else if (!CHANGES.has(e.decision) && !e.text) actions.append(el("p", "hint", t("The text of this call was not kept (keeping it is off, or it is older than the kept texts). Exceptions can be made in a terminal with kytral-guard allow.")));
    if (actions.children.length) box.append(actions);
    td.append(box); tr.append(td); return tr;
  }
  const TAGS = { catastrophic: N("Catastrophic"), covers: N("Covers catastrophes"), self: N("Self-protection") };
  function renderRules() {
    const s = state, v = s.rules[scope], root = $("#rules"); root.replaceChildren();
    for (const b of $$("#scopeTabs [data-scope]")) { const on = b.dataset.scope === scope; b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1; if (on) root.setAttribute("aria-labelledby", b.id); }
    $("#scopePath").textContent = !v.file ? "" : v.exists ? v.file : t("{file} (not created yet: the preset applies)", { file: v.file });
    const p = el("p"), ask = el("b", "", t("Ask"));
    p.append(...rich(scope === "agents"
      ? t("{0} shows a prompt in Claude Code, Cursor, Copilot CLI, Grok Build, Qwen Code, TRAE, Qoder, CodeBuddy and Amp. In Codex, Gemini CLI, Windsurf, Kimi Code, iFlow, opencode, MiMo Code, Droid, Auggie, Devin, Kiro and Cline, and in modes that skip prompts, the question comes to this page while it is open; otherwise the call is blocked and the agent asks you to run it yourself. Changes apply from the next tool call.")
      : t("Your AI apps cannot show Kytral Guard's questions: {0} waits for your answer on this page while it is open, or in a terminal with kytral-guard confirm. Without an answer in time, the call is refused. Changes apply from the next tool call."), ask));
    $("#scopeNote").replaceChildren(icon("info"), p);
    const level = el("b", "", t(LEVEL_NAMES[s.rules.level] ?? "Custom"));
    $("#levelNote").replaceChildren(...rich(s.rules.level === "custom" ? t("Protection level: {0}. Pick a level in the Simple view to reset the rules.")
      : t("Protection level: {0}. Changing a rule below makes it Custom."), level));
    if (v.error) { root.append(note("error", t("This policy has an error, so every call it covers is refused until it is fixed: {error}", { error: v.error }))); return; }
    if (s.settings.plugins.length) root.append(note("info", t("A plugin ({plugins}) may replace these rules with a central policy.", { plugins: s.settings.plugins.join(", ") })));
    for (const g of v.groups) {
      const grp = el("div", "rule-group"); grp.append(el("h2", "eyebrow group-title", t(g.name)));
      for (const r of g.rules) {
        const row = el("div", "rule"), main = el("div"), name = el("div", "name", t(r.name));
        if (r.tag) name.append(el("span", `sev ${r.tag}`, t(TAGS[r.tag])));
        main.append(name, el("div", "rid", r.id), el("div", "ex", r.examples));
        if (!r.present) main.append(note("info", t("This rule is not in your policy: it does not build on the preset.")));
        else if (r.lock === "allow") main.append(note("lock", t("Allow is only possible by editing the policy file.")));
        else if (r.lock === "all") main.append(note("lock", t("Always blocked: an agent must never be able to turn the guard off.")));
        const tri = el("div", "tri"); tri.setAttribute("role", "radiogroup"); tri.setAttribute("aria-label", t(r.name));
        for (const a of ["block", "confirm", "allow"]) {
          const b = button("", null, { v: a, rule: r.id }); b.setAttribute("role", "radio"); b.setAttribute("aria-checked", String(r.action === a)); b.tabIndex = r.action === a ? 0 : -1;
          const locked = !r.present || (r.lock === "all" ? a !== "block" : r.lock === "allow" && a === "allow");
          if (locked) { b.disabled = true; if (r.present) b.append(icon("lock")); }
          b.append(document.createTextNode(t(ACT[a]))); tri.append(b);
        }
        // a chosen option that is locked cannot take the focus: the group stays reachable with Tab through its first open one
        const opts = [...tri.children];
        if (!opts.some(b => b.tabIndex === 0 && !b.disabled)) { const first = opts.find(b => !b.disabled); if (first) first.tabIndex = 0; }
        row.append(main, tri); grp.append(row);
      }
      root.append(grp);
    }
    root.append(el("div", "rules-foot", t("Everything else is allowed, and still recorded in the log.")));
  }
  function renderExceptions() {
    const x = state.exceptions;
    $("#excFile").textContent = state.paths.policy; $("#knownFile").textContent = state.paths.known;
    const cmds = $("#excCommands"); cmds.replaceChildren();
    if (x.error) cmds.append(note("error", x.error));
    if (!x.commands.length) cmds.append(empty(t("No exact command"), t("Open a blocked or asked command in Activity to always allow, ask or block it.")));
    for (const c of x.commands) {
      const it = el("div", "item"), main = el("div"), meta = el("div", "meta"), right = el("div", "right");
      main.append(el("div", "what", c.command));
      meta.append(el("span", `pill ${c.action === "allow" ? "allow" : c.action === "confirm" ? "ask" : "block"}`, t(ALWAYS[c.action])), el("span", "", c.name));
      if (c.evenIfCatastrophic) meta.append(el("span", "", t("even if catastrophic (allow --force)")));
      main.append(meta); right.append(button("btn small", t("Remove"), { rmExc: c.name })); it.append(main, right); cmds.append(it);
    }
    const tools = $("#excTools"); tools.replaceChildren();
    if (!x.tools.length) tools.append(empty(t("No tool approved for good"), t("A tool a server did not declare can be approved for good from Approvals.")));
    for (const g of x.tools) {
      const it = el("div", "item"), main = el("div"), meta = el("div", "meta"), right = el("div", "right");
      main.append(el("div", "what", [g.agentName, g.serverName, g.tool].filter(Boolean).join(" · ")));
      meta.append(el("span", "pill confirmed", t("Approved for good")),
        el("span", "", t("By {who}, {date}", { who: g.approver, date: new Date(g.approvedAt).toLocaleDateString(I.lang, { month: "short", day: "numeric", year: "numeric" }) })));
      main.append(meta); right.append(button("btn small", t("Remove"), { rmTool: g.tool, agentId: g.agentId, server: g.server })); it.append(main, right); tools.append(it);
    }
  }
  function renderAgents() {
    const list = $("#agentsList"); list.replaceChildren();
    if (!state.agents.length) list.append(empty(t("No coding agent found"), t("Install one, then come back here or run kytral-guard init in a terminal.")));
    for (const a of state.agents) {
      const it = el("div", "item"), main = el("div"), meta = el("div", "meta"), right = el("div", "right");
      main.append(el("div", "agent-name", a.name));
      meta.append(el("span", "tag" + (a.canAsk ? " can" : ""), t(a.canAsk ? "Asks you in the agent" : "Cannot ask: asks on this page, else blocks")));
      main.append(meta); if (a.problems.length) main.append(el("div", "fix", a.problems.map(I.said).join(" ")));
      if (!a.installed) right.append(el("span", "state warn", t("Not protected")), button("btn small primary", t("Protect it"), { protectAgent: a.id }));
      else right.append(el("span", `state ${a.problems.length ? "warn" : "ok"}`, t(a.problems.length ? "Needs a setting" : "Protected")));
      it.append(main, right); list.append(it);
    }
    const apps = $("#appsList"); apps.replaceChildren();
    if (!state.apps.length) apps.append(empty(t("No AI app found"), t("Claude Desktop, VS Code, Cline, LM Studio and the other supported apps show up here once installed.")));
    for (const f of state.apps) {
      const it = el("div", "item"), main = el("div"), right = el("div", "right");
      const nm = el("div", "agent-name", f.app); nm.append(el("small", "", f.file)); main.append(nm);
      if (f.error) main.append(el("div", "fix", f.error));
      for (const sv of f.servers) {
        const meta = el("div", "meta");
        meta.append(el("span", "what", sv.name), el("span", `state ${sv.wrapped ? "ok" : sv.remote ? "off" : "warn"}`,
          t(sv.wrapped ? "Every call is checked" : sv.remote ? "Online server: cannot be checked from this computer" : "Not checked yet")));
        main.append(meta);
      }
      if (!f.servers.length && !f.error) main.append(el("div", "meta", t("No MCP server.")));
      if (f.servers.some(sv => !sv.remote && !sv.wrapped)) right.append(button("btn small primary", t("Check their calls"), { protectApp: f.client }));
      it.append(main, right); apps.append(it);
    }
  }
  const CONFIRM_MODES = { auto: N("asked on this page while it is open"), on: N("always queued (KYTRAL_CONFIRM_QUEUE=1)"), off: N("turned off (KYTRAL_CONFIRM_QUEUE=0)") };
  function renderSettings() {
    const s = state.settings;
    for (const [id, k, envId, envName] of [["#swKeep", "keepCalls", "#keepEnv", "KYTRAL_KEEP_CALLS"], ["#swAllowed", "auditAllows", "#allowEnv", "KYTRAL_AUDIT_ALLOWS"]]) {
      $(id).setAttribute("aria-checked", String(s[k].on));
      const env = s[k].env; $(envId).hidden = env == null;
      $(envId).textContent = env == null ? "" : t("{name}={value} is set in this terminal's environment: it decides for the commands started from it.", { name: envName, value: env });
    }
    $("#homePath").textContent = state.paths.home;
    const forget = $("#forgetBtn"); if (forget) forget.textContent = t("Forget texts");
    const files = $("#files"); files.replaceChildren();
    for (const [label, path] of [[N("Rules for coding agents"), state.paths.policy], [N("Rules for AI apps"), state.paths.mcpPolicy], [N("Log"), state.paths.audit], [N("Kept command texts"), state.paths.kept], [N("MCP tools approved for good"), state.paths.known]]) {
      const d = el("div"); d.append(el("dt", "", t(label)), el("dd", "", path)); files.append(d);
    }
    const info = $("#pageInfo");
    info.replaceChildren(...rich(t("Served at {0}, reachable from this computer only, since {time}. Agents cannot open it. Confirmations: {mode}.",
      { time: new Date(state.page.startedAt).toLocaleTimeString(I.lang), mode: t(CONFIRM_MODES[s.confirmMode]) }), el("span", "mono", `http://127.0.0.1:${state.page.port}`)));
    if (state.version) info.append(" ", el("span", "version", `Kytral Guard ${state.version}`));
  }

  // ---------- notifications ----------
  function notifyNew() {
    const fresh = state.approvals.filter(a => !seen.has(a.id));
    for (const a of state.approvals) seen.add(a.id);
    // screen readers hear a new request at once (it is refused if nobody answers in time); the call's own sentence makes two
    // requests in a row differ, so the second one is read too
    if (fresh.length && !firstRender) $("#announce").replaceChildren(el("p", "", t("({n}) Kytral Guard needs you", { n: state.approvals.length })), el("p", "", plainOf(fresh[0])));
    if (!fresh.length || !document.hidden || !("Notification" in window) || Notification.permission !== "granted") return;
    for (const a of fresh.slice(0, 3)) safe(() => { const n = new Notification(t("Kytral Guard needs you"), { body: plainOf(a), tag: a.id }); n.onclick = () => { window.focus(); n.close(); }; });
  }

  // ---------- language ----------
  function fillLanguages() {
    for (const sel of $$("[data-lang]")) {
      sel.replaceChildren(...I.LANGUAGES.map(([code, name]) => { const o = new Option(name, code); o.lang = code; return o; }));
      sel.value = I.lang;
    }
  }
  /** Says the page in another language, at once (the state is drawn again). */
  async function setLanguage(code) {
    try { await I.use(code); } catch { toast(t("This language could not be loaded."), { error: true }); return; }
    pref.set("kg-lang", I.lang);
    document.documentElement.lang = I.lang;
    I.translatePage(); fillLanguages(); memo.clear();
    $("#toastAction").textContent = t("Undo");
    if (state) render(); else if (!token) signedOut(); else setLive(t("Connecting…"), "wait");
  }

  // ---------- events ----------
  function go(m, to) {
    mode = m; if (to) { tab = to; safe(() => sessionStorage.setItem("kg-tab", tab)); } pref.set("kg-mode", mode); memo.clear(); render(); window.scrollTo(0, 0);
    // the control that led here is now hidden ("Switch to Advanced", "See the details"): the new view's heading takes the focus
    const f = document.activeElement; if (!f || f === document.body || f.closest("[hidden]")) focusHeading(null);
  }
  function openInAdvanced(key) {
    filterDec = "all"; for (const x of $$("#decFilter [data-f]")) x.setAttribute("aria-checked", String(x.dataset.f === "all"));
    $("#q").value = ""; $("#agentFilter").value = ""; openKey = key; go("advanced", "activity");
    const row = $(`tr.ev[data-key="${CSS.escape(key)}"]`); if (row) { row.scrollIntoView({ block: "center" }); (row.querySelector(".rowbtn") ?? row).focus({ preventScroll: true }); }
  }
  document.addEventListener("change", ev => { const sel = ev.target instanceof Element ? ev.target.closest("[data-lang]") : null; if (sel) void setLanguage(sel.value); });
  document.addEventListener("click", async ev => {
    const tg = ev.target instanceof Element ? ev.target : null; if (!tg || !state) return;
    const cp = tg.closest("[data-copy]");
    if (cp) {
      try { await navigator.clipboard.writeText(cp.dataset.copy); toast(t("Copied. Paste it in your terminal.")); }
      catch { const code = cp.previousElementSibling; if (code) { const r = document.createRange(); r.selectNodeContents(code); const s = getSelection(); s.removeAllRanges(); s.addRange(r); } toast(t("Selected: copy it with Ctrl+C.")); }
      return;
    }
    const m = tg.closest("[data-mode]"); if (m && m.closest("#modeSwitch, .simple-foot")) { go(m.dataset.mode); return; }
    const tb = tg.closest(".rail [data-tab]"); if (tb) { go("advanced", tb.dataset.tab); return; }
    const gt = tg.closest("[data-goto]"); if (gt) { go("advanced", gt.dataset.goto); return; }
    const a = tg.closest("[data-act]");
    if (a) { a.disabled = true; await act(`/api/${a.dataset.act}`); a.disabled = false; return; }
    const ap = tg.closest("[data-ap]"); if (ap) { for (const b of $$(`[data-ap="${CSS.escape(ap.dataset.ap)}"]`)) b.disabled = true; await act("/api/approval", { id: ap.dataset.ap, verdict: ap.dataset.verdict }); return; }
    const d = tg.closest("[data-details]"); if (d) { openInAdvanced(d.dataset.details); return; }
    const lv = tg.closest("[data-level]");
    if (lv) {
      const before = state.rules.level, to = lv.dataset.level; if (before === to) return;
      await act("/api/level", { level: to }, before !== "custom" ? () => undo(() => act("/api/level", { level: before })) : null);
      return;
    }
    const pa = tg.closest("[data-protect-agent]"); if (pa) { pa.disabled = true; await act("/api/protect-agent", { agent: pa.dataset.protectAgent }); return; }
    const pp = tg.closest("[data-protect-app]"); if (pp) { pp.disabled = true; await act("/api/protect-app", { client: pp.dataset.protectApp }); return; }
    const sc = tg.closest("#scopeTabs [data-scope]"); if (sc) { scope = sc.dataset.scope; memo.delete("rules"); renderAdvanced(); return; }
    const tri = tg.closest(".tri button");
    if (tri && !tri.disabled) {
      if (tri.getAttribute("aria-checked") === "true") return;
      const at = scope, rule = tri.dataset.rule;
      await act("/api/rule", { scope: at, rule, action: tri.dataset.v }, j => j.before ? undo(() => act("/api/rule", { scope: at, rule, action: j.before })) : null);
      return;
    }
    const exc = tg.closest("[data-exc]");
    if (exc && !exc.disabled) {
      const body = exc.dataset.exc !== "" ? { seq: Number(exc.dataset.exc), action: exc.dataset.action } : { command: exc.dataset.command, action: exc.dataset.action };
      await act("/api/exception", body, j => j.name ? undo(() => act("/api/exception/remove", { name: j.name })) : null);
      return;
    }
    const rx = tg.closest("[data-rm-exc]");
    if (rx) { await act("/api/exception/remove", { name: rx.dataset.rmExc }, j => j.removed ? undo(() => act("/api/exception", { command: j.removed.command, action: j.removed.action })) : null); return; }
    const rt = tg.closest("[data-rm-tool]"); if (rt) { await act("/api/known/remove", { tool: rt.dataset.rmTool, agentId: rt.dataset.agentId, server: rt.dataset.server }); return; }
    const sw = tg.closest(".switch[data-setting]");
    if (sw) {
      const k = sw.dataset.setting, to = sw.getAttribute("aria-checked") !== "true";
      await act("/api/settings", { [k]: to }, () => undo(() => act("/api/settings", { [k]: !to })));
      return;
    }
    if (tg.closest("#forgetBtn")) {
      const c = el("div", "confirm-inline", t("Delete the kept texts?")), yes = button("btn small danger", t("Delete")), no = button("btn small", t("Keep them"));
      yes.id = "forgetYes"; no.id = "forgetNo"; c.append(yes, no); $("#forgetBox").replaceChildren(c); yes.focus(); return;
    }
    if (tg.closest("#forgetYes, #forgetNo")) {
      const doIt = !!tg.closest("#forgetYes"), b = button("btn small danger", t("Forget texts")); b.id = "forgetBtn"; $("#forgetBox").replaceChildren(b); b.focus();
      if (doIt) await act("/api/forget"); return;
    }
    if (tg.closest("#notifyBtn")) { safe(() => Notification.requestPermission().then(() => { $("#notifyBtn").hidden = Notification.permission !== "default"; })); return; }
    const row = tg.closest("tr.ev");
    if (row) { openKey = openKey === row.dataset.key ? null : row.dataset.key; renderEvents(); const again = $(`tr.ev[data-key="${CSS.escape(row.dataset.key)}"] .rowbtn`); if (again) again.focus(); }
  });
  document.addEventListener("keydown", ev => {
    const tg = ev.target instanceof Element ? ev.target : null; if (!tg) return;
    // arrow keys move between the options of a group (radio buttons, tabs), as in a native control
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[ev.key];
    const item = step && tg.closest('[role="radio"], [role="tab"]'), group = item && item.closest('[role="radiogroup"], [role="tablist"]');
    if (!group) return;
    const items = $$('[role="radio"]:not([disabled]), [role="tab"]', group), i = items.indexOf(item);
    if (i < 0 || items.length < 2) return;
    ev.preventDefault(); items[(i + step + items.length) % items.length].focus();
  });
  $("#q").addEventListener("input", () => { openKey = null; if (state) renderEvents(); });
  $("#agentFilter").addEventListener("change", () => { openKey = null; if (state) renderEvents(); });
  $("#decFilter").addEventListener("click", ev => {
    const b = ev.target instanceof Element ? ev.target.closest("[data-f]") : null; if (!b) return;
    filterDec = b.dataset.f; for (const x of $$("#decFilter [data-f]")) x.setAttribute("aria-checked", String(x === b)); openKey = null; if (state) renderEvents();
  });
  window.addEventListener("resize", () => { if (state && mode === "advanced" && tab === "activity") renderChart(); });
  // a new link opened in this same tab changes only the fragment, which does not reload the page
  window.addEventListener("hashchange", () => { if (location.hash.startsWith("#k=")) void signIn(); });

  // the reader's language first (the one picked before, else the browser's), then sign in
  (async () => {
    try { await I.use(I.detect(pref.get("kg-lang", null), navigator.languages?.length ? navigator.languages : [navigator.language])); } catch { /* US English */ }
    document.documentElement.lang = I.lang;
    I.translatePage(); fillLanguages();
    setLive(t("Connecting…"), "wait"); $("#toastAction").textContent = t("Undo");
    void signIn();
  })();
})();
