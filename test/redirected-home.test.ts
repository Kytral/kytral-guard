// KYTRAL_HOME (or KYTRAL_AUDIT, or the home folder replaced by a link) redirected to a blank home is like a wipe: the kill is
// lifted for new processes, a documented limit (docs/kill-switch.md, Limits). doctor and the agent hooks warn when none of
// the files the kill switch is read from exists where the variables point while a default path they replace still holds
// one: a warning, not a block. A hook's answer, stdout and exit code are the same with it as without it; it writes nothing,
// names no path on the hooks' stderr, and is silent on a fresh install. Every machine here has a HOME of its own: the real
// ~/.kytral is never read.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { runHookAsync } from "../src/hooks.js";

const ROOT = resolve(import.meta.dirname, "..");
const TSX = pathToFileURL(join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;   // run from a temp folder, which has no node_modules
const S = "3b8f1d6a9c2e5b7d0f4a8c1e6b9d2f5a7c0e3b6d9f1a4c7e2b5d8f0a3c6e9b1d";
const WARNING = "Kytral Guard: warning: no kill switch state where KYTRAL_HOME or KYTRAL_AUDIT points, although the default location still holds some (wiped or redirected?): a kill in force there is not seen here; 'kytral-guard doctor' says where";
const DOCTOR = /^warn {2}no kill switch state here: /m;
const FILES = ["kill-switch.json", "audit.jsonl", "audit.jsonl.tail"];
const event = (command: string) => JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, cwd: tmpdir(), session_id: "s" });

/** A machine with a HOME of its own (its default home is HOME/.kytral), a strong secret, and no other KYTRAL_ variable. */
function machine() {
  const t = mkdtempSync(join(tmpdir(), "kg-left-")), home = join(t, "home"), kytral = join(home, ".kytral");
  mkdirSync(home);
  const base: Record<string, string | undefined> = { ...process.env, HOME: home, USERPROFILE: home, APPDATA: join(home, "AppData", "Roaming"), XDG_CONFIG_HOME: join(home, ".config") };
  for (const k of Object.keys(base)) if (/^KYTRAL_/i.test(k)) delete base[k];
  base.KYTRAL_SECRET = S;
  const env = (more: Record<string, string> = {}) => ({ ...base, ...more }) as NodeJS.ProcessEnv;
  const cli = (args: string[], more: Record<string, string> = {}, input = "") => {
    const r = spawnSync(process.execPath, ["--import", TSX, join(ROOT, "src/cli.ts"), ...args], { cwd: t, env: env(more), encoding: "utf8", input });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };
  const hook = (command: string, more: Record<string, string> = {}) => cli(["hook", "claude-code"], more, event(command));
  /** The default home as it is, names and contents: nothing is written there for the warning. */
  const snapshot = () => readdirSync(kytral).sort().map(f => [f, readFileSync(join(kytral, f), "utf8")]);
  return { t, home, kytral, env, cli, hook, snapshot, place: (name: string) => join(t, name) };
}

test("a fresh install is silent: no default home, with KYTRAL_HOME or KYTRAL_AUDIT set to a new place, or neither set", () => {
  const m = machine();
  for (const more of [{ KYTRAL_HOME: m.place("new") }, { KYTRAL_AUDIT: m.place("new.jsonl") }, {}]) {
    const w = JSON.stringify(more), d = m.cli(["doctor"], more);   // doctor first: the place is still blank
    assert.doesNotMatch(d.out + d.err, /wiped or redirected/, w);
    const h = m.hook("ls", more);
    assert.equal(h.code, 0, w); assert.equal(h.out, "", w); assert.equal(h.err, "", w);
  }
});

test("KYTRAL_HOME redirected to a blank home after a kill: lifted for new hooks (the documented limit), which say so on stderr after the same answer, once and without a path; doctor names the paths; nothing is written for it", () => {
  const m = machine(), fresh = machine();   // fresh: the same calls on a machine whose default home was never used
  assert.equal(m.cli(["kill", "--by", "ops"]).code, 0);
  assert.equal(m.hook("ls").code, 2, "the kill stops a hook of the default home");
  const before = m.snapshot();
  // doctor: one warn line with the paths, the exit code it has without it
  const d = m.cli(["doctor"], { KYTRAL_HOME: m.place("blank") }), dFresh = fresh.cli(["doctor"], { KYTRAL_HOME: fresh.place("blank") });
  const here = FILES.map(f => join(m.place("blank"), f)).join(", "), there = FILES.map(f => join(m.kytral, f)).join(", ");
  assert.ok(d.out.includes(`\nwarn  no kill switch state here: none of ${here} exists, although ${there} still exist (wiped or redirected?): a kill in force there is not seen here\n`), d.out);
  assert.equal(d.out.match(/wiped or redirected/g)?.length, 1, "one line");
  assert.equal(d.code, dFresh.code); assert.doesNotMatch(dFresh.out, DOCTOR);
  assert.doesNotMatch(m.cli(["doctor", "--report"], { KYTRAL_HOME: m.place("blank") }).out, /wiped or redirected|kg-left-/, "not in the report for a public issue");
  // the hooks: the answer of a machine that never used its default home, then one fixed line, no path
  for (const [command, place] of [["ls", "blank"], ["rm -rf ~", "blank-2"]] as const) {
    const r = m.hook(command, { KYTRAL_HOME: m.place(place) }), f = fresh.hook(command, { KYTRAL_HOME: fresh.place(place) });
    assert.equal(r.code, f.code, command); assert.equal(r.out, f.out, `${command}: the same answer on stdout`);
    assert.equal(r.err, `${f.err}${WARNING}\n`, `${command}: one line on stderr, after the answer's`);
    assert.ok(![m.t, m.home, m.place(place)].some(p => r.err.includes(p)), `${command}: no path`);
  }
  assert.equal(fresh.hook("ls", { KYTRAL_HOME: fresh.place("blank") }).code, 0);
  const again = m.hook("ls", { KYTRAL_HOME: m.place("blank") });
  assert.equal(again.code, 0, "the kill is lifted for new processes: the documented limit");
  assert.equal(again.err, "", "silent once the new home holds one of the files: the first call journaled itself");
  // a place that holds one of the files, even an empty audit log, is silent (a documented miss)
  mkdirSync(m.place("one-file")); writeFileSync(join(m.place("one-file"), "audit.jsonl"), "");
  assert.equal(m.hook("ls", { KYTRAL_HOME: m.place("one-file") }).err, "");
  assert.deepEqual(m.snapshot(), before, "the default home is unchanged");
  // the default home wiped itself, no variable set: lifted (the wipe limit) and nothing to compare with (a documented miss)
  for (const f of FILES) unlinkSync(join(m.kytral, f));
  const wiped = m.hook("ls");
  assert.equal(wiped.code, 0); assert.equal(wiped.err, "");
});

test("KYTRAL_AUDIT redirected to a blank log: silent while kill-switch.json is there (its kill still stops hooks); with it deleted too, lifted for new hooks, which warn; doctor names the default log", () => {
  const m = machine();
  assert.equal(m.cli(["kill"]).code, 0);
  const one = m.hook("ls", { KYTRAL_AUDIT: m.place("log-1.jsonl") });
  assert.equal(one.code, 2, "kill-switch.json still holds the kill"); assert.ok(!one.err.includes(WARNING), one.err);
  unlinkSync(join(m.kytral, "kill-switch.json"));
  assert.equal(m.hook("ls").code, 2, "with the default log, the deleted kill still stops a hook (its marker)");
  const log = m.place("log-2.jsonl"), d = m.cli(["doctor"], { KYTRAL_AUDIT: log });
  const here = [join(m.kytral, "kill-switch.json"), log, `${log}.tail`].join(", "), there = [join(m.kytral, "audit.jsonl"), join(m.kytral, "audit.jsonl.tail")].join(", ");
  assert.ok(d.out.includes(`\nwarn  no kill switch state here: none of ${here} exists, although ${there} still exist (wiped or redirected?): a kill in force there is not seen here\n`), d.out);
  const r = m.hook("ls", { KYTRAL_AUDIT: log });
  assert.equal(r.code, 0, "lifted for new processes: the documented limit"); assert.equal(r.out, ""); assert.equal(r.err, `${WARNING}\n`);
});

test("a stderr whose reader is gone does not change the answer the warning comes with", async () => {
  const m = machine();
  assert.equal(m.cli(["kill"]).code, 0);
  for (const [command, code] of [["ls", 0], ["rm -rf ~", 2]] as const) {
    const r = await new Promise<{ code: number | null; out: string }>(done => {
      const p = spawn(process.execPath, ["--import", TSX, join(ROOT, "src/cli.ts"), "hook", "claude-code"], { cwd: m.t, env: m.env({ KYTRAL_HOME: m.place(`gone-${code}`) }) });
      p.stderr.destroy();   // nobody reads it: the hook's write there fails (EPIPE)
      let out = ""; p.stdout.setEncoding("utf8").on("data", (d: string) => { out += d; });
      p.on("close", c => done({ code: c, out }));
      p.stdin.end(event(command));
    });
    assert.equal(r.code, code, command);
    assert.equal(r.out ? JSON.parse(r.out).hookSpecificOutput.permissionDecision : "allow", code ? "deny" : "allow", command);
  }
});

test("the in-process API says nothing: runHookAsync answers without the warning where the hook command prints it", async () => {
  const m = machine();
  assert.equal(m.cli(["kill"]).code, 0);
  const keys = ["HOME", "USERPROFILE", "KYTRAL_HOME", "KYTRAL_AUDIT", "KYTRAL_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS"];
  const saved = Object.fromEntries(keys.map(k => [k, process.env[k]]));
  try {
    Object.assign(process.env, { HOME: m.home, USERPROFILE: m.home, KYTRAL_HOME: m.place("in-process"), KYTRAL_SECRET: S });
    for (const k of ["KYTRAL_AUDIT", "KYTRAL_POLICY", "KYTRAL_PLUGINS"]) delete process.env[k];
    assert.deepEqual(await runHookAsync("claude-code", event("ls")), { stdout: "", stderr: "", exitCode: 0 });
  } finally { for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  assert.equal(m.hook("ls", { KYTRAL_HOME: m.place("command") }).err, `${WARNING}\n`, "the command, for the same machine");
});
