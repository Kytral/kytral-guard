// Adversarial regression probes: doctor --report as a whitelist of formats. Green = nothing leaks. The real CLI, with its
// own HOME, project folder and KYTRAL_HOME in each test.
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path"; import { pathToFileURL } from "node:url";
import { serverName } from "../src/bug-report.js";

const ROOT = resolve(import.meta.dirname, "..");
const TSX = pathToFileURL(join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;
const S = "5e8a2c7f1d4b9036e2a8c5f7d1b4e9036a2c8f5d7b1e4a9c3f6d2b8e5a7c1f4d";
function machine(env: Record<string, string> = {}, kh?: (home: string) => string) {
  const t = mkdtempSync(join(tmpdir(), "kg-test-")), home = join(t, "home"), project = join(t, "project");
  mkdirSync(home, { recursive: true }); mkdirSync(project, { recursive: true });
  const e: Record<string, string | undefined> = { ...process.env, HOME: home, USERPROFILE: home, APPDATA: join(home, "AppData", "Roaming"), XDG_CONFIG_HOME: join(home, ".config") };
  for (const k of Object.keys(e)) if (/^KYTRAL_/i.test(k)) delete e[k];
  Object.assign(e, { KYTRAL_HOME: kh ? kh(home) : join(home, ".kytral") }, env);
  const cli = (...args: string[]) => { const r = spawnSync(process.execPath, ["--import", TSX, join(ROOT, "src/cli.ts"), ...args], { cwd: project, env: e as NodeJS.ProcessEnv, encoding: "utf8" });
    return { code: r.status, out: r.stdout, err: r.stderr, all: r.stdout + r.stderr }; };
  return { t, home, project, cli };
}
const noLeak = (text: string, secrets: string[]) => { for (const s of secrets) assert.ok(!text.includes(s), `leak: ${JSON.stringify(s)}\n${text}`); };
const SEC = "hunter2-Qx7";

test("option_values_every_form: --opt value, --opt=value, -o value, positionals, repeated options, --policy=value => no value copied", () => {
  const m = machine();
  const forms = [["doctor", "--report", "--token", SEC], ["doctor", "--report", `--token=${SEC}`], ["doctor", "--report", "-t", SEC], ["doctor", "--report", `-t=${SEC}`],
    ["doctor", "--report", SEC], ["doctor", SEC, "--report"], ["doctor", "--report", "--report", `--x=${SEC}`], [`--policy=${SEC}`, "doctor", "--report"],
    ["doctor", "--report", `--policy=${SEC}`], ["doctor", "--report", "--policy", "/nonexistent", "--policy", join("/nonexistent", SEC)], ["doctor", "--report", "--policy"],
    ["doctor", "--report", `--${SEC}=v`], ["doctor", "--report", "--", SEC]];
  for (const f of forms) noLeak(m.cli(...f).all, [SEC, "Qx7"]);
});
test("option_named_like_a_token: an 'option' that is itself a token (--ghp_..., --sk-...) is not copied", () => {
  const m = machine();
  for (const tok of ["ghp_N4r7Q2x9L1m8K3v6B5c0Z7a2S4d6F8g1H3j5", "sk-live-0123456789abcdefABCDEF", "AKIAQAQAQAQAQAQAQAQA", "hunter2pw"])
    noLeak(m.cli("doctor", "--report", `--${tok}`).all, [tok]);
});
test("server_names_credentials_unicode_length: URLs/credentials, spaces, unicode/homoglyphs, invisible characters, length 64/65 => <name>", () => {
  const masked = ["https://u:p4ss@h", "user@host", "user:pass", "a=b", "db pw", "pass word", "ｈunter2", "hunter\u200b2", "hunter\u00ad2", "һunter2", "hunter2\n", "\u202ehunter2",
    "-dash", ".dot", "_under", "s".repeat(65), "a".repeat(64) /* hexadecimal: masked, fail closed */, "x/y", "x\\y", "~/x", "$HOME", "%41", "a;b", "a|b", "'q'", "\"q\""];
  for (const n of masked) assert.equal(serverName(n), "<name>", JSON.stringify(n));
  for (const n of ["github", "fs", "postgres-prod", "my.server_1", "Filesystem", "s".repeat(64), "server-2026-10-20", "db01"]) assert.equal(serverName(n), n, n);
});
test("token_shaped_names_up_to_64: known and random tokens of <= 64 characters => <name>", () => {
  const toks = ["ghp_N4r7Q2x9L1m8K3v6B5c0Z7a2S4d6F8g1H3j5", "github_pat_11ABCDEFG0abcdefghijklmnop", "glpat-AbCdEfGhIjKlMnOpQrSt", "xoxb-1234567890-abcdefghij",
    "sk-proj-AbCdEf0123456789", "sk_live_51HxYzAbCdEf", "rk_test_abcdefghijklmnop", "AKIAQAQAQAQAQAQAQAQA", "AIzaSyA-abcdefghijklmnopqrstuvwxyz012", "eyJhbGciOiJIUzI1NiJ9.e30.abc",
    "npm_Ab3dE5gH7jK9mN1pQ3sT5vW7yZ9aB1cD3eF5", "SG.Ab3dE5gH7jK9mN1p.Qr3sT5vW7yZ9aB1cD3", "f".repeat(64), "0123456789abcdef", "550e8400-e29b-41d4-a716-446655440000",
    "Zq81kQ0pLm2vNb7cXr4tWq19aa", "x7kq2m9p4z8w1r5t", "12345678901234567890"];
  for (const t of toks) assert.equal(serverName(t), "<name>", t);
});
test("secret_of_env_as_server_name: a server name equal to a secret of the environment (>= 8 characters) is masked", () => {
  const m = machine({ MY_SERVICE_PASSWORD: "plainword-prod", KYTRAL_SECRET: S });
  writeFileSync(join(m.project, ".mcp.json"), JSON.stringify({ mcpServers: { "plainword-prod": { command: "x" }, safe: { command: "y" } } }));
  const r = m.cli("doctor", "--report"); assert.equal(r.code, 0, r.err); noLeak(r.out, ["plainword-prod"]); assert.match(r.out, /not wrapped: (<name>, safe|safe, <name>)/);
});
test("kytral_home_three_forms_and_unknown_vars: ~/.kytral (default), under ~ (custom), <path>; unknown KYTRAL_ variables counted, never named", () => {
  const forms: [(h: string) => string, string][] = [[h => join(h, ".kytral"), "~/.kytral (default)"], [h => join(h, "clients", "acme-hunter2", ".kytral"), "under ~ (custom)"],
    [h => h, "under ~ (custom)"], [() => join(tmpdir(), "elsewhere-hunter2"), "<path>"]];
  for (const [kh, shown] of forms) {
    const r = machine({ KYTRAL_hunter2: "1", KYTRAL_TOKEN_X: "y" }, kh).cli("doctor", "--report"); assert.equal(r.code, 0, r.err);
    assert.ok(r.out.includes(`- KYTRAL_HOME: ${shown}`), r.out); noLeak(r.all, ["hunter2", "acme", "elsewhere", "KYTRAL_TOKEN_X"]);
    assert.match(r.out, /plus 2 unknown to this version \(not named\)/);
  }
  const m = machine(); symlinkSync(join(m.home, "real"), join(m.home, "lnk"));
  const rr = machine({}, h => join(h, "..", "home", ".kytral")).cli("doctor", "--report"); assert.match(rr.out, /- KYTRAL_HOME: ~\/\.kytral \(default\)/);
});
test("every_line_is_a_template: every line of the report matches a fixed template (whitelist), even with a loaded environment", () => {
  const m = machine({ KYTRAL_SECRET: S, KYTRAL_AUDIENCE: "kytral-guard:test-audience", KYTRAL_BADGE: "eyJx.y.z", GITHUB_TOKEN: "ghp_x", KYTRAL_FOO: SEC });
  writeFileSync(join(m.project, ".mcp.json"), JSON.stringify({ mcpServers: { github: { command: "kytral-guard", args: ["--", "x"] }, [`postgres://a:${SEC}@h`]: { command: "y" }, ok: { command: "z" } } }));
  mkdirSync(join(m.home, ".kytral")); writeFileSync(join(m.home, ".kytral", "audit.jsonl"), `{"x":"${SEC}"}\n`);
  const r = m.cli("doctor", "--report"); assert.equal(r.code, 0, r.err);
  const NAME = "(?:<name>|[A-Za-z0-9][A-Za-z0-9._-]{0,63})", NAMES = `(?:none|${NAME}(?:, ${NAME})*(?:, and \\d+ more)?)`;
  const T = [/^$/, /^#{3,4} [A-Za-z ():-]+(?: \(kytral-guard doctor --report\))?$/, /^Redacted: .*$/, /^- kytral-guard: (\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?|unknown)$/, /^- Node\.js: \d+\.\d+\.\d+$/,
    /^- OS: (Linux|Darwin|Windows_NT|FreeBSD|OpenBSD|NetBSD|SunOS|AIX|other) (\d+(\.\d+){0,3}|unknown)( \(WSL\))?, platform [a-z0-9]+, arch [a-z0-9]+$/,
    /^- KYTRAL_HOME: (~\/\.kytral \(default\)|under ~ \(custom\)|<path>), (exists|does not exist yet)$/, /^- KYTRAL_ variables set \(names only\): (none|KYTRAL_[A-Z_]+(, KYTRAL_[A-Z_]+)*)(; plus \d+ unknown to this version \(not named\))?$/,
    /^- KYTRAL_(AUDIT_)?SECRET: (not set|set but empty|set, usable|set, refused \([a-z0-9 :,]+\))$/, /^- Agent hooks: .*$/, new RegExp(`^- [A-Za-z ,.()~/]+: (wrapped: ${NAMES}; not wrapped: ${NAMES}|no MCP server|cannot be read \\([A-Za-z0-9_ ]+\\))$`),
    /^- MCP clients: no configuration found .*$/, /^- Source: [a-z -]+\(?[a-z -]*\)?(, (cannot be read \([A-Z0-9_]+\)|does not load: [A-Za-z0-9 ':|()]+))?$/, /^- Rules: \d+ \(block \d+, confirm \d+, allow \d+\)$/,
    /^- Default: (allow|block|confirm|unknown); unknownTools: (allow|block|confirm|unknown)$/, /^- Presets: .*$/, /^- Killed: (yes|no)( \(signature not checked: no usable secret in this shell\))?$/,
    /^- Present: (no|yes, \d+ entr(y|ies)|yes, cannot be read \([A-Z0-9_]+\))$/, /^- could not be checked \([A-Z0-9_]+\)$/];
  for (const line of r.out.split("\n")) assert.ok(T.some(re => re.test(line)), `line matching no template: ${JSON.stringify(line)}`);
  noLeak(r.all, [SEC, "KYTRAL_FOO", "ghp_x", "eyJx"]);
});
