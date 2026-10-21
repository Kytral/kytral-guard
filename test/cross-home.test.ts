// What grants an allow is bound to the file it was signed for, as the kill switch is: an "always" grant (known-tools.json),
// a confirmation request or decision (the queue directory), a kept call that `kytral-guard allow --call` or the dashboard
// turns into an exception (kept-calls.jsonl). Copied from another KYTRAL_HOME that uses the same secret, alone, together, or
// as a whole home copied over this one, none of them lifts a kill or grants anything here; neither does one an older
// version wrote (unbound), nor this home's own reached through another path.
import { test } from "node:test"; import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { spawnSync } from "node:child_process";
import { copyFileSync, cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join, resolve } from "node:path";
import { AuditLog, auditKey } from "../src/audit.js";
import { canonicalJson, confirmKey, decide, FileConfirmQueue, listRequests } from "../src/confirm-queue.js";
import { keepCall, readKeptCalls } from "../src/kept-calls.js";
import { BAD_GRANT, knownKey } from "../src/known-tools.js";
import { DEFAULT_POLICY, deriveKey, Guard, issueBadge, loadPolicy } from "../src/index.js";

const ROOT = resolve(import.meta.dirname, "..");
const S = "2d9f4b7e1a6c3058d2f9b4e7a1c6d3085f2b9e4a7d1c6f3b8e5a2d9c4f7b1e6a", AUD = "kytral-guard:cross-home-grants";
const tmp = () => mkdtempSync(join(tmpdir(), "kg-cross-grants-"));
const bd = (agent = "agent-a") => issueBadge(S, agent, ["*"], 600, Date.now(), { aud: AUD });
/** A guard of the home `h`, as a proxy builds one: its grants, tombstones and kill switch there (its audit log in memory, unless given). */
const guard = (h: string, o: Record<string, unknown> = {}) => new Guard({ policy: loadPolicy(DEFAULT_POLICY), secret: S, audience: AUD, revocationFile: null, nonceFile: null,
  knownToolsFile: join(h, "known-tools.json"), killSwitchFile: join(h, "kill-switch.json"), ...o });
/** The audit log of the home `h`, which a guard starts its kill switch from. */
const fileAudit = (h: string) => new AuditLog(join(h, "audit.jsonl"), { key: auditKey(S) });
/** "Always" for `mystery`, given by a human in the home `h`. */
async function grant(h: string) { await guard(h, { confirm: async () => ({ choice: "always", approver: "alice" }) }).check(bd(), { tool: "mystery", args: {} }); }
/** Whether a new guard of `h` (or `g`), with nobody to confirm, lets `mystery` through: only a valid grant does, anything else confirms (refused). */
async function granted(h: string, g = guard(h)) {
  try { await g.check(bd(), { tool: "mystery", args: {} }); return true; }
  catch (e) { assert.match((e as Error).message, /^confirmation refused: tool 'mystery' is unknown/, "refused for want of a grant, nothing else"); return false; }
}

function cli(h: string, args: string[], input = "") {
  const env: Record<string, string | undefined> = { ...process.env, KYTRAL_HOME: h, KYTRAL_SECRET: S };
  for (const k of ["KYTRAL_AUDIT", "KYTRAL_AUDIT_SECRET", "KYTRAL_POLICY", "KYTRAL_PLUGINS", "KYTRAL_KNOWN_TOOLS", "KYTRAL_KEPT_CALLS", "KYTRAL_CONFIRMATIONS", "KYTRAL_KEEP_CALLS"]) delete env[k];
  const r = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli.ts"), ...args], { cwd: ROOT, env: env as NodeJS.ProcessEnv, encoding: "utf8", input });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
const hook = (h: string, command: string) => cli(h, ["hook", "claude-code"], JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, cwd: tmpdir(), session_id: "s" }));

test("an always grant is signed for its known-tools.json: another home's (same secret), copied in alone, with its tombstones or over this home's, grants nothing here and is journaled as rejected; this home's own still holds", async () => {
  const d = tmp(), theirs = join(d, "theirs"); await grant(theirs); assert.equal(await granted(theirs), true, "their own grant holds there");
  const FILES = ["known-tools.json", "known-tools.tombstones.json"];
  writeFileSync(join(theirs, "known-tools.tombstones.json"), "{}");
  let n = 0;
  for (const copied of [[FILES[0]], FILES]) for (const ownFirst of [false, true]) {
    const h = join(d, `ours-${++n}`); mkdirSync(h);
    if (ownFirst) { await grant(h); await guard(h).removeKnown("mystery", "agent-a"); assert.equal(await granted(h), false, "removed here"); }
    for (const f of copied) copyFileSync(join(theirs, f), join(h, f));
    const g = guard(h); assert.equal(await granted(h, g), false, `copied ${copied.join("+")}${ownFirst ? ", over this home's" : ""}`);
    assert.ok(g.audit.entries.some(e => e.decision === "known-reject" && e.tool === "mystery" && e.rule === BAD_GRANT), "journaled as rejected");
    const list = cli(h, ["known", "list"]); assert.match(list.err, /rejected \(bad signature \(forged, edited, or signed for another known-tools file/);
    await grant(h); assert.equal(await granted(h), true, "a grant given here holds here");
  }
});

test("an always grant written by an older version (signed without the file's id), or for this home reached through another path, grants nothing: the tool is confirmed again", async () => {
  const d = tmp(), h = join(d, "kh"); mkdirSync(h);
  const body = JSON.stringify({ server: AUD, tool: "mystery", agentId: "agent-a", approver: "alice", approvedAt: new Date().toISOString() }), k = knownKey(AUD, "mystery", "agent-a");
  const older = createHmac("sha256", deriveKey(S, "known-tools/v1")).update(JSON.stringify([k, body])).digest("base64url");
  writeFileSync(join(h, "known-tools.json"), JSON.stringify({ [k]: JSON.stringify({ v: body, sig: older }) }));
  assert.equal(await granted(h), false, "an older version's grant");
  await grant(h); assert.equal(await granted(h), true);
  const moved = join(d, "moved"); renameSync(h, moved);
  assert.equal(await granted(moved), false, "the same file through another path");
});

test("a confirmation request or decision is signed for its queue directory: a request copied to another home's queue is neither shown nor answered there, and a decision made for another queue is refused here", async () => {
  const d = tmp(), ours = join(d, "ours", "confirmations"), theirs = join(d, "theirs", "confirmations"); mkdirSync(theirs, { recursive: true });
  const g = guard(join(d, "ours"), { confirmQueue: new FileConfirmQueue({ secret: S, dir: ours, timeoutMs: 20000, pollMs: 5 }) });
  const p = g.check(bd(), { tool: "mystery", args: { a: 1 } });
  const [r] = listRequests(S, ours).requests; assert.ok(r, "pending here");
  copyFileSync(join(ours, `${r.id}.request.json`), join(theirs, `${r.id}.request.json`));
  assert.deepEqual(listRequests(S, theirs), { requests: [], invalid: [`${r.id}.request.json`] }, "not shown there");
  assert.throws(() => decide(S, r.id, "approve_always", "mallory", theirs), /no pending request/, "not answered there");
  // a decision for this very request, correctly signed, but for the other queue
  const body = { v: 1, id: r.id, verdict: "approve", argsHash: r.argsHash, approver: "mallory", decidedAt: new Date().toISOString() };
  writeFileSync(join(ours, `${r.id}.decision.json`), JSON.stringify({ ...body, sig: createHmac("sha256", confirmKey(S, theirs)).update(`decision\n${canonicalJson(body)}`).digest("base64url") }));
  await assert.rejects(p, /confirmation refused/);
  assert.ok(g.audit.entries.some(e => e.decision === "confirm-invalid" && /bad decision signature/.test(e.rule!)));
  assert.ok(!g.audit.entries.some(e => e.decision === "confirmed" || e.decision === "known-add"));
  // answered in its own queue, the same request goes through
  const p2 = g.check(bd(), { tool: "mystery", args: { a: 1 } });
  let r2; for (let i = 0; i < 200 && !r2; i++) { [r2] = listRequests(S, ours).requests; if (!r2) await new Promise(res => setTimeout(res, 5)); }
  decide(S, r2!.id, "approve", "alice", ours); await p2;
});

test("a kept call is signed for its kept-calls.jsonl: another home's, an edited one or an older version's (unsigned) is not read, so neither allow --call nor the dashboard can make it an exception", () => {
  const d = tmp(), ours = join(d, "ours", "kept-calls.jsonl"), theirs = join(d, "theirs", "kept-calls.jsonl");
  const call = (seq: number, command: string) => ({ seq, agent: "claude-code", tool: "Bash", decision: "ask", rule: "git-history", args: { command } });
  assert.ok(keepCall(call(7, "git reset --hard HEAD~1"), S, ours)); assert.ok(keepCall(call(7, "git reset --hard HEAD~50"), S, theirs));
  assert.deepEqual(readKeptCalls(S, ours).map(k => k.text), ["git reset --hard HEAD~1"]);
  copyFileSync(theirs, ours); assert.deepEqual(readKeptCalls(S, ours), [], "another home's");
  const line = JSON.parse(readFileSync(theirs, "utf8")), edited = { ...line, text: "git reset --hard HEAD~99" }, { mac: _m, ...unsigned } = line;
  writeFileSync(theirs, [JSON.stringify(edited), JSON.stringify(unsigned)].join("\n") + "\n");
  assert.deepEqual(readKeptCalls(S, theirs), [], "edited, or unsigned");
  // the CLI: the text kept by this home's hook is allowed with --call; once another home's file is put in its place, nothing is
  const h = join(d, "kh"), other = join(d, "other");
  for (const home of [h, other]) assert.equal(JSON.parse(hook(home, "git reset --hard HEAD~3").out).hookSpecificOutput.permissionDecision, "ask");
  const [kept] = readKeptCalls(S, join(h, "kept-calls.jsonl")), [theirKept] = readKeptCalls(S, join(other, "kept-calls.jsonl"));
  assert.equal(kept.seq, theirKept.seq, "the same seq in both homes");
  copyFileSync(join(other, "kept-calls.jsonl"), join(h, "kept-calls.jsonl"));
  const r = cli(h, ["allow", "--call", String(kept.seq)]); assert.equal(r.code, 1, r.out); assert.match(r.err, new RegExp(`no text is kept for call ${kept.seq}`));
});

test("a kept call whose folder is created on first use, reached through a link (as /var is a link to /private/var on macOS), is signed for the folder's real path: read back through the link and through the real path", () => {
  const d = tmp(), real = join(d, "real"), link = join(d, "link"); mkdirSync(real); symlinkSync(real, link);
  const file = join(link, "home", "kept-calls.jsonl");   // "home" does not exist yet: keepCall creates it
  assert.ok(keepCall({ seq: 3, agent: "claude-code", tool: "Bash", decision: "ask", rule: "git-history", args: { command: "git reset --hard HEAD~1" } }, S, file));
  assert.deepEqual(readKeptCalls(S, file).map(k => k.text), ["git reset --hard HEAD~1"], "through the link");
  assert.deepEqual(readKeptCalls(S, join(real, "home", "kept-calls.jsonl")).map(k => k.text), ["git reset --hard HEAD~1"], "through the real path");
});

test("another home with the same secret copied whole over this one (every file of its KYTRAL_HOME): the kill is not lifted, and once this home resumes, none of its grants, kept calls or pending requests counts here", { timeout: 120000 }, async () => {
  const d = tmp(), h = join(d, "ours"), other = join(d, "theirs");
  // theirs: resumed at a newer generation, an always grant, a kept call, a pending request
  for (const step of ["kill", "resume", "kill", "resume", "kill", "resume"]) assert.equal(cli(other, [step]).code, 0, step);
  await grant(other);
  assert.equal(JSON.parse(hook(other, "git reset --hard HEAD~4").out).hookSpecificOutput.permissionDecision, "ask");
  const q = new FileConfirmQueue({ secret: S, dir: join(other, "confirmations"), timeoutMs: 30000, pollMs: 5 });
  const pending = guard(other, { confirmQueue: q }).check(bd(), { tool: "other_tool", args: {} }).catch(() => "refused");
  for (let i = 0; i < 200 && !listRequests(S, join(other, "confirmations")).requests.length; i++) await new Promise(res => setTimeout(res, 5));
  // ours: killed
  for (const step of ["kill", "resume", "kill"]) assert.equal(cli(h, [step]).code, 0, step);
  cpSync(other, h, { recursive: true, force: true });
  assert.deepEqual(readdirSync(h).sort(), readdirSync(other).sort());
  assert.equal(hook(h, "ls").code, 2, "a hook");
  assert.match(String(await guard(h, { audit: fileAudit(h) }).check(bd(), { tool: "read_file", args: {} }).catch(e => e.message)), /^kill switch active/, "an SDK guard");
  assert.equal(cli(h, ["resume"]).code, 0);
  assert.equal(hook(h, "ls").code, 0, "resumed here");
  assert.equal(await granted(h), false, "their grant");
  const [theirKept] = readKeptCalls(S, join(other, "kept-calls.jsonl"));
  assert.match(cli(h, ["allow", "--call", String(theirKept.seq)]).err, /no text is kept for call/, "their kept call");
  const listed = listRequests(S, join(h, "confirmations")); assert.equal(listed.requests.length, 0, "their pending request"); assert.equal(listed.invalid.length, 1);
  decide(S, listRequests(S, join(other, "confirmations")).requests[0].id, "deny", "alice", join(other, "confirmations"));
  assert.equal(await pending, "refused");
  unlinkSync(join(h, "known-tools.json")); await grant(h); assert.equal(await granted(h), true, "a grant given here holds here");
});
