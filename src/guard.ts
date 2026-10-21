import { glob, Action, Policy, ToolCall, Decision } from "./policy.js";
import { evaluateSyncBounded } from "./evaluate-bounded.js";
import { verifyBadge, Badge } from "./badge.js";
import { AuditLog, auditKey, type Entry } from "./audit.js";
import { keepCall } from "./kept-calls.js";
import { FileSet, statePath } from "./store.js";
import { randomBytes } from "node:crypto";
import { assertAudience, assertStrongSecret, assertAuditSecret } from "./secret.js";
import { BAD_GRANT, cleanName, isPlainToolName, knownKey, knownToolsKey, knownToolsPath, parseGrant, removeGrants, tombstonePath, KnownGrant } from "./known-tools.js";
import { KillSwitch, KILL_POLL_MS, killSwitchKey, killSwitchPath, startingSwitch } from "./kill-switch.js";
import type { ConfirmQueue } from "./confirm-queue.js";
import { KytralPlugin, notifyPlugins, pluginConfirm, pluginKillReason } from "./plugins.js";
/** Human answer. "once" (default choice) = this call only; "always" = add (server, tool, agent) to known-tools.json
 *  (only offered for unknown tools); "deny" = refuse. Booleans are accepted: true = once, false = deny.
 *  Answer { choice, approver } to record who decided (audit and grant). A permanent grant must name its approver:
 *  "always" without a name is refused; a bare "once" is journaled as approver "unidentified". */
export type ConfirmChoice = "once" | "always" | "deny";
export type ConfirmAnswer = boolean | ConfirmChoice | { choice: ConfirmChoice; approver?: string };
export interface ConfirmContext { agentId: string; server: string; choices: ConfirmChoice[]; defaultChoice: ConfirmChoice }
export type Confirmer = (call: ToolCall, d: Decision, ctx: ConfirmContext) => Promise<ConfirmAnswer>;
const SEVERITY: Record<Action, number> = { allow: 0, confirm: 1, block: 2 };
/** Normalizes a confirmer's answer; anything unexpected becomes a refusal. `approver` is undefined unless a name (a letter or digit) was given. */
function readAnswer(ans: ConfirmAnswer): { choice: ConfirmChoice; approver?: string } {
  const o: any = ans !== null && typeof ans === "object" ? ans : { choice: ans === true ? "once" : ans === false || ans == null ? "deny" : ans };
  const name = typeof o.approver === "string" ? cleanName(o.approver) : "";
  return { choice: o.choice, approver: /[\p{L}\p{N}]/u.test(name) ? name : undefined };
}
export class GuardError extends Error {}
export interface GuardOptions {
  policy: Policy; secret: string; audit?: AuditLog; confirm?: Confirmer;
  /** Persistent revocation list (JSON). Default: $KYTRAL_REVOCATIONS or $KYTRAL_HOME/revocations.json (~/.kytral), always resolved to an absolute path. null = memory only. */
  revocationFile?: string | null;
  /** Where single-use (once) badge nonces are bound to a proxy instance. Default: $KYTRAL_NONCES or $KYTRAL_HOME/nonces.json (absolute). */
  nonceFile?: string | null;
  /** Expected badge audience (required, unique per deployment): this option or $KYTRAL_AUDIENCE. "kytral-guard" is refused. Every check fails closed without it. */
  audience?: string;
  /** "Always allow" grants for unknown tools, keyed by server + tool + agent. Default: $KYTRAL_KNOWN_TOOLS or $KYTRAL_HOME/known-tools.json. null = memory only. */
  knownToolsFile?: string | null;
  /** Server key used in known-tools.json. Default: $KYTRAL_SERVER_ID, else the audience (unique per proxy). */
  server?: string;
  /** Local confirmation queue, used when no `confirm` callback is given (proxy: KYTRAL_CONFIRM_QUEUE=1). Without either, confirm = refuse. */
  confirmQueue?: ConfirmQueue | null;
  /** Kill switch shared with every proxy and the CLI (`kytral-guard kill` / `resume`), read before every call. Default: $KYTRAL_HOME/kill-switch.json. */
  killSwitchFile?: string;
  /** Loaded plugins: an extra kill switch, remote approvals (before the confirmation queue), copies of audit entries. */
  plugins?: KytralPlugin[];
  /** Who runs this guard, for plugins: the MCP proxy or an SDK integration (default). */
  source?: "proxy" | "sdk";
  /** Keep the text of refused and confirmed calls in $KYTRAL_HOME/kept-calls.jsonl, masked, for the dashboard (the proxy: keepCallsEnabled()). Default: no. */
  keepCalls?: boolean;
}
export class Guard {
  revoked: FileSet; nonces: FileSet; knownTools: FileSet; tombstones: FileSet; killed = false; killSwitch: KillSwitch; audit: AuditLog; plugins: KytralPlugin[]; readonly instance = randomBytes(8).toString("hex");
  /** Pending confirmations to end at once on kill(). */
  private killWaiters = new Set<() => void>();
  /** Tools the MCP server itself annotated with destructiveHint (learned from tools/list); only ever escalates. */
  destructiveTools = new Set<string>();
  /** Tool names advertised by the server's tools/list (learned by the proxy). */
  serverTools = new Set<string>();
  /** Ids of tools/list requests sent by the client and not yet answered: only their responses teach known tools. */
  pendingToolsList = new Set<string>();
  /** Bounded (oldest dropped first): a client flooding tools/list cannot grow memory without limit. */
  static readonly MAX_PENDING_TOOLS_LIST = 1024;
  expectToolsList(id: unknown) {
    const k = JSON.stringify(id); this.pendingToolsList.delete(k); this.pendingToolsList.add(k);
    while (this.pendingToolsList.size > Guard.MAX_PENDING_TOOLS_LIST) this.pendingToolsList.delete(this.pendingToolsList.values().next().value!);
  }
  isKnownTool(tool: string) { return this.serverTools.has(tool) || (this.o.policy.knownTools ?? []).some(g => glob(g, tool)); }
  constructor(private o: GuardOptions) {
    // Same rule as the CLI/proxy (assertStrongSecret), no escape hatch. KYTRAL_AUDIT_SECRET, if set, must be strong too.
    if (typeof o.secret !== "string") throw new GuardError("KYTRAL_SECRET is missing: a string secret is required");
    assertStrongSecret(o.secret); assertAuditSecret();
    // HMAC-chained audit: an AuditLog given without a key gets this deployment's (KYTRAL_AUDIT_SECRET, else the secret).
    this.audit = o.audit ?? new AuditLog();
    this.audit.key ??= auditKey(o.secret);
    this.plugins = o.plugins ?? [];
    if (this.plugins.length) this.audit.sinks.push(e => notifyPlugins(this.plugins, "onAudit", e));
    // Revocations only restrict: monotonic in memory (a deleted/rewritten file never un-revokes a running proxy).
    this.revoked = new FileSet(o.revocationFile === undefined ? statePath(process.env.KYTRAL_REVOCATIONS, "revocations.json") : o.revocationFile, { monotonic: true, onMissing: "keep" });
    this.nonces = new FileSet(o.nonceFile === undefined ? statePath(process.env.KYTRAL_NONCES, "nonces.json") : o.nonceFile);
    // Known-tools grants: every entry HMAC-signed (key derived from the proxy secret and bound to the file's real path), bad
    // entries dropped + audited (another home's grants, copied in, are bad entries here); deleted file = cleared.
    // A corrupt file grants nothing (unknown tools are confirmed again), is audited, and is never written over.
    const knownPath = o.knownToolsFile === undefined ? knownToolsPath() : o.knownToolsFile;
    // Anti-replay: removing a grant leaves a tombstone (removal time); a grant made at or before it is refused, so a
    // removed grant restored from a backup of known-tools.json stays dead. Tombstones only restrict: monotonic, never forgotten.
    this.tombstones = new FileSet(tombstonePath(knownPath), { monotonic: true, onMissing: "keep" });
    this.knownTools = new FileSet(knownPath, {
      signKey: knownToolsKey(o.secret, knownPath), onMissing: "clear", lazyCorrupt: true,
      onReject: (k) => { let tool = "?", agentId = "unknown"; try { [, tool, agentId] = JSON.parse(k); } catch {} this.audit.append({ agentId, tool, decision: "known-reject", rule: BAD_GRANT }); },
      onCorrupt: (why) => this.audit.append({ agentId: "unknown", tool: "-", decision: "known-tools-corrupt", rule: why.slice(0, 200) }),
    });
    // Kill switch shared by every proxy of this KYTRAL_HOME. Fail closed: anything but a signed, fresh resume blocks every call;
    // an unusable state (unreadable, corrupt, forged or replayed resume) is journaled once. It starts from the last kill or
    // resume the audit log records (startingSwitch), as agent hooks do: a proxy or an SDK guard started after kill-switch.json
    // was deleted, or an older resume put back, still finds the kill. A log that cannot be read stops the construction.
    const ksFile = o.killSwitchFile ?? killSwitchPath();
    this.killSwitch = new KillSwitch(ksFile, killSwitchKey(o.secret),
      (why) => this.audit.append({ agentId: "unknown", tool: "-", decision: "kill-switch-invalid", rule: why.slice(0, 200) }), startingSwitch(o.secret, ksFile, this.audit));
  }
  get server() { return this.o.server ?? process.env.KYTRAL_SERVER_ID ?? this.o.audience ?? process.env.KYTRAL_AUDIENCE ?? "default"; }
  /** Removes one agent's "always" grant for a tool on this server (tombstoned: a restored backup cannot bring it back); journaled with who removed it. (CLI: `known remove`.) */
  removeKnown(tool: string, agentId: string, server = this.server, approver = "unidentified"): boolean {
    const had = removeGrants(this.knownTools, this.tombstones, tool, { agentId, server }).length > 0;
    this.audit.append({ agentId, tool, decision: "known-remove", ...(had ? {} : { rule: "absent" }), server, approver: cleanName(approver) || "unidentified" });
    return had;
  }
  /** Valid "always" grant for this tool and agent on this server, or null (none, forged, replayed, corrupt file: fail closed). */
  private knownGrant(tool: string, agentId: string): KnownGrant | null {
    if (!isPlainToolName(tool)) return null;
    const key = knownKey(this.server, tool, agentId);
    const grant = parseGrant(key, this.knownTools.get(key)); if (!grant) return null;
    // Anti-replay: a grant made at or before the key's last removal (tombstone) is a restored copy: refused and journaled.
    const at = Date.parse(grant.approvedAt), t = this.tombstones.get(key);
    if (!Number.isFinite(at)) return null;
    if (t !== undefined && !(at > Number(t))) { this.audit.append({ agentId, tool, decision: "known-reject", rule: "revoked (tombstone): replayed entry" }); return null; }
    return grant;
  }
  /** Remote approvals from plugins (Slack, a web page), then the confirmation queue if there is one, else a refusal. */
  private pluginConfirmer(): Confirmer | undefined {
    if (!this.plugins.some(p => p.confirm)) return undefined;
    const fallback = this.queueConfirmer();
    return async (call, d, ctx) => {
      const timeout = Number(process.env.KYTRAL_REMOTE_CONFIRM_TIMEOUT_MS ?? 60_000);
      const answer = await pluginConfirm(this.plugins, { source: this.o.source ?? "sdk", agent: ctx.agentId, tool: call.tool, args: call.args, rule: d.rule, reason: d.reason,
        cwd: ctx.server, localPrompt: !!fallback, timeoutMs: Number.isFinite(timeout) && timeout > 0 ? timeout : 60_000 }, Number.isFinite(timeout) && timeout > 0 ? timeout : 60_000);
      if (answer) return { choice: answer.verdict === "allow" ? "once" : "deny", approver: `${answer.approver ?? "unidentified"} (via ${answer.plugin})` };
      return fallback ? fallback(call, d, ctx) : "deny";
    };
  }
  /** Confirmer backed by the confirmation queue: approve = once, approve_always = always; an invalid decision is journaled. */
  private queueConfirmer(): Confirmer | undefined {
    const q = this.o.confirmQueue; if (!q) return undefined;
    return async (call, d, ctx) => {
      // The queue polls the kill switch (this process and the shared file) and withdraws its request as soon as it is engaged.
      const a = await q.ask({ server: ctx.server, agentId: ctx.agentId, tool: call.tool, rule: d.rule ?? "", reason: d.reason, args: call.args, always: ctx.choices.includes("always") }, () => this.killReason() !== null);
      if (a.problem?.startsWith("invalid")) this.audit.append({ agentId: ctx.agentId, tool: call.tool, decision: "confirm-invalid", rule: a.problem.slice(0, 200) });
      return { choice: a.verdict === "approve_always" ? "always" : a.verdict === "approve" ? "once" : "deny", approver: a.approver };
    };
  }
  kill() { this.killed = true; for (const wake of [...this.killWaiters]) wake(); }   // one-click kill switch (this process): blocks every agent, ends pending confirmations
  resume() { this.killed = false; }   // lifts kill() only: `kytral-guard kill` stays in force until `kytral-guard resume`
  /**
   * Why every call is refused right now: kill(), or the shared kill switch engaged, unreadable or invalid. Null when calls go
   * on. Never throws (the proxy and pending confirmations poll it): what cannot be checked refuses every call.
   */
  killReason(): string | null {
    if (this.killed) return "kill switch active";
    try { return this.killSwitch.check() ?? pluginKillReason(this.plugins); }
    catch (e) { return `kill switch active: it cannot be checked (${(e as NodeJS.ErrnoException)?.code ?? "error"}), every tool call is refused (fail closed)`; }
  }
  /** Settles as soon as a kill is seen: kill() at once, the shared kill switch within KILL_POLL_MS. Call stop() when done. */
  private untilKilled(): { killed: Promise<void>; stop: () => void } {
    let stop = () => {};
    const killed = new Promise<void>(resolve => {
      const fire = () => { stop(); resolve(); };
      const timer = setInterval(() => { if (this.killReason()) fire(); }, KILL_POLL_MS); timer.unref();
      this.killWaiters.add(fire);
      stop = () => { clearInterval(timer); this.killWaiters.delete(fire); };
    });
    return { killed, stop };
  }
  revoke(idOrAgent: string) { this.revoked.add(idOrAgent); }
  /** Replaces the policy from the next call (the proxy follows its policy file). A confirmation already pending keeps its decision. */
  setPolicy(policy: Policy) { this.o.policy = policy; }
  /** The text of a refused or confirmed call, kept apart from the log for the dashboard (masked), when keepCalls is on. */
  private keep(e: Entry, agentId: string, call: ToolCall, d: Pick<Decision, "rule" | "reason">) {
    if (this.o.keepCalls) keepCall({ seq: e.seq, ts: e.ts, agent: agentId, tool: call.tool, decision: e.decision, rule: d.rule, reason: d.reason, args: call.args, cwd: this.server }, this.o.secret);
  }
  /**
   * Synchronous decision. Returns null when the call is allowed (audit written), throws GuardError when refused,
   * or returns a pending confirmation (only when a confirmer is configured and a rule asks for it).
   */
  checkSync(badgeToken: string, call: ToolCall): null | { confirm: () => Promise<void> } {
    let agentId = "unknown";
    // `kept`: the decision behind a refusal of the policy or of a human, whose call text is kept for the dashboard
    const deny = (why: string, rule?: string, kept?: Pick<Decision, "rule" | "reason">): never => {
      const e = this.audit.append({ agentId, tool: call.tool, decision: "block", rule });
      if (kept) this.keep(e, agentId, call, kept);
      throw new GuardError(why);
    };
    const killed = this.killReason();   // first: wins over badges, rules, known tools and confirmations
    if (killed) deny(killed, "kill-switch", { rule: "kill-switch", reason: killed });
    let badge!: Badge;
    try {
      badge = verifyBadge(this.o.secret, badgeToken, this.revoked, Date.now());   // signature, expiry, revocation
      // Audience is mandatory in the SDK too: no shared default. Fail closed if not configured.
      const audience = assertAudience(this.o.audience ?? process.env.KYTRAL_AUDIENCE);
      if (badge.aud !== audience) throw new Error(`badge: wrong audience '${badge.aud}'`);
      if (badge.once) { const owner = this.nonces.get(badge.nonce); if (owner && owner !== this.instance) throw new Error("badge: single-use badge already bound to another proxy"); if (!owner) this.nonces.add(badge.nonce, this.instance); }
    } catch (e) { if (e instanceof GuardError) throw e; deny((e as Error).message); }
    agentId = badge.agentId;
    if (!badge.tools.some(t => t === "*" || t === call.tool)) deny(`tool '${call.tool}' not on badge`);
    // with a deadline and a memory limit, in a worker thread: a crafted argument of a few hundred characters must not stop
    // the guard (out of memory), nor a few dozen kilobytes hold the proxy's calls for minutes (evaluate-bounded.ts)
    let d = evaluateSyncBounded(this.o.policy, call);
    // A policy built in code (no loadPolicy) may carry an invalid action: refuse it, never treat it as allow.
    if (!Object.hasOwn(SEVERITY, d.action)) deny(`invalid policy action '${String(d.action)}'`, d.rule);
    // Unknown tools: the default applies to policies built in code too (no loadPolicy) - never an undefined action.
    const unknownAction = this.o.policy.unknownTools ?? "confirm";
    if (d.reason === "default" && !this.isKnownTool(call.tool) && unknownAction !== "allow") {
      if (!["block", "confirm"].includes(unknownAction)) deny(`invalid unknownTools '${String(unknownAction)}'`, "unknown-tool");
      // The unknown-tool rule only ever escalates the policy decision: with `default: block` the tool stays blocked.
      if (SEVERITY[unknownAction] > SEVERITY[d.action]) {
        // A human "always" grant makes the tool known for this agent on this server: it only cancels this escalation, so the
        // call gets the policy decision a known tool would get (every rule was evaluated before and wins).
        const grant = unknownAction === "confirm" ? this.knownGrant(call.tool, agentId) : null;
        d = grant ? { ...d, rule: "known-tool", reason: `tool approved as known by ${grant.approver} (${grant.approvedAt})` }
          : { action: unknownAction, rule: "unknown-tool", reason: `tool '${call.tool}' is unknown (not advertised by the server, not in knownTools)` };
      }
    }
    if (d.action === "allow" && this.destructiveTools.has(call.tool)) d = { action: "confirm", rule: "mcp-destructive-hint", reason: "server annotated the tool as destructive" };
    if (d.action === "block") deny(`blocked: ${d.reason}`, d.rule, d);
    if (d.action === "confirm") {
      const confirmer = this.o.confirm ?? this.pluginConfirmer() ?? this.queueConfirmer();
      if (!confirmer) deny(`confirmation refused: ${d.reason}`, d.rule, d);
      // "always" only for the unknown-tool rule, for a plain tool name the server did not annotate as destructive.
      const canAlways = d.rule === "unknown-tool" && isPlainToolName(call.tool) && !this.destructiveTools.has(call.tool);
      const ctx: ConfirmContext = { agentId, server: this.server, choices: canAlways ? ["once", "always", "deny"] : ["once", "deny"], defaultChoice: "once" };
      return { confirm: async () => {
        // A kill (kill(), or `kytral-guard kill` from another process) ends a pending confirmation at once, whatever the confirmer
        // does; the queue polls the kill switch itself and withdraws its request.
        const watch = this.o.confirm ? this.untilKilled() : null;
        let ans: ConfirmAnswer = false;
        try { const asked = confirmer!(call, d, ctx); ans = await (watch ? Promise.race([asked, watch.killed.then(() => false)]) : asked); }   // the human is asked at once, as before
        catch { ans = false; } finally { watch?.stop(); }
        const killed = this.killReason();   // kill switch also wins after the answer, before any call or grant
        if (killed) deny(`confirmation refused: ${killed}`, "kill-switch", { rule: "kill-switch", reason: killed });
        const { choice, approver: named } = readAnswer(ans);
        if (!ctx.choices.includes(choice) || choice === "deny") deny(`confirmation refused: ${d.reason}`, d.rule, d);
        // A permanent grant must say who gave it: "always" without the approver's name is refused, never recorded anonymously.
        if (choice === "always" && !named) deny(`confirmation refused: 'always' needs the approver's name (answer { choice: "always", approver })`, d.rule, d);
        // Re-check the badge after the (possibly long) human wait: revocation, expiry, audience - before any call or "always" entry.
        try {
          const again = verifyBadge(this.o.secret, badgeToken, this.revoked, Date.now());
          if (again.aud !== assertAudience(this.o.audience ?? process.env.KYTRAL_AUDIENCE) || again.agentId !== agentId) throw new Error("badge: changed during confirmation");
        } catch (e) { deny(`confirmation refused: badge no longer valid after confirmation (${(e as Error).message})`, d.rule); }
        const approver = named ?? "unidentified";
        if (choice === "always") {
          const key = knownKey(this.server, call.tool, agentId);
          // A permanent grant that cannot be recorded (corrupt known-tools.json, unreadable tombstone) refuses the call: fail closed.
          try {
            const t = Number(this.tombstones.get(key) ?? 0); if (!Number.isFinite(t)) throw new Error("unreadable tombstone");
            // Dated after the key's tombstone, if any: a re-grant after a removal stays valid (anti-replay compares the two).
            const grant: KnownGrant = { server: this.server, tool: call.tool, agentId, approver, approvedAt: new Date(Math.max(Date.now(), t + 1)).toISOString() };
            this.knownTools.add(key, JSON.stringify(grant));
          } catch (e) { deny(`confirmation refused: 'always' could not be recorded (${(e as Error).message})`, d.rule); }
          this.audit.append({ agentId, tool: call.tool, decision: "known-add", rule: d.rule, server: this.server, approver });
        }
        this.keep(this.audit.append({ agentId, tool: call.tool, decision: choice === "always" ? "confirmed-always" : "confirmed", rule: d.rule, approver }), agentId, call, d);
      } };
    }
    this.audit.append({ agentId, tool: call.tool, decision: "allow", rule: d.rule });
    return null;
  }
  /**
   * Refuses a request that is not a tool call (the proxy: an MCP resource naming the guard's secret): journaled like a
   * blocked call, under the badge's agent when the badge is valid. Always throws GuardError.
   */
  refuse(badgeToken: string, tool: string, rule: string, why: string, args: Record<string, unknown> = {}): never {
    let agentId = "unknown";
    try { agentId = verifyBadge(this.o.secret, badgeToken, this.revoked, Date.now()).agentId; } catch {}
    this.keep(this.audit.append({ agentId, tool, decision: "block", rule }), agentId, { tool, args }, { rule, reason: why });
    throw new GuardError(why);
  }
  async check(badgeToken: string, call: ToolCall): Promise<void> {
    const pending = this.checkSync(badgeToken, call);
    if (pending) await pending.confirm();
  }
  wrap<A extends Record<string, unknown>, R>(badge: string, tool: string, fn: (a: A) => Promise<R>) {
    return async (args: A) => { await this.check(badge, { tool, args }); return fn(args); };
  }
}
