// Plugins extend a guard without forking it: a central policy, a second kill switch (fleet-wide), remote approvals for
// confirmations nobody can answer locally, and a copy of every decision and audit entry (SIEM, dashboards, alerting).
// Kytral Guard Pro is such a plugin; anyone can write one.
//
// Plugins are listed in KYTRAL_PLUGINS (comma-separated module specifiers or paths) or in $KYTRAL_HOME/config.json
// ({ "plugins": ["@kytral/guard-pro"] }). A module's default export is a plugin, or a function that returns one.
// A plugin that cannot be loaded makes the guard refuse every call: it was configured to enforce something.
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { loadPolicy, policyProblem, type Action, type Policy } from "./policy.js";
import type { Entry } from "./audit.js";
import { NotRegularFile, readRegular, renameReplace, stateDir, statePath, withFileLock } from "./store.js";

/** A call that needs a human, as a plugin sees it. */
export interface ConfirmRequestInfo {
  /** Where the call comes from: an agent hook, the MCP proxy, or the SDK. */
  source: "hook" | "proxy" | "sdk";
  /** Agent name (hooks) or badge agent id (proxy, SDK). */
  agent: string; tool: string; args: Record<string, unknown>;
  rule?: string; reason: string;
  /** Working directory (hooks) or MCP server key (proxy). */
  cwd?: string; session?: string;
  /** Can the agent itself show a prompt to a human for this call? */
  localPrompt: boolean;
  /** How long the guard waits for this plugin's verdict (ms): a request should expire then, nobody waits after. */
  timeoutMs?: number;
}
/** A remote answer: who decided, and how. Null: no answer (the guard falls back to its own behavior). */
export interface RemoteVerdict { verdict: "allow" | "deny"; approver?: string; note?: string }
export interface DecisionEvent extends Omit<ConfirmRequestInfo, "localPrompt"> { action: Action; outcome: "allow" | "ask" | "deny" | "confirmed" }

export interface KytralPlugin {
  name: string;
  /**
   * A policy that replaces the local one (for example distributed and signed by a control plane), for agent hooks ("hook")
   * or the MCP proxy ("proxy"). A string is YAML, parsed and validated by this guard like a local policy file; an invalid
   * policy refuses every call (fail closed). Called once per process.
   */
  policy?(target: "hook" | "proxy"): Policy | string | null | undefined;
  /** A reason to refuse every call right now (for example a fleet-wide kill switch), or null. Synchronous and fast: called before every decision. */
  killReason?(): string | null;
  /** Asked before a confirmation is shown locally or refused: resolve a verdict, or null to let the guard proceed as usual. */
  confirm?(request: ConfirmRequestInfo): Promise<RemoteVerdict | null>;
  /** A copy of every audit entry this process writes, after it is on disk. Must not throw. */
  onAudit?(entry: Entry): void;
  /** Every decision, with its outcome. Must not throw. */
  onDecision?(event: DecisionEvent): void;
  /** Called before a short-lived process (an agent hook) exits: send what is buffered. */
  flush?(): Promise<void>;
}
export interface PluginContext { home: string; version: string }
type PluginModule = { default?: KytralPlugin | ((ctx: PluginContext) => KytralPlugin | Promise<KytralPlugin>) };

/**
 * $KYTRAL_HOME/config.json: plugins, how long a hook waits for a remote approval, and the switches of the dashboard (keep
 * the text of refused calls, journal allowed calls). Throws when it is malformed.
 */
export interface GuardConfig { plugins?: string[]; remoteConfirmTimeoutSeconds?: number; keepCalls?: boolean; auditAllows?: boolean }
const configPath = () => statePath(undefined, "config.json");
function readConfig(cfg: string): Record<string, unknown> {
  let parsed: any;
  // read without ever waiting (a FIFO in its place is refused, not opened): every hook reads it
  try { parsed = JSON.parse(readRegular(cfg).toString("utf8")); } catch (e) { throw new Error(e instanceof NotRegularFile ? e.message : `${cfg} is not valid JSON (${(e as Error).message})`); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${cfg} must hold a JSON object`);
  if (parsed.plugins !== undefined && (!Array.isArray(parsed.plugins) || parsed.plugins.some((p: unknown) => typeof p !== "string"))) throw new Error(`${cfg}: "plugins" must be a list of module names or paths`);
  const t = parsed.remoteConfirmTimeoutSeconds;
  if (t !== undefined && !(typeof t === "number" && Number.isFinite(t) && t > 0 && t <= 3600)) throw new Error(`${cfg}: "remoteConfirmTimeoutSeconds" must be a number of seconds (at most 3600)`);
  for (const k of ["keepCalls", "auditAllows"]) if (parsed[k] !== undefined && typeof parsed[k] !== "boolean") throw new Error(`${cfg}: "${k}" must be true or false`);
  return parsed;
}
export function guardConfig(): GuardConfig {
  const cfg = configPath();
  if (!existsSync(cfg)) return {};
  const p = readConfig(cfg) as GuardConfig;
  return { plugins: p.plugins, remoteConfirmTimeoutSeconds: p.remoteConfirmTimeoutSeconds, keepCalls: p.keepCalls, auditAllows: p.auditAllows };
}
/** Sets switches of config.json (undefined removes one), keeping its other keys; written atomically under its lock. */
export function updateGuardConfig(patch: Pick<GuardConfig, "keepCalls" | "auditAllows">): GuardConfig {
  const cfg = configPath();
  mkdirSync(dirname(cfg), { recursive: true, mode: 0o700 });
  return withFileLock(cfg, () => {
    const data = existsSync(cfg) ? readConfig(cfg) : {};
    for (const [k, v] of Object.entries(patch)) { if (v === undefined) delete data[k]; else data[k] = v; }
    const tmp = `${cfg}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
    renameReplace(tmp, cfg);
    return guardConfig();
  });
}
/** Plugin specifiers from KYTRAL_PLUGINS and $KYTRAL_HOME/config.json ("plugins"), in that order, without duplicates. */
export function pluginSpecs(): string[] {
  const out: string[] = [];
  for (const s of (process.env.KYTRAL_PLUGINS ?? "").split(",")) if (s.trim()) out.push(s.trim());
  out.push(...(guardConfig().plugins ?? []));
  return [...new Set(out)];
}
/** Loads and validates plugins. Throws (fail closed) when one cannot be imported or is malformed. */
export async function loadPlugins(specs: string[] = pluginSpecs(), version = "0"): Promise<KytralPlugin[]> {
  const plugins: KytralPlugin[] = [];
  for (const spec of specs) {
    const target = isAbsolute(spec) || spec.startsWith(".") ? pathToFileURL(resolve(spec)).href : spec;
    let mod: PluginModule;
    try { mod = await import(target) as PluginModule; } catch (e) { throw new Error(`plugin '${spec}' cannot be loaded: ${(e as Error).message}`); }
    const exp = mod.default;
    const plugin = typeof exp === "function" ? await exp({ home: stateDir(), version }) : exp;
    if (!plugin || typeof plugin !== "object" || typeof plugin.name !== "string") throw new Error(`plugin '${spec}' does not export a plugin (an object with a name, or a function returning one)`);
    plugins.push(plugin);
  }
  return plugins;
}

/**
 * The first policy a plugin provides for this target, parsed and validated; undefined when none does. Throws when it is
 * invalid, saying why in fixed words (policyProblem): a hook's refusal goes to its agent, and the policy may hold a secret.
 */
export function pluginPolicy(plugins: KytralPlugin[], target: "hook" | "proxy"): Policy | undefined {
  for (const p of plugins) {
    const pol = p.policy?.(target);
    if (pol === null || pol === undefined) continue;
    try {
      if (typeof pol === "string") return loadPolicy(pol);
      // an object is read exactly like a file: its preset (extends) is merged and checked here
      return loadPolicy(JSON.stringify(pol));
    } catch (e) { throw new Error(`plugin '${p.name}' provides an invalid ${target} policy (${policyProblem(e)})`); }
  }
  return undefined;
}
/** Why a plugin refuses every call right now, or null. A plugin that throws refuses (fail closed). */
export function pluginKillReason(plugins: KytralPlugin[]): string | null {
  for (const p of plugins) {
    try { const r = p.killReason?.(); if (r) return `${p.name}: ${r}`; }
    catch (e) { return `${p.name}: kill switch unreadable (${(e as Error).message}), every call is refused (fail closed)`; }
  }
  return null;
}
/** The first remote verdict, waiting at most `timeoutMs`. A plugin that throws or times out gives no verdict. */
export async function pluginConfirm(plugins: KytralPlugin[], request: ConfirmRequestInfo, timeoutMs: number): Promise<(RemoteVerdict & { plugin: string }) | null> {
  for (const p of plugins) {
    if (!p.confirm) continue;
    let timer: NodeJS.Timeout | undefined;
    const answer = await Promise.race([
      Promise.resolve().then(() => p.confirm!(request)).catch(() => null),
      // referenced on purpose: with an unref'd timer, a plugin that never settles lets the event loop drain and the process
      // exit before the answer is written (most agents then run the tool)
      new Promise<null>(r => { timer = setTimeout(() => r(null), timeoutMs); }),
    ]);
    clearTimeout(timer);
    if (answer && (answer.verdict === "allow" || answer.verdict === "deny")) return { ...answer, plugin: p.name };
  }
  return null;
}
/** Calls a notification hook of every plugin, swallowing their errors (a notification never changes a decision). */
export function notifyPlugins<K extends "onAudit" | "onDecision">(plugins: KytralPlugin[], hook: K, arg: Parameters<NonNullable<KytralPlugin[K]>>[0]): void {
  for (const p of plugins) { try { (p[hook] as ((a: unknown) => void) | undefined)?.(arg); } catch {} }
}
/** Flushes every plugin, waiting at most `timeoutMs` in total. */
export async function flushPlugins(plugins: KytralPlugin[], timeoutMs = 2000): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  await Promise.race([Promise.allSettled(plugins.map(p => { try { return p.flush?.(); } catch { return undefined; } })), new Promise(r => { timer = setTimeout(r, timeoutMs); })]);
  clearTimeout(timer);
}
