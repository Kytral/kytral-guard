// The policy files a person edits: the hooks' ($KYTRAL_POLICY, else $KYTRAL_HOME/policy.yaml) and the one the MCP proxy
// reads when `kytral-guard mcp wrap` gave it no other ($KYTRAL_HOME/mcp-policy.yaml). Edits keep the file's comments and
// layout, are checked before they are written (an invalid policy is never written), and replace the file atomically under
// its lock. Used by `kytral-guard allow` and by the dashboard.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { Document, isMap, isSeq, YAMLMap, YAMLSeq } from "yaml";
import { Action, loadPolicy, Policy } from "./policy.js";
import { parseDocumentQuietly } from "./quiet-yaml.js";
import { renameReplace, statePath, withFileLock } from "./store.js";

export const POLICY_TEMPLATE = `# Kytral Guard policy for coding agents (used by 'kytral-guard hook').
# Built on the coding-agent preset: your rules come first, then the preset's.
# Reference: https://github.com/Kytral/kytral-guard/blob/main/docs/policy.md
extends: coding-agent
rules: []
# Examples:
#  - name: protect-production-db
#    argMatches: 'prod-db\\.internal|DATABASE_URL_PROD'
#    action: block
#  - name: allow-local-db-reset
#    argMatches: '^supabase db reset$'
#    action: allow
`;
export const MCP_POLICY_TEMPLATE = `# Kytral Guard policy for the MCP servers of AI apps (servers wrapped by 'kytral-guard mcp wrap').
# Built on the strict preset: your rules come first, then the preset's. An app reads it when it starts its servers.
# Reference: https://github.com/Kytral/kytral-guard/blob/main/docs/policy.md
extends: strict
rules: []
`;
export class PolicyFileError extends Error {}

function ensure(file: string, template: string): string {
  if (!existsSync(file)) {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    try { writeFileSync(file, template, { mode: 0o600, flag: "wx" }); } catch (e: any) { if (e.code !== "EEXIST") throw e; }
  }
  return file;
}
/** The policy file the hooks read ($KYTRAL_POLICY, else $KYTRAL_HOME/policy.yaml), created from the template when missing. */
export function hookPolicyFile(explicit?: string): string {
  return ensure(explicit ?? process.env.KYTRAL_POLICY ?? statePath(undefined, "policy.yaml"), POLICY_TEMPLATE);
}
/** The policy of the MCP proxies started without --policy or --preset. */
export const mcpPolicyPath = () => statePath(undefined, "mcp-policy.yaml");
/** mcpPolicyPath(), created from its template (extends the strict preset) when missing. */
export const mcpPolicyFile = () => ensure(mcpPolicyPath(), MCP_POLICY_TEMPLATE);

/** Rewrites a policy file with one change, keeping its comments. Throws PolicyFileError, and writes nothing, if the result is invalid. */
export function editPolicy(file: string, change: (doc: Document) => void): Policy {
  return withFileLock(file, () => {
    const doc = parseDocumentQuietly(readFileSync(file, "utf8"));
    if (doc.errors.length) throw new PolicyFileError(`${file}: ${doc.errors[0].message}`);
    change(doc);
    const text = doc.toString({ lineWidth: 0 });
    let policy: Policy;
    try { policy = loadPolicy(text); } catch (e) { throw new PolicyFileError(`the policy would become invalid (${(e as Error).message}): ${file} is unchanged`); }
    const tmp = `${file}.${process.pid}.tmp`;
    writeFileSync(tmp, text, { mode: 0o600 });
    renameReplace(tmp, file);
    return policy;
  });
}
/** editPolicy on the list of rules (created when missing). */
export function editRules(file: string, change: (rules: YAMLSeq, doc: Document) => void): Policy {
  return editPolicy(file, doc => {
    let rules = doc.get("rules");
    if (!isSeq(rules)) { rules = doc.createNode([]); doc.set("rules", rules); }
    (rules as YAMLSeq).flow = false;
    change(rules as YAMLSeq, doc);
  });
}

/** What an exception does with its exact command: allow it, ask a human (confirm), or block it. */
export type ExceptionAction = Action;
const PREFIX: Record<ExceptionAction, string> = { allow: "allow", confirm: "ask", block: "block" };
const EXCEPTION_NAME = /^(allow|ask|block)-[0-9a-f]{8}$/;
/** Name of the exception rule for an exact command: allow-<hash>, ask-<hash> or block-<hash> (8 hex digits of its SHA-256). */
export const exceptionName = (command: string, action: ExceptionAction) => `${PREFIX[action]}-${createHash("sha256").update(command).digest("hex").slice(0, 8)}`;
export interface ExceptionRule {
  name: string; command: string; action: Action;
  /** An allowed command that runs even if it turns catastrophic (made with `kytral-guard allow --force`). */
  evenIfCatastrophic: boolean;
}
const ACTIONS: readonly string[] = ["allow", "confirm", "block"];
const isException = (r: unknown): r is YAMLMap => isMap(r) && typeof r.get("argEquals") === "string" && ACTIONS.includes(String(r.get("action")));
/** The rules of a policy file that match one exact text (`argEquals`): the exceptions of `allow` and of the dashboard, and hand-written ones. */
export function listExceptions(file: string): ExceptionRule[] {
  if (!existsSync(file)) return [];
  const rules = parseDocumentQuietly(readFileSync(file, "utf8")).get("rules");
  return (isSeq(rules) ? rules.items.filter(isException) : []).map(r => ({
    name: String(r.get("name")), command: String(r.get("argEquals")), action: r.get("action") as Action,
    evenIfCatastrophic: r.get("action") === "allow" && r.get("exceptCatastrophic") !== true,
  }));
}
/** The policy without the exceptions made for this exact command: what a new exception for it would go before. */
export function withoutExceptionsFor(policy: Policy, command: string): Policy {
  const c = command.trim();
  return { ...policy, rules: policy.rules.filter(r => !(EXCEPTION_NAME.test(r.name) && typeof r.argEquals === "string" && r.argEquals.trim() === c)) };
}
/**
 * Makes an exact command always allowed, asked or blocked: a rule on its exact text, first in the policy, that replaces the
 * other exceptions made for it. An allowed command stays blocked if it ever turns catastrophic (a script it runs was
 * changed) unless `evenIfCatastrophic` (`kytral-guard allow --force`). Returns the rule's name.
 */
export function addException(file: string, command: string, action: ExceptionAction, o: { evenIfCatastrophic?: boolean } = {}): string {
  const name = exceptionName(command, action);
  const rule = { name, argFields: ["command"], argEquals: command, ...(action === "allow" && !o.evenIfCatastrophic ? { exceptCatastrophic: true } : {}), action };
  editRules(file, (rules, doc) => {
    rules.items = rules.items.filter(r => !(isMap(r) && (r.get("name") === name || (EXCEPTION_NAME.test(String(r.get("name"))) && r.get("argEquals") === command))));
    rules.items.unshift(doc.createNode(rule));
  });
  return name;
}
/** Removes the rule with this name. False when there is none (nothing is written). */
export function removeRule(file: string, name: string): boolean {
  let found = false;
  if (!existsSync(file)) return false;
  editRules(file, rules => { rules.items = rules.items.filter(r => { const hit = isMap(r) && r.get("name") === name; found ||= hit; return !hit; }); });
  return found;
}

/** Sets the action of rules (the `overrides` map); null removes an override, and the rule's own action applies again. */
export function setOverrides(file: string, changes: Record<string, Action | null>): Policy {
  return editPolicy(file, doc => {
    let o = doc.get("overrides");
    if (!isMap(o)) { o = doc.createNode({}); doc.set("overrides", o); }
    for (const [rule, action] of Object.entries(changes)) {
      if (action === null) (o as YAMLMap).delete(rule); else (o as YAMLMap).set(rule, action);
    }
    if (!(o as YAMLMap).items.length) doc.delete("overrides");
  });
}
/** Sets a top-level field of a policy file (unknownTools...); null removes it, and the preset's value applies again. */
export function setPolicyField(file: string, field: "unknownTools", value: Action | null): Policy {
  return editPolicy(file, doc => { if (value === null) doc.delete(field); else doc.set(field, value); });
}
/** The policy of a file as it would be without its overrides and without the given top-level fields: the actions they change. */
export function basePolicy(file: string, without: string[] = []): Policy {
  const doc = parseDocumentQuietly(readFileSync(file, "utf8"));
  doc.delete("overrides"); for (const f of without) doc.delete(f);
  return loadPolicy(doc.toString({ lineWidth: 0 }));
}
