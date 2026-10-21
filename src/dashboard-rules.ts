// The rules as the dashboard shows them: a name and examples for people, the group they belong to, and what the page may
// not do with them (a catastrophe is never allowed from the page; guard-tamper is always blocked). Two scopes: the coding
// agents (hooks, the coding-agent preset) and the MCP servers of AI apps (the proxy, the strict preset). Also the three
// protection levels of the Simple view: each sets the rules that are not locked; catastrophes stay blocked at every level.
import type { Action } from "./policy.js";

export type Scope = "agents" | "apps";
export type Level = "relaxed" | "balanced" | "strict";
export interface RuleInfo {
  id: string; name: string; examples: string; group: string;
  /** "catastrophic": irreversible; "covers": also covers catastrophes; "self": the guard's own protection. */
  tag?: "catastrophic" | "covers" | "self";
  /** "allow": the page cannot allow it (edit the policy file); "all": it stays block. */
  lock?: "allow" | "all";
}
/** The pseudo-rule of the apps scope that stands for the policy's `unknownTools` (tools a server did not declare). */
export const UNKNOWN_TOOL = "unknown-tool";

export const RULE_INFO: Record<Scope, RuleInfo[]> = {
  agents: [
    { group: "Shell commands", id: "shell-catastrophic", name: "Catastrophic commands", tag: "catastrophic", lock: "allow",
      examples: "rm -rf ~  ·  terraform destroy  ·  git push --force origin main  ·  kubectl delete namespace prod" },
    { group: "Shell commands", id: "shell-destructive", name: "Destructive commands", examples: "rm -rf src  ·  git reset --hard  ·  kubectl delete deployment api" },
    { group: "Shell commands", id: "shell-unresolved", name: "Commands the guard cannot see through", examples: "curl … | bash  ·  eval \"$CMD\"  ·  a script written by the same command" },
    { group: "Files", id: "sensitive-file-write", name: "Credential, system and startup files", tag: "catastrophic", lock: "allow",
      examples: "~/.ssh/authorized_keys  ·  /etc/hosts  ·  ~/.bashrc  ·  .git/hooks" },
    { group: "Databases", id: "sql-destructive", name: "Drop, empty or rewrite whole tables", tag: "catastrophic", lock: "allow",
      examples: "DROP TABLE users  ·  TRUNCATE orders  ·  DELETE FROM orders" },
    { group: "Databases", id: "sql-opaque", name: "SQL whose effect cannot be known in advance", examples: "CALL purge_old()  ·  DELETE FROM orders WHERE id = $1" },
    { group: "Databases", id: "sql-unparseable", name: "SQL the guard cannot parse", examples: "unknown dialects, cut statements" },
    { group: "MCP tools", id: "mcp-destructive-tool", name: "Tools that delete, reset or revoke", examples: "github · delete_repository  ·  linear · delete_issue" },
    { group: "MCP tools", id: "mcp-money", name: "Payments, transfers and refunds", examples: "stripe · create_refund  ·  stripe · create_payout" },
    { group: "MCP tools", id: "mcp-mass-message", name: "Messages to more than 20 recipients", examples: "gmail · send_email to 300 addresses" },
    { group: "Kytral Guard itself", id: "guard-tamper", name: "Turn off or weaken the guard", tag: "self", lock: "all",
      examples: "cat ~/.kytral/secret  ·  kytral-guard resume  ·  editing ~/.claude/settings.json  ·  npm uninstall -g kytral-guard" },
  ],
  apps: [
    { group: "Databases", id: "destructive-sql", name: "Drop or empty tables", tag: "catastrophic", lock: "allow", examples: "DROP TABLE users  ·  TRUNCATE orders  ·  DELETE FROM orders" },
    { group: "Databases", id: "sql-unrestricted-write", name: "Writes that do not pin rows", tag: "catastrophic", lock: "allow",
      examples: "UPDATE users SET plan = 'free'  ·  DELETE FROM orders WHERE 1 = 1" },
    { group: "Databases", id: "sql-opaque", name: "SQL whose effect cannot be known in advance", examples: "CALL purge_old()  ·  WHERE id = $1" },
    { group: "Databases", id: "sql-unparseable", name: "SQL the guard cannot parse", examples: "unknown dialects, cut statements" },
    { group: "Files and commands", id: "rm-rf", name: "Recursive rm", tag: "covers", lock: "allow", examples: "rm -rf build  ·  rm -r ~/notes" },
    { group: "Files and commands", id: "recursive-delete-other-commands", name: "Other recursive deletes", tag: "covers", lock: "allow",
      examples: "find . -delete  ·  rimraf  ·  Remove-Item -Recurse  ·  rd /s" },
    { group: "Files and commands", id: "sensitive-path", name: "Credential and system files", tag: "catastrophic", lock: "allow", examples: "~/.ssh  ·  /etc/passwd  ·  ~/.bashrc" },
    { group: "Files and commands", id: "shell-destructive", name: "Destructive commands", tag: "covers", lock: "allow", examples: "git reset --hard  ·  kubectl delete  ·  terraform destroy" },
    { group: "Files and commands", id: "shell-unresolved", name: "Commands the guard cannot see through", examples: "curl … | bash  ·  eval \"$CMD\"" },
    { group: "Files and commands", id: "shell-unparseable", name: "Commands the guard cannot parse", examples: "unbalanced quotes, unknown syntax" },
    { group: "Tools", id: "delete-files-or-backups", name: "Tools that delete, purge or reset", examples: "delete_file  ·  purge_backups  ·  reset_index" },
    { group: "Tools", id: "money-transfer", name: "Transfers, payouts and refunds", examples: "calls whose arguments mention a transfer, payout, wire or refund" },
    { group: "Tools", id: "mass-email", name: "Messages to more than 20 recipients", examples: "send_email to 300 addresses" },
    { group: "Tools", id: UNKNOWN_TOOL, name: "Tools the server did not declare", examples: "a tool missing from the server's own list" },
    { group: "Kytral Guard itself", id: "guard-tamper", name: "Turn off or weaken the guard", tag: "self", lock: "all",
      examples: "reading ~/.kytral/secret  ·  kytral-guard resume  ·  editing the app's MCP configuration" },
  ],
};
/** Can the page set this rule to this action? A reason when it cannot. */
export function lockReason(info: RuleInfo | undefined, action: Action): string | null {
  if (!info) return "this rule is not shown on the dashboard";
  if (info.lock === "all" && action !== "block") return "this rule keeps agents from turning the guard off: it stays Block";
  if (info.lock === "allow" && action === "allow") return "a catastrophe cannot be allowed from the dashboard: edit the policy file if you really mean it";
  return null;
}

/**
 * What keeps an exact command from always being `action`. An exception goes first in the policy, so it would win over every
 * rule that matches the command: "self" when one of them protects the guard (only Block), "catastrophic" when one blocks
 * a catastrophe or the policy blocks the command (Allow only from a terminal, with --force), else null. `matched`: the
 * rules that match the command, its own exceptions aside (matchingRules); `decided`: what that policy decides.
 */
export function exceptionLock(matched: readonly { rule?: string }[], decided: Action, action: Action): "self" | "catastrophic" | null {
  const locks = matched.map(d => RULE_INFO.agents.find(r => r.id === d.rule)?.lock);
  if (action !== "block" && locks.includes("all")) return "self";
  if (action === "allow" && (locks.includes("allow") || decided === "block")) return "catastrophic";
  return null;
}
/**
 * The terminal command that allows a blocked command anyway: by the number of its kept call, which needs no quoting, else
 * by its text in single quotes for a POSIX shell. Null on Windows without a number: no quoting is safe in both PowerShell
 * and cmd.exe for a text an agent wrote.
 */
export function forceAllowCommand(o: { seq?: number | null; command: string; windows: boolean }): string | null {
  if (o.seq != null) return `kytral-guard allow --force --call ${o.seq}`;
  return o.windows ? null : `kytral-guard allow --force '${o.command.replace(/'/g, "'\\''")}'`;
}

export const LEVEL_NAMES: Record<Level, string> = { relaxed: "Relaxed", balanced: "Balanced", strict: "Strict" };
/** The action each level gives the rules that are not locked (engine actions: confirm = ask a human). */
export const LEVELS: Record<Level, Record<Scope, Record<string, Action>>> = {
  relaxed: {
    agents: { "shell-destructive": "allow", "shell-unresolved": "allow", "sql-opaque": "allow", "sql-unparseable": "allow", "mcp-destructive-tool": "allow", "mcp-money": "confirm", "mcp-mass-message": "confirm" },
    apps: { "sql-opaque": "allow", "sql-unparseable": "allow", "shell-unresolved": "allow", "shell-unparseable": "allow", "delete-files-or-backups": "allow", "money-transfer": "confirm", "mass-email": "confirm", [UNKNOWN_TOOL]: "allow" },
  },
  balanced: {
    agents: { "shell-destructive": "confirm", "shell-unresolved": "confirm", "sql-opaque": "confirm", "sql-unparseable": "confirm", "mcp-destructive-tool": "confirm", "mcp-money": "confirm", "mcp-mass-message": "confirm" },
    apps: { "sql-opaque": "confirm", "sql-unparseable": "confirm", "shell-unresolved": "confirm", "shell-unparseable": "confirm", "delete-files-or-backups": "confirm", "money-transfer": "confirm", "mass-email": "confirm", [UNKNOWN_TOOL]: "confirm" },
  },
  strict: {
    agents: { "shell-destructive": "block", "shell-unresolved": "confirm", "sql-opaque": "confirm", "sql-unparseable": "confirm", "mcp-destructive-tool": "block", "mcp-money": "confirm", "mcp-mass-message": "confirm" },
    apps: { "sql-opaque": "confirm", "sql-unparseable": "confirm", "shell-unresolved": "confirm", "shell-unparseable": "confirm", "delete-files-or-backups": "block", "money-transfer": "confirm", "mass-email": "confirm", [UNKNOWN_TOOL]: "block" },
  },
};
