// "Always allow" grants for unknown tools: $KYTRAL_KNOWN_TOOLS or $KYTRAL_HOME/known-tools.json.
// One HMAC-signed entry per exact (server, tool, agent) - never a pattern - recording who approved it and when, signed for
// that file only. Written under the inter-process lock (0600 temp file + atomic rename). A grant only cancels the unknown-tool
// confirmation: policy rules are evaluated first and always win. Removing a grant leaves a tombstone (anti-replay).
import { createHmac } from "node:crypto";
import { resolve } from "node:path";
import { deriveKey, FileSet, realFilePath, statePath } from "./store.js";

export interface KnownGrant { server: string; tool: string; agentId: string; approver: string; approvedAt: string }
export const knownKey = (server: string, tool: string, agentId: string) => JSON.stringify([server, tool, agentId]);
/**
 * Signing key of the grants of the file `file`: derived from KYTRAL_AUDIT_SECRET if set, else from the proxy secret
 * (KYTRAL_SECRET), domain-separated, then bound to the file's real path (realFilePath), as kill-switch.json's id is. A grant
 * signed for one file never verifies in another (copied from another KYTRAL_HOME using the same secret, or this one reached
 * through another path), and neither does one written by an older version, which signed none: it is rejected, and the tool is
 * confirmed again. Grants kept in memory (no file) are signed with the key alone.
 */
export function knownToolsKey(secret: string, file: string | null): Buffer {
  const key = deriveKey(process.env.KYTRAL_AUDIT_SECRET || secret, "known-tools/v1");
  return file === null ? key : createHmac("sha256", key).update(`known-tools/dep\n${realFilePath(resolve(file))}`).digest();
}
/** Why a grant is rejected when its signature does not verify (journaled, and said by `known list`). */
export const BAD_GRANT = "bad signature (forged, edited, or signed for another known-tools file: another KYTRAL_HOME, another path, or an older version)";
export const knownToolsPath = () => statePath(process.env.KYTRAL_KNOWN_TOOLS, "known-tools.json");
/** Tombstones of removed grants live next to the grants file: <name>.tombstones.json (known-tools.tombstones.json). */
export const tombstonePath = (knownPath: string | null) => knownPath === null ? null : knownPath.replace(/\.json$/, "") + ".tombstones.json";
/** "Always" is only offered for plain tool names: letters, digits, _ - . / (no glob or regex character, space, control or non-ASCII character). */
export const isPlainToolName = (tool: unknown): tool is string => typeof tool === "string" && /^[A-Za-z0-9_.\/-]{1,128}$/.test(tool);
/** Keeps a human-entered name printable and short (audit, `known list`). */
export const cleanName = (s: string) => s.replace(/[\x00-\x1f\x7f]/g, "?").trim().slice(0, 128);

/** Grant described by a verified entry, or null if its key is not an exact (server, plain tool name, agent). */
export function parseGrant(key: string, value: string | undefined): KnownGrant | null {
  if (value === undefined) return null;
  let server: unknown, tool: unknown, agentId: unknown;
  try { [server, tool, agentId] = JSON.parse(key); } catch { return null; }
  if (typeof server !== "string" || typeof agentId !== "string" || !isPlainToolName(tool)) return null;
  let meta: any = {}; try { meta = JSON.parse(value) ?? {}; } catch {}
  const text = (x: unknown) => (typeof x === "string" && x ? x : "unknown");
  return { server, tool, agentId, approver: text(meta.approver), approvedAt: text(meta.approvedAt) };
}
/**
 * Removes the grants of one tool: every agent and server unless narrowed (a revocation must not miss its target).
 * Anti-replay: each key gets a tombstone (removal time) before its removal - a crash in between leaves the grant refused -
 * and again after it, which also covers a grant added meanwhile. A restored backup of the grants file is then refused;
 * a later grant is dated after the tombstone and stays valid. An exact (server, tool, agent) is tombstoned even if absent.
 */
export function removeGrants(set: FileSet, tombstones: FileSet, tool: string, only: { agentId?: string; server?: string } = {}): [string, string, string][] {
  const match = (k: string) => {
    try { const [s, t, a] = JSON.parse(k); return t === tool && (only.server === undefined || s === only.server) && (only.agentId === undefined || a === only.agentId); }
    catch { return false; }
  };
  const exact = only.server !== undefined && only.agentId !== undefined ? [knownKey(only.server, tool, only.agentId)] : [];
  for (const k of new Set([...exact, ...set.entries().map(([k]) => k).filter(match)])) tombstones.add(k, String(Date.now()));
  const removed = set.removeWhere(match);
  for (const k of removed) tombstones.add(k, String(Date.now()));
  return removed.map(k => JSON.parse(k));
}
