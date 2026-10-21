// Startup check: the HMAC secret signs every badge. Empty/short/low-variety secrets allow badge forgery.
import { randomBytes } from "node:crypto";
import { lstatSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { readRegular, statePath } from "./store.js";
const WEAK = ["changeme", "secret", "password", "test", "kytral", "example", "xxxx", "0000", "1234"];
export function assertStrongSecret(secret: string | undefined): string {
  // set but empty is refused, not read as unset: a deployment whose secret lookup failed must stop, not use another secret
  if (secret === "" && process.env.KYTRAL_SECRET === "")
    throw new Error("KYTRAL_SECRET is set but empty: give it a strong value (openssl rand -hex 32), or unset it to use $KYTRAL_HOME/secret ('kytral-guard init' creates it)");
  if (typeof secret !== "string" || !secret) throw new Error("KYTRAL_SECRET is missing or empty (set it, e.g. openssl rand -hex 32, or run 'kytral-guard init' to create $KYTRAL_HOME/secret)");
  if (secret !== secret.trim()) throw new Error("KYTRAL_SECRET has leading/trailing whitespace (copy/paste error?)");
  const core = secret.replace(/\s+/g, "");   // whitespace never counts toward length or variety
  if (Buffer.byteLength(core) < 32) throw new Error("KYTRAL_SECRET too short: at least 32 non-whitespace bytes required (openssl rand -hex 32)");
  if (new Set(core).size < 10) throw new Error("KYTRAL_SECRET too weak: not enough distinct characters");
  const low = core.toLowerCase();
  if (WEAK.some(w => low.includes(w) && low.replaceAll(w, "").length < 16)) throw new Error("KYTRAL_SECRET too weak: dictionary/placeholder value");
  return secret;
}

/** Each proxy must have its own audience so that a badge issued for one proxy cannot be replayed on another. */
export function assertAudience(aud: string | undefined): string {
  if (!aud || !aud.trim()) throw new Error("KYTRAL_AUDIENCE is missing: set a unique name per proxy (e.g. kytral-guard:crm-prod)");
  if (aud.trim() === "kytral-guard") throw new Error("KYTRAL_AUDIENCE must not be the shared default 'kytral-guard'");
  if (!/^[\w.:@\/-]{3,128}$/.test(aud)) throw new Error("KYTRAL_AUDIENCE: 3-128 chars among [A-Za-z0-9_.:@/-]");
  return aud;
}

/** Where the deployment secret lives when KYTRAL_SECRET is not set: $KYTRAL_SECRET_FILE, else $KYTRAL_HOME/secret (0600). */
export const secretFilePath = () => statePath(process.env.KYTRAL_SECRET_FILE, "secret");
/**
 * The deployment secret: KYTRAL_SECRET when set (even empty, which is then refused), else the secret file. With `create`, a
 * missing file is created with 32 random bytes (hex), owner-only. Not validated here: callers apply assertStrongSecret.
 * Keeping it in a file keeps it out of MCP and agent configuration files, which are often committed or shared.
 */
export function resolveSecret(opts: { create?: boolean } = {}): string | undefined {
  if (process.env.KYTRAL_SECRET !== undefined) return process.env.KYTRAL_SECRET;
  const p = secretFilePath();
  const read = () => {
    // the default location must be a plain file: a planted symbolic link would make the guard use a secret someone else knows
    if (!process.env.KYTRAL_SECRET_FILE && !lstatSync(p).isFile()) throw new Error(`${p} is not a regular file (a symbolic link?): refused`);
    return readRegular(p).toString("utf8").replace(/\r?\n$/, "");   // never waits: a FIFO at KYTRAL_SECRET_FILE is refused, not opened
  };
  const fresh = () => randomBytes(32).toString("hex") + "\n";
  try {
    const v = read();
    // `init` replaces an empty secret file: nothing can have been signed with an empty secret (it is always refused)
    if (opts.create && !v.trim()) { writeFileSync(p, fresh(), { mode: 0o600 }); return read(); }
    return v;
  } catch (e: any) { if (e?.code !== "ENOENT") throw e; }
  if (!opts.create) return undefined;
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  try { writeFileSync(p, fresh(), { mode: 0o600, flag: "wx" }); } catch (e: any) { if (e?.code !== "EEXIST") throw e; }
  return read();
}

/** KYTRAL_AUDIT_SECRET is optional, but when set it takes precedence for derived keys (allowlist): same strength rule. */
export function assertAuditSecret(v: string | undefined = process.env.KYTRAL_AUDIT_SECRET): string | undefined {
  if (v === undefined) return undefined;
  if (v === "") throw new Error("KYTRAL_AUDIT_SECRET is set but empty: give it a strong value (openssl rand -hex 32), or unset it to derive the audit keys from the deployment secret");
  try { return assertStrongSecret(v); } catch (e) { throw new Error((e as Error).message.replaceAll("KYTRAL_SECRET", "KYTRAL_AUDIT_SECRET")); }
}
