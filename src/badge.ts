import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { assertStrongSecret } from "./secret.js";
export interface Badge { agentId: string; tools: string[]; expiresAt: number; id: string; aud: string; iat: number; nonce: string; once?: boolean }
export interface IssueOptions { aud?: string; once?: boolean }
export interface VerifyOptions { audience?: string }
export const DEFAULT_AUDIENCE = "kytral-guard";
const b64 = (s: string) => Buffer.from(s).toString("base64url");
export function issueBadge(secret: string, agentId: string, tools: string[], ttlSeconds: number, now = Date.now(), opts: IssueOptions = {}): string {
  if (!secret) throw new Error("badge: empty secret refused");
  assertStrongSecret(secret);   // same rule as Guard, proxy and CLI
  const badge: Badge = { agentId, tools, expiresAt: now + ttlSeconds * 1000, id: randomBytes(8).toString("hex"),
    aud: opts.aud ?? process.env.KYTRAL_AUDIENCE ?? DEFAULT_AUDIENCE, iat: now, nonce: randomBytes(16).toString("hex"), ...(opts.once ? { once: true } : {}) };
  const body = b64(JSON.stringify(badge));
  return `${body}.${createHmac("sha256", secret).update(body).digest("base64url")}`;
}
export function verifyBadge(secret: string, token: string, revoked: { has(x: string): boolean }, now = Date.now(), opts: VerifyOptions = {}): Badge {
  if (!secret) throw new Error("badge: empty secret refused");
  assertStrongSecret(secret);
  const [body, sig, extra] = (token ?? "").split(".");
  if (!body || !sig || extra !== undefined) throw new Error("badge: malformed");
  const exp = createHmac("sha256", secret).update(body).digest();
  const got = Buffer.from(sig, "base64url");
  if (got.length !== exp.length || !timingSafeEqual(got, exp)) throw new Error("badge: bad signature");
  // one spelling per signature: the decoder skips characters outside base64url, so "ab&&c" read like "abc" and one
  // badge had many valid tokens (the claims, signed whole, could not change)
  if (got.toString("base64url") !== sig) throw new Error("badge: bad signature");
  const b = JSON.parse(Buffer.from(body, "base64url").toString()) as Badge;
  if (typeof b.expiresAt !== "number" || !(now <= b.expiresAt)) throw new Error("badge: expired");
  if (typeof b.aud !== "string" || !b.nonce) throw new Error("badge: missing aud/nonce (legacy badge, reissue it)");
  if (opts.audience !== undefined && b.aud !== opts.audience) throw new Error(`badge: wrong audience '${b.aud}'`);
  if (revoked.has(b.id) || revoked.has(b.agentId) || revoked.has(b.nonce)) throw new Error("badge: revoked");
  return b;
}
