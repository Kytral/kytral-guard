// Cross-platform `npm test` (the former script, `KYTRAL_HOME=$(mktemp -d) KYTRAL_AUDIENCE=kytral-guard:test node --import tsx
// --test test/*.test.ts`, needed a POSIX shell): fresh KYTRAL_HOME, fixed test audience, every test/*.test.ts in sorted order.
// Extra arguments are forwarded: options (use the --opt=value form) go to node, file paths replace the default file list.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const extra = process.argv.slice(2);
const picked = extra.filter(a => !a.startsWith("-"));
const files = picked.length ? picked : readdirSync(join(root, "test")).filter(f => f.endsWith(".test.ts")).sort().map(f => join("test", f));
const home = mkdtempSync(join(tmpdir(), "kytral-test-"));
const r = spawnSync(process.execPath, ["--import", "tsx", "--test", ...extra.filter(a => a.startsWith("-")), ...files],
  { cwd: root, stdio: "inherit", env: { ...process.env, KYTRAL_HOME: home, KYTRAL_AUDIENCE: "kytral-guard:test" } });
try { rmSync(home, { recursive: true, force: true }); } catch {}
process.exit(r.status ?? 1);
