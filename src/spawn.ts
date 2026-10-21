// Starting the MCP server the proxy wraps, the way its client would have started it. On Windows, a bare `npx`, `uvx` or
// `pnpm` is found through PATH and PATHEXT, and a .cmd / .bat file (npm's shims) runs through cmd.exe with every argument
// escaped for it: Node refuses to start such a file directly, and cmd.exe would read & | < > ^ % in an argument as its own.
// The server never sees the guard's secrets.
import { existsSync, statSync } from "node:fs";
import { delimiter, extname, isAbsolute, join } from "node:path";

/** Variables the proxy reads and the server must not get: the secret signs badges, approvals and kill switch states. */
const PRIVATE = /^KYTRAL_(SECRET|AUDIT_SECRET|BADGE)$/i;
/** The proxy's environment, minus the guard's secrets. */
export function serverEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(env).filter(([k]) => !PRIVATE.test(k)));
}

const isFile = (p: string) => { try { return statSync(p).isFile(); } catch { return false; } };
/** The file a Windows command name runs: as given if it has a path or an extension, else the first PATH × PATHEXT match. */
export function resolveWindowsCommand(cmd: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const exts = (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean);
  const candidates = (base: string) => extname(base) ? [base, ...exts.map(e => base + e)] : exts.map(e => base + e);
  if (/[\\/]/.test(cmd) || isAbsolute(cmd)) return candidates(cmd).find(isFile);
  const dirs = [process.cwd(), ...(env.Path ?? env.PATH ?? "").split(delimiter).filter(Boolean)];
  for (const d of dirs) { const hit = candidates(join(d, cmd)).find(isFile); if (hit) return hit; }
  return undefined;
}

// cmd.exe metacharacters, escaped with ^ (the scheme of the widely used cross-spawn package)
const META = /([()\][%!^"`<>&|;, *?])/g;
/** One argument for a program started through cmd.exe: quoted for the C runtime, then every metacharacter escaped for cmd.exe. */
export function cmdArg(arg: string, doubleEscape = false): string {
  let a = arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, "$1$1");
  a = `"${a}"`.replace(META, "^$1");
  return doubleEscape ? a.replace(META, "^$1") : a;
}

/** How to start `cmd args` on this platform: the file, its arguments, and whether they are already a verbatim command line. */
export function serverCommand(cmd: string, args: string[], env: NodeJS.ProcessEnv = process.env, platform = process.platform): { file: string; args: string[]; verbatim: boolean } {
  if (platform !== "win32") return { file: cmd, args, verbatim: false };
  const file = resolveWindowsCommand(cmd, env);
  // a program (.exe, .com) starts directly; anything else (a .cmd or .bat shim) through cmd.exe, which finds it as the client did
  if (!file || /\.(exe|com)$/i.test(file)) return { file: file ?? cmd, args, verbatim: false };
  // shims (npx.cmd, pnpm.cmd, npm's node_modules/.bin and global shims) pass %* on to the program, which cmd.exe reads a
  // second time: escaped once, an argument holding a quote would end the quoting early and let & or | through
  const line = [cmd.replace(/\//g, "\\").replace(META, "^$1"), ...args.map(a => cmdArg(a, true))].join(" ");
  return { file: env.ComSpec ?? env.COMSPEC ?? "cmd.exe", args: ["/d", "/s", "/c", `"${line}"`], verbatim: true };
}
export const commandExists = (cmd: string, env: NodeJS.ProcessEnv = process.env, platform = process.platform) =>
  platform === "win32" ? resolveWindowsCommand(cmd, env) !== undefined : (/[\\/]/.test(cmd) ? existsSync(cmd) : true);
