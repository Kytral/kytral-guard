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
/**
 * PATH as Windows reads it, whatever the case of its name: process.env finds it so on Windows, but a copy of it keeps the
 * name Windows gives ("Path"), next to any other spelling added to the copy. Of several spellings, the first in sorted order
 * ("PATH", then "Path", then "path") counts, undefined too (no PATH then), as in Node's child_process: the program it starts
 * gets that one only.
 */
function windowsPath(env: NodeJS.ProcessEnv): string | undefined {
  const name = Object.keys(env).filter(k => k.toUpperCase() === "PATH").sort()[0];
  return name === undefined ? undefined : env[name];
}
/** The file a Windows command name runs: as given if it has a path or an extension, else the first PATH × PATHEXT match. */
export function resolveWindowsCommand(cmd: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const exts = (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean);
  const candidates = (base: string) => extname(base) ? [base, ...exts.map(e => base + e)] : exts.map(e => base + e);
  if (/[\\/]/.test(cmd) || isAbsolute(cmd)) return candidates(cmd).find(isFile);
  const dirs = [process.cwd(), ...(windowsPath(env) ?? "").split(delimiter).filter(Boolean)];
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
  // a program (.exe, .com) starts directly; anything else (a .cmd or .bat shim) through cmd.exe
  if (!file || /\.(exe|com)$/i.test(file)) return { file: file ?? cmd, args, verbatim: false };
  // cmd.exe is given the file found above, quoted, so that it does not look the name up a second time: inside quotes,
  // spaces and & | < > ^ ( ) are plain characters, and no Windows file name holds a quote. % (and ! with delayed
  // expansion) would be expanded even there: a path that holds one is given by its name, which cmd.exe finds
  const path = file.replace(/\//g, "\\");
  const head = /[%!"]/.test(path) ? cmd.replace(/\//g, "\\").replace(META, "^$1") : `"${path}"`;
  // shims (npx.cmd, pnpm.cmd, npm's node_modules/.bin and global shims) pass %* on to the program, which cmd.exe reads a
  // second time: escaped once, an argument holding a quote would end the quoting early and let & or | through
  const line = [head, ...args.map(a => cmdArg(a, true))].join(" ");
  return { file: env.ComSpec ?? env.COMSPEC ?? "cmd.exe", args: ["/d", "/s", "/c", `"${line}"`], verbatim: true };
}
export const commandExists = (cmd: string, env: NodeJS.ProcessEnv = process.env, platform = process.platform) =>
  platform === "win32" ? resolveWindowsCommand(cmd, env) !== undefined : (/[\\/]/.test(cmd) ? existsSync(cmd) : true);
