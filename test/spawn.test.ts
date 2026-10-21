// Starting the wrapped MCP server: the guard's secrets stay out of its environment, and on Windows `npx` and other .cmd
// shims start through cmd.exe with every argument intact (Node refuses to start them directly).
import { test } from "node:test"; import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs"; import { tmpdir } from "node:os"; import { join } from "node:path";
import { cmdArg, resolveWindowsCommand, serverCommand, serverEnv } from "../src/spawn.js";

test("the wrapped server never gets the guard's secret or the agent's badge", () => {
  const env = serverEnv({ KYTRAL_SECRET: "s", kytral_audit_secret: "a", KYTRAL_BADGE: "b", KYTRAL_HOME: "/h", KYTRAL_AUDIENCE: "kytral-guard:x", PATH: "/bin", DATABASE_URL: "postgres://x" });
  assert.deepEqual(env, { KYTRAL_HOME: "/h", KYTRAL_AUDIENCE: "kytral-guard:x", PATH: "/bin", DATABASE_URL: "postgres://x" });
});

test("on POSIX the server command runs as given", () => {
  assert.deepEqual(serverCommand("npx", ["-y", "a b"], {}, "linux"), { file: "npx", args: ["-y", "a b"], verbatim: false });
});

test("cmd.exe escaping quotes the argument, then escapes every metacharacter", () => {
  assert.equal(cmdArg("a b"), '^"a^ b^"');
  assert.equal(cmdArg('say "hi"'), '^"say^ \\^"hi\\^"^"');
  assert.equal(cmdArg("x&y", true), '^^^"x^^^&y^^^"');
  assert.equal(cmdArg("dir\\"), '^"dir\\\\^"');
});

test("a command is found through PATH whatever the case of the variable's name, as on Windows; of several spellings, the one Node gives the program it starts", () => {
  const a = mkdtempSync(join(tmpdir(), "kg-path-")), b = mkdtempSync(join(tmpdir(), "kg-path-"));
  for (const d of [a, b]) writeFileSync(join(d, "fake-tool.cmd"), "");
  const found = (env: NodeJS.ProcessEnv) => resolveWindowsCommand("fake-tool", { PATHEXT: ".cmd", ...env });
  for (const name of ["PATH", "Path", "path"]) assert.equal(found({ [name]: a }), join(a, "fake-tool.cmd"), name);
  // the first in sorted order ("PATH", "Path", "path"), whatever the order of the keys
  assert.equal(found({ Path: a, PATH: b }), join(b, "fake-tool.cmd"));
  assert.equal(found({ PATH: b, Path: a }), join(b, "fake-tool.cmd"));
  assert.equal(found({ path: b, Path: a }), join(a, "fake-tool.cmd"));
  assert.equal(found({ Path: a, PATH: undefined }), undefined, "PATH, first, undefined: no PATH, as the program started gets none");
  assert.equal(found({}), undefined);
});

test("on Windows, cmd.exe is given the path of the .cmd shim found, quoted, not its name to look up again; a path holding % or ! (expanded even inside quotes) is given by its name", () => {
  const dir = mkdtempSync(join(tmpdir(), "kg spawn & (x) ")), odd = mkdtempSync(join(tmpdir(), "kg %PATH%! "));
  for (const d of [dir, odd]) writeFileSync(join(d, "fake-tool.cmd"), "");
  const run = (d: string) => serverCommand("fake-tool", ["a b"], { PATH: d, PATHEXT: ".cmd" }, "win32");
  const shim = join(dir, "fake-tool.cmd").replace(/\//g, "\\");
  assert.deepEqual(run(dir), { file: "cmd.exe", args: ["/d", "/s", "/c", `""${shim}" ^^^"a^^^ b^^^""`], verbatim: true });
  assert.deepEqual(run(odd).args, ["/d", "/s", "/c", '"fake-tool ^^^"a^^^ b^^^""']);
});

const ARGS = ["plain", "two words", 'quote"inside', "amp&er", "pipe|x", "caret^x", "lt<gt>", "trailing\\", "percent%PATH%", "excl!x",
  "(paren)", "semi;colon", "comma,x", "", "  spaced  ", "postgresql://h/db?sslmode=require&x=1", "C:\\Program Files\\x"];

test("Windows: a .cmd shim found through PATH gets every argument intact, like npx", { skip: process.platform !== "win32" && "Windows only" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "kg spawn ")), bin = join(dir, "node_modules", ".bin");
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(dir, "echo.js"), "console.log(JSON.stringify(process.argv.slice(2)))");
  // like npm's shims: the .cmd passes its arguments on to node
  const shim = `@"${process.execPath}" "${join(dir, "echo.js")}" %*\r\n`;
  writeFileSync(join(dir, "fake-npx.cmd"), shim); writeFileSync(join(bin, "fake-tool.cmd"), shim);
  // a copy of process.env keeps the name Windows gives the variable ("Path"): it is replaced, whatever its case
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => k.toUpperCase() !== "PATH")),
    PATH: `${dir};${bin};${process.env.PATH ?? ""}`, PATHEXT: ".COM;.EXE;.BAT;.CMD" };
  assert.equal(resolveWindowsCommand("fake-npx", env)?.toLowerCase(), join(dir, "fake-npx.cmd").toLowerCase());
  for (const name of ["fake-npx", "fake-tool"]) {
    const run = serverCommand(name, ARGS, env, "win32");
    assert.equal(run.verbatim, true);
    const r = spawnSync(run.file, run.args, { env, windowsVerbatimArguments: true, encoding: "utf8" });
    assert.deepEqual(JSON.parse(r.stdout), ARGS, `${name}: ${r.stderr}`);
  }
  // a program starts directly
  assert.deepEqual(serverCommand("node", ["-v"], env, "win32").verbatim, false);
  // and the real npx (a .cmd next to node.exe)
  if (resolveWindowsCommand("npx")) {
    const run = serverCommand("npx", ["--version"]);
    const r = spawnSync(run.file, run.args, { windowsVerbatimArguments: run.verbatim, encoding: "utf8" });
    assert.match(r.stdout, /^\d+\.\d+/, r.stderr);
  }
});
