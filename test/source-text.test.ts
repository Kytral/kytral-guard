// The project's own text files hold no raw control characters and none of the invisible ones that change how code
// reads (bidirectional overrides, zero-width characters): code that needs them writes them as \u escapes, so that what a
// reviewer sees is what runs.
import { test } from "node:test"; import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs"; import { extname, join, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const TEXT = new Set([".ts", ".js", ".mjs", ".cjs", ".json", ".md", ".yaml", ".yml", ".html", ".css", ".svg", ".txt", ".sh", ".ps1"]);
const SKIP = new Set(["node_modules", "dist", ".git", "coverage"]);
const HIDDEN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;

function* files(dir: string): Generator<string> {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* files(p);
    else if (TEXT.has(extname(e.name))) yield p;
  }
}

test("source files hold no raw control, bidirectional or zero-width characters", () => {
  const found: string[] = [];
  for (const f of files(ROOT)) {
    const lines = readFileSync(f, "utf8").split("\n");
    lines.forEach((line, i) => { const m = HIDDEN.exec(line); if (m) found.push(`${relative(ROOT, f)}:${i + 1} U+${m[0].charCodeAt(0).toString(16).padStart(4, "0")}`); });
  }
  assert.deepEqual(found, []);
});
