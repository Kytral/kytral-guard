// Bundles the CLI into one file and each worker thread into one file: agents start the CLI for every guarded tool call, and
// loading one file instead of a module graph cuts its start-up time by about a quarter. dist/cli.js (replacing tsc's) is the
// small entry point that starts the analysis thread first, then loads the CLI bundle, dist/cli-main.js. The SQL parser stays
// external: it is loaded lazily, one dialect at a time, from node_modules. The library entry (dist/index.js) is left as tsc
// emits it.
import { build } from "esbuild";
import { cpSync, readFileSync, rmSync } from "node:fs";

// The worker threads too (analysis with a deadline, SQL parsing with a deadline, the dashboard's audit log check): a worker
// starts with its own module graph.
await build({
  entryPoints: { cli: "src/cli-entry.ts", "cli-main": "src/cli.ts", "analysis-worker": "src/analysis-worker.ts", "evaluate-worker": "src/evaluate-worker.ts", "sql-worker": "src/sql-worker.ts", "audit-worker": "src/audit-worker.ts" },
  outdir: "dist", bundle: true, platform: "node", format: "esm", target: "node22",
  external: ["node-sql-parser", "node-sql-parser/*"],
  // CommonJS dependencies (yaml, shell-quote) call require(): give the ESM bundle one.
  banner: { js: "import { createRequire as __kytralCreateRequire } from 'node:module'; const require = __kytralCreateRequire(import.meta.url);" },
  legalComments: "none", logLevel: "warning",
});
// tsc's copy of the entry point: dist/cli.js is the bundle above
for (const f of ["dist/cli-entry.js", "dist/cli-entry.d.ts"]) rmSync(f, { force: true });
const head = readFileSync("dist/cli.js", "utf8").slice(0, 120);
if (!head.startsWith("#!/usr/bin/env node")) throw new Error(`dist/cli.js must start with its shebang, got: ${head.split("\n")[0]}`);
// The dashboard's page (HTML, script, style, logo, fonts), served by `kytral-guard dashboard` from dist/dashboard
cpSync("src/dashboard", "dist/dashboard", { recursive: true });
