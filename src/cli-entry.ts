#!/usr/bin/env node
// The `kytral-guard` command (dist/cli.js). Agents start it for every guarded tool call: for `hook`, the analysis thread is
// started before anything else, so that its start-up overlaps loading the CLI (one bundle, dist/cli-main.js) and reading
// the event; evaluateBounded then uses it (see prewarmAnalysis in hooks.ts). It does not keep the process alive.
import { Worker } from "node:worker_threads";

const KEY = Symbol.for("kytral-guard.analysis-worker");
if (process.argv[2] === "hook") {
  try {
    // the limits of evaluateBounded's own threads (hooks.ts)
    const w = new Worker(new URL("./analysis-worker.js", import.meta.url), { workerData: null, resourceLimits: { maxOldGenerationSizeMb: 512 } });
    const drop = () => { if ((globalThis as Record<symbol, unknown>)[KEY] === w) delete (globalThis as Record<symbol, unknown>)[KEY]; };
    w.unref(); w.once("error", drop); w.once("exit", drop);
    (globalThis as Record<symbol, unknown>)[KEY] = w;
  } catch { /* the hook starts its own thread */ }
}
await import(new URL("./cli-main.js", import.meta.url).href);
