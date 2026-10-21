// evaluate() with a deadline, synchronously, for the MCP proxy and the SDK (Guard.checkSync): the analysis runs in a
// worker thread (started on first use, then reused) while the calling thread waits on a shared flag, as SQL parsing does
// (sql-bounded.ts). Size is not a measure of cost: a few hundred characters can make an analysis use gigabytes, and a few
// dozen kilobytes can keep a regular expression busy for minutes; an analysis that does not answer within
// KYTRAL_ANALYSIS_TIMEOUT_MS (default 8 s, 2 s more for the first one, which also starts the worker), or that runs out of
// memory, is abandoned: the worker is stopped and the call needs a human (rule analysis-limit). Calls over 2 MB are not
// analyzed. Agent hooks bound their own analysis (evaluateBounded in hooks.ts).
import { MessageChannel, receiveMessageOnPort, Worker, type MessagePort } from "node:worker_threads";
import type { Decision, Policy, ToolCall } from "./policy.js";

/** Arguments larger than this are not analyzed: a human confirms. */
export const MAX_ANALYSIS_BYTES = 2 * 1024 * 1024;
export function argsSize(args: Record<string, unknown>): number { try { return JSON.stringify(args).length; } catch { return Infinity; } }
const limit = (what: string): Decision => ({ action: "confirm", rule: "analysis-limit", reason: `matched rule 'analysis-limit': ${what}` });

/**
 * The node options of a worker thread: undefined (inherited, as usual) unless the process runs code given with `node -e`
 * or `node -p`, which a worker would inherit and run instead of its own file (it would never answer): then the parent's
 * options without that code and the --input-type that goes with it. (Given explicitly, process-wide options are refused,
 * so they are only passed when they must be.)
 */
export function workerExecArgv(argv: string[] = process.execArgv): string[] | undefined {
  if (!argv.some(a => /^(-e|--eval|-p|--print|--input-type)(=|$)/.test(a))) return undefined;
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-e" || a === "--eval" || a === "-p" || a === "--print" || a === "--input-type") { i++; continue; }
    if (/^--(eval|print|input-type)=/.test(a)) continue;
    out.push(a);
  }
  return out;
}

interface EvalWorker { worker: Worker; port: MessagePort; flag: Int32Array; warm: boolean }
let current: EvalWorker | undefined;
let seq = 0;
const workerUrl = () => new URL(import.meta.url.endsWith(".ts") ? "./evaluate-worker.ts" : "./evaluate-worker.js", import.meta.url);

function start(): EvalWorker {
  const { port1, port2 } = new MessageChannel();
  const flag = new Int32Array(new SharedArrayBuffer(4));
  const worker = new Worker(workerUrl(), { workerData: { port: port2, flag }, transferList: [port2], execArgv: workerExecArgv(), resourceLimits: { maxOldGenerationSizeMb: 512 } });
  worker.on("error", () => { if (current?.worker === worker) current = undefined; });   // out of memory: the wait below times out
  worker.unref(); port1.unref();
  return { worker, port: port1, flag, warm: false };
}
/** Starts the worker ahead of the first call (the MCP proxy, when it starts): its start-up then costs no call anything. */
export function prewarmEvaluate(): void { try { current ??= start(); } catch { /* started (or refused) at the first call */ } }
/** Stops the worker (it is started again for the next call). */
export function stopEvaluateWorker(): void { if (current) { void current.worker.terminate(); current = undefined; } }

/** The policy's decision, or analysis-limit (confirm) when the call is too large, or not analyzed in time or memory. */
export function evaluateSyncBounded(policy: Policy, call: ToolCall): Decision {
  const size = argsSize(call.args);
  if (size > MAX_ANALYSIS_BYTES) return limit(`the call is too large to analyze (${Math.round(size / 1024)} KB)`);
  let w: EvalWorker;
  try { w = current ??= start(); } catch (e) { return limit(`the analysis could not start (${(e as Error).message})`); }
  const timeout = Number(process.env.KYTRAL_ANALYSIS_TIMEOUT_MS) || 8000, id = ++seq, deadline = Date.now() + (w.warm ? timeout : timeout + 2000);
  Atomics.store(w.flag, 0, 0);
  try { w.port.postMessage({ id, policy, call }); } catch (e) { return limit(`the call could not be handed to the analysis (${(e as Error).message})`); }
  for (;;) {
    const m = receiveMessageOnPort(w.port)?.message as { id: number; d?: Decision; error?: string } | undefined;
    if (m?.id === id) { w.warm = true; return m.d ?? limit(`the analysis failed (${m.error ?? "no answer"})`); }
    const left = deadline - Date.now();
    if (left <= 0 || Atomics.wait(w.flag, 0, 0, left) === "timed-out") {
      stopEvaluateWorker();
      return limit(`the call could not be analyzed within ${Math.round(timeout / 1000)} s (${Math.round(size / 1024)} KB)`);
    }
  }
}
