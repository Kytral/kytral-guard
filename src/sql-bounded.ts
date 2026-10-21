// SQL parsing with a deadline, synchronously: the parse runs in a worker thread (started on first use, then reused) while
// the calling thread waits on a shared flag. A parse that takes longer than KYTRAL_SQL_TIMEOUT_MS (default 2 s, 5 s for the
// first one, which also starts the worker) is abandoned: the worker is stopped and the text is "unparseable" (a human
// confirms). After a timeout, SQL is not parsed for 10 s (more of the same input would time out too).
import { MessageChannel, receiveMessageOnPort, Worker, type MessagePort } from "node:worker_threads";
import { parseVerdict, type SqlVerdict } from "./sql.js";
import { workerExecArgv } from "./evaluate-bounded.js";

interface SqlWorker { worker: Worker; port: MessagePort; flag: Int32Array; warm: boolean }
let current: SqlWorker | undefined;
let seq = 0, pausedUntil = 0, direct = false;
/** Parse in this thread from now on: for code that already runs under a deadline (the hook's analysis worker). */
export function useDirectSqlParsing(): void { direct = true; }
const workerUrl = () => new URL(import.meta.url.endsWith(".ts") ? "./sql-worker.ts" : "./sql-worker.js", import.meta.url);

function start(): SqlWorker {
  const { port1, port2 } = new MessageChannel();
  const flag = new Int32Array(new SharedArrayBuffer(4));
  const worker = new Worker(workerUrl(), { workerData: { port: port2, flag }, transferList: [port2], execArgv: workerExecArgv(), resourceLimits: { maxOldGenerationSizeMb: 256 } });
  worker.on("error", () => {});   // a parse that runs out of memory: the wait below times out
  worker.unref(); port1.unref();
  return { worker, port: port1, flag, warm: false };
}
/** Stops the worker (it is restarted on the next parse). */
export function stopSqlWorker(): void { if (current) { void current.worker.terminate(); current = undefined; } }

/** Without the parser: an unconditional DELETE/UPDATE is still an unrestricted write; the rest is unparseable. */
function fallback(text: string): SqlVerdict {
  return /^\s*(delete|update)\b/i.test(text) && !/\bwhere\b/i.test(text) ? "unrestricted-write" : "unparseable";
}
/** The parser's verdict, or the fallback when it does not answer in time. */
export function parseSqlBounded(text: string, dialect: string): SqlVerdict {
  if (direct) return parseVerdict(text, dialect);
  if (Date.now() < pausedUntil) return fallback(text);
  const w = current ??= start();
  const id = ++seq, deadline = Date.now() + (Number(process.env.KYTRAL_SQL_TIMEOUT_MS) || (w.warm ? 2000 : 5000));
  Atomics.store(w.flag, 0, 0);
  w.port.postMessage({ id, text, dialect });
  for (;;) {
    const m = receiveMessageOnPort(w.port)?.message as { id: number; v: SqlVerdict } | undefined;
    if (m?.id === id) { w.warm = true; return m.v; }
    const left = deadline - Date.now();
    if (left <= 0 || Atomics.wait(w.flag, 0, 0, left) === "timed-out") {
      stopSqlWorker();
      pausedUntil = Date.now() + 10_000;
      return fallback(text);
    }
  }
}
