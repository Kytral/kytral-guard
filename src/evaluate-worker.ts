// Evaluates calls for another thread that waits with a deadline (see evaluate-bounded.ts): answers on the port, then wakes
// the waiting thread through the flag. SQL is parsed in this thread: the whole thread is stopped at the deadline.
import { workerData, type MessagePort } from "node:worker_threads";
import { evaluate, type Policy, type ToolCall } from "./policy.js";
import { useDirectSqlParsing } from "./sql-bounded.js";

useDirectSqlParsing();
const { port, flag } = workerData as { port: MessagePort; flag: Int32Array };
port.on("message", (m: { id: number; policy: Policy; call: ToolCall }) => {
  let out: { id: number; d?: unknown; error?: string };
  try { out = { id: m.id, d: evaluate(m.policy, m.call) }; } catch (e) { out = { id: m.id, error: (e as Error).message }; }
  port.postMessage(out);
  Atomics.store(flag, 0, 1); Atomics.notify(flag, 0);
});
