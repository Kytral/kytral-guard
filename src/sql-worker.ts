// Parses SQL for another thread (see sql-bounded.ts): answers on the port, then wakes the thread waiting on the flag.
import { workerData, type MessagePort } from "node:worker_threads";
import { parseVerdict, type SqlVerdict } from "./sql.js";

const { port, flag } = workerData as { port: MessagePort; flag: Int32Array };
port.on("message", (m: { id: number; text: string; dialect: string }) => {
  let v: SqlVerdict;
  try { v = parseVerdict(m.text, m.dialect); } catch { v = "unparseable"; }
  port.postMessage({ id: m.id, v });
  Atomics.store(flag, 0, 1); Atomics.notify(flag, 0);
});
