// Verifies the audit log in a worker thread, for the dashboard: a large log takes a while to read and check, and the page
// must keep answering meanwhile. Same verification as `kytral-guard audit verify`.
import { parentPort, workerData } from "node:worker_threads";
import { describeAudit, verifyAuditFile } from "./audit.js";

const { path, key } = workerData as { path: string; key: Uint8Array };
try {
  const r = verifyAuditFile(path, Buffer.from(key));
  parentPort!.postMessage({ exitCode: r.exitCode, lines: r.lines, text: describeAudit(r).slice(1).join(" ") });
} catch (e) {
  parentPort!.postMessage({ error: (e as Error).message });
}
