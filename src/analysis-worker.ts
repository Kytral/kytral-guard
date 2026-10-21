// Evaluates one call in a worker thread, so that an agent hook can stop an analysis that takes too long (see evaluateBounded).
// The call comes in workerData, or in the first message when the thread was started ahead of time (prewarmAnalysis).
import { parentPort, workerData } from "node:worker_threads";
import { evaluate, matchingRules, Policy, ToolCall } from "./policy.js";
import { useDirectSqlParsing } from "./sql-bounded.js";

useDirectSqlParsing();   // this whole thread is stopped at the hook's deadline: no second thread for SQL

// `all`: every rule that matches (matchingRules), for the dashboard's exceptions
const run = (d: { policy: Policy; call: ToolCall; all?: boolean }) => parentPort?.postMessage(d.all ? { all: matchingRules(d.policy, d.call) } : evaluate(d.policy, d.call));
if (workerData) run(workerData); else parentPort?.once("message", run);
