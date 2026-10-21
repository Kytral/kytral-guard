// Every YAML text this package reads (policies, presets, the MCP configuration files of the apps, the Taskfiles and
// pnpm-workspace.yaml files a command runs) goes through here, with nothing printed. The yaml package reports a warning (an
// unknown tag, a key that is a list, an unknown directive) with process.emitWarning, quoting the text at fault, and its parser
// writes every token on stdout when LOG_TOKENS or LOG_STREAM is set. Such a text may hold a secret, and stdout is the MCP
// channel in the proxy, a hook's answer to its agent, and the report doctor --report prints for a public issue.
import { parse, parseDocument } from "yaml";

/** Runs `f` with LOG_TOKENS and LOG_STREAM unset, then sets them back as they were: the programs started later still get them. */
function withoutYamlDebug<T>(f: () => T): T {
  const debug = ["LOG_TOKENS", "LOG_STREAM"].flatMap(k => process.env[k] === undefined ? [] : [[k, process.env[k]!] as const]);
  for (const [k] of debug) delete process.env[k];
  try { return f(); } finally { for (const [k, v] of debug) process.env[k] = v; }
}
/**
 * The text as YAML, with nothing printed: yaml's warnings quote it (an unknown tag, a key that is a list), and its parser writes every
 * token on stdout when LOG_TOKENS or LOG_STREAM is set. A policy may hold a secret, and the proxy's stdout is the MCP channel.
 */
export const parseQuietly = (text: string): unknown => withoutYamlDebug(() => parse(text, { logLevel: "error" }));
/** The text as a YAML document (its comments and layout kept, for an edit), with nothing printed: its errors are in `errors`, as always. */
export const parseDocumentQuietly = (text: string) => withoutYamlDebug(() => parseDocument(text, { logLevel: "error" }));
