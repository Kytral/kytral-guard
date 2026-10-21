// Path classification for deletion and overwrite targets, shared by the shell, PowerShell and file-tool analyzers.
// A target is "broad" when deleting it recursively is catastrophic whatever the command (the filesystem root, a home
// directory, the current or parent directory, a top-level directory, a repository's .git, system and credential files);
// "cleanup" when it is a regenerable build or cache directory inside the project (node_modules, dist, .next...).

import { homedir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Sentinel the shell tokenizer substitutes for a variable it cannot resolve. */
export const VAR = "\u0001VAR\u0001";
export const unq = (p: string) => p.replace(/^['"]|['"]$/g, "");
export type Severity = "catastrophic" | "destructive";

/**
 * Kytral Guard's own state and code, the hook configurations that load it (every agent it supports, plus agents that read
 * the same formats), and the MCP configurations that route tools through its proxy: writing them disables or weakens the
 * guard.
 */
export function guardConfigPath(p0: string): boolean {
  const p = unq(p0).replace(/\\/g, "/");
  return /(^|\/)\.kytral(\/|$)/i.test(p) || STATE_VAR.test(p) || underStateDir(p)
    // the guard's own code: an installed copy (npm, nvm, Windows AppData...) and the one running now
    || /(^|\/)node_modules\/(kytral-guard|@kytral\/[^\/]+)(\/|$)/i.test(p) || underOwnCode(p)
    // agent hook configurations
    || /(^|\/)\.claude\/(settings(\.local)?|managed-settings)\.json$/i.test(p) || /(^|\/)(Library\/Application Support\/ClaudeCode|ClaudeCode|claude-code)\/managed-settings\.json$/i.test(p)
    || /(^|\/)\.claude\.json$/i.test(p) || /(^|\/)\.cursor\/(hooks|cli)\.json$/i.test(p) || /(^|\/)(etc\/cursor|Cursor)\/hooks\.json$/i.test(p)
    || /(^|\/)\.codex\/(hooks\.json|config\.toml|requirements\.toml)$/i.test(p) || /(^|\/)\.gemini\/settings\.json$/i.test(p) || /(^|\/)etc\/gemini-cli\/settings\.json$/i.test(p)
    || /(^|\/)\.copilot\/hooks(\/|$)/i.test(p) || /(^|\/)\.github\/hooks(\/|$)/i.test(p)
    || /(^|\/)\.codeium\/windsurf\/(hooks|mcp_config)\.json$/i.test(p) || /(^|\/)\.windsurf\/hooks\.json$/i.test(p) || /(^|\/)\.devin\/(hooks[\w.]*|config(\.local)?)\.json$/i.test(p)
    // Grok Build: hook files, the hook directories registry, and the settings that turn hooks or their compatibility sources off
    || /(^|\/)\.grok\/(hooks(\/|$)|hooks-paths|((managed_)?config|requirements|sandbox)\.toml$)/i.test(p) || /(^|\/)etc\/grok\/(managed_config|requirements)\.toml$/i.test(p)
    // Kimi Code, TRAE (and TRAE CN, TRAE CLI), opencode and MiMo Code: hook files, plugin folders, configuration
    || /(^|\/)\.kimi(-code)?\/config\.toml$/i.test(p) || /(^|\/)\.trae(-cn)?\/(cli\/)?hooks\.json$/i.test(p)
    || /(^|\/)\.(iflow|qoder|codebuddy)\/settings(\.local)?\.json$/i.test(p)
    // Devin CLI's user configuration, Amp's plugins, Cline's hook folders
    || /(^|\/)(\.config|AppData\/Roaming)\/devin\/config\.json$/i.test(p) || /(^|\/)\.config\/amp\/plugins(\/|$)/i.test(p)
    || /(^|\/)Documents\/Cline\/Hooks(\/|$)/i.test(p) || /(^|\/)\.clinerules\/hooks(\/|$)/i.test(p)
    || /(^|\/)\.(config\/)?(opencode|mimocode)\/(plugins?|hooks?)(\/|$)/i.test(p) || /(^|\/)(opencode|mimocode)\.jsonc?$/i.test(p)
    || /(^|\/)\.(kiro|amp|factory|qwen|augment|junie|agents|opencode|kilo|cline)\/(hooks|plugins?|settings|config)[\w.-]*(\.json)?(\/|$)/i.test(p)
    // MCP server configurations (removing the proxy wrapper takes the guard off those tools)
    || /(^|\/)\.mcp\.json$/i.test(p) || /(^|\/)\.(cursor|vscode|roo|kiro|amazonq)\/mcp\.json$/i.test(p) || /(^|\/)claude_desktop_config\.json$/i.test(p)
    || /(^|\/)(Code|Code - Insiders|VSCodium)\/User\/mcp\.json$/i.test(p) || /(^|\/)\.lmstudio\/mcp\.json$/i.test(p)
    || /(^|\/)globalStorage\/[^\/]+\/settings\/(cline_)?mcp_settings\.json$/i.test(p)
    || /(^|\/)\.continue\/config\.(json|yaml)$/i.test(p) || /(^|\/)\.continue\/mcpServers\//i.test(p);
}

/** $KYTRAL_HOME, ${KYTRAL_HOME}, %KYTRAL_HOME%, $env:KYTRAL_HOME (and the variables naming files in it), as a path. */
const STATE_VAR = /^(\$\{?|%|\$env:)KYTRAL_(HOME|AUDIT|POLICY|SECRET_FILE)\b\}?%?(\/|$)/i;
/** A path in a comparable form: forward slashes, drive letters as "c:/", Git Bash "/c/" too, ~ expanded, lower case. */
export function normPath(p: string): string {
  return p.replace(/\\/g, "/").replace(/^~(?=\/|$)/, homedir().replace(/\\/g, "/")).replace(/^\/([a-z])\//i, "$1:/").replace(/\/+$/, "").toLowerCase();
}
/**
 * The state directory when KYTRAL_HOME names a dedicated folder (not a root, not the home directory): writes under it are
 * guard tampering like writes under ~/.kytral.
 */
export function customStateDir(): string | undefined {
  const h = process.env.KYTRAL_HOME;
  if (!h) return undefined;
  const d = normPath(resolve(h));
  if (d.split("/").filter(Boolean).length < 2 || d === normPath(homedir())) return undefined;
  return d;
}
function underStateDir(p: string): boolean {
  const d = customStateDir();
  if (!d || !/^([\/~]|[A-Za-z]:)/.test(p)) return false;
  const q = normPath(p);
  return q === d || q.startsWith(d + "/");
}
/** The dist folder of the copy of Kytral Guard running now (a clone or a global install outside node_modules too). */
let ownCode: string | undefined;
function underOwnCode(p: string): boolean {
  if (!/^([\/~]|[A-Za-z]:)/.test(p)) return false;
  try { ownCode ??= normPath(fileURLToPath(new URL("../dist/", import.meta.url))); } catch { return false; }
  const q = normPath(p);
  return q === ownCode || q.startsWith(ownCode + "/");
}

/**
 * System, credential and guard-configuration paths (POSIX, macOS, Windows, Git Bash). Relative paths only match by file
 * name or by a credential directory (`.ssh/`, `.aws/`), never by a top-level name: a project's own `bin/`, `lib/` or `etc/`
 * folder is not the system's.
 */
export function sensitivePath(p0: string): boolean {
  const s = unq(p0).replace(/\\/g, "/");
  return /^\/(\*)?$/.test(s) || /^\/(etc|bin|sbin|usr|lib|lib32|lib64|boot|root|sys|proc|var\/lib|var\/spool\/cron)(\/|$)/.test(s)
    || /^\/dev\/(sd|nvme|hd|xvd|vd|mmcblk|disk|md|dm-|mapper|rdisk)/.test(s)
    || /^\/(System|Library|Applications|private\/(etc|var))(\/|$)/.test(s)
    || /^~\/?$/.test(s) || /(^|\/)\.(ssh|gnupg|aws|kube|azure|oci)(\/|$)/.test(s) || /(^|\/)\.docker\/config\.json$/.test(s)
    || /(^|\/)\.config\/(gcloud|gh|git|systemd|autostart)(\/|$)/.test(s) || /(^|\/)Library\/(Keychains|LaunchAgents|LaunchDaemons)(\/|$)/.test(s)
    || /(^|\/)(passwd|shadow|gshadow|sudoers|authorized_keys|known_hosts|crontab|fstab|hosts|\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|\.zprofile|\.zshenv|\.zlogin|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.git-credentials|\.env)$/.test(s)
    || /(^|\/)\.git\/(config|hooks|HEAD|refs)(\/|$)/.test(s)
    || /^[A-Za-z]:\/*$/.test(s) || /^[A-Za-z]:\/+(Windows|Program Files( \(x86\))?|ProgramData|Boot|Recovery|System Volume Information)(\/|$)/i.test(s)
    || /^\/[a-z]\/(Windows|Program Files( \(x86\))?|ProgramData)(\/|$)/i.test(s)
    || /(^|\/)AppData\/Roaming\/Microsoft\/Windows\/Start Menu\/Programs\/Startup(\/|$)/i.test(s)
    || guardConfigPath(s);
}

/**
 * A sensitivePath whose loss or overwrite is catastrophic: everything but files a project legitimately writes (`.env`,
 * a project `.npmrc` / `.pypirc`, an Ansible `hosts` inventory), which stay sensitive (destructive) without blocking work.
 */
export function criticalPath(p0: string): boolean {
  const p = unq(p0).replace(/\\/g, "/");
  if (/(^|\/)(\.env|\.npmrc|\.pypirc)$/.test(p) && !/^(~|\/(home|Users)\/[^\/]+|[A-Za-z]:\/Users\/[^\/]+)\/\.(npmrc|pypirc)$/i.test(p)) return false;
  if (/(^|\/)hosts$/.test(p) && !/^\/(private\/)?etc\/hosts$/.test(p) && !/\/drivers\/etc\/hosts$/i.test(p)) return false;
  return sensitivePath(p);
}

/** The path with trailing slashes and a trailing "everything in it" glob removed: "/data/*" -> "/data", "~/" -> "~". */
function stem(p: string): string {
  let t = p;
  for (let k = 0; k < 4; k++) t = t.replace(/\/+(\*\*?|\.\*|\*\.\*|\{[^}]*\})?$/, "");
  return t;
}

/**
 * Catastrophic deletion target: deleting it recursively destroys a system, a home, a whole project or a repository's history.
 * Root, `~` (and `$HOME`, which the tokenizer turns into `~`), the current or parent directory (`.`, `..`, `*`, `./*`), a
 * top-level directory (`/data`, `/c`), a user's home (`/home/bob`, `C:/Users/bob`), an unresolved variable followed by a
 * slash and nothing else (`"$DIR/"*`, empty variable => `/*`), `.git`, and every sensitivePath.
 */
export function broadPath(p0: string): boolean {
  const p = unq(p0).replace(/\\/g, "/");
  if (!p) return false;
  if (/^[*.?\/{},\[\]!]+$/.test(p)) return true;                         // /, /*, ., .., *, ./*, .*, ../.., **
  const s = stem(p);
  if (s === "" || s === "~" || /^~[\w.-]*$/.test(s)) return true;          // root after stem, ~, ~user
  if (/^\u0001VAR\u0001([\w.-]*\u0001)?\/[*.?\/]*$/.test(p)) return true; // "$DIR/", "$DIR/*", "$(cmd)/*": empty expansion => root
  if (/^\/+[^\/]+$/.test(s)) return true;                                  // /data, /home, /srv, /c (Git Bash drive)
  if (/^\/+(home|Users)\/+[^\/]+$/.test(s)) return true;                    // /home/bob, /Users/bob
  // The folders of a home that hold a person's work: ~/projects, ~/Documents, C:\Users\bob\source\repos
  if (/^(~[\w.-]*|\/+(home|Users)\/+[^\/]+|[A-Za-z]:\/+Users\/+[^\/]+|\/[a-z]\/Users\/+[^\/]+)\/+(Documents|Desktop|Downloads|Pictures|Music|Videos|Movies|Library|OneDrive[^\/]*|Dropbox|Google Drive|iCloud Drive|projects?|Projects?|src|code|Code|dev|Dev|Development|workspace|Workspace|work|repos|Repos|git|GitHub|source)(\/+(repos|projects|code))?$/i.test(s)) return true;
  if (/^[A-Za-z]:\/*$/.test(s) || /^(\/[a-z]|[A-Za-z]:)\/+(Users|Documents and Settings)(\/+[^\/]+)?$/i.test(s)) return true;
  if (/(^|\/)\.git$/.test(s)) return true;                                 // the repository's history
  if (/^\.{1,2}(\/\.{1,2})*$/.test(s)) return true;                        // ./.. and friends
  return criticalPath(p) || criticalPath(s);
}

/** Regenerable build output, dependency and cache directories: deleting them is routine (they are rebuilt or reinstalled). */
const CLEANUP = new Set(["node_modules", "dist", "build", "out", "target", ".next", ".nuxt", ".output", ".svelte-kit", ".turbo", ".cache",
  ".parcel-cache", ".vite", ".angular", ".expo", ".docusaurus", "storybook-static", "coverage", ".nyc_output", "__pycache__",
  ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox", ".venv", "venv", ".gradle", ".dart_tool", "cdk.out", ".serverless",
  ".terraform", ".eslintcache", "tmp", "temp", ".tmp", ".temp", ".wrangler", ".vercel", ".netlify", "htmlcov", ".hypothesis", "bower_components",
  ".sass-cache", "elm-stuff", ".stack-work", "_build", "deps", ".pnpm-store", ".yarn-cache"]);
/**
 * Names a recursive search may delete as routine cleanup, because tools write them again: find . -name '__pycache__'
 * -exec rm -rf {} +, Get-ChildItem -Recurse -Include *.pyc | Remove-Item (lowercase: PowerShell compares without case).
 */
export const CLEANUP_NAMES = new Set(["__pycache__", "*.pyc", "*.pyo", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".ipynb_checkpoints", ".ds_store",
  "thumbs.db", "node_modules", "*.orig", "*.rej", "*.tsbuildinfo", ".eslintcache"]);
/** Caches in the home folder that apps and tools fill again: ~/Library/Caches/<app>, Xcode's DerivedData, ~/.cache/<tool>, npm's and Gradle's. */
const HOME_CACHE = /^(~|\$HOME|\$\{HOME\})\/+(Library\/Caches\/[^\/*?]+|Library\/Developer\/Xcode\/DerivedData|\.cache\/[^\/*?]+|\.npm\/_cacache|\.gradle\/caches)(\/[^*?]*)?$/;
/** Dependency lockfiles: the package manager writes them again (rm -rf node_modules package-lock.json && npm install). */
const LOCKFILES = new Set(["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "Cargo.lock", "poetry.lock",
  "Pipfile.lock", "uv.lock", "composer.lock", "Gemfile.lock", "go.sum"]);
/**
 * A relative path inside the project whose last segment is a regenerable directory (`dist`, `./node_modules`, `packages/*\/dist`)
 * or a dependency lockfile, or a named entry under /tmp or /var/tmp (`/tmp/build-123`, not `/tmp` itself).
 */
export function cleanupPath(p0: string): boolean {
  const p = unq(p0).replace(/\\/g, "/");
  if (/^\/(var\/)?tmp\/+[^\/*?]+/.test(p) && !/(^|\/)\.\.(\/|$)/.test(p)) return true;
  if (HOME_CACHE.test(p) && !/(^|\/)\.\.(\/|$)/.test(p)) return true;
  if (!p || /^[\/~$]/.test(p) || p.includes(VAR) || /^[A-Za-z]:/.test(p) || /(^|\/)\.\.(\/|$)/.test(p)) return false;
  const last = stem(p.replace(/^(\.\/)+/, "")).split("/").pop() ?? "";
  return CLEANUP.has(last) || LOCKFILES.has(last) || /\.egg-info$/.test(last);
}

/**
 * Severity of deleting `targets`: recursive deletion of a broad target is catastrophic; of regenerable directories only,
 * harmless (null); of anything else, destructive. A single-file deletion is catastrophic on a sensitive path, destructive
 * when it empties a directory (`rm *`, `rm ~/*`), harmless otherwise.
 */
export function deletionSeverity(targets: string[], recursive: boolean): Severity | null {
  const ops = targets.filter(t => t !== "");
  if (!ops.length) return null;
  if (recursive) {
    if (ops.some(broadPath)) return "catastrophic";
    return ops.every(cleanupPath) ? null : "destructive";
  }
  if (ops.some(t => criticalPath(t))) return "catastrophic";
  if (ops.some(t => sensitivePath(t))) return "destructive";
  return ops.some(t => /^[~\/.]*\*[*.?\/]*$/.test(unq(t)) || /^\u0001VAR\u0001([\w.-]*\u0001)?\/\*$/.test(t)) ? "destructive" : null;
}
