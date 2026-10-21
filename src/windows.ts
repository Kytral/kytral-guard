// PowerShell and cmd.exe analysis: Remove-Item -Recurse / rd /s / del /s on broad targets (also fed by Get-ChildItem through
// a pipeline), .NET file APIs, Invoke-Expression and Start-Process payloads, disk and volume commands, shadow copies and boot
// configuration, registry hives, cloud cmdlets, overwrites of system files. POSIX-style commands typed in PowerShell (git,
// terraform, kubectl...) are covered by the shell analyzer, which runs on the same text.
import { broadPath, CLEANUP_NAMES, cleanupPath, criticalPath, Severity, VAR } from "./paths.js";

export interface WindowsReport { destructive: string[]; unresolved: string[]; catastrophic: string[] }

/** Splits text into pipelines (; && || & newline) of stages (| and script blocks), outside quotes. */
function pipelines(text: string): string[][] {
  const out: string[][] = []; let stages: string[] = [], cur = "", q: string | null = null;
  const endStage = () => { if (cur.trim()) stages.push(cur.trim()); cur = ""; };
  const endPipe = () => { endStage(); if (stages.length) out.push(stages); stages = []; };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { cur += c; if (c === q) q = null; else if (c === "`" && q === '"') cur += text[++i] ?? ""; continue; }
    if (c === "'" || c === '"') { q = c; cur += c; continue; }
    if (c === "`") { cur += c + (text[++i] ?? ""); continue; }
    // {default}, {GUID}: an identifier (bcdedit), kept in its statement; any other brace opens or closes a script block
    const ident = c === "{" ? /^\{[\w-]+\}/.exec(text.slice(i)) : null;
    if (ident) { cur += ident[0]; i += ident[0].length - 1; continue; }
    if ((c === "|" || c === "&") && text[i + 1] === c) { endPipe(); i++; continue; }
    if (c === "|" || c === "{" || c === "}") { endStage(); continue; }   // a script block stays in its pipeline: gci | % { Remove-Item $_ }
    if (c === ";" || c === "&" || c === "\n" || c === "\r") { endPipe(); continue; }
    cur += c;
  }
  endPipe();
  return out;
}
/** PowerShell / cmd tokens: quotes removed ('' inside '...' is a quote), backtick escapes, backslashes kept (Windows paths). */
function tokens(stmt: string): string[] {
  const out: string[] = []; let cur = "", q: string | null = null, any = false;
  for (let i = 0; i < stmt.length; i++) {
    const c = stmt[i];
    if (q) {
      if (c === q) { if (q === "'" && stmt[i + 1] === "'") { cur += "'"; i++; } else q = null; continue; }
      if (c === "`" && q === '"') { cur += stmt[++i] ?? ""; continue; }
      cur += c; continue;
    }
    if (c === "'" || c === '"') { q = c; any = true; continue; }
    if (c === "`") { cur += stmt[++i] ?? ""; any = true; continue; }
    if (/\s/.test(c)) { if (cur || any) out.push(cur); cur = ""; any = false; continue; }
    cur += c; any = true;
  }
  if (cur || any) out.push(cur);
  return out;
}

const HOME = /^(~|\$HOME|\$env:USERPROFILE|\$env:HOMEPATH|\$env:HOMEDRIVE\$env:HOMEPATH|%USERPROFILE%|%HOMEPATH%|%HOMEDRIVE%%HOMEPATH%|\$env:APPDATA|\$env:LOCALAPPDATA|%APPDATA%|%LOCALAPPDATA%|\[Environment\]::GetFolderPath\(['"]?UserProfile['"]?\))$/i;
const SYSTEM = /^(\$env:(SystemRoot|windir|SystemDrive|ProgramFiles|ProgramFiles\(x86\)|ProgramData|ProgramW6432|CommonProgramFiles)|%(SystemRoot|windir|SystemDrive|ProgramFiles|ProgramFiles\(x86\)|ProgramData)%)$/i;
const CWD = /^(\.|\.\.|\*|\$PWD|\(Get-Location\)|\$\(Get-Location\)|\(pwd\)|\$\(pwd\)|\(gl\))$/i;
const HIVE_ROOT = /^(HKLM|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|HKEY_USERS)(:|\\|\/|$)/i;
/** Deleting it recursively is catastrophic: drive roots, homes, system folders, the current directory, registry hives. */
export function winBroad(t0: string): boolean {
  const t = t0.trim().replace(/[\\\/]+(\*(\.\*)?)?$/, "") || "\\";
  if (/^[\\\/]$/.test(t) || /^[A-Za-z]:$/.test(t)) return true;
  if (HOME.test(t) || SYSTEM.test(t) || CWD.test(t)) return true;
  if (/^(HKLM|HKCU|HKCR|HKU):?$/i.test(t) || /^HK(LM|CR|U):\\?(SOFTWARE|SYSTEM)?$/i.test(t)) return true;
  const sub = /^(\$env:\w+|%\w+%|\$HOME|~)[\\\/](.*)$/i.exec(t);
  if (sub && (HOME.test(sub[1]) || SYSTEM.test(sub[1])) && /^(\*|Documents|Desktop|Downloads|Pictures|AppData|\.ssh|source|repos?)?$/i.test(sub[2])) return true;
  if (sub && SYSTEM.test(sub[1])) return true;
  return broadPath(t.replace(/\\/g, "/")) || criticalPath(t);
}
const winCleanup = (t: string) => cleanupPath(t.replace(/\\/g, "/"));
const winCritical = (x: string) => criticalPath(x) || criticalPath(x.replace(/\\/g, "/"));
/** Values of PowerShell parameters (prefix-matched, case-insensitive: -Pa, -Path, -LiteralPath) and positional arguments. */
function psTargets(args: string[], pathParams: RegExp, otherValueParams: RegExp): string[] {
  const out: string[] = [];
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (/^-/.test(a)) {
      const [name, inline] = a.split(/:(.*)/s);
      // -Path .,$env:USERPROFILE is a list of two paths (a quoted value stays whole: its comma belongs to the name)
      const list = (v: string) => (/['"]/.test(v) ? [v.replace(/^['"]|['"]$/g, "")] : v.split(",").map(x => x.trim()).filter(Boolean));
      if (pathParams.test(name)) { if (inline !== undefined && inline !== "") out.push(...list(inline)); else if (k + 1 < args.length) out.push(...list(args[++k])); }
      else if (otherValueParams.test(name) && inline === undefined) k++;
      continue;
    }
    out.push(...a.split(",").filter(Boolean));
  }
  return out;
}
/** Values of a PowerShell parameter (prefix-matched): -Include a,b or -Include 'a', 'b' or -Include:a. */
function psValues(args: string[], name: RegExp): string[] {
  const out: string[] = [];
  for (let k = 0; k < args.length; k++) {
    const [n, inline] = args[k].split(/:(.*)/s);
    if (!args[k].startsWith("-") || !name.test(n)) continue;
    let v = inline !== undefined && inline !== "" ? inline : args[++k] ?? "";
    while (v.endsWith(",") && k + 1 < args.length) v += args[++k];
    out.push(...v.split(",").map(x => x.trim().replace(/^['"]|['"]$/g, "")).filter(Boolean));
  }
  return out;
}
/** A path inside the current folder: . or a relative path, without a drive, a home, a variable, a provider (FileSystem::C:\) or a parent folder. */
const insideProject = (p: string) => /^(\.|\.\\|\.\/)?$/.test(p) || (!/^[A-Za-z]:|^[\\\/~$%]|(^|[\\\/])\.\.([\\\/]|$)/.test(p) && !p.includes("::") && !p.includes(VAR));
const REMOVER = /^(remove-item|ri|rm|rmdir|rd|del|erase)$/;
const LISTER = /^(get-childitem|gci|ls|dir|get-item|gi)$/;
const REMOVE_TARGET_OPTS = /^-(fi(l(t(e(r)?)?)?)?|include|exclude|credential|stream)$/i;
const PATH_OPTS = /^-(p|pa|pat|path|literalpath|lp|psp|pspath)$/i;
/** Command name of a stage: path, case and extension removed. */
const cmdName = (raw: string) => raw.replace(/^.*[\\\/]/, "").toLowerCase().replace(/\.(exe|com|cmd|bat)$/, "");
/** The tokens of a stage without leading call operators and variable assignments. */
function stageTokens(stage: string): { raw: string; args: string[] } {
  const t = tokens(stage);
  let k = 0;
  while (k < t.length) {
    if (t[k] === "&" || t[k] === ".") { k++; break; }                       // a call operator: the next word is the command, a $variable too
    if (/^\$[\w:]+\s*=$/.test(t[k]) || t[k] === "=") { k++; continue; }     // $x= …  $env:X= …
    if (/^\$[\w:]+$/.test(t[k]) && t[k + 1] === "=") { k += 2; continue; }  // $x = …  $env:X = … (the right-hand side runs)
    break;
  }
  return { raw: t[k] ?? "", args: t.slice(k + 1) };
}

/** A .NET file call ([System.IO.Directory]::Delete(...) and the like): its first argument, and the rest up to ")". */
interface IoCall { kind: string; method: string; first: string; rest: string }
/**
 * The .NET file calls of a text, read by hand after each call's name rather than by one regular expression: on many
 * calls left open ("[IO.File]::Delete('" repeated), that expression's lazy first argument and its rest up to ")"
 * backtracked cubically (50 KB took 88 s). Same reading as it had: the first argument is a quoted text up to its first
 * closing quote on the same line, a $variable or [Environment]…; the rest runs to the next ")", found in a table built
 * once (linear in the text); calls do not overlap.
 */
function ioCalls(text: string): IoCall[] {
  const out: IoCall[] = [], head = /\[(?:System\.)?IO\.(Directory|File)\]::(Delete|WriteAll\w*|AppendAll\w*|Copy|Move|Replace)\s*\(\s*/gi;
  const variable = /\$[\w:]+|\[Environment\][^,)]*/iy;
  let nextParen: Int32Array | undefined;
  const parenFrom = (i: number) => {
    if (!nextParen) {
      nextParen = new Int32Array(text.length + 1); nextParen[text.length] = -1;
      for (let k = text.length - 1; k >= 0; k--) nextParen[k] = text.charCodeAt(k) === 41 ? k : nextParen[k + 1];
    }
    return nextParen[i];
  };
  for (let m = head.exec(text); m; m = head.exec(text)) {
    const at = head.lastIndex, q = text[at];
    let first: string | undefined, end = at;
    if (q === "'" || q === '"') {
      const c = text.indexOf(q, at + 1);
      if (c >= 0 && !/[\n\r\u{2028}\u{2029}]/u.test(text.slice(at + 1, c))) { first = text.slice(at + 1, c); end = c + 1; }
    } else {
      variable.lastIndex = at; const v = variable.exec(text);
      if (v) { first = v[0]; end = at + v[0].length; }
    }
    const close = first === undefined ? -1 : parenFrom(end);
    if (first === undefined || close < 0) { head.lastIndex = m.index + 1; continue; }   // not a call: search again one character on
    out.push({ kind: m[1], method: m[2], first, rest: text.slice(end, close) });
    head.lastIndex = close + 1;
  }
  return out;
}

/** Findings for PowerShell / cmd.exe text. */
export function analyzeWindows(text: string, depth = 0): WindowsReport {
  const rep: WindowsReport = { destructive: [], unresolved: [], catastrophic: [] };
  const hit = (sev: Severity, what: string) => { rep.destructive.push(what); if (sev === "catastrophic") rep.catastrophic.push(what); };
  if (depth > 4) return rep;
  // $p = 'C:\'; Remove-Item -Recurse $p: literal assignments are substituted into targets.
  const vars = new Map<string, string>();
  for (const m of text.matchAll(/\$(\w+)\s*=\s*(['"])(.*?)\2/g)) vars.set(m[1].toLowerCase(), m[3]);
  const subst = (x: string) => { const m = /^\$(\w+)$/.exec(x); return m && vars.has(m[1].toLowerCase()) ? vars.get(m[1].toLowerCase())! : x; };
  if (/win32_shadowcopy/i.test(text) && /remove-(wmiobject|ciminstance)|\.delete\s*\(/i.test(text)) hit("catastrophic", "deleting volume shadow copies");
  // .NET file APIs: [System.IO.Directory]::Delete('C:\', $true), [IO.File]::Delete(...), [IO.File]::WriteAllText(<system file>, ...)
  for (const m of ioCalls(text)) {
    const { kind, method } = m; const target = subst(m.first), restArgs = m.rest;
    if (/^delete$/i.test(method)) {
      const recursive = /^directory$/i.test(kind) && /,\s*\$true/i.test(restArgs);
      if ((recursive && winBroad(target)) || winCritical(target)) hit("catastrophic", `[IO.${kind}]::Delete(${target})`);
      else hit("destructive", `[IO.${kind}]::Delete(${target})`);
    } else if (/^(copy|move|replace)$/i.test(method)) {
      const dest = /^\s*,\s*(['"])(.*?)\1/.exec(restArgs)?.[2];
      if (dest && winCritical(dest)) hit("catastrophic", `[IO.${kind}]::${method} onto a system file`);
    } else if (winCritical(target)) hit("catastrophic", `[IO.${kind}]::${method} onto a system file`);
  }
  // [ScriptBlock]::Create('…'): code built at run time
  for (const m of text.matchAll(/\[ScriptBlock\]::Create\(\s*(['"])(.*?)\1\s*\)/gi)) merge(rep, analyzeWindows(m[2], depth + 1));
  for (const pipe of pipelines(text)) {
    // Get-ChildItem <path> [-Recurse] | … Remove-Item: the listed path is what gets deleted.
    const lister = pipe.findIndex(s => LISTER.test(cmdName(stageTokens(s).raw)));
    const remover = pipe.findIndex((s, n) => n > lister && REMOVER.test(cmdName(stageTokens(s).raw)));
    if (lister >= 0 && remover > lister) {
      const l = stageTokens(pipe[lister]), r = stageTokens(pipe[remover]);
      const listed = psTargets(l.args, PATH_OPTS, /^-(fi(l(t(e(r)?)?)?)?|include|exclude|depth|attributes)$/i).map(subst), paths = listed.length ? listed : ["."];
      const recursive = l.args.some(a => /^-r/i.test(a)) || r.args.some(a => /^-r/i.test(a));
      // -Include / -Filter inside the project: only what they name goes (-Recurse -Include __pycache__ | Remove-Item: cleanup).
      // Every listed path counts, and the remover takes the lister's items directly: a stage between them (| Split-Path |,
      // | ForEach-Object { $_.Parent } |) can turn them into their folders.
      const named = psValues(l.args, /^-(fi(l(t(e(r)?)?)?)?|include)$/i);
      const scoped = named.length > 0 && remover === lister + 1 && paths.every(insideProject) && !l.args.some(a => /^-ex/i.test(a));
      if (!r.args.some(a => /^-whatif(:\$?true)?$/i.test(a))) {
        const broad = paths.find(p => winBroad(p) && (recursive || /\\\*?$|^[A-Za-z]:\\?$/.test(p) || /^\$env:|^~|^\$HOME/i.test(p)));
        if (scoped) { if (!named.every(n => CLEANUP_NAMES.has(n.toLowerCase()))) hit("destructive", `${l.raw} ${paths.join(",")} -Include ${named.join(",")} | ${r.raw}`); }
        else if (broad) hit("catastrophic", `${l.raw} ${broad} | ${r.raw}`);
        else if (!paths.every(winCleanup)) hit("destructive", `${l.raw} ${paths.join(",")} | ${r.raw}`);
      }
    }
    for (const [n, stage] of pipe.entries()) {
      const { raw, args: rawArgs } = stageTokens(stage); if (!raw) continue;
      const args = rawArgs.map(subst);
      const c = cmdName(subst(raw));   // $x = 'rm'; & $x -rf ~: the command a variable names
      const lower = args.map(a => a.toLowerCase());
      const sw = (re: RegExp) => args.some(a => re.test(a));
      if (c === "cmd" && sw(/^\/[ck]$/i)) { merge(rep, analyzeWindows(args.slice(args.findIndex(a => /^\/[ck]$/i.test(a)) + 1).join(" "), depth + 1)); continue; }
      if (c === "powershell" || c === "pwsh") {
        const j = args.findIndex(a => /^-(c|command|encodedcommand|ec|e|enc)$/i.test(a));
        if (j >= 0) {
          const code = /^-(encodedcommand|ec|e|enc)$/i.test(args[j]) ? (() => { try { return Buffer.from(args[j + 1] ?? "", "base64").toString("utf16le"); } catch { return ""; } })() : args.slice(j + 1).join(" ");
          merge(rep, analyzeWindows(code, depth + 1));
        }
        continue;
      }
      if (c === "invoke-expression" || c === "iex") {
        const code = args.filter(a => !/^-command$/i.test(a)).join(" ");
        // iex (Get-Content x.ps1), iex (irm https://…), irm … | iex: code the analyzer cannot see, like curl | bash
        if (!args.length || /\b(get-content|gc|cat|type|invoke-webrequest|iwr|invoke-restmethod|irm|curl|wget|downloadstring|readalltext)\b/i.test(code)) rep.unresolved.push("Invoke-Expression of a file, a download or piped text");
        else if (/^\$/.test(code.trim())) rep.unresolved.push("Invoke-Expression of a variable");   // iex $code: built where the analysis cannot see
        else merge(rep, analyzeWindows(code, depth + 1));
        continue;
      }
      if (c === "start-process" || c === "saps") {
        const file = psTargets(args, /^-(filepath|fp)$/i, /^-(argumentlist|args|workingdirectory|wd|verb|credential|redirect\w*)$/i)[0] ?? "";
        const argList = args.slice(args.findIndex(a => /^-(argumentlist|args)$/i.test(a)) + 1).filter(a => !a.startsWith("-")).join(" ");
        if (file) merge(rep, analyzeWindows(`${file} ${args.some(a => /^-(argumentlist|args)$/i.test(a)) ? argList : ""}`, depth + 1));
        continue;
      }
      if (REMOVER.test(c)) {
        const cmdSyntax = /^(rd|rmdir|del|erase)$/.test(c) && sw(/^\/[a-z]$/i);
        if (!cmdSyntax && sw(/^-whatif(:\$?true)?$/i)) continue;
        const recursive = cmdSyntax ? sw(/^\/s$/i) : sw(/^-r/i);
        const targets = (cmdSyntax ? args.filter(a => !/^\/[a-z]$/i.test(a)) : psTargets(args, PATH_OPTS, REMOVE_TARGET_OPTS)).map(subst);
        if (targets.some(x => /^HK(LM|CR|U|CU)?:|^HKEY_/i.test(x))) { hit(targets.some(x => HIVE_ROOT.test(x)) ? "catastrophic" : "destructive", `${raw} on the registry`); continue; }
        const piped = (x: string) => /^\$_|^\$input|^\$PSItem/i.test(x);
        const fed = lister >= 0 && n === remover;   // its targets are the listed path, judged above
        if (fed && targets.every(piped)) continue;
        const unknown = !fed && (targets.some(piped) || targets.length === 0 && pipe.length > 1);
        if (recursive) {
          if (targets.some(winBroad)) hit("catastrophic", `${raw} -Recurse ${targets.join(" ")}`);
          else if (unknown || !targets.length || !targets.every(winCleanup)) { if (targets.length || unknown) hit("destructive", `${raw} -Recurse ${targets.join(" ")}`.trim()); }
        } else if (targets.some(winCritical)) hit("catastrophic", `${raw} ${targets.join(" ")}`);
        else if (targets.some(x => /^[~.\\\/]*\*[*.]*$/.test(x) || /^[A-Za-z]:\\\*$/.test(x))) hit("destructive", `${raw} ${targets.join(" ")}`);
        continue;
      }
      if (c === "robocopy" && sw(/^\/(mir|purge)$/i)) {
        // robocopy <source> <destination> /MIR or /PURGE deletes what the destination has and the source lacks: robocopy
        // empty C:\work /mir wipes C:\work (a build output folder is routine)
        const dst = args.filter(a => !a.startsWith("/"))[1] ?? "";
        if (winBroad(dst)) hit("catastrophic", `robocopy ${dst} /MIR`); else if (!winCleanup(dst)) hit("destructive", `robocopy ${dst} /MIR`);
        continue;
      }
      if (c === "format" && sw(/^[A-Za-z]:$/)) { hit("catastrophic", `format ${args.find(a => /^[A-Za-z]:$/.test(a))}`); continue; }
      if (/^(format-volume|clear-disk|initialize-disk|remove-partition|reset-physicaldisk|remove-physicaldisk|remove-virtualdisk|remove-storagepool|diskpart)$/.test(c)) { hit("catastrophic", raw); continue; }
      if (c === "vssadmin" && /^(delete|resize)$/.test(lower[0] ?? "")) { hit("catastrophic", `vssadmin ${lower[0]} shadows`); continue; }
      if (c === "wmic" && lower.some(a => a.includes("shadowcopy")) && lower.includes("delete")) { hit("catastrophic", "wmic shadowcopy delete"); continue; }
      if (c === "wbadmin" && lower[0] === "delete") { hit("catastrophic", "wbadmin delete (backups)"); continue; }
      if (c === "bcdedit" && (sw(/^\/(delete|deletevalue)$/i) || lower.some(a => /^(recoveryenabled|bootstatuspolicy|safeboot)$/.test(a)))) { hit("catastrophic", "bcdedit (boot configuration)"); continue; }
      if (c === "cipher" && sw(/^\/w/i)) { hit("destructive", "cipher /w"); continue; }
      if (c === "fsutil" && lower[0] === "file" && /^setzerodata$/.test(lower[1] ?? "")) { hit("destructive", "fsutil file setZeroData"); continue; }
      if (c === "reg" && lower[0] === "delete") { hit(HIVE_ROOT.test(args[1] ?? "") ? "catastrophic" : "destructive", `reg delete ${args[1] ?? ""}`.trim()); continue; }
      if (/^(remove-itemproperty|clear-itemproperty|rp)$/.test(c)) { const ts = psTargets(args, /^-(p|path|literalpath|lp)$/i, /^-(n|name)$/i); if (ts.some(x => HIVE_ROOT.test(x))) hit("catastrophic", `${raw} on HKLM`); else if (ts.some(x => /^HK/i.test(x))) hit("destructive", `${raw} on the registry`); continue; }
      if (/^(set-itemproperty|sp|new-itemproperty)$/.test(c)) { const ts = psTargets(args, /^-(p|path|literalpath|lp)$/i, /^-(n|name|value|type|propertytype)$/i); if (ts.some(x => HIVE_ROOT.test(x))) hit("destructive", `${raw} on HKLM`); continue; }
      if (c === "takeown" && sw(/^\/r$/i)) { const ts = psTargets(args, /^\/f$/i, /^\/(s|u|p|d)$/i); hit(ts.some(winBroad) ? "catastrophic" : "destructive", "takeown /r"); continue; }
      if (c === "icacls" && sw(/^\/t$/i) && args.slice(0, 1).some(winBroad)) { hit("catastrophic", `icacls ${args[0]} /t`); continue; }
      if (/^(stop-computer|restart-computer)$/.test(c)) { hit("destructive", raw); continue; }
      if (c === "shutdown" && sw(/^[\/-][srpgh]$/i) && !sw(/^[\/-]a$/i)) { hit("destructive", "shutdown"); continue; }
      if (c === "net" && lower[0] === "user" && sw(/^\/del(ete)?$/i)) { hit("destructive", "net user /delete"); continue; }
      if (c === "schtasks" && sw(/^\/delete$/i)) { hit("destructive", "schtasks /delete"); continue; }
      if (c === "sc" && lower[0] === "delete") { hit("destructive", "sc delete"); continue; }
      if (/^(clear-recyclebin|clear-eventlog|remove-eventlog)$/.test(c) || (c === "wevtutil" && /^(cl|clear-log)$/.test(lower[0] ?? ""))) { hit("destructive", raw); continue; }
      if (/^remove-az(resourcegroup|sqlserver|sqldatabase|storageaccount|cosmosdbaccount|keyvault|akscluster|postgresqlflexibleserver|mysqlflexibleserver|rediscache|disk|snapshot|recoveryservicesvault)$/.test(c)) { hit("catastrophic", raw); continue; }
      if (c === "remove-s3bucket") { hit(sw(/^-deletebucketcontent/i) ? "catastrophic" : "destructive", raw); continue; }
      if (/^remove-(ec2instance|rdsdbinstance|rdsdbcluster|ddbtable|cfnstack|ekscluster)$/.test(c)) { hit("catastrophic", raw); continue; }
      if (/^remove-(az|s3object|mg|azuread|ad(user|group|computer|organizationalunit)|mailbox|vm$|gcs)/.test(c)) { hit("destructive", raw); continue; }
      if (/^(set-content|sc|out-file|add-content|clear-content|copy-item|cpi|copy|move-item|mi|move|new-item)$/.test(c)) {
        const ts = psTargets(args, /^-(p|path|literalpath|lp|destination|dest|filepath)$/i, /^-(value|encoding|filter|include|exclude|credential|itemtype|type|name)$/i);
        const dest = /^(copy-item|cpi|copy|move-item|mi|move)$/.test(c) ? ts.slice(-1) : ts;
        if (dest.some(winCritical)) hit("catastrophic", `${raw} onto a system file`);
        continue;
      }
    }
  }
  return rep;
}
function merge(into: WindowsReport, r: WindowsReport) { into.destructive.push(...r.destructive); into.unresolved.push(...r.unresolved); into.catastrophic.push(...r.catastrophic); }

const PS_VERB = /\b(Remove|Clear|Format|Initialize|Stop|Restart|Set|Out|Add|Copy|Move|Reset|New|Invoke|Start)-[A-Za-z]{2,}/i;
/** Cheap test: does this text look like a PowerShell or cmd.exe command (so the Windows analyzer should run on it)? */
export function looksWindows(t: string): boolean {
  return PS_VERB.test(t) || /[A-Za-z]:\\|\$env:\w|%[A-Za-z_]+%|\bHK(LM|CU|CR|U):/i.test(t) || /(^|[\s;&|(])(rd|rmdir|del|erase)\s+\/[sqf]\b/i.test(t)
    || /\s-(Recurse|LiteralPath|WhatIf)\b/i.test(t) || /\[(System\.)?IO\.(File|Directory)\]::|\[ScriptBlock\]::|\biex\b/i.test(t)
    || /(^|[\s;&|(])(format\s+[a-z]:|diskpart|vssadmin|wbadmin|bcdedit|wmic|fsutil|reg(\.exe)?\s+delete|cipher(\.exe)?\s+\/w|takeown|icacls|schtasks|robocopy|cmd(\.exe)?\s+\/[ck]|(powershell|pwsh)(\.exe)?\s)/i.test(t);
}
