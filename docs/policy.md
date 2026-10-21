# Policy reference

A policy is a YAML document: a list of rules evaluated from top to bottom; the **first rule that matches decides**
(`allow`, `confirm` or `block`); when none matches, `default` decides.

```yaml
extends: coding-agent        # optional: a built-in preset whose rules come after yours
default: allow               # decision when no rule matches (default: allow)
unknownTools: confirm        # MCP proxy / SDK only, see mcp-proxy.md (default: confirm)
sqlDialect: postgresql       # dialect of the SQL parser (default: postgresql)
knownTools: ["internal_*"]   # MCP proxy / SDK only
rules:
  - name: protect-production-db
    argMatches: 'prod-db\.internal|DATABASE_URL_PROD'
    action: block
```

Where policies come from:

| | Default | Override |
|---|---|---|
| agent hooks | `~/.kytral/policy.yaml` if it exists, else the `coding-agent` preset | `KYTRAL_POLICY=file`, or `--policy file` / `--preset name` in the hook command |
| MCP proxy | the `strict` preset | `--policy file` or `--preset name` |
| SDK | none: pass `policy` | `loadPolicy(yamlText)`, `presetPolicy(name)` |
| `kytral-guard check` | same as hooks | `--policy file`, `--preset name` |

A policy that does not load (bad YAML, unknown action or analyzer, invalid regex) is an error: hooks refuse every call,
the proxy refuses to start. Validate before deploying: `kytral-guard policy validate policy.yaml`. A hook's refusal (which
the agent and its model read) and the proxy's error say why in fixed words, with the line of a YAML syntax error, never the
file's path or a word of it: YAML's own messages quote the line at fault, which may hold a secret. `kytral-guard doctor`
names the file, `kytral-guard policy validate <file>` shows the whole message, both in your terminal. No YAML text the guard
reads is ever printed by the YAML parser (its warnings, or its `LOG_TOKENS` / `LOG_STREAM` debugging output).

## Presets and `extends`

| Preset | For | In one line |
|---|---|---|
| `coding-agent` | agent hooks | block catastrophes, confirm scoped destruction, stay silent on routine work; file contents are not commands |
| `strict` | MCP proxy, SDK | block every destructive finding (including `rm -rf node_modules`), confirm deletions, payments and mass e-mail |

`extends: <preset>` puts your rules **before** the preset's, so they can tighten (block more) or loosen (allow a precise
command) it; `default`, `unknownTools`, `sqlDialect` you set override the preset's, and `knownTools` are added. Print the
effective policy with `kytral-guard policy show [--policy file | --preset name]`.

> Because your rules come first, an `allow` or `confirm` rule that also matches a catastrophic command overrides the
> preset's block (a `confirm` on every `git push` would let a force-push to `main` through with a click). Keep loosening
> rules narrow: anchor their regex (`^…$`) and restrict them with `argFields`.

### Changing a preset rule: `overrides`

`overrides` gives rules a new action by name, the preset's included, without copying them:

```yaml
extends: coding-agent
overrides:
  shell-destructive: block      # never run rm -rf src, git reset --hard...: refuse instead of asking
  mcp-money: allow              # payments run without asking
rules: []
```

Every name must be a rule of the policy (a typo is an error, and the policy does not load). `guard-tamper` cannot be
overridden: it keeps agents from turning the guard off. The dashboard's rules and protection levels write this map
([dashboard.md](dashboard.md)); it removes an override that gives a rule its preset's action back.

### Allowing one command: `kytral-guard allow`

The simplest way to silence a confirmation you answer every time is to allow that exact command:

```console
$ kytral-guard allow "git reset --hard origin/main"
allowed    git reset --hard origin/main
           was: git reset --hard (discards uncommitted work) (rule shell-destructive)
           rule allow-3f9c2a1b in /home/you/.kytral/policy.yaml; still blocked if it ever turns catastrophic
           undo: kytral-guard allow --remove allow-3f9c2a1b
$ kytral-guard allow --list
```

It adds this rule first in the hooks' policy file (`$KYTRAL_POLICY`, else `~/.kytral/policy.yaml`, created if needed),
keeping the file's comments:

```yaml
  - name: allow-3f9c2a1b
    argFields: [command]
    argEquals: git reset --hard origin/main
    exceptCatastrophic: true
    action: allow
```

A command that a catastrophe rule matches (`shell-catastrophic`, `sensitive-file-write`, `sql-destructive`), or that the
policy blocks, is refused unless you add `--force` (the rule then has no `exceptCatastrophic`), even when a rule set to
Ask or an earlier exception decides first. A command that would turn the guard off (`guard-tamper`) is refused even with
`--force`: edit the policy file by hand if you really mean it. `kytral-guard allow --call <n>` takes the exact text of a
call the dashboard shows, with no quoting to get right; it reads only texts the guard of this home kept, signed for their
file (it needs the deployment secret to check them). Agents cannot run `kytral-guard allow` themselves: the
`guard-tamper` analyzer blocks it, and the policy file is a guard file they cannot write. When a hook asks you to confirm
a shell command, its message shows the line to run: `kytral-guard allow --call <n>`, which names the kept call, so that
nothing an agent wrote is pasted in your terminal (else, on Linux and macOS, the command in single quotes when no shell
reads it differently).

## Rule fields

| Field | Matches when |
|---|---|
| `name` | (required) shown in decisions and the audit log |
| `action` | (required) `allow`, `confirm` or `block` |
| `tool` | glob on the tool name, case-insensitive (`*delete*`, `mcp__github__*`) |
| `toolMatches` | regex on the canonical tool name (lower case, `camelCase` split into `camel_case`) |
| `toolNotMatches` | the rule does **not** apply to tools whose canonical name matches this regex |
| `argMatches` | regex tested on every normalized view of every argument value (see below), case-insensitive |
| `argEquals` | an argument value is exactly this text (surrounding spaces aside): the raw text, no normalization, so a look-alike (`dеploy` with a Cyrillic `е`) does not match |
| `exceptCatastrophic` | `true`: the rule does not apply to a call the shell analysis finds catastrophic (an allowed command whose script was later changed into `rm -rf ~`) |
| `argFields` | the rule only looks at these top-level arguments (for `argMatches`, `argEquals`, analyzers and counts), e.g. `[command]` |
| `analyzer` | a structural analyzer reports a finding (see below) |
| `maxCount` + `countArgs` | more than `maxCount` items in these fields (arrays, or strings split on `,` `;`), or more distinct e-mail addresses anywhere in the arguments |

All the conditions of a rule must hold. Regexes use JavaScript syntax with the `i` and `u` flags.

## Analyzers

| Analyzer | Finds |
|---|---|
| `shell-catastrophic` | broad, irreversible shell actions: `rm -rf` of `/`, `~`, `.`, `*`, `.git`, a top-level or system directory or `"$VAR/"*`; disk tools (`dd of=/dev/sda`, `mkfs`, `wipefs`); `kill -9 -1`; fork bombs; writes to critical files; force-push or deletion of `main`/`master`/`production`; and the catastrophic entries of the command catalog (below) |
| `shell-destructive` | every destructive shell finding, catastrophic ones included: also `rm -rf <project dir>`, `git reset --hard`, `git clean -f`, `chmod -R`, `rsync --delete`, `truncate`, interpreter one-liners that delete files, and the destructive entries of the catalog |
| `shell-unresolved` | what cannot be decided statically: a variable or `$(…)` in command position, `alias`, `source` of a file nobody can read, `eval` of an expansion, a script piped into `sh`/`python`/`node` (or run from `source <(…)`), an interpreter one-liner that spawns processes, a redirection to an expanded path, a script too large to read or downloaded by the same command. Inside script files only remote code, unreadable scripts and unknown commands run on `/` or `~` count |
| `shell-unparseable` | a string the shell tokenizer cannot parse |
| `sql-unrestricted-write` | `DROP`, `TRUNCATE`, `ALTER … DROP`, `DELETE`/`UPDATE` whose `WHERE` does not pin rows with constants (missing, tautology, `LIKE`, range, `IS NOT NULL`, subquery, multi-table, `JOIN`), `REPLACE … SELECT`, `MERGE … THEN DELETE`, `INSERT OVERWRITE`, `COPY … PROGRAM` |
| `sql-opaque` | SQL whose effect is unknown statically: `CALL`/`EXEC`, bind parameters in the `WHERE` (`$1`, `?`, `@v`, `:v`), `COPY`, `GRANT`/`REVOKE`, `ALTER … RENAME` |
| `sql-unparseable` | a statement that looks like a SQL write but does not parse in `sqlDialect` |
| `path-sensitive` | a path argument (`file_path`, `path`, `destination`… or every string when `argFields` is set) that is a system, credential or guard file: `/etc/*`, `~/.ssh/*`, `~/.aws/*`, shell rc files, `.git/hooks`, `C:\Windows\*`, `~/.kytral/*`, the hook configurations of every supported agent (`.claude/settings*.json`, `~/.claude.json`, `.cursor/hooks.json`, `.codex/hooks.json`, `.gemini/settings.json`, `.copilot/hooks/`, `.github/hooks/`, `.grok/hooks/` and Grok's `config.toml` / `requirements.toml`, Windsurf and Devin hooks…) and MCP configurations (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`); a project's `.env` is not |
| `guard-tamper` | reading or setting the guard's secret (`$KYTRAL_SECRET`, `~/.kytral/secret`), or running `kytral-guard resume`, `badge`, `confirm approve`, `allow`, `uninstall`, `mcp unwrap`, `dashboard` (also by its script path, `node …/dist/cli.js resume`) |

### What the shell analyzers understand

- **Tokenization** with [shell-quote](https://github.com/ljharb/shell-quote) after decoding ANSI-C quoting (`$'\x72m'`),
  line continuations and `$IFS`; commands are split on `;`, `&&`, `||`, `|`, and subshells and substitutions are command
  lists of their own (`(cd x && rm -rf ~)`); reserved words (`if`, `then`, `do`…) do not hide the command after them;
  quoted strings may span lines; brace expansion in command position (`{rm,-rf,/}`) is expanded; `$HOME` is read as `~`,
  `$PWD` as `.`, `${TMPDIR:-/tmp}` and `$(mktemp -d)` as a temporary path, `$((…))` as a number.
- **Variables**: a plain assignment that always runs is followed (`OUT=dist` then `rm -rf "$OUT"` is `rm -rf dist`), and
  so are the arguments of a script (`$1`). An assignment inside `if`/`while`/`for`/`case`/a function or after `&&`/`||`,
  a second different value, `read`, `unset`, `+=`, `eval` or `source` in the text leave the variable unknown. Subshells
  see the variables without changing them; `bash -c '…'`, scripts and recipes start without them.
- **Wrappers** with their options: `sudo -u root`, `doas`, `env [-S "…"]`, `timeout 10`, `nice -n 5`, `ionice`, `nohup`,
  `xargs -I{}`, `parallel`, `flock`, `chroot`, `stdbuf`, `strace`, `su -c '…'`, `runuser`, `sg`, `watch '…'`, container
  entrypoints and schedulers (`gosu`, `su-exec`, `setpriv`, `unshare`, `tini`, `dumb-init`, `pkexec`, `systemd-run`,
  `mpirun`, `srun`, `xvfb-run`, `fakeroot`, `numactl`, `cpulimit`…), and `concurrently '…' '…'`. A command the analyzer
  does not know that is followed by a dangerous one (`some-wrapper --opt rm -rf /`) is analyzed from that command on.
- **Nested and remote execution**: `sh -c`/`bash -c`, `eval`, `$(…)` and backticks (also inside double quotes),
  `ssh host '…'`, `docker`/`podman`/`kubectl exec`, `docker compose exec`, `docker run` with a bind mount of the host
  (catastrophic when `/`, a home or the Docker socket is mounted), `find … -exec <command>`, `gcloud compute ssh
  --command`, `vagrant ssh -c`, `wsl -e`, `nix-shell --run`, `script -c`, `ansible -a`, `salt cmd.run`, `pdsh`, `pwsh -c`
  / `-EncodedCommand`.
- **Pipelines**: a script assembled and fed to a shell is decoded and analyzed (`echo '…' | sh`, `echo <base64> | base64 -d
  | bash`, `printf '\x72\x6d…' | sh`, `xxd -r -p`); `xargs rm` is judged by what produces its input (`find / … | xargs rm -rf`
  is catastrophic).
- **git**: global options (`git -C dir`, `git -c key=value`), and configuration values that git runs as commands
  (`-c core.sshCommand=…`, `git config alias.x '!…'`, `GIT_SSH_COMMAND=…`, `EDITOR=…`).
- **Interpreter one-liners**: `node -e`/`-p`, `python -c`, `perl -e`/`-ne`/`-pe`, `ruby -e`, `php -r`, `lua -e`, `Rscript
  -e`, `julia -e`, `deno eval`, `bun -e`, `awk 'BEGIN{system(…)}'`: deletion APIs are destructive (catastrophic on `/` or a
  home), and the command lines they spawn (`os.system('…')`, `execSync('…')`) are analyzed like any command.
- **Runners**: `npx`, `pnpm exec`/`dlx`, `yarn dlx`, `bunx`, `uv run`, `poetry run`, `pipx run`, `conda run`, `bundle
  exec`, `nix develop -c`, `direnv exec`, `doppler run --`, and scripts run by an interpreter (`python manage.py`,
  `php artisan`, `php bin/console`, `node ace`, `ruby bin/rails`, `python -m django`).
- **SQL inside commands**: `psql -c`, `mysql -e`, `sqlite3 db "…"`, `duckdb`, `clickhouse-client -q`, `sqlcmd -Q`,
  `cockroach sql -e`, `snowsql -q`, `bq query`, `wrangler d1 execute --command`, `turso db shell`, also behind `sudo`,
  `docker exec` or `sh -c`, are analyzed by the SQL analyzers; a backslash is read both ways (it escapes a quote in
  MySQL, not in PostgreSQL, SQLite or SQL Server). SQL files in the working directory are read and judged whole, every
  statement (`psql -f migrate.sql` and `mysql app < seed.sql` run, `psql -f drop.sql` and a `DROP` after `BEGIN;` are
  blocked, client commands such as `\!` or `\i` are confirmed). SQL from a pipe, a variable, a command substitution, or a
  file not read here (missing, written by the same line, stdin or a device, over 1 MB, read by a client on another host
  or in a container: `ssh`, `docker exec`, `kubectl exec`) is `sql-opaque` (confirmed).
- **Files a command runs** are read from the call's working directory (agent hooks report it; `cd` in the command is
  followed) and analyzed with the command, their findings naming the file: shell scripts (`bash x.sh`, `./x.sh` by its
  shebang, `source x.sh`, `bash < x.sh`, `cat x.sh | sh`, `bash <(cat x.sh)`), `package.json` scripts with their `pre`/`post`
  scripts (`npm run`, `npm test`, `npm install` lifecycle scripts, `yarn x`, `pnpm x`, `bun run x`, workspaces with `-w`,
  `--filter`, `-r`, `yarn workspace`, and `turbo`, `lerna`, `nx` across packages), Makefile recipes with their
  prerequisites and variables (`make -n` only runs `+` lines), justfile and Taskfile recipes, git hooks run by `commit`,
  `push`, `merge`, `rebase`, `checkout`… (`.git/hooks`, `core.hooksPath`, husky; `--no-verify` skips the hooks it skips),
  `crontab file`, `at -f`, `trap` handlers, PowerShell scripts (`pwsh -File`), and programs (`python x.py`, `python -m
  pkg.mod`, `uv run x.py`, `node x.js`, `npx tsx x.ts`, `deno run`, `bun x.ts`, `ruby`, `perl`, `php`) with the local
  modules they import. In a program, deletion calls are judged by their target (`shutil.rmtree(Path.home())` is
  catastrophic, `fs.rmSync('dist', …)` routine), and the command lines it runs (`os.system('…')`, `execSync(cmd)` after
  `cmd = '…'`, `subprocess.run(['rm', '-rf', …])`) are analyzed like any command; strings and comments are not code.
  A here-document fed to a shell or an interpreter is that program; one written to a file is that file's content when
  the same command runs it. Reads are bounded (regular text files, 1 MB each, 64 files and 4 MB per call); a script that
  cannot be read is confirmed; code in dependency folders (`node_modules`, `site-packages`…) is not analyzed; commands run
  on another host or in a container (`ssh`, `docker exec`) never read local files.
- **Routine idioms stay silent**: sourcing environment scripts (`source .venv/bin/activate`, `~/.nvm/nvm.sh`, `.env`),
  shell-init `eval "$(ssh-agent -s)"`, `eval "$(direnv hook bash)"`, recursive `chmod`/`chown` inside the project,
  truncating a log, copying `.env.example` to `.env`.
- **PowerShell and cmd.exe** (the Claude Code PowerShell tool, `pwsh -c`, `cmd /c`): `Remove-Item -Recurse` (and its
  aliases `rm`, `ri`, `rd`, `del`), also fed by `Get-ChildItem … |`, `rd /s`, `del /s`, `[IO.Directory]::Delete`,
  `[IO.File]::Delete`/`WriteAllText` on system files, `Invoke-Expression` and `Start-Process` payloads (a file or a
  download is confirmed), literal variables (`$p='C:\'; Remove-Item -Recurse $p`), `format`, `Format-Volume`, `Clear-Disk`,
  `diskpart`, `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete`, `bcdedit`, `reg delete HKLM`,
  `Set-ItemProperty HKLM:`, `takeown /r`, `icacls /t`, `fsutil setZeroData`, `robocopy /MIR` or `/PURGE` (it deletes what
  the destination has and the source lacks), `Invoke-Expression $variable` (confirmed), Az and AWS cmdlets. A command named
  by a variable is followed (`$x = 'rm'; & $x -rf ~`). `Get-ChildItem -Recurse -Include __pycache__ | Remove-Item` deletes
  only what `-Include`/`-Filter` names: routine for files tools write again, when every listed path is inside the project
  and `Remove-Item` takes the items directly (a stage between them, such as `Split-Path`, can turn them into their
  folders). PowerShell's own `if ($?)`, `if ($LASTEXITCODE …)` and `$env:X = 'value'` are not read as unknown shell
  commands; `$env:X = Remove-Item …` runs the command on its right and is analyzed as such.
- **macOS**: `diskutil erase…`, `tmutil delete` and `deletelocalsnapshots` (backups) are blocked; `csrutil disable`,
  `launchctl unload`/`bootout` of a system service, `defaults delete <domain>` (every preference of an app) and `tmutil
  disable` are confirmed.

### Deletion targets

| Target of a recursive deletion | Severity |
|---|---|
| `/`, `~`, `$HOME`, `.`, `..`, `*`, `./*`, `.git`, `/data` (top-level), `/home/bob`, `C:\`, `C:\Users\bob`, system and credential paths, `"$DIR/"*` (an empty variable means `/*`) | catastrophic |
| regenerable directories inside the project: `node_modules`, `dist`, `build`, `out`, `target`, `.next`, `.nuxt`, `.svelte-kit`, `.turbo`, `.cache`, `coverage`, `__pycache__`, `.pytest_cache`, `.venv`, `.terraform`, `tmp`…, dependency lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`…), named entries under `/tmp`, caches of the home folder (`~/Library/Caches/<app>`, Xcode's `DerivedData`, `~/.cache/<tool>`, `~/.npm/_cacache`) | harmless |
| anything else (`src`, `./lib`, `/srv/app/releases/12`, `$BUILD_DIR`) | destructive |

A single-file deletion is catastrophic on a critical file (`/etc/passwd`, `~/.ssh/id_ed25519`), destructive when it
empties a directory (`rm *`), harmless otherwise. Targets that come from stdin (`xargs rm`) or `find` (`{}`) are
destructive, except a `find` that starts inside the project (its global options `-H`, `-P`, `-D`, `-O` come before the
start points; `-L` follows links out of the project, so it is not routine), whose tests must all hold (no `-o`, `!` or
parentheses), names files tools write again and only deletes them (`find . -name '__pycache__' -exec rm -rf {} +`,
`find . -name '*.pyc' -delete`): that is routine. A script that does not exist is run by nothing when it is alone on
its line, and stays unknown (confirmed) after another command of the line, which may write it (`python gen.py &&
python out.py`); a git hook or a `python -m` module that is not there runs nothing.

### Command catalog

Catastrophic (blocked by both presets) and destructive (confirmed by `coding-agent`) entries for:

- **Infrastructure as code**: `terraform`/`tofu`/`terragrunt` (`destroy`, `apply -destroy`, `apply -auto-approve`, `state rm`), `pulumi` (`destroy`, `stack rm`, `up --yes`), `cdk destroy`, `serverless remove`, `sam delete`, `eksctl delete cluster`, `copilot app delete`.
- **Kubernetes**: `kubectl`/`oc` `delete` (catastrophic for namespaces, PV/PVC, CRDs, nodes, cluster roles, `--all`, `-A`), `drain`, `replace --force`, `apply --prune`, `scale --replicas=0`; `helm uninstall`; `argocd app delete`.
- **Cloud**: `aws` (`s3 rm --recursive`, `s3 rb --force`, `terminate-instances`, `delete-db-instance`, `delete-table`, `delete-stack`, `schedule-key-deletion`… and any `delete-*`/`terminate-*`), `gcloud` (`projects delete`, `sql instances delete`, `storage rm --recursive`…), `gsutil rm -r`/`rb`, `bq rm -r`, `az` (`group delete`, `keyvault purge`, `storage blob delete-batch`…), `doctl`, `hcloud`, `linode-cli`, `scw`, `oci`, `ibmcloud`, `civo`, `exo`, `vultr-cli`, `upctl`.
- **Containers**: `docker`/`podman`/`nerdctl` `system prune [--volumes]`, `volume rm`/`prune`, `compose down -v`, `stack rm`; `docker-compose down -v`.
- **Data stores**: `dropdb`, `pg_dropcluster`, `mysqladmin drop`, `redis-cli FLUSHALL`/`FLUSHDB`, `mongosh --eval` with `dropDatabase()`/`drop()`/`deleteMany({})`, `cqlsh -e 'DROP KEYSPACE'`, `etcdctl del --prefix`, `consul kv delete -recurse`, `vault secrets disable`, `influx bucket delete`.
- **ORMs and frameworks**: `prisma migrate reset`, `prisma db push --force-reset`/`--accept-data-loss`, `rails`/`rake db:drop`/`reset`/`purge` (catastrophic with `RAILS_ENV=production`), `artisan migrate:fresh`/`db:wipe` (with `--force`), `manage.py flush` (with `--noinput`), `supabase db reset` (`--linked`), `flyway clean`, `liquibase dropAll`, `sequelize db:drop`, `typeorm schema:drop`, `mikro-orm schema:drop`, `dbmate drop`, `migrate drop`, `atlas schema clean`, `sqlx database drop`, `dotnet ef database drop`, `mix ecto.drop`, `wp db reset`, `drush sql:drop`, `doctrine:database:drop`, `knex migrate:rollback --all`, `alembic downgrade base`, `drizzle-kit drop`.
- **Object storage**: `mc rm -r`/`rb`, `rclone purge`/`delete`/`sync`, `s3cmd del -r`/`rb`, `azcopy remove --recursive`.
- **Hosting and registries**: `heroku apps:destroy`/`pg:reset`, `fly apps destroy`/`volumes destroy`, `vercel project rm`, `netlify sites:delete`, `firebase firestore:delete --all-collections`/`database:remove`, `wrangler d1 delete`/`r2 bucket delete`, `railway delete`, `gh`/`glab repo delete`, `npm unpublish`.
- **HTTP APIs**: `curl -X DELETE`, `http DELETE`, `wget --method=DELETE` (catastrophic on `/_all` or `/*`).
- **System**: `shutdown`, `reboot`, `systemctl poweroff`, `kill -1`, `killall5`, `crontab -r`, `userdel`, `iptables -F`, `nft flush ruleset`, `ufw reset`.

Missing a tool your agents use? Open an issue with the command line: the catalog is plain data in
[`src/catalog.ts`](../src/catalog.ts).

## Argument normalization

Before rules run, every string of the arguments (keys included, nested JSON included) is turned into several views, and
`argMatches` matches if any view matches: the raw string; NFKC-normalized, lower case, without invisible characters,
accents and common homoglyphs (Cyrillic and Greek look-alikes); URL-decoded (up to three times); base64-decoded tokens of
12 characters or more; SQL-canonical (comments removed, `CHAR(68,82,…)`, `0x…` and string concatenation decoded);
shell-canonical (line continuations, `$IFS`, empty quotes and `$(echo …)` removed); and each of these with whitespace
squashed.

Write `argMatches` patterns that run in linear time: an agent controls the text they scan. Avoid a quantifier followed
by another that can match the same characters (`\s+.*`, `(a+)+`, `[^;]*\s` after `\s+`), and bound open-ended scans
(`.{0,200}?` instead of `.*`). A pattern that backtracks on a long argument slows every check down; in agent hooks, the MCP
proxy and the SDK, an analysis that exceeds `KYTRAL_ANALYSIS_TIMEOUT_MS` (8 s) is stopped and the call needs a human
(rule `analysis-limit`).

## Examples

```yaml
extends: coding-agent
rules:
  # Never touch the production database, whatever the command or tool.
  - name: protect-production-db
    argMatches: 'prod-db\.internal|db\.prod\.example\.com'
    action: block

  # Allow one routine command the preset would ask about.
  - name: allow-local-db-reset
    argMatches: '^supabase db reset$'
    argFields: [command]
    action: allow

  # Ask before production deploys.
  - name: confirm-deploys
    argMatches: '\b(vercel\s+(deploy\s+)?--prod|fly\s+deploy|firebase\s+deploy|kubectl\s+apply\b.*\b(prod|production)\b)'
    argFields: [command]
    action: confirm

  # Every tool of one MCP server needs a human.
  - name: payments-server
    tool: 'mcp__stripe__*'
    action: confirm

  # At most 5 recipients per e-mail.
  - name: small-mailings
    toolMatches: 'send|mail'
    maxCount: 5
    countArgs: [to, cc, bcc]
    action: confirm
```

Check a policy against commands before deploying it:

```bash
kytral-guard check --policy policy.yaml "supabase db reset"            # ALLOW, exit 0
kytral-guard check --policy policy.yaml "psql -h prod-db.internal"     # BLOCK, exit 2
echo '{"tool":"mcp__stripe__create_refund","args":{}}' | kytral-guard check --policy policy.yaml --json
```
