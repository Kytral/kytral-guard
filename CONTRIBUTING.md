# Contributing to Kytral Guard

Thanks for helping make AI agents safer. The most useful contributions are often the smallest: a destructive command we
miss, a routine command we block, a CLI that belongs in the catalog.

## Report a gap

- **Missed catastrophe**: a command or tool call that should be blocked or confirmed but is allowed. Use the "Missed
  catastrophe" issue template and give the exact command line and the output of `kytral-guard check --json "<command>"`.
- **False positive**: a routine command that is blocked or confirmed. Same, with the "False positive" template.
- **Bug**: something that does not work as documented. Use the "Bug report" form and paste the output of
  `kytral-guard doctor --report`, which is redacted for a public issue (plain `kytral-guard doctor` is not).
- **Vulnerability of the guard itself** (forged approvals, failing open, audit tampering): never in a public issue, see
  [SECURITY.md](SECURITY.md).

## Develop

Requirements: Node.js 22.22.3 or later on the 22 line, or 24.11.1 or later. The test suite runs the TypeScript sources
through tsx, which loads them in worker threads only from these versions on: below them every test that analyzes a call in
a worker fails (`Cannot find module '…/src/policy.js'` in the worker). The published package (`dist/`) needs Node.js 22 or
later.

```bash
git clone https://github.com/Kytral/kytral-guard.git
cd kytral-guard
npm ci
npm run build
npm test                         # every test/*.test.ts, in a fresh KYTRAL_HOME
npm test -- test/catastrophe-catalog.test.ts    # one file
node dist/cli.js check "terraform destroy"      # try the CLI
```

The tests run on Linux, macOS and Windows in CI; tests of POSIX file modes are skipped on Windows.

## Where things are

| File | What |
|---|---|
| `src/analyze.ts` | shell tokenizer and analyzer, SQL analyzer, wrappers, runners, remote execution |
| `src/catalog.ts` | catalog of destructive CLIs (infrastructure, cloud, databases, ORMs, hosting, system) |
| `src/paths.ts` | classification of deletion and overwrite targets |
| `src/windows.ts` | PowerShell and cmd.exe analyzer |
| `src/normalize.ts` | argument normalization (Unicode, encodings, SQL and shell canonical forms) |
| `src/policy.ts` | policy format, evaluation, presets |
| `src/hooks.ts` | agent hook adapters; `src/install.ts`: `init` / `uninstall` |
| `src/guard.ts`, `src/proxy.ts`, `src/badge.ts` | SDK guard, MCP proxy, badges |
| `src/audit.ts`, `src/kill-switch.ts`, `src/confirm-queue.ts`, `src/known-tools.ts`, `src/store.ts` | audit log, kill switch, confirmation queue, grants, state files |

## Add a command to the catalog

1. Add a check in `src/catalog.ts` (a function of the arguments that returns a catastrophic or destructive finding, or
   `null`). Use `positionals()` with the CLI's options that take a value, so `tool --profile prod delete x` is read right.
2. Add the dangerous forms to `CATASTROPHIC` or `DESTRUCTIVE`, and the routine forms of the same CLI to `HARMLESS`, in
   `test/catastrophe-catalog.test.ts`.
3. Document it in the catalog list of `docs/policy.md`.

## Rules of the house

- **Fail closed.** When the guard cannot decide, the answer is a refusal or a human confirmation, never an allow.
- **Never weaken a bypass test.** Tests named `bypass*` and the catastrophic corpus are regressions of real bypasses:
  a change that makes one of them pass the other way is a regression, whatever the reason. Open limits stay as `todo`
  tests.
- **Every new detection comes with its false-positive tests.** A guard that blocks routine work gets uninstalled.
- **Never journal arguments**, and never print secrets.
- Code style: TypeScript strict, ESM, no new runtime dependency without discussion; comments explain why.
- Commits: [Conventional Commits](https://www.conventionalcommits.org/) (`feat(catalog): …`, `fix(hooks): …`).

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
