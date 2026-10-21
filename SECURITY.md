# Security policy

Kytral Guard is a security tool, so reports of security problems in it come first.

## Reporting a vulnerability

Report it privately, either by email to **security@kytral.com** or with GitHub private vulnerability reporting: open the
**Security** tab of this repository, then **Report a vulnerability**.

Never report a vulnerability in a public issue, discussion, pull request or comment. If you are not sure whether something is a
vulnerability, report it privately: we will tell you if it can go to a public issue.

Examples of what to report privately: a way to forge or replay a badge, an approval, a known-tools grant or a kill switch
state without the deployment secret; to lift the kill switch or make a guard (an agent hook, a proxy, the SDK) accept calls
while it is engaged; to modify, delete or truncate audit entries without `kytral-guard audit verify` noticing; to make the
guard fail open (a crash, a hang, an input that slows the analysis past the agent's hook timeout, or an input that lets a call
run without a decision); or to run code or write files through the guard itself (policy loading, hooks, the installer, the
proxy).

## What to include

- The Kytral Guard version, and how it runs: an agent hook (with which agent), the MCP proxy (with which client), or the SDK.
- The output of `kytral-guard doctor --report`, if the setup matters. It is redacted: no secrets, variable values, audit
  entries, tool arguments, user or host names, or full paths.
- The steps, input or proof of concept that reproduce the problem, what happened, and what you expected.
- The impact as you see it: what an attacker gains, and what they need first (local access, the same OS account, a secret...).
- Whether you want to be credited, and under which name or handle.

Do not send real secrets, badges, audit logs or production data: use test values, or redact them.

## What happens next

We aim to:

- acknowledge your report within 2 business days;
- give you an initial assessment (confirmed or not, and its severity) within 7 days;
- fix or mitigate a critical issue within 30 days.

We keep you informed until the issue is fixed. Disclosure is coordinated: we agree on a date with you, then publish a
security advisory with the fixed version, crediting you if you want to be credited. Please keep the issue confidential
until then.

## Report publicly

A destructive command the analyzers miss (a "missed catastrophe") or a routine command they block (a "false positive")
is not a vulnerability of the guard: it is a gap in its coverage, and public reports help everyone add it to their
policies right away. Use the issue forms. If a bypass is severe and generic (it defeats a whole analyzer), report it
privately instead.

## Supported versions

Security fixes go to the current minor release. Please upgrade to it before reporting.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| < 0.1 | No |

## Scope and limits

The threat model, including what Kytral Guard does not protect against (for example a determined process running as the
same OS user), is in [docs/threat-model.md](docs/threat-model.md); what differs on Windows (file permissions, symbolic
links, what is not tested there) is in its [Windows](docs/threat-model.md#windows) section.
