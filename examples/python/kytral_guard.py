"""Guard the tools of a Python agent (LangChain, CrewAI, LlamaIndex, your own loop) with Kytral Guard.

No Python package needed: each call is checked by the kytral-guard CLI, which answers with JSON.
Requires Node.js 22+ and:  npm install -g kytral-guard && kytral-guard init

    python kytral_guard.py
"""
import json
import os
import shlex
import shutil
import subprocess
from functools import wraps

# The CLI: KYTRAL_GUARD_CMD (e.g. "node /path/to/kytral-guard/dist/cli.js"), else kytral-guard on PATH (.cmd shim on Windows too).
KYTRAL = shlex.split(os.environ["KYTRAL_GUARD_CMD"], posix=os.name != "nt") if os.environ.get("KYTRAL_GUARD_CMD") else [shutil.which("kytral-guard")]


class KytralBlocked(Exception):
    """The guard refused the call (or could not decide: it fails closed)."""


def check(tool: str, args: dict) -> dict:
    """Asks Kytral Guard about one tool call: {"action": "allow" | "confirm" | "block", "rule": ..., "reason": ...}."""
    if not KYTRAL[0]:
        raise KytralBlocked("kytral-guard is not installed (npm install -g kytral-guard)")
    proc = subprocess.run([*KYTRAL, "hook", "generic"], input=json.dumps({"tool": tool, "args": args}),
                          capture_output=True, text=True, timeout=30)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise KytralBlocked(f"Kytral Guard did not answer (exit {proc.returncode}): {proc.stderr.strip()}")


def guarded(tool_name: str, ask=lambda reason: input(f"Kytral Guard: {reason}. Run it? [y/N] ").strip().lower() == "y"):
    """Decorator: the function runs only if Kytral Guard allows the call, or a human confirms it."""
    def decorate(fn):
        @wraps(fn)
        def wrapper(**kwargs):
            decision = check(tool_name, kwargs)
            if decision["action"] == "block":
                raise KytralBlocked(decision["reason"])
            if decision["action"] == "confirm" and not ask(decision["reason"]):
                raise KytralBlocked(f"not confirmed: {decision['reason']}")
            return fn(**kwargs)
        return wrapper
    return decorate


@guarded("run_shell")
def run_shell(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@guarded("run_sql")
def run_sql(sql: str) -> str:
    return f"(pretend we ran) {sql}"


if __name__ == "__main__":
    print(run_shell(command="echo hello from a guarded tool"))
    print(run_sql(sql="SELECT * FROM users WHERE id = 7"))
    for attempt in (lambda: run_shell(command="rm -rf ~"), lambda: run_sql(sql="DELETE FROM users")):
        try:
            attempt()
        except KytralBlocked as e:
            print("blocked:", e)
