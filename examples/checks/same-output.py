#!/usr/bin/env python3
"""same-output.py REF [RUN]: `same-output` in Python, a checker that runs either way: a process
per run (RUN is its last argument), or, since this file names PATINA_CHECK_SERVE, one process
per sweep job that reads a line per run and answers one (the loop at the end). Interpreter
start-up is most of a small checker's cost: serving pays it once."""
import filecmp
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def last(run):
    k = 1
    while os.path.isdir(f"{run}/boot-{k + 1}"):
        k += 1
    return f"{run}/boot-{k}"


def check(ref, run):
    """(0, "") passes, (1, "LABEL: detail") is a finding, (77, "CLASS: detail") is not judged,
    (2, "why") an error."""
    if os.environ.get("PATINA_CASE_NAME"):
        ref = f"{ref}/seed-1/{os.environ['PATINA_CASE_NAME']}"
    if not os.path.isdir(f"{last(ref)}"):
        return 77, "no-reference: a reference sweep needs --keep all"
    # The reference had this run's input (same-input.sh); otherwise an error, not a finding.
    same = subprocess.run(
        ["sh", "-c", '. "$0"; same_input "$1" "$2"', f"{HERE}/same-input.sh", ref, run],
        capture_output=True,
        text=True,
    )
    if same.returncode != 0:
        return 2, same.stdout.strip() or same.stderr.strip()
    want = str(json.load(open(f"{ref}/result.json"))["guest"]["exit"])
    if os.environ["PATINA_EXIT"] != want:
        return 1, f"wrong-exit: exit {os.environ['PATINA_EXIT']}, the reference exited {want}"
    if not filecmp.cmp(f"{last(ref)}/stdout", f"{last(run)}/stdout", shallow=False):
        return 1, "wrong-output: stdout differs from the reference's"
    return 0, ""


if os.environ.get("PATINA_CHECK_SERVE"):
    for line in sys.stdin:
        req = json.loads(line)
        os.environ.update(req["env"])
        code, say = check(sys.argv[1], req["rundir"])
        print({0: "pass", 1: f"fail {say}", 77: f"skip {say}", 2: f"error: {say}"}[code], flush=True)
else:
    code, say = check(sys.argv[1], sys.argv[2])
    print(say)
    sys.exit(code)
