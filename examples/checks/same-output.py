#!/usr/bin/env python3
"""same-output.py REF [RUN]: `same-output` in Python, a checker that runs either way: with
`--check`, a process per run (RUN is its last argument); with `--check-serve`, one process per
sweep job that reads a line per run and answers one (the loop at the end). Interpreter start-up
is most of a small checker's cost: serving pays it once."""
import filecmp
import json
import os
import sys


def last(run):
    k = 0
    while os.path.isdir(f"{run}/inc-{k + 1}"):
        k += 1
    return f"{run}/inc-{k}"


def check(ref, run):
    """(0, "") passes, (1, "LABEL: detail") is a finding, (77, "why") is not judged."""
    if os.environ.get("PATINA_CASE_NAME"):
        ref = f"{ref}/seed-1/{os.environ['PATINA_CASE_NAME']}"
    if not os.path.isdir(f"{last(ref)}"):
        return 77, "no reference run (a reference sweep needs --keep all)"
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
        print({0: "pass", 1: f"fail {say}", 77: f"skip {say}"}[code], flush=True)
else:
    code, say = check(sys.argv[1], sys.argv[2])
    print(say)
    sys.exit(code)
