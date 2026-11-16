#!/bin/sh
# the toolchain tier's syscall-free race b (check-then-act, no system call in the window), stock build,
# counter preemption only: with the race-hunting policy (every segment short) seed 13 finds
# the double spend (evidence-races: 10 of 200 seeds), and 3 varied runs of it are identical.
# SKIP without CAP_PERFMON.
#@ tier=area budget=120 slots=1
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
P = ppatina(required=False)
HUNT = ["pmu-short-permille=1000", "pmu-short-max=64"]
cmd = ["/guest/counters/races", "b"]
ok, txt = verify(P, f"{RUNS}/b-replay", 13, GU, 3, "cpu,aslr,sandbox", HUNT, cmd)
o = outcome(f"{RUNS}/b-replay/run-0") or {}
out = last_line(f"{RUNS}/b-replay/run-0")
print(f"race b, seed 13, hunt policy: {'identical' if ok else 'NOT IDENTICAL'} (3 runs), outcome {o.get('outcome')}, {out!r}")
if not ok: die("not identical: " + txt[-300:])
if "DOUBLE-SPEND" not in out: die("seed 13 no longer finds the double spend")
PY
