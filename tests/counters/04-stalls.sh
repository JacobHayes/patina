#!/bin/sh
# Spin-waits that stall without counter preemption run to the end with it: one seed each of
# the spin table (glibc pthread_spin_lock, a C test-and-set lock, a Rust spin_loop lock, the
# holder making a call inside the critical section) and of stock Go at the default CPU count
# (go-sweep, the Go stall reproducer, and W4). The 100-seed sweeps are evidence-spin and
# evidence-go. SKIP without CAP_PERFMON.
#@ tier=area budget=280 slots=5
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
from concurrent.futures import ThreadPoolExecutor
P = ppatina(required=False)
cases = [("glibc-spin", GU, ["stall-ms=2000"], ["/guest/spinwait", "glibc-spin"], "counter=4000"),
         ("own-spin", GU, ["stall-ms=2000"], ["/guest/spinwait", "own-spin"], "counter=4000"),
         ("rs-spin", GU, ["stall-ms=2000"], ["/guest/rs-spin", "spin"], "counter=4000"),
         ("go-sweep", GO, ["stall-ms=3000"], ["/guest/go-sweep"], None),
         ("w4", GO, [], ["/guest/go-static", "all"], None)]
def one(c):
    name, g, opts, cmd, want = c
    return c, run(P, f"{RUNS}/{name}", 1, g, PMU + opts, cmd)
fail = []
with ThreadPoolExecutor(5) as ex:
    for (name, g, opts, cmd, want), o in ex.map(one, cases):
        print(f"{name} seed 1: {o['outcome']} {o['message'][:60]} wall {o['wall_ms']} ms, "
              f"preemptions {o.get('counters', {}).get('pmu', {}).get('preempts')}, {o['_last'][:40]!r}")
        if o["outcome"] != "ok": fail.append(f"{name}: {o['outcome']} {o['message'][:80]}")
        elif want and want not in o["_last"]: fail.append(f"{name}: wrong output")
if fail: die("; ".join(fail))
PY
