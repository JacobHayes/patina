# The spin table, unrebuilt binaries, the holder making a call inside the critical
# section: glibc pthread_spin_lock, a C test-and-set lock, a Rust spin_loop lock. 100 seeds
# each with --preempt branches (stall-ms = 2000): no stall, every run ok with the right count.
#@ tier=evidence budget=3600 slots=8 arch=x86_64
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
P = ppatina()
n = int(os.environ.get("COUNTERS_SEEDS", "100"))
fail = []
for name, cmd, want in [("glibc-spin", ["/guest/spinwait", "glibc-spin"], "counter=4000"),
                        ("own-spin", ["/guest/spinwait", "own-spin"], "counter=4000"),
                        ("rs-spin", ["/guest/rs-spin", "spin"], "counter=4000")]:
    res = sweep(P, "03/" + name, list(range(1, n + 1)), GU, PMU + ["stall-ms=2000"], cmd)
    c = classes(res)
    walls = sorted(o["wall_ms"] for o in res.values())
    print(f"{name}: {c}, wall median {walls[len(walls)//2]} ms max {walls[-1]} ms, max_skid {skid(res)}")
    if c.get("ok", 0) != n: fail.append(f"{name}: {c}")
    if want and any(want not in o["_last"] for o in res.values()): fail.append(f"{name}: wrong count")
if fail: die("; ".join(fail))
PY
