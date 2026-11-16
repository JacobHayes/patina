# Item 3. Stock Go at the default CPU count (GOMAXPROCS 4), with --preempt branches:
# go-sweep (language runtimes's stall reproducer) and W4 (go-static all): 100 seeds each, no stall, all ok;
# 5 seeds x 20 runs under --vary cpu,load,aslr,sandbox identical, faults off and on.
# No --cpus.
#@ tier=evidence budget=1500 slots=8
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
from concurrent.futures import ThreadPoolExecutor
P = ppatina()
n = int(os.environ.get("COUNTERS_SEEDS", "100"))
VR = int(os.environ.get("COUNTERS_VRUNS", "20"))
fail = []
for name, opts, cmd in [("go-sweep", ["stall-ms=3000"], ["/guest/go-sweep"]),
                        ("w4", [], ["/guest/go-static", "all"])]:
    res = sweep(P, "04/" + name, list(range(1, n + 1)), GO, PMU + opts, cmd)
    c = classes(res)
    d = len({o["digest"] for o in res.values()})
    print(f"{name} at the default CPU count, {n} seeds: {c}; {d} distinct digests; max_skid {skid(res)}")
    if c.get("ok", 0) != n: fail.append(f"{name}: {c}")
    seeds = sorted(s for s, o in res.items() if o["outcome"] == "ok")[:5]
    jobs = [(name, f, s) for f in (False, True) for s in seeds]
    def v(j):
        nm, f, s = j
        return j, verify(P, f"{RUNS}/04/{nm}-d{'f' if f else ''}/seed-{s}", s, GO, VR, "cpu,load,aslr,sandbox",
                         PMU + opts + (FAULT if f else []), cmd)
    with ThreadPoolExecutor(2) as ex:
        for (nm, f, s), (ok, txt) in ex.map(v, jobs):
            print(f"  {nm} seed {s} faults {'on' if f else 'off'}: {('identical (%d runs)' % VR) if ok else 'NOT IDENTICAL'}")
            if not ok: fail.append(f"{nm} seed {s} faults {f}: {txt[-300:]}")
if fail: die("; ".join(fail))
PY
