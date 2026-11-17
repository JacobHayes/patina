# Exactness at the stop. The same fixed N reached two ways must stop at the same instruction
# with the same registers: by hops only (every conditional branch emulated and counted by the
# runtime: the definition of the stop) and through the hardware counter (overflow aimed at
# N - margin, then hops). With the slice fixed (pmu-slice = N..N, no short slices), the
# preempt records (instruction pointer, N, register hash) and so the digests must be equal.
# N = 3000 (counter period programmed per segment) on seven small programs, and N = 1,100,000
# (the free-running period, overflows, rearm, landing) on two.
#@ tier=area budget=200 slots=8 arch=x86_64
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
from concurrent.futures import ThreadPoolExecutor
P = ppatina(required=False)
cases = [(3000, 2048, 512, p) for p in [["loops", "1", "1000"], ["recur", "1", "150"], ["indirect", "1", "100"],
                                       ["strings", "1", "1500"], ["fp", "1", "60"], ["signals", "1", "3000"], ["threads", "1", "1000"]]]
cases += [(1100000, 1100000, 1024, p) for p in [["loops", "1", "40"], ["recur", "1", "30"]]]
def one(c):
    n, mh, mc, p = c
    base = ["pmu-short-permille=0", f"pmu-slice={n}..{n}", "pmu-short-max=1", "stall-ms=600000"]
    name = f"{n}-{p[0]}"
    a = run(P, f"{RUNS}/10/{name}-hops", 1, GU, base + [f"pmu-margin={mh}"], ["/guest/counters/compute"] + p, keep=True)
    b = run(P, f"{RUNS}/10/{name}-counter", 1, GU, base + [f"pmu-margin={mc}"], ["/guest/counters/compute"] + p, keep=True)
    ca, _ = preempts(f"{RUNS}/10/{name}-hops/inc-0/boundary.log")
    for d in ("hops", "counter"):
        prune(f"{RUNS}/10/{name}-{d}")
    return name, a, b, ca
fail = []
with ThreadPoolExecutor(8) as ex:
    for name, a, b, ca in ex.map(one, cases):
        sa, sb = a.get("counters", {}).get("pmu", {}), b.get("counters", {}).get("pmu", {})
        print(f"{name}: hops-only {a['outcome']} {a['digest']} ({sa.get('hops')} hops, {sa.get('alarms')} alarms), "
              f"counter {b['outcome']} {b['digest']} ({sb.get('hops')} hops, {sb.get('alarms')} alarms, {sb.get('landings')} landings); {ca} stops")
        if a["outcome"] != "ok" or b["outcome"] != "ok": fail.append(name + " not ok")
        elif a["digest"] != b["digest"]: fail.append(name + " stops differ")
        elif ca == 0 or sb.get("alarms", 0) == 0 or sa.get("alarms", 1) != 0: fail.append(name + " did not exercise both paths")
if fail: die("; ".join(fail))
PY
