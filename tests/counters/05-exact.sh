# Exactness at the stop. The same fixed N reached two ways must stop at the same instruction
# with the same registers: by hops only (every conditional branch emulated and counted by the
# runtime: the definition of the stop) and through the hardware counter (overflow aimed at
# N - margin, then hops). With the slice fixed (pmu-slice = N..N, no short slices), the
# preempt records (instruction pointer, N, register hash) and so the digests must be equal.
# N = 3000 (counter period programmed per segment) on seven small programs (six on arm64,
# where every branch is a hop: the floating-point program's 35 million hops alone outlast the
# budget; evidence-compute repeats its stops), N = 1,100,000 (the free-running period,
# overflows, rearm, landing) on two, and on x86_64 bursts at N = 2100: an overflow every few
# microseconds, more than the kernel lets through per tick at the rate it falls to on a loaded
# virtual machine, so it throttles (stops) the counter at overflows ("stopped" counts those
# seen; the arm64 runners measured never throttled it, so there it is left to 08-load). A
# counter run may instead fail closed (stop pmu-late: an overflow interrupt later than the
# margin, seen on virtual machines); it may never differ. A difference prints the first differing record and keeps both runs' logs.
#@ tier=area budget=200 slots=8
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
from concurrent.futures import ThreadPoolExecutor
P = ppatina(required=False)
print(f"perf_event_max_sample_rate {sample_rate()}")
cases = [(3000, 2048, 1024, p) for p in [["loops", "1", "1000"], ["recur", "1", "150"], ["indirect", "1", "100"],
                                        ["strings", "1", "1500"], ["fp", "1", "60"], ["signals", "1", "3000"], ["threads", "1", "1000"]]
         if os.uname().machine == "x86_64" or p[0] != "fp"]
cases += [(1100000, 1100000, 1024, p) for p in [["loops", "1", "40"], ["recur", "1", "30"]]]
cases += [(2100, 2048, 1024, ["bursts", "1"])] if os.uname().machine == "x86_64" else []
def one(c):
    n, mh, mc, p = c
    name = f"{n}-{p[0]}"
    return (name,) + exact(P, f"{RUNS}/10/{name}", n, mh, mc, ["/guest/counters/compute"] + p)
fail, equal = [], 0
with ThreadPoolExecutor(8) as ex:
    for name, v, a, b, ca in ex.map(one, cases):
        sa, sb = a.get("counters", {}).get("pmu", {}), b.get("counters", {}).get("pmu", {})
        print(f"{name}: {v.splitlines()[0]}: hops-only {a['outcome']} {a['digest']} ({sa.get('hops')} hops, {sa.get('alarms')} alarms), "
              f"counter {b['outcome']} {b['digest']} ({sb.get('hops')} hops, {sb.get('alarms')} alarms, {sb.get('landings')} landings, "
              f"{sb.get('stopped')} stopped); {ca} stops")
        if v == "late":
            print(f"  fails closed: {b['message']}")
        elif v != "equal":
            print("  " + "\n  ".join(v.splitlines()[1:]) if "\n" in v else f"  {(b if a['outcome'] == 'ok' else a).get('message')}")
            fail.append(f"{name} {v.splitlines()[0]}")
        elif ca == 0 or sb.get("alarms", 0) == 0 or sa.get("alarms", 1) != 0:
            fail.append(name + " did not exercise both paths")
        else:
            equal += 1
if not equal:
    fail.append("no case compared")
if fail: die("; ".join(fail))
PY
