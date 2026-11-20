# Counter preemption, the mechanism in seconds: the same fixed N reached by hops only (every
# conditional branch emulated and counted by the runtime: the definition of the stop) and
# through the counter (overflow aimed at N - margin, then hops) stops at the same instructions
# with the same registers (equal digests), for N = 3,000 (period per segment) and N = 1,100,000
# (free-running period, rearm, landing), or the counter run fails closed (stop pmu-late, an
# overflow interrupt later than the margin); and the default policy gives identical runs under
# --vary cpu,aslr with at least one preemption. SKIP without CAP_PERFMON.
#@ tier=area budget=60 slots=4
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
from concurrent.futures import ThreadPoolExecutor
P = ppatina(required=False)
cases = [(3000, 2048, 1024, ["loops", "1", "1000"]), (3000, 2048, 1024, ["signals", "1", "3000"]),
         (3000, 2048, 1024, ["threads", "1", "1000"]), (1100000, 1100000, 1024, ["loops", "1", "40"])]
def one(c):
    n, mh, mc, p = c
    name = f"{n}-{p[0]}"
    return (name,) + exact(P, f"{RUNS}/{name}", n, mh, mc, ["/guest/counters/compute"] + p)
fail, equal = [], 0
with ThreadPoolExecutor(4) as ex:
    for name, v, a, b, _ in ex.map(one, cases):
        sa, sb = a.get("counters", {}).get("pmu", {}), b.get("counters", {}).get("pmu", {})
        print(f"{name}: {v.splitlines()[0]}: hops-only {a['outcome']} {a['digest']} ({sa.get('preempts')} stops, {sa.get('alarms')} overflows), "
              f"counter {b['outcome']} {b['digest']} ({sb.get('preempts')} stops, {sb.get('alarms')} overflows)")
        if v == "late":
            print(f"  fails closed: {b['message']}")
        elif v != "equal":
            print("  " + "\n  ".join(v.splitlines()[1:]) if "\n" in v else f"  {(b if a['outcome'] == 'ok' else a).get('message')}")
            fail.append(f"{name} {v.splitlines()[0]}")
        elif not sa.get("preempts") or not sb.get("alarms") or sa.get("alarms"):
            fail.append(name + " did not exercise both paths")
        else:
            equal += 1
if not equal:
    fail.append("no case compared")
ok, txt = verify(P, f"{RUNS}/verify", 7, GU, 3, "cpu,aslr", PMU, ["/guest/counters/compute", "loops"])
o = outcome(f"{RUNS}/verify/run-0") or {}
print(f"default policy, loops: {'identical' if ok else 'NOT IDENTICAL'} (3 runs), preemptions {o.get('counters', {}).get('pmu', {}).get('preempts')}")
if not ok: fail.append("verify: " + txt[-300:])
elif not o.get("counters", {}).get("pmu", {}).get("preempts"): fail.append("no preemption under the default policy")
if fail: die("; ".join(fail))
PY
