#!/bin/sh
# Counter preemption, the mechanism in seconds: the same fixed N reached by hops only (every
# conditional branch emulated and counted by the runtime: the definition of the stop) and
# through the counter (overflow aimed at N - margin, then hops) stops at the same instructions
# with the same registers (equal digests), for N = 3,000 (period per segment) and N = 1,100,000
# (free-running period, rearm, landing); and the default policy gives identical runs under
# --vary cpu,aslr with at least one preemption. SKIP without CAP_PERFMON.
#@ tier=area budget=60 slots=4
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
from concurrent.futures import ThreadPoolExecutor
P = ppatina(required=False)
cases = [(3000, 2048, 512, ["loops", "1", "1000"]), (3000, 2048, 512, ["signals", "1", "3000"]),
         (3000, 2048, 512, ["threads", "1", "1000"]), (1100000, 1100000, 1024, ["loops", "1", "40"])]
def one(c):
    n, mh, mc, p = c
    base = ["pmu-short-permille=0", f"pmu-slice={n}..{n}", "pmu-short-max=1", "stall-ms=600000"]
    name = f"{n}-{p[0]}"
    a = run(P, f"{RUNS}/{name}-hops", 1, GU, base + [f"pmu-margin={mh}"], ["/guest/counters/compute"] + p)
    b = run(P, f"{RUNS}/{name}-counter", 1, GU, base + [f"pmu-margin={mc}"], ["/guest/counters/compute"] + p)
    return name, a, b
fail = []
with ThreadPoolExecutor(4) as ex:
    for name, a, b in ex.map(one, cases):
        sa, sb = a.get("counters", {}).get("pmu", {}), b.get("counters", {}).get("pmu", {})
        print(f"{name}: hops-only {a['outcome']} {a['digest']} ({sa.get('preempts')} stops, {sa.get('alarms')} overflows), "
              f"counter {b['outcome']} {b['digest']} ({sb.get('preempts')} stops, {sb.get('alarms')} overflows)")
        if a["outcome"] != "ok" or b["outcome"] != "ok": fail.append(name + " not ok")
        elif a["digest"] != b["digest"]: fail.append(name + " stops differ")
        elif not sa.get("preempts") or not sb.get("alarms") or sa.get("alarms"): fail.append(name + " did not exercise both paths")
ok, txt = verify(P, f"{RUNS}/verify", 7, GU, 3, "cpu,aslr", ["pmu=true"], ["/guest/counters/compute", "loops"])
o = outcome(f"{RUNS}/verify/run-0") or {}
print(f"default policy, loops: {'identical' if ok else 'NOT IDENTICAL'} (3 runs), preemptions {o.get('counters', {}).get('pmu', {}).get('preempts')}")
if not ok: fail.append("verify: " + txt[-300:])
elif not o.get("counters", {}).get("pmu", {}).get("preempts"): fail.append("no preemption under the default policy")
if fail: die("; ".join(fail))
PY
