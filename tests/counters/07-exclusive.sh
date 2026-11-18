# arm64 exclusive accesses under counters (every one emulated). A load- or store-exclusive that
# faults raises the instruction's own fault, SIGSEGV with the program counter still at it (the
# handler maps the page, returns, and the access runs again, still emulated, so the pair stays
# on one monitor and the retry loop ends): it prints what it prints natively. A program with more exclusive instructions than one process's patch
# table holds stops `unsupported`, stop `capacity`, instead of leaving any of them native.
# SKIP without CAP_PERFMON or a supported CPU.
#@ tier=area budget=60 slots=2 arch=aarch64
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
from concurrent.futures import ThreadPoolExecutor
P = ppatina(required=False)
G = GU + "/counters/excl"
# A livelocked retry loop ends at the wall-time bound, not the script's.
opts = PMU + ["timeout=120"]
def one(mode):
    exe = "excl-many" if mode == "many" else "excl"
    return mode, run(P, f"{RUNS}/{mode}", 1, GU, opts, [f"/guest/counters/{exe}", mode])
fail = []
with ThreadPoolExecutor(2) as ex:
    for mode, o in ex.map(one, ["map", "many"]):
        st = o.get("counters", {}).get("pmu", {})
        print(f"{mode}: {o['outcome']} {o.get('stop')} {o['message'][:100]!r}, {o['_last']!r}, preemptions {st.get('preempts')}")
        if mode == "many":
            if (o["outcome"], o.get("stop")) != ("unsupported", "capacity"):
                fail.append(f"many: {o['outcome']} {o.get('stop')}, want unsupported capacity")
            continue
        want = native([G, mode])
        if o["outcome"] != "ok":
            fail.append(f"{mode}: {o['outcome']} {o['message'][:80]}")
        elif o["_last"] != want:
            fail.append(f"{mode}: {o['_last']!r}, natively {want!r}")
if fail: die("; ".join(fail))
PY
