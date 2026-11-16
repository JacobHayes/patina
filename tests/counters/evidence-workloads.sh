# Item 5. W1-W9 (determinism hardening/cost measurement's commands and fault configurations; W4 at the default CPU count)
# with --pmu: 3 runs under --vary cpu,aslr,sandbox identical; 3 seeds give 3 distinct digests.
#@ tier=evidence budget=900 slots=3
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
sys.path.insert(0, os.path.join(os.path.dirname(os.environ["PYTHONPATH"]), "..", "durability", "bench"))
from counters import *
from workloads import WL, ORDER
from concurrent.futures import ThreadPoolExecutor
P = ppatina()
def one(w):
    g, cmd, fo, extra = WL[w]
    extra = [] if w == "W4" else extra
    ok, txt = verify(P, f"{RUNS}/06/{w}-verify", 1, g, 3, "cpu,aslr,sandbox", ["--pmu"] + fo + extra, cmd)
    o = outcome(f"{RUNS}/06/{w}-verify/run-0") or {}
    ds = [run(P, f"{RUNS}/06/{w}-s{s}", s, g, ["--pmu"] + fo + extra, cmd)["digest"] for s in (2, 3)]
    return w, ok, txt, o, [o.get("digest")] + ds
fail = []
with ThreadPoolExecutor(3) as ex:
    for w, ok, txt, o, ds in ex.map(one, ORDER):
        st = o.get("pmu_stats", {})
        print(f"{w}: {'identical' if ok else 'NOT IDENTICAL'} (3 runs), class {o.get('class')}, preempts {st.get('preempts')}, "
              f"segments {st.get('segments')}, distinct digests over seeds 1-3: {len(set(ds))}")
        if not ok: fail.append(f"{w}: {txt[-300:]}")
        if len(set(ds)) < 3: fail.append(f"{w}: seeds 1-3 give {len(set(ds))} digests")
if fail: die("; ".join(fail))
PY
