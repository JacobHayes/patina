# Seven compute programs (loops, recursion, indirect calls, string ops, floating
# point, signals in flight, 16 threads), stock gcc builds: per program, one seed, 100 runs
# under --vary cpu,load,aslr,sandbox and 100 runs under --vary parallel (8 sandboxes at once):
# all identical (digest: every preempt record's stop instruction, N, register hash; virtual
# counts), the same digest in both, at least one preemption, checksum equal to native.
#@ tier=evidence budget=1200 slots=8
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
from concurrent.futures import ThreadPoolExecutor
P = ppatina()
progs = ["loops", "recur", "indirect", "strings", "fp", "signals", "threads"]
n = int(os.environ.get("COUNTERS_RUNS", "100"))
os.environ["PATINA_TEST_PARALLEL"] = "8"
seed = 7
# The varied runs: a few programs at once (one sandbox each); the parallel runs: one program
# at a time (8 sandboxes), so at most 8 sandboxes run at any moment.
def vary(p):
    return verify(P, f"{RUNS}/02/{p}-vary", seed, GU, n, "cpu,load,aslr,sandbox", PMU, ["/guest/counters/compute", p])
with ThreadPoolExecutor(int(os.environ.get("COUNTERS_VJOBS", "2"))) as ex:
    va = dict(zip(progs, ex.map(vary, progs)))
pa = {p: verify(P, f"{RUNS}/02/{p}-par", seed, GU, n, "parallel", PMU, ["/guest/counters/compute", p]) for p in progs}
def one(p):
    a, b = va[p], pa[p]
    nat = native([GU + "/counters/compute", p])
    oa, ob = outcome(f"{RUNS}/02/{p}-vary/run-0"), outcome(f"{RUNS}/02/{p}-par/run-0")
    cnt, recs = preempts(f"{RUNS}/02/{p}-vary/run-0/inc-0/boundary.log")
    out = last_line(f"{RUNS}/02/{p}-vary/run-0")
    return p, a, b, oa, ob, cnt, recs, out, nat
fail = []
if True:
    for p, a, b, oa, ob, cnt, recs, out, nat in map(one, progs):
        st = (oa or {}).get("counters", {}).get("pmu", {})
        print(f"{p}: vary {'identical' if a[0] else 'NOT IDENTICAL'} ({n}), parallel {'identical' if b[0] else 'NOT IDENTICAL'} ({n}), "
              f"digest {oa and oa['digest']} / {ob and ob['digest']}, preempt records {cnt}, first stops "
              f"{[(s, hex(r), N) for s, r, N in recs[:2]]}, max_skid {st.get('max_skid')}, output {out!r} native {nat!r}")
        if not (a[0] and b[0]): fail.append(p + " not identical: " + (a[1] if not a[0] else b[1])[-300:])
        elif oa["digest"] != ob["digest"]: fail.append(p + " digests differ between the two verifies")
        elif cnt == 0: fail.append(p + " no preemption")
        elif out != nat: fail.append(p + " output differs from native")
if fail: die("; ".join(fail))
PY
