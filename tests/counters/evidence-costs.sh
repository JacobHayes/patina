# Item 6. Costs, serially (run on a quiet host for the numbers in docs/EVIDENCE.md): per-trap
# overhead (getppid loop, off/on), per-preemption cost (compute loops: extra wall per stop),
# W1-W9 end-to-end wall off/on (median of 3). Writes $RUNS/07/costs.tsv. Measurement: fails
# only if a run is not ok.
#@ tier=evidence budget=1200 slots=1
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
sys.path.insert(0, os.path.join(os.path.dirname(os.environ["PYTHONPATH"]), "..", "durability", "bench"))
from counters import *
from workloads import WL, ORDER
P = ppatina()
rows = []
def med(patina, name, g, opts, cmd, k=3):
    rs = [run(patina, f"{RUNS}/07/{name}-{i}", 1, g, opts, cmd) for i in range(k)]
    if any(r["outcome"] not in ("ok", "failure", "crash") for r in rs): die(f"{name}: {[r['outcome'] + ' ' + r['message'][:80] for r in rs]}")
    rs.sort(key=lambda r: r["wall_ms"])
    return rs[k // 2]
a = med(P, "traps-off", GU, [], ["/guest/counters/compute", "traps", "10"])
b = med(P, "traps-on", GU, ["pmu=true"], ["/guest/counters/compute", "traps", "10"])
per_trap = (b["wall_ms"] - a["wall_ms"]) * 1e3 / b["sched"]["traps"]
rows.append(("per-trap overhead (us)", f"{per_trap:.2f}", f"{a['wall_ms']} ms off, {b['wall_ms']} ms on, {b['sched']['traps']} traps"))
for p in ["loops", "fp"]:
    a = med(P, p + "-off", GU, [], ["/guest/counters/compute", p])
    b = med(P, p + "-on", GU, ["pmu=true"], ["/guest/counters/compute", p])
    st = b["counters"]["pmu"]
    rows.append((f"per-preemption cost, {p} (ms)", f"{(b['wall_ms'] - a['wall_ms']) / max(st['preempts'], 1):.2f}",
                 f"{a['wall_ms']} ms off, {b['wall_ms']} ms on, {st['preempts']} stops, {st['hops']} hops, {st['landings']} landings"))
for w in ORDER:
    g, cmd, fo, extra = WL[w]
    a = med(P, w + "-off", g, fo + extra, cmd)
    b = med(P, w + "-on", g, ["pmu=true"] + fo + extra, cmd)
    rows.append((f"{w} wall (ms)", f"{a['wall_ms']} -> {b['wall_ms']}", f"x{b['wall_ms'] / max(a['wall_ms'], 1):.2f}, {b['counters']['pmu']['preempts']} stops, {b['sched']['traps']} traps"))
with open(RUNS + "/07/costs.tsv", "w") as f:
    for r in rows:
        f.write("\t".join(r) + "\n")
        print("\t".join(r))
PY
