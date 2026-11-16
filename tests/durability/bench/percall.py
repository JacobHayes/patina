"""cost measurement cost: per call, by class, native vs patina; and boundary logging on vs compiled out.

Per call = (wall(N) - wall(0)) / N for one run each, repeated REPS times: median [min..max].
patina: the launcher's wall_ms; --preempt-permille 0 (capture + handler + record, plus the
supervisor round trip the class itself needs) and the default 100 (adds the seeded yields).
nolog: the same with a runtime built with --cfg patina_nolog (no record, no buffer hashing),
PATINA_RT_NOLOG. Native: the same static binary pinned to the same core, outside any sandbox
(the per-call cost of a system call does not depend on the namespaces).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import *  # noqa

NOLOG = os.environ.get("PATINA_RT_NOLOG")
cases = [  # mode, N under patina, N native
    ("getppid", 1_000_000, 10_000_000),
    ("clock", 1_000_000, 10_000_000),
    ("pipe", 200_000, 2_000_000),
    ("futex-wake", 1_000_000, 10_000_000),
    ("futex-pair", 100_000, 1_000_000),
    ("yield", 1_000_000, 10_000_000),
]
only = sys.argv[1:] or [c[0] for c in cases]
res = {"loadavg_before": uptime(), "cpu": CPU, "reps": REPS}
for mode, n, nn in cases:
    if mode not in only:
        continue
    nat = []
    for i in range(REPS):
        t1, r1 = native_run(f"{OUT}/nat", [f"{GUESTS}/costs", mode, str(nn)], sandbox=False)
        t0, r0 = native_run(f"{OUT}/nat", [f"{GUESTS}/costs", mode, "0"], sandbox=False)
        assert r1 == 0 and r0 == 0, (mode, r1, r0)
        nat.append((t1 - t0) * 1e6 / nn)
    row = {"native_ns": stats(nat)}
    configs = [("patina_p0_ns", ["--preempt-permille", "0"], None), ("patina_p100_ns", [], None)]
    if NOLOG:
        configs.append(("nolog_p0_ns", ["--preempt-permille", "0"], NOLOG))
    for key, opts, rt in configs:
        xs, traps, sw = [], None, None
        for i in range(REPS):
            o1 = patina_run(f"{OUT}/patina", ["/guest/costs", mode, str(n)], opts=opts, rt=rt)
            o0 = patina_run(f"{OUT}/patina0", ["/guest/costs", mode, "0"], opts=opts, rt=rt)
            assert o1["class"] == "ok" and o0["class"] == "ok", (mode, key, o1["class"], o1.get("detail"))
            xs.append((o1["wall_ms"] - o0["wall_ms"]) * 1e6 / n)
            traps = (o1["traps"] - o0["traps"]) / n
            sw = (o1["switches"] - o0["switches"]) / n
        row[key] = stats(xs)
        row[key + "_traps_per_iter"] = traps
        row[key + "_switches_per_iter"] = sw
    res[mode] = row
    log(f"{mode}: native {fmt(row['native_ns'], ' ns', 1)}; patina p0 {fmt(row['patina_p0_ns'], ' ns', 0)} "
        f"({row['patina_p0_ns_traps_per_iter']:.2f} traps, {row['patina_p0_ns_switches_per_iter']:.2f} switches per iteration); "
        f"patina p100 {fmt(row['patina_p100_ns'], ' ns', 0)}"
        + (f"; nolog p0 {fmt(row['nolog_p0_ns'], ' ns', 0)}" if NOLOG else ""))
res["loadavg_after"] = uptime()
save("percall" + ("-" + "-".join(sys.argv[1:]) if sys.argv[1:] else "") + ".json", res)
log("loadavg", res["loadavg_before"], "->", res["loadavg_after"])
