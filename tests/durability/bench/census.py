"""cost measurement outcome census and throughput: SEEDS seeds (default 200) of each workload with its fault
configuration, JOBS (default 8) runs at a time, each run on its own core (cores 0..JOBS-1,
round-robin); counts by outcome, the share of unsupported/internal, and seeds per
second per core (seeds / wall / JOBS). Boundary logs deleted; outcome.json kept for every run.
Usage: census.py [W...]   (W4 runs at --cpus 2; W4@24 is W4 at the default CPU count)
"""
import concurrent.futures as cf
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib  # noqa
from lib import *  # noqa
from workloads import WL, ORDER

SEEDS = int(os.environ.get("SEEDS", "200"))
JOBS = int(os.environ.get("JOBS", "8"))
only = sys.argv[1:] or ORDER
res = {"loadavg_before": uptime(), "seeds": SEEDS, "jobs": JOBS}


def one(w, gdir, argv, opts, seed):
    out = f"{OUT}/{w}/s{seed}"
    cpu = (seed - 1) % JOBS
    shutil.rmtree(out, ignore_errors=True)
    cmd = ["taskset", "-c", str(cpu), PATINA, "run", "--seed", str(seed), "--out", out, "--mount", gdir + ":/guest:copy", *opts, "--", *argv]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)
    try:
        o = json.load(open(f"{out}/outcome.json"))
    except (OSError, ValueError):
        o = {"outcome": "no-outcome", "message": ""}
    prune(out)
    return seed, o


for w in only:
    name = w
    gdir, argv, faults, extra = WL[w.split("@")[0]]
    if w == "W4@24":
        extra = []
    opts = extra + faults
    t0 = time.time()
    counts, details, walls = {}, {}, []
    with cf.ThreadPoolExecutor(JOBS) as ex:
        futs = [ex.submit(one, name, gdir, argv, opts, s) for s in range(1, SEEDS + 1)]
        for f in cf.as_completed(futs):
            s, o = f.result()
            c = o["outcome"]
            counts[c] = counts.get(c, 0) + 1
            if c != "ok":
                d = (o.get("message") or "")[:80]
                details.setdefault(c, {}).setdefault(d, []).append(s)
            if "wall_ms" in o:
                walls.append(o["wall_ms"])
    el = time.time() - t0
    inconcl = sum(counts.get(k, 0) for k in ("unsupported", "internal", "no-outcome"))
    res[name] = {"counts": counts, "inconclusive_share": inconcl / SEEDS, "wall_s": el,
                 "seeds_per_s": SEEDS / el, "seeds_per_s_per_core": SEEDS / el / JOBS,
                 "run_wall_ms": stats(walls) if walls else None,
                 "details": {c: {d: sorted(v)[:12] for d, v in dd.items()} for c, dd in details.items()}}
    log(f"{name} ({' '.join(opts)}): {counts}; unsupported+internal {inconcl}/{SEEDS} = {100 * inconcl / SEEDS:.1f}%; "
        f"{el:.0f} s, {SEEDS / el:.2f} seeds/s, {SEEDS / el / JOBS:.2f} per core")
    for c, dd in res[name]["details"].items():
        for d, ss in dd.items():
            log(f"    {c}: {d!r} seeds {ss}")
res["loadavg_after"] = uptime()
save("census" + ("-" + "-".join(sys.argv[1:]) if sys.argv[1:] else "") + ".json", res)
