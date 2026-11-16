"""Is the Go stall one quirk or a class? Busy-wait patterns under scheduling at system calls
only (stock builds). SEEDS seeds each (default 20), --stall-ms 2000. Also native: each pattern 20 times, pinned to 2 cores, must finish.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import *  # noqa

SEEDS = int(os.environ.get("SEEDS", "20"))
cases = [
    ("C pthread_spin_lock, call inside", ["/guest/spinwait", "glibc-spin"], []),
    ("C own spin lock, call inside", ["/guest/spinwait", "own-spin"], []),
    ("C own spin lock, no call inside", ["/guest/spinwait", "own-spin-nocall"], []),
    ("C spin 100 then sched_yield", ["/guest/spinwait", "bounded"], []),
    ("C pthread_mutex", ["/guest/spinwait", "mutex"], []),
    ("Rust spin lock (spin_loop), call inside", ["/guest/rs-spin", "spin"], []),
    ("Rust std Mutex", ["/guest/rs-spin", "mutex"], []),
]
res = {"seeds": SEEDS}
for name, argv, opts in cases:
    counts, walls = {}, []
    for s in range(1, SEEDS + 1):
        o = patina_run(f"{OUT}/sp", argv, opts=["--seed", str(s), "--stall-ms", "2000", *opts])
        counts[o["class"]] = counts.get(o["class"], 0) + 1
        if o["class"] == "ok":
            walls.append(o["wall_ms"])
    nat_ok = 0
    if not opts:
        for i in range(5):
            _, rc = native_run(f"{OUT}/nat", [GUESTS + argv[0][6:], *argv[1:]], sandbox=False)
            nat_ok += rc == 0
    res[name] = {"counts": counts, "ok_wall_ms": stats(walls) if walls else None, "native_ok_of_5": nat_ok}
    log(f"{name}: {counts}" + (f", ok runs {fmt(stats(walls), ' ms', 0)}" if walls else "")
        + ("" if opts else f"; native {nat_ok}/5 ok"))
save("spin.json", res)
