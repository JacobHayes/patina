"""cost measurement cost: end to end, every workload W1-W9: wall time native, under patina with faults off and
with the workload's fault configuration; traps (syscalls seen) and switches per run alongside.

REPS runs of each (median [min..max]), seed = rep number (1..REPS), pinned to CPU. Native is
the same command in a bwrap sandbox shaped like patina's (tests/files/lib/native.sh), pinned to the
same core (Go then sees one CPU). One extra native run per workload under strace -f -c gives
the native system-call count. Usage: e2e.py [W...]
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import *  # noqa
from workloads import WL, ORDER

only = sys.argv[1:] or ORDER
res = {"loadavg_before": uptime(), "cpu": CPU, "reps": REPS}
for w in only:
    gdir, argv, faults, extra = WL[w]
    row = {}
    nat = []
    for i in range(REPS):
        t, rc = native_run(f"{OUT}/{w}-nat", argv, guest=gdir)
        nat.append(t)
    row["native_ms"] = stats(nat)
    row["native_exit"] = rc
    # native system-call count
    os.environ["STRACE"] = "1"
    native_run(f"{OUT}/{w}-strace", argv, guest=gdir)
    del os.environ["STRACE"]
    try:
        txt = open(f"{OUT}/{w}-strace/strace").read()
        # strace -c's total line: % time, seconds, usecs/call, calls, errors, "total"
        m = re.search(r"^\s*100\.00\s+\S+\s+\S+\s+(\d+)\s+(\d+)?\s*total", txt, re.M)
        row["native_syscalls"] = int(m.group(1)) if m else None
    except OSError:
        row["native_syscalls"] = None
    for key, opts in (("off", extra), ("on", extra + faults)):
        walls, exts, traps, sws, classes, incs = [], [], [], [], {}, []
        for i in range(REPS):
            o = patina_run(f"{OUT}/{w}-{key}", argv, guest=gdir, opts=["--seed", str(i + 1), *opts])
            walls.append(o["wall_ms"])
            exts.append(o["ext_ms"])
            traps.append(o["sched"]["traps"])
            sws.append(o["sched"]["switches"])
            incs.append(o["incarnations"])
            classes[o["outcome"]] = classes.get(o["outcome"], 0) + 1
        row[key] = {"wall_ms": stats(walls), "ext_ms": stats(exts), "traps": stats(traps),
                    "switches": stats(sws), "incarnations": stats(incs), "classes": classes}
    res[w] = row
    log(f"{w}: native {fmt(row['native_ms'], ' ms', 0)} (exit {rc}, {row['native_syscalls']} syscalls); "
        f"patina off {fmt(row['off']['wall_ms'], ' ms', 0)} traps {row['off']['traps']['median']:.0f} "
        f"switches {row['off']['switches']['median']:.0f} {row['off']['classes']}; "
        f"patina on {fmt(row['on']['wall_ms'], ' ms', 0)} traps {row['on']['traps']['median']:.0f} "
        f"switches {row['on']['switches']['median']:.0f} incarnations {row['on']['incarnations']['median']:.0f} {row['on']['classes']}")
res["loadavg_after"] = uptime()
save("e2e" + ("-" + "-".join(sys.argv[1:]) if sys.argv[1:] else "") + ".json", res)
log("loadavg", res["loadavg_before"], "->", res["loadavg_after"])
