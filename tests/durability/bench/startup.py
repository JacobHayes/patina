"""cost measurement cost: per-run start-up, broken into phases, for a static `true`, the dynamic
/usr/bin/true and `python3 -c pass`. PATINA_TIMING=1 makes the launcher print host CLOCK_MONOTONIC
marks of its own and of the supervisor (Ctl::timing). REPS runs each, median [min..max] ms:

  launcher setup       launch -> spawn        run directory, logs, control memfd, /etc files
  bwrap + sup exec     spawn -> sup_start     namespaces, mounts, exec of the supervisor
  sup start, /in copy  sup_start -> copied    wire init, stdio ids, /in copy, base records
  runtime start        copied -> first_hello  fork, exec of the runtime, its start-up
  load + guest         first_hello -> main_exit  image load (scan) and the guest's own run
  exit barrier         main_exit -> finish
  kill + export        finish -> exported     kill(-1), reap, live-tree export
  teardown             exported -> waited     verdict write, bwrap and namespaces exit
  launcher finish      waited -> done, plus the rest of the process (result.json)
  total (process)      wall of the patina process

Native for comparison: the same program pinned, exec'd directly and inside bwrap (native.sh).
"""
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import *  # noqa

progs = {
    "static true": ["/guest/true-static"],
    "dynamic true": ["/usr/bin/true"],
    "python3 -c pass": ["/usr/bin/python3", "-c", "pass"],
}
phases = [("launcher setup", "launch", "spawn"), ("bwrap + sup exec", "spawn", "sup_start"),
          ("sup start, /in copy", "sup_start", "copied"), ("runtime start", "copied", "first_hello"),
          ("load + guest", "first_hello", "main_exit"), ("exit barrier", "main_exit", "finish"),
          ("kill + export", "finish", "exported"), ("teardown", "exported", "waited"),
          ("launcher finish", "waited", "done")]
res = {"loadavg_before": uptime(), "cpu": CPU, "reps": REPS}
for name, argv in progs.items():
    rows = {p[0]: [] for p in phases}
    tot, traps = [], None
    for i in range(REPS):
        out = f"{OUT}/su"
        shutil.rmtree(out, ignore_errors=True)
        e = dict(os.environ, PATINA_TIMING="1")
        t0 = time.perf_counter_ns()
        r = subprocess.run(["taskset", "-c", str(CPU), PATINA, "run", "--seed", "1", "--out", out, "--mount", GUESTS + ":/guest:copy", "--", *argv],
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=e, text=True)
        t1 = time.perf_counter_ns()
        line = [l for l in r.stderr.splitlines() if l.startswith("patina-timing")][0]
        m = dict(re.findall(r"(\w+)=(\d+)", line))
        m = {k: int(v) for k, v in m.items()}
        for p, a, b in phases:
            rows[p].append((m[b] - m[a]) / 1e6)
        tot.append((t1 - t0) / 1e6)
        o = json.load(open(f"{out}/result.json"))
        assert o["outcome"] == "ok", o
        traps = o["sched"]["traps"]
    nat_direct = [native_run(f"{OUT}/nd", [a if not a.startswith("/guest/") else GUESTS + a[6:] for a in argv],
                             sandbox=False)[0] for _ in range(REPS)]
    nat_bwrap = [native_run(f"{OUT}/nb", argv)[0] for _ in range(REPS)]
    r = {p: stats(v) for p, v in rows.items()}
    r["total (process)"] = stats(tot)
    r["native exec"] = stats(nat_direct)
    r["native in bwrap"] = stats(nat_bwrap)
    r["sched"]["traps"] = traps
    res[name] = r
    log(f"== {name} ({traps} traps)")
    for k, v in r.items():
        if k != "traps":
            log(f"  {k:22s} {fmt(v, ' ms', 2)}")
res["loadavg_after"] = uptime()
save("startup.json", res)
log("loadavg", res["loadavg_before"], "->", res["loadavg_after"])
