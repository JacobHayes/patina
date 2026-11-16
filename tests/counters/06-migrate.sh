# Hazard: CPU migration inside a run. patina pins a sandbox to one CPU; here a second thread moves
# every task of the run to a random CPU every 2 ms while it runs (counters are per task, so
# they must follow). 5 runs each of four programs must equal an unperturbed run.
#@ tier=area budget=200 slots=2
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, random, subprocess, sys, threading, time
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
P = ppatina()
cpus = sorted(os.sched_getaffinity(0))
def tasks(root):
    kids = {}
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                pp = int(open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()[1])
            except (OSError, IndexError, ValueError):
                continue
            kids.setdefault(pp, []).append(int(p))
    out, todo = [], [root]
    while todo:
        p = todo.pop()
        try:
            out += [int(t) for t in os.listdir(f"/proc/{p}/task")]
        except OSError:
            pass
        todo += kids.get(p, [])
    return out
def moved(out, cmd):
    subprocess.run(["rm", "-rf", out])
    pr = subprocess.Popen([P, "run", "--seed", "3", "--pmu", "--out", out, "--guest", GU, "--"] + cmd,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    n = 0
    rnd = random.Random(len(out))
    while pr.poll() is None:
        for t in tasks(pr.pid):
            try:
                os.sched_setaffinity(t, {rnd.choice(cpus)})
                n += 1
            except OSError:
                pass
        time.sleep(0.002)
    o = outcome(out) or {"class": "none", "digest": "-"}
    prune(out)
    return o, n
fail = []
for p in ["loops", "strings", "fp", "threads"]:
    cmd = ["/guest/counters/compute", p]
    ref = run(P, f"{RUNS}/11/{p}-ref", 3, GU, ["--pmu"], cmd)
    res = [moved(f"{RUNS}/11/{p}-m{i}", cmd) for i in range(5)]
    same = sum(o["digest"] == ref["digest"] and o["class"] == "ok" for o, _ in res)
    print(f"{p}: reference {ref['class']} {ref['digest']} ({ref['pmu_stats']['preempts']} stops); moved runs equal: {same}/5; "
          f"affinity changes per run: {[n for _, n in res]}")
    if same != 5: fail.append(f"{p}: {[(o['class'], o['digest']) for o, _ in res]}")
if fail: die("; ".join(fail))
PY
