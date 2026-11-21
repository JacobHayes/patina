# 1 (privilege). Without CAP_PERFMON (this unprivileged patina), preempt = "branches" is an
# error (outcome error, exit 2) and no run directory is made; the default (load-time points)
# runs, and its result says mode points.
#@ tier=quick budget=30 slots=1
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, subprocess, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
g = GU
cmd = ["/guest/counters/compute", "recur"]
a = run(PATINA, RUNS + "/01/off", 1, g, [], cmd)
r = subprocess.run([PATINA, "run", "--seed", "1"] + config(PMU)[0] + ["--out", RUNS + "/01/req", "--mount", g + ":/guest:copy", "--"] + cmd,
                   capture_output=True, text=True)
print("default:", a["outcome"], a["digest"], "mode:", (a.get("sched") or {}).get("mode"))
print("preempt = branches unprivileged: exit", r.returncode, "message:", r.stderr.strip())
if a["outcome"] != "ok" or (a.get("sched") or {}).get("mode") != "points": die("default run")
if r.returncode != 2 or os.path.exists(RUNS + "/01/req"): die("preempt = branches without counters did not refuse")
PY
