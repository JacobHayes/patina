# 1 (privilege). Without CAP_PERFMON, pmu = true is off with a message, the run is as without it
# (same digest), and the result says why; without it the result says preempt traps.
#@ tier=quick budget=30 slots=1
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, subprocess, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
g = GU
cmd = ["/guest/counters/compute", "recur"]
a = run(PATINA, RUNS + "/01/off", 1, g, [], cmd)
r = subprocess.run([PATINA, "run", "--seed", "1"] + config(["pmu=true"]) + ["--out", RUNS + "/01/req", "--mount", g + ":/guest:copy", "--"] + cmd,
                   capture_output=True, text=True)
b = outcome(RUNS + "/01/req")
print("without pmu:", a["outcome"], a["digest"], "pmu:", pmu(a))
print("pmu unprivileged:", b["outcome"], b["digest"], "pmu:", pmu(b))
print("message:", r.stderr.strip())
if a["outcome"] != "ok" or pmu(a) is not None: die("default run")
if b["digest"] != a["digest"] or not str(pmu(b)).startswith("off: "): die("unprivileged pmu")
if "counter preemption is off" not in r.stderr: die("no message")
PY
