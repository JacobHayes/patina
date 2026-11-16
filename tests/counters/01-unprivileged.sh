# 1 (privilege). Without CAP_PERFMON, --pmu is off with a message, the run is as without it
# (same digest), and the outcome says why; without --pmu the outcome has no pmu field.
#@ tier=quick budget=30 slots=1
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, subprocess, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
g = GU
cmd = ["/guest/counters/compute", "recur"]
a = run(PATINA, RUNS + "/01/off", 1, g, [], cmd)
r = subprocess.run([PATINA, "run", "--seed", "1", "--pmu", "--out", RUNS + "/01/req", "--guest", g, "--"] + cmd,
                   capture_output=True, text=True)
b = outcome(RUNS + "/01/req")
print("without --pmu:", a["class"], a["digest"], "pmu field:", "pmu" in a)
print("--pmu unprivileged:", b["class"], b["digest"], "pmu:", b.get("pmu"))
print("message:", r.stderr.strip())
if a["class"] != "ok" or "pmu" in a: die("default run")
if b["digest"] != a["digest"] or not str(b.get("pmu", "")).startswith("off: "): die("unprivileged --pmu")
if "counter preemption is off" not in r.stderr: die("no message")
PY
