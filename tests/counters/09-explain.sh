# `patina explain` of a counter-preemption run: the observed replay (the runtime records what a
# program's calls touched, in a log of its own) leaves the run as it was: the same digest and the
# same boundary log, preemptions included, on threads the counter preempts often (race b, the
# race-hunting policy: every segment short). The observation must not move a counter stop.
# SKIP without CAP_PERFMON.
#@ tier=area budget=60
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import filecmp, json, os, subprocess, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
P = ppatina(required=False)
r = f"{RUNS}/09/races"
o = run(P, r, 1, GU, ["branches=hunt"], ["/guest/counters/races", "b"], keep=True)
n = o.get("counters", {}).get("pmu", {}).get("preempts")
print(f"run: {o['outcome']}, {n} preemptions, digest {o['digest']}")
if pmu(o) != "on" or not n or n < 10:
    die("the run was not preempted by the counter: " + json.dumps(o)[:300])
t = subprocess.run([P, "explain", r, "--format", "json"], capture_output=True, text=True, timeout=900)
if t.returncode != 0:
    die(f"explain: exit {t.returncode}: {t.stderr[-300:]}")
e = outcome(r + "/explain") or {}
if e.get("digest") != o["digest"]:
    die(f"the observed replay's digest {e.get('digest')} is not the run's {o['digest']}")
if not filecmp.cmp(r + "/inc-0/boundary.log", r + "/explain/inc-0/boundary.log", shallow=False):
    die("the observed replay's boundary log is not the run's")
obs = os.path.getsize(r + "/explain/inc-0/observe.log")
if not obs:
    die("no observations")
print(f"explain: the observed replay is the run ({obs} bytes of observations)")
PY
