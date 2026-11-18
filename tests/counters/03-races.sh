# the toolchain tier's syscall-free race b (check-then-act, no system call in the window), stock build,
# counter preemption only: with the race-hunting policy (every segment short) some of seeds
# 1-60 find the double spend (evidence-races: 10 of 200 seeds on Zen 5), and 3 varied runs of
# the first such seed are identical. SKIP without CAP_PERFMON.
#@ tier=area budget=120 slots=4
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
P = ppatina(required=False)
HUNT = ["branches=hunt"]
cmd = ["/guest/counters/races", "b"]
res = sweep(P, "03/b-hunt", list(range(1, 61)), GU, HUNT, cmd, jobs=4)
found = sorted(s for s, o in res.items() if "DOUBLE-SPEND" in o["_last"])
print(f"race b, hunt policy: found in {len(found)} of 60 seeds (first {found[:5]}); {classes(res)}")
if not found: die("no seed of 1-60 finds the double spend")
s = found[0]
ok, txt = verify(P, f"{RUNS}/b-replay", s, GU, 3, "cpu,aslr,sandbox", HUNT, cmd)
o = outcome(f"{RUNS}/b-replay/run-0") or {}
out = last_line(f"{RUNS}/b-replay/run-0")
print(f"race b, seed {s}: {'identical' if ok else 'NOT IDENTICAL'} (3 runs), outcome {o.get('outcome')}, {out!r}")
if not ok: die("not identical: " + txt[-300:])
if "DOUBLE-SPEND" not in out: die(f"seed {s} does not find the double spend again")
PY
