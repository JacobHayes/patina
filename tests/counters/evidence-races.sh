# Item 4. the toolchain tier's syscall-free races, stock builds (no patina-cc), counter preemption only (no
# --mem). races b (check-then-act, no system call in the window): 200 seeds with the default
# policy and 200 with a race-hunting policy (every segment short: pmu-short-permille = 1000
# pmu-short-max = 64); found in some seeds; a failing seed replays 20/20 (patina verify, varied).
# pool: measured the same way. Its updates are single read-modify-write instructions
# (`incq mem`, `add reg, mem`): no instruction-boundary schedule can interleave them, so it
# cannot be found by any preemption on a one-thread-at-a-time executor; printed, not failed,
# after checking that the compiled code is indeed so.
#@ tier=evidence budget=1200 slots=8
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, subprocess, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
P = ppatina()
n = int(os.environ.get("COUNTERS_RACE_SEEDS", "200"))
T = GU + "/tier"
HUNT = ["pmu-short-permille=1000", "pmu-short-max=64"]
fail = []
for name, cmd, pat in [("b", ["/guest/counters/races", "b"], "DOUBLE-SPEND"), ("pool", ["/guest/counters/pool"], "LOST-UPDATE")]:
    found = {}
    for pol, opts in [("default", ["pmu=true"]), ("hunt", HUNT)]:
        res = sweep(P, f"05/{name}-{pol}", list(range(1, n + 1)), GU, opts, cmd)
        bad = [s for s, o in res.items() if o["outcome"] not in ("ok", "failure", "crash")]
        f = sorted(s for s, o in res.items() if pat in o["_last"])
        found[pol] = f
        print(f"{name} {pol}: found in {len(f)}/{n} seeds (first {f[:5]}); {classes(res)}")
        if bad: fail.append(f"{name} {pol}: runs neither ok nor failed: {bad[:5]}")
    if name == "b":
        if not found["hunt"]:
            fail.append("b: not found in 200 seeds")
            continue
        s = found["hunt"][0]
        ok, txt = verify(P, f"{RUNS}/05/b-replay", s, GU, 20, "cpu,load,aslr,sandbox", HUNT, cmd)
        o = outcome(f"{RUNS}/05/b-replay/run-0")
        out = last_line(f"{RUNS}/05/b-replay/run-0")
        print(f"b: seed {s} replayed 20 runs: {'identical' if ok else 'NOT IDENTICAL'}, class {o and o['outcome']}, {out!r}")
        if not ok or pat not in out: fail.append("b: replay")
    else:
        dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", T + "/pool"], capture_output=True, text=True).stdout
        w = dis[dis.find("<worker>:"):]
        w = w[:w.find("\n\n")]
        rmw = [l.strip() for l in w.splitlines() if "stats" in l]
        print("pool's updates in the compiled worker:", rmw)
        single = rmw and all(l.split("\t")[-1].split()[0] in ("incq", "add", "addq") for l in rmw)
        if not found["hunt"] and not found["default"]:
            if not single: fail.append("pool not found, and its updates are not single instructions")
            else: print("ITEM NOT MET for pool: not found in any seed; its lost update needs two CPUs inside one instruction")
if fail: die("; ".join(fail))
PY
