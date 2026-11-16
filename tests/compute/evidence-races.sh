#!/bin/sh
# Evidence (docs/EVIDENCE.md, compute points): the syscall-free races `races b`, `pool` and
# `rs-race` (Rust atomics), seeds 1-200, in three columns: the stock build
# (tests/guests/counters; rs-race-stock), the build with compute points at the default
# compute-gap, and at compute-gap=8. Each column: failing seeds,
# and whether the first one replays identical. The prototype found 14 and 165 of 200 with a
# switch at 1 event in 10.
#@ tier=evidence budget=600 slots=6
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
OUT=$RUNS/evidence-races python3 -I - <<'PY'
import json, os, subprocess
from concurrent.futures import ThreadPoolExecutor

P, GU, OUT = os.environ["PATINA"], os.environ["PATINA_GUESTS"], os.environ["OUT"]
N = int(os.environ.get("RACE_SEEDS", "200"))
# (name, stock build, rebuilt build, arguments) under /guest
PROGS = [("races b", "counters/races", "compute/races", ["b"]), ("pool", "counters/pool", "compute/pool", []),
         ("rs-race", "compute/rs-race-stock", "compute/rs-race", [])]
COLS = [("stock", []), ("default", []), ("gap 8", ["--fault", "compute-gap=8"])]


def run(job):
    (pn, stock, rebuilt, args), (cn, opts), s = job
    prog = stock if cn == "stock" else rebuilt
    out = os.path.join(OUT, f"{prog.replace('/', '-')}-{cn.replace(' ', '')}-{s}")
    subprocess.run(["rm", "-rf", out])
    subprocess.run([P, "run", "--seed", str(s), "--out", out, "--mount", GU + ":/guest:copy", *opts, "--",
                    f"/guest/{prog}", *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
    with open(os.path.join(out, "result.json")) as f:
        r = json.load(f)
    return job, out, r


jobs = [(p, c, s) for p in PROGS for c in COLS for s in range(1, N + 1)]
with ThreadPoolExecutor(6) as ex:
    res = list(ex.map(run, jobs))
for p in PROGS:
    for c in COLS:
        rows = [(j[2], out, r) for j, out, r in res if j[0] == p and j[1] == c]
        fails = [(s, out) for s, out, r in rows if r["outcome"] == "failure"]
        other = sorted({r["outcome"] for _, _, r in rows} - {"ok", "failure"})
        rep = ""
        if fails:
            t = subprocess.run([P, "replay", fails[0][1]], capture_output=True, text=True).stdout
            rep = f"; seed {fails[0][0]} replays {'identical' if t.startswith('identical') else 'NOT IDENTICAL'}"
        sw = sorted(r.get("compute", {}).get("switches", 0) for _, _, r in rows)
        print(f"{p[0]:<8} {c[0]:<8} failure {len(fails)}/{N}{rep}; other outcomes {other or 'none'}; "
              f"median compute switches {sw[len(sw) // 2]}", flush=True)
PY
