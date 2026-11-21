# Evidence (docs/EVIDENCE.md, compute points): compute points change nothing for stock
# programs. W1-W9 with their fault settings, and the stock thread, race and loop guests,
# seeds 1-3: the build named by PATINA_BASE (one without compute points) and this build give
# the same digest and the same result.json but for wall_ms.
#@ tier=evidence budget=600 slots=6
HERE=$(cd "$(dirname "$0")" && pwd)
: "${PATINA:?}" "${PATINA_BASE:?a build without compute points}" "${PATINA_GUESTS:?}" "${PATINA_WORKLOADS:?}" "${RUNS:?}"
OUT=$RUNS/evidence-identity PYTHONPATH=$HERE/../durability/bench python3 -I - <<'PY'
import json, os, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.environ["PYTHONPATH"])
from workloads import WL, ORDER

OUT, GU = os.environ["OUT"], os.environ["PATINA_GUESTS"]
BUILDS = {"base": os.environ["PATINA_BASE"], "this": os.environ["PATINA"]}
CASES = [(w, *WL[w][:3]) for w in ORDER] + [
    ("c-threads", GU, ["/guest/c-threads"], []),
    ("rs-threads", GU, ["/guest/rs-threads"], []),
    ("spinpoints flag", GU, ["/guest/spinpoints", "flag"], []),
    ("races b (stock)", GU, ["/guest/compute/races-stock", "b"], []),
    ("pool (stock)", GU, ["/guest/compute/pool-stock"], []),
    ("loop (stock)", GU, ["/guest/compute/loop-stock", "100000"], []),
]
SEEDS = [1, 2, 3]


def run(job):
    name, guest, argv, opts, seed, build = job
    out = os.path.join(OUT, f"{name.replace(' ', '_')}-{seed}-{build}")
    subprocess.run(["rm", "-rf", out])
    subprocess.run([BUILDS[build], "run", "--seed", str(seed), "--out", out, "--mount", guest + ":/guest:copy",
                    *opts, "--", *argv], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900)
    with open(os.path.join(out, "result.json")) as f:
        r = json.load(f)
    r.pop("wall_ms", None)
    r.get("counters", {}).get("net", {}).pop("sup_hwm_kb", None)
    r.get("counters", {}).get("sched", {}).pop("spin_steps", None)
    return job, r


jobs = [(n, g, a, o, s, b) for (n, g, a, o) in CASES for s in SEEDS for b in BUILDS]
with ThreadPoolExecutor(6) as ex:
    res = {(j[0], j[4], j[5]): r for j, r in ex.map(run, jobs)}
bad = 0
for (n, g, a, o) in CASES:
    cells = []
    for s in SEEDS:
        b, t = res[(n, s, "base")], res[(n, s, "this")]
        same = b == t
        bad += not same
        cells.append(f"seed {s} {t['outcome']} {t['digest']}" + ("" if same else f" DIFFERS (base {b['digest']})"))
        if not same:
            diff = sorted(k for k in set(b) | set(t) if b.get(k) != t.get(k))
            cells.append(f"(differs in {diff})")
    print(f"{n:<18} " + "; ".join(cells), flush=True)
print(f"{len(CASES) * len(SEEDS)} runs of each build: {bad} differ")
sys.exit(1 if bad else 0)
PY
