# 5. Lost-wake-up stress: 16 threads in a ring of pipes, RING_LAPS laps (default 5,000),
#    preempt-permille 500, RING_SEEDS seeds (default 4): every run completes (ok); none liveness,
#    none unsupported. Runs go RING_JOBS (default 4) at a time, each pinned to its own CPU; each boundary
#    log is deleted once its digest is recorded. The large version (50 seeds x 100,000 laps)
#    is tests/io/evidence-ring.sh.
#@ tier=area budget=120 slots=4 arch=x86_64
. "$(dirname "$0")/lib.inc"
o=$RUNS/05-ring; mkdir -p "$o"
LAPS=${RING_LAPS:-5000}
SEEDS=${RING_SEEDS:-4}
cpus=$(python3 -I -c 'import os; print(" ".join(map(str, sorted(os.sched_getaffinity(0))[:int(os.environ.get("RING_JOBS", "4"))])))')
one() { # seed cpu
    d=$o/s$1
    timeout 1800 taskset -c "$2" "$PATINA" run --seed "$1" --config "$("$PATINA_CFG" preempt-permille=500)" --out "$d" --mount "$PATINA_GUESTS":/guest:copy -- /guest/ring "$LAPS" >/dev/null 2>"$d.err" || true
    rm -f "$d/inc-0/boundary.log"
}
seed=1
while [ "$seed" -le "$SEEDS" ]; do
    for c in $cpus; do
        [ "$seed" -le "$SEEDS" ] || break
        one "$seed" "$c" &
        seed=$((seed + 1))
    done
    wait
done
python3 -I - "$o" "$SEEDS" "$LAPS" <<'PY'
import json, sys, collections
o, n, laps = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
cls = collections.Counter(); walls = []; digests = set()
for s in range(1, n + 1):
    oc = json.load(open(f"{o}/s{s}/result.json"))
    cls[oc["outcome"]] += 1
    walls.append(oc["wall_ms"]); digests.add(oc["digest"])
    if oc["outcome"] == "ok":
        assert open(f"{o}/s{s}/inc-0/stdout").read() == f"laps {laps} hops {laps*16-15}\n", s
    else:
        print("seed", s, oc["outcome"], oc["stop"], oc["message"][:300])
print(f"{n} seeds x {laps} laps: classes {dict(cls)}; distinct digests {len(digests)}; wall ms min/median/max {min(walls)}/{sorted(walls)[n//2]}/{max(walls)}")
assert cls["ok"] == n, cls
PY
io_line ring $(for s in $(seq 1 "$SEEDS"); do echo "$o/s$s/result.json"; done)
