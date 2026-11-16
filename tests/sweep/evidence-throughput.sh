# Evidence (sweep throughput): runs per second of `patina sweep` for the trivial guest
# (hello-static) at -j 1, 4 and 8, and for a guest that holds 500 pipes with data in each at
# -j 8; the outcomes of each sweep. SEEDS (default 400) seeds per sweep.
#@ tier=evidence budget=600 slots=8
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
n=${SEEDS:-400}
pipes='import os
ps = [os.pipe() for _ in range(500)]
for r, w in ps: os.write(w, b"x" * 4096)
for r, w in ps: assert os.read(r, 4096) == b"x" * 4096'
rate() {
    name=$1 j=$2; shift 2
    t0=$(date +%s%N)
    st=0
    "$PATINA" sweep -j "$j" --seeds "1..$n" --keep none --out "$RUNS/$name-j$j" --format json "$@" >"$RUNS/$name-j$j.json" 2>/dev/null || st=$?
    t1=$(date +%s%N)
    python3 -I - "$RUNS/$name-j$j.json" "$n" "$t0" "$t1" "$name" "$j" "$st" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
n, t0, t1 = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
s = (t1 - t0) / 1e9
print(f"{sys.argv[5]:<8} -j {sys.argv[6]}: {n} runs in {s:.1f} s, {n / s:.0f} runs/s, exit {sys.argv[7]}, outcomes {r['outcomes']}")
PY
}
for j in 1 4 8; do rate trivial "$j" -- "$PATINA_GUESTS/hello-static"; done
rate pipes 8 -- /usr/bin/python3 -c "$pipes"
