# Evidence (the cost of --check): runs per second of `patina sweep` of hello-static at -j 8,
# SEEDS (default 400) seeds, with no checker, with `--check true` and with a five-line sh
# checker that reads the run directory; two rounds, interleaved. Every run must end ok.
#@ tier=evidence budget=300 slots=8
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
n=${SEEDS:-400}
cat >"$RUNS/five" <<'EOF'
#!/bin/sh
[ "$PATINA_EXIT" = 0 ] || exit 0
[ -f "$1/result.json" ] || { echo "no-result: $1"; exit 2; }
grep -q '^pid ' "$1/inc-0/stdout" || { echo "no-pid: the program printed no pid"; exit 1; }
exit 0
EOF
chmod +x "$RUNS/five"
rate() {
    name=$1; shift
    t0=$(date +%s%N)
    st=0
    "$PATINA" sweep -j 8 --seeds "1..$n" --keep none --out "$RUNS/$name" --format json "$@" -- "$PATINA_GUESTS/hello-static" >"$RUNS/$name.json" 2>/dev/null || st=$?
    t1=$(date +%s%N)
    python3 -I - "$RUNS/$name.json" "$n" "$t0" "$t1" "$name" "$st" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
n, t0, t1 = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
s = (t1 - t0) / 1e9
print(f"{sys.argv[5]:<10} {n} runs in {s:.2f} s, {n / s:.0f} runs/s, exit {sys.argv[6]}, outcomes {r['outcomes']}")
assert sys.argv[6] == "0" and r["outcomes"] == {"ok": n}, "not every run ended ok"
PY
}
for round in 1 2; do
    rate "none-$round"
    rate "true-$round" --check true
    rate "sh5-$round" --check "$RUNS/five"
done
