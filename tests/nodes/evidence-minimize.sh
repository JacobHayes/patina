# Evidence (docs/EVIDENCE.md, "Minimizing to one node's crash"): seeds 1..200 of ack2.py
# (`early`: b answers before its fsync) under the planted mix of 14-points-sweep (crashes at both
# nodes' points at 60 per mille, net delays and duplicates, disk delays), 6 at a time; each
# failing run minimized. Prints the failing seeds, how many reduced to one node's crash alone
# (`crash-at=N@NODE`), and the runs minimize made (mean, most).
#@ tier=evidence budget=900 slots=6
. "$(dirname "$0")/lib.inc"
o=$RUNS/evidence-minimize; mkdir -p "$o"
rm -f "$o/early.toml"
conf "$o/early.toml" a python3 /guest/ack2.py a; conf "$o/early.toml" b python3 /guest/ack2.py b early
export o PATINA PATINA_GUESTS
# one SEED: "SEED failure RUNS TO" for a failing seed, "SEED OUTCOME" for another.
one() {
    d=$o/s$1; rm -rf "${d:?}"
    timeout 300 "$PATINA" run --seed "$1" --out "$d" --mount "$PATINA_GUESTS":/guest:copy --config "$o/early.toml" \
        --fault crash-permille=60 --fault net-delay-ms=0..20 --fault net-dup-permille=10 --fault fs-delay-permille=20 \
        -- python3 /guest/ack2.py driver 4 >/dev/null 2>&1 || [ -f "$d/result.json" ] || { echo "$1 no-result"; return; }
    c=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["outcome"])' "$d/result.json")
    if [ "$c" = failure ]; then
        timeout 600 "$PATINA" minimize "$d" --format json >"$d.json" 2>/dev/null || { echo "$1 minimize-failed"; return; }
        python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])); print(sys.argv[2], "failure", m["runs"], m["to"].replace(" ", ","))' "$d.json" "$1"
    else
        echo "$1 $c"
    fi
    rm -rf "${d:?}" "${d:?}.json"
}
export -f one
seq 1 200 | xargs -P 6 -I{} bash -c 'one {}' | sort -n >"$o/seeds.txt"
python3 -I - "$o/seeds.txt" <<'PY'
import sys
rows = [l.split() for l in open(sys.argv[1])]
bad = [r for r in rows if r[1] in ("no-result", "minimize-failed")]
assert not bad, bad
f = [r for r in rows if r[1] == "failure"]
single = [r for r in f if "crash-at=" in r[3]]
runs = [int(r[2]) for r in f]
print("seeds 1-200: %d failing, %d reduced to one node's crash alone; minimize runs mean %.1f, most %d"
      % (len(f), len(single), sum(runs) / len(runs), max(runs)))
for r in f:
    if r not in single:
        print("  not reduced to one crash: seed %s: %s" % (r[0], r[3]))
PY
