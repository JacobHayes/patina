# Shared helpers for the scripts of this area (sourced, not run): the three-node store of
# tests/guests/nodes/q3.py, on the helpers of the nodes area.
. "$(dirname "$0")/../nodes/lib.inc"

# The three-node store (tests/guests/nodes/q3.py) under the seed's partitions and the net preset.
Q3_FAULTS="--faults net --fault partition-gap-ms=1000..6000 --fault partition-ms=1000..6000"
Q3_SECONDS=60
# q3_sweep DIR VARIANT KEEP: seeds 1-8 of VARIANT (ok, or a planted bug) in DIR/VARIANT, the
# driver running Q3_SECONDS of virtual time; prints the report's outcomes.
q3_sweep() {
    _f=$1/$2.toml; rm -f "$_f"
    _b=""; [ "$2" = ok ] || _b=$2
    for _n in n1 n2 n3; do conf "$_f" "$_n" python3 /guest/q3.py "$_n" $_b; done
    rm -rf "${1:?}/$2"
    _st=0
    timeout 600 "$PATINA" sweep --seeds 1..8 -j 4 --keep "$3" --out "$1/$2" --config "$_f" $Q3_FAULTS \
        --mount "$PATINA_GUESTS":/guest:copy -- python3 /guest/q3.py driver "$Q3_SECONDS" >"$1/$2.txt" 2>&1 || _st=$?
    [ -f "$1/$2/report.json" ] || { tail -20 "$1/$2.txt"; die "sweep $2: no report (exit $_st)"; }
    field "$1/$2/report.json" outcomes
}
# q3_bug DIR VARIANT: the planted bug is found in most of seeds 1-8 and its first failing run
# replays identically (the sweep's own replay).
q3_bug() {
    _out=$(q3_sweep "$1" "$2" fail)
    _n=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["outcomes"].get("failure", 0))' "$1/$2/report.json")
    [ "$_n" -ge 4 ] || die "$2: found in only $_n of 8 seeds ($_out)"
    # Each failing group's first run, replayed by the sweep.
    _r=$(python3 -I -c 'import json,sys
g=[g for g in json.load(open(sys.argv[1]))["groups"] if g["outcome"] == "failure"]
r=["seed %s %s" % (x["replay"]["seed"], x["replay"]["result"]) for x in g if x["replay"]]
print(", ".join(r))
sys.exit(0 if r and len(r) == len(g) and all(x["replay"]["result"] == "identical" for x in g) else 1)' "$1/$2/report.json") \
        || die "$2: a first failing run did not replay identically: ${_r:-no replay}"
    _l=$(cat "$1/$2"/seed-*/inc-0/stdout 2>/dev/null | sed -n 's/^FAIL: \([a-z ]*\):.*/\1/p' | sort | uniq -c | tr -s ' \n' ' ')
    echo "$2: found in $_n of 8 seeds:$_l; replayed: $_r"
}
