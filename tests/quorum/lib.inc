# Shared helpers for the scripts of this area (sourced, not run): the three-node store of
# tests/guests/nodes/q3.py, on the helpers of the nodes area.
. "$(dirname "$0")/../nodes/lib.inc"

# The three-node store (tests/guests/nodes/q3.py) under the seed's partitions and the net preset.
Q3_FAULTS="--faults net --fault partition-gap-ms=1000..6000 --fault partition-ms=1000..6000"
Q3_SECONDS=60
# q3_sweep DIR VARIANT KEEP: seeds 1-8 of VARIANT (ok) in DIR/VARIANT, the driver running
# Q3_SECONDS of virtual time; prints the report's outcomes.
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
# q3_bug DIR VARIANT: the planted bug is found by a search of seeds (find_bug) and its first
# failing run replays identically (the sweep's own replay); prints what it found.
q3_bug() {
    _f=$1/$2.toml; rm -f "$_f"
    for _n in n1 n2 n3; do conf "$_f" "$_n" python3 /guest/q3.py "$_n" "$2"; done
    _r=$(find_bug "$1" "$2" --config "$_f" $Q3_FAULTS -- python3 /guest/q3.py driver "$Q3_SECONDS")
    _l=$(cat "$1/$2"/seed-*/inc-0/stdout 2>/dev/null | sed -n 's/^FAIL: \([a-z ]*\):.*/\1/p' | sort | uniq -c | tr -s ' \n' ' ')
    echo "$2:$_l; $_r"
}
