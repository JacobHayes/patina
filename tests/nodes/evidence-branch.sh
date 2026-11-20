# Evidence (docs/EVIDENCE.md, "Every crash point of every node"): `patina sweep --branch --crash
# machine` on runs with nodes, each sweep once at -j 6 with --keep fail:
# - ack2.py (two nodes; `early`: b answers before its fsync), seeds 1..8, 5 puts;
# - q3.py (three replicas; `nosync`: a node answers before it syncs; `early`: the primary
#   answers before a backup has the update), seeds 1..2, 2 s of virtual time;
# - wal.py (one node recovering its log; `nocheck`: recovery trusts each record's length),
#   seeds 1..2, 15 s of virtual time.
# Each line: crash points per node over the seeds, children tried, runs, wall seconds, failing
# runs, groups. Then wal.py's `nocheck` again with `--branch-max 300` (a sample of 300 children
# per seed).
#@ tier=evidence budget=1200 slots=6
. "$(dirname "$0")/lib.inc"
o=$RUNS/evidence-branch; mkdir -p "$o"
# sw NAME SEEDS CONFIG DRIVER...: one branch sweep into $o/NAME; prints its line.
sw() {
    n=$1 seeds=$2 cfg=$3; shift 3
    max=""; case $n in *-max) max="--branch-max 300" ;; esac
    rm -rf "${o:?}/$n"
    t0=$(date +%s)
    st=0
    timeout 1100 "$PATINA" sweep --seeds "$seeds" --branch $max --crash machine -j 6 --keep fail --out "$o/$n" \
        --config "$cfg" --mount "$PATINA_GUESTS":/guest:copy -- "$@" >"$o/$n.txt" 2>&1 || st=$?
    [ -f "$o/$n/report.json" ] || die "$n: no report (exit $st): $(tail -3 "$o/$n.txt")"
    python3 -I - "$o/$n/report.json" "$n" "$seeds" "$(( $(date +%s) - t0 ))" <<'PY'
import json, sys
rep, name, seeds, wall = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3], sys.argv[4]
b = rep["branch"]
per = ", ".join("%s %d" % (x["node"], x["points"]) for x in b["nodes"])
fail = sum(g["count"] for g in rep["groups"])
groups = "; ".join("%s (%d)" % (g["signature"], g["count"]) for g in rep["groups"]) or "-"
print("%-14s seeds %s: points %d (%s), tried %d, %d runs, %s s wall, %d failing; %s"
      % (name, seeds, b["points"], per, b["tried"], rep["runs"], wall, fail, groups))
PY
}
mk() {  # mk FILE PROG BUG NODE...: one table per node, BUG (if any) after the node's name
    f=$1 prog=$2 bug=$3; shift 3
    rm -f "$f"
    for n in "$@"; do
        if [ -n "$bug" ]; then conf "$f" "$n" python3 "/guest/$prog" "$n" "$bug"; else conf "$f" "$n" python3 "/guest/$prog" "$n"; fi
    done
}
rm -f "$o/ack2-ok.toml" "$o/ack2-early.toml"
conf "$o/ack2-ok.toml" a python3 /guest/ack2.py a; conf "$o/ack2-ok.toml" b python3 /guest/ack2.py b
conf "$o/ack2-early.toml" a python3 /guest/ack2.py a; conf "$o/ack2-early.toml" b python3 /guest/ack2.py b early
sw ack2-ok 1..8 "$o/ack2-ok.toml" python3 /guest/ack2.py driver 5
sw ack2-early 1..8 "$o/ack2-early.toml" python3 /guest/ack2.py driver 5
for v in ok nosync early; do
    b=""; [ $v = ok ] || b=$v
    mk "$o/q3-$v.toml" q3.py "$b" n1 n2 n3
    sw "q3-$v" 1..2 "$o/q3-$v.toml" python3 /guest/q3.py driver 2
done
for v in ok nocheck; do
    b=""; [ $v = ok ] || b=$v
    mk "$o/wal-$v.toml" wal.py "$b" a
    sw "wal-$v" 1..2 "$o/wal-$v.toml" python3 /guest/wal.py driver 15
done
sw wal-nocheck-max 1..2 "$o/wal-nocheck.toml" python3 /guest/wal.py driver 15
