# 5. Quorum: the three-node store of 01-quorum under two machine crashes at crash points
# (`sweep --crash-points`, `[sweep] crash-pairs`): each first crash's child that ended ok, then another node's
# crash at each of its next 3 points, a sample of 40 children and 40 pairs of each of two seeds.
# A write two nodes acknowledged survives one crash; `nosync` (a node answers before it syncs)
# loses it when both crash, found only in pairs. The correct store is ok at every first crash
# and pair tried: it elects a primary after two crashes too (each node asks again after a grace
# period of its own, and grants a higher view whether or not it is asking itself). Every
# failing run kept (`--keep fail` keeps each group's first three) printed the lost write. A
# pair's rerun line gives its digest again.
#@ tier=area budget=90 slots=6
. "$(dirname "$0")/lib.inc"
o=$RUNS/05-quorum-pairs; mkdir -p "$o"
pairs() {
    f=$o/$1.toml; rm -f "$f"
    b=""; [ "$1" = ok ] || b=$1
    for n in n1 n2 n3; do conf "$f" "$n" python3 /guest/q3.py "$n" $b; done
    printf '[sweep]\ncrash-pairs = 3\n' >>"$f"
    q3_traps "$f"
    rm -rf "${o:?}/$1"; st=0
    # KEEP none is the test input PATINA_TEST_KEEP_NONE.
    k=$2; env $([ "$k" = none ] && echo PATINA_TEST_KEEP_NONE=1) timeout 300 "$PATINA" sweep --seeds 1..2 --crash-points=40 --faults crash -j 6 --keep "${k/none/fail}" \
        --out "$o/$1" --config "$f" --mount "$PATINA_GUESTS":/guest:copy -- python3 /guest/q3.py driver 2 >"$o/$1.txt" 2>&1 || st=$?
    [ -f "$o/$1/report.json" ] || die "$1: no report (exit $st): $(tail -3 "$o/$1.txt")"
}
pairs ok none
[ "$st" = 0 ] || die "correct: exit $st: $(grep -A4 '^[a-z].*exit' "$o/ok.txt" | head -12)"
python3 -I - "$o/ok/report.json" <<'PY' || die "correct"
import json, sys
b = json.load(open(sys.argv[1]))["crash_points"]
assert b["tried"] == 80 and b["pairs"]["tried"] == 80 < b["pairs"]["pairs"], b
assert all(x["tried"] == 40 for x in b["seeds"]), b["seeds"]
print("correct: ok at %d first crashes and %d of %d pairs" % (b["tried"], b["pairs"]["tried"], b["pairs"]["pairs"]))
PY
pairs nosync fail
[ "$st" = 1 ] || die "nosync: exit $st: $(tail -5 "$o/nosync.txt")"
python3 -I - "$o/nosync/report.json" <<'PY' || die "nosync"
import json, os, sys
r = json.load(open(sys.argv[1]))
runs = [x for g in r["groups"] for x in g["runs"]]
assert runs and all("point2" in x for x in runs), [(x.get("node"), x["point"], x.get("node2")) for x in runs]
kept = [x["dir"] + "/inc-0/stdout" for x in runs if os.path.isfile(x["dir"] + "/inc-0/stdout")]
assert kept and all("lost write" in open(p).read() for p in kept), r["groups"][0]["signature"]
print("nosync: a lost write in %d of %d pairs, in no first crash alone" % (len(runs), r["crash_points"]["pairs"]["tried"]))
PY
c=$(field "$o/nosync/report.json" groups.0.first.dir)
s=$(field "$o/nosync/report.json" groups.0.first.seed)
st=0; timeout 120 "$PATINA" run --seed "$s" --config "$c/run.json" --out "$o/rerun" -- python3 /guest/q3.py driver 2 >/dev/null 2>&1 || st=$?
d1=$(field "$o/rerun/result.json" digest) d2=$(field "$c/result.json" digest)
[ "$d1" = "$d2" ] || die "rerun of $c: digest $d1, not $d2"
echo "rerun of $(basename "$c"): same digest"
