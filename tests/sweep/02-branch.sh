# 2. `patina sweep --branch`: each seed once with crashes on and never firing, then once per
#    crash point it counted, crashing there.
# - On the window guest (one record acknowledged before its sync), the sweep finds
#   acked-records-stored; the
#   group's first run is a child whose crash point lies between that record's write and its
#   sync (from a base run's operation log); its rerun line gives the same signature; it replayed
#   identical. It ran one child per crash point of the base.
# - Cut by --max-findings 1, the report says fewer points were tried than exist; the same
#   command without it runs only the missing children, and the report's groups and counts then
#   equal the uncut sweep's.
# - With two seeds and two cases, the children are each base's crash points, per base.
# - --branch without --crash, or with a rate, is refused and runs nothing; a plain sweep and a
#   branch sweep into one directory replace each other.
# - examples/acklog-c: the sweep finds acked-records-kept.
#@ tier=quick budget=15 slots=4
. "$(dirname "$0")/../cli/lib.inc"
d=$RUNS/branch
mkdir -p "$d"
W=/guest/window
sw() { o=$1; shift; st=0; timeout 120 "$PATINA" sweep -j 4 --out "$d/$o" --mount "$PATINA_GUESTS":/guest:copy "$@" >"$d/$o.txt" 2>&1 || st=$?; }
# window BASE: the window's first and last crash points: from the data.log write whose sync comes
# after an acks.log sync, to that sync (from the base run's operation log).
window() { python3 -I - "$1" "$(dirname "$0")/../faults/lib" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[2])
import faults
ops = faults.oplog(os.path.join(sys.argv[1], "inc-0"))
nm = faults.names(ops)
on = lambda o, name: nm.get(o["ino"]) == name
pts = faults.points(ops)
for i, o in enumerate(ops):
    if o["kind"] == "Write" and on(o, "data.log"):
        j = next(j for j in range(i + 1, len(ops)) if ops[j]["kind"] == "Fsync" and on(ops[j], "data.log"))
        if any(ops[k]["kind"] == "Fsync" and on(ops[k], "acks.log") for k in range(i + 1, j)):
            print(pts[i], pts[j])
PY
}
# The guest's unsynced record starts a new block, so a crash in its window loses it in every
# seed: the base's own window says where.
s=1
timeout 60 "$PATINA" run --seed $s --crash machine:0 --out "$d/base" --mount "$PATINA_GUESTS":/guest:copy -- $W >/dev/null 2>&1 || true
set -- $(window "$d/base")
[ $# = 2 ] || die "the base acknowledges no record before its sync"
lo=$1 hi=$2
sw full --seeds $s --branch --crash machine -- $W
[ "$st" = 1 ] || die "branch sweep of seed $s: exit $st ($(tail -3 "$d/full.txt"))"
rerun=$(python3 -I - "$d" "$s" "$lo" "$hi" <<'PY'
import json, os, sys
d, s, lo, hi = sys.argv[1], *map(int, sys.argv[2:])
rep = json.load(open(os.path.join(d, "full", "report.json")))
n = json.load(open(os.path.join(d, "base", "result.json")))["faults"]["counts"]["crash"]["eligible"]
g = [g for g in rep["groups"] if "acked-records-stored" in g["signature"]]
if len(g) != 1:
    sys.exit("FAIL: groups %s" % [x["signature"] for x in rep["groups"]])
g = g[0]
p = g["first"]["point"]
if g["first"]["seed"] != s or p is None or not lo <= p <= hi:
    sys.exit("FAIL: first run %s@%s, window %d..%d" % (g["first"]["seed"], p, lo, hi))
if (g["replay"] or {}).get("result") != "identical":
    sys.exit("FAIL: replay %s" % g["replay"])
b = rep["branch"]
if rep["runs"] != n + 1 or b["points"] != n or b["tried"] != n:
    sys.exit("FAIL: %d runs, branch %s; the base counted %d" % (rep["runs"], b, n))
print(g["rerun"])
print("window: first run seed %d@%d in points %d..%d of %d; %d runs, replayed identical" % (s, p, lo, hi, n, rep["runs"]), file=sys.stderr)
PY
) || { echo "$rerun"; exit 1; }
sh -c "$(echo "$rerun" | sed "s|^patina run |'$PATINA' run --out '$d/rerun' |")" >/dev/null 2>&1 || true
sig() { field "$1" signature; }
[ "$(sig "$d/rerun/result.json")" = "$(field "$d/full/report.json" groups | python3 -I -c 'import json,sys; print([g for g in json.load(sys.stdin) if "acked" in g["signature"]][0]["signature"])')" ] ||
    die "rerun: $(sig "$d/rerun/result.json")"
echo "rerun gives the same signature: $rerun"

# Cut and resume.
sw cut --seeds $s --branch --crash machine --max-findings 1 -- $W
grep -q '^crash points: [0-9]* of [0-9]* tried' "$d/cut.txt" || die "cut: $(cat "$d/cut.txt")"
tried=$(field "$d/cut/report.json" branch.tried) all=$(field "$d/cut/report.json" branch.points)
[ "$tried" -lt "$all" ] || die "--max-findings 1 tried $tried of $all"
sw cut --seeds $s --branch --crash machine -- $W
grep -q "^sweep: $tried of $all children already in" "$d/cut.txt" || die "resume: $(head -3 "$d/cut.txt")"
python3 -I - "$d/full/report.json" "$d/cut/report.json" <<'PY' || exit 1
import json, sys
a, b = (json.load(open(f)) for f in sys.argv[1:])
key = lambda r: (r["runs"], r["outcomes"], r["branch"], [(g["signature"], g["count"], g["first"]["seed"], g["first"]["point"]) for g in r["groups"]])
if key(a) != key(b):
    sys.exit("FAIL: resumed %s, uncut %s" % (key(b), key(a)))
PY
echo "cut at $tried of $all points; resumed, the report equals the uncut sweep's"

# Two seeds, two cases: one base per pair, one child per point of each.
printf '/guest/hello-static\n/guest/hello-static x\n' >"$d/lines"
sw cases --seeds 1..2 --cases "$d/lines" --branch --crash process
[ "$st" = 0 ] || die "cases: exit $st ($(tail -3 "$d/cases.txt"))"
python3 -I - "$d/cases/report.json" <<'PY' || exit 1
import json, sys
r = json.load(open(sys.argv[1]))
b = r["branch"]
if len(b["seeds"]) != 4 or b["points"] == 0 or b["tried"] != b["points"] or r["runs"] != 4 + b["points"]:
    sys.exit("FAIL: %d runs, %s" % (r["runs"], b))
print("2 seeds x 2 cases: %d runs, %s" % (r["runs"], [(s["seed"], s["case"], s["points"]) for s in b["seeds"]]))
PY

# Refusals; plain and branch sweeps replace each other.
for c in "" "--crash machine:5" "--crash machine-at:3"; do
    sw refused --seeds 1 --branch $c -- /guest/hello-static
    [ "$st" = "$(exit_of error)" ] && [ ! -e "$d/refused" ] || die "--branch $c: exit $st, $(ls "$d/refused" 2>&1 | head -2)"
    echo "--branch ${c:-without --crash}: $(tail -1 "$d/refused.txt")"
done
sw swap --seeds 1 --crash machine -- /guest/hello-static
sw swap --seeds 1 --branch --crash machine -- /guest/hello-static
grep -q 'replacing it' "$d/swap.txt" && ls "$d/swap" | grep -q '^seed-1@' || die "branch over plain: $(head -2 "$d/swap.txt")"
sw swap --seeds 1 --crash machine -- /guest/hello-static
grep -q 'replacing it' "$d/swap.txt" && ! ls "$d/swap" | grep -q '^seed-1@' || die "plain over branch: $(head -2 "$d/swap.txt")"
echo "a branch sweep and a plain sweep replace each other"

sw acklog --seeds 1 --branch --crash machine --max-findings 1 -- /guest/examples/acklog
[ "$st" = 1 ] && grep -q 'acked-records-kept' "$d/acklog.txt" || die "acklog: exit $st ($(tail -3 "$d/acklog.txt"))"
echo "examples/acklog-c: $(grep -m1 '^violation' "$d/acklog.txt")"
