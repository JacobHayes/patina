# 17. `--fault crash-at=N` crashes at the N-th crash point. A base run (`--fault crash-permille=0`)
# of the window guest counts its points; one child per point 1..count+1, all compared with a
# run without a crash:
# - each child reports `crashes[0].point` N; two points of one call (an fsync's, before and
#   after it) are both reached, and the later one's operation log is longer;
# - a child's boundary log equals the run without `--crash` up to its CrashPoint record, and
#   two children's logs first differ at the earlier one's CrashPoint record;
# - every child that ends violation acked-records-stored crashed between the write of the
#   record acknowledged before its sync and that sync (found in the base's operation log);
#   whether one does depends on the seed's draw of what survives, so if none does, later
#   seeds are tried at the points of that window only, until one does;
# - the base and the child past the last point end as the run without `--crash` (same
#   digest, no crash injected);
# - a child replays identical.
#@ tier=quick budget=10 slots=2
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/17
run "$d/ref" 1 -- /guest/window
run "$d/base" 1 --fault crash-permille=0 -- /guest/window
n=$(field "$d/base/result.json" faults.counts.crash.eligible)
[ "$n" -gt 2 ] || die "the base has $n crash points"
export PATINA PATINA_GUESTS d
seq 1 $((n + 1)) | xargs -P 4 -I{} bash -euo pipefail -O inherit_errexit -c '
    st=0; timeout 60 "$PATINA" run --seed 1 --fault crash-at=$1 --out "$d/c-$1" --mount "$PATINA_GUESTS":/guest:copy -- /guest/window >/dev/null 2>&1 || st=$?
    [ -f "$d/c-$1/result.json" ] || echo "child $1: no result.json (exit $st)"' sh {} >"$d/children.txt"
[ ! -s "$d/children.txt" ] || die "a child did not run: $(head -3 "$d/children.txt")"
mid=$((n / 2)) late=$((n * 3 / 4))
# first A B: the first record at which two runs' logs differ (log diff exits 1: they differ)
first() {
    "$PATINA" log diff "$1/inc-0/boundary.log" "$2/inc-0/boundary.log" >"$1.diff" || [ $? = 1 ]
    sed -n 's/^first difference at record \([0-9]*\) .*/\1/p' "$1.diff"
}
# cp_at RUN: the line number of the first CrashPoint record of a run's log dump
cp_at() { "$PATINA" log dump "$1/inc-0/boundary.log" | awk '/ CrashPoint / && !n {n = NR} END {print n}'; }
for c in "$mid" "$late"; do
    i=$(($(cp_at "$d/c-$c") - 1))
    [ "$(first "$d/ref" "$d/c-$c")" = "$i" ] || die "child $c: first differs from the run without a crash at record $(first "$d/ref" "$d/c-$c"), its CrashPoint is record $i"
done
i=$(($(cp_at "$d/c-$mid") - 1))
[ "$(first "$d/c-$mid" "$d/c-$late")" = "$i" ] || die "children $mid and $late first differ at record $(first "$d/c-$mid" "$d/c-$late"), not at $mid's CrashPoint ($i)"
echo "children $mid and $late equal the run without a crash up to their CrashPoint records, and each other up to $mid's"
python3 -I - "$d" "$n" "$LIB" <<'PY' || exit 1
import json, os, sys
d, n = sys.argv[1], int(sys.argv[2])
sys.path.insert(0, sys.argv[3])
import faults
def res(p):
    return json.load(open(os.path.join(d, p, "result.json")))
base, ref = res("base"), res("ref")
ops = faults.oplog(os.path.join(d, "base", "inc-0"))
nm = faults.names(ops)
on = lambda o, name: nm.get(o["ino"]) == name
# The window: the data.log write whose next data.log fsync comes after an acks.log fsync.
win = None
for i, o in enumerate(ops):
    if o["kind"] == "Write" and on(o, "data.log"):
        nxt = next(j for j in range(i + 1, len(ops)) if ops[j]["kind"] == "Fsync" and on(ops[j], "data.log"))
        if any(ops[j]["kind"] == "Fsync" and on(ops[j], "acks.log") for j in range(i + 1, nxt)):
            win = (o["seq"], ops[nxt]["seq"])
assert win, "no record of the base is acknowledged before its sync"
seqs, viol, multi = {}, [], 0
for p in range(1, n + 1):
    r = res("c-%d" % p)
    c = r["crashes"]
    if len(c) != 1 or c[0]["point"] != p:
        sys.exit("FAIL: child %d: crashes %s" % (p, [(x["seq"], x.get("point")) for x in c]))
    seqs[p] = c[0]["seq"]
    if r["outcome"] == "violation":
        if "acked-records-stored" not in r["message"]:
            sys.exit("FAIL: child %d: %s" % (p, r["message"]))
        viol.append(p)
        if not win[0] <= seqs[p] <= win[1]:
            sys.exit("FAIL: child %d (seq %d) violates outside the window %s" % (p, seqs[p], win))
    elif r["outcome"] != "ok":
        sys.exit("FAIL: child %d: %s %s" % (p, r["outcome"], r["message"]))
for p in range(1, n):
    if seqs[p] == seqs[p + 1]:
        a, b = (len(faults.oplog(os.path.join(d, "c-%d" % q, "inc-0"))) for q in (p, p + 1))
        if b <= a:
            sys.exit("FAIL: points %d and %d (seq %d): operation logs of %d and %d records" % (p, p + 1, seqs[p], a, b))
        multi += 1
if not multi:
    sys.exit("FAIL: no call holds two crash points")
past = res("c-%d" % (n + 1))
for name, r in (("the base", base), ("the child past the last point", past)):
    if r["crashes"] or r["faults"]["counts"]["crash"]["injected"] != 0 or r["digest"] != ref["digest"]:
        sys.exit("FAIL: %s: %s, digest %s (without a crash %s)" % (name, r["crashes"], r["digest"], ref["digest"]))
# The window's points, for the seed search below.
pts = faults.points(ops)
inw = [p for p, o in zip(pts, ops) if p and win[0] <= o["seq"] <= win[1]]
open(os.path.join(d, "window"), "w").write(" ".join(map(str, range(min(inw), max(inw) + 1))))
open(os.path.join(d, "found"), "w").write("1" if viol else "")
print("%d points: each child crashed at its own; %d calls hold two points; violation at points %s, seqs %s, window %s; the base and point %d end as the run without a crash (%s)" % (
    n, multi, viol, [seqs[p] for p in viol], win, n + 1, ref["digest"]))
PY
# What survives a crash is the seed's draw: search later seeds at the window's points.
s=1
while [ ! -s "$d/found" ]; do
    s=$((s + 1))
    [ "$s" -le 20 ] || die "no child of seeds 1-20 ends violation acked-records-stored (window points $(cat "$d/window"))"
    for p in $(cat "$d/window"); do
        run "$d/s$s-$p" "$s" --fault crash-at=$p -- /guest/window
        if [ "$(class "$d/s$s-$p")" = violation ]; then
            field "$d/s$s-$p/result.json" message | grep -q acked-records-stored || die "seed $s point $p: $(field "$d/s$s-$p/result.json" message)"
            echo "seed $s point $p: $(field "$d/s$s-$p/result.json" message)"; echo 1 >"$d/found"; break
        fi
    done
done
"$PATINA" replay "$d/c-$mid" >"$d/replay.txt" 2>&1 || true
grep -q '^identical' "$d/replay.txt" || die "replay of child $mid: $(tail -2 "$d/replay.txt")"
echo "child $mid replays: $(head -1 "$d/replay.txt")"
