# 11. Nodes: a log recovered after machine crashes (tests/guests/nodes/wal.py). Node a appends
# checksummed records, fsyncing every fourth, and fsyncs another file every third, so a crash
# can leave the log's last record as zeros or cut short. Correct: recovery stops at the first
# record that is not whole and valid and truncates there; ok on every seed of a sweep, a torn
# tail dropped in some, the self-check passing in all. Planted bug: recovery that trusts each
# record's length (`nocheck`) recovers a record no node wrote, found in most seeds; its first
# failing run replays identically.
#@ tier=quick budget=60 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/11-wal; mkdir -p "$o"
W_FAULTS="--crash machine --fault crash-gap-ms=300..1500 --fault down-ms=100..300 --fault max-incarnations=12"
# wal_sweep VARIANT KEEP: seeds 1-8 of VARIANT (ok, or nocheck) in $o/VARIANT; prints the outcomes.
wal_sweep() {
    f=$o/$1.toml; rm -f "$f"
    b=""; [ "$1" = ok ] || b=$1
    conf "$f" a python3 /guest/wal.py a $b
    rm -rf "${o:?}/$1"
    st=0
    timeout 600 "$PATINA" sweep --seeds 1..8 -j 4 --keep "$2" --out "$o/$1" --config "$f" $W_FAULTS \
        --mount "$PATINA_GUESTS":/guest:copy -- python3 /guest/wal.py driver 15 >"$o/$1.txt" 2>&1 || st=$?
    [ -f "$o/$1/report.json" ] || { tail -20 "$o/$1.txt"; die "sweep $1: no report (exit $st)"; }
    field "$o/$1/report.json" outcomes
}
out=$(wal_sweep ok all)
[ "$out" = '{"ok": 8}' ] || { tail -30 "$o/ok.txt"; die "correct: $out"; }
set -- $(python3 -I -c 'import json,re,sys
t=c=0
for d in sys.argv[1:]:
    t+=int(re.search(r"dropped in (\d+) of", open(d + "/inc-0/stdout").read()).group(1)) > 0
    c+=json.load(open(d + "/result.json"))["self_check"]["verdict"] == "pass"
print(t, c)' "$o"/ok/seed-*)
[ "$1" -ge 1 ] || die "correct: no torn tail in 8 runs (the scenario never arose)"
[ "$2" = 8 ] || die "correct: the self-check passed in only $2 of 8 runs"
echo "correct: ok on seeds 1-8, a torn tail dropped in $1 runs, self-check passed in all"
wal_sweep nocheck fail >/dev/null
n=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["outcomes"].get("failure", 0))' "$o/nocheck/report.json")
[ "$n" -ge 4 ] || die "nocheck: found in only $n of 8 seeds"
r=$(python3 -I -c 'import json,sys
g=[g for g in json.load(open(sys.argv[1]))["groups"] if g["outcome"] == "failure"]
r=["seed %s %s" % (x["replay"]["seed"], x["replay"]["result"]) for x in g if x["replay"]]
print(", ".join(r))
sys.exit(0 if r and len(r) == len(g) and all(x["replay"]["result"] == "identical" for x in g) else 1)' "$o/nocheck/report.json") \
    || die "nocheck: a first failing run did not replay identically: ${r:-no replay}"
echo "nocheck: found in $n of 8 seeds; replayed: $r"
