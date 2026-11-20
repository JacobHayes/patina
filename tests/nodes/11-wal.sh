# 11. Nodes: a log recovered after machine crashes (tests/guests/nodes/wal.py). Node a appends
# checksummed records, fsyncing every fourth, and fsyncs another file every third, so a crash
# can leave the log's last record as zeros or cut short. Correct: recovery stops at the first
# record that is not whole and valid and truncates there; ok on every seed of a sweep, the
# self-check passing in all, and a torn tail dropped (searched past the sweep's seeds if none
# of them had one). Planted bug: recovery that trusts each record's length (`nocheck`)
# recovers a record no node wrote, found by a search of seeds (find_bug); its first failing
# run replays identically.
#@ tier=area,release budget=60 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/11-wal; mkdir -p "$o"
W_FAULTS="--crash machine --fault crash-gap-ms=300..1500 --fault down-ms=100..300 --fault max-incarnations=12"
# The correct version: seeds 1-8, every run kept.
rm -f "$o/ok.toml"; conf "$o/ok.toml" a python3 /guest/wal.py a
rm -rf "${o:?}/ok"
st=0
timeout 600 "$PATINA" sweep --seeds 1..8 -j 4 --keep all --out "$o/ok" --config "$o/ok.toml" $W_FAULTS \
    --mount "$PATINA_GUESTS":/guest:copy -- python3 /guest/wal.py driver 15 >"$o/ok.txt" 2>&1 || st=$?
[ -f "$o/ok/report.json" ] || { tail -20 "$o/ok.txt"; die "sweep ok: no report (exit $st)"; }
out=$(field "$o/ok/report.json" outcomes)
[ "$out" = '{"ok": 8}' ] || { tail -30 "$o/ok.txt"; die "correct: $out"; }
# torn DIR...: how many of the runs dropped a torn tail.
torn() {
    python3 -I -c 'import re,sys
print(sum(int(re.search(r"dropped in (\d+) of", open(d + "/inc-0/stdout").read()).group(1)) > 0 for d in sys.argv[1:]))' "$@"
}
c=$(python3 -I -c 'import json,sys; print(sum(json.load(open(d + "/result.json"))["self_check"]["verdict"] == "pass" for d in sys.argv[1:]))' "$o"/ok/seed-*)
[ "$c" = 8 ] || die "correct: the self-check passed in only $c of 8 runs"
t=$(torn "$o"/ok/seed-*)
# The scenario must arise: if no run of the sweep tore a tail, later seeds one at a time, each ok.
s=9
while [ "$t" = 0 ] && [ $s -le $FIND_SEEDS ]; do
    run_ok "$o/ok-$s" $s --config "$o/ok.toml" $W_FAULTS -- python3 /guest/wal.py driver 15
    t=$(torn "$o/ok-$s"); s=$((s + 1))
done
[ "$t" -ge 1 ] || die "correct: no torn tail in seeds 1-$FIND_SEEDS (the scenario never arose)"
echo "correct: ok on seeds 1-8 with the self-check passing in all; a torn tail dropped in $t runs (seeds 1-$((s - 1)))"
f=$o/nocheck.toml; rm -f "$f"; conf "$f" a python3 /guest/wal.py a nocheck
r=$(find_bug "$o" nocheck --config "$f" $W_FAULTS -- python3 /guest/wal.py driver 15)
echo "nocheck: $r"
