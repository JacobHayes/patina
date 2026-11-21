# 21. The shared mappings of 19-mapshare under every crash point (branch sweeps under machine
# crashes): `order`, a pwrite on a page another process stored to through its mapping: no file
# holds the write without the stores; `durable`, a store made by one process and fsynced by
# another, before a synced marker: the marker means the store survived, and a later unsynced
# store of the same process is lost after some crash; `durable-sync`, the same with sync(2) by a
# process mapping another page of the file. Every crash point is tried.
#@ tier=area,release budget=30 slots=4
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/21
rm -rf "${d:?}"
mkdir -p "$d"
o=$d/sweep-order
st=0
timeout 300 "$PATINA" sweep --seeds 1..20 --crash-points --faults crash --keep fail --out "$o" \
    --allow-unmet synced-store-kept --allow-unmet unsynced-store-lost --mount "$PATINA_GUESTS":/guest:copy -- /guest/mapshare order >"$o.txt" 2>&1 || st=$?
[ $st = 0 ] || die "branch sweep of order under machine crashes: exit $st: $(head -5 "$o.txt")"
echo "order: branch sweep under machine crashes: $(grep -E '^patina sweep' "$o.txt" | cut -d'(' -f1)"
# durable-sync: the syncing process maps only another page of the file.
for m in durable durable-sync; do
    o=$d/sweep-$m
    st=0
    timeout 300 "$PATINA" sweep --seeds 1..2 --crash-points --faults crash --keep fail --out "$o" \
        --allow-unmet write-keeps-earlier-store --mount "$PATINA_GUESTS":/guest:copy -- /guest/mapshare $m >"$o.txt" 2>&1 || st=$?
    [ $st = 0 ] || die "branch sweep of $m under machine crashes: exit $st: $(head -5 "$o.txt")"
    echo "branch sweep, $m under machine crashes: $(grep -E '^patina sweep' "$o.txt" | cut -d'(' -f1)"
    # Every crash point was tried, and the unsynced store was lost after some crash.
    python3 -I - "$o/report.json" $m <<'PY' || exit 1
import json, sys
r = json.load(open(sys.argv[1]))
b = r["crash_points"]
if b["tried"] != b["points"] or b["points"] < 4:
    sys.exit("FAIL: %s: %d of %d crash points tried" % (sys.argv[2], b["tried"], b["points"]))
if "unsynced-store-lost" in json.dumps(r["sdk"]["sometimes_never_held"]):
    sys.exit("FAIL: %s: the unsynced store survived every crash" % sys.argv[2])
PY
done
