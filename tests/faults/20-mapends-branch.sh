# 20. The modes of 18-mapends under every crash point: a branch sweep of the durability case (a
# killed child's store, then fsync of the file and the directory by its parent, then a synced
# marker: after a machine crash the marker means the store survived) and of kill, forked, vfork,
# orphan and fixed (a flush of two records, which a crash point between them cuts) under
# process and machine crashes: no finding, no self-check failure; every crash point of the
# durability case is tried.
#@ tier=area,release budget=30 slots=4
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/20
rm -rf "${d:?}"
mkdir -p "$d"
for spec in "machine durable" "process kill" "machine kill" "machine forked" "process vfork" "machine vfork" "process orphan" "machine orphan" "process fixed" "machine fixed"; do
    read -r plane m <<<"$spec"
    o=$d/sweep-$plane-$m
    st=0
    timeout 300 "$PATINA" sweep --seeds 1..2 --branch --crash "$plane" --keep fail --out "$o" \
        --mount "$PATINA_GUESTS":/guest:copy -- /guest/mapends "$m" >"$o.txt" 2>&1 || st=$?
    [ $st = 0 ] || die "branch sweep $m under $plane crashes: exit $st: $(head -5 "$o.txt")"
    echo "branch sweep, $m under $plane crashes: $(grep -E '^patina sweep' "$o.txt" | cut -d'(' -f1)"
done
# Every crash point of the durability case was tried, and some crashed after the marker.
python3 -I - "$d/sweep-machine-durable/report.json" <<'PY' || exit 1
import json, sys
r = json.load(open(sys.argv[1]))
b = r["branch"]
if b["tried"] != b["points"] or b["points"] < 4:
    sys.exit("FAIL: durable: %d of %d crash points tried" % (b["tried"], b["points"]))
PY
