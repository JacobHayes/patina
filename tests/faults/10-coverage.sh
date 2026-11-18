# 10. Crash-point coverage for ack-log over COV_SEEDS seeds (default 20; evidence: 500) (machine:20,
# ext4-ordered): the
# number of distinct post-crash trees, and crashes observed between a write and its fsync,
# between the record fsync and the acknowledgement write, and between the checkpoint
# rename and the directory fsync.
#@ tier=area budget=120
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/10
mkdir -p "$d"
: >"$d/positions"
: >"$d/trees"
N=${COV_SEEDS:-20}
SWEEP_KEEP=all sweep 10/sweep "$N" --crash machine:20 -- /guest/ack-log correct
bad=$(awk -F'\t' 'NR > 1 && $2 != "ok" {print; exit}' "$d/sweep/summary.tsv")
[ -z "$bad" ] || die "not ok: $bad"
for seed in $(seq 1 "$N"); do
    o=$d/sweep/run-$seed
    set --; for inc in "$o"/inc-*; do [ -d "$inc/post-crash" ] && set -- "$@" "$inc"; done
    [ $# = 0 ] || python3 -I "$LIB/faults.py" crash-position "$@" >>"$d/positions"
    jq -r '.crashes[].tree_digest' "$o/result.json" >>"$d/trees"
    rm -rf "${o:?}"
done
echo "crashes: $(wc -l <"$d/positions"); distinct post-crash trees: $(sort -u "$d/trees" | wc -l)"
sort "$d/positions" | uniq -c | sort -rn
grep -q '^write->fsync (data.log)$' "$d/positions" || die "no crash between a record write and its fsync"
grep -q '^fsync->ack-write$' "$d/positions" || die "no crash between the record fsync and the ack write"
grep -q '^rename->dir-fsync$' "$d/positions" || die "no crash between the rename and the directory fsync"
