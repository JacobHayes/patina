# 10. Crash-point coverage for ack-log over COV_SEEDS seeds (default 50; evidence: 500) (crash-permille=20,
# ext4-ordered): the
# number of distinct post-crash trees, and crashes observed between a write and its fsync,
# between the record fsync and the acknowledgement write, and between the checkpoint
# rename and the directory fsync. Which seeds crash where depends on the host, and the last of
# these is rare (about one crash in thirty), so when one of them is missing the sweep goes on
# over the next COV_SEEDS seeds, up to six times COV_SEEDS.
#@ tier=area budget=120
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/10
mkdir -p "$d"
: >"$d/positions"
: >"$d/trees"
N=${COV_SEEDS:-50}
W1='^write->fsync (data.log)$' W2='^fsync->ack-write$' W3='^rename->dir-fsync$'
a=1
while :; do
    b=$((a + N - 1))
    SWEEP_KEEP=all sweep 10/sweep "$a-$b" --fault crash-permille=20 -- /guest/ack-log correct
    bad=$(awk -F'\t' 'NR > 1 && $2 != "ok" {print; exit}' "$d/sweep/summary.tsv")
    [ -z "$bad" ] || die "not ok: $bad"
    for seed in $(seq "$a" "$b"); do
        o=$d/sweep/run-$seed
        set --; for inc in "$o"/boot-*; do [ -d "$inc/post-crash" ] && set -- "$@" "$inc"; done
        [ $# = 0 ] || python3 -I "$LIB/faults.py" crash-position "$@" >>"$d/positions"
        jq -r '.crashes[].tree_digest' "$o/result.json" >>"$d/trees"
        rm -rf "${o:?}"
    done
    { grep -q "$W1" "$d/positions" && grep -q "$W2" "$d/positions" && grep -q "$W3" "$d/positions"; } || [ "$b" -ge $((6 * N)) ] || { a=$((b + 1)); continue; }
    break
done
echo "seeds 1-$b: crashes: $(wc -l <"$d/positions"); distinct post-crash trees: $(sort -u "$d/trees" | wc -l)"
sort "$d/positions" | uniq -c | sort -rn
grep -q "$W1" "$d/positions" || die "no crash between a record write and its fsync"
grep -q "$W2" "$d/positions" || die "no crash between the record fsync and the ack write"
grep -q "$W3" "$d/positions" || die "no crash between the rename and the directory fsync"
