# 5. Determinism with crashes on: W9 with crashes + filesystem errors, 4 runs per seed under
# --vary cpu,load,aslr,sandbox, seeds 1-2, both crash models (the two models in parallel). patina verify compares digests,
# outcomes, output and every crash record (which carries the post-crash tree's digest).
#@ tier=area budget=60 slots=4
. "$(dirname "$0")/lib/common.inc"
one_model() {
    m=$1
    for s in 1 2; do
        o=$RUNS/verify-$m-$s
        timeout 600 "$PATINA" verify --seed "$s" --runs 4 --vary cpu,load,aslr,sandbox --out "$o" \
            --mount "$W/fjall-harness":/guest:copy --config "$("$PATINA_CFG" fs-model="$m")" --crash machine:5 --fault fs-error-permille=2 \
            -- /guest/fjall-harness-release >"$o.txt" 2>&1 || grep -q '^identical: ' "$o.txt" || { echo "FAIL: $m seed $s: $(tail -3 "$o.txt")"; return 1; }
        echo "$m seed $s: $(tail -1 "$o.txt")"
        rm -rf "${o:?}"
    done
}
one_model ext4-ordered >"$RUNS/ext4.log" 2>&1 & p1=$!
one_model posix-strict >"$RUNS/posix.log" 2>&1 & p2=$!
st=0
wait $p1 || st=1
wait $p2 || st=1
cat "$RUNS/ext4.log" "$RUNS/posix.log"
exit $st
