# W6 shell-pipeline under /bin/sh (dash) and /bin/bash over the system coreutils
# (tests/guests/shell-pipeline/w6.sh: pipelines, $(...), background jobs and wait, here-documents,
# find | sort | xargs (also -P4), tar create/extract round trip, ls -l, date, mktemp, sleep 5).
# Regressions (the evidence tier's matrix and soak have W6).
#  a. R: `ok`; stdout equals a native run after masking the "~ " lines.
#  b. D (seed 1, 3 runs, --vary cpu,load,aslr,sandbox), faults off and on (fs-error-permille=10);
#     identical stdout includes the masked lines (ls -l times, date, mktemp names, PIDs).
#  c. ls -l times and date are virtual (2026-01-01 epoch).
#  d. `sleep 5` takes 5 s of virtual time: the script's own date check (elapsed >= 5 s).
#  e. fs-error-permille=10 over 24 seeds, each shell (the script's files are under /work, where
#     file faults act): every run `ok` or `failure` with an exit status (no signal); every failing
#     run stopped before "done" (set -e) with a tool's error on stderr; at least one run failed
#     that way.
#  f. more than one digest over 4 seeds (the seed reaches the run).
#@ tier=area budget=150 slots=4
. "$(dirname "$0")/lib.inc"
S=shell-pipeline
FAULT="--fault fs-error-permille=10"

one_shell() {
    sh=$1
    echo "== $sh: a. R"
    n_ms=$(native "$RUNS/$sh-native.txt" "$W/$S" /bin/$sh /guest/w6.sh)
    run $S "$RUNS/$sh-r" 1 -- /bin/$sh /guest/w6.sh
    c=$(field "$RUNS/$sh-r/result.json" outcome)
    echo "$sh seed 1: class $c, wall $(field "$RUNS/$sh-r/result.json" wall_ms) ms, native wall ${n_ms} ms"
    [ "$c" = ok ] || fail "W6 $sh seed 1: class $c"
    grep -v '^~ ' "$RUNS/$sh-native.txt" >"$RUNS/$sh-native.masked"
    grep -v '^~ ' "$RUNS/$sh-r/inc-0/stdout" | cmp - "$RUNS/$sh-native.masked" \
        && echo "$sh: stdout equals native after masking $(grep -c '^~ ' "$RUNS/$sh-native.txt") lines" \
        || fail "W6 $sh: stdout differs from native after masking"
    [ "$(tail -1 "$RUNS/$sh-r/inc-0/stdout")" = done ] || fail "W6 $sh: script did not finish"

    echo "== $sh: b. D, faults off and on"
    verify_seeds $S $sh-d cpu,load,aslr,sandbox "1" -- /bin/$sh /guest/w6.sh || fail "W6 $sh D (faults off)"
    verify_seeds $S $sh-df cpu,load,aslr,sandbox "1" $FAULT -- /bin/$sh /guest/w6.sh || fail "W6 $sh D (faults on)"

    echo "== $sh: c. virtual times"
    o=$RUNS/$sh-d/seed-1/run-0/inc-0/stdout
    awk '/^~ ls -l -/ && n++ < 2' "$o"
    grep '^~ date' "$o"
    n=$(awk '/^~ ls -l -/ && !/ 2026-01-01 00:00:0/ {n++} END {print n + 0}' "$o")
    [ "$n" = 0 ] || fail "W6 $sh: $n ls -l lines with a time outside the virtual epoch's first seconds"
    d=$(sed -n 's/^~ date +%s //p' "$o")
    [ "$d" -ge 1767225600 ] && [ "$d" -lt 1767225660 ] || fail "W6 $sh: date +%s = $d, not virtual time"

    echo "== $sh: f. distinct digests over 4 seeds"
    SWEEP_JOBS=2 sweep $sh-4 $S 1-4 -- -- /bin/$sh /guest/w6.sh
    d=$(digests $sh-4)
    echo "W6 $sh: $d distinct digests over seeds 1-4"
    [ "$d" -ge 2 ] || fail "W6 $sh: one digest for 4 seeds"

    echo "== $sh: e. fs-error-permille=10 over 24 seeds"
    SWEEP_JOBS=2 SWEEP_KEEP=all sweep $sh-f24 $S 1-24 -- $FAULT -- /bin/$sh /guest/w6.sh
    awk -F'\t' 'NR>1 {print $2, $3}' "$RUNS/$sh-f24/summary.tsv" | sort | uniq -c
    bad=$(awk -F'\t' 'NR>1 && !($2=="ok" || ($2=="failure" && $3 ~ /^exit status/))' "$RUNS/$sh-f24/summary.tsv" | wc -l)
    [ "$bad" = 0 ] || fail "W6 $sh faults: $bad runs neither ok nor failed with an exit status"
    nf=0
    for s in $(seq 1 24); do
        o=$RUNS/$sh-f24/run-$s
        if [ "$(field "$o/result.json" outcome)" = failure ]; then
            nf=$((nf + 1))
            last=$(tail -1 "$o/inc-0/stdout")
            [ "$last" != done ] || fail "W6 $sh seed $s: failed but printed done"
            [ -s "$o/inc-0/stderr" ] || fail "W6 $sh seed $s: failed with an empty stderr"
        fi
    done
    echo "$sh: $nf of 24 runs stopped by set -e after an injected error"
    [ "$nf" -gt 0 ] || fail "W6 $sh: no run stopped on an injected error"
    exit "$FAILS"
}
# The two shells run concurrently (2 sandboxes each at most); their output is printed in order.
(one_shell sh >"$RUNS/sh.log" 2>&1) & p1=$!
(one_shell bash >"$RUNS/bash.log" 2>&1) & p2=$!
wait $p1 || FAILS=$((FAILS + $?))
wait $p2 || FAILS=$((FAILS + $?))
cat "$RUNS/sh.log" "$RUNS/bash.log"

echo "== d. sleep 5 in virtual time"
grep -q '^sleep 5: elapsed >= 5: yes$' "$RUNS/sh-r/inc-0/stdout" || fail "W6: the script's sleep 5 did not take 5 virtual seconds"
finish
