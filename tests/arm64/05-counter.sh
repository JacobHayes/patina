# 5. The counter-timer trap: reads of CNTFRQ_EL0 and CNTVCT_EL0 answer from virtual time, so
# two runs print the same values (the real counter moves between runs) and the counter goes
# forward between reads; also when the program is reached by an exec (which resets the trap).
#@ tier=quick budget=10 arch=aarch64
. "$(dirname "$0")/lib.inc"
for via in direct exec; do
    for k in a b; do
        case $via in
            direct) prun "$RUNS/$via$k" --seed 1 -- "$PATINA_GUESTS/counter" ;;
            exec) prun "$RUNS/$via$k" --seed 1 --mount "$PATINA_GUESTS:/guest" -- /usr/bin/env /guest/counter ;;
        esac
        [ "$st" = 0 ] || die "$via $k: exit $st ($(tail -2 "$RUNS/$via$k.txt"))"
    done
    a=$RUNS/${via}a/inc-0/stdout
    cmp -s "$a" "$RUNS/${via}b/inc-0/stdout" || die "$via: the reads differ between runs: $(tr '\n' ' ' <"$a") vs $(tr '\n' ' ' <"$RUNS/${via}b/inc-0/stdout")"
    awk '/^cntvct/ { if (NR > 2 && $2 <= last) bad = 1; last = $2 } END { exit bad }' "$a" ||
        die "$via: the counter did not go forward: $(tr '\n' ' ' <"$a")"
    echo "$via: $(tr '\n' ' ' <"$a")"
done
