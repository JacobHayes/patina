# 5. preempt-permille 0 and 1000 both pass the 01-ok and 02-verify checks; switches per run for 0, 100, 1000.
#@ tier=area budget=60 arch=x86_64
. "$(dirname "$0")/lib.inc"
. "$(dirname "$0")/verify.inc"
for p in 0 1000; do
    for g in $GUESTS; do
        out=$RUNS/05-preempt/p$p-$g
        PATINA_OPTS="--config $("$PATINA_CFG" preempt-permille="$p")" patina_run "$out" 1 "$g"
        check_result "$out" "$g"
    done
    verify_all "05-preempt/verify-p$p" --config "$("$PATINA_CFG" preempt-permille="$p")"
done
echo "switches per run (seed 1):"
for g in $GUESTS; do
    line="$g:"
    for p in 0 100 1000; do
        out=$RUNS/05-preempt/switches-p$p-$g
        PATINA_OPTS="--config $("$PATINA_CFG" preempt-permille="$p")" patina_run "$out" 1 "$g"
        check_result "$out" "$g"
        line="$line p$p=$(field "$out/result.json" sched.switches)/$(field "$out/result.json" sched.traps)traps"
    done
    echo "$line"
done
