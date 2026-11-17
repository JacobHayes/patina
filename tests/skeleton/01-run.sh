# 1. patina run --seed 1 for each guest: outcome ok, stdout as expected, PID printed is 2.
#@ tier=quick arch=x86_64
. "$(dirname "$0")/lib.inc"
for g in $GUESTS; do
    out=$RUNS/01-run/$g
    patina_run "$out" 1 "$g" a b
    c=$(field "$out/result.json" outcome)
    [ "$c" = ok ] || die "$g: class $c ($(field "$out/result.json" message))"
    python3 -I "$(dirname "$0")/check_hello.py" "$out/inc-0/stdout" "$g" a b || die "$g: stdout"
    echo "$g ok digest $(field "$out/result.json" digest) traps $(field "$out/result.json" sched.traps)"
done
