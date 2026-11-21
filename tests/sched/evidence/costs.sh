#!/bin/sh
# Scheduler evidence: cost of one call_sup round trip and of
# uncontended and contended mutexes, from the launcher's wall_ms of whole runs.
#   PATINA=... PATINA_CFG=tests/cfg PATINA_GUESTS=... OUT=dir sh tests/sched/evidence/costs.sh
set -eu
: "${PATINA:?}" "${PATINA_CFG:?}" "${PATINA_GUESTS:?}" "${OUT:?}"
mkdir -p "$OUT"
. "$(dirname "$0")/../../json.inc"
cpu=${CPU:-2}
run() { # name preempt args...
    name=$1; p=$2; shift 2
    for rep in 1 2 3; do
        o=$OUT/$name-$rep
        taskset -c "$cpu" "$PATINA" run --seed 1 --config "$("$PATINA_CFG" preempt-permille="$p")" --out "$o" --mount "$PATINA_GUESTS":/guest:copy -- "$@" >/dev/null
        echo "$name rep $rep: class $(field "$o/result.json" outcome) wall_ms $(field "$o/result.json" wall_ms) traps $(field "$o/result.json" sched.traps) switches $(field "$o/result.json" sched.switches)"
    done
}
N=1000000
run getppid-0 0 /guest/getppid 0
run getppid-N 0 /guest/getppid $N
run yield-0 0 /guest/cost yield 0
run yield-N 0 /guest/cost yield $N
run mutex1-N 0 /guest/cost mutex1 $N
run mutex1-N-p100 100 /guest/cost mutex1 $N
run mutex2-N-p100 100 /guest/cost mutex2 $N
run mutex2-N-p1000 1000 /guest/cost mutex2 $N
