#!/bin/sh
# Scheduler evidence: cost of one call_sup round trip and of
# uncontended and contended mutexes, from the launcher's wall_ms of whole runs.
#   PATINA=... PATINA_GUESTS=... OUT=dir sh tests/sched/evidence/costs.sh
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${OUT:?}"
mkdir -p "$OUT"
field() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }
cpu=${CPU:-2}
run() { # name preempt args...
    name=$1; p=$2; shift 2
    for rep in 1 2 3; do
        o=$OUT/$name-$rep
        "$PATINA" run --cpu "$cpu" --seed 1 --preempt-permille "$p" --out "$o" --guest "$PATINA_GUESTS" -- "$@" >/dev/null
        echo "$name rep $rep: class $(field "$o/outcome.json" class) wall_ms $(field "$o/outcome.json" wall_ms) traps $(field "$o/outcome.json" traps) switches $(field "$o/outcome.json" switches)"
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
