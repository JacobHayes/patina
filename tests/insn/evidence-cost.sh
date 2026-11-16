# Evidence. Cost: a tight loop of 1,000,000 rdtsc natively and under patina (same core), time per
# emulation; rdtsc/rdtscp emulations per run for the scheduler/files guests, CPython and Go start-up.
#@ tier=evidence budget=300 slots=8
. "$(dirname "$0")/lib.inc"
o=$RUNS/08-cost
mkdir -p "$o"
c=$(( $(nproc) - 1 ))
now() { date +%s%N; }
for i in 1 2 3; do
    t0=$(now); taskset -c "$c" "$PATINA_GUESTS/insn" loop 1000000 >"$o/native-$i.txt"; t1=$(now)
    patina_run "$o/loop0-$i" 1 insn loop 0
    patina_run "$o/loop-$i" 1 insn loop 1000000
    [ "$(field "$o/loop-$i/result.json" outcome)" = ok ] || die "loop under patina"
    e=$(field "$o/loop-$i/result.json" counters.insn.emulated.rdtsc)
    [ "$e" -ge 1000000 ] || die "only $e emulations"
    w=$(field "$o/loop-$i/result.json" wall_ms); w0=$(field "$o/loop0-$i/result.json" wall_ms)
    rm -f "$o/loop-$i/inc-0/boundary.log"
    echo "run $i: native $(( (t1 - t0) / 1000000 )) ms for the process (loop alone: $(awk 'NR == 1 {print $6 / 1e6}' "$o/native-$i.txt") ms);" \
        "patina $w ms, empty loop $w0 ms: $(( (w - w0) * 1000 / (e / 1000) )) ns per emulated rdtsc"
done
echo "== rdtsc / rdtscp emulations per run (seed 1)"
for w in hello-dyn hello-static hello-rs c-threads order deadlock liveness rs-threads fs-tour tsorder \
    proc-policy insn-go-hello go-sig "/usr/bin/python3 -c pass" "/usr/bin/python3 -c import_json"; do
    name=$(echo "$w" | tr -c 'a-z0-9\n' '_' | cut -c1-24)
    # shellcheck disable=SC2086
    set -- $w
    if [ "$w" = "/usr/bin/python3 -c import_json" ]; then set -- /usr/bin/python3 -c 'import json, decimal, hashlib'; fi
    patina_run "$o/w-$name" 1 "$@" || true
    f=$o/w-$name/result.json
    echo "  $w: class $(field "$f" outcome), rdtsc $(field "$f" counters.insn.emulated.rdtsc), rdtscp $(field "$f" counters.insn.emulated.rdtscp), traps $(field "$f" sched.traps)"
    rm -f "$o/w-$name/inc-0/boundary.log"
done
