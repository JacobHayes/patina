# 6. Memory: mem-error-at=N swept over the guest's memory requests: each mmap step sees
# ENOMEM exactly at its call and the guest carries on; thread creation fails with EAGAIN;
# with every request failing after a point, malloc returns NULL with ENOMEM.
#@ tier=quick budget=30
. "$(dirname "$0")/lib/common.inc"
seen=""
for n in $(seq 1 24); do
    o=$RUNS/06/at-$n
    run "$o" 1 --fault mem-error-at=$n -- /guest/memfault
    [ "$(class "$o")" = ok ] || die "mem-error-at=$n: $(class "$o") $(field "$o/outcome.json" message)"
    grep -qx done "$o/inc-0/stdout" || die "mem-error-at=$n: guest did not finish"
    [ "$(grep -v ' ok$' "$o/inc-0/stdout" | grep -vc '^done$')" -le 1 ] || die "mem-error-at=$n: more than one failed step"
    f=$(grep -v ' ok$' "$o/inc-0/stdout" | grep -v '^done$' | tr '\n' ' ')
    echo "mem-error-at=$n: $(field "$o/outcome.json" faults.recent | python3 -I -c 'import json,sys; print(" ".join(x["call"] for x in json.load(sys.stdin)) or "-")') -> ${f:-no failure visible to the guest (handled by libc, or N beyond its requests)}"
    seen="$seen$f"
done
for k in 0 1 2 3 4; do
    echo "$seen" | grep -q "step $k mmap ENOMEM" || die "mmap step $k never saw ENOMEM"
done
echo "$seen" | grep -q "step 10 thread EAGAIN" || die "thread creation never failed with EAGAIN"
# The order: the failing mmap step follows N.
prev=-1
for n in $(seq 1 24); do
    k=$(grep -o 'step [0-4] mmap ENOMEM' "$RUNS/06/at-$n/inc-0/stdout" | awk '{print $2}')
    [ -z "$k" ] && continue
    [ "$k" -gt "$prev" ] || die "mmap failures not in call order"
    prev=$k
done
# malloc: fail every request from the first malloc's mmap on (its seq from a plain run).
o0=$RUNS/06/plain
run "$o0" 1 -- /guest/memfault
s=$("$PATINA" log dump "$o0/inc-0/boundary.log" | grep -m1 ' mmap .*args=\[0x0, 0x41000,' | awk '{print $1}' | cut -d= -f2)
[ -n "$s" ] || die "cannot find the first malloc's mmap in the log"
o=$RUNS/06/malloc
run "$o" 1 --fault mem-error-permille=1000 --fault fault-after-seq=$s -- /guest/memfault
grep -q "step 5 malloc ENOMEM" "$o/inc-0/stdout" || die "malloc did not return NULL/ENOMEM: $(cat "$o/inc-0/stdout")"
grep -qx done "$o/inc-0/stdout" || die "guest did not finish after malloc failures"
echo "every request failing from seq $s: $(grep -v ' ok$' "$o/inc-0/stdout" | tr '\n' ' ')"
