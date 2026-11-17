#!/bin/sh
# 10. Pause points. The spin table (glibc pthread_spin_lock, a C test-and-set lock with
# `pause`, a Rust spin_loop lock; two threads, the holder makes a system call inside the
# critical section) ends ok with the right count on seeds 1-3 with pause points, having
# yielded at them; with pause points off it ends unsupported, stop compute-stall. One of
# them gives one digest over 5 runs under --vary cpu,aslr. Spin probes are off throughout,
# so that pause points alone are measured.
#@ tier=quick budget=30 slots=4 arch=x86_64
. "$(dirname "$0")/lib.inc"
o=$RUNS/10-pause
mkdir -p "$o"
cfg_on=$("$PATINA_CFG" pause-points=true spin-probes=false stall-ms=1000)
cfg_off=$("$PATINA_CFG" pause-points=false spin-probes=false stall-ms=1000)
one() { # NAME SEED on|off PROG ARGS...
    n=$1 s=$2 p=$3; shift 3
    rm -rf "$o/$n-$s-$p"
    if [ "$p" = on ]; then c=$cfg_on; else c=$cfg_off; fi
    timeout 20 "$PATINA" run --seed "$s" --config "$c" --out "$o/$n-$s-$p" \
        --mount "$PATINA_GUESTS":/guest:copy -- "$@" >/dev/null 2>&1 || true
}
for spec in "glibc-spin /guest/spinwait glibc-spin" "own-spin /guest/spinwait own-spin" "rs-spin /guest/rs-spin spin"; do
    for s in 1 2 3; do echo "$spec" | (read -r n g m; one "$n" "$s" on "$g" "$m") & done
    echo "$spec" | (read -r n g m; one "$n" 1 off "$g" "$m") &
    wait
done
# Determinism with pause points: 5 runs under varied CPU and address layout, one digest.
rm -rf "$o/verify"
timeout 60 "$PATINA" verify --seed 2 --runs 5 --vary cpu,aslr --config "$cfg_on" --out "$o/verify" \
    --mount "$PATINA_GUESTS":/guest:copy -- /guest/spinwait own-spin >/dev/null 2>&1 || true
nd=$(for i in 0 1 2 3 4; do field "$o/verify/run-$i/result.json" digest; done | sort -u | wc -l)
[ "$nd" = 1 ] || die "own-spin seed 2: $nd digests over 5 runs under --vary cpu,aslr"
echo "own-spin seed 2: one digest over 5 runs under --vary cpu,aslr ($(field "$o/verify/run-0/result.json" sched.pause_points) pause points)"
for n in glibc-spin own-spin rs-spin; do
    for s in 1 2 3; do
        d=$o/$n-$s-on
        [ "$(field "$d/result.json" outcome)" = ok ] || die "$n seed $s: $(field "$d/result.json" outcome) $(field "$d/result.json" message)"
        grep -q 'counter=4000' "$d/inc-0/stdout" || die "$n seed $s: wrong count: $(cat "$d/inc-0/stdout")"
        [ "$(field "$d/result.json" sched.pause_points)" -gt 0 ] || die "$n seed $s: no pause point"
    done
    d=$o/$n-1-off
    r="$(field "$d/result.json" outcome)/$(field "$d/result.json" stop)"
    [ "$r" = unsupported/compute-stall ] || die "$n, pause points off: $r $(field "$d/result.json" message)"
    echo "$n: ok on seeds 1-3 (pause points $(field "$o/$n-1-on/result.json" sched.pause_points) on seed 1, sites $(field "$o/$n-1-on/result.json" sched.pause_sites)); off: $r"
done
