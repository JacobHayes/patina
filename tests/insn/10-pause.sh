# 10. Pause points. The spin table (glibc pthread_spin_lock, a C test-and-set lock with the
# spin hint (x86 `pause`, arm64 `yield`), a Rust spin_loop lock (x86 `pause`, arm64 `isb`); two
# threads, the holder makes a system call inside the critical section) ends ok with the right
# count on seeds 1-3 with pause points, having yielded at them; with pause points off it ends
# unsupported, stop compute-stall; so does the C lock without the hint, with pause points on.
# glibc's arm64 spin lock has no hint (a plain load loop, glibc 2.39): it is a no-hint lock
# there and stalls with pause points on too (spin probes are its answer). One lock gives one
# digest over 5 runs under --vary cpu,aslr. Spin probes are off throughout, so that pause
# points alone are measured.
# Under [sched] preempt = "traps": these are its mechanisms (load-time points, the default,
# switch inside these loops at their points, so nothing stalls there).
#@ tier=quick budget=30 slots=1.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/10-pause
mkdir -p "$o"
# Test inputs (AGENTS.md): no spin probes, stall-ms 1000; pause points on or off per run.
export PATINA_TEST_SPIN_PROBES=0 PATINA_TEST_STALL_MS=1000
cfg=$("$PATINA_CFG" preempt=traps)
one() { # NAME SEED on|off PROG ARGS...
    n=$1 s=$2 p=$3; shift 3
    rm -rf "${o:?}/$n-$s-$p"
    if [ "$p" = on ]; then c=1; else c=0; fi
    PATINA_TEST_PAUSE_POINTS=$c timeout 20 "$PATINA" run --config "$cfg" --seed "$s" --out "$o/$n-$s-$p" \
        --mount "$PATINA_GUESTS":/guest:copy -- "$@" >/dev/null 2>&1 || true
}
for spec in "glibc-spin /guest/spinwait glibc-spin" "own-spin /guest/spinwait own-spin" "rs-spin /guest/rs-spin spin"; do
    for s in 1 2 3; do echo "$spec" | (read -r n g m; one "$n" "$s" on "$g" "$m") & done
    echo "$spec" | (read -r n g m; one "$n" 1 off "$g" "$m") &
    [ "$spec" != "${spec#own-spin}" ] && one nohint 1 on /guest/spinwait own-spin-nohint &
    wait
done
# The hinted locks; on arm64 glibc's is not one.
hinted="own-spin rs-spin"
if [ "$ARCH" = x86_64 ]; then hinted="glibc-spin $hinted"; else nohint="glibc-spin-1-on"; fi
for d in nohint-1-on ${nohint:-}; do
    r="$(field "$o/$d/result.json" outcome)/$(field "$o/$d/result.json" stop)"
    [ "$r" = unsupported/compute-stall ] || die "$d (no hint), pause points on: $r $(field "$o/$d/result.json" message)"
    echo "${d%-1-on} (no hint), pause points on: $r"
done
# Determinism with pause points: 5 runs under varied CPU and address layout, one digest.
rm -rf "${o:?}/verify"
timeout 60 "$PATINA" verify --config "$cfg" --seed 2 --runs 5 --vary cpu,aslr --out "$o/verify" \
    --mount "$PATINA_GUESTS":/guest:copy -- /guest/spinwait own-spin >/dev/null 2>&1 || true
nd=$(for i in 0 1 2 3 4; do field "$o/verify/run-$i/result.json" digest; done | sort -u | wc -l)
[ "$nd" = 1 ] || die "own-spin seed 2: $nd digests over 5 runs under --vary cpu,aslr"
echo "own-spin seed 2: one digest over 5 runs under --vary cpu,aslr ($(field "$o/verify/run-0/result.json" sched.pause_points) pause points)"
for n in $hinted; do
    for s in 1 2 3; do
        d=$o/$n-$s-on
        [ "$(field "$d/result.json" outcome)" = ok ] || die "$n seed $s: $(field "$d/result.json" outcome) $(field "$d/result.json" message)"
        grep -q 'counter=4000' "$d/boot-1/stdout" || die "$n seed $s: wrong count: $(cat "$d/boot-1/stdout")"
        [ "$(field "$d/result.json" sched.pause_points)" -gt 0 ] || die "$n seed $s: no pause point"
    done
    d=$o/$n-1-off
    r="$(field "$d/result.json" outcome)/$(field "$d/result.json" stop)"
    [ "$r" = unsupported/compute-stall ] || die "$n, pause points off: $r $(field "$d/result.json" message)"
    echo "$n: ok on seeds 1-3 (pause points $(field "$o/$n-1-on/result.json" sched.pause_points) on seed 1, sites $(field "$o/$n-1-on/result.json" sched.pause_sites)); off: $r"
done
