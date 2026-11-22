# 9. BTI. A BTI-marked program, dynamic (its loader makes its text PROT_BTI where the CPU has
# BTI; the scan follows that mprotect) and static (the runtime's loader does, as the kernel
# would): its `isb` (a pause site) reached by an indirect call to a landing pad runs as a pause
# point: ok, the same digest twice. An indirect call to a patched site that is not a landing
# pad (`bare`, starting with `isb`) is the program's branch-target fault, as without Patina:
# SIGILL at the site, not a pause point (on a host without BTI the call is fine). A signal
# handler in a BTI-guarded shared object (bti-sig): with a landing pad it runs; without one its
# entry is the same fault.
#@ tier=quick budget=10 arch=aarch64 slots=0.5
. "$(dirname "$0")/lib.inc"
for g in bti-dyn bti-static; do
    for k in a b; do
        prun "$RUNS/$g-$k" --seed 1 -- "$PATINA_GUESTS/$g"
        [ "$st" = 0 ] || die "$g $k: exit $st ($(tail -2 "$RUNS/$g-$k.txt"))"
        grep -qx 'spin 45' "$RUNS/$g-$k/boot-1/stdout" || die "$g $k: $(cat "$RUNS/$g-$k/boot-1/stdout")"
        [ "$(field "$RUNS/$g-$k/result.json" sched.pause_points)" -ge 10 ] || die "$g $k: the isb was not a pause point"
    done
    lhs=$(field "$RUNS/$g-a/result.json" digest); rhs=$(field "$RUNS/$g-b/result.json" digest)
    [ "$lhs" = "$rhs" ] || die "$g: digests differ between repeats"
    echo "$g: spin 45, $(field "$RUNS/$g-a/result.json" sched.pause_points) pause points, the same digest twice"
done
bti=0
grep -qw bti /proc/cpuinfo && bti=1
[ $bti = 1 ] || echo "SKIP: this host has no BTI: the branch-target faults are not exercised, only that the same calls run"
# check NAME WANT-ON-BTI-HOST WANT-STDOUT-ELSEWHERE -- CMD...
check() {
    n=$1 want=$2 expect=$3
    shift 4
    prun "$RUNS/$n" --seed 1 -- "$@"
    f=$RUNS/$n/result.json
    r="$(field "$f" outcome)/$(field "$f" guest.signal)"
    if [ $bti = 1 ] && [ "$want" != ok ]; then
        [ "$r/$(field "$f" sched.pause_points)" = "$want" ] || die "$n: $r (want $want) $(field "$f" message)"
    else
        [ "$st" = 0 ] && grep -qx "$expect" "$RUNS/$n/boot-1/stdout" || die "$n: $r, $(cat "$RUNS/$n/boot-1/stdout")"
    fi
    echo "$n: $r (outcome/signal)"
}
check violate-dyn crash/4/0 'bare 07' -- "$PATINA_GUESTS/bti-dyn" violate
check violate-static crash/4/0 'bare 07' -- "$PATINA_GUESTS/bti-static" violate
check handler-pad ok 'handled 1' -- "$PATINA_GUESTS/bti-sig" pad
check handler-bare crash/4/0 'handled 2' -- "$PATINA_GUESTS/bti-sig" bare
