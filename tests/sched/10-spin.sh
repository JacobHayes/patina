# 10. Spin-waits without a system call or `pause` (tests/guests/threads/spinpoints.c), with
# stall-ms = 1000:
#  a. A flag spin (each iteration leaves the state unchanged) is found by a spin probe and the
#     run ends ok; with probes off it ends unsupported, stop compute-stall.
#  b. A spin that counts its iterations cannot be preempted: unsupported, stop compute-stall,
#     after stall-ms of CPU time plus a margin (CPU time, which host load does not stretch), naming the spinning thread; the same seed twice stops at
#     the same record (same digest).
#  c. One thread computing for about 2 s with no other thread is ok, not a stall.
#  d. Stock Go at the default CPU count (go-sweep, whose background sweeper spins without a
#     system call or `pause`) ends ok on seeds 1-3.
#  e. A spin that changes only memory (spinpoints memcount: its registers are the same each
#     iteration) is not found: unsupported, stop compute-stall.
#  f. No breakpoint stays in code once a probe ends: spinpoints text, 10 rounds each found by a
#     probe, checksums every executable segment after each round: unchanged; a thread that
#     finds a second spin point right after leaving the first (no system call between), then
#     its code run again by another thread: ok.
#  g. arm64: a spin lock on exclusive pairs (llsc-spin, ldaxr/stxr: test-and-set and
#     compare-and-swap) is found and ends ok with the right count; a stop inside a pair would
#     make its store fail every time.
#  h. JIT-style code (spinpoints jit): a branch to itself in writable, executable memory,
#     which the spinning thread's signal handler patches into a no-op: ok, the patch held (no
#     breakpoint is planted in writable code, where restoring the old word would undo it).
#  i. A flag wait with a bounded inner loop (spinpoints nested 300): the inner loop's counter
#     changes, the outer loop's state does not. Where a probe arrives depends on the host's
#     timing; what it decides must not: patina verify, 4 runs of seed 1 varying CPU, load and
#     address randomization, all ok, one digest, a spin point found.
#@ tier=quick budget=30 slots=5
. "$(dirname "$0")/lib.inc"
o=$RUNS/10-spin
mkdir -p "$o"
# Test inputs (AGENTS.md): each run's environment.
on="PATINA_TEST_STALL_MS=1000"
off="PATINA_TEST_STALL_MS=1000 PATINA_TEST_SPIN_PROBES=0"
one() { # OUT GUESTDIR SEED INPUTS -- PROG ARGS...
    d=$o/$1 g=$2 s=$3 c=$4; shift 4
    rm -rf "${d:?}"
    timeout 60 env $c "$PATINA" run --seed "$s" --out "$d" --mount "$g":/guest:copy "$@" >/dev/null 2>&1 || true
}
G=$PATINA_GUESTS
one flag "$G" 1 "$on" -- /guest/spinpoints flag &
one flag-off "$G" 1 "$off" -- /guest/spinpoints flag &
python3 -I "$(dirname "$0")/../cpu-ms.py" sh -c 'rm -rf "${1:?}" && exec timeout 60 env $3 "$2" run --seed 1 --out "$1" --mount "$4":/guest:copy -- /guest/spinpoints count' sh "$o/count-a" "$PATINA" "$on" "$G" >"$o/count-a.ms" &
one count-b "$G" 1 "$on" -- /guest/spinpoints count &
one alone "$G" 1 "$on" -- /guest/spinpoints alone 2000 &
wait
for s in 1 2 3; do one "go-$s" "$PATINA_WORKLOADS/go-static" "$s" "$on" -- /guest/go-sweep & done
one memcount "$G" 1 "$on" -- /guest/spinpoints memcount &
one text "$G" 1 "$on" -- /guest/spinpoints text 10 &
wait
arm64=""; [ "$(uname -m)" != aarch64 ] || arm64=yes # lint-allow: test-subst — uname -m does not fail
one twice "$G" 1 "$on" -- /guest/spinpoints twice &
one jit "$G" 1 "$on" --timeout 20 -- /guest/spinpoints jit &
timeout 120 env $on "$PATINA" verify --seed 1 --runs 4 --vary cpu,load,aslr --out "$o/nested" \
    --mount "$G":/guest:copy -- /guest/spinpoints nested 300 >"$o/nested.txt" 2>&1 || true &
[ -z "$arm64" ] || for m in xchg cas; do one "llsc-$m" "$G" 1 "$on" -- /guest/llsc-spin "$m" & done
wait
res() { echo "$(field "$o/$1/result.json" outcome)/$(field "$o/$1/result.json" stop): $(field "$o/$1/result.json" message)"; }
stall() { [ "$(field "$o/$1/result.json" outcome)/$(field "$o/$1/result.json" stop)" = unsupported/compute-stall ]; }

[ "$(field "$o/flag/result.json" outcome)" = ok ] || die "a. flag spin: $(res flag)"
[ "$(field "$o/flag/result.json" counters.sched.spin_found)" -gt 0 ] || die "a. flag spin: ok without a found spin"
stall flag-off || die "a. flag spin, probes off: $(res flag-off)"
echo "a. flag spin: ok, preemptions $(field "$o/flag/result.json" sched.preemptions); probes off: $(res flag-off | cut -c1-60)"

stall count-a || die "b. counting spin: $(res count-a)"
ms=$(cat "$o/count-a.ms")
[ "$ms" -ge 1000 ] && [ "$ms" -le 4000 ] || die "b. counting spin used $ms ms of CPU time"
field "$o/count-a/result.json" message | grep -q spinpoints || die "b. the message does not name the thread: $(res count-a)"
lhs=$(field "$o/count-a/result.json" digest); rhs=$(field "$o/count-b/result.json" digest)
[ "$lhs" = "$rhs" ] ||
    die "b. the same seed stopped at different records"
echo "b. counting spin after $ms ms of CPU time: $(res count-a | cut -c1-110)"

[ "$(field "$o/alone/result.json" outcome)" = ok ] || die "c. lone compute: $(res alone)"
echo "c. lone compute of about 2 s: ok, wall $(field "$o/alone/result.json" wall_ms) ms"

for s in 1 2 3; do
    [ "$(field "$o/go-$s/result.json" outcome)" = ok ] || die "d. go-sweep seed $s: $(res "go-$s")"
done
echo "d. go-sweep at the default CPU count: ok on seeds 1-3 (spin points found on seed 1: $(field "$o/go-1/result.json" counters.sched.spin_found))"

stall memcount || die "e. memory-only counting spin: $(res memcount)"
echo "e. memory-only counting spin: $(res memcount | cut -c1-60)"

[ "$(field "$o/text/result.json" outcome)" = ok ] && grep -qx 'text same after 10 rounds' "$o/text/inc-0/stdout" ||
    die "f. text checksum: $(res text) $(cat "$o/text/inc-0/stdout" 2>/dev/null)"
echo "f. text unchanged after 10 rounds ($(field "$o/text/result.json" counters.sched.spin_found) spin points found)"
[ "$(field "$o/twice/result.json" outcome)" = ok ] && grep -qx 'twice done' "$o/twice/inc-0/stdout" ||
    die "f. two spin points in a row: $(res twice) $(cat "$o/twice/inc-0/stdout" 2>/dev/null)"
[ "$(field "$o/twice/result.json" counters.sched.spin_found)" -ge 2 ] || die "f. twice: fewer than two spin points found"
echo "f. two spin points in a row, then their code run again: ok"

[ "$(field "$o/jit/result.json" outcome)" = ok ] && grep -qx 'jit patched' "$o/jit/inc-0/stdout" ||
    die "h. JIT code patched by its handler: $(res jit) $(cat "$o/jit/inc-0/stdout" 2>/dev/null)"
[ "$(field "$o/jit/result.json" counters.sched.spin_found)" -ge 1 ] || die "h. jit: ok without a found spin"
echo "h. JIT code patched by its signal handler while it spins: ok"

grep -q '^identical: ' "$o/nested.txt" || die "i. nested spin: verify differed: $(tail -3 "$o/nested.txt")"
for i in 0 1 2 3; do
    r=$o/nested/run-$i
    [ "$(field "$r/result.json" outcome)" = ok ] || die "i. nested spin, run $i: $(res "nested/run-$i")"
    [ "$(field "$r/result.json" counters.sched.spin_found)" -gt 0 ] || die "i. nested spin, run $i: ok without a found spin"
done
n=$(for i in 0 1 2 3; do field "$o/nested/run-$i/result.json" digest; done | sort -u | wc -l)
[ "$n" = 1 ] || die "i. nested spin: $n digests in 4 runs of one seed"
echo "i. nested spin: 4 runs of seed 1 under verify ok with one digest"

if [ "$arm64" ]; then
    for m in xchg cas; do
        d=$o/llsc-$m
        [ "$(field "$d/result.json" outcome)" = ok ] && grep -qx "$m counter=400" "$d/inc-0/stdout" ||
            die "g. llsc-spin $m: $(res "llsc-$m") $(cat "$d/inc-0/stdout" 2>/dev/null)"
        [ "$(field "$d/result.json" counters.sched.spin_found)" -gt 0 ] || die "g. llsc-spin $m: ok without a found spin"
    done
    echo "g. exclusive-pair spin locks: ok (spin points found: xchg $(field "$o/llsc-xchg/result.json" counters.sched.spin_found), cas $(field "$o/llsc-cas/result.json" counters.sched.spin_found))"
fi
