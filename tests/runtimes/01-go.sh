# W4 go-static: stock static Go at the default CPU count (regressions;
# the 100-seed stall rates are tests/runtimes/evidence-go-stalls.sh).
#  a. R: `ok`, stdout equal to a native run after masking "~ " lines and the gomaxprocs line.
#  b. Spin-waits: the reproducer go-sweep (whose background sweeper spins without a system call
#     or `pause`) is ok on seeds 1-8; with traps and spin probes off it ends unsupported,
#     stop compute-stall, on at least one of them, and every other run is ok (load-time
#     points switch inside the sweeper's loop, so it does not stall). go-static is ok on
#     seeds 1-8.
#  c. D (seed 1, --vary cpu,load,aslr,sandbox), faults off and on.
#  d. F: an injected file error is seen by the program (printed "file error:" lines).
#  e. Report: threads, SIGURG sends and deliveries, rdtsc emulations, futex calls, denied calls.
#  f. go-spin: a goroutine computing without a trap for less than stall-ms is `ok`; a 20 s
#     spin with traps under stall-ms = 1000 ends as `unsupported` (compute-stall) (after 1 s,
#     not 20; with load-time points it is preempted at its loop's point and runs to its end).
#  g. Network: D with network faults; net-reset-permille seen as "connection reset
#     by peer", a 10 s net-blackout seen as the http.Client's 5 s timeout, net-chunk-max=1
#     with all 16 responses correct.
#@ tier=area budget=90 slots=4
. "$(dirname "$0")/lib.inc"
G=go-static
FAULT="--fault fs-error-permille=20"
NETF="--fault net-reset-permille=30 --fault net-chunk-max=7 --fault net-delay-ms=0..3"

echo "== a. R"
n_ms=$(native "$RUNS/go-native.txt" "$W/$G" /guest/go-static all)
run $G "$RUNS/go-r" 1 -- /guest/go-static all
c=$(field "$RUNS/go-r/result.json" outcome)
echo "seed 1: class $c, native wall ${n_ms} ms"
if [ "$c" = ok ]; then
    # The CPU count changes the first line (gomaxprocs 4 numcpu 4); the rest must be native's.
    grep -v '^~ \|^gomaxprocs ' "$RUNS/go-native.txt" >"$RUNS/go-native.masked"
    grep -v '^~ \|^gomaxprocs ' "$RUNS/go-r/inc-0/stdout" | cmp - "$RUNS/go-native.masked" && echo "stdout equals native after masking" \
        || fail "W4 stdout differs from native after masking"
else
    fail "W4 seed 1: class $c"
fi

echo "== b. spin-waits"
PATINA_TEST_STALL_MS=1000 sweep go-sweep $G 1-8 -- -- /guest/go-sweep
echo "go-sweep: ok $(count go-sweep ok) of 8"
[ "$(count go-sweep ok)" = 8 ] || fail "go-sweep: not every seed ok"
PATINA_TEST_STALL_MS=1000 PATINA_TEST_SPIN_PROBES=0 sweep go-sweep-np $G 1-8 -- --config "$("$PATINA_CFG" preempt=traps)" -- /guest/go-sweep
cs=$(stalls go-sweep-np); ok=$(count go-sweep-np ok)
echo "go-sweep, spin probes off: ok $ok, compute-stall $cs of 8"
[ "$cs" -gt 0 ] || fail "go-sweep did not reproduce the spin-wait with spin probes off"
[ $((ok + cs)) = 8 ] || fail "go-sweep, spin probes off: outcomes other than ok/compute-stall"
echo "go-static: $(PATINA_TEST_STALL_MS=3000 sweep go-static8 $G 1-8 -- -- /guest/go-static all | cut -d';' -f1)"
[ "$(count go-static8 ok)" = 8 ] || fail "W4: $((8 - $(count go-static8 ok))) of 8 not ok"

echo "== c. D, faults off and on"
verify_seeds $G go-d2 cpu,load,aslr,sandbox "1" -- /guest/go-static all || fail "W4 D (faults off)"
verify_seeds $G go-d2f cpu,load,aslr,sandbox "1" $FAULT -- /guest/go-static all || fail "W4 D (faults on)"

echo "== d. F: injected file errors seen by the program"
fs=""
for s in 1 2 3; do
    run $G "$RUNS/go-f$s" "$s" $FAULT -- /guest/go-static all
    if [ "$(field "$RUNS/go-f$s/result.json" outcome)" = ok ] && grep -q '^file error:' "$RUNS/go-f$s/inc-0/stdout"; then
        fs="$fs $s"
        echo "seed $s: $(field "$RUNS/go-f$s/result.json" faults.injected) faults injected; program printed $(grep -c '^file error:' "$RUNS/go-f$s/inc-0/stdout") file errors, e.g.: $(grep -m1 '^file error:' "$RUNS/go-f$s/inc-0/stdout")"
    fi
done
[ -n "$fs" ] || fail "W4 F: no run where the program saw an injected file error"

echo "== e. report (seed 1)"
stats "$RUNS/go-r"

echo "== f. go-spin"
PATINA_TEST_STALL_MS=3000 run $G "$RUNS/spin-short" 1 -- /guest/go-spin 300000000
echo "short spin, stall-ms 3000: class $(field "$RUNS/spin-short/result.json" outcome), wall $(field "$RUNS/spin-short/result.json" wall_ms) ms, stdout: $(cat "$RUNS/spin-short/inc-0/stdout")"
[ "$(field "$RUNS/spin-short/result.json" outcome)" = ok ] || fail "go-spin short: not ok"
PATINA_TEST_STALL_MS=1000 run $G "$RUNS/spin-20s" 1 --config "$("$PATINA_CFG" preempt=traps)" -- /guest/go-spin 20000000000
echo "20 s spin, stall-ms 1000: class $(field "$RUNS/spin-20s/result.json" outcome), wall $(field "$RUNS/spin-20s/result.json" wall_ms) ms, detail $(field "$RUNS/spin-20s/result.json" message)"
[ "$(field "$RUNS/spin-20s/result.json" stop)" = compute-stall ] || fail "go-spin 20 s: not compute-stall"

echo "== g. network"
verify_seeds $G go-dn cpu,load,aslr,sandbox "1" $NETF -- /guest/go-static net || fail "W4 D (network faults on)"
echo "-- net-reset-permille=1000"
netf $G go-reset 'connection reset by peer' "1 2 3" --fault net-reset-permille=1000 -- /guest/go-static net || fail "W4: no reset seen"
echo "-- net-blackout=1+10000 (ms)"
netf $G go-part 'Client.Timeout exceeded' "1" --fault net-blackout=1+10000 -- /guest/go-static net || fail "W4: the client timeout did not fire during the partition"
echo "-- net-chunk-max=1"
netf $G go-chunk '^net: 16 of 16 responses correct' "1" --fault net-chunk-max=1 -- /guest/go-static net || fail "W4: responses not all correct under net-chunk-max=1"
finish
