# W2 tokio-mt: stock tokio multi-thread runtime, 4 workers (tokio-mt local: the
# echo server and 16 clients over tokio::net::Unix*, timers, spawn_blocking file writes,
# tokio::process, a 5 s timeout on a read nobody answers). Regressions (the evidence
# tier's matrix has W2).
#  a. R: `ok`, stdout lines equal to a native run's after masking "~ " lines.
#  b. D (seed 1, 3 runs, --vary cpu,load,aslr,sandbox), faults off and on (fs-error-permille=10).
#  c. >= 5 distinct digests over 10 seeds.
#  d. The 5 s tokio::time::timeout fires (in virtual time: see the partition in g).
#  e. F: injected file errors are seen by the program (spawn_blocking errors printed).
#  g. TCP (tokio-mt net, the network wire): D faults off and on, at seed 5: the seed that diverged
#     before the exit barrier (docs/EVIDENCE.md runtimes "exit versus a wire delivery"). F: net-reset seen
#     as "ConnectionReset"; net-partition=1..100001: the 5 s read timeouts fire during it, then
#     all 16 clients finish with correct data (two 100 s partitions: a real wait fails the
#     budget); net-chunk-max=1: all ok.
#@ tier=area budget=60 slots=4
. "$(dirname "$0")/lib.inc"
T=tokio-mt
FAULT="--fault fs-error-permille=10"
NETF="--fault net-reset-permille=30 --fault net-chunk-max=7 --fault net-delay-ms=0..3"

echo "== a. R"
n_ms=$(native "$RUNS/tk-native.txt" "$W/$T" /guest/tokio-mt local)
run $T "$RUNS/tk-r" 1 -- /guest/tokio-mt local
c=$(field "$RUNS/tk-r/result.json" outcome)
echo "seed 1: class $c, native wall ${n_ms} ms"
[ "$c" = ok ] || fail "W2 seed 1: class $c"
grep -v '^~ ' "$RUNS/tk-native.txt" | sort >"$RUNS/tk-native.masked"
grep -v '^~ ' "$RUNS/tk-r/inc-0/stdout" | sort | cmp - "$RUNS/tk-native.masked" && echo "stdout lines equal native after masking" \
    || fail "W2 stdout differs from native after masking"

echo "== b. D, faults off and on"
verify_seeds $T tk-d cpu,load,aslr,sandbox "1" -- /guest/tokio-mt local || fail "W2 D (faults off)"
verify_seeds $T tk-df cpu,load,aslr,sandbox "1" $FAULT -- /guest/tokio-mt local || fail "W2 D (faults on)"

echo "== c. distinct digests over 10 seeds"
sweep tk-10 $T 1-10 -- -- /guest/tokio-mt local
d=$(digests tk-10)
echo "W2: $d distinct digests over seeds 1-10 ($(count tk-10 ok) ok)"
[ "$d" -ge 5 ] || fail "W2: $d distinct digests"

echo "== d. the 5 s timeout"
for s in 1 2 3; do
    run $T "$RUNS/tk-t$s" "$s" -- /guest/tokio-mt local
    grep -q '^timeout 5s: fired, elapsed >= 5s: true$' "$RUNS/tk-t$s/inc-0/stdout" || fail "W2 seed $s: the 5 s timeout did not fire as expected"
    echo "seed $s: wall $(field "$RUNS/tk-t$s/result.json" wall_ms) ms; native wall ${n_ms} ms"
done

echo "== e. F"
fs=0
for s in 1 2 3; do
    o=$RUNS/tk-f$s
    run $T "$o" "$s" $FAULT -- /guest/tokio-mt local
    n=$(grep -c '^spawn_blocking error' "$o/inc-0/stdout" || true)
    echo "seed $s: $(field "$o/result.json" faults.injected) faults injected, class $(field "$o/result.json" outcome), $n spawn_blocking errors seen"
    [ "$n" -gt 0 ] && fs=$((fs + 1))
done
[ "$fs" -gt 0 ] || fail "W2 F: no injected error seen by the program"

echo "== g. TCP"
verify_seeds $T tk-dn cpu,load,aslr,sandbox "5" -- /guest/tokio-mt net || fail "W2 D (tcp, faults off)"
verify_seeds $T tk-dnf cpu,load,aslr,sandbox "5" $NETF -- /guest/tokio-mt net || fail "W2 D (tcp, network faults on)"
echo "-- net-reset-permille=20"
netf $T tk-reset 'error: ConnectionReset' "1 2 3" --fault net-reset-permille=20 -- /guest/tokio-mt net || fail "W2: no reset seen"
echo "-- net-partition=1..100001 (ms)"
netf $T tk-part '^echo (tcp): 16 of 16 clients ok' "1 2" --fault net-partition=1..100001 -- /guest/tokio-mt net >"$RUNS/tk-part.txt" || true
cat "$RUNS/tk-part.txt"
[ "$(grep -c ': class ok, .* 1 lines match' "$RUNS/tk-part.txt")" = 2 ] || fail "W2: not every client recovered after the partition"
for s in 1 2; do
    n=$(sed -n 's/^timeouts during echo: //p' "$RUNS/tk-part-$s/inc-0/stdout")
    [ "${n:-0}" -gt 0 ] || fail "W2 seed $s: no 5 s timeout fired during the 100 s partition"
done
echo "-- net-chunk-max=1"
netf $T tk-chunk '^echo (tcp): 16 of 16 clients ok' "1" --fault net-chunk-max=1 -- /guest/tokio-mt net || fail "W2: not every client ok under net-chunk-max=1"
finish
