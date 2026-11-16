# language runtimes item 1, W4 go-static: stock static Go (regressions; the 100-seed stall rates and
# per-CPU-count sweeps are tests/runtimes/evidence-go-stalls.sh, docs/EVIDENCE.md language runtimes "Go stalls").
#  a. R: `ok` at --cpus 2, stdout equal to a native run after masking "~ " lines
#     and the gomaxprocs line.
#  b. Stalls are the spin-wait mechanism and nothing else: the reproducer go-sweep at the default
#     CPU count stalls ("no trap") on at least one of seeds 1-8 and every other run is ok; at
#     --cpus 2 and at --cpus 1 seeds 1-8 of go-static never stall.
#  c. D at --cpus 2 (seed 1, --vary cpu,load,aslr,sandbox), faults off and on.
#  d. F: an injected file error is seen by the program (printed "file error:" lines).
#  e. Report: threads, SIGURG sends and deliveries, rdtsc emulations, futex calls, denied calls.
#  f. go-spin: a goroutine computing without a trap for less than stall-ms is `ok`; a 20 s
#     spin under stall-ms = 1000 ends as `unsupported` (compute-stall) (after 1 s, not 20).
#  g. Network at --cpus 2: D with network faults; net-reset-permille seen as "connection reset
#     by peer", a 10 s net-partition seen as the http.Client's 5 s timeout, net-chunk-max=1
#     with all 16 responses correct.
#@ tier=area budget=90 slots=4
. "$(dirname "$0")/lib.inc"
G=go-static
FAULT="--fault fs-error-permille=20"
NETF="--fault net-reset-permille=30 --fault net-chunk-max=7 --fault net-delay-ms=0..3"

echo "== a. R"
n_ms=$(native "$RUNS/go-native.txt" "$W/$G" /guest/go-static all)
run $G "$RUNS/go-r" 1 --cpus 2 -- /guest/go-static all
c=$(field "$RUNS/go-r/outcome.json" outcome)
echo "seed 1 --cpus 2: class $c, native wall ${n_ms} ms"
if [ "$c" = ok ]; then
    # --cpus 2 changes the first line (gomaxprocs 2 numcpu 2); the rest must be native's.
    grep -v '^~ \|^gomaxprocs ' "$RUNS/go-native.txt" >"$RUNS/go-native.masked"
    grep -v '^~ \|^gomaxprocs ' "$RUNS/go-r/inc-0/stdout" | cmp - "$RUNS/go-native.masked" && echo "stdout equals native after masking" \
        || fail "W4 stdout differs from native after masking"
else
    fail "W4 seed 1: class $c"
fi

echo "== b. stalls: the spin-wait mechanism only"
sweep go-sweep24 $G 1-8 -- --config "$("$PATINA_CFG" stall-ms=1000)" -- /guest/go-sweep
st=$(count go-sweep24 unsupported); ok=$(count go-sweep24 ok)
echo "go-sweep at the default CPU count: ok $ok, stall $st of 8"
[ "$st" -gt 0 ] || fail "go-sweep did not reproduce the stall at the default CPU count"
[ $((ok + st)) = 8 ] || fail "go-sweep: outcomes other than ok/stall"
nt=$(awk -F'\t' 'NR>1 && $2=="unsupported" && $3 !~ /^no trap for /' "$RUNS/go-sweep24/summary.tsv" | wc -l)
[ "$nt" = 0 ] || fail "go-sweep: $nt stalls that are not 'no trap' (a different mechanism)"
for n in 1 2; do
    echo "go-static --cpus $n: $(sweep go-ncpu$n $G 1-8 -- --cpus $n --config "$("$PATINA_CFG" stall-ms=3000)" -- /guest/go-static all | cut -d';' -f1)"
    [ "$(count go-ncpu$n ok)" = 8 ] || fail "W4 at --cpus $n: $((8 - $(count go-ncpu$n ok))) of 8 not ok"
done

echo "== c. D at --cpus 2, faults off and on"
verify_seeds $G go-d2 cpu,load,aslr,sandbox "1" --cpus 2 -- /guest/go-static all || fail "W4 D (faults off)"
verify_seeds $G go-d2f cpu,load,aslr,sandbox "1" --cpus 2 $FAULT -- /guest/go-static all || fail "W4 D (faults on)"

echo "== d. F: injected file errors seen by the program"
fs=""
for s in 1 2 3; do
    run $G "$RUNS/go-f$s" "$s" --cpus 2 $FAULT -- /guest/go-static all
    if [ "$(field "$RUNS/go-f$s/outcome.json" outcome)" = ok ] && grep -q '^file error:' "$RUNS/go-f$s/inc-0/stdout"; then
        fs="$fs $s"
        echo "seed $s: $(field "$RUNS/go-f$s/outcome.json" faults.injected) faults injected; program printed $(grep -c '^file error:' "$RUNS/go-f$s/inc-0/stdout") file errors, e.g.: $(grep -m1 '^file error:' "$RUNS/go-f$s/inc-0/stdout")"
    fi
done
[ -n "$fs" ] || fail "W4 F: no run where the program saw an injected file error"

echo "== e. report (seed 1, --cpus 2)"
stats "$RUNS/go-r"

echo "== f. go-spin"
run $G "$RUNS/spin-short" 1 --config "$("$PATINA_CFG" stall-ms=3000)" -- /guest/go-spin 300000000
echo "short spin, stall-ms 3000: class $(field "$RUNS/spin-short/outcome.json" outcome), wall $(field "$RUNS/spin-short/outcome.json" wall_ms) ms, stdout: $(cat "$RUNS/spin-short/inc-0/stdout")"
[ "$(field "$RUNS/spin-short/outcome.json" outcome)" = ok ] || fail "go-spin short: not ok"
run $G "$RUNS/spin-20s" 1 --config "$("$PATINA_CFG" stall-ms=1000)" -- /guest/go-spin 20000000000
echo "20 s spin, stall-ms 1000: class $(field "$RUNS/spin-20s/outcome.json" outcome), wall $(field "$RUNS/spin-20s/outcome.json" wall_ms) ms, detail $(field "$RUNS/spin-20s/outcome.json" message)"
[ "$(field "$RUNS/spin-20s/outcome.json" outcome)" = unsupported ] || fail "go-spin 20 s: not stall"

echo "== g. network (--cpus 2)"
verify_seeds $G go-dn cpu,load,aslr,sandbox "1" --cpus 2 $NETF -- /guest/go-static net || fail "W4 D (network faults on)"
echo "-- net-reset-permille=50"
netf $G go-reset 'connection reset by peer' "1 2 3" --cpus 2 --fault net-reset-permille=50 -- /guest/go-static net || fail "W4: no reset seen"
echo "-- net-partition=1..10001 (ms)"
netf $G go-part 'Client.Timeout exceeded' "1" --cpus 2 --fault net-partition=1..10001 -- /guest/go-static net || fail "W4: the client timeout did not fire during the partition"
echo "-- net-chunk-max=1"
netf $G go-chunk '^net: 16 of 16 responses correct' "1" --cpus 2 --fault net-chunk-max=1 -- /guest/go-static net || fail "W4: responses not all correct under net-chunk-max=1"
finish
