# language runtimes item 2, W5 cpython: stock /usr/bin/python3, no flags (regressions; the recorded run used
# 5 seeds x 20 runs and 100 fault seeds: docs/EVIDENCE.md language runtimes, the evidence tier's matrix has W5).
#  a. R: `ok`, stdout equal to a native run after masking "~ " and "v " lines.
#  b. The printed values identical across runs of a seed (D: seed 1, 3 runs, --vary
#     cpu,load,aslr,sandbox), faults off and on.
#  c. Across seeds 1-5: the values drawn from entropy (random, hash, urandom, mkdtemp, uuid4)
#     differ for every pair of seeds; >= 3 distinct digests.
#  e. fs-error-permille=5 over 20 seeds: every run `ok` or `failure` with exit status 1, never a
#     signal, never unsupported/internal; at least one run shows the program seeing an error.
#  f. Network: D (seed 1) with network faults on; net-reset-permille seen as a
#     ConnectionReset/Aborted error, a 15 s net-partition seen as the client's 10 s socket
#     timeout, net-chunk-max=1 with every reply still whole.
#@ tier=area budget=60 slots=4
. "$(dirname "$0")/lib.inc"
P=cpython
CMD="/usr/bin/python3 /guest/w5.py all"
FAULT="--fault fs-error-permille=5"
NETF="--fault net-reset-permille=50 --fault net-chunk-max=3 --fault net-delay-ms=0..3"
NET="/usr/bin/python3 /guest/w5.py net"

echo "== a. R"
n_ms=$(native "$RUNS/py-native.txt" "$W/$P" $CMD)
run $P "$RUNS/py-r" 1 -- $CMD
c=$(field "$RUNS/py-r/outcome.json" outcome)
echo "seed 1: class $c, native wall ${n_ms} ms"
[ "$c" = ok ] || fail "W5 seed 1: class $c"
grep -v '^[~v] ' "$RUNS/py-native.txt" >"$RUNS/py-native.masked"
grep -v '^[~v] ' "$RUNS/py-r/inc-0/stdout" | cmp - "$RUNS/py-native.masked" && echo "stdout equals native after masking" \
    || fail "W5 stdout differs from native after masking"

echo "== b. D, faults off and on"
verify_seeds $P py-d cpu,load,aslr,sandbox "1" -- $CMD || fail "W5 D (faults off)"
verify_seeds $P py-df cpu,load,aslr,sandbox "1" $FAULT -- $CMD || fail "W5 D (faults on)"

echo "== c. values and digests across seeds 1-5"
SWEEP_KEEP=all sweep py-5 $P 1-5 -- -- $CMD
for s in 1 2 3 4 5; do grep '^v ' "$RUNS/py-5/run-$s/inc-0/stdout" >"$RUNS/py-values-$s.txt"; done
cat "$RUNS/py-values-1.txt"
for key in random hash id urandom time pid native_id mkdtemp uuid4; do
    n=$(for s in 1 2 3 4 5; do grep "^v $key " "$RUNS/py-values-$s.txt"; done | sort -u | wc -l)
    echo "$key: $n distinct values over 5 seeds"
    case $key in
        random | hash | urandom | mkdtemp | uuid4) [ "$n" = 5 ] || fail "W5: $key not different for every seed" ;;
    esac
done
d=$(digests py-5)
echo "W5: $d distinct digests over seeds 1-5"
[ "$d" -ge 3 ] || fail "W5: $d distinct digests"

echo "== e. fs-error-permille=5 over 20 seeds"
SWEEP_KEEP=all sweep py-f20 $P 1-20 -- $FAULT -- $CMD
awk -F'\t' 'NR>1 {print $2, $3}' "$RUNS/py-f20/summary.tsv" | sort | uniq -c
bad=$(awk -F'\t' 'NR>1 && !($2=="ok" || ($2=="failure" && $3=="exit status 1"))' "$RUNS/py-f20/summary.tsv" | wc -l)
[ "$bad" = 0 ] || fail "W5 faults: $bad runs neither ok nor a clean exit status 1"
sig=$(for s in $(seq 1 20); do field "$RUNS/py-f20/outcomes/$s.json" signal; done | grep -vc null || true)
[ "$sig" = 0 ] || fail "W5 faults: $sig runs ended by a signal"
seen=0
for s in $(seq 1 20); do
    o=$RUNS/py-f20/run-$s
    [ "$(field "$o/outcome.json" faults.injected)" -gt 0 ] || continue
    if grep -q '^oserror' "$o/inc-0/stdout" || [ "$(field "$o/outcome.json" outcome)" = failure ]; then seen=$((seen + 1)); fi
done
echo "runs where the program saw an injected error: $seen of 20"
[ "$seen" -gt 0 ] || fail "W5 faults: no run saw an injected error"

echo "== f. network"
verify_seeds $P py-dn cpu,load,aslr,sandbox "1" $NETF -- $CMD || fail "W5 D (network faults on)"
echo "-- net-reset-permille=100"
netf $P py-reset 'tcp .*error: Connection' "1 2 3 4 5" --fault net-reset-permille=100 -- $NET || fail "W5: no reset seen"
echo "-- net-partition=1..15001 (ms)"
netf $P py-part 'tcp client .*TimeoutError' "1" --fault net-partition=1..15001 -- $NET || fail "W5: the socket timeout did not fire during the partition"
echo "-- net-chunk-max=1"
netf $P py-chunk "tcp echo: \['MSG0', 'MSG1', 'MSG2', 'MSG3'\]" "1" --fault net-chunk-max=1 -- $NET || fail "W5: a reply was not whole under net-chunk-max=1"
finish
