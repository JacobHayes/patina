# Evidence (language runtimes "Go stalls", VERDICT open problem 1): stock Go's stall rate under scheduling at
# system calls only. W4 (go-static all) over seeds 1-RUNTIMES_STALL_SEEDS (100) at the default CPU count (24) and at
# --cpus 1, 2, 3, 4, 8; the reproducer go-sweep over 40 seeds at --cpus 2, 3 and 24; and
# go-static net over 100 seeds at 24 CPUs. Every stall must be "no trap" (the spin-wait
# mechanism); --cpus 1 and 2 must have none. stall-ms = 3000 throughout (language runtimes's item b used the
# default 10 s at 24 CPUs; a run that computes 3-10 s without a trap would count as a stall
# here: none of language runtimes's ok runs at 24 CPUs came close, wall_ms in docs/EVIDENCE.md language runtimes).
#@ tier=evidence budget=900 slots=8
. "$(dirname "$0")/lib.inc"
export SWEEP_JOBS=8
G=go-static
N=${RUNTIMES_STALL_SEEDS:-100}
for n in 24 1 2 3 4 8; do
    echo "W4 --cpus $n: $(sweep go-ncpu$n $G 1-$N -- --cpus $n --config "$("$PATINA_CFG" stall-ms=3000)" -- /guest/go-static all | cut -d';' -f1)"
    nt=$(awk -F'\t' 'NR>1 && $2=="unsupported" && $3 !~ /^no trap for /' "$RUNS/go-ncpu$n/summary.tsv" | wc -l)
    [ "$nt" = 0 ] || fail "W4 --cpus $n: $nt stalls that are not 'no trap'"
    other=$(awk -F'\t' 'NR>1 && $2!="unsupported" && $2!="ok"' "$RUNS/go-ncpu$n/summary.tsv" | wc -l)
    [ "$other" = 0 ] || fail "W4 --cpus $n: $other outcomes other than ok/stall"
done
for n in 1 2; do
    [ "$(count go-ncpu$n ok)" = "$N" ] || fail "W4 at --cpus $n: $((N - $(count go-ncpu$n ok))) of $N not ok"
done
for n in 2 3 24; do
    echo "go-sweep --cpus $n: $(sweep go-sweep$n $G 1-40 -- --cpus $n --config "$("$PATINA_CFG" stall-ms=3000)" -- /guest/go-sweep | cut -d';' -f1)"
done
[ "$(count go-sweep2 ok)" = 40 ] || fail "go-sweep at --cpus 2: not every seed ok"
echo "go-static net at 24 CPUs: $(sweep go-net100 $G 1-$N -- --config "$("$PATINA_CFG" stall-ms=3000)" -- /guest/go-static net | cut -d';' -f1)"
awk -F'\t' 'NR>1 {print $2}' "$RUNS/go-net100/summary.tsv" | sort | uniq -c
finish
