# 9. Stock static Go: spinning goroutine, 10 ms syscall ticker, signal.Notify(SIGUSR1) and
# syscall.Kill(self), one P: ok, notified, identical over 4 runs. The log must show Go's
# preemption signal (SIGURG, 0x17) and SIGUSR1 (0xa) delivered through runtime-built frames.
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
verify "$RUNS/09-go" 1 go-sig 4
echo "4 identical runs, digest $(field "$RUNS/09-go/run-0/result.json" digest), traps $(field "$RUNS/09-go/run-0/result.json" sched.traps)"
deliveries "$RUNS/09-go/run-0" | tee "$RUNS/09-go/deliveries.txt"
grep -q ' 0x17$' "$RUNS/09-go/deliveries.txt" || die "no SIGURG delivered"
grep -q ' 0xa$' "$RUNS/09-go/deliveries.txt" || die "no SIGUSR1 delivered"
for seed in 2 3; do
    patina_run "$RUNS/09-go/seed-$seed" "$seed" go-sig
    check_ok "$RUNS/09-go/seed-$seed" go-sig
    echo "seed $seed: ok, digest $(field "$RUNS/09-go/seed-$seed/result.json" digest)"
done
