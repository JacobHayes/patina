# 4. Exit ordering: 50 children write to one pipe and exit; the parent reads to EOF, then waits.
# The (pid, status) sequence and the bytes read are identical across runs; the SIGCHLD handler
# reaps (and so counts) exactly 50.
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/04-exit-order
for seed in 1 2 3; do
    verify_ok "$o/v$seed" "$seed" 2 cpu,load /guest/exit-order
    python3 -I "$HERE/check_procs.py" exit-order "$o/v$seed/run-0/boot-1/stdout" || die "seed $seed: wrong values"
done
n=$(for seed in 1 2 3; do grep '^reaped' "$o/v$seed/run-0/boot-1/stdout" | sha256sum; done | sort -u | wc -l)
echo "distinct reap orders over seeds 1-3: $n"
echo "exit-order $(counts "$o/v1/run-0")"
