# 8. Shared-memory futex across fork: a process-shared pthread mutex and condition variable in
# MAP_SHARED|MAP_ANONYMOUS memory, and a POSIX semaphore in /dev/shm. ok, identical runs, the
# values right (the guest checks its own invariants and exits 1 otherwise), several seeds.
#@ tier=quick budget=30 slots=1.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/08-shm
for seed in 1 2 3; do
    verify_ok "$o/v$seed" "$seed" 2 cpu,load /guest/shm
    grep -q '^mutex/cond: counter=400 .* child status=0$' "$o/v$seed/run-0/boot-1/stdout" || die "seed $seed: mutex/cond values"
    grep -q '^semaphore: waits=100 value=0 child status=0$' "$o/v$seed/run-0/boot-1/stdout" || die "seed $seed: semaphore values"
done
n=$(for seed in 1 2 3; do field "$o/v$seed/run-0/result.json" digest; done | sort -u | wc -l)
echo "distinct digests over seeds 1-3: $n"
cat "$o/v1/run-0/boot-1/stdout"
