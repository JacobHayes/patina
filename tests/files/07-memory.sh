# 7. Memory: 100k mmap/munmap of mixed sizes, mremap growth, brk grow and shrink, MADV_DONTNEED
#    and MADV_FREE read zeros; addresses identical under --vary aslr.
#@ tier=quick budget=40 arch=x86_64
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/07-memory
verify_ok "$o" 1 aslr 2 -- /guest/memtest
out=$o/run-0/inc-0/stdout
grep -q '^madvise dontneed 0 -> 0 0 7$' "$out" || die "MADV_DONTNEED did not read zeros"
grep -q '^madvise free 0 -> 0 0 7$' "$out" || die "MADV_FREE did not read zeros"
grep -q '^addr brk-regrow .* byte 0$' "$out" || die "brk regrowth not zero"
echo "memory: $(grep -c '^addr' "$out") addresses identical with ASLR on and off"
