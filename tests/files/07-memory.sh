# 7. Memory: 100k mmap/munmap of mixed sizes, mremap growth, brk grow and shrink, MADV_DONTNEED
#    reads zeros and MADV_FREE is refused (EINVAL, the data kept); addresses identical under
#    --vary aslr.
#@ tier=quick budget=40 slots=0.5
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/07-memory
verify_ok "$o" 1 aslr 2 -- /guest/memtest
out=$o/run-0/boot-1/stdout
grep -q '^madvise dontneed 0 -> 0 0 7$' "$out" || die "MADV_DONTNEED did not read zeros"
grep -q '^madvise free -1 -> 7 7 7$' "$out" || die "MADV_FREE was not refused with the data kept"
grep -q '^addr brk-regrow .* byte 0$' "$out" || die "brk regrowth not zero"
echo "memory: $(grep -c '^addr' "$out") addresses identical with ASLR on and off"
