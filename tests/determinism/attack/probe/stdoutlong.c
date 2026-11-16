/* stdout's block count across wall time: write 8 MiB, fstat(1), compute for argv[1] seconds of
 * wall time (a getppid now and then so the stall watchdog does not fire; the guest cannot read wall
 * time, the loop count is calibrated by the caller), fstat(1) again. XFS trims speculative preallocation of idle files in the background
 * (speculative_prealloc_lifetime, 300 s by default). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
    static char buf[1 << 16]; memset(buf, 'x', sizeof buf);
    for (int i = 0; i < 128; i++) write(1, buf, sizeof buf);
    struct stat st; fstat(1, &st);
    fprintf(stderr, "before size %lld blocks %lld\n", (long long)st.st_size, (long long)st.st_blocks);
    unsigned long long n = strtoull(argc > 1 ? argv[1] : "1000000000", 0, 0), x = 1;
    for (unsigned long long i = 0; i < n; i++) {
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;
        if ((i & ((1ULL << 26) - 1)) == 0) getppid(); /* a trap now and then: not a stall */
    }
    fstat(1, &st);
    fprintf(stderr, "after size %lld blocks %lld (%llu)\n", (long long)st.st_size, (long long)st.st_blocks, x & 1);
    return 0;
}
