/* The launcher's stdout is a host file (XFS here): write to it in steps and report what fstat
 * shows (size, blocks, blksize) after each step, on stderr; sleep virtually in between so a
 * run spans wall time (speculative preallocation, writeback). */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
int main(void) {
    static char buf[1 << 16]; memset(buf, 'x', sizeof buf); buf[sizeof buf - 1] = '\n';
    for (int step = 0; step < 40; step++) {
        for (int i = 0; i < 4 * (step + 1); i++) write(1, buf, sizeof buf);
        struct stat st; fstat(1, &st);
        fprintf(stderr, "step %d size %lld blocks %lld blksize %ld\n", step, (long long)st.st_size, (long long)st.st_blocks, (long)st.st_blksize);
        if (step % 10 == 9) { struct timespec t = {1, 0}; nanosleep(&t, 0); }
    }
    return 0;
}
