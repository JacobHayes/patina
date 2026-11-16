/* determinism hardening attack guest: pipe capacity at creation and after F_SETPIPE_SZ, for many pipes.
 * The kernel accounts pipe pages per host user (pipe-user-pages-soft/hard). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 1200;
    int small = 0, first_small = -1;
    for (int i = 0; i < n; i++) {
        int p[2];
        if (pipe(p)) { printf("pipe %d errno %d\n", i, errno); break; }
        int sz = fcntl(p[0], F_GETPIPE_SZ);
        if (sz != 65536) { small++; if (first_small < 0) first_small = i; }
        if (i % 200 == 0 || i == n - 1) printf("pipe %d size %d\n", i, sz);
        if (i == 0) {
            int r = fcntl(p[0], F_SETPIPE_SZ, 1 << 20);
            printf("setsz 1M r=%d e=%d\n", r, r < 0 ? errno : 0);
        }
    }
    printf("small %d first_small %d\n", small, first_small);
    int p[2]; pipe(p);
    int r = fcntl(p[0], F_SETPIPE_SZ, 1 << 20);
    printf("last setsz 1M r=%d e=%d\n", r, r < 0 ? errno : 0);
    fcntl(p[1], F_SETFL, O_NONBLOCK);
    static char buf[1 << 20]; ssize_t w = write(p[1], buf, sizeof buf);
    printf("nonblocking write of 1M: %zd\n", w);
    return 0;
}
