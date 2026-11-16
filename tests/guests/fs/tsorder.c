// files timestamp ordering: 40 operations on /work/t, each followed by an optional sleep
// (argv[1] milliseconds; 0 under patina) and a statx snapshot of every name in the set.
// Output: "S step path field sec nsec" for atime, mtime, ctime and btime.
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static const char *names[] = {"t", "t/a", "t/b", "t/c", "t/d", "t/e", "t/s"};
#define NN (sizeof names / sizeof *names)

static void create(const char *p) {
    int fd = open(p, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0) { perror(p); exit(1); }
    close(fd);
}
static void wr(const char *p) {
    int fd = open(p, O_WRONLY | O_APPEND);
    if (fd < 0 || write(fd, "data\n", 5) != 5) { perror(p); exit(1); }
    close(fd);
}
static void ck(int r, const char *what) {
    if (r != 0) { perror(what); exit(1); }
}
static void ut(const char *p, long s) {
    struct timespec ts[2] = {{s, 0}, {s + 1, 0}};
    ck(utimensat(AT_FDCWD, p, ts, 0), "utimensat");
}
static void utnow(const char *p) { ck(utimensat(AT_FDCWD, p, NULL, 0), "utimensat-now"); }

int main(int argc, char **argv) {
    long ms = argc > 1 ? atol(argv[1]) : 0;
    ck(chdir("/work"), "chdir");
    for (int step = 1; step <= 40; step++) {
        switch (step) {
        case 1: ck(mkdir("t", 0755), "mkdir"); break;
        case 2: create("t/a"); break;
        case 3: wr("t/a"); break;
        case 4: create("t/b"); break;
        case 5: wr("t/b"); break;
        case 6: ck(chmod("t/a", 0600), "chmod"); break;
        case 7: ck(link("t/a", "t/c"), "link"); break;
        case 8: ck(rename("t/b", "t/d"), "rename"); break;
        case 9: wr("t/c"); break;
        case 10: ut("t/d", 1000000000); break;
        case 11: ck(unlink("t/a"), "unlink"); break;
        case 12: create("t/e"); break;
        case 13: ck(chmod("t", 0700), "chmod"); break;
        case 14: ck(rename("t/e", "t/b"), "rename"); break;
        case 15: wr("t/d"); break;
        case 16: utnow("t/b"); break;
        case 17: ck(link("t/d", "t/a"), "link"); break;
        case 18: ck(unlink("t/c"), "unlink"); break;
        case 19: ck(chmod("t/d", 0640), "chmod"); break;
        case 20: create("t/c"); break;
        case 21: wr("t/c"); break;
        case 22: ck(symlink("c", "t/s"), "symlink"); break;
        case 23: ck(rename("t/c", "t/e"), "rename"); break;
        case 24: wr("t/b"); break;
        case 25: ut("t/e", 2000000000); break;
        case 26: ck(chmod("t/b", 0644), "chmod"); break;
        case 27: ck(link("t/b", "t/c"), "link"); break;
        case 28: ck(unlink("t/s"), "unlink"); break;
        case 29: wr("t/a"); break;
        case 30: ck(rename("t/a", "t/c"), "rename-over"); break;
        case 31: utnow("t"); break;
        case 32: wr("t/e"); break;
        case 33: ck(chmod("t/e", 0444), "chmod"); break;
        case 34: ck(unlink("t/b"), "unlink"); break;
        case 35: create("t/b"); break;
        case 36: wr("t/b"); break;
        case 37: ck(link("t/e", "t/a"), "link"); break;
        case 38: ck(rename("t/d", "t/s"), "rename"); break;
        case 39: ut("t/c", 1500000000); break;
        case 40: ck(unlink("t/e"), "unlink"); break;
        }
        if (ms > 0) {
            struct timespec d = {ms / 1000, (ms % 1000) * 1000000};
            nanosleep(&d, NULL);
        }
        for (unsigned i = 0; i < NN; i++) {
            struct statx x;
            if (statx(AT_FDCWD, names[i], AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS | STATX_BTIME, &x) != 0) continue;
            struct statx_timestamp *f[4] = {&x.stx_atime, &x.stx_mtime, &x.stx_ctime, &x.stx_btime};
            for (int k = 0; k < 4; k++)
                printf("S %d %s %c %lld %u\n", step, names[i], "amcb"[k], (long long)f[k]->tv_sec, f[k]->tv_nsec);
        }
    }
    return 0;
}
