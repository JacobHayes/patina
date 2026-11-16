/* Fill a tmpfs mount until the first failure (argv[1] directory, argv[2] MiB cap) and
 * report where and how it failed, then statfs. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <unistd.h>
int main(int argc, char **argv) {
    const char *d = argc > 1 ? argv[1] : "/work";
    long cap = argc > 2 ? atol(argv[2]) : 4096;
    static char buf[1 << 20]; memset(buf, 7, sizeof buf);
    char p[256]; snprintf(p, sizeof p, "%s/fill", d);
    int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    long mib = 0; long tot = 0;
    for (; mib < cap; mib++) {
        ssize_t w = write(fd, buf, sizeof buf);
        if (w < 0) { printf("write failed at %ld MiB errno %d\n", mib, errno); break; }
        tot += w;
        if (w != sizeof buf) { printf("short write %zd at %ld MiB\n", w, mib); }
    }
    printf("total %ld\n", tot);
    struct statfs s; statfs(d, &s);
    printf("statfs blocks %llu free %llu avail %llu files %llu ffree %llu\n", (unsigned long long)s.f_blocks,
           (unsigned long long)s.f_bfree, (unsigned long long)s.f_bavail, (unsigned long long)s.f_files, (unsigned long long)s.f_ffree);
    int n = 0; for (;; n++) { char q[256]; snprintf(q, sizeof q, "%s/f%d", d, n); int f = open(q, O_CREAT | O_WRONLY, 0644); if (f < 0) { printf("create failed at %d errno %d\n", n, errno); break; } close(f); if (n > 200000) break; }
    return 0;
}
