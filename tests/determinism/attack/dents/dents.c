/* getdents64 order and d_off cookies after 10,000 mixed creates, unlinks and renames;
 * every record (name, d_ino, d_off, d_type) is hashed and the first 64 printed. */
#define _GNU_SOURCE
#include "../common.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
static uint64_t st = 88172645463325252ull;
static uint64_t rnd(void) { st ^= st << 13; st ^= st >> 7; st ^= st << 17; return st; }
static void listdir(const char *d, int verbose) {
    int fd = open(d, O_RDONLY | O_DIRECTORY);
    char buf[4096]; long n; uint64_t h = FNV0; int cnt = 0;
    while ((n = syscall(SYS_getdents64, fd, buf, sizeof buf)) > 0) {
        for (long o = 0; o < n;) {
            unsigned long long ino = *(unsigned long long *)(buf + o);
            long long off = *(long long *)(buf + o + 8);
            unsigned short rl = *(unsigned short *)(buf + o + 16);
            unsigned char ty = *(unsigned char *)(buf + o + 18);
            const char *nm = buf + o + 19;
            h = fnv_add(h, buf + o, rl);
            if (verbose && cnt < 64) printf("%s ino=%llu off=%lld type=%u %s\n", d, ino, off, ty, nm);
            cnt++; o += rl;
        }
    }
    /* seek back to a cookie in the middle and continue */
    lseek(fd, 0, SEEK_SET);
    n = syscall(SYS_getdents64, fd, buf, 512);
    long long mid = n > 0 ? *(long long *)(buf + 8) : -1;
    lseek(fd, mid, SEEK_SET);
    n = syscall(SYS_getdents64, fd, buf, sizeof buf);
    h = fnv_add(h, buf, n > 0 ? n : 0);
    printf("%s entries %d hash %016llx tell %lld\n", d, cnt, (unsigned long long)h, (long long)lseek(fd, 0, SEEK_CUR));
    close(fd);
}
int main(int argc, char **argv) {
    int ops = argc > 1 ? atoi(argv[1]) : 10000;
    const char *dirs[] = {"/work/d", "/tmp/d", "/dev/shm/d"};
    for (int k = 0; k < 3; k++) {
        if (mkdir(dirs[k], 0755)) { printf("%s mkdir failed\n", dirs[k]); continue; }
        char a[256], b[256];
        for (int i = 0; i < ops; i++) {
            int x = rnd() % 1000, y = rnd() % 1000;
            snprintf(a, sizeof a, "%s/f%d-%0*d", dirs[k], x, (int)(x % 40), 0);
            snprintf(b, sizeof b, "%s/f%d-%0*d", dirs[k], y, (int)(y % 40), 0);
            switch (rnd() % 4) {
            case 0: case 1: close(open(a, O_CREAT | O_WRONLY, 0644)); break;
            case 2: unlink(a); break;
            case 3: rename(a, b); break;
            }
            if (i % 2500 == 0) listdir(dirs[k], 0);
        }
        listdir(dirs[k], 1);
    }
    listdir("/usr/bin", 0);
    listdir("/dev", 1);
    listdir("/", 1);
    return 0;
}
