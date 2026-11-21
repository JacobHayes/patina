// madvise over every advice value from 0 to 26 (and 8 with high bits, as 27) and four kinds of mapping (private and shared,
// anonymous and of a file in the current directory), two pages each: page 0 written after the
// mapping is made (9), page 1 as it came (7 in the file, 0 anonymous). Per call one line:
//   KIND ADVICE ret ERRNO p0 P0 p1 P1 child C
// with the bytes read back after the call and what a fork child reads from page 0 (`segv` when
// the page is not there). Run natively and under Patina, the lines are compared
// (tests/files/15-madvise.sh).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static sigjmp_buf jb;
static void on_segv(int s) {
    (void)s;
    siglongjmp(jb, 1);
}

int main(void) {
    long pg = sysconf(_SC_PAGESIZE);
    const char *kinds[] = {"anon-private", "anon-shared", "file-private", "file-shared"};
    char *fill = malloc(2 * pg);
    memset(fill, 7, 2 * pg);
    signal(SIGSEGV, on_segv);
    signal(SIGBUS, on_segv);
    for (int k = 0; k < 4; k++) {
        for (int i = 0; i <= 27; i++) {
            // 0 to 25; 26, invalid; MADV_FREE with the upper half of the register set (the
            // kernel reads an int).
            long adv = i <= 26 ? i : (1L << 32) | 8;
            int fd = -1;
            int flags = (k & 1) ? MAP_SHARED : MAP_PRIVATE;
            if (k >= 2) {
                fd = open("madv.dat", O_RDWR | O_CREAT | O_TRUNC, 0600);
                if (fd < 0 || write(fd, fill, 2 * pg) != 2 * pg) {
                    perror("madv.dat");
                    return 1;
                }
            } else {
                flags |= MAP_ANONYMOUS;
            }
            volatile char *m = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, flags, fd, 0);
            if (m == MAP_FAILED) {
                perror("mmap");
                return 1;
            }
            m[0] = 9;
            errno = 0;
            int r = syscall(SYS_madvise, m, 2 * pg, adv);
            int er = r < 0 ? errno : 0;
            printf("%s %d ret %d %s p0 %d p1 %d", kinds[k], i, r, er ? strerrorname_np(er) : "-", m[0], m[pg]);
            fflush(stdout);
            pid_t c = fork();
            if (c == 0) {
                if (sigsetjmp(jb, 1)) {
                    printf(" child segv\n");
                    fflush(stdout);
                    _exit(0);
                }
                int v = m[0];
                printf(" child %d\n", v);
                fflush(stdout);
                _exit(0);
            }
            int st;
            waitpid(c, &st, 0);
            munmap((void *)m, 2 * pg);
            if (fd >= 0) {
                close(fd);
                unlink("madv.dat");
            }
        }
    }
    return 0;
}
