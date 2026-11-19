/* mapends MODE: stores through a MAP_SHARED mapping of a work-tree file, made by a process
 * that then ends in one of the ways a process can end, or loses its mapping:
 *   kill      a child stores and is killed by SIGKILL from the main process
 *   term      the same with SIGTERM (default action)
 *   orphan    the child is still running when the main process exits
 *   vfork     a child stores, vforks, and its vfork child stores too and kills it
 *   violation the main process stores and fails an `always`
 *   msync     the main process stores, msyncs, and fails an `always`
 *   hang      the main process stores and sleeps (run with --time-limit)
 *   unmap     the main process stores, unmaps and exits
 *   exit      the main process stores and exits with the mapping still mapped
 *   fixed     the main process stores and maps anonymous memory over the mapping (MAP_FIXED)
 *   remap     the main process stores, moves the mapping's second page (mremap) and stores
 *             through it: unsupported
 *   forked    the main process stores, forks; the child (sharing the mapping) stores and is
 *             killed by SIGKILL
 *   durable   a child stores and is killed; the main process fsyncs the file and the
 *             directory, then writes and fsyncs a marker. In a later incarnation: the marker
 *             means the store is durable (`always`: synced-store-kept).
 * Every mode but orphan, violation, msync, hang and remap prints the file's first bytes as read(2)
 * returns them, which is what a native run prints too.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "patina.h"

/* Not a whole number of pages: the last page is partial, and a store to it is a record of
 * its own (the page before it stays clean). */
#define LEN (2 * 4096 + 100)

static char *map_file(void) {
    int fd = open("shm", O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || ftruncate(fd, LEN) != 0) exit(3);
    char *m = mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) exit(4);
    return m;
}

/* A child that stores and tells the parent through the pipe, then waits to be ended. */
static pid_t storing_child(int vf) {
    int p[2];
    char b;
    if (pipe(p) != 0) exit(5);
    pid_t c = fork();
    if (c < 0) exit(6);
    if (c == 0) {
        char *m = map_file();
        m[0] = 'x';
        m[LEN - 1] = 'z';
        if (vf) {
            /* The vfork child shares the memory: its store is the parent's; it ends the
             * parent, which is blocked in vfork, and leaves. */
            if (vfork() == 0) {
                m[1] = 'y';
                kill(getppid(), SIGKILL);
                _exit(0);
            }
        }
        if (write(p[1], "r", 1) != 1) _exit(7);
        for (;;) pause();
    }
    if (!vf && read(p[0], &b, 1) != 1) exit(8);
    return c;
}

static void show(void) {
    char b[3] = {0};
    int fd = open("shm", O_RDONLY);
    if (fd < 0 || pread(fd, b, 2, 0) != 2) exit(9);
    printf("shm: %d %d\n", b[0], b[1]);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "kill";
    const char *inc = getenv("PATINA_INCARNATION");
    if (!strcmp(mode, "durable") && inc && atoi(inc) > 0) {
        char s = 0, b = 0;
        int m = open("marker", O_RDONLY);
        if (m < 0 || read(m, &s, 1) != 1) return 0; /* crashed before the marker was synced */
        int fd = open("shm", O_RDONLY);
        if (fd < 0 || read(fd, &b, 1) != 1) b = 0;
        char detail[32];
        snprintf(detail, sizeof detail, "shm[0]=%d", b);
        PATINA_ALWAYS(b == 'x', "synced-store-kept", detail);
        return 0;
    }
    if (!strcmp(mode, "kill") || !strcmp(mode, "term") || !strcmp(mode, "durable")) {
        pid_t c = storing_child(0);
        kill(c, !strcmp(mode, "term") ? SIGTERM : SIGKILL);
        waitpid(c, NULL, 0);
        if (!strcmp(mode, "durable")) {
            int fd = open("shm", O_RDWR), d = open(".", O_RDONLY);
            if (fd < 0 || d < 0 || fsync(fd) != 0 || fsync(d) != 0) return 10;
            int m = open("marker", O_WRONLY | O_CREAT, 0600);
            if (m < 0 || write(m, "s", 1) != 1 || fsync(m) != 0 || fsync(d) != 0) return 11;
        }
        show();
        return 0;
    }
    if (!strcmp(mode, "orphan")) {
        storing_child(0);
        return 0;
    }
    if (!strcmp(mode, "forked")) {
        char *m = map_file();
        m[0] = 'w';
        int p[2];
        char b;
        if (pipe(p) != 0) return 5;
        pid_t c = fork();
        if (c == 0) {
            m[1] = 'v';
            m[LEN - 1] = 'z';
            if (write(p[1], "r", 1) != 1) _exit(7);
            for (;;) pause();
        }
        if (c < 0 || read(p[0], &b, 1) != 1) return 8;
        kill(c, SIGKILL);
        waitpid(c, NULL, 0);
        show();
        return 0;
    }
    if (!strcmp(mode, "vfork")) {
        pid_t c = storing_child(1);
        waitpid(c, NULL, 0);
        show();
        return 0;
    }
    char *m = map_file();
    memset(m, 'w', 2);
    m[LEN - 1] = 'z';
    if (!strcmp(mode, "msync") && msync(m, LEN, MS_SYNC) != 0) return 12;
    if (!strcmp(mode, "violation") || !strcmp(mode, "msync"))
        PATINA_ALWAYS(0, "mapends-planted", mode);
    if (!strcmp(mode, "hang"))
        for (;;) sleep(1);
    if (!strcmp(mode, "unmap") && munmap(m, LEN) != 0) return 13;
    if (!strcmp(mode, "fixed") &&
        mmap(m, LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != m)
        return 14;
    if (!strcmp(mode, "remap")) {
        char *n = mremap(m + 4096, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, m + 4 * 4096);
        if (n == MAP_FAILED) return 15;
        n[0] = 'q'; /* the file's second page, through its new address */
    }
    show();
    return 0;
}
