/* mapshare MODE: two processes change the same page of a work-tree file, at least one of them
 * through a MAP_SHARED mapping, and one stores back bytes it stored or saw before:
 *   back       the main process stores 'A' and msyncs, forks; the child stores 'B' and exits;
 *              the main process stores 'A' again and unmaps
 *   back-kill  the same, but the child is killed by SIGKILL after its store
 *   alternate  the main process and a child (both mapping the file) store 'P' and 'C' in turn,
 *              each followed by msync, six times
 *   store-write  a child stores at bytes 0 and 200; the main process pwrites byte 100 of the
 *              same page; the child exits
 *   store-writev  the same with writev at the descriptor's position
 *   write-store  a child maps the page holding 'a' at byte 100; the main process pwrites 'Y'
 *              there; the child stores 'a' back and exits
 *   trunc      the main process stores in page 2 and msyncs, forks; the child truncates the
 *              file to one page and back to three; the main process stores the same byte
 *              again and unmaps
 *   files      100 files, one after another, mapped, stored through and unmapped (more
 *              files than Patina keeps shadows of at once)
 *   held       65 files mapped at once (one more than Patina keeps shadows of)
 *   durable    a child stores 'x' and waits; the main process fsyncs the file and the
 *              directory, writes and fsyncs a marker; the child then stores 'u' at byte 1 and
 *              is killed. In a later boot: the marker means the first store is durable
 *              (`always`: synced-store-kept); the second may be lost (`sometimes`:
 *              unsynced-store-lost).
 *   durable-sync  durable, but the child maps only the second page and stores there, and the
 *              main process, mapping only the first page, calls sync(2) instead of fsync
 *   order      store-write, and in a later boot: the page cache held the child's
 *              stores before the write, so a file that has the write has them
 *              (`always`: write-keeps-earlier-store).
 * Every mode but durable and order prints bytes of the file as read(2) returns them, which is what a
 * native run prints too.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "patina.h"

#define PG 4096
#define LEN (3 * PG)

static int fd;

static char *map_file(void) {
    char *m = mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) exit(4);
    return m;
}

static void put(int p, char c) {
    if (write(p, &c, 1) != 1) _exit(7);
}

static char get(int p) {
    char c;
    if (read(p, &c, 1) != 1) _exit(8);
    return c;
}

static void show(const int *at, int n) {
    int f = open("shm", O_RDONLY);
    if (f < 0) exit(9);
    printf("shm:");
    for (int i = 0; i < n; i++) {
        char b = 0;
        if (pread(f, &b, 1, at[i]) != 1) exit(9);
        printf(" %d=%d", at[i], b);
    }
    printf("\n");
}

static int later(int at) {
    char s = 0, b[2] = {0};
    int m = open("marker", O_RDONLY);
    if (m < 0 || read(m, &s, 1) != 1) return 0; /* crashed before the marker was synced */
    int f = open("shm", O_RDONLY);
    if (f < 0 || pread(f, b, 2, at) != 2) b[0] = b[1] = 0;
    char detail[32];
    snprintf(detail, sizeof detail, "shm[0]=%d", b[0]);
    PATINA_ALWAYS(b[0] == 'x', "synced-store-kept", detail);
    PATINA_SOMETIMES(b[1] != 'u', "unsynced-store-lost");
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "back";
    const char *boot = getenv("PATINA_BOOT");
    int dsync = !strcmp(mode, "durable-sync");
    if ((!strcmp(mode, "durable") || dsync) && boot && atoi(boot) > 0) return later(dsync ? PG : 0);
    if (!strcmp(mode, "order") && boot && atoi(boot) > 0) {
        char b[201] = {0};
        int f = open("shm", O_RDONLY);
        if (f >= 0 && pread(f, b, sizeof b, 0) == sizeof b)
            PATINA_ALWAYS(b[100] != 'Y' || (b[0] == 'x' && b[200] == 'z'),
                          "write-keeps-earlier-store", "");
        return 0;
    }
    fd = open("shm", O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || ftruncate(fd, LEN) != 0) return 3;
    int up[2], down[2];
    if (pipe(up) != 0 || pipe(down) != 0) return 5;

    if (!strcmp(mode, "back") || !strcmp(mode, "back-kill") || !strcmp(mode, "trunc")) {
        int at = !strcmp(mode, "trunc") ? 2 * PG + 7 : 0;
        char *m = map_file();
        m[at] = 'A';
        if (msync(m, LEN, MS_ASYNC) != 0) return 12;
        pid_t c = fork();
        if (c < 0) return 6;
        if (c == 0) {
            if (!strcmp(mode, "trunc")) {
                if (ftruncate(fd, PG) != 0 || ftruncate(fd, LEN) != 0) _exit(13);
                _exit(0);
            }
            m[at] = 'B';
            if (!strcmp(mode, "back-kill")) {
                put(up[1], 'r');
                for (;;) pause();
            }
            _exit(0);
        }
        if (!strcmp(mode, "back-kill")) {
            get(up[0]);
            kill(c, SIGKILL);
        }
        waitpid(c, NULL, 0);
        m[at] = 'A';
        if (munmap(m, LEN) != 0) return 13;
        show(&at, 1);
        return 0;
    }
    if (!strcmp(mode, "alternate")) {
        char *m = map_file();
        pid_t c = fork();
        if (c < 0) return 6;
        for (int i = 0; i < 6; i++) {
            if (c == 0) {
                get(down[0]);
                m[0] = 'C';
                if (msync(m, LEN, MS_ASYNC) != 0) _exit(12);
                put(up[1], 'c');
            } else {
                m[0] = 'P';
                if (msync(m, LEN, MS_ASYNC) != 0) return 12;
                put(down[1], 'p');
                get(up[0]);
            }
        }
        if (c == 0) _exit(0);
        waitpid(c, NULL, 0);
        m[0] = 'P';
        if (munmap(m, LEN) != 0) return 13;
        int at = 0;
        show(&at, 1);
        return 0;
    }
    if (!strcmp(mode, "store-write") || !strcmp(mode, "store-writev") ||
        !strcmp(mode, "write-store") || !strcmp(mode, "order")) {
        int ws = !strcmp(mode, "write-store");
        if (ws && pwrite(fd, "a", 1, 100) != 1) return 10;
        pid_t c = fork();
        if (c < 0) return 6;
        if (c == 0) {
            char *m = map_file();
            if (!ws) {
                m[0] = 'x';
                m[200] = 'z';
            }
            put(up[1], 'r');
            get(down[0]);
            if (ws) m[100] = 'a';
            _exit(0);
        }
        get(up[0]);
        if (!strcmp(mode, "store-writev")) {
            struct iovec v = {"Y", 1};
            if (lseek(fd, 100, SEEK_SET) != 100 || writev(fd, &v, 1) != 1) return 10;
        } else if (pwrite(fd, "Y", 1, 100) != 1) {
            return 10;
        }
        put(down[1], 'g');
        waitpid(c, NULL, 0);
        int at[3] = {0, 100, 200};
        show(at, 3);
        return 0;
    }
    if (!strcmp(mode, "files")) {
        for (int i = 0; i < 100; i++) {
            char name[16];
            snprintf(name, sizeof name, "f%d", i);
            int f = open(name, O_RDWR | O_CREAT | O_TRUNC, 0600);
            if (f < 0 || ftruncate(f, PG) != 0) return 3;
            char *m = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_SHARED, f, 0);
            if (m == MAP_FAILED) return 4;
            m[i] = 'a' + i % 26;
            if (munmap(m, PG) != 0 || close(f) != 0) return 13;
        }
        int f = open("f99", O_RDONLY);
        char b = 0;
        if (f < 0 || pread(f, &b, 1, 99) != 1) return 9;
        printf("f99: 99=%d\n", b);
        return 0;
    }
    if (!strcmp(mode, "held")) {
        for (int i = 0; i < 65; i++) {
            char name[16];
            snprintf(name, sizeof name, "h%d", i);
            int f = open(name, O_RDWR | O_CREAT | O_TRUNC, 0600);
            if (f < 0 || ftruncate(f, PG) != 0) return 3;
            char *m = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_SHARED, f, 0);
            if (m == MAP_FAILED) return 4;
            m[0] = 'h';
        }
        printf("held 65\n");
        return 0;
    }
    if (!strcmp(mode, "durable") || dsync) {
        pid_t c = fork();
        if (c < 0) return 6;
        if (c == 0) {
            char *m = dsync ? mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, PG)
                            : map_file();
            if (m == MAP_FAILED) _exit(4);
            m[0] = 'x';
            put(up[1], 'r');
            get(down[0]);
            m[1] = 'u';
            put(up[1], 'r');
            for (;;) pause();
        }
        get(up[0]);
        int d = open(".", O_RDONLY);
        if (dsync) {
            char *m = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (m == MAP_FAILED) return 4;
            m[7] = 'p';
            sync();
        } else if (d < 0 || fsync(fd) != 0 || fsync(d) != 0) {
            return 10;
        }
        if (d < 0) return 10;
        int mk = open("marker", O_WRONLY | O_CREAT, 0600);
        if (mk < 0 || write(mk, "s", 1) != 1 || fsync(mk) != 0 || fsync(d) != 0) return 11;
        put(down[1], 'g');
        get(up[0]);
        kill(c, SIGKILL);
        waitpid(c, NULL, 0);
        return 0;
    }
    return 2;
}
