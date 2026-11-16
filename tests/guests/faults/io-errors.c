/* io-errors: exercise every faultable filesystem call class in a loop and tally errnos.
 *
 *   io-errors tally [N]   N rounds (default 200) of open, read, write, sync, rename,
 *                         unlink, mkdir, truncate, link, fallocate, close on /work.
 *                         Prints "tally CLASS ERRNO COUNT" lines, then "violations V":
 *                         a failed call that left an effect, or a close that failed
 *                         without closing the descriptor.
 *   io-errors nth         10 writes of 4-byte records "Wn\n_" to /work/w.dat; prints each
 *                         result, then the file contents (a failed write is not in it).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { OPEN, READ, WRITE, SYNC, RENAME, UNLINK, MKDIR, TRUNC, LINK, FALLOC, CLOSE, NCLASS };
static const char *names[NCLASS] = {"open", "read", "write", "sync", "rename", "unlink",
                                    "mkdir", "truncate", "link", "fallocate", "close"};
static long tally[NCLASS][200];
static long violations, vby[NCLASS];
#define VIOL(c) (violations++, vby[c]++)

static void note(int c, int r) {
    int e = r < 0 ? errno : 0;
    if (e >= 200) e = 199;
    tally[c][e]++;
}

static int exists(const char *p) {
    struct stat st;
    return lstat(p, &st) == 0;
}

static long fsize(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;
    return st.st_size;
}

static int tally_mode(int rounds) {
    char buf[64];
    /* Set-up: a data file to write, one to read. Retried: faults may hit set-up too. */
    int wfd = -1, rfd = -1;
    while (wfd < 0) wfd = open("data", O_CREAT | O_RDWR, 0644);
    while (rfd < 0) {
        int fd = open("src", O_CREAT | O_RDWR, 0644);
        if (fd < 0) continue;
        while (pwrite(fd, "0123456789", 10, 0) != 10) {}
        rfd = fd;
    }
    long size = 0;
    for (int i = 0; i < rounds; i++) {
        int r;
        /* open */
        snprintf(buf, sizeof buf, "o%d", i % 8);
        r = open(buf, O_CREAT | O_RDWR, 0644);
        note(OPEN, r);
        if (r >= 0) {
            while (close(r) != 0 && fcntl(r, F_GETFD) >= 0) {}
        }
        /* read */
        r = (int)pread(rfd, buf, 4, 0);
        note(READ, r);
        /* write: one byte at the end; a failed write must not change the size */
        r = (int)pwrite(wfd, "x", 1, size);
        note(WRITE, r);
        if (r == 1) size++;
        if (fsize(wfd) != size) VIOL(WRITE), size = fsize(wfd);
        /* sync */
        r = fsync(wfd);
        note(SYNC, r);
        /* rename a <-> b */
        if (!exists("ra") && !exists("rb")) {
            int fd = open("ra", O_CREAT | O_WRONLY, 0644);
            if (fd >= 0) while (close(fd) != 0 && fcntl(fd, F_GETFD) >= 0) {}
        }
        if (exists("ra")) {
            r = rename("ra", "rb");
            note(RENAME, r);
            if (r != 0 && (!exists("ra") || exists("rb"))) VIOL(RENAME);
        } else {
            r = rename("rb", "ra");
            note(RENAME, r);
            if (r != 0 && (!exists("rb") || exists("ra"))) VIOL(RENAME);
        }
        /* unlink */
        int fd = open("u", O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) {
            while (close(fd) != 0 && fcntl(fd, F_GETFD) >= 0) {}
            r = unlink("u");
            note(UNLINK, r);
            if (r != 0 && !exists("u")) VIOL(UNLINK);
        }
        /* mkdir (then rmdir, counted as unlink) */
        int had = exists("m");
        r = mkdir("m", 0755);
        note(MKDIR, r);
        if (r != 0 && !had && exists("m")) VIOL(MKDIR);
        if (exists("m")) {
            r = rmdir("m");
            note(UNLINK, r);
        }
        /* truncate */
        r = ftruncate(wfd, size);
        note(TRUNC, r);
        if (fsize(wfd) != size) VIOL(TRUNC);
        /* link */
        if (exists("l")) unlink("l");
        if (!exists("l")) {
            r = link("data", "l");
            note(LINK, r);
            if (r != 0 && exists("l")) VIOL(LINK);
        }
        /* fallocate: KEEP_SIZE so the size bookkeeping above holds */
        r = fallocate(wfd, FALLOC_FL_KEEP_SIZE, 0, 4096);
        note(FALLOC, r);
        /* close: EIO still closes */
        fd = open("c", O_CREAT | O_RDWR, 0644);
        if (fd >= 0) {
            r = close(fd);
            note(CLOSE, r);
            if (fcntl(fd, F_GETFD) >= 0) VIOL(CLOSE);
        }
    }
    for (int c = 0; c < NCLASS; c++)
        for (int e = 0; e < 200; e++)
            if (tally[c][e]) printf("tally %s %s %ld\n", names[c], e ? strerrorname_np(e) : "ok", tally[c][e]);
    for (int c = 0; c < NCLASS; c++)
        if (vby[c]) printf("violation %s %ld\n", names[c], vby[c]);
    printf("violations %ld\n", violations);
    return 0;
}

static int nth_mode(void) {
    int fd = open("w.dat", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return 1; }
    for (int i = 1; i <= 10; i++) {
        char rec[5];
        snprintf(rec, sizeof rec, "W%d\n", i % 10);
        ssize_t r = write(fd, rec, 3);
        printf("write %d: %s\n", i, r == 3 ? "ok" : strerrorname_np(errno));
    }
    close(fd);
    char buf[64] = {0};
    fd = open("w.dat", O_RDONLY);
    ssize_t n = read(fd, buf, sizeof buf - 1);
    printf("contents (%zd bytes): ", n);
    for (ssize_t i = 0; i < n; i++) putchar(buf[i] == '\n' ? ' ' : buf[i]);
    putchar('\n');
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 1 && strcmp(argv[1], "nth") == 0) return nth_mode();
    return tally_mode(argc > 2 ? atoi(argv[2]) : 200);
}
