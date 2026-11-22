/* ack-log: append a record, fsync it, then acknowledge it in an fsynced acks file. Every
 * fifth record, a checkpoint file is replaced by write-temp, fsync, rename, directory fsync.
 * On start, if state exists, every acknowledged record must be present (else it prints
 * "INVARIANT acked-record-lost" and exits 1), then it continues where it left off. Any
 * failed open, read or write stops it (exit 0) without acknowledging more.
 *
 *   ack-log MODE [TOTAL]
 *     correct  as above; an fsync error stops the program before acknowledging
 *     nofsync  the planted bug: no fsync of the record before the acknowledgement
 *     retry    the planted bug: retry fsync until it succeeds, then acknowledge
 *     fatal    the first fsync error is fatal: stop without acknowledging (exit 0)
 *
 * Records are 32 bytes at offset 32*i; acknowledgements 8 bytes each ("%07d\n").
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REC 32
#define ACK 8
static const char *mode;
static int dirfd_;

static void rec_of(int i, char *b) {
    char tail[REC];
    memset(tail, 'a' + i % 26, sizeof tail);
    snprintf(b, REC + 1, "rec %06d %.*s\n", i, REC - 12, tail);
}

static int valid_rec(const char *buf, long len, int i) {
    char want[REC + 1];
    if ((long)(i + 1) * REC > len) return 0;
    rec_of(i, want);
    return memcmp(buf + (long)i * REC, want, REC) == 0;
}

static char *slurp(const char *p, long *len) {
    *len = 0;
    int fd = open(p, O_RDONLY);
    if (fd < 0 && errno != ENOENT) {
        /* Recovery cannot judge what it cannot open: stop without acknowledging more. */
        printf("open %s: %s: stopping\n", p, strerrorname_np(errno));
        exit(0);
    }
    if (fd < 0) return NULL;
    struct stat st;
    fstat(fd, &st);
    char *b = calloc(1, st.st_size + 1);
    long n = 0, r = 0;
    while (n < st.st_size && (r = read(fd, b + n, st.st_size - n)) > 0) n += r;
    if (r < 0) {
        /* Recovery cannot judge what it cannot read: stop without acknowledging more. */
        printf("read %s: %s: stopping\n", p, strerrorname_np(errno));
        exit(0);
    }
    close(fd);
    *len = n;
    return b;
}

static int exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0;
}

/* fsync with the mode's error policy: 0 = synced (or the error was retried away), -1 = stop. */
static int sync_fd(int fd) {
    if (fsync(fd) == 0) return 0;
    if (strcmp(mode, "retry") == 0) {
        printf("fsync %s: retrying\n", strerrorname_np(errno));
        while (fsync(fd) != 0) {}
        return 0;
    }
    printf("fsync %s: stopping without acknowledging\n", strerrorname_np(errno));
    return -1;
}

static int open_new(const char *p) {
    int existed = exists(p);
    int fd = open(p, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        printf("open %s: %s: stopping\n", p, strerrorname_np(errno));
        exit(0);
    }
    if (!existed && sync_fd(dirfd_) != 0) exit(0);
    return fd;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    mode = argc > 1 ? argv[1] : "correct";
    int total = argc > 2 ? atoi(argv[2]) : 30;
    const char *boot = getenv("PATINA_BOOT");
    printf("ack-log %s boot %s\n", mode, boot ? boot : "-");
    dirfd_ = open(".", O_RDONLY | O_DIRECTORY);

    int next = 0, nacks = 0;
    if (exists("data.log") || exists("acks")) {
        long dl, al, cl;
        char *data = slurp("data.log", &dl), *acks = slurp("acks", &al);
        int valid = 0;
        while (valid_rec(data, dl, valid)) valid++;
        int acked = 0, maxack = -1;
        nacks = (int)((al + ACK - 1) / ACK);
        for (int e = 0; e < al / ACK; e++) {
            char *a = acks + e * ACK;
            if (a[7] != '\n') continue;
            int n = atoi(a);
            if (n == 0 && a[6] != '0') continue;
            acked++;
            if (n > maxack) maxack = n;
            if (!valid_rec(data, dl, n)) {
                fprintf(stderr, "INVARIANT acked-record-lost record %d (acked, not in data.log)\n", n);
                printf("recovery: acknowledged record %d is missing\n", n);
                return 1;
            }
        }
        char *ck = slurp("ckpt", &cl);
        if (ck) {
            int n;
            if (cl != 12 || sscanf(ck, "ckpt %06d\n", &n) != 1 || n > maxack + 1) {
                fprintf(stderr, "INVARIANT ckpt-torn (%ld bytes)\n", cl);
                return 1;
            }
        }
        next = valid > maxack + 1 ? valid : maxack + 1;
        printf("recovered: %d valid records, %d acknowledged, next %d\n", valid, acked, next);
    }
    int data = open_new("data.log");
    int acks = open_new("acks");
    for (int i = next; i < total; i++) {
        char r[REC + 1];
        rec_of(i, r);
        if (pwrite(data, r, REC, (long)i * REC) != REC) {
            printf("write record %d: %s\n", i, strerrorname_np(errno));
            return 0;
        }
        if (strcmp(mode, "nofsync") != 0 && sync_fd(data) != 0) return 0;
        char a[16];
        snprintf(a, sizeof a, "%07d\n", i);
        if (pwrite(acks, a, ACK, (long)nacks * ACK) != ACK) {
            printf("write ack %d: %s\n", i, strerrorname_np(errno));
            return 0;
        }
        nacks++;
        if (sync_fd(acks) != 0) return 0;
        printf("ack %d\n", i);
        if ((i + 1) % 5 == 0) {
            int c = open("ckpt.tmp", O_CREAT | O_TRUNC | O_WRONLY, 0644);
            char b[32];
            snprintf(b, sizeof b, "ckpt %06d\n", i + 1);
            if (c < 0 || write(c, b, 12) != 12) return 0;
            if (sync_fd(c) != 0) return 0;
            close(c);
            if (rename("ckpt.tmp", "ckpt") != 0) return 0;
            if (sync_fd(dirfd_) != 0) return 0;
        }
    }
    printf("complete: %d records\n", total);
    return 0;
}
