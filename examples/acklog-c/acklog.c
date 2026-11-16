/* A log that acknowledges a record only once it is on disk. After a machine crash, every
 * acknowledged record must still be in the log. The bug: the record is never fsynced, so the
 * acknowledgement can reach the disk before the record does. `acklog fixed` syncs it. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "patina.h"

#define N 40

/* The number of whole records at the start of a file; each is "%07d\n" of its index. */
static int count(int fd) {
    char got[8], want[16];
    int n = 0;
    while (pread(fd, got, 8, n * 8L) == 8 && snprintf(want, sizeof want, "%07d\n", n) && !memcmp(got, want, 8)) n++;
    return n;
}

int main(int argc, char **argv) {
    int fixed = argc > 1 && strcmp(argv[1], "fixed") == 0;
    int data = open("data.log", O_CREAT | O_RDWR, 0644);
    int acks = open("acks.log", O_CREAT | O_RDWR, 0644);
    int dir = open(".", O_RDONLY);
    if (data < 0 || acks < 0 || dir < 0 || fsync(dir) != 0) return 2;

    /* Recovery: after a crash the program starts again here, on what reached the disk. */
    int stored = count(data), acked = count(acks);
    char detail[64];
    snprintf(detail, sizeof detail, "%d acknowledged, %d stored", acked, stored);
    PATINA_ALWAYS(acked <= stored, "acked-records-kept", detail);
    if (acked > stored) {
        printf("lost acknowledged records: %s\n", detail);
        return 1;
    }

    for (int i = acked; i < N; i++) {
        char rec[16];
        snprintf(rec, sizeof rec, "%07d\n", i);
        if (pwrite(data, rec, 8, i * 8L) != 8) return 2;
        if (fixed && fsync(data) != 0) return 2; /* the fix */
        if (pwrite(acks, rec, 8, i * 8L) != 8 || fsync(acks) != 0) return 2;
    }
    printf("%d records acknowledged\n", N);
    return 0;
}
