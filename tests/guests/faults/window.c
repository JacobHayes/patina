/* window: append N records to data.log and acknowledge each in acks.log, each write synced
 * before the next step, except record GAP: its acknowledgement is written and synced before
 * the record is. A machine crash between that record's write and its sync can keep the
 * acknowledgement and lose the record: a window of a few crash points among about a hundred.
 * On start it checks every acknowledged record is stored (`always`: acked-records-stored),
 * then continues where it left off. Records and acknowledgements are "%07d\n" of the index.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "patina.h"

#define N 16
#define GAP 9

static int count(int fd) {
    char got[8], want[16];
    int n = 0;
    while (pread(fd, got, 8, n * 8L) == 8 && snprintf(want, sizeof want, "%07d\n", n) && !memcmp(got, want, 8)) n++;
    return n;
}

int main(void) {
    int data = open("data.log", O_CREAT | O_RDWR, 0644);
    int acks = open("acks.log", O_CREAT | O_RDWR, 0644);
    int dir = open(".", O_RDONLY);
    if (data < 0 || acks < 0 || dir < 0 || fsync(dir) != 0) return 2;
    int stored = count(data), acked = count(acks);
    char detail[64];
    snprintf(detail, sizeof detail, "%d acknowledged, %d stored", acked, stored);
    PATINA_ALWAYS(acked <= stored, "acked-records-stored", detail);
    if (acked > stored) return 1;
    for (int i = acked; i < N; i++) {
        char rec[16];
        snprintf(rec, sizeof rec, "%07d\n", i);
        if (pwrite(data, rec, 8, i * 8L) != 8) return 2;
        if (i != GAP && fsync(data) != 0) return 2;
        if (pwrite(acks, rec, 8, i * 8L) != 8 || fsync(acks) != 0) return 2;
        if (i == GAP && fsync(data) != 0) return 2;
    }
    printf("%d records acknowledged\n", N);
    return 0;
}
