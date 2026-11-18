/* An append-only log with no Patina SDK in it. It prints "ack I" once record I is
 * written; the planted bug is that the record is never fsynced. `kvlog fixed` syncs it. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int fixed = argc > 1 && !strcmp(argv[1], "fixed");
    int data = open("data.log", O_CREAT | O_RDWR, 0644), dir = open(".", O_RDONLY);
    struct stat st;
    if (data < 0 || dir < 0 || fsync(dir) || fstat(data, &st)) return 2;
    for (int i = st.st_size / 8; i < 40; i++) {
        char rec[16];
        snprintf(rec, sizeof rec, "%07d\n", i);
        if (pwrite(data, rec, 8, i * 8L) != 8) return 2;
        if (fixed && fsync(data)) return 2;
        dprintf(1, "ack %d\n", i);
    }
    return 0;
}
