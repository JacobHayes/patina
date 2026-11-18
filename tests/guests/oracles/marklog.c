/* marklog [fixed]: append record I to data.log, then mark "ack I" (SDK). The planted bug: the
 * record is never fsynced before its acknowledgement. `marklog fixed` fsyncs it first. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "patina.h"

int main(int argc, char **argv) {
    int fixed = argc > 1 && !strcmp(argv[1], "fixed");
    int fd = open("data.log", O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) return 2;
    for (int i = 0; i < 8; i++) {
        char rec[16], ack[16];
        snprintf(rec, sizeof rec, "%07d\n", i);
        if (write(fd, rec, 8) != 8 || (fixed && fsync(fd))) return 2;
        snprintf(ack, sizeof ack, "ack %d", i);
        patina_mark(ack);
    }
    return close(fd) ? 2 : 0;
}
