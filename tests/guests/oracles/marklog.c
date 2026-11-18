/* marklog [fixed]: append record I to data.log, mark "wrote I", then mark "ack I" (SDK). The
 * planted bug: the record is never fsynced before its acknowledgement. `marklog fixed` fsyncs
 * it between the two marks, so only the progress mark "wrote I" sees an unsynced write. */
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
        char rec[16], label[16];
        snprintf(rec, sizeof rec, "%07d\n", i);
        if (write(fd, rec, 8) != 8) return 2;
        snprintf(label, sizeof label, "wrote %d", i);
        patina_mark(label);
        if (fixed && fsync(fd)) return 2;
        snprintf(label, sizeof label, "ack %d", i);
        patina_mark(label);
    }
    return close(fd) ? 2 : 0;
}
