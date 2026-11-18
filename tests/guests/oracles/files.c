/* files MODE: changes to the work tree whose paths `patina log events` names.
 *   tour   create a/x, rename it to b/y, append to it, fsync it
 *   data   write data/f only
 *   other  write data/f, then other/f (outside data/) */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int put(const char *path, int sync) {
    int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0 || write(fd, "record\n", 7) != 7 || (sync && fsync(fd)) || close(fd)) return 1;
    return 0;
}

int main(int argc, char **argv) {
    const char *m = argc > 1 ? argv[1] : "";
    if (!strcmp(m, "tour")) {
        if (mkdir("a", 0755) || mkdir("b", 0755)) return 2;
        int fd = open("a/x", O_CREAT | O_WRONLY, 0644);
        if (fd < 0 || rename("a/x", "b/y") || write(fd, "moved\n", 6) != 6 || fsync(fd) || close(fd))
            return 2;
        return 0;
    }
    if (strcmp(m, "data") && strcmp(m, "other")) {
        fprintf(stderr, "usage: files tour|data|other\n");
        return 2;
    }
    if (mkdir("data", 0755) || put("data/f", 1)) return 2;
    if (!strcmp(m, "other") && (mkdir("other", 0755) || put("other/f", 1))) return 2;
    return 0;
}
