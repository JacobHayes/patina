/* Serves public/report.txt, ten times, and refuses a symlink there so that a link planted in
 * public/ cannot make it serve a file from elsewhere. The bug: it checks the name with lstat
 * and then opens the name, so a link that appears between the two calls is followed.
 * `serve fixed` opens with O_NOFOLLOW and serves only the file it checked. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "patina.h"

static const char REPORT[] = "quarterly numbers: all fine\n";

int main(int argc, char **argv) {
    int fixed = argc > 1 && strcmp(argv[1], "fixed") == 0;
    mkdir("public", 0755);
    int out = open("public/report.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (out >= 0) {
        if (write(out, REPORT, sizeof REPORT - 1) != sizeof REPORT - 1) return 2;
        close(out);
    }

    int served = 0, refused = 0;
    for (int i = 0; i < 10; i++) {
        struct stat st, got;
        if (lstat("public/report.txt", &st) != 0 || !S_ISREG(st.st_mode)) {
            refused++;
            continue;
        }
        int fd = open("public/report.txt", fixed ? O_RDONLY | O_NOFOLLOW : O_RDONLY);
        if (fd < 0) {
            refused++;
            continue;
        }
        /* the fix: the file opened is the file checked */
        if (fixed && (fstat(fd, &got) != 0 || got.st_dev != st.st_dev || got.st_ino != st.st_ino)) {
            close(fd);
            refused++;
            continue;
        }
        char buf[4096], detail[64];
        ssize_t n = read(fd, buf, sizeof buf);
        close(fd);
        snprintf(detail, sizeof detail, "%zd bytes", n);
        PATINA_ALWAYS(n == sizeof REPORT - 1 && memcmp(buf, REPORT, n) == 0, "served-only-public", detail);
        served++;
    }
    printf("%d served, %d refused\n", served, refused);
    return 0;
}
