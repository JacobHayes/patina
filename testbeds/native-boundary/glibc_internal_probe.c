/* Kernel calls made where no interposer sees them, each beside the same
 * question asked through an interposed call: under Patina both answers come
 * from the virtual kernel, so they agree; a call that reached the host would
 * answer the host's. argv[1] selects the pair, and the line printed names
 * both answers (glibc_internal_library.c holds the library's code):
 *
 *   weak         glibc's getloadavg through a weak import (glibc's own
 *                open/read of /proc/loadavg) / /proc/loadavg read through
 *                the interposed open and read
 *   library      the same getloadavg, called from a shared library
 *   library-raw  an inline getpid in a shared library / getpid() */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int getloadavg(double loads[], int count) __attribute__((weak));
extern int probe_library_loadavg(double loads[3]);
extern long probe_library_raw_getpid(void);

/* The three load averages /proc/loadavg names (two decimals each, as the
 * kernel formats them), through interposed calls, comma-separated into
 * `out`. */
static int door_loadavg(char out[64]) {
    char text[128] = {0};
    int fd = open("/proc/loadavg", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t length = read(fd, text, sizeof text - 1);
    close(fd);
    if (length <= 0) return -1;
    size_t at = 0;
    int fields = 0;
    for (ssize_t i = 0; i < length && fields < 3 && at < 63; i++) {
        if (text[i] == ' ') {
            if (++fields < 3) out[at++] = ',';
        } else {
            out[at++] = text[i];
        }
    }
    out[at] = 0;
    return fields == 3 ? 3 : -1;
}

static void print_loads(const char *mode, int glibc, const double internal[3]) {
    char door[64] = "none";
    int read = door_loadavg(door);
    printf("GLIBC_INTERNAL mode=%s glibc=%d internal=%.2f,%.2f,%.2f door=%d loads=%s\n", mode,
           glibc, internal[0], internal[1], internal[2], read, door);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "none";
    double loads[3] = {-1, -1, -1};
    if (strcmp(mode, "weak") == 0) {
        if (getloadavg == NULL) {
            puts("GLIBC_INTERNAL mode=weak unresolved");
            return 1;
        }
        print_loads(mode, getloadavg(loads, 3), loads);
    } else if (strcmp(mode, "library") == 0) {
        print_loads(mode, probe_library_loadavg(loads), loads);
    } else if (strcmp(mode, "library-raw") == 0) {
        long raw = probe_library_raw_getpid();
        printf("GLIBC_INTERNAL mode=%s raw=%ld door=%ld\n", mode, raw, (long)getpid());
    } else {
        return 2;
    }
    return 0;
}
