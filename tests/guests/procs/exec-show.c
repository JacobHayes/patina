/* Exec target: prints what it was started with, one fact per line.
 *   exe=<readlink /proc/self/exe>  argv[i]=<...>  env=<$EXEC_SHOW_ENV>  fds=<open descriptors 0..63>
 *   hidden=<errno of fcntl(3000, F_GETFD)>
 * More than 64 arguments: argc=<n> cmdline=<strings in /proc/self/cmdline> bytes=<its length>
 * instead of one line per argument.
 * Exit status 0. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char exe[512];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    exe[n < 0 ? 0 : n] = 0;
    printf("exe=%s\n", exe);
    if (argc > 64) {
        static char cl[4 << 20];
        int f = open("/proc/self/cmdline", O_RDONLY);
        size_t got = 0;
        ssize_t r;
        while (f >= 0 && got < sizeof cl && (r = read(f, cl + got, sizeof cl - got)) > 0) got += r;
        int strs = 0;
        for (size_t i = 0; i < got; i++) strs += cl[i] == 0;
        printf("argc=%d cmdline=%d bytes=%zu\n", argc, strs, got);
    } else {
        for (int i = 0; i < argc; i++) printf("argv[%d]=%s\n", i, argv[i]);
    }
    const char *e = getenv("EXEC_SHOW_ENV");
    printf("env=%s\n", e ? e : "(unset)");
    printf("fds=");
    for (int fd = 0; fd < 64; fd++)
        if (fcntl(fd, F_GETFD) >= 0) printf("%d,", fd);
    printf("\n");
    errno = 0;
    int r = fcntl(3000, F_GETFD);
    printf("hidden=%d,%s\n", r, r < 0 ? strerror(errno) : "open");
    fflush(stdout);
    return 0;
}
