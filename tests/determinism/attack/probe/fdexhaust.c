/* Descriptor exhaustion: open until failure, report the count and errno, raise the soft
 * limit to the hard limit, repeat; also pipe() and dup2 at the top of the range. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>
static int fill(void) {
    int n = 0;
    for (;;) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) { printf("open failed after %d errno %d\n", n, errno); return n; }
        n++;
        if (n > 70000) { printf("stopped at %d\n", n); return n; }
    }
}
int main(void) {
    struct rlimit r; getrlimit(RLIMIT_NOFILE, &r);
    printf("nofile %llu %llu\n", (unsigned long long)r.rlim_cur, (unsigned long long)r.rlim_max);
    fill();
    int p[2]; printf("pipe %d errno %d\n", pipe(p), errno);
    r.rlim_cur = r.rlim_max; printf("raise %d errno %d\n", setrlimit(RLIMIT_NOFILE, &r), errno);
    getrlimit(RLIMIT_NOFILE, &r);
    printf("nofile %llu %llu\n", (unsigned long long)r.rlim_cur, (unsigned long long)r.rlim_max);
    fill();
    printf("dup2 high %d errno %d\n", dup2(0, 1000000), errno);
    return 0;
}
