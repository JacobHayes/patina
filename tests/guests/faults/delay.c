/* delay: 100 small writes to /work/d.dat; prints the virtual time they took (ms). */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static long long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

int main(void) {
    int fd = open("d.dat", O_CREAT | O_TRUNC | O_WRONLY, 0644);
    long long t0 = now_ns();
    int ok = 0;
    for (int i = 0; i < 100; i++)
        if (write(fd, "0123456789abcdef", 16) == 16) ok++;
    long long t1 = now_ns();
    close(fd);
    printf("writes %d virtual_ms %lld\n", ok, (t1 - t0) / 1000000);
    return 0;
}
