/* Shared helpers for the blocking I/O guests. Output is schedule-independent unless a guest prints
 * an order on purpose (evloop). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c, ...)                                                       \
    do {                                                                    \
        if (!(c)) {                                                         \
            fprintf(stderr, "INVARIANT %s:%d: ", __FILE__, __LINE__);       \
            fprintf(stderr, __VA_ARGS__);                                   \
            fprintf(stderr, " (errno %d)\n", errno);                        \
            exit(1);                                                        \
        }                                                                   \
    } while (0)

static inline uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

static inline ssize_t readn(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return got ? (ssize_t)got : r;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static inline void spawn(pthread_t *t, void *(*f)(void *), void *arg) {
    CHECK(pthread_create(t, NULL, f, arg) == 0, "pthread_create");
}
