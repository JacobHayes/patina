/* blocking I/O item 5: 16 threads in a ring, each blocking-reads one byte from its predecessor's
 * pipe and writes it to its successor's; argv[1] laps (default 100,000). */
#include "common.h"

enum { T = 16 };
static int p[T][2];
static long laps;

static void *node(void *x) {
    int i = (int)(intptr_t)x;
    long seen = 0;
    for (;;) {
        char b;
        CHECK(read(p[i][0], &b, 1) == 1, "ring read");
        if (b == 'S') {
            if (i != T - 1) CHECK(write(p[(i + 1) % T][1], &b, 1) == 1, "ring write");
            return (void *)seen;
        }
        seen++;
        if (i == 0 && seen == laps) b = 'S';
        CHECK(write(p[(i + 1) % T][1], &b, 1) == 1, "ring write");
        if (b == 'S') return (void *)seen;
    }
}

int main(int argc, char **argv) {
    laps = argc > 1 ? atol(argv[1]) : 100000;
    for (int i = 0; i < T; i++) CHECK(pipe(p[i]) == 0, "pipe");
    pthread_t t[T];
    for (int i = 0; i < T; i++) spawn(&t[i], node, (void *)(intptr_t)i);
    CHECK(write(p[0][1], "t", 1) == 1, "inject");
    long total = 0;
    for (int i = 0; i < T; i++) {
        void *r;
        pthread_join(t[i], &r);
        total += (long)r;
    }
    printf("laps %ld hops %ld\n", laps, total);
    CHECK(total == laps * T - (T - 1), "hops");
    return 0;
}
