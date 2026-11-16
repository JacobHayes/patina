/* Cost of a pipe write+read pair between two threads: ping-pong over two pipes. */
#include "common.h"

static int a[2], b[2];
static long n;
static void *echo(void *x) {
    (void)x;
    char c;
    for (long i = 0; i < n; i++) {
        CHECK(read(a[0], &c, 1) == 1, "read");
        CHECK(write(b[1], &c, 1) == 1, "write");
    }
    return NULL;
}
int main(int argc, char **argv) {
    n = argc > 1 ? atol(argv[1]) : 100000;
    CHECK(pipe(a) == 0 && pipe(b) == 0, "pipe");
    pthread_t t;
    spawn(&t, echo, NULL);
    char c = 'x';
    for (long i = 0; i < n; i++) {
        CHECK(write(a[1], &c, 1) == 1, "write");
        CHECK(read(b[0], &c, 1) == 1, "read");
    }
    pthread_join(t, NULL);
    printf("round trips %ld\n", n);
    return 0;
}
