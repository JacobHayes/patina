/* Atomic pipe writes: 8 threads each write 1,000 records of exactly 4,096 bytes to one pipe; the
 * reader checks that no record is interleaved with another. */
#include "common.h"

enum { T = 8, N = 1000, R = 4096 };
static int p[2];

static void fill(uint8_t *b, int t, int s) {
    uint32_t h[2] = {(uint32_t)t, (uint32_t)s};
    memcpy(b, h, 8);
    for (int j = 8; j < R; j++) b[j] = (uint8_t)(t * 37 + s * 11 + j);
}

static void *writer(void *x) {
    int t = (int)(intptr_t)x;
    uint8_t b[R];
    for (int s = 0; s < N; s++) {
        fill(b, t, s);
        CHECK(write(p[1], b, R) == R, "record write");
    }
    return NULL;
}

int main(void) {
    CHECK(pipe(p) == 0, "pipe");
    pthread_t w[T];
    for (int t = 0; t < T; t++) spawn(&w[t], writer, (void *)(intptr_t)t);
    int next[T] = {0};
    long bad = 0;
    uint8_t b[R], want[R];
    for (long k = 0; k < (long)T * N; k++) {
        CHECK(readn(p[0], b, R) == R, "record read");
        uint32_t h[2];
        memcpy(h, b, 8);
        if (h[0] >= T || (int)h[1] != next[h[0]]) {
            bad++;
            continue;
        }
        fill(want, h[0], h[1]);
        if (memcmp(b, want, R) != 0) bad++;
        next[h[0]]++;
    }
    for (int t = 0; t < T; t++) pthread_join(w[t], NULL);
    printf("records %d interleaved %ld\n", T * N, bad);
    CHECK(bad == 0, "interleaved records");
    return 0;
}
