/* Containment: a guest store into the control region (mapped read-write in every guest
 * process at 0x6020_0000_0000) changes the supervisor's virtual clock. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main(int argc, char **argv) {
    volatile uint64_t *ctl = (volatile uint64_t *)0x602000000000ull;
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    uint64_t v = (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
    int idx = -1;
    for (int i = 0; i < 512; i++) if (ctl[i] >= v && ctl[i] < v + 10000000ull) { idx = i; break; }
    printf("monotonic %llu, vclock word at index %d\n", (unsigned long long)v, idx);
    if (idx < 0 || (argc > 1 && atoi(argv[1]) == 0)) return 0;
    ctl[idx] += 3600ull * 1000000000ull;
    clock_gettime(CLOCK_MONOTONIC, &t);
    printf("after one store: monotonic %lld.%09ld\n", (long long)t.tv_sec, t.tv_nsec);
    return 0;
}
