/* Containment: program code reaching the control region at its published address
 * (0x6020_0000_0000), where it used to be mapped read-write in every guest process.
 *   ctlwrite            find the virtual clock's word and add an hour to it (before the
 *                       containment change, one store moved the supervisor's clock)
 *   ctlwrite OFF BYTE   after a few calls, store BYTE at offset OFF: a stray write
 *   ctlwrite log OFF    the same at the boundary log's published address */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
    volatile uint64_t *ctl = (volatile uint64_t *)0x602000000000ull;
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    if (argc > 2) {
        int log = !strcmp(argv[1], "log");
        volatile uint8_t *base = (volatile uint8_t *)(log ? 0x603000000000ull : 0x602000000000ull);
        unsigned long off = strtoul(argv[log ? 2 : 1], 0, 0);
        for (int i = 0; i < 10; i++) { getppid(); clock_gettime(CLOCK_MONOTONIC, &t); }
        printf("store at %p\n", (void *)(base + off));
        fflush(stdout);
        base[off] = log ? 0xff : (uint8_t)strtoul(argv[2], 0, 0);
        printf("stored\n");
        return 0;
    }
    uint64_t v = (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
    int idx = -1;
    for (int i = 0; i < 512; i++) if (ctl[i] >= v && ctl[i] < v + 10000000ull) { idx = i; break; }
    printf("monotonic %llu, vclock word at index %d\n", (unsigned long long)v, idx);
    if (idx < 0) return 0;
    ctl[idx] += 3600ull * 1000000000ull;
    clock_gettime(CLOCK_MONOTONIC, &t);
    printf("after one store: monotonic %lld.%09ld\n", (long long)t.tv_sec, t.tv_nsec);
    return 0;
}
