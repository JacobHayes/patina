/* Containment: a jump to a `syscall` instruction (the bytes 0f 05; on arm64 an `svc #0` word)
 * in the runtime's text, made by program code on its own stack, as through a corrupted
 * function pointer. Before the containment change it reached the real kernel: the host's
 * CLOCK_REALTIME and the real getrandom, neither recorded.
 *   gadget count   print how many such instructions the runtime's text holds
 *   gadget N       jump to the N-th, as clock_gettime(CLOCK_REALTIME), then as getrandom */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static uint8_t *at[4096];
static int find(void) {
    uint8_t *t = (uint8_t *)0x600000000000ull;
    int p[2], n = 0;
    if (pipe(p)) return 0;
    for (size_t pg = 0; pg < (8u << 20); pg += 4096) {
        if (write(p[1], t + pg, 1) != 1) break; /* EFAULT: past the mapped text */
        char c; read(p[0], &c, 1);
#ifdef __x86_64__
        for (size_t i = pg; i < pg + 4096; i++)
            if (t[i] == 0x0f && t[i + 1] == 0x05 && n < 4096) at[n++] = t + i;
#else
        for (size_t i = pg; i < pg + 4096; i += 4)
            if (*(uint32_t *)(t + i) == 0xd4000001 && n < 4096) at[n++] = t + i;
#endif
    }
    return n;
}
#ifdef __x86_64__
#define NR_CLOCK_GETTIME 228
#define NR_GETRANDOM 318
static long raw(uint8_t *g, long nr, long a, long b, long c) {
    register long r10 __asm__("r10") = 0;
    __asm__ volatile(
        "lea 1f(%%rip), %%r11\n\t"
        "push %%r11\n\t"
        "jmp *%[g]\n\t"
        "1:\n\t"
        : "+a"(nr), "+D"(a), "+S"(b), "+d"(c), "+r"(r10)
        : [g] "r"(g)
        : "rcx", "r11", "memory");
    return nr;
}
#else
#define NR_CLOCK_GETTIME 113
#define NR_GETRANDOM 278
static long raw(uint8_t *g, long nr, long a, long b, long c) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("adr x30, 1f\n\tbr %[g]\n1:"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), [g] "r"(g)
                     : "x16", "x30", "cc", "memory");
    return x0;
}
#endif
int main(int argc, char **argv) {
    int n = find();
    if (argc < 2 || !strcmp(argv[1], "count")) { printf("%d\n", n); return 0; }
    int i = atoi(argv[1]);
    if (i < 0 || i >= n) { printf("no pair %d of %d\n", i, n); return 2; }
    struct timespec v, h = {0};
    clock_gettime(CLOCK_REALTIME, &v);
    raw(at[i], NR_CLOCK_GETTIME, CLOCK_REALTIME, (long)&h, 0);
    printf("virtual realtime %lld; real call gives year %lld\n", (long long)v.tv_sec, (long long)(h.tv_sec / 31556952 + 1970));
    unsigned char rnd[8] = {0};
    raw(at[i], NR_GETRANDOM, (long)rnd, 8, 0);
    printf("real getrandom %02x%02x%02x%02x\n", rnd[0], rnd[1], rnd[2], rnd[3]);
    return 0;
}
