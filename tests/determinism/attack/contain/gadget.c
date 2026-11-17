/* Containment: a jump to a `syscall` instruction (the bytes 0f 05; on arm64 an `svc #0` word)
 * in the runtime's text, made by program code on its own stack, as through a corrupted
 * function pointer. Before the containment change it reached the real kernel: the host's
 * CLOCK_REALTIME and the real getrandom, neither recorded.
 *   gadget count TEXT   print how many such instructions the runtime's text holds (TEXT: the
 *                       text segment's size, from the runtime binary) and a hash of the text
 *   gadget N TEXT       jump to the N-th, as clock_gettime(CLOCK_REALTIME), then as getrandom
 * The text is read with plain loads (reading the runtime is not contained); a system call
 * cannot read it for the program (`write(fd, text, 1)` is EFAULT, as for a hole). */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static uint8_t *at[4096];
static uint64_t text_hash;
static int find(size_t size) {
    uint8_t *t = (uint8_t *)0x600000000000ull;
    int n = 0;
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < size; i++) h = (h ^ t[i]) * 0x100000001b3ull;
    text_hash = h;
#ifdef __x86_64__
    for (size_t i = 0; i + 1 < size; i++)
        if (t[i] == 0x0f && t[i + 1] == 0x05 && n < 4096) at[n++] = t + i;
#else
    for (size_t i = 0; i + 4 <= size; i += 4)
        if (*(uint32_t *)(t + i) == 0xd4000001 && n < 4096) at[n++] = t + i;
#endif
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
    if (argc < 3) return 2;
    int n = find(strtoul(argv[2], 0, 0));
    if (!strcmp(argv[1], "count")) { printf("%d\n%016llx\n", n, (unsigned long long)text_hash); return 0; }
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
