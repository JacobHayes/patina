/* Containment on arm64: program code, on its own stack, branches to the runtime's one `svc #0`
 * (found by reading the runtime's text) as clock_gettime(CLOCK_REALTIME), as through a
 * corrupted function pointer. The call itself reaches the kernel (the filter allows that
 * address); the stub's stack check must stop the program before it gets the answer back. */
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static uint32_t *find(void) {
    uint32_t *t = (uint32_t *)0x600000000000ull;
    for (size_t i = 0; i < (4u << 20) / 4; i++)
        if (t[i] == 0xd4000001) return t + i; /* svc #0 */
    return 0;
}

static long raw(void *g, long nr, long a, long b) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    __asm__ volatile("adr x30, 1f\n\tbr %[g]\n1:"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), [g] "r"(g)
                     : "x16", "x30", "cc", "memory");
    return x0;
}

int main(void) {
    uint32_t *g = find();
    if (!g) { printf("no svc in the runtime's text\n"); return 2; }
    struct timespec v, h = {0};
    clock_gettime(CLOCK_REALTIME, &v);
    long r = raw(g, 113 /* clock_gettime */, CLOCK_REALTIME, (long)&h);
    printf("virtual realtime %lld; the real call returned %ld, year %lld\n", (long long)v.tv_sec, r,
           (long long)(h.tv_sec / 31556952 + 1970));
    return 0;
}
