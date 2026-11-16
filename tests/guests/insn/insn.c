/* instruction channels item 1. insn tsc: rdtsc and rdtscp 1,000 times each, interleaved with clock_gettime;
 * checks that the values strictly increase and agree with the clock (3 ticks per ns), prints
 * every value. insn rand: rdrand and rdseed, 16/32/64-bit forms, 100 times each; prints the
 * values and checks the carry flag. insn loop N: N rdtsc in a tight loop (item 8 cost).
 * insn ud2: the guest's own ud2 (must die of SIGILL). insn tscsig: the guest asks for
 * PR_TSC_SIGSEGV itself and must get the signal from rdtsc. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/prctl.h>

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
static inline uint64_t rdtscp(uint32_t *aux) {
    uint32_t lo, hi, c;
    __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(c));
    *aux = c;
    return ((uint64_t)hi << 32) | lo;
}
static uint64_t mono(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL " __VA_ARGS__); printf("\n"); } } while (0)

static void tsc(void) {
    uint64_t prev = 0, prevns = 0;
    for (int i = 0; i < 1000; i++) {
        uint32_t aux = 99;
        uint64_t ns0 = mono();
        uint64_t a = rdtsc();
        uint64_t b = rdtscp(&aux);
        uint64_t ns1 = mono();
        printf("%d %llu %llu %u %llu\n", i, (unsigned long long)a, (unsigned long long)b, aux, (unsigned long long)ns1);
        CHECK(a > prev && b > a, "not increasing at %d", i);
        CHECK(ns0 >= prevns && ns1 > ns0, "clock not increasing at %d", i);
        /* consistent with the virtual clock: the counter reads between the two clock reads */
        CHECK(a / 3 >= ns0 && b / 3 <= ns1, "counter outside the clock interval at %d", i);
        CHECK(aux == 0, "rdtscp aux %u", aux);
        prev = b;
        prevns = ns1;
    }
}

#define RD(insn, width, reg)                                                                  \
    static int insn##width(uint64_t *v) {                                                      \
        uint##width##_t x;                                                                     \
        unsigned char cf;                                                                      \
        __asm__ volatile(#insn " %0; setc %1" : "=" reg(x), "=qm"(cf)::"cc");                  \
        *v = x;                                                                                \
        return cf;                                                                             \
    }
RD(rdrand, 16, "r")
RD(rdrand, 32, "r")
RD(rdrand, 64, "r")
RD(rdseed, 16, "r")
RD(rdseed, 32, "r")
RD(rdseed, 64, "r")

/* An extended register (REX.B) destination, and a 16-bit form that must keep the upper bits. */
static int rdrand_r9(uint64_t *v) {
    uint64_t x;
    unsigned char cf;
    __asm__ volatile("rdrand %%r9; setc %1; mov %%r9, %0" : "=r"(x), "=qm"(cf)::"r9", "cc");
    *v = x;
    return cf;
}
static int rdseed16_keep(uint64_t *v) {
    uint64_t x = 0x1122334455660000ull;
    unsigned char cf;
    __asm__ volatile("rdseed %w0; setc %1" : "+r"(x), "=qm"(cf)::"cc");
    *v = x;
    return cf && (x >> 16) == 0x112233445566ull;
}

static void rnd(void) {
    struct { const char *name; int (*f)(uint64_t *); } t[] = {
        {"rdrand16", rdrand16}, {"rdrand32", rdrand32}, {"rdrand64", rdrand64},
        {"rdseed16", rdseed16}, {"rdseed32", rdseed32}, {"rdseed64", rdseed64},
        {"rdrand-r9", rdrand_r9}, {"rdseed16-keep", rdseed16_keep},
    };
    for (unsigned k = 0; k < sizeof t / sizeof t[0]; k++) {
        int distinct = 0;
        uint64_t last = 0;
        for (int i = 0; i < 100; i++) {
            uint64_t v;
            int cf = t[k].f(&v);
            CHECK(cf, "%s carry clear at %d", t[k].name, i);
            if (i && v != last) distinct++;
            last = v;
            printf("%s %d %llx\n", t[k].name, i, (unsigned long long)v);
        }
        CHECK(distinct > 50, "%s: only %d changes", t[k].name, distinct);
    }
}

static sigjmp_buf jb;
static void on_segv(int s) { siglongjmp(jb, s); }

static void tscsig(void) {
    int mode = -1;
    CHECK(prctl(PR_GET_TSC, &mode) == 0 && mode == PR_TSC_ENABLE, "PR_GET_TSC %d", mode);
    uint64_t a = rdtsc();
    CHECK(prctl(PR_SET_TSC, PR_TSC_SIGSEGV) == 0, "PR_SET_TSC");
    signal(SIGSEGV, on_segv);
    int s = sigsetjmp(jb, 1);
    if (s == 0) {
        (void)rdtsc();
        CHECK(0, "rdtsc did not fault after PR_TSC_SIGSEGV");
    }
    printf("tscsig %llu signal %d\n", (unsigned long long)a, s);
    CHECK(s == SIGSEGV, "signal %d", s);
    CHECK(prctl(PR_SET_TSC, PR_TSC_ENABLE) == 0, "PR_SET_TSC enable");
    CHECK(rdtsc() > a, "rdtsc after re-enable");
}

int main(int argc, char **argv) {
    const char *m = argc > 1 ? argv[1] : "tsc";
    if (!strcmp(m, "tsc")) tsc();
    else if (!strcmp(m, "rand")) rnd();
    else if (!strcmp(m, "tscsig")) tscsig();
    else if (!strcmp(m, "ud2")) { fflush(stdout); __builtin_trap(); }
    else if (!strcmp(m, "loop")) {
        long n = argc > 2 ? atol(argv[2]) : 1000000;
        uint64_t x = 0, t0 = mono();
        for (long i = 0; i < n; i++) x ^= rdtsc();
        uint64_t t1 = mono();
        printf("loop %ld xor %llx clock_ns %llu\n", n, (unsigned long long)x, (unsigned long long)(t1 - t0));
    } else {
        fprintf(stderr, "usage: insn tsc|rand|loop [N]\n");
        return 2;
    }
    printf("%s %s\n", fails ? "FAILED" : "OK", m);
    return fails ? 1 : 0;
}
