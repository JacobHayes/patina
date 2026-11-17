/* Instruction channels, arm64 (the twin of insn.c, built as `insn` on arm64).
 * insn tsc: CNTVCT_EL0 (and CNTVCTSS_EL0 where the CPU has it) 1,000 times each, interleaved
 *   with clock_gettime: the values strictly increase and lie between the clock reads (one tick
 *   per ns, CNTFRQ_EL0 = 1e9); then two reads around a 1 ms sleep differ by at least 1e6.
 * insn rand: RNDR and RNDRRS into several registers, 100 times each, when the auxiliary vector
 *   advertises them (HWCAP2_RNG): the flags say success and the values change; otherwise prints
 *   "no-rng".
 * insn litpool: a literal-pool word in .text equal to the `yield` encoding, read by `ldr`:
 *   must read as that word (data in text is not patched).
 * insn ud2: the guest's own `udf #0` (must die of SIGILL). insn udf7061: the guest's own
 *   `udf #0x7061`, the patch's encoding at an address the runtime never patched (must die of
 *   SIGILL). insn cntpct: CNTPCT_EL0, not readable at EL0 (must die of SIGILL).
 * insn tscsig: a child asks for PR_TSC_SIGSEGV itself and must die of SIGSEGV at its next
 *   counter read; the parent checks the wait status.
 * insn mte: PR_SET_TAGGED_ADDR_CTRL must be refused.
 * insn loop N: N counter reads in a tight loop (the cost per read). */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define HWCAP2_RNG_BIT (1UL << 16)
#define HWCAP2_ECV_BIT (1UL << 19)

static inline uint64_t cntvct(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}
static inline uint64_t cntvctss(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, s3_3_c14_c0_6" : "=r"(v));
    return v;
}
static inline uint64_t cntfrq(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
    return v;
}
static uint64_t mono(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL " __VA_ARGS__); printf("\n"); } } while (0)

static void tsc(void) {
    int ss = (getauxval(AT_HWCAP2) & HWCAP2_ECV_BIT) != 0;
    uint64_t prev = 0, prevns = 0, f = cntfrq();
    printf("cntfrq %llu cntvctss %s\n", (unsigned long long)f, ss ? "yes" : "no");
    CHECK(f == 1000000000ull, "cntfrq %llu", (unsigned long long)f);
    for (int i = 0; i < 1000; i++) {
        uint64_t ns0 = mono();
        uint64_t a = cntvct();
        uint64_t b = ss ? cntvctss() : cntvct();
        uint64_t ns1 = mono();
        printf("%d %llu %llu %llu\n", i, (unsigned long long)a, (unsigned long long)b, (unsigned long long)ns1);
        CHECK(a > prev && b > a, "not increasing at %d", i);
        CHECK(ns0 >= prevns && ns1 > ns0, "clock not increasing at %d", i);
        /* consistent with the virtual clock: the counter reads between the two clock reads */
        CHECK(a >= ns0 && b <= ns1, "counter outside the clock interval at %d", i);
        prev = b;
        prevns = ns1;
    }
    uint64_t a = cntvct();
    struct timespec ms = {0, 1000000};
    nanosleep(&ms, 0);
    uint64_t b = cntvct();
    printf("sleep 1ms: %llu\n", (unsigned long long)(b - a));
    CHECK(b - a >= 1000000, "a 1 ms sleep moved the counter %llu", (unsigned long long)(b - a));
}

/* RNDR into x0 / x9 / x30 (the link register is saved around it), RNDRRS into x3; each returns
 * the value and whether NZCV said success (Z clear). */
#define RD(name, sysreg, reg)                                                              \
    static int name(uint64_t *v) {                                                         \
        uint64_t x, ok;                                                                    \
        __asm__ volatile("mrs " reg ", " sysreg "\n\tcset %1, ne\n\tmov %0, " reg          \
                         : "=r"(x), "=r"(ok)::reg, "cc");                                  \
        *v = x;                                                                            \
        return (int)ok;                                                                    \
    }
RD(rndr_x0, "s3_3_c2_c4_0", "x0")
RD(rndr_x9, "s3_3_c2_c4_0", "x9")
RD(rndr_x30, "s3_3_c2_c4_0", "x30")
RD(rndrrs_x3, "s3_3_c2_c4_1", "x3")

static void rnd(void) {
    if (!(getauxval(AT_HWCAP2) & HWCAP2_RNG_BIT)) {
        printf("no-rng\n");
        return;
    }
    struct { const char *name; int (*f)(uint64_t *); } t[] = {
        {"rndr-x0", rndr_x0}, {"rndr-x9", rndr_x9}, {"rndr-x30", rndr_x30}, {"rndrrs-x3", rndrrs_x3},
    };
    for (unsigned k = 0; k < sizeof t / sizeof t[0]; k++) {
        int distinct = 0;
        uint64_t last = 0;
        for (int i = 0; i < 100; i++) {
            uint64_t v;
            int ok = t[k].f(&v);
            CHECK(ok, "%s NZCV says failure at %d", t[k].name, i);
            if (i && v != last) distinct++;
            last = v;
            printf("%s %d %llx\n", t[k].name, i, (unsigned long long)v);
        }
        CHECK(distinct > 50, "%s: only %d changes", t[k].name, distinct);
    }
}

static void litpool(void) {
    uint32_t w;
    __asm__ volatile("ldr %w0, 1f\n\tb 2f\n\t.balign 4\n1:\t.word 0xd503203f\n2:" : "=r"(w));
    printf("litpool %08x\n", w);
    CHECK(w == 0xd503203f, "the literal reads %08x", w);
}

static void tscsig(void) {
    int mode = -1;
    CHECK(prctl(PR_GET_TSC, &mode) == 0 && mode == PR_TSC_ENABLE, "PR_GET_TSC %d", mode);
    uint64_t a = cntvct();
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        if (prctl(PR_SET_TSC, PR_TSC_SIGSEGV) != 0) _exit(3);
        (void)cntvct();
        _exit(4);
    }
    int st = 0;
    CHECK(waitpid(p, &st, 0) == p, "waitpid");
    printf("tscsig %llu child status %#x\n", (unsigned long long)a, st);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == 11, "child status %#x", st);
    CHECK(cntvct() > a, "counter after the child");
}

static void mte(void) {
    /* PR_SET_TAGGED_ADDR_CTRL(PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC | tags 1..15) */
    errno = 0;
    int r = prctl(55, 1UL | (1UL << 1) | (0xfffeUL << 3), 0, 0, 0);
    printf("mte prctl %d errno %d\n", r, errno);
    CHECK(r == -1 && errno == EINVAL, "PR_SET_TAGGED_ADDR_CTRL was not refused");
}

int main(int argc, char **argv) {
    const char *m = argc > 1 ? argv[1] : "tsc";
    if (!strcmp(m, "tsc")) tsc();
    else if (!strcmp(m, "rand")) rnd();
    else if (!strcmp(m, "litpool")) litpool();
    else if (!strcmp(m, "tscsig")) tscsig();
    else if (!strcmp(m, "mte")) mte();
    else if (!strcmp(m, "ud2")) { fflush(stdout); __asm__ volatile("udf #0"); }
    else if (!strcmp(m, "udf7061")) { fflush(stdout); __asm__ volatile("udf #0x7061"); }
    else if (!strcmp(m, "cntpct")) {
        uint64_t v;
        fflush(stdout);
        __asm__ volatile("mrs %0, cntpct_el0" : "=r"(v));
        printf("cntpct %llu\n", (unsigned long long)v);
    } else if (!strcmp(m, "loop")) {
        long n = argc > 2 ? atol(argv[2]) : 1000000;
        uint64_t x = 0, t0 = mono();
        for (long i = 0; i < n; i++) x ^= cntvct();
        uint64_t t1 = mono();
        printf("loop %ld xor %llx clock_ns %llu\n", n, (unsigned long long)x, (unsigned long long)(t1 - t0));
    } else {
        fprintf(stderr, "usage: insn tsc|rand|litpool|tscsig|mte|ud2|udf7061|cntpct|loop [N]\n");
        return 2;
    }
    printf("%s %s\n", fails ? "FAILED" : "OK", m);
    return fails ? 1 : 0;
}
