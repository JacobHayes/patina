// arm64 twin of sig-fp.c (built as sig-fp there). FP/SIMD state across signal delivery: the
// program keeps values in all 32 vector registers across a system call that signals itself
// (tgkill, in one asm block), with a non-default FPCR, and accumulates a double computation
// between calls, 10,000 times; the handler clobbers the vector registers and FPCR. Everything
// must come back exact. Then a handler edits its ucontext and the edits take effect: x0, pc
// (past a udf), a vector register, the signal mask; and, on a host with SVE, a P register
// (in the full SVE record of a fault taken with SVE state live).
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define N 10000
#define FPCR_RP (1u << 22) // round towards +infinity
static volatile int handled;

static void clobber(int sig) {
    (void)sig;
    // Handler-side FP work with other values and rounding.
    uint64_t c = 3u << 22; // round towards zero
    asm volatile("msr fpcr, %0" ::"r"(c));
    volatile double x = 3.14159;
    for (int i = 0; i < 8; i++) x = x * x;
    asm volatile("movi v0.16b, #0\n movi v7.16b, #0x77\n movi v8.16b, #0x88\n movi v15.16b, #0xff\n"
                 "movi v16.16b, #0x16\n movi v31.16b, #0x31" ::: "v0", "v7", "v8", "v15", "v16", "v31");
    handled++;
}

// Fill v0..v31 from `in`, tgkill(self, SIGUSR1), store v0..v31 to `out`.
static void regs_across_signal(const double *in, double *out, long pid, long tid) {
    asm volatile("ld1 {v0.2d-v3.2d}, [%0], #64\n ld1 {v4.2d-v7.2d}, [%0], #64\n"
                 "ld1 {v8.2d-v11.2d}, [%0], #64\n ld1 {v12.2d-v15.2d}, [%0], #64\n"
                 "ld1 {v16.2d-v19.2d}, [%0], #64\n ld1 {v20.2d-v23.2d}, [%0], #64\n"
                 "ld1 {v24.2d-v27.2d}, [%0], #64\n ld1 {v28.2d-v31.2d}, [%0], #64\n"
                 "mov x0, %2\n mov x1, %3\n mov x2, #10\n mov x8, #131\n svc #0\n"
                 "st1 {v0.2d-v3.2d}, [%1], #64\n st1 {v4.2d-v7.2d}, [%1], #64\n"
                 "st1 {v8.2d-v11.2d}, [%1], #64\n st1 {v12.2d-v15.2d}, [%1], #64\n"
                 "st1 {v16.2d-v19.2d}, [%1], #64\n st1 {v20.2d-v23.2d}, [%1], #64\n"
                 "st1 {v24.2d-v27.2d}, [%1], #64\n st1 {v28.2d-v31.2d}, [%1], #64\n"
                 : "+r"(in), "+r"(out)
                 : "r"(pid), "r"(tid)
                 : "x0", "x1", "x2", "x8", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9",
                   "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
                   "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31");
}

static uint64_t fpcr(void) {
    uint64_t v;
    asm volatile("mrs %0, fpcr" : "=r"(v));
    return v;
}

// The computation: a long dependent chain in doubles, one signal per step.
static double compute(int steps, int *reg_errors, int with_signals) {
    double in[64], out[64];
    double s = 0.1, acc = 1.5;
    long pid = getpid(), tid = syscall(SYS_gettid);
    for (int i = 0; i < steps; i++) {
        for (int j = 0; j < 64; j++) in[j] = i * 64.0 + j + 0.25;
        if (with_signals) {
            regs_across_signal(in, out, pid, tid);
            if (memcmp(in, out, sizeof in)) (*reg_errors)++;
        }
        acc = acc * 1.0000001 + s;
        s = s * 1.0000003 + 1e-9;
        // FPCR set to round-up by the caller must survive.
        if ((fpcr() & (3u << 22)) != FPCR_RP) (*reg_errors)++;
    }
    return acc + s;
}

static volatile uint64_t sve_p0_pattern;

// The ucontext edits: x0, pc past the udf, v31 (in the FP/SIMD record), the mask; for SIGILL
// with a full SVE record, p0.
static void on_edit(int sig, siginfo_t *si, void *ucv) {
    (void)si;
    ucontext_t *uc = ucv;
    uc->uc_mcontext.pc += 4;
    uint8_t *rec = uc->uc_mcontext.__reserved;
    for (int off = 0; off < 4096;) {
        uint32_t magic = *(uint32_t *)(rec + off), size = *(uint32_t *)(rec + off + 4);
        if (magic == 0 || size < 8) break;
        if (sig == SIGUSR2 && magic == 0x46508001) { // FPSIMD: v31
            memset(rec + off + 16 + 31 * 16, 0x5a, 16);
        }
        if (sig == SIGILL && magic == 0x53564501 && size > 16) { // SVE, full form: p0
            int vq = *(uint16_t *)(rec + off + 8) / 16;
            memset(rec + off + 16 + 32 * 16 * vq, 0x11, 2 * vq);
            sve_p0_pattern = 1;
        }
        off += size;
    }
    if (sig == SIGUSR2) {
        uc->uc_mcontext.regs[0] = 4242;
        sigaddset(&uc->uc_sigmask, SIGHUP);
    }
}

int main(void) {
    // Reference value: same computation, same rounding, no signals.
    uint64_t c0 = fpcr();
    asm volatile("msr fpcr, %0" ::"r"((uint64_t)FPCR_RP));
    int e0 = 0;
    double ref = compute(N, &e0, 0);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = clobber;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
    int errors = 0;
    double res = compute(N, &errors, 1);
    asm volatile("msr fpcr, %0" ::"r"(c0));
    printf("fp handled=%d reg_errors=%d exact=%d\n", handled, errors, memcmp(&ref, &res, sizeof ref) == 0);

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_edit;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    long r;
    uint8_t v31[16];
    long pid = getpid(), tid = syscall(SYS_gettid);
    asm volatile("movi v31.16b, #0\n mov x0, %2\n mov x1, %3\n mov x2, #12\n mov x8, #131\n svc #0\n udf #0\n"
                 "mov %0, x0\n st1 {v31.16b}, [%1]\n"
                 : "=&r"(r)
                 : "r"(v31), "r"(pid), "r"(tid)
                 : "x0", "x1", "x2", "x8", "v31", "memory");
    sigset_t m;
    sigprocmask(SIG_SETMASK, NULL, &m);
    int v_ok = 1;
    for (int i = 0; i < 16; i++) v_ok &= v31[i] == 0x5a;
    printf("ucontext x0=%ld v31_edited=%d mask_edited=%d\n", r, v_ok, sigismember(&m, SIGHUP));

    if (getauxval(AT_HWCAP) & HWCAP_SVE) {
        // SVE state live (p0 all true, then a fault): the handler sets p0 to 0x11 per byte.
        uint8_t p0[256 / 8];
        uint64_t vl;
        asm volatile(".arch_extension sve\n rdvl %0, #1" : "=r"(vl));
        asm volatile(".arch_extension sve\n ptrue p0.b\n udf #0\n str p0, [%0]" ::"r"(p0) : "p0", "memory");
        int p_ok = sve_p0_pattern == 1;
        for (unsigned i = 0; i < vl / 8; i++) p_ok &= p0[i] == 0x11;
        printf("sve p0_edited=%d\n", p_ok);
    } else {
        printf("sve p0_edited=no-sve\n");
    }
    return 0;
}
