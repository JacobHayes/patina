// signals item 3: FP state across signal delivery. Thread A keeps values in all sixteen YMM
// registers, x87 and a non-default MXCSR across a syscall (getppid, in one asm block),
// and accumulates a double/AVX computation between syscalls; thread B signals A 10,000
// times; A's handler clobbers YMM, x87 and MXCSR. Everything must come back exact.
// Then: a handler that edits its ucontext (rax, and rip past a ud2) takes effect.
// Build with -mavx2.
#define _GNU_SOURCE
#include <immintrin.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define N 10000
static volatile int handled;
static volatile pid_t tid_a;
static volatile int a_ready, b_done;

static void clobber(int sig) {
    (void)sig;
    // Handler-side FP work with different values and rounding.
    _mm_setcsr((_mm_getcsr() & ~0x6000) | 0x4000); // round up
    __m256d x = _mm256_set1_pd(3.14159);
    for (int i = 0; i < 8; i++) x = _mm256_mul_pd(x, x);
    asm volatile("vxorpd %%ymm0, %%ymm0, %%ymm0\n vxorpd %%ymm7, %%ymm7, %%ymm7\n vxorpd %%ymm15, %%ymm15, %%ymm15\n"
                 "fldpi\n fldpi\n faddp\n fstp %%st(0)\n" ::: "xmm0", "xmm7", "xmm15", "st");
    volatile double sink = x[0] + x[3];
    (void)sink;
    handled++;
}

// Fill ymm0..15 from `in`, make a getppid syscall, store ymm0..15 to `out`.
static void regs_across_syscall(const double *in, double *out) {
    asm volatile(
        "vmovupd 0(%0), %%ymm0\n vmovupd 32(%0), %%ymm1\n vmovupd 64(%0), %%ymm2\n vmovupd 96(%0), %%ymm3\n"
        "vmovupd 128(%0), %%ymm4\n vmovupd 160(%0), %%ymm5\n vmovupd 192(%0), %%ymm6\n vmovupd 224(%0), %%ymm7\n"
        "vmovupd 256(%0), %%ymm8\n vmovupd 288(%0), %%ymm9\n vmovupd 320(%0), %%ymm10\n vmovupd 352(%0), %%ymm11\n"
        "vmovupd 384(%0), %%ymm12\n vmovupd 416(%0), %%ymm13\n vmovupd 448(%0), %%ymm14\n vmovupd 480(%0), %%ymm15\n"
        "mov $110, %%eax\n syscall\n"
        "vmovupd %%ymm0, 0(%1)\n vmovupd %%ymm1, 32(%1)\n vmovupd %%ymm2, 64(%1)\n vmovupd %%ymm3, 96(%1)\n"
        "vmovupd %%ymm4, 128(%1)\n vmovupd %%ymm5, 160(%1)\n vmovupd %%ymm6, 192(%1)\n vmovupd %%ymm7, 224(%1)\n"
        "vmovupd %%ymm8, 256(%1)\n vmovupd %%ymm9, 288(%1)\n vmovupd %%ymm10, 320(%1)\n vmovupd %%ymm11, 352(%1)\n"
        "vmovupd %%ymm12, 384(%1)\n vmovupd %%ymm13, 416(%1)\n vmovupd %%ymm14, 448(%1)\n vmovupd %%ymm15, 480(%1)\n"
        :
        : "r"(in), "r"(out)
        : "rax", "rcx", "r11", "memory", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
          "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
}

// The computation: a long dependent chain in doubles and AVX lanes, one syscall per step.
static double compute(int steps, int *reg_errors, int with_syscalls) {
    double in[64], out[64];
    __m256d acc = _mm256_set_pd(1.0, 1.5, 2.0, 2.5);
    const __m256d k = _mm256_set1_pd(1.0000001);
    double s = 0.1;
    long double ld = 1.0L;
    for (int i = 0; i < steps; i++) {
        for (int j = 0; j < 64; j++) in[j] = i * 64.0 + j + 0.25;
        if (with_syscalls) {
            regs_across_syscall(in, out);
            if (memcmp(in, out, sizeof in)) (*reg_errors)++;
        }
        acc = _mm256_add_pd(_mm256_mul_pd(acc, k), _mm256_set1_pd(s));
        s = s * 1.0000003 + 1e-9;
        ld = ld * 1.0000001L + 1e-12L;
        // MXCSR set to round-down by the caller must survive.
        if ((_mm_getcsr() & 0x6000) != 0x2000) (*reg_errors)++;
    }
    return acc[0] + acc[1] + acc[2] + acc[3] + s + (double)ld;
}

static double result_a;
static int errors_a;

static void *thread_a(void *arg) {
    (void)arg;
    tid_a = (pid_t)syscall(SYS_gettid);
    _mm_setcsr((_mm_getcsr() & ~0x6000) | 0x2000); // round down
    a_ready = 1;
    result_a = compute(N * 3, &errors_a, 1);
    while (!b_done) syscall(SYS_getppid);
    return NULL;
}

static void *thread_b(void *arg) {
    (void)arg;
    while (!a_ready) sched_yield();
    for (int i = 0; i < N; i++) {
        int h = handled;
        syscall(SYS_tgkill, getpid(), tid_a, SIGUSR1);
        while (handled == h) sched_yield();
    }
    b_done = 1;
    return NULL;
}

// ucontext editing: the handler sets rax and skips the two-byte ud2 after the syscall.
static void on_edit(int sig, siginfo_t *si, void *ucv) {
    (void)sig;
    (void)si;
    ucontext_t *uc = ucv;
    uc->uc_mcontext.gregs[REG_RAX] = 4242;
    uc->uc_mcontext.gregs[REG_RIP] += 2;
}

int main(void) {
    // Reference value: same computation, same rounding, no signals, no syscalls.
    unsigned csr = _mm_getcsr();
    _mm_setcsr((csr & ~0x6000) | 0x2000);
    int e0 = 0;
    double ref = compute(N * 3, &e0, 0);
    _mm_setcsr(csr);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = clobber;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
    pthread_t a, b;
    pthread_create(&a, NULL, thread_a, NULL);
    pthread_create(&b, NULL, thread_b, NULL);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    printf("fp handled=%d reg_errors=%d exact=%d\n", handled, errors_a, memcmp(&ref, &result_a, sizeof ref) == 0);

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_edit;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR2, &sa, NULL);
    long r;
    pid_t pid = getpid(), tid = (pid_t)syscall(SYS_gettid);
    asm volatile("mov %1, %%rdi\n mov %2, %%rsi\n mov %3, %%rdx\n mov $234, %%eax\n syscall\n ud2\n mov %%rax, %0\n"
                 : "=r"(r)
                 : "r"((long)pid), "r"((long)tid), "r"((long)SIGUSR2)
                 : "rax", "rcx", "rdx", "rsi", "rdi", "r11", "memory");
    printf("ucontext rax=%ld\n", r);
    return 0;
}
