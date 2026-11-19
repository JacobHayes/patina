// Signal frames the kernel cannot use. Each case ends in the SIGSEGV the kernel gives; its
// handler (on the alternate stack) prints what it got: the code, whether si_addr and the saved
// stack pointer are the case's pointer, the saved return register (rax, x0).
//   rt    rt_sigreturn with the stack pointer where the runtime lives (unmapped for the program)
//   top   rt_sigreturn with the stack pointer above every mapping
//   mis   rt_sigreturn with a stack pointer not 16-byte aligned (arm64; x86_64 has no such rule)
//   fp    a handler points its frame's FP state at unmapped memory and returns (x86_64)
//   mxcsr a handler sets a reserved MXCSR bit in its frame and returns (x86_64)
//   xhdr  a handler sets an XSAVE header bit no host enables (bit 62) and returns (x86_64)
//   ro    a signal arrives while the stack pointer is in read-only memory: no frame can be written
//   nores a handler installed without SA_RESTORER (x86_64 refuses to deliver to it; arm64 uses
//         its default restorer, and the handler returns)
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define RT 0x600000001000ul
#define TOP 0x7ffffffff000ul

static uint64_t want_sp;
static const char *mode;

#ifdef __x86_64__
#define SP(uc) ((uint64_t)(uc)->uc_mcontext.gregs[REG_RSP])
#define RET(uc) ((unsigned long)(uc)->uc_mcontext.gregs[REG_RAX])
#else
#define SP(uc) ((uint64_t)(uc)->uc_mcontext.sp)
#define RET(uc) ((unsigned long)(uc)->uc_mcontext.regs[0])
#endif

static void on_segv(int sig, siginfo_t *si, void *ucv) {
    ucontext_t *uc = ucv;
    printf("sig=%d code=%d addr_is_sp=%d ret=%lu sp_kept=%d\n", sig, si->si_code, (uint64_t)si->si_addr == want_sp,
           RET(uc), SP(uc) == want_sp);
    fflush(stdout);
    _exit(0);
}

static void on_usr1(int sig, siginfo_t *si, void *ucv) {
    (void)sig, (void)si;
#ifdef __x86_64__
    ucontext_t *uc = ucv;
    uint8_t *fp = (uint8_t *)uc->uc_mcontext.fpregs;
    if (!strcmp(mode, "fp"))
        uc->uc_mcontext.fpregs = (void *)0x1000; // below every mapping
    else if (!strcmp(mode, "mxcsr"))
        *(uint32_t *)(fp + 24) |= 1u << 31;
    else if (!strcmp(mode, "xhdr"))
        *(uint64_t *)(fp + 512) |= 1ull << 62;
#else
    (void)ucv;
#endif
    if (write(1, "usr1 handled\n", 13) != 13)
        _exit(5);
}

// rt_sigreturn on the stack pointer `sp`.
static void sigreturn_on(uint64_t sp) {
#ifdef __x86_64__
    asm volatile("mov %%rsp, %%r12\n mov %0, %%rsp\n mov $15, %%eax\n syscall\n mov %%r12, %%rsp" ::"r"(sp)
                 : "rax", "rcx", "r11", "r12", "memory");
#else
    asm volatile("mov x9, sp\n mov sp, %0\n mov x0, #77\n mov x8, #139\n svc #0\n mov sp, x9" ::"r"(sp)
                 : "x0", "x8", "x9", "memory");
#endif
}

// kill(getpid(), SIGUSR1) with the stack pointer at `sp`.
static void kill_on(uint64_t sp, long pid) {
#ifdef __x86_64__
    asm volatile("mov %%rsp, %%r12\n mov %0, %%rsp\n mov %1, %%rdi\n mov $10, %%esi\n mov $62, %%eax\n syscall\n"
                 "mov %%r12, %%rsp" ::"r"(sp),
                 "r"(pid)
                 : "rax", "rcx", "rdi", "rsi", "r11", "r12", "memory");
#else
    asm volatile("mov x9, sp\n mov sp, %0\n mov x0, %1\n mov x1, #10\n mov x8, #129\n svc #0\n mov sp, x9" ::"r"(sp),
                 "r"(pid)
                 : "x0", "x1", "x8", "x9", "memory");
#endif
}

// The kernel's `struct sigaction` (the same layout on x86_64 and arm64).
struct ksigaction {
    void *handler;
    unsigned long flags;
    void *restorer;
    uint64_t mask;
};

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    stack_t ss = {.ss_sp = malloc(65536), .ss_size = 65536};
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction(SIGSEGV, &sa, NULL);
    sa.sa_sigaction = on_usr1;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);
    const char *m = mode = argv[1];
    if (!strcmp(m, "rt") || !strcmp(m, "top") || !strcmp(m, "mis")) {
        uint64_t sp;
        if (!strcmp(m, "rt")) {
            sp = RT;
        } else if (!strcmp(m, "top")) {
            sp = TOP;
        } else {
            sp = (uint64_t)__builtin_frame_address(0) - 4104;
        }
        want_sp = sp;
        sigreturn_on(sp);
    } else if (!strcmp(m, "fp") || !strcmp(m, "mxcsr") || !strcmp(m, "xhdr")) {
        syscall(SYS_kill, getpid(), SIGUSR1);
    } else if (!strcmp(m, "ro")) {
        size_t n = 1 << 16;
        char *p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED || mprotect(p, n, PROT_READ))
            return 3;
        want_sp = (uint64_t)p + n;
        kill_on(want_sp, getpid());
    } else if (!strcmp(m, "nores")) {
        struct ksigaction k = {.handler = (void *)on_usr1, .flags = SA_SIGINFO};
        if (syscall(SYS_rt_sigaction, SIGUSR1, &k, NULL, 8))
            return 4;
        syscall(SYS_kill, getpid(), SIGUSR1);
        printf("returned\n");
        return 0;
    } else {
        return 2;
    }
    printf("returned\n");
    return 1;
}
