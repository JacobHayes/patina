// signals evidence: dump the signal frame a handler receives, field by field, as
// "field value" lines. Addresses are printed relative to something that is the same
// under a native kernel and under patina (the alternate stack, the frame, the interrupted
// stack pointer), so `diff` of a native run and an patina run lists exactly the differences.
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define ALT (64 * 1024)
static char *alt;
static uint8_t snap[8192];
static uintptr_t frame, xstate_end;
static unsigned h_mxcsr;
static unsigned short h_fcw;

static void on_sig(int sig, siginfo_t *si, void *ucv) {
    (void)sig;
    (void)si;
    asm volatile("stmxcsr %0\n fnstcw %1" : "=m"(h_mxcsr), "=m"(h_fcw));
    frame = (uintptr_t)ucv - 8;
    ucontext_t *uc = ucv;
    uintptr_t fp = (uintptr_t)uc->uc_mcontext.fpregs;
    uint32_t ext = *(uint32_t *)(fp + 464 + 4);
    xstate_end = fp + ext;
    size_t n = xstate_end - frame;
    if (n > sizeof snap) n = sizeof snap;
    memcpy(snap, (void *)frame, n);
}

#define U64(off) (*(uint64_t *)(snap + (off)))
#define U32(off) (*(uint32_t *)(snap + (off)))
#define U16(off) (*(uint16_t *)(snap + (off)))

static const char *greg[] = {"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rdi", "rsi", "rbp", "rbx",
                             "rdx", "rax", "rcx", "rsp", "rip", "eflags", "csgsfs", "err", "trapno", "oldmask", "cr2"};

static int all_zero(int off, int n) {
    for (int i = 0; i < n; i++)
        if (snap[off + i]) return 0;
    return 1;
}

static void dump(const char *tag, uintptr_t interrupted_sp_hint, uintptr_t local) {
    uintptr_t uc = 8, mc = uc + 40, fpp = U64(mc + 23 * 8);
    printf("%s frame_mod16 %lu\n", tag, (unsigned long)(frame % 16));
    if (interrupted_sp_hint)
        printf("%s frame_below_alt_top %lu\n", tag, (unsigned long)((uintptr_t)alt + ALT - frame));
    // pretcode: glibc's __restore_rt is "mov $15, %rax; syscall".
    const uint8_t *rt = (const uint8_t *)U64(0);
    printf("%s pretcode_is_restore_rt %d\n", tag, rt[0] == 0x48 && rt[1] == 0xc7 && rt[2] == 0xc0 && rt[3] == 15 && rt[7] == 0x0f && rt[8] == 0x05);
    printf("%s uc_flags %#lx\n", tag, U64(uc + 0));
    printf("%s uc_link %#lx\n", tag, U64(uc + 8));
    printf("%s uc_stack.ss_sp_is_alt %d\n", tag, U64(uc + 16) == (uintptr_t)alt);
    printf("%s uc_stack.ss_flags %#x\n", tag, U32(uc + 24));
    printf("%s uc_stack.pad %#x\n", tag, U32(uc + 28));
    printf("%s uc_stack.ss_size %lu\n", tag, U64(uc + 32));
    uint64_t rsp = U64(mc + 15 * 8), rip = U64(mc + 16 * 8);
    for (int i = 0; i < 23; i++) {
        uint64_t v = U64(mc + i * 8);
        const char *g = greg[i];
        if (!strcmp(g, "rsp"))
            printf("%s mc.rsp_below_main_local %ld\n", tag, (long)(local - v));
        else if (!strcmp(g, "rip"))
            printf("%s mc.rip_after_syscall %d\n", tag, ((uint8_t *)v)[-2] == 0x0f && ((uint8_t *)v)[-1] == 0x05);
        else if (!strcmp(g, "rcx"))
            printf("%s mc.rcx_is_rip %d\n", tag, v == rip);
        else if (!strcmp(g, "rdi"))
            printf("%s mc.rdi_is_pid %d\n", tag, (pid_t)v == getpid());
        else if (!strcmp(g, "rsi"))
            printf("%s mc.rsi_is_tid %d\n", tag, (pid_t)v == (pid_t)syscall(SYS_gettid));
        else if (!strcmp(g, "rbp") || !strcmp(g, "rbx") || !strcmp(g, "r12") || !strcmp(g, "r13") ||
                 !strcmp(g, "r14") || !strcmp(g, "r15") || !strcmp(g, "r8") || !strcmp(g, "r9") || !strcmp(g, "r10"))
            printf("%s mc.%s_set %d\n", tag, g, v != 0); // program state, address-dependent
        else if (!strcmp(g, "eflags") || !strcmp(g, "r11"))
            printf("%s mc.%s %#lx\n", tag, g, v & ~0x10000UL); // RF masked: set by the CPU on some paths
        else
            printf("%s mc.%s %#lx\n", tag, g, v);
    }
    (void)rsp;
    printf("%s mc.fpstate_minus_frame %ld\n", tag, (long)(fpp - frame));
    printf("%s mc.fpstate_mod64 %lu\n", tag, (unsigned long)(fpp % 64));
    printf("%s mc.reserved1_zero %d\n", tag, all_zero(mc + 24 * 8, 64));
    printf("%s uc_sigmask %#lx\n", tag, U64(uc + 296));
    int si = 312;
    printf("%s si.signo %d\n", tag, (int)U32(si));
    printf("%s si.errno %d\n", tag, (int)U32(si + 4));
    printf("%s si.code %d\n", tag, (int)U32(si + 8));
    printf("%s si.pad %#x\n", tag, U32(si + 12));
    printf("%s si.pid_is_self %d\n", tag, (pid_t)U32(si + 16) == getpid());
    printf("%s si.uid %u\n", tag, U32(si + 20));
    printf("%s si.rest_zero %d\n", tag, all_zero(si + 24, 128 - 24));
    printf("%s gap_frame_to_fp_zero_bytes %ld\n", tag, (long)(fpp - frame - 440));
    int f = (int)(fpp - frame);
    printf("%s fp.fcw %#x\n", tag, U16(f + 0));
    printf("%s fp.fsw %#x\n", tag, U16(f + 2));
    printf("%s fp.ftw %#x\n", tag, snap[f + 4]);
    printf("%s fp.mxcsr %#x\n", tag, U32(f + 24));
    printf("%s fp.mxcsr_mask %#x\n", tag, U32(f + 28));
    printf("%s fp.xmm0_lo %#lx\n", tag, U64(f + 160));
    printf("%s fp.legacy_reserved_416_464_zero %d\n", tag, all_zero(f + 416, 48));
    printf("%s fp.sw.magic1 %#x\n", tag, U32(f + 464));
    printf("%s fp.sw.extended_size %u\n", tag, U32(f + 468));
    printf("%s fp.sw.xfeatures %#lx\n", tag, U64(f + 472));
    printf("%s fp.sw.xstate_size %u\n", tag, U32(f + 480));
    printf("%s fp.sw.padding_zero %d\n", tag, all_zero(f + 484, 28));
    printf("%s fp.hdr.xstate_bv %#lx\n", tag, U64(f + 512));
    printf("%s fp.hdr.xcomp_bv %#lx\n", tag, U64(f + 520));
    printf("%s fp.hdr.reserved_zero %d\n", tag, all_zero(f + 528, 48));
    uint32_t xs = U32(f + 480);
    printf("%s fp.magic2 %#x\n", tag, U32(f + xs));
    printf("%s fp.end_minus_frame %ld\n", tag, (long)(xstate_end - frame));
    printf("%s handler.mxcsr %#x\n", tag, h_mxcsr);
    printf("%s handler.fcw %#x\n", tag, h_fcw);
}

int main(void) {
    alt = aligned_alloc(4096, ALT);
    stack_t ss = {.ss_sp = alt, .ss_size = ALT, .ss_flags = 0};
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sig;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR2);
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR2, &sa, NULL);
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGTERM);
    sigprocmask(SIG_BLOCK, &m, NULL);

    // Non-default FP control state in the interrupted code: the handler must start clean.
    unsigned mx = 0x1f80 | 0x2000;
    unsigned short cw = 0x27f;
    asm volatile("ldmxcsr %0\n fldcw %1" ::"m"(mx), "m"(cw));
    asm volatile("vpcmpeqd %%ymm0, %%ymm0, %%ymm0" ::: "xmm0"); // ymm0 all ones: AVX in use
    char here;
    raise(SIGUSR1);
    unsigned mx2;
    asm volatile("stmxcsr %0" : "=m"(mx2));
    dump("onstack", 1, (uintptr_t)&here);
    printf("onstack after.mxcsr_restored %d\n", mx2 == mx);

    raise(SIGUSR2);
    dump("plain", 0, (uintptr_t)&here);
    printf("plain frame_below_local %ld\n", (long)((uintptr_t)&here - frame) / 1024);
    return 0;
}
