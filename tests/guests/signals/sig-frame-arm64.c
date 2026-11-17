// signals evidence, arm64 twin of sig-frame.c (built as sig-frame there): dump the signal frame
// a handler receives, field by field, as "field value" lines. Addresses are printed relative
// to something that is the same under a native kernel and under patina (the alternate stack,
// the frame, the interrupted stack pointer), so `diff` of a native run and a patina run lists
// exactly the differences. The handler's entry registers are caught by an assembly stub.
// Cases: a signal raised on the alternate stack and on the thread's stack; one raised after
// system calls failed with EFAULT (a write the kernel refuses, a clock read whose answer the
// runtime copies) and a counter-timer read (natively none leaves fault information; under
// patina the copy and the read are faults of the runtime's own); a load fault last (after it
// the kernel keeps the thread's fault code). On a host with SVE, also a signal raised by a
// call made with SVE state live (the kernel discards it at the call: the header form).
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#define ALT (64 * 1024)
#define FRAME 4688 // siginfo + ucontext
static char *alt;
static uint8_t snap[FRAME + 16];
// Entry registers: x0, x1, x2, x29, x30, sp, fpcr.
uint64_t sig_entry_regs[7];
static uint64_t frame;

extern char fault_insn[];

void on_sig(int sig, siginfo_t *si, void *ucv) {
    (void)si;
    frame = sig_entry_regs[5];
    memcpy(snap, (void *)frame, sizeof snap);
    if (sig == SIGSEGV) ((ucontext_t *)ucv)->uc_mcontext.pc += 4; // past the faulting load
}

void entry_stub(int, siginfo_t *, void *);
asm(".text\n.p2align 2\n.globl entry_stub\n.type entry_stub, %function\nentry_stub:\n"
    "  adrp x16, sig_entry_regs\n  add x16, x16, :lo12:sig_entry_regs\n"
    "  stp x0, x1, [x16]\n  stp x2, x29, [x16, #16]\n  mov x17, sp\n  stp x30, x17, [x16, #32]\n"
    "  mrs x17, fpcr\n  str x17, [x16, #48]\n"
    "  b on_sig\n");

#define U64(off) (*(uint64_t *)(snap + (off)))
#define U32(off) (*(uint32_t *)(snap + (off)))
#define U16(off) (*(uint16_t *)(snap + (off)))

static int all_zero(int off, int n) {
    for (int i = 0; i < n; i++)
        if (snap[off + i]) return 0;
    return 1;
}

static const char *rec_name(uint32_t m) {
    switch (m) {
    case 0x46508001: return "fpsimd";
    case 0x45535201: return "esr";
    case 0x53564501: return "sve";
    case 0x54504902: return "tpidr2";
    case 0x54366345: return "za";
    case 0x5a544e01: return "zt";
    case 0x46504d52: return "fpmr";
    case 0x504f4530: return "poe";
    case 0x47435300: return "gcs";
    case 0x45585401: return "extra";
    default: return "unknown";
    }
}

static uint64_t fpcr_set;

// fault: the frame of the load fault (registers are the program's own, printed as set or not).
static void dump(const char *tag, int onstack, uintptr_t local, int fault) {
    const int uc = 128, mc = uc + 176, rec = uc + 464;
    printf("%s frame_mod16 %lu\n", tag, (unsigned long)(frame % 16));
    if (onstack) printf("%s frame_below_alt_top %lu\n", tag, (unsigned long)((uintptr_t)alt + ALT - frame));
    // Handler entry.
    const uint32_t *rt = (const uint32_t *)sig_entry_regs[4];
    printf("%s entry.x0 %lu\n", tag, sig_entry_regs[0]);
    printf("%s entry.x1_is_info %d\n", tag, sig_entry_regs[1] == frame);
    printf("%s entry.x2_is_uc %d\n", tag, sig_entry_regs[2] == frame + uc);
    printf("%s entry.x29_is_record %d\n", tag, sig_entry_regs[3] == frame + FRAME);
    printf("%s entry.x30_is_sigreturn %d\n", tag, rt[0] == 0xd2801168 && rt[1] == 0xd4000001);
    printf("%s entry.fpcr_kept %d\n", tag, sig_entry_regs[6] == fpcr_set);
    // siginfo
    printf("%s si.signo %d\n", tag, (int)U32(0));
    printf("%s si.errno %d\n", tag, (int)U32(4));
    printf("%s si.code %d\n", tag, (int)U32(8));
    printf("%s si.pad %#x\n", tag, U32(12));
    printf("%s si.pid_is_self %d\n", tag, (pid_t)U32(16) == getpid());
    printf("%s si.uid %u\n", tag, U32(20));
    printf("%s si.rest_zero %d\n", tag, all_zero(24, 128 - 24));
    // ucontext
    printf("%s uc_flags %#lx\n", tag, U64(uc + 0));
    printf("%s uc_link %#lx\n", tag, U64(uc + 8));
    printf("%s uc_stack.ss_sp_is_alt %d\n", tag, U64(uc + 16) == (uintptr_t)alt);
    printf("%s uc_stack.ss_flags %#x\n", tag, U32(uc + 24));
    printf("%s uc_stack.pad %#x\n", tag, U32(uc + 28));
    printf("%s uc_stack.ss_size %lu\n", tag, U64(uc + 32));
    printf("%s uc_sigmask %#lx\n", tag, U64(uc + 40));
    printf("%s uc.unused_zero %d\n", tag, all_zero(uc + 48, 128));
    // mcontext: the registers of the interrupted tgkill (raise).
    printf("%s mc.fault_address %#lx\n", tag, U64(mc));
    uint64_t sp = U64(mc + 8 + 31 * 8), pc = U64(mc + 8 + 32 * 8);
    for (int i = 0; i < 31; i++) {
        uint64_t v = U64(mc + 8 + i * 8);
        if (fault)
            printf("%s mc.x%d_set %d\n", tag, i, v != 0);
        else if (i == 0 || i == 2 || i == 8)
            printf("%s mc.x%d %#lx\n", tag, i, v);
        else if (i == 1)
            printf("%s mc.x1_is_tid %d\n", tag, (pid_t)v == (pid_t)syscall(SYS_gettid));
        else if (i == 29)
            printf("%s mc.x29_is_record_fp %d\n", tag, v == U64(FRAME));
        else if (i == 30)
            printf("%s mc.x30_is_record_lr %d\n", tag, v == U64(FRAME + 8));
        else
            printf("%s mc.x%d_set %d\n", tag, i, v != 0); // program state, address-dependent
    }
    printf("%s mc.sp_below_main_local %ld\n", tag, (long)(local - sp));
    if (fault)
        printf("%s mc.pc_is_fault_insn %d\n", tag, pc == (uintptr_t)fault_insn);
    else
        printf("%s mc.pc_after_svc %d\n", tag, ((uint32_t *)pc)[-1] == 0xd4000001);
    printf("%s mc.pstate %#lx\n", tag, U64(mc + 8 + 33 * 8));
    printf("%s mc.pad_zero %d\n", tag, all_zero(mc + 8 + 34 * 8, 8));
    // Context records.
    char order[256] = "";
    int off = 0, end = -1;
    while (off + 8 <= 4096) {
        uint32_t m = U32(rec + off), size = U32(rec + off + 4);
        if (m == 0) {
            end = off;
            break;
        }
        if (size < 8 || off + size > 4096) break;
        strcat(order, rec_name(m));
        strcat(order, ",");
        int r = rec + off;
        const char *n = rec_name(m);
        printf("%s rec.%s.size %u\n", tag, n, size);
        if (m == 0x46508001) {
            printf("%s rec.fpsimd.fpsr %#x\n", tag, U32(r + 8));
            printf("%s rec.fpsimd.fpcr_kept %d\n", tag, U32(r + 12) == fpcr_set);
            printf("%s rec.fpsimd.v8 %#lx\n", tag, U64(r + 16 + 8 * 16));
            printf("%s rec.fpsimd.v9 %#lx\n", tag, U64(r + 16 + 9 * 16));
        } else if (m == 0x45535201) {
            printf("%s rec.esr.esr %#lx\n", tag, U64(r + 8));
        } else if (m == 0x53564501 || m == 0x54366345) {
            printf("%s rec.%s.vl %u\n", tag, n, U16(r + 8));
            printf("%s rec.%s.flags %#x\n", tag, n, U16(r + 10));
            printf("%s rec.%s.reserved_zero %d\n", tag, n, all_zero(r + 12, 4));
            if (m == 0x53564501 && size > 16) {
                // The full form: is anything beyond the FP/SIMD registers set?
                int vq = U16(r + 8) / 16, beyond = 0;
                for (int z = 0; z < 32; z++)
                    beyond |= !all_zero(r + 16 + z * 16 * vq + 16, 16 * vq - 16);
                beyond |= !all_zero(r + 16 + 32 * 16 * vq, 34 * vq);
                printf("%s rec.sve.beyond_fpsimd %d\n", tag, beyond);
            }
        } else if (m == 0x54504902) {
            printf("%s rec.tpidr2.value %#lx\n", tag, U64(r + 8));
        }
        off += size;
    }
    printf("%s rec.order %s\n", tag, order);
    printf("%s rec.end_found %d\n", tag, end >= 0);
    if (end >= 0) printf("%s rec.tail_zero %d\n", tag, all_zero(rec + end, 4096 - end));
}

int main(void) {
    alt = aligned_alloc(4096, ALT);
    stack_t ss = {.ss_sp = alt, .ss_size = ALT, .ss_flags = 0};
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = entry_stub;
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

    // Non-default FP state in the interrupted code: rounding towards +infinity, and known
    // values in the callee-saved v8 and v9 (raise's code leaves them).
    fpcr_set = 1 << 22;
    asm volatile("msr fpcr, %0" ::"r"(fpcr_set));
    asm volatile("movz x9, #0x1234, lsl #48\n fmov d8, x9\n movz x9, #0x5678\n fmov d9, x9" ::: "x9", "v8", "v9");
    char here;
    raise(SIGUSR1);
    uint64_t f2;
    asm volatile("mrs %0, fpcr" : "=r"(f2));
    dump("onstack", 1, (uintptr_t)&here, 0);
    printf("onstack after.fpcr_restored %d\n", f2 == fpcr_set);

    raise(SIGUSR2);
    dump("plain", 0, (uintptr_t)&here, 0);
    printf("plain frame_below_local %ld\n", (long)((uintptr_t)&here - frame) / 1024);

    if (getauxval(AT_HWCAP) & HWCAP_SVE) {
        // z0 with every byte set, then tgkill(self, SIGUSR2) in the same block.
        long pid = getpid(), tid = syscall(SYS_gettid);
        asm volatile(".arch_extension sve\n index z0.b, #1, #1\n mov x0, %0\n mov x1, %1\n mov x2, #12\n"
                     " mov x8, #131\n svc #0" ::"r"(pid), "r"(tid)
                     : "x0", "x1", "x2", "x8", "v0", "memory");
        dump("sve_call", 0, (uintptr_t)&here, 0);
    }

    // EFAULT from calls and a counter-timer read, then a signal: no fault information.
    long r = syscall(SYS_write, 1, (void *)16, 1);
    long rc = syscall(SYS_clock_gettime, CLOCK_MONOTONIC, (void *)16);
    uint64_t cnt;
    asm volatile("mrs %0, cntvct_el0" : "=r"(cnt));
    (void)cnt;
    raise(SIGUSR2);
    printf("after_efault write %ld clock_gettime %ld\n", r, rc);
    dump("after_efault", 0, (uintptr_t)&here, 0);

    // A load fault: its address and syndrome.
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    asm volatile("mov x9, #16\n.globl fault_insn\nfault_insn: ldr x10, [x9]" ::: "x9", "x10", "memory");
    dump("fault", 0, (uintptr_t)&here, 1);
    return 0;
}
