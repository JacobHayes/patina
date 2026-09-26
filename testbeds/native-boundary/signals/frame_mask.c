/* Class pairing: a handler that edits its frame's saved mask to block the
 * signals containment runs on (SIGSYS for the syscall trap, SIGSEGV for the
 * timestamp-counter trap). The kernel installs that mask when the handler
 * returns; natively the guest then keeps running with them blocked, so the
 * next raw syscall and `rdtsc` must still be answered under patina too.
 * Named cases, each printing FRAME_MASK_OK:
 *
 *   libc      an action installed through sigaction(2), returning through
 *             glibc's restorer;
 *   raw       (x86_64) a raw rt_sigaction with the guest's own SA_RESTORER
 *             stub issuing a raw rt_sigreturn;
 *   raw-libc  (x86_64) the same, with a stub that tail-calls syscall(2).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static volatile sig_atomic_t handled;

static void block_containment(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    ucontext_t *uc = context;
    sigaddset(&uc->uc_sigmask, SIGSYS);
    sigaddset(&uc->uc_sigmask, SIGSEGV);
    handled++;
}

/* A syscall the containment trap answers: a raw instruction on x86_64, the
 * libc door on arm64 (whose raw `svc` the audit refuses). */
static long raw_getpid(void) {
#if defined(__x86_64__)
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"((long)SYS_getpid) : "rcx", "r11", "memory");
    return result;
#else
    return syscall(SYS_getpid);
#endif
}

static void after_return(void) {
    assert(handled == 1);
    assert(raw_getpid() == getpid());
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    (void)lo;
    (void)hi;
#endif
    puts("FRAME_MASK_OK");
}

#if defined(__x86_64__)
/* The kernel's `struct sigaction` for x86_64. */
struct kernel_action {
    void *handler;
    unsigned long flags;
    void *restorer;
    uint64_t mask;
};
#define KERNEL_SA_RESTORER 0x04000000UL
extern void stub_raw(void);
extern void stub_libc(void);
__asm__(".text\n"
        ".globl stub_raw\n"
        "stub_raw:\n"
        "  mov $15, %eax\n"
        "  syscall\n"
        ".globl stub_libc\n"
        "stub_libc:\n"
        "  mov $15, %edi\n"
        "  jmp syscall\n");

static void raw_action(void (*stub)(void)) {
    struct kernel_action action = {(void *)block_containment,
                                   SA_SIGINFO | KERNEL_SA_RESTORER, (void *)stub, 0};
    assert(syscall(SYS_rt_sigaction, SIGUSR1, &action, NULL, sizeof action.mask) == 0);
}
#endif

int main(int argc, char **argv) {
    assert(argc == 2);
    if (strcmp(argv[1], "libc") == 0) {
        struct sigaction action;
        memset(&action, 0, sizeof action);
        action.sa_sigaction = block_containment;
        action.sa_flags = SA_SIGINFO;
        assert(sigaction(SIGUSR1, &action, NULL) == 0);
#if defined(__x86_64__)
    } else if (strcmp(argv[1], "raw") == 0) {
        raw_action(stub_raw);
    } else if (strcmp(argv[1], "raw-libc") == 0) {
        raw_action(stub_libc);
#endif
    } else {
        fprintf(stderr, "unknown case %s\n", argv[1]);
        return 2;
    }
    fflush(stdout);
    assert(raise(SIGUSR1) == 0);
    after_return();
    return 0;
}
