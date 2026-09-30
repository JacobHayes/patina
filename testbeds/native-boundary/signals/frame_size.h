/* Linux test-only delivery calibration: how much of the stack a handler runs
 * on a delivery takes above the handler's stack pointer at its entry. Natively that is the
 * kernel's signal frame, whose size depends on the host CPU's extended state
 * (AT_MINSIGSTKSZ is a capability bound, not the size delivered: on AMX hosts
 * it includes tile state even without ARCH_REQ_XCOMP_PERM). Under patina the
 * kernel builds that frame on a private stack, and the cost is the shim's
 * slot and (x86_64) the handler's return address. Measured to the entry
 * stack pointer, which the handler's own frame shape does not change, on
 * generous storage; these guests do not change extended-state permissions
 * after calibration. */
#ifndef PATINA_TEST_FRAME_SIZE_H
#define PATINA_TEST_FRAME_SIZE_H
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <ucontext.h>

/* The kernel's own floor for an alternate stack (its MINSIGSTKSZ). */
#if defined(__x86_64__)
#define KERNEL_MINSIGSTKSZ 2048
#elif defined(__aarch64__)
#define KERNEL_MINSIGSTKSZ 5120
#else
#error "signal stack calibration requires a supported Linux architecture"
#endif

/* ENTRY_SP_HANDLER(name, body) defines the handler `name`, which records its
 * stack pointer at entry in `name##_sp` and continues into the C `body` (a
 * three-argument handler), so the measurement never includes a compiler's
 * frame. */
#if defined(__x86_64__)
#define ENTRY_SP_HANDLER(name, body)                                                     \
    volatile uintptr_t name##_sp;                                                        \
    void name(int, siginfo_t *, void *);                                                 \
    __asm__(".text\n.globl " #name "\n.type " #name ",@function\n" #name ":\n"            \
            "  movq %rsp, " #name "_sp(%rip)\n"                                          \
            "  jmp " #body "\n.size " #name ", .-" #name "\n")
#elif defined(__aarch64__)
#define ENTRY_SP_HANDLER(name, body)                                                     \
    volatile uintptr_t name##_sp;                                                        \
    void name(int, siginfo_t *, void *);                                                 \
    __asm__(".text\n.globl " #name "\n.type " #name ",%function\n" #name ":\n"            \
            "  bti c\n  mov x16, sp\n  adrp x17, " #name "_sp\n"                          \
            "  str x16, [x17, :lo12:" #name "_sp]\n"                                      \
            "  b " #body "\n.size " #name ", .-" #name "\n")
#endif

static volatile sig_atomic_t measured_frame_calls;
void measure_frame_body(int sig, siginfo_t *info, void *context);
void measure_frame_body(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    measured_frame_calls++;
}
ENTRY_SP_HANDLER(measure_frame, measure_frame_body);

/* The bytes a delivery takes from the top of the alternate stack its
 * handler runs on, down to the handler's frame. */
static size_t delivery_stack_bytes(void) {
    _Alignas(64) static unsigned char probe[256 * 1024];
    stack_t stack = {.ss_sp = probe, .ss_size = sizeof probe, .ss_flags = 0}, previous;
    struct sigaction action = {.sa_sigaction = measure_frame,
                               .sa_flags = SA_SIGINFO | SA_ONSTACK};
    struct sigaction old_action;
    sigset_t one, old_mask;
    sigemptyset(&action.sa_mask);
    sigemptyset(&one);
    sigaddset(&one, SIGUSR2);
    measure_frame_sp = 0;
    measured_frame_calls = 0;
    assert(sigaltstack(&stack, &previous) == 0);
    assert(sigaction(SIGUSR2, &action, &old_action) == 0);
    assert(sigprocmask(SIG_UNBLOCK, &one, &old_mask) == 0);
    assert(raise(SIGUSR2) == 0);
    assert(sigprocmask(SIG_SETMASK, &old_mask, NULL) == 0);
    assert(sigaction(SIGUSR2, &old_action, NULL) == 0);
    assert(sigaltstack(&previous, NULL) == 0);
    uintptr_t frame = measure_frame_sp;
    uintptr_t top = (uintptr_t)probe + sizeof probe;
    assert(measured_frame_calls == 1 && frame > (uintptr_t)probe && frame < top);
    return top - frame;
}

/* A stack size with `wanted` bytes of room the kernel still accepts. */
static size_t small_stack_bytes(size_t wanted) {
    return wanted < KERNEL_MINSIGSTKSZ ? KERNEL_MINSIGSTKSZ : wanted;
}

static void report_delivery_stack_bytes(void) {
    printf("DELIVERY_STACK_BYTES %zu AUXV_MINSIGSTKSZ %lu\n", delivery_stack_bytes(),
           getauxval(AT_MINSIGSTKSZ));
}
#endif
