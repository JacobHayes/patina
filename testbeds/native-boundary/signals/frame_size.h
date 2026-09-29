/* Linux test-only frame calibration. AT_MINSIGSTKSZ is a capability bound,
 * not the size delivered to this process: on AMX hosts it includes tile state
 * even without ARCH_REQ_XCOMP_PERM. Measure a real frame on generous storage;
 * never include Patina's C/Rust routing frames in the small-stack allowance.
 * These guests do not change extended-state permissions after calibration. */
#ifndef PATINA_TEST_FRAME_SIZE_H
#define PATINA_TEST_FRAME_SIZE_H
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <ucontext.h>

static uintptr_t kernel_frame_base(siginfo_t *info, void *context) {
#if defined(__x86_64__)
    /* rt_sigframe begins with the restorer return address, then ucontext. */
    (void)info;
    return (uintptr_t)context - sizeof(void *);
#elif defined(__aarch64__)
    /* rt_sigframe begins with siginfo, followed by ucontext. */
    (void)context;
    return (uintptr_t)info;
#else
#error "signal frame calibration requires a supported Linux architecture"
#endif
}

static volatile uintptr_t measured_frame_base;
static volatile sig_atomic_t measured_frame_calls;
static void measure_frame(int sig, siginfo_t *info, void *context) {
    (void)sig;
    measured_frame_base = kernel_frame_base(info, context);
    measured_frame_calls++;
}

static size_t kernel_frame_size(void) {
    _Alignas(64) static unsigned char probe[256 * 1024];
    stack_t stack = {.ss_sp = probe, .ss_size = sizeof probe, .ss_flags = 0}, previous;
    struct sigaction action = {.sa_sigaction = measure_frame, .sa_flags = SA_SIGINFO | SA_ONSTACK};
    struct sigaction old_action;
    sigset_t one, old_mask;
    sigemptyset(&action.sa_mask);
    sigemptyset(&one);
    sigaddset(&one, SIGUSR2);
    measured_frame_base = 0;
    measured_frame_calls = 0;
    assert(sigaltstack(&stack, &previous) == 0);
    assert(sigaction(SIGUSR2, &action, &old_action) == 0);
    assert(sigprocmask(SIG_UNBLOCK, &one, &old_mask) == 0);
    assert(raise(SIGUSR2) == 0);
    assert(sigprocmask(SIG_SETMASK, &old_mask, NULL) == 0);
    assert(sigaction(SIGUSR2, &old_action, NULL) == 0);
    assert(sigaltstack(&previous, NULL) == 0);
    uintptr_t base = measured_frame_base;
    uintptr_t top = (uintptr_t)probe + sizeof probe;
    assert(measured_frame_calls == 1 && base > (uintptr_t)probe && base < top);
    size_t frame = top - base;
    assert(frame >= 512 && frame < sizeof probe / 2);
    return frame;
}

static void report_kernel_frame_size(void) {
    printf("KERNEL_FRAME_BYTES %zu AUXV_MINSIGSTKSZ %lu\n",
           kernel_frame_size(), getauxval(AT_MINSIGSTKSZ));
}
#endif
