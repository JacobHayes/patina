/* Class pairing: the virtual mask's refresh from the host's
 * (src/thread/signals/delivery.rs refresh_handler_mask). A handler a fault
 * runs, whose sa_mask blocks SIGUSR2, raises SIGUSR2 and leaves by
 * siglongjmp to a context that unblocks it: glibc restores that mask with
 * its own system call, which the shim does not see. Natively SIGUSR2 is
 * delivered as the mask is restored; under the shim, by the next delivery
 * point at the latest, never left pending. Prints, for three such jumps,
 * whether SIGUSR2's handler had run once the program next yielded. */
#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

static sigjmp_buf escape;
static volatile sig_atomic_t usr2;

static void on_usr2(int sig) {
    (void)sig;
    usr2++;
}

/* An undefined instruction: SIGILL on both arches (arm64's __builtin_trap is
 * a brk, which raises SIGTRAP). */
static void illegal(void) {
#if defined(__aarch64__)
    __asm__ volatile("udf #0");
#else
    __builtin_trap();
#endif
}

static void on_ill(int sig) {
    (void)sig;
    assert(raise(SIGUSR2) == 0);
    assert(usr2 == 0);
    siglongjmp(escape, 1);
}

int main(void) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_usr2;
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGUSR2, &action, NULL) == 0);
    action.sa_handler = on_ill;
    sigaddset(&action.sa_mask, SIGUSR2);
    assert(sigaction(SIGILL, &action, NULL) == 0);
    for (int run = 0; run < 3; run++) {
        usr2 = 0;
        if (sigsetjmp(escape, 1) == 0) illegal();
        sched_yield();
        printf("HELD_BACK_ESCAPE run=%d usr2=%d\n", run, (int)usr2);
    }
    return 0;
}
