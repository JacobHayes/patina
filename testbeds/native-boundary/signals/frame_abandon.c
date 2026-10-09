/* Class pairing: the signal-frame detectors in the shim's panic boundary
 * (`patina_planted_live_scopes`, `patina_planted_handlers_over_shim`, in a
 * shim built with `planted-faults`). A guest handler that leaves by
 * siglongjmp discards every frame between it and the jump's target. Natively
 * those are libc's and the kernel's; under the shim none may be a shim Rust
 * frame, whose destructors (its panic scope among them) would never run.
 *
 * Natively (built without the shim) both counts are 0 in every case.
 * Each named case runs its delivery three times, the handler leaving by
 * siglongjmp every time, then prints one line:
 *
 *   FRAME_ABANDON handled=<runs> beneath=<scopes> over=<handlers>
 *
 * `beneath` counts the shim scopes this guest code still has beneath it
 * after the jumps (0 unless a discarded frame never gave its scope back);
 * `over` counts the handlers that ran with a shim Rust frame beneath them.
 *
 *   fault-escape  a SIGSEGV the guest's own store raises; its handler runs
 *                 from the fault, with only C beneath it (the control);
 *   raise         raise(SIGUSR1) to an unblocked handler;
 *   unblock       a pending SIGUSR1 released by pthread_sigmask;
 *   sigsuspend    a pending SIGUSR1 released by sigsuspend's mask;
 *   pipe-read     a second thread signals the main thread blocked in read;
 *   handoff       a second thread signals the main thread while it yields;
 *   held-back     a SIGSEGV handler that blocks SIGUSR1 raises it, and it
 *                 is delivered as the handler returns;
 *   counter       a timer expires during timestamp-counter reads (x86_64;
 *                 clock reads elsewhere);
 *   raw-tgkill    a raw tgkill instruction (x86_64, under SUD);
 *   raise-counter raise(SIGUSR1) runs a handler that reads the counter until
 *                 a timer expires (x86_64): the timer's delivery, at a
 *                 counter read, is over the frames raise left suspended;
 *   abort         abort() to a SIGABRT handler;
 *   atexit-fault  a SIGSEGV handler runs inside an atexit handler (beneath
 *                 counts exit's own frames there, so only `over` speaks).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Weak, so the same source runs natively as the oracle, where nothing of
 * the shim is beneath any handler: both counts are 0 there. */
__attribute__((weak)) uint64_t patina_planted_live_scopes(void);
__attribute__((weak)) uint64_t patina_planted_handlers_over_shim(void);

static uint64_t live_scopes(void) {
    return patina_planted_live_scopes ? patina_planted_live_scopes() : 0;
}

static uint64_t handlers_over_shim(void) {
    return patina_planted_handlers_over_shim ? patina_planted_handlers_over_shim() : 0;
}

enum { RUNS = 3 };

static sigjmp_buf escape;
static volatile sig_atomic_t handled;
static volatile int *volatile nowhere;
static pthread_t main_thread;
/* The second thread and pipe of the current run, if it has them. */
static pthread_t helper;
static int helping, fds[2] = {-1, -1};
static int entered;

static void leave(int sig) {
    (void)sig;
    handled++;
    siglongjmp(escape, 1);
}

static void install(int sig, void (*handler)(int), int blocked) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    if (blocked) sigaddset(&action.sa_mask, blocked);
    assert(sigaction(sig, &action, NULL) == 0);
}

static void block(int sig) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, sig);
    assert(pthread_sigmask(SIG_BLOCK, &set, NULL) == 0);
}

static void *signal_main(void *delay) {
    if (delay) {
        struct timespec wait = {0, 10000000};
        assert(nanosleep(&wait, NULL) == 0);
    }
    assert(pthread_kill(main_thread, SIGUSR1) == 0);
    return NULL;
}

/* Raises the held-back SIGUSR1 on its first run; a second run means the
 * fault was retried without the SIGUSR1 handler leaving. */
static void segv_holding_usr1(int sig) {
    (void)sig;
    if (entered++) siglongjmp(escape, 2);
    assert(raise(SIGUSR1) == 0);
}

static void counter_read(void);

/* raise-counter's SIGUSR1 handler: a timer expires during its counter reads,
 * and SIGALRM's handler leaves by siglongjmp. */
static void count_until_alarm(int sig) {
    (void)sig;
    struct itimerval once = {{0, 0}, {0, 1000}};
    assert(syscall(SYS_setitimer, ITIMER_REAL, &once, NULL) == 0);
    for (;;) counter_read();
}

static void counter_read(void) {
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    (void)lo;
    (void)hi;
#else
    struct timespec now;
    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
#endif
}

static long raw_tgkill(int sig) {
#if defined(__x86_64__)
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"((long)SYS_tgkill), "D"((long)getpid()), "S"((long)gettid()),
                       "d"((long)sig)
                     : "rcx", "r11", "memory");
    return result;
#else
    (void)sig;
    assert(!"raw-tgkill is an x86_64 case");
    return -1;
#endif
}

static void report(uint64_t over_before) {
    uint64_t beneath = live_scopes();
    uint64_t over = handlers_over_shim() - over_before;
    printf("FRAME_ABANDON handled=%d beneath=%llu over=%llu\n", (int)handled,
           (unsigned long long)beneath, (unsigned long long)over);
    fflush(stdout);
}

static uint64_t atexit_over_before;

static void atexit_fault(void) {
    install(SIGSEGV, leave, 0);
    for (int run = 0; run < RUNS; run++)
        if (sigsetjmp(escape, 1) == 0) *nowhere = 1;
    report(atexit_over_before);
}

/* One delivery of `name`, which its handler leaves by siglongjmp. */
static void deliver(const char *name) {
    if (strcmp(name, "fault-escape") == 0) {
        *nowhere = 1;
    } else if (strcmp(name, "raise") == 0) {
        assert(raise(SIGUSR1) == 0);
    } else if (strcmp(name, "unblock") == 0) {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        assert(raise(SIGUSR1) == 0);
        assert(pthread_sigmask(SIG_UNBLOCK, &set, NULL) == 0);
    } else if (strcmp(name, "sigsuspend") == 0) {
        sigset_t none;
        sigemptyset(&none);
        assert(raise(SIGUSR1) == 0);
        sigsuspend(&none);
    } else if (strcmp(name, "pipe-read") == 0 || strcmp(name, "handoff") == 0) {
        int reading = name[0] == 'p';
        assert(pipe(fds) == 0);
        assert(pthread_create(&helper, NULL, signal_main, reading ? &helper : NULL) == 0);
        helping = 1;
        if (reading) {
            char byte;
            (void)read(fds[0], &byte, 1);
        } else {
            for (;;) sched_yield();
        }
    } else if (strcmp(name, "held-back") == 0) {
        *nowhere = 1;
    } else if (strcmp(name, "counter") == 0) {
        /* Through syscall(2), whose rows the shim models (as segv_routing.c). */
        struct itimerval once = {{0, 0}, {0, 1000}};
        assert(syscall(SYS_setitimer, ITIMER_REAL, &once, NULL) == 0);
        for (;;) counter_read();
    } else if (strcmp(name, "raise-counter") == 0) {
        assert(raise(SIGUSR1) == 0);
    } else if (strcmp(name, "raw-tgkill") == 0) {
        assert(raw_tgkill(SIGUSR1) == 0);
    } else if (strcmp(name, "abort") == 0) {
        abort();
    } else {
        assert(!"unknown case");
    }
    assert(!"a handler that leaves by siglongjmp returned");
}

int main(int argc, char **argv) {
    assert(argc == 2);
    const char *name = argv[1];
    main_thread = pthread_self();
    assert(live_scopes() == 0);
    uint64_t over_before = handlers_over_shim();
    if (strcmp(name, "atexit-fault") == 0) {
        atexit_over_before = over_before;
        assert(atexit(atexit_fault) == 0);
        exit(0);
    }
    if (strcmp(name, "fault-escape") == 0) install(SIGSEGV, leave, 0);
    else if (strcmp(name, "held-back") == 0) install(SIGSEGV, segv_holding_usr1, SIGUSR1);
    if (strcmp(name, "raise-counter") == 0) {
        install(SIGUSR1, count_until_alarm, 0);
        install(SIGALRM, leave, 0);
    } else if (strcmp(name, "counter") == 0) install(SIGALRM, leave, 0);
    else if (strcmp(name, "abort") == 0) install(SIGABRT, leave, 0);
    else install(SIGUSR1, leave, 0);
    if (strcmp(name, "unblock") == 0 || strcmp(name, "sigsuspend") == 0) block(SIGUSR1);
    for (int run = 0; run < RUNS; run++) {
        entered = 0;
        int jumped = sigsetjmp(escape, 1);
        assert(jumped != 2);
        if (jumped == 0) deliver(name);
        if (helping) {
            assert(pthread_join(helper, NULL) == 0);
            assert(close(fds[0]) == 0 && close(fds[1]) == 0);
            helping = 0;
        }
    }
    report(over_before);
    return 0;
}
