/* Class pairing: real libc/raw doors for reserved-signal containment,
 * single-entry state, and internal-fatal versus guest-abort finalization. */
#define _GNU_SOURCE
#include "patina_native.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

extern int tkill(pid_t tid, int sig);
extern unsigned char PATINA_SUD_ARMED;
extern unsigned char PATINA_TSC_ARMED;
static volatile sig_atomic_t handled;
static void *empty_task(void *value) { return value; }
static void assert_safe_mask(void);
static void handler(int sig) {
    assert(sig == SIGUSR1);
    assert_safe_mask();
    handled++;
}

static long raw4(long nr, long a, long b, long c, long d) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = 0; /* prctl arg5: all tested tails are zero */
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return result;
}
static void assert_safe_mask(void) {
    uint64_t mask = UINT64_MAX;
    assert(raw4(SYS_rt_sigprocmask, SIG_BLOCK, 0, (long)&mask, sizeof mask) == 0);
    assert((mask & (UINT64_C(1) << (SIGSYS - 1))) == 0);
    if (PATINA_TSC_ARMED)
        assert((mask & (UINT64_C(1) << (SIGSEGV - 1))) == 0);
}
static void *sender(void *arg) {
    (void)arg;
    struct timespec delay = {0, 10};
    assert(nanosleep(&delay, NULL) == 0);
    assert(kill(1, SIGUSR1) == 0);
    assert(nanosleep(&delay, NULL) == 0);
    assert(kill(1, SIGUSR2) == 0);
    return NULL;
}
static void prctl_state(void) {
    char name[16] = {0};
    assert(prctl(PR_SET_NAME, "one-entry", 0UL, 0UL, 0UL) == 0);
    assert(raw4(SYS_prctl, PR_GET_NAME, (long)name, 0, 0) == 0);
    assert(strcmp(name, "one-entry") == 0);
    assert(raw4(SYS_prctl, PR_SET_NAME, (long)"raw-entry", 0, 0) == 0);
    assert(prctl(PR_GET_NAME, name, 0UL, 0UL, 0UL) == 0);
    assert(strcmp(name, "raw-entry") == 0);
    assert(prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) == 0);
    assert(raw4(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0) == 1);
    errno = 0;
    assert(prctl(PR_SET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL) == -1 && errno == EINVAL);
    assert(prctl(PR_SET_THP_DISABLE, 1UL, 0UL, 0UL, 0UL) == 0);
    assert(raw4(SYS_prctl, PR_GET_THP_DISABLE, 0, 0, 0) == 1);
    assert(raw4(SYS_prctl, PR_SET_VMA, 0, 0, 0) == 0);
}

static void install_handler(void) {
    struct sigaction act = {0}, old = {0};
    act.sa_handler = handler;
    sigemptyset(&act.sa_mask);
    assert(sigaction(SIGUSR1, &act, NULL) == 0);
    assert(sigaction(SIGUSR1, NULL, &old) == 0);
    assert(old.sa_handler == handler && old.sa_restorer != NULL);
}

static void handler_visibility(void) {
    install_handler();
    assert(tgkill(1, (pid_t)patina_thread_id(), SIGUSR1) == 0);
    assert(tkill((pid_t)patina_thread_id(), SIGUSR1) == 0);
    assert(handled == 2);
}

static void reserved_masks(void) {
    sigset_t all;
    sigfillset(&all);
    assert(sigprocmask(SIG_SETMASK, &all, NULL) == 0);
    assert_safe_mask();
    uint64_t kernel_all = UINT64_MAX;
    assert(raw4(SYS_rt_sigprocmask, SIG_SETMASK, (long)&kernel_all, 0, sizeof kernel_all) == 0);
    assert_safe_mask(); /* checks the SIGSYS frame did not restore a reserved bit */
}

/* The handler's raw mask query consumes an inner SIGSYS frame fixup. */
static void nested_unblock(void) {
    install_handler();
    uint64_t mask = UINT64_C(1) << (SIGUSR1 - 1);
    assert(raw4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&mask, 0, sizeof mask) == 0);
    assert(kill(1, SIGUSR1) == 0);
    assert(handled == 0);
    assert(raw4(SYS_rt_sigprocmask, SIG_UNBLOCK, (long)&mask, 0, sizeof mask) == 0);
    assert(handled == 1);
    uint64_t observed = UINT64_MAX;
    assert(raw4(SYS_rt_sigprocmask, SIG_BLOCK, 0, (long)&observed, sizeof observed) == 0);
    if (observed & mask) {
        const char diagnostic[] = "outer rt_sigreturn undid unblock\n";
        write(2, diagnostic, sizeof diagnostic - 1);
        _exit(81);
    }
    assert(kill(1, SIGUSR1) == 0);
    assert(handled == 2);
}

static void sigwait_retry(void) {
    install_handler();
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    assert(pthread_sigmask(SIG_SETMASK, &mask, NULL) == 0);
    pthread_t worker;
    assert(pthread_create(&worker, NULL, sender, NULL) == 0);
    int sig = 0;
    assert(sigwait(&mask, &sig) == 0 && sig == SIGUSR2);
    assert(handled == 1); /* unrelated USR1 handler interrupted and sigwait retried */
    assert(pthread_join(worker, NULL) == 0);
}

static void suspend_masks(int raw) {
    install_handler();
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    assert(pthread_sigmask(SIG_SETMASK, &mask, NULL) == 0);
    pthread_t worker;
    int sig = 0;
    assert(pthread_create(&worker, NULL, sender, NULL) == 0);
    uint64_t suspend_mask = UINT64_MAX & ~(UINT64_C(1) << (SIGUSR1 - 1));
    if (raw) {
        assert(raw4(SYS_rt_sigsuspend, (long)&suspend_mask, sizeof suspend_mask, 0, 0) == -EINTR);
    } else {
        sigset_t temporary;
        sigfillset(&temporary);
        sigdelset(&temporary, SIGUSR1);
        assert(sigsuspend(&temporary) == -1 && errno == EINTR);
    }
    assert_safe_mask();
    assert(pthread_join(worker, NULL) == 0);
    assert(sigwait(&mask, &sig) == 0 && sig == SIGUSR2);
    assert(handled == 1);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    assert(PATINA_SUD_ARMED); /* no unsupported-kernel false green */
    if (strcmp(argv[1], "guest-abort") == 0) abort();
    if (strcmp(argv[1], "internal-c") == 0) fork();
    if (strcmp(argv[1], "internal-rust") == 0) raw4(999999, 0, 0, 0, 0);
    if (strcmp(argv[1], "internal-context-active") == 0) {
        pthread_t worker;
        assert(pthread_create(&worker, NULL, empty_task, NULL) == 0);
        assert(pthread_join(worker, NULL) == 0);
        patina_custom_op_record(NULL, 0);
        assert(!"custom operation without begin returned");
    }
    if (strcmp(argv[1], "internal-context") == 0) {
        size_t length;
        const uint8_t label[] = "nested";
        assert(patina_custom_op_begin(label, sizeof(label) - 1, NULL, 0, 0, &length) == 0);
        patina_custom_op_begin(label, sizeof(label) - 1, NULL, 0, 0, &length);
        assert(!"nested custom operation returned");
    }
    int reserved = strstr(argv[1], "segv") ? SIGSEGV : SIGSYS;
    if (strncmp(argv[1], "reserved-", 9) == 0) {
        if (reserved == SIGSEGV) assert(PATINA_TSC_ARMED);
        if (strstr(argv[1], "libc")) signal(reserved, handler);
        else {
            struct patina_signal_action act = {.handler = (uintptr_t)handler};
            raw4(SYS_rt_sigaction, reserved, (long)&act, 0, sizeof(uint64_t));
        }
        return 98;
    }
    if (strcmp(argv[1], "prctl") == 0) prctl_state();
    else if (strcmp(argv[1], "handler") == 0) handler_visibility();
    else if (strcmp(argv[1], "masks") == 0) reserved_masks();
    else if (strcmp(argv[1], "nested-unblock") == 0) nested_unblock();
    else if (strcmp(argv[1], "sigwait") == 0) sigwait_retry();
    else if (strcmp(argv[1], "suspend-libc") == 0) suspend_masks(0);
    else if (strcmp(argv[1], "suspend-raw") == 0) suspend_masks(1);
    else assert(!"unknown signal boundary case");
    assert(patina_shutdown() == 0);
    return 0;
}
