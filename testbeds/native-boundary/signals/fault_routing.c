/* Class pairing: the synchronous signals an instruction raises (SIGBUS,
 * SIGFPE, SIGILL, SIGTRAP), whose host disposition is the shim's fault front
 * handler while the guest's action is virtual. Named cases, run natively as
 * the oracle and under the shim, each printing what the guest saw:
 *
 *   swap-escape  a raised trap signal is dequeued in one delivery batch with
 *                two SA_NODEFER SIGUSR1s whose handler, run first, installs
 *                a new action for it; its frame still runs the action it was
 *                dequeued with, which leaves by siglongjmp. A genuine trap
 *                right after, before anything else, runs the new action,
 *                under the new action's mask.
 *
 * The trap signal is what __builtin_trap raises: SIGILL on x86_64 (ud2),
 * SIGTRAP on arm64 (brk). */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(__x86_64__)
#define TRAP_SIG SIGILL
#else
#define TRAP_SIG SIGTRAP
#endif

static sigjmp_buf first, second, *jump;
static char seen[16];
static volatile sig_atomic_t count;
static void note(char c) {
    seen[count++] = c;
}

static void on_trap_new(int sig) {
    sigset_t now;
    (void)sig;
    note('N');
    assert(sigprocmask(SIG_BLOCK, NULL, &now) == 0);
    note(sigismember(&now, SIGUSR2) ? 'M' : '-');
    siglongjmp(*jump, 1);
}

static void on_trap_old(int sig) {
    (void)sig;
    note('O');
    siglongjmp(*jump, 1);
}

static void install(int sig, void (*handler)(int), int flags, int masked) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = handler;
    action.sa_flags = flags;
    sigemptyset(&action.sa_mask);
    if (masked) sigaddset(&action.sa_mask, SIGUSR2);
    assert(sigaction(sig, &action, NULL) == 0);
}

static void on_usr1(int sig) {
    (void)sig;
    note('u');
    install(TRAP_SIG, on_trap_new, 0, 0);
}

static void swap_escape(void) {
    install(SIGUSR1, on_usr1, SA_NODEFER, 0);
    install(TRAP_SIG, on_trap_old, 0, 1);
    sigset_t both;
    sigemptyset(&both);
    sigaddset(&both, SIGUSR1);
    sigaddset(&both, TRAP_SIG);
    jump = &first;
    if (sigsetjmp(first, 1) == 0) {
        assert(sigprocmask(SIG_BLOCK, &both, NULL) == 0);
        assert(pthread_kill(pthread_self(), SIGUSR1) == 0);
        assert(kill(getpid(), SIGUSR1) == 0);
        assert(raise(TRAP_SIG) == 0);
        assert(sigprocmask(SIG_UNBLOCK, &both, NULL) == 0);
        note('!');
    }
    /* Nothing between the escape and the trap enters the shim. */
    jump = &second;
    if (sigsetjmp(second, 1) == 0) __builtin_trap();
    printf("SWAP %.*s\n", (int)count, seen);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    if (strcmp(argv[1], "swap-escape") == 0) {
        swap_escape();
    } else {
        fprintf(stderr, "unknown case %s\n", argv[1]);
        return 2;
    }
    puts("FAULT_ROUTING_OK");
    return 0;
}
