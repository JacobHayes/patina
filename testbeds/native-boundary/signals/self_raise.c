#define _GNU_SOURCE 1
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static _Thread_local pthread_t owner;
static _Thread_local volatile sig_atomic_t calls;
static _Thread_local int nested;
static _Thread_local int deferred;
static _Thread_local int on_altstack;
static char alternate[65536];
static void handler(int sig) {
    assert(sig == SIGUSR1);
    assert(pthread_equal(pthread_self(), owner));
    ++calls;
    if (on_altstack) {
        char here;
        assert((uintptr_t)&here >= (uintptr_t)alternate);
        assert((uintptr_t)&here < (uintptr_t)(alternate + sizeof alternate));
    }
    /* A real modeled boundary in the callback: no shim lock/ownership may
     * survive across delivery. No timing or synchronization sleeps. */
    assert(write(1, "handled\n", 8) == 8);
    if ((nested || deferred) && calls == 1) assert(raise(sig) == 0);
}
static void info_handler(int sig, siginfo_t *info, void *context) {
    (void)sig; (void)info; (void)context;
    assert(!"unsupported siginfo handler must never execute on Darwin");
}
static void *exercise(void *arg) {
    (void)arg;
    owner = pthread_self();
    calls = 0;
    assert(raise(0) == 0);
    errno = 0;
    assert(raise(-1) == -1 && errno == EINVAL);
    errno = 0;
    assert(raise(32) == -1 && errno == EINVAL); /* reserved on Linux, out of range on Darwin */
    assert(raise(SIGUSR1) == 0 && calls == 1);
    return NULL;
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "handled";
    if (!strcmp(mode, "default")) {
        assert(signal(SIGTERM, SIG_DFL) != SIG_ERR);
        assert(write(1, "default\n", 8) == 8);
        raise(SIGTERM);
        assert(!"default termination returned");
    }
    if (!strcmp(mode, "stop")) {
        assert(signal(SIGTSTP, SIG_DFL) != SIG_ERR);
        raise(SIGTSTP);
        assert(!"unsupported default stop returned");
    }
    if (!strcmp(mode, "reserved")) {
        raise(SIGSYS);
        assert(!"reserved signal returned");
    }
    struct sigaction action = {0};
    sigemptyset(&action.sa_mask);
    action.sa_handler = handler;
    owner = pthread_self();
    if (!strcmp(mode, "info")) {
        action.sa_sigaction = info_handler;
        action.sa_flags = SA_SIGINFO;
        assert(sigaction(SIGUSR1, &action, NULL) == 0);
        raise(SIGUSR1);
        assert(!"unsupported siginfo returned");
    }
    if (!strcmp(mode, "deferred")) {
        deferred = 1;
        assert(sigaction(SIGUSR1, &action, NULL) == 0);
        raise(SIGUSR1);
        assert(!"unsupported deferred delivery returned");
    }
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    exercise(NULL);
    pthread_t worker;
    assert(pthread_create(&worker, NULL, exercise, NULL) == 0);
    assert(pthread_join(worker, NULL) == 0);
    assert(calls == 1); /* worker delivery never reached main */
    assert(signal(SIGUSR1, SIG_IGN) == handler);
    assert(raise(SIGUSR1) == 0 && calls == 1);
    assert(signal(SIGCHLD, SIG_DFL) != SIG_ERR);
    assert(raise(SIGCHLD) == 0);
    action.sa_flags = SA_RESETHAND;
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    assert(raise(SIGUSR1) == 0 && calls == 2);
    struct sigaction old;
    assert(sigaction(SIGUSR1, NULL, &old) == 0 && old.sa_handler == SIG_DFL);
    action.sa_flags = SA_NODEFER;
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    nested = 1;
    calls = 0;
    assert(raise(SIGUSR1) == 0 && calls == 2);
    nested = 0;
    stack_t stack = {.ss_sp = alternate, .ss_size = sizeof alternate, .ss_flags = 0};
    assert(sigaltstack(&stack, NULL) == 0);
    action.sa_flags = SA_ONSTACK;
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    on_altstack = 1;
    assert(raise(SIGUSR1) == 0 && calls == 3);
    on_altstack = 0;
    stack.ss_flags = SS_DISABLE;
    assert(sigaltstack(&stack, NULL) == 0);
    puts("SELF_RAISE_OK");
}
