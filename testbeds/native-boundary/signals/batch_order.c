/* Class pairing: the order, loss and saved masks of a delivery batch's
 * frames (src/thread/signals/delivery.rs). Two realtime signals of one
 * number queued while blocked, then unblocked, under SA_NODEFER: the kernel
 * builds a frame for each, the second over the first, so the one sent last
 * runs first; a handler that leaves by siglongjmp from the top frame loses
 * the one below. Without SA_NODEFER the second waits for the first's mask to
 * go and runs after the jump. Two signals a sigsuspend releases: the frame
 * built first (the lower signal's, which runs last) saves the mask from
 * before the suspension, the next the temporary mask with the first's
 * handler mask. Named cases print what they saw; a `-raw` suffix (x86_64)
 * unblocks and suspends through the raw instruction, which SUD traps.
 * `forward-nested` has a handler that glibc's syscall(2) ran (a libc door)
 * send a second signal with the raw instruction: it runs before that
 * instruction returns. */
#define _GNU_SOURCE
#include <assert.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static sigjmp_buf env;
static int jump_first, raw_door, order[8], saved[8], n;
static volatile sig_atomic_t usr2_ran;

static long raw4(long nr, long a0, long a1, long a2, long a3) {
#if defined(__x86_64__)
    if (raw_door) {
        long result;
        register long r10 __asm__("r10") = a3;
        __asm__ volatile("syscall"
                         : "=a"(result)
                         : "a"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10)
                         : "rcx", "r11", "memory");
        return result;
    }
#endif
    return syscall(nr, a0, a1, a2, a3);
}

static int mask_bits(const sigset_t *set) {
    return sigismember(set, SIGUSR1) | sigismember(set, SIGUSR2) << 1 |
           sigismember(set, SIGHUP) << 2;
}

static void on_signal(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = context;
    order[n] = sig == SIGRTMIN ? info->si_value.sival_int : sig;
    saved[n] = mask_bits(&uc->uc_sigmask);
    n++;
    if (jump_first && n == 1) siglongjmp(env, 1);
}

static void on_usr2(int sig) {
    (void)sig;
    usr2_ran = 1;
}

/* forward-nested's SIGUSR1 handler: a raw tgkill of SIGUSR2. */
static void send_usr2(int sig) {
    (void)sig;
    raw_door = 1;
    usr2_ran = 0;
    assert(raw4(SYS_tgkill, getpid(), gettid(), SIGUSR2, 0) == 0);
    printf("forward-nested: usr2 ran before the raw tgkill returned: %d\n", (int)usr2_ran);
}

static void install(int sig, int flags) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = on_signal;
    action.sa_flags = SA_SIGINFO | flags;
    sigemptyset(&action.sa_mask);
    assert(sigaction(sig, &action, NULL) == 0);
}

static void set_mask(int how, const sigset_t *set) {
    assert(raw4(SYS_rt_sigprocmask, how, (long)set, 0, 8) == 0);
}

static void realtime(const char *name, int flags, int jump) {
    n = 0;
    jump_first = jump;
    install(SIGRTMIN, flags);
    sigset_t rt;
    sigemptyset(&rt);
    sigaddset(&rt, SIGRTMIN);
    set_mask(SIG_BLOCK, &rt);
    for (int value = 1; value <= 2; value++) {
        union sigval sent = {.sival_int = value};
        assert(sigqueue(getpid(), SIGRTMIN, sent) == 0);
    }
    if (sigsetjmp(env, 1) == 0) set_mask(SIG_UNBLOCK, &rt);
    set_mask(SIG_UNBLOCK, &rt);
    printf("%s: handled=%d order=", name, n);
    for (int i = 0; i < n; i++) printf("%d ", order[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    assert(argc == 2);
    char name[64];
    snprintf(name, sizeof name, "%s", argv[1]);
    char *raw = strstr(name, "-raw");
    if (raw) {
        *raw = 0;
        raw_door = 1;
    }
    if (strcmp(name, "nodefer") == 0) {
        realtime(name, SA_NODEFER, 0);
    } else if (strcmp(name, "nodefer-jump") == 0) {
        realtime(name, SA_NODEFER, 1);
    } else if (strcmp(name, "defer-jump") == 0) {
        realtime(name, 0, 1);
    } else if (strcmp(name, "sigsuspend-two") == 0) {
        install(SIGUSR1, 0);
        install(SIGUSR2, 0);
        sigset_t old, temporary;
        sigemptyset(&old);
        sigaddset(&old, SIGUSR1);
        sigaddset(&old, SIGUSR2);
        sigaddset(&old, SIGHUP);
        set_mask(SIG_SETMASK, &old);
        assert(raise(SIGUSR1) == 0 && raise(SIGUSR2) == 0);
        sigemptyset(&temporary);
        sigaddset(&temporary, SIGHUP);
        raw4(SYS_rt_sigsuspend, (long)&temporary, 8, 0, 0);
        printf("sigsuspend-two: handled=%d", n);
        for (int i = 0; i < n; i++) printf(" sig%d saved=%d", order[i], saved[i]);
        printf("\n");
    } else if (strcmp(name, "forward-nested") == 0) {
        struct sigaction action;
        memset(&action, 0, sizeof action);
        sigemptyset(&action.sa_mask);
        action.sa_handler = on_usr2;
        assert(sigaction(SIGUSR2, &action, NULL) == 0);
        action.sa_handler = send_usr2;
        assert(sigaction(SIGUSR1, &action, NULL) == 0);
        /* glibc's syscall(2): a libc door that forwards to the syscall model. */
        assert(syscall(SYS_tgkill, getpid(), gettid(), SIGUSR1) == 0);
    } else {
        assert(!"unknown case");
    }
    return 0;
}
