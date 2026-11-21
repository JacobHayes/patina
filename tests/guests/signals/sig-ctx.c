// siglongjmp out of a handler (the saved mask comes back); swapcontext and
// getcontext/setcontext round trips; a handler that sets the interrupted call's return
// register to INT64_MIN, then to -EFBIG, which the return from the handler restores like any
// other value (tests/signals/04-context runs this under a finite RLIMIT_FSIZE too).
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static sigjmp_buf env;
static volatile int jumps, in_handler_blocked;

static void on_jump(int sig) {
    sigset_t m;
    sigprocmask(SIG_SETMASK, NULL, &m);
    in_handler_blocked = sigismember(&m, sig);
    jumps++;
    siglongjmp(env, jumps);
}

static ucontext_t uc_main, uc_co;
static volatile int co_steps;
static char co_stack[64 * 1024];

static void coroutine(int a, int b) {
    for (int i = 0; i < 5; i++) {
        co_steps += a + b;
        swapcontext(&uc_co, &uc_main);
    }
}

static volatile int resumed;

static volatile long set_ret;

static void on_set_ret(int sig, siginfo_t *si, void *ctx) {
    (void)sig, (void)si;
    ucontext_t *uc = ctx;
#if defined(__x86_64__)
    uc->uc_mcontext.gregs[REG_RAX] = (greg_t)set_ret;
#else
    uc->uc_mcontext.regs[0] = (uint64_t)set_ret;
#endif
}

// tgkill(self, SIGUSR2) by hand, returning the return register as the program sees it after
// the handler ran.
static long kill_self_raw(void) {
    long pid = getpid(), tid = syscall(SYS_gettid);
#if defined(__x86_64__)
    register long rax __asm__("rax") = SYS_tgkill;
    register long rdi __asm__("rdi") = pid, rsi __asm__("rsi") = tid, rdx __asm__("rdx") = SIGUSR2;
    __asm__ volatile("syscall" : "+r"(rax) : "r"(rdi), "r"(rsi), "r"(rdx) : "rcx", "r11", "memory");
    return rax;
#else
    register long x8 __asm__("x8") = SYS_tgkill;
    register long x0 __asm__("x0") = pid, x1 __asm__("x1") = tid, x2 __asm__("x2") = SIGUSR2;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
#endif
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_jump;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
    int v = sigsetjmp(env, 1);
    if (v < 3) raise(SIGUSR1);
    sigset_t m;
    sigprocmask(SIG_SETMASK, NULL, &m);
    printf("siglongjmp jumps=%d v=%d blocked_in_handler=%d blocked_after=%d\n", jumps, v, in_handler_blocked,
           sigismember(&m, SIGUSR1));

    getcontext(&uc_co);
    uc_co.uc_stack.ss_sp = co_stack;
    uc_co.uc_stack.ss_size = sizeof co_stack;
    uc_co.uc_link = &uc_main;
    makecontext(&uc_co, (void (*)(void))coroutine, 2, 3, 4);
    int rounds = 0;
    for (int i = 0; i < 5; i++) {
        swapcontext(&uc_main, &uc_co);
        rounds++;
    }
    printf("swapcontext rounds=%d steps=%d\n", rounds, co_steps);

    // getcontext/setcontext: resume the saved point three times.
    ucontext_t here;
    getcontext(&here);
    resumed++;
    if (resumed < 3) setcontext(&here);
    printf("setcontext resumed=%d\n", resumed);

    sa.sa_handler = NULL;
    sa.sa_sigaction = on_set_ret;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR2, &sa, NULL);
    long got[2], want[2] = {INT64_MIN, -EFBIG};
    for (int i = 0; i < 2; i++) {
        set_ret = want[i];
        got[i] = kill_self_raw();
    }
    printf("setret min=%#lx efbig=%#lx\n", (unsigned long)got[0], (unsigned long)got[1]);
    int bad = got[0] != want[0] || got[1] != want[1];
    return bad;
}
