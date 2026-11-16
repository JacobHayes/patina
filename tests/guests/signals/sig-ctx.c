// signals item 4: siglongjmp out of a handler (the saved mask comes back); swapcontext and
// getcontext/setcontext round trips.
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>

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
    return 0;
}
