// signals item 7: a guest that blocks every signal, SIGSYS and SIGSEGV included, and
// registers handlers with a full sa_mask keeps working: its syscalls still trap, handlers
// that make syscalls run, and the mask query reports SIGSYS and SIGSEGV as blocked.
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static volatile int handled;

static void on_sig(int sig) {
    // Syscalls inside a handler whose sa_mask holds everything.
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    char buf[32];
    int n = snprintf(buf, sizeof buf, "handler %d\n", sig);
    if (write(1, buf, n) != n) _exit(3);
    handled++;
}

static void *thr(void *a) {
    (void)a;
    sigset_t m;
    pthread_sigmask(SIG_SETMASK, NULL, &m);
    printf("thread inherits sys=%d segv=%d\n", sigismember(&m, SIGSYS), sigismember(&m, SIGSEGV));
    return NULL;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sigfillset(&sa.sa_mask);
    int sigs[] = {SIGUSR1, SIGSYS, SIGSEGV, SIGTERM};
    for (int i = 0; i < 4; i++) sigaction(sigs[i], &sa, NULL);

    sigset_t all, q;
    sigfillset(&all);
    sigprocmask(SIG_SETMASK, &all, NULL);
    sigprocmask(SIG_SETMASK, NULL, &q);
    printf("blocked sys=%d segv=%d usr1=%d kill=%d\n", sigismember(&q, SIGSYS), sigismember(&q, SIGSEGV),
           sigismember(&q, SIGUSR1), sigismember(&q, SIGKILL));

    // Ordinary calls go on working.
    struct timespec t = {0, 1000000};
    nanosleep(&t, NULL);
    printf("pid_ok=%d\n", getpid() > 0);

    // A blocked signal stays pending; unblocking delivers it to the full-mask handler.
    raise(SIGUSR1);
    sigset_t p;
    sigpending(&p);
    printf("pending usr1=%d handled=%d\n", sigismember(&p, SIGUSR1), handled);
    sigset_t u;
    sigemptyset(&u);
    sigaddset(&u, SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &u, NULL);
    fflush(stdout);
    printf("after unblock handled=%d\n", handled);
    sigprocmask(SIG_SETMASK, NULL, &q);
    printf("still blocked sys=%d segv=%d\n", sigismember(&q, SIGSYS), sigismember(&q, SIGSEGV));

    pthread_t th;
    pthread_create(&th, NULL, thr, NULL);
    pthread_join(th, NULL);
    return 0;
}
