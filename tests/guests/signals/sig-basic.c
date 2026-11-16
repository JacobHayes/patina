// Handlers, raise, kill, tgkill between threads, sigqueue with a value,
// SA_SIGINFO fields, nested delivery with and without SA_NODEFER, mask manipulation,
// sigpending, sigsuspend, sigtimedwait with timeout, alarm and setitimer in virtual time.
// Prints key=value lines; the checker compares values.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t count[65];
static volatile int last_code, last_pid, last_uid, last_value, depth, max_depth;
static volatile pid_t handler_tid;

static long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000L + t.tv_nsec;
}

static void on_info(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    // Everything first, the count last: the sender polls the count, and a switch can
    // happen at the gettid trap.
    handler_tid = (pid_t)syscall(SYS_gettid);
    last_code = si->si_code;
    last_pid = si->si_pid;
    last_uid = si->si_uid;
    last_value = si->si_value.sival_int;
    count[sig]++;
}

// Nested: the SIGUSR2 handler raises SIGUSR2 again once. With SA_NODEFER the second one
// runs inside the first (depth 2); without, it waits until the first returns (depth 1).
static void on_nest(int sig) {
    count[sig]++;
    depth++;
    if (depth > max_depth) max_depth = depth;
    if (count[sig] == 1 || count[sig] == 3) raise(sig);
    depth--;
}

static void set(int sig, void (*h)(int, siginfo_t *, void *), int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = h;
    sa.sa_flags = SA_SIGINFO | flags;
    sigemptyset(&sa.sa_mask);
    if (sigaction(sig, &sa, NULL)) perror("sigaction");
}

static void set_plain(int sig, void (*h)(int), int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);
    if (sigaction(sig, &sa, NULL)) perror("sigaction");
}

#define NT 4
static pthread_t th[NT];
static volatile pid_t tids[NT];
static volatile int stop;
static int got_by[NT];
static pthread_barrier_t bar;

static void *worker(void *arg) {
    int i = (int)(intptr_t)arg;
    tids[i] = (pid_t)syscall(SYS_gettid);
    pthread_barrier_wait(&bar);
    while (!stop) sched_yield();
    (void)i;
    return NULL;
}

int main(void) {
    pid_t pid = getpid();
    set(SIGUSR1, on_info, 0);
    set(SIGTERM, on_info, 0);
    set(SIGALRM, on_info, 0);
    set(SIGRTMIN + 1, on_info, 0);

    // raise: SI_TKILL from ourselves, delivered before raise returns.
    raise(SIGUSR1);
    printf("raise count=%d code=%d pid_ok=%d uid=%d\n", count[SIGUSR1], last_code, last_pid == pid, last_uid);

    // kill(getpid()): SI_USER.
    kill(pid, SIGTERM);
    printf("kill count=%d code=%d pid_ok=%d\n", count[SIGTERM], last_code, last_pid == pid);

    // sigqueue with a value: SI_QUEUE.
    union sigval v = {.sival_int = 4242};
    sigqueue(pid, SIGUSR1, v);
    printf("sigqueue count=%d code=%d value=%d\n", count[SIGUSR1], last_code, last_value);

    // Real-time signals queue, standard signals coalesce (while blocked).
    sigset_t m, old;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigaddset(&m, SIGRTMIN + 1);
    sigprocmask(SIG_BLOCK, &m, &old);
    for (int i = 0; i < 3; i++) {
        v.sival_int = 100 + i;
        sigqueue(pid, SIGRTMIN + 1, v);
        raise(SIGUSR1);
    }
    sigset_t p;
    sigpending(&p);
    printf("pending usr1=%d rt1=%d usr2=%d\n", sigismember(&p, SIGUSR1), sigismember(&p, SIGRTMIN + 1), sigismember(&p, SIGUSR2));
    int before_u = count[SIGUSR1], before_r = count[SIGRTMIN + 1];
    sigprocmask(SIG_SETMASK, &old, NULL);
    printf("unblock usr1=%d rt1=%d last_value=%d\n", count[SIGUSR1] - before_u, count[SIGRTMIN + 1] - before_r, last_value);
    sigprocmask(SIG_SETMASK, NULL, &m);
    printf("mask_after usr1=%d\n", sigismember(&m, SIGUSR1));

    // Nested delivery.
    set_plain(SIGUSR2, on_nest, 0);
    raise(SIGUSR2);
    printf("nest_defer count=%d max_depth=%d\n", count[SIGUSR2], max_depth);
    max_depth = 0;
    set_plain(SIGUSR2, on_nest, SA_NODEFER);
    raise(SIGUSR2);
    printf("nest_nodefer count=%d max_depth=%d\n", count[SIGUSR2], max_depth);

    // SA_RESETHAND: the second raise of SIGWINCH (default: ignore) runs no handler.
    set_plain(SIGWINCH, on_nest, SA_RESETHAND | SA_NODEFER);
    count[SIGWINCH] = 0;
    raise(SIGWINCH);
    raise(SIGWINCH);
    struct sigaction cur;
    sigaction(SIGWINCH, NULL, &cur);
    printf("resethand count=%d dfl=%d\n", count[SIGWINCH], cur.sa_handler == SIG_DFL);

    // sigsuspend: block SIGALRM, arm an alarm, suspend with it unblocked.
    sigemptyset(&m);
    sigaddset(&m, SIGALRM);
    sigprocmask(SIG_BLOCK, &m, &old);
    long t0 = now_ns();
    alarm(2);
    sigset_t susp;
    sigprocmask(SIG_SETMASK, NULL, &susp);
    sigdelset(&susp, SIGALRM);
    int r = sigsuspend(&susp);
    long dt = now_ns() - t0;
    sigprocmask(SIG_SETMASK, NULL, &m);
    printf("sigsuspend r=%d errno_eintr=%d alrm=%d elapsed_s=%ld mask_restored=%d\n", r, errno == EINTR, count[SIGALRM],
           dt / 1000000000L, sigismember(&m, SIGALRM));
    sigprocmask(SIG_SETMASK, &old, NULL);

    // alarm return value: remaining seconds of a previous alarm.
    alarm(10);
    unsigned rem = alarm(0);
    printf("alarm_remaining=%u\n", rem);

    // setitimer(ITIMER_REAL) interval: 3 expiries 250 ms apart, counted with pause().
    int a0 = count[SIGALRM];
    struct itimerval it = {.it_interval = {0, 250000}, .it_value = {0, 250000}};
    t0 = now_ns();
    setitimer(ITIMER_REAL, &it, NULL);
    while (count[SIGALRM] - a0 < 3) pause();
    dt = now_ns() - t0;
    struct itimerval cur_it;
    getitimer(ITIMER_REAL, &cur_it);
    memset(&it, 0, sizeof it);
    setitimer(ITIMER_REAL, &it, NULL);
    printf("itimer expiries=%d elapsed_ms=%ld interval_us=%ld\n", count[SIGALRM] - a0, dt / 1000000L,
           (long)cur_it.it_interval.tv_usec);

    // sigtimedwait: timeout, then a queued signal with its value.
    sigemptyset(&m);
    sigaddset(&m, SIGRTMIN + 2);
    sigprocmask(SIG_BLOCK, &m, &old);
    struct timespec to = {1, 500000000};
    siginfo_t si;
    t0 = now_ns();
    r = sigtimedwait(&m, &si, &to);
    dt = now_ns() - t0;
    printf("sigtimedwait_timeout r=%d eagain=%d elapsed_ms=%ld\n", r, errno == EAGAIN, dt / 1000000L);
    v.sival_int = 77;
    sigqueue(pid, SIGRTMIN + 2, v);
    r = sigtimedwait(&m, &si, &to);
    printf("sigtimedwait_got sig_ok=%d value=%d code=%d\n", r == SIGRTMIN + 2, si.si_value.sival_int, si.si_code);
    sigprocmask(SIG_SETMASK, &old, NULL);

    // Threads: tgkill to each thread; the handler runs on that thread.
    pthread_barrier_init(&bar, NULL, NT + 1);
    for (int i = 0; i < NT; i++) pthread_create(&th[i], NULL, worker, (void *)(intptr_t)i);
    pthread_barrier_wait(&bar);
    int ok = 0;
    for (int i = 0; i < NT; i++) {
        int c0 = count[SIGUSR1];
        syscall(SYS_tgkill, pid, tids[i], SIGUSR1);
        while (count[SIGUSR1] == c0) sched_yield();
        ok += handler_tid == tids[i];
    }
    printf("tgkill threads=%d handled_on_target=%d code=%d\n", NT, ok, last_code);

    // Process-directed signals while threads run, blocked in the sender: which thread
    // handles each one depends on the schedule.
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigprocmask(SIG_BLOCK, &m, NULL);
    for (int k = 0; k < 8; k++) {
        int c0 = count[SIGUSR1];
        kill(pid, SIGUSR1);
        while (count[SIGUSR1] == c0) sched_yield();
        for (int i = 0; i < NT; i++)
            if (handler_tid == tids[i]) got_by[i]++;
    }
    stop = 1;
    for (int i = 0; i < NT; i++) pthread_join(th[i], NULL);
    printf("schedule");
    for (int i = 0; i < NT; i++) printf(" %d", got_by[i]);
    printf("\n");
    printf("done\n");
    return 0;
}
