// signals item 6: a thread blocked in a call is signalled by another thread.
//   sig-restart wait : nanosleep (EINTR, remaining time), futex wait with and without
//                      SA_RESTART, futex wait with a timeout (EINTR even with SA_RESTART).
//   sig-restart io   : read on a pipe and poll, with and without SA_RESTART (needs the
//                      blocking I/O of blocking I/O).
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static volatile pid_t tid_a;
static volatile int handled, phase;
static volatile uint32_t word;
static int pfd[2];

static void on_usr1(int sig) {
    (void)sig;
    handled++;
}

static void set_restart(int on) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sa.sa_flags = on ? SA_RESTART : 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
}

static void sleep_ns(long ns) {
    struct timespec t = {ns / 1000000000L, ns % 1000000000L};
    nanosleep(&t, NULL);
}

static long futex_wait(volatile uint32_t *w, uint32_t v, const struct timespec *to) {
    return syscall(SYS_futex, w, FUTEX_WAIT_PRIVATE, v, to, NULL, 0);
}

// The other thread: at each phase, wait a second of virtual time, signal A, then (for the
// futex and I/O phases) wait another second and release A.
static void *thread_b(void *arg) {
    int io = (int)(intptr_t)arg;
    for (int p = 1; p <= 4; p++) {
        while (phase != p) sleep_ns(1000000);
        sleep_ns(1000000000L);
        syscall(SYS_tgkill, getpid(), tid_a, SIGUSR1);
        sleep_ns(1000000000L);
        if (!io) {
            word = 1;
            syscall(SYS_futex, &word, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
        } else if (p <= 2) {
            if (write(pfd[1], "x", 1) != 1) perror("write");
        } else {
            if (write(pfd[1], "y", 1) != 1) perror("write");
        }
    }
    return NULL;
}

static double secs(struct timespec t) {
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void run_wait(void) {
    struct timespec t0, t1;
    // nanosleep 5 s, signalled after about 1 s: EINTR and about 4 s remaining.
    set_restart(1);
    phase = 1;
    struct timespec req = {5, 0}, rem = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int r = nanosleep(&req, &rem);
    int e = errno;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("nanosleep r=%d eintr=%d handled=%d elapsed_plus_rem_ok=%d rem_s=%ld\n", r, e == EINTR, handled,
           (long)((secs(t1) - secs(t0) + secs(rem)) * 1000 + 0.5) == 5000, (long)rem.tv_sec);

    // futex wait, SA_RESTART: the handler runs, the wait goes on until the wake.
    word = 0;
    phase = 2;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    long fr = futex_wait(&word, 0, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("futex_restart r=%ld handled=%d woken_after_s=%ld\n", fr, handled, (long)(secs(t1) - secs(t0) + 0.5));

    // futex wait without SA_RESTART: EINTR.
    set_restart(0);
    word = 0;
    phase = 3;
    fr = futex_wait(&word, 0, NULL);
    e = errno;
    printf("futex_norestart r=%ld eintr=%d handled=%d\n", fr, e == EINTR, handled);
    while (word == 0) sleep_ns(1000000);

    // futex wait with a timeout, SA_RESTART: the restart block makes it EINTR.
    set_restart(1);
    word = 0;
    phase = 4;
    struct timespec to = {10, 0};
    fr = futex_wait(&word, 0, &to);
    e = errno;
    printf("futex_timeout r=%ld eintr=%d handled=%d\n", fr, e == EINTR, handled);
    while (word == 0) sleep_ns(1000000);
}

static void run_io(void) {
    char c;
    set_restart(1);
    phase = 1;
    ssize_t n = read(pfd[0], &c, 1);
    printf("read_restart n=%zd c=%c handled=%d\n", n, n == 1 ? c : '-', handled);
    set_restart(0);
    phase = 2;
    n = read(pfd[0], &c, 1);
    int e = errno;
    printf("read_norestart n=%zd eintr=%d handled=%d\n", n, e == EINTR, handled);
    n = read(pfd[0], &c, 1); // the byte written after the signal
    struct pollfd p = {.fd = pfd[0], .events = POLLIN};
    set_restart(1);
    phase = 3;
    int r = poll(&p, 1, 10000); // poll is never restarted
    e = errno;
    printf("poll_restartflag r=%d eintr=%d handled=%d\n", r, e == EINTR, handled);
    n = read(pfd[0], &c, 1);
    set_restart(0);
    phase = 4;
    r = poll(&p, 1, 10000);
    e = errno;
    printf("poll_norestart r=%d eintr=%d handled=%d\n", r, e == EINTR, handled);
}

int main(int argc, char **argv) {
    int io = argc > 1 && !strcmp(argv[1], "io");
    tid_a = (pid_t)syscall(SYS_gettid);
    if (io && pipe(pfd)) perror("pipe");
    pthread_t b;
    pthread_create(&b, NULL, thread_b, (void *)(intptr_t)io);
    if (io)
        run_io();
    else
        run_wait();
    pthread_join(b, NULL);
    return 0;
}
