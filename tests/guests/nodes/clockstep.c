/* clockstep.c: what a node's timers do when the driver steps its realtime clock.
 *
 *   clockstep node    start the timers below at once, print when each fires (ms of the
 *                     monotonic clock since the start) and what it returned, then the realtime
 *                     clock against the monotonic one
 *   clockstep driver  step node b's clock by +5 s at 1 s, and by -5 s at 20 s
 *
 * The timers (each in its own thread), all 10 s away at the start:
 *   abs-sleep      clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME): moves with the clock
 *   rel-sleep      clock_nanosleep(CLOCK_REALTIME, relative): does not move
 *   cond           pthread_cond_timedwait on a CLOCK_REALTIME condition variable (a futex
 *                  wait with FUTEX_CLOCK_REALTIME): moves
 *   tfd-abs        timerfd on CLOCK_REALTIME with TFD_TIMER_ABSTIME: moves
 *   tfd-cancel     the same with TFD_TIMER_CANCEL_ON_SET: its read answers ECANCELED at the
 *                  step, then the next read waits for the (moved) expiry
 *   tfd-rel        timerfd on CLOCK_REALTIME, relative: does not move
 *   tfd-mono       timerfd on CLOCK_MONOTONIC, relative: does not move
 * and at 19 s, abs-back: clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME) 3 s away, which the
 * -5 s step at 20 s moves 5 s later.
 * Linux documents this: clock_nanosleep(2) and clock_settime(2) (absolute CLOCK_REALTIME
 * sleeps follow a change of the clock, relative ones do not), timerfd_create(2)
 * (TFD_TIMER_CANCEL_ON_SET), pthread_cond_timedwait(3p). */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include "patina.h"

static struct timespec t0;

static long ms_since(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - t0.tv_sec) * 1000 + (t.tv_nsec - t0.tv_nsec) / 1000000;
}

static pthread_mutex_t out = PTHREAD_MUTEX_INITIALIZER;
static void say(const char *what, int r) {
    pthread_mutex_lock(&out);
    printf("%s: %ld ms, %s\n", what, ms_since(), r == 0 ? "0" : strerror(r));
    fflush(stdout);
    pthread_mutex_unlock(&out);
}

static struct timespec rt_in(long s) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec += s;
    return t;
}

static void *abs_sleep(void *a) {
    (void)a;
    struct timespec t = rt_in(10);
    say("abs-sleep", clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &t, NULL));
    return NULL;
}

static void *rel_sleep(void *a) {
    (void)a;
    struct timespec t = {10, 0};
    say("rel-sleep", clock_nanosleep(CLOCK_REALTIME, 0, &t, NULL));
    return NULL;
}

static void *cond(void *a) {
    (void)a;
    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t c = PTHREAD_COND_INITIALIZER; /* CLOCK_REALTIME */
    struct timespec t = rt_in(10);
    pthread_mutex_lock(&m);
    int r;
    do
        r = pthread_cond_timedwait(&c, &m, &t);
    while (r == 0);
    pthread_mutex_unlock(&m);
    say("cond", r);
    return NULL;
}

static void tfd(const char *what, int clock, int flags, long s) {
    int fd = timerfd_create(clock, 0);
    struct itimerspec v = {{0, 0}, {s, 0}};
    if (flags & TFD_TIMER_ABSTIME)
        v.it_value = rt_in(s);
    if (timerfd_settime(fd, flags, &v, NULL) != 0) {
        say(what, errno);
        return;
    }
    for (;;) {
        uint64_t n;
        ssize_t r = read(fd, &n, 8);
        if (r == 8) {
            say(what, 0);
            return;
        }
        say(what, errno);
        if (errno != ECANCELED)
            return;
    }
}

static void *tfd_abs(void *a) {
    (void)a;
    tfd("tfd-abs", CLOCK_REALTIME, TFD_TIMER_ABSTIME, 10);
    return NULL;
}
static void *tfd_cancel(void *a) {
    (void)a;
    tfd("tfd-cancel", CLOCK_REALTIME, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, 10);
    return NULL;
}
static void *tfd_rel(void *a) {
    (void)a;
    tfd("tfd-rel", CLOCK_REALTIME, 0, 10);
    return NULL;
}
static void *tfd_mono(void *a) {
    (void)a;
    tfd("tfd-mono", CLOCK_MONOTONIC, 0, 10);
    return NULL;
}

/* Realtime minus monotonic, in ms: moves by a step, not by time passing. */
static long gap(void) {
    struct timespec r, m;
    clock_gettime(CLOCK_REALTIME, &r);
    clock_gettime(CLOCK_MONOTONIC, &m);
    return (r.tv_sec - m.tv_sec) * 1000 + (r.tv_nsec - m.tv_nsec) / 1000000;
}

static void node(void) {
    void *(*f[])(void *) = {abs_sleep, rel_sleep, cond, tfd_abs, tfd_cancel, tfd_rel, tfd_mono};
    pthread_t th[8];
    int n = sizeof f / sizeof f[0];
    long g0 = gap();
    for (int i = 0; i < n; i++)
        pthread_create(&th[i], NULL, f[i], NULL);
    struct timespec s = {19, 0};
    clock_nanosleep(CLOCK_MONOTONIC, 0, &s, NULL);
    long g1 = gap();
    struct timespec t = rt_in(3);
    say("abs-back", clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &t, NULL));
    long g2 = gap();
    for (int i = 0; i < n; i++)
        pthread_join(th[i], NULL);
    printf("realtime - monotonic: %+ld ms after the first step, %+ld ms after the second\n",
           g1 - g0, g2 - g0);
}

static void driver(void) {
    struct timespec s = {1, 0};
    clock_nanosleep(CLOCK_MONOTONIC, 0, &s, NULL);
    long r = patina_control("clock step b +5s");
    s.tv_sec = 19;
    clock_nanosleep(CLOCK_MONOTONIC, 0, &s, NULL);
    long r2 = patina_control("clock step b -5s");
    s.tv_sec = 10;
    clock_nanosleep(CLOCK_MONOTONIC, 0, &s, NULL);
    printf("steps: %ld %ld\n", r, r2);
}

int main(int argc, char **argv) {
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (argc > 1 && strcmp(argv[1], "node") == 0)
        node();
    else
        driver();
    return 0;
}
