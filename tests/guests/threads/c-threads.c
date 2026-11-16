// C pthreads: mutex counter, condition-variable ping-pong, barrier, join, a
// detached thread, nanosleep, and a pthread_cond_timedwait whose 30 s timeout expires.
// Prints one line per check; exit 1 with an INVARIANT line on stderr if a check fails.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static int bad;
#define CHECK(c, ...) do { if (!(c)) { fprintf(stderr, "INVARIANT " __VA_ARGS__); fputc('\n', stderr); bad = 1; } } while (0)

static int64_t now_ns(clockid_t c) {
    struct timespec t;
    clock_gettime(c, &t);
    return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

// 1. counter
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long counter;
#define NT 8
#define ITER 2000
static void *incr(void *a) {
    (void)a;
    for (int i = 0; i < ITER; i++) {
        pthread_mutex_lock(&mu);
        counter++;
        pthread_mutex_unlock(&mu);
        if (i % 100 == 0) sched_yield();
    }
    return NULL;
}

// 2. ping-pong
static pthread_mutex_t pm = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pc = PTHREAD_COND_INITIALIZER;
static int turn, rounds_done;
#define ROUNDS 200
static char trace[2 * ROUNDS + 1];
static int ntrace;
static void *pingpong(void *a) {
    int me = (int)(intptr_t)a;
    for (int i = 0; i < ROUNDS; i++) {
        pthread_mutex_lock(&pm);
        while (turn != me) pthread_cond_wait(&pc, &pm);
        trace[ntrace++] = me ? 'o' : 'i';
        turn = !me;
        rounds_done++;
        pthread_cond_broadcast(&pc);
        pthread_mutex_unlock(&pm);
    }
    return NULL;
}

// 3. barrier
#define NB 4
#define PHASES 5
static pthread_barrier_t bar;
static int phase_seen[NB][PHASES];
static int phase;
static pthread_mutex_t bm = PTHREAD_MUTEX_INITIALIZER;
static void *barrier_worker(void *a) {
    int me = (int)(intptr_t)a;
    for (int p = 0; p < PHASES; p++) {
        pthread_mutex_lock(&bm);
        phase_seen[me][p] = phase;
        pthread_mutex_unlock(&bm);
        if (pthread_barrier_wait(&bar) == PTHREAD_BARRIER_SERIAL_THREAD) {
            pthread_mutex_lock(&bm);
            phase++;
            pthread_mutex_unlock(&bm);
        }
        pthread_barrier_wait(&bar);
    }
    return NULL;
}

// 4. detached
static pthread_mutex_t dm = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t dc = PTHREAD_COND_INITIALIZER;
static int detached_done;
static void *detached(void *a) {
    (void)a;
    struct timespec t = {0, 5 * 1000 * 1000};
    nanosleep(&t, NULL);
    pthread_mutex_lock(&dm);
    detached_done = 42;
    pthread_cond_signal(&dc);
    pthread_mutex_unlock(&dm);
    return NULL;
}

int main(void) {
    int64_t wall0 = now_ns(CLOCK_MONOTONIC);
    pthread_t t[NT];
    for (int i = 0; i < NT; i++) pthread_create(&t[i], NULL, incr, NULL);
    for (int i = 0; i < NT; i++) pthread_join(t[i], NULL);
    printf("counter %ld\n", counter);
    CHECK(counter == NT * ITER, "counter %ld", counter);

    pthread_t p0, p1;
    pthread_create(&p0, NULL, pingpong, (void *)0);
    pthread_create(&p1, NULL, pingpong, (void *)1);
    pthread_join(p0, NULL);
    pthread_join(p1, NULL);
    int alternates = 1;
    for (int i = 0; i < ntrace; i++) alternates &= trace[i] == (i % 2 ? 'o' : 'i');
    printf("pingpong %d rounds alternating %d\n", rounds_done, alternates);
    CHECK(rounds_done == 2 * ROUNDS && alternates, "pingpong");

    pthread_barrier_init(&bar, NULL, NB);
    pthread_t b[NB];
    for (int i = 0; i < NB; i++) pthread_create(&b[i], NULL, barrier_worker, (void *)(intptr_t)i);
    for (int i = 0; i < NB; i++) pthread_join(b[i], NULL);
    int ok = 1;
    for (int i = 0; i < NB; i++)
        for (int p = 0; p < PHASES; p++) ok &= phase_seen[i][p] == p;
    printf("barrier phases %d ok %d\n", phase, ok);
    CHECK(ok && phase == PHASES, "barrier");

    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_t d;
    pthread_create(&d, &at, detached, NULL);
    pthread_mutex_lock(&dm);
    while (!detached_done) pthread_cond_wait(&dc, &dm);
    pthread_mutex_unlock(&dm);
    printf("detached %d\n", detached_done);
    CHECK(detached_done == 42, "detached");

    int64_t s0 = now_ns(CLOCK_MONOTONIC);
    struct timespec ts = {0, 250 * 1000 * 1000};
    int r = nanosleep(&ts, NULL);
    int64_t slept = now_ns(CLOCK_MONOTONIC) - s0;
    printf("nanosleep rc %d ns %lld\n", r, (long long)slept);
    CHECK(r == 0 && slept >= 250000000 && slept < 251000000, "nanosleep %lld", (long long)slept);

    pthread_mutex_t tm = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t tc = PTHREAD_COND_INITIALIZER;
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += 30;
    pthread_mutex_lock(&tm);
    int64_t w0 = now_ns(CLOCK_MONOTONIC);
    r = pthread_cond_timedwait(&tc, &tm, &dl);
    int64_t waited = now_ns(CLOCK_MONOTONIC) - w0;
    pthread_mutex_unlock(&tm);
    printf("timedwait rc %s ns %lld\n", r == ETIMEDOUT ? "ETIMEDOUT" : "other", (long long)waited);
    CHECK(r == ETIMEDOUT && waited >= 30000000000LL && waited < 30100000000LL, "timedwait %d %lld", r, (long long)waited);
    printf("virtual elapsed ns %lld\n", (long long)(now_ns(CLOCK_MONOTONIC) - wall0));
    return bad;
}
