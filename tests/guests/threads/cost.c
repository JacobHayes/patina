// Cost probes, timed from outside by the wall clock of whole runs.
//   cost yield N        N x sched_yield (one call_sup round trip each)
//   cost mutex1 N       one thread: N x (lock; getppid; unlock)
//   cost mutex2 N       two threads, each N/2 x (lock; getppid; unlock): contended when a
//                       preemption draw at the getppid trap switches while the lock is held
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long iters, total;
static void *locker(void *a) {
    (void)a;
    for (long i = 0; i < iters; i++) {
        pthread_mutex_lock(&mu);
        total += getppid() >= 0;
        pthread_mutex_unlock(&mu);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    long n = atol(argv[2]);
    if (!strcmp(argv[1], "yield")) {
        for (long i = 0; i < n; i++) sched_yield();
    } else if (!strcmp(argv[1], "mutex1")) {
        iters = n;
        locker(NULL);
    } else if (!strcmp(argv[1], "mutex2")) {
        iters = n / 2;
        pthread_t a, b;
        pthread_create(&a, NULL, locker, NULL);
        pthread_create(&b, NULL, locker, NULL);
        pthread_join(a, NULL);
        pthread_join(b, NULL);
    } else {
        return 2;
    }
    printf("%s %ld done %ld\n", argv[1], n, total);
    return 0;
}
