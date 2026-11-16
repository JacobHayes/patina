// N threads (argv[1], default 8) each append their id K times (argv[2], default 4)
// to a shared log under a mutex, yielding between appends. Prints the log.
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static char logbuf[4096];
static int n, k, len;

static void *worker(void *a) {
    int id = (int)(intptr_t)a;
    for (int i = 0; i < k; i++) {
        pthread_mutex_lock(&mu);
        logbuf[len++] = (char)('a' + id);
        pthread_mutex_unlock(&mu);
        sched_yield();
    }
    return NULL;
}

int main(int argc, char **argv) {
    n = argc > 1 ? atoi(argv[1]) : 8;
    k = argc > 2 ? atoi(argv[2]) : 4;
    pthread_t t[26];
    for (int i = 0; i < n; i++) pthread_create(&t[i], NULL, worker, (void *)(intptr_t)i);
    for (int i = 0; i < n; i++) pthread_join(t[i], NULL);
    printf("%s\n", logbuf);
    if (len != n * k) {
        fprintf(stderr, "INVARIANT log length %d\n", len);
        return 1;
    }
    return 0;
}
