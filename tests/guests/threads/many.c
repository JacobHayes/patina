// Create and join TOTAL threads (argv[1], default 5000) in batches of 50; print
// every thread's kernel tid, in creation order.
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static pid_t *tids;
static void *worker(void *a) {
    tids[(intptr_t)a] = gettid();
    return NULL;
}

int main(int argc, char **argv) {
    int total = argc > 1 ? atoi(argv[1]) : 5000;
    tids = calloc(total, sizeof *tids);
    pthread_t t[50];
    for (int base = 0; base < total; base += 50) {
        int n = total - base < 50 ? total - base : 50;
        for (int i = 0; i < n; i++)
            if (pthread_create(&t[i], NULL, worker, (void *)(intptr_t)(base + i)) != 0) {
                fprintf(stderr, "INVARIANT pthread_create failed at %d\n", base + i);
                return 1;
            }
        for (int i = 0; i < n; i++) pthread_join(t[i], NULL);
    }
    for (int i = 0; i < total; i++) printf("%d\n", tids[i]);
    return 0;
}
