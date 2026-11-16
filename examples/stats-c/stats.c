/* Four worker threads take jobs from a queue under a lock and checksum each job's data. After
 * each job a worker updates the shared statistics: it reads the count of finished jobs, folds
 * its checksum into the running mean, and writes the count back plus one.
 *
 * The bug: the statistics are updated without the lock. Two workers that update them at the
 * same time both read the same count, and one job is lost. Nothing in that update makes a
 * system call, so a stock build runs it the same way on every seed. `stats fixed` takes the
 * lock for the update. */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { WORKERS = 4, JOBS = 200, WORDS = 2000 };

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int next_job;
static int fixed;
static struct {
    long done;
    double mean;
} stats;

static uint64_t checksum(int job) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < WORDS; i++) h = (h ^ (uint64_t)(job * WORDS + i)) * 1099511628211ULL;
    return h;
}

static void *worker(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&lock);
        int job = next_job < JOBS ? next_job++ : -1;
        pthread_mutex_unlock(&lock);
        if (job < 0) return NULL;
        double sum = (double)(checksum(job) >> 40);
        if (fixed) pthread_mutex_lock(&lock);
        long done = stats.done;
        stats.mean = (stats.mean * done + sum) / (done + 1);
        stats.done = done + 1;
        if (fixed) pthread_mutex_unlock(&lock);
    }
}

int main(int argc, char **argv) {
    fixed = argc > 1 && strcmp(argv[1], "fixed") == 0;
    pthread_t t[WORKERS];
    for (int i = 0; i < WORKERS; i++) pthread_create(&t[i], NULL, worker, NULL);
    for (int i = 0; i < WORKERS; i++) pthread_join(t[i], NULL);
    printf("%ld of %d jobs counted, mean %.0f\n", stats.done, JOBS, stats.mean);
    if (stats.done != JOBS) {
        fprintf(stderr, "lost updates: %ld of %d jobs counted\n", stats.done, JOBS);
        return 1;
    }
    return 0;
}
