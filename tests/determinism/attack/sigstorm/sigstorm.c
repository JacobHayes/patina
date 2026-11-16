/* 10,000 signals between threads and processes; each handler records the receiver's own
 * event counter at delivery (its loop iteration count), all hashed. */
#define _GNU_SOURCE
#include "../common.h"
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static __thread volatile long counter;
static __thread uint64_t th = FNV0;
static __thread int got;
static void on_sig(int s) { long c = counter; th = fnv_add(th, &c, sizeof c); th = fnv_add(th, &s, sizeof s); got++; }
static volatile int tids[4];
static volatile int stop;
static void *worker(void *a) {
    long i = (long)a; tids[i] = syscall(SYS_gettid);
    while (!stop) { counter++; if (counter % 3 == 0) getppid(); }
    printf("thread %ld got %d hash %016llx\n", i, got, (unsigned long long)th);
    return 0;
}
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 10000;
    struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = on_sig; sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, 0); sigaction(SIGUSR2, &sa, 0);
    pthread_t t[4];
    for (long i = 0; i < 4; i++) pthread_create(&t[i], 0, worker, (void *)i);
    while (!tids[0] || !tids[1] || !tids[2] || !tids[3]) sched_yield();
    pid_t c = fork();
    if (c == 0) {
        for (int i = 0; i < n / 2; i++) { counter++; if (i % 2) getppid(); }
        printf("child got %d hash %016llx\n", got, (unsigned long long)th); fflush(stdout); _exit(0);
    }
    for (int i = 0; i < n / 2; i++) {
        syscall(SYS_tgkill, getpid(), tids[i % 4], (i & 1) ? SIGUSR1 : SIGUSR2);
        if (i % 5 == 0) kill(c, SIGUSR1);
        counter++;
    }
    int st; waitpid(c, &st, 0);
    stop = 1;
    for (int i = 0; i < 4; i++) pthread_join(t[i], 0);
    printf("main got %d hash %016llx child st %x\n", got, (unsigned long long)th, st);
    return 0;
}
