/* PIDs, TIDs, exit/wait/SIGCHLD ordering: 300 children exiting in bursts (SIGCHLD handler
 * counting), 2,000 threads created and joined in batches, fork+exec churn; every pid, tid,
 * wait result and handler observation is printed or hashed. */
#define _GNU_SOURCE
#include "../common.h"
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static volatile int chld;
static uint64_t sh = FNV0;
static void on_chld(int s, siginfo_t *si, void *u) { (void)s; (void)u; chld++; sh = fnv_add(sh, &si->si_pid, 4); sh = fnv_add(sh, &si->si_status, 4); }
static void *thr(void *a) { long t = syscall(SYS_gettid); return (void *)(t ^ (long)a); }
int main(int argc, char **argv) {
    int kids = argc > 1 ? atoi(argv[1]) : 300, threads = argc > 2 ? atoi(argv[2]) : 2000;
    struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_sigaction = on_chld; sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGCHLD, &sa, 0);
    uint64_t h = FNV0;
    for (int burst = 0; burst < kids / 30; burst++) {
        pid_t p[30];
        for (int i = 0; i < 30; i++) {
            p[i] = fork();
            if (p[i] == 0) { for (int k = 0; k < (i * 7) % 5; k++) getppid(); _exit(i); }
        }
        for (int i = 0; i < 30; i++) {
            int st; pid_t r = waitpid(-1, &st, 0);
            h = fnv_add(h, &r, 4); h = fnv_add(h, &st, 4);
        }
        printf("burst %d pids %d..%d chld %d hash %016llx\n", burst, p[0], p[29], chld, (unsigned long long)h);
    }
    printf("children done chld=%d sighash %016llx\n", chld, (unsigned long long)sh);
    uint64_t th = FNV0;
    for (int b = 0; b < threads / 50; b++) {
        pthread_t t[50];
        for (int i = 0; i < 50; i++) pthread_create(&t[i], 0, thr, (void *)(long)i);
        for (int i = 0; i < 50; i++) { void *r; pthread_join(t[i], &r); th = fnv_add(th, &r, sizeof r); }
        if (b % 8 == 0) printf("threads batch %d hash %016llx\n", b, (unsigned long long)th);
    }
    printf("threads done hash %016llx\n", (unsigned long long)th);
    for (int i = 0; i < 20; i++) {
        pid_t c = fork();
        if (c == 0) { execl("/usr/bin/true", "true", (char *)0); _exit(127); }
        int st; waitpid(c, &st, 0); printf("exec %d pid %d st %x\n", i, c, st);
    }
    printf("self pid %d tid %ld ppid %d\n", getpid(), syscall(SYS_gettid), getppid());
    return 0;
}
