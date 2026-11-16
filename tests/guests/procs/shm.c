/* Futexes in memory shared across fork.
 * A process-shared pthread mutex and condition variable in MAP_SHARED|MAP_ANONYMOUS memory:
 * parent and child take turns incrementing a counter 200 times each, signalling the other.
 * Then a POSIX named semaphore (/dev/shm): the child posts 100 times after its own work, the
 * parent waits 100 times. Prints the shared trace. */
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

struct shared {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int turn, counter;
    char trace[1024];
    int tlen;
};

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct shared *s = mmap(NULL, sizeof *s, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (s == MAP_FAILED) return 1;
    pthread_mutexattr_t ma;
    pthread_condattr_t ca;
    pthread_mutexattr_init(&ma), pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED);
    pthread_condattr_init(&ca), pthread_condattr_setpshared(&ca, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&s->mu, &ma);
    pthread_cond_init(&s->cv, &ca);
    pid_t c = fork();
    int me = c == 0 ? 1 : 0;
    for (int i = 0; i < 200; i++) {
        pthread_mutex_lock(&s->mu);
        while (s->turn != me) pthread_cond_wait(&s->cv, &s->mu);
        s->counter++;
        if (s->tlen < (int)sizeof s->trace - 1 && i % 20 == 0) s->trace[s->tlen++] = me ? 'c' : 'p';
        s->turn = !me;
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
    }
    if (c == 0) _exit(0);
    int st;
    waitpid(c, &st, 0);
    printf("mutex/cond: counter=%d trace=%s child status=%d\n", s->counter, s->trace, st);

    sem_unlink("/patina-procs");
    sem_t *sem = sem_open("/patina-procs", O_CREAT | O_EXCL, 0600, 0);
    if (sem == SEM_FAILED) {
        perror("sem_open");
        return 1;
    }
    c = fork();
    if (c == 0) {
        sem_t *cs = sem_open("/patina-procs", 0);
        for (int i = 0; i < 100; i++) {
            usleep(10);
            sem_post(cs);
        }
        _exit(0);
    }
    int got = 0;
    for (int i = 0; i < 100; i++) got += sem_wait(sem) == 0;
    waitpid(c, &st, 0);
    int v = -1;
    sem_getvalue(sem, &v);
    sem_unlink("/patina-procs");
    printf("semaphore: waits=%d value=%d child status=%d\n", got, v, st);
    if (s->counter != 400 || got != 100 || v != 0) {
        fprintf(stderr, "INVARIANT shm\n");
        return 1;
    }
    return 0;
}
