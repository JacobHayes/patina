// Two threads take two mutexes in opposite order; a barrier forces both to hold
// their first mutex before either asks for its second. Never finishes.
#include <pthread.h>
#include <stdio.h>

static pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER, m2 = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t bar;

static void *a(void *x) {
    (void)x;
    pthread_mutex_lock(&m1);
    pthread_barrier_wait(&bar);
    pthread_mutex_lock(&m2);
    return NULL;
}
static void *b(void *x) {
    (void)x;
    pthread_mutex_lock(&m2);
    pthread_barrier_wait(&bar);
    pthread_mutex_lock(&m1);
    return NULL;
}

int main(void) {
    pthread_barrier_init(&bar, NULL, 2);
    pthread_t ta, tb;
    pthread_create(&ta, NULL, a, NULL);
    pthread_create(&tb, NULL, b, NULL);
    printf("m1 %p m2 %p\n", (void *)&m1, (void *)&m2);
    fflush(stdout);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    return 0;
}
