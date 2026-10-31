/*
 * A finished thread's teardown and the threads still running. The task of a
 * managed thread completes as its start routine ends (glibc: from its
 * thread-local destructor pass); what the C library runs on the thread after
 * it (the pthread_key destructors, the allocator's thread shutdown, the
 * thread's exit) is host code on no task. Here a key destructor computes for a while, then publishes a flag,
 * while main yields until it sees the flag and counts its yields. Natively
 * the count is the host's. Under patina no task may run beside that
 * teardown, so the count is the same on every run of a seed and on its
 * replay.
 */
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>

static pthread_key_t key;
static atomic_int published;

static void destructor(void *value) {
    volatile unsigned long spin = 0;
    for (unsigned long i = 0; i < 20000000UL; i++) {
        spin += i;
    }
    (void)value;
    atomic_store(&published, 1);
}

static void *worker(void *arg) {
    pthread_setspecific(key, arg);
    return NULL;
}

int main(void) {
    if (pthread_key_create(&key, destructor) != 0) {
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, &key) != 0) {
        return 1;
    }
    unsigned long yields = 0;
    while (!atomic_load(&published)) {
        sched_yield();
        yields++;
    }
    if (pthread_join(thread, NULL) != 0) {
        return 1;
    }
    printf("NATIVE_THREAD_TEARDOWN yields=%lu\n", yields);
    return 0;
}
