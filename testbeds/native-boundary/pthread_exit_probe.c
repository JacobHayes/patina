/*
 * A C guest's pthread_exit (glibc 2.39). With no argument: the unwind runs
 * the C cleanup handler pthread_cleanup_push registered (the setjmp form C
 * compiles to), and pthread_join answers the value. With "handler": the
 * worker leaves from inside a SIGUSR1 handler, which glibc allows.
 */
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void cleanup(void *arg) {
    printf("NATIVE_PTHREAD_EXIT cleanup=%d\n", (int)(intptr_t)arg);
}

static void *worker(void *arg) {
    pthread_cleanup_push(cleanup, (void *)7);
    pthread_exit((void *)((intptr_t)arg + 1));
    pthread_cleanup_pop(0);
    return NULL;
}

static void exit_from_handler(int sig) {
    pthread_exit((void *)(intptr_t)sig);
}

static void *handler_worker(void *arg) {
    (void)arg;
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = exit_from_handler;
    sigaction(SIGUSR1, &action, NULL);
    raise(SIGUSR1);
    return NULL;
}

int main(int argc, char **argv) {
    void *(*start)(void *) = worker;
    if (argc > 1 && strcmp(argv[1], "handler") == 0) start = handler_worker;
    pthread_t thread;
    if (pthread_create(&thread, NULL, start, (void *)41) != 0) return 1;
    void *value = NULL;
    if (pthread_join(thread, &value) != 0) return 2;
    printf("NATIVE_PTHREAD_EXIT value=%d\n", (int)(intptr_t)value);
    return 0;
}
