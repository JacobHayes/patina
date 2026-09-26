/*
 * A C guest's pthread_exit and cancellation (glibc 2.39). With no argument:
 * the unwind runs the C cleanup handler pthread_cleanup_push registered (the
 * setjmp form C compiles to), and pthread_join answers the value. The other
 * modes end the worker where glibc does and patina stops by name instead:
 * - "handler": pthread_exit inside a SIGUSR1 handler;
 * - "cancel-handler": a pending cancel acting at pthread_testcancel inside a
 *   SIGUSR1 handler;
 * - "cancel-write": a pending cancel at a write that does not block;
 * - "cancel-self-join": a pending cancel at a join of the thread itself,
 *   which glibc waits in (and so acts) instead of answering EDEADLK.
 * Natively each joins as PTHREAD_CANCELED (-1) or the signal number. And
 * "cancel-join" is where glibc does not act, and neither does patina: the
 * join of a thread already ended waits for nothing (nptl
 * pthread_join_common.c), so a pending cancel lets it return, value 0.
 */
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

static void cancel_from_handler(int sig) {
    (void)sig;
    pthread_testcancel();
}

static void *cancel_handler_worker(void *arg) {
    (void)arg;
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = cancel_from_handler;
    sigaction(SIGUSR1, &action, NULL);
    pthread_cancel(pthread_self());
    raise(SIGUSR1);
    return NULL;
}

static void *cancel_write_worker(void *arg) {
    (void)arg;
    pthread_cancel(pthread_self());
    if (write(1, "NATIVE_PTHREAD_EXIT not canceled\n", 33) < 0) return NULL;
    return NULL;
}

static void *cancel_self_join_worker(void *arg) {
    (void)arg;
    pthread_cancel(pthread_self());
    pthread_join(pthread_self(), NULL);
    return NULL;
}

static void *ended(void *arg) {
    return arg;
}

static void *cancel_join_worker(void *arg) {
    (void)arg;
    pthread_t other;
    if (pthread_create(&other, NULL, ended, NULL) != 0) return NULL;
    struct timespec pause = {0, 1000000};
    nanosleep(&pause, NULL);
    pthread_cancel(pthread_self());
    pthread_join(other, NULL);
    return NULL;
}

int main(int argc, char **argv) {
    static const struct {
        const char *mode;
        void *(*start)(void *);
    } modes[] = {
        {"handler", handler_worker},
        {"cancel-handler", cancel_handler_worker},
        {"cancel-write", cancel_write_worker},
        {"cancel-self-join", cancel_self_join_worker},
        {"cancel-join", cancel_join_worker},
    };
    void *(*start)(void *) = worker;
    for (size_t i = 0; argc > 1 && i < sizeof modes / sizeof modes[0]; ++i) {
        if (strcmp(argv[1], modes[i].mode) == 0) start = modes[i].start;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, start, (void *)41) != 0) return 1;
    void *value = NULL;
    if (pthread_join(thread, &value) != 0) return 2;
    printf("NATIVE_PTHREAD_EXIT value=%d\n", (int)(intptr_t)value);
    return 0;
}
