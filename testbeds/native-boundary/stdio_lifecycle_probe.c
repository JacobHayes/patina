/*
 * The C streams across the edges of a run: the end of `main` and a run patina
 * refuses. Each case is selected by argv[1]; `native_abi` runs the same source
 * natively (unlinked) and under the shim, and compares where the host is the
 * oracle.
 *
 * - teardown: a thread printing in a loop while `main` exits; an atexit
 *   handler then prints. Only the root task runs after `main`, so the handler
 *   must neither wait for the printing thread nor refuse the run.
 * - errno: the first write to stdout leaves errno as it found it.
 * - deadlock: buffered output, then a run patina refuses (a normal mutex
 *   relocked by its holder): the output reaches the capture before the abort.
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void at_end(void) { printf("atexit handler says bye\n"); }

static void *printing(void *unused) {
    (void)unused;
    for (int i = 0;; ++i) printf("log %d\n", i);
    return NULL;
}

static int teardown(void) {
    atexit(at_end);
    pthread_t thread;
    if (pthread_create(&thread, NULL, printing, NULL) != 0) return 1;
    for (int i = 0; i < 50; ++i) printf("main %d\n", i);
    exit(0);
}

static int first_write_errno(void) {
    errno = 0;
    printf("first line\n");
    int seen = errno;
    printf("errno after the first write: %d\n", seen);
    return 0;
}

static int deadlock(void) {
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    printf("progress before the refusal\n");
    pthread_mutex_lock(&mutex);
    pthread_mutex_lock(&mutex);
    printf("unreachable\n");
    return 0;
}

int main(int argc, char **argv) {
    const char *which = argc > 1 ? argv[1] : "";
    if (strcmp(which, "teardown") == 0) return teardown();
    if (strcmp(which, "errno") == 0) return first_write_errno();
    if (strcmp(which, "deadlock") == 0) return deadlock();
    fprintf(stderr, "unknown case: %s\n", which);
    return 2;
}
