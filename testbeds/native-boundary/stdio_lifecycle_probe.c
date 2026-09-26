/*
 * The C streams across the edges of a run: the end of `main` and a run patina
 * refuses. Each case is selected by argv[1]; `native_abi` runs the same source
 * natively (unlinked) and under the shim, and compares where the host is the
 * oracle.
 *
 * - teardown: a thread printing in a loop while `main` exits; an atexit
 *   handler then prints. Only the root task runs after `main`, so the handler
 *   must neither wait for the printing thread nor refuse the run.
 * - env-teardown: the same with `setenv` and the environment's lock.
 * - errno: the first write to stdout leaves errno as it found it.
 * - deadlock: buffered output, then a run patina refuses (a normal mutex
 *   relocked by its holder): the output reaches the capture before the abort.
 * - zoneinfo: the same before another refusal, `localtime_r` over a zoneinfo
 *   file the guest put at /etc/localtime.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

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

static void env_at_end(void) {
    setenv("PROBE_AT_EXIT", "bye", 1);
    printf("atexit handler set %s\n", getenv("PROBE_AT_EXIT"));
}

static void *setting(void *unused) {
    (void)unused;
    for (int i = 0;; ++i) setenv("PROBE_THREAD", i % 2 ? "odd" : "even", 1);
    return NULL;
}

static int env_teardown(void) {
    atexit(env_at_end);
    pthread_t thread;
    if (pthread_create(&thread, NULL, setting, NULL) != 0) return 1;
    for (int i = 0; i < 50; ++i) setenv("PROBE_MAIN", i % 2 ? "odd" : "even", 1);
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

static int zoneinfo(void) {
    printf("progress before the refusal\n");
    mkdir("/etc", 0755);
    int fd = open("/etc/localtime", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0 || write(fd, "TZif", 4) != 4 || close(fd) != 0) return 1;
    time_t now = 0;
    struct tm local;
    localtime_r(&now, &local);
    printf("unreachable\n");
    return 0;
}

int main(int argc, char **argv) {
    const char *which = argc > 1 ? argv[1] : "";
    if (strcmp(which, "teardown") == 0) return teardown();
    if (strcmp(which, "env-teardown") == 0) return env_teardown();
    if (strcmp(which, "errno") == 0) return first_write_errno();
    if (strcmp(which, "deadlock") == 0) return deadlock();
    if (strcmp(which, "zoneinfo") == 0) return zoneinfo();
    fprintf(stderr, "unknown case: %s\n", which);
    return 2;
}
