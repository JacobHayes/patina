/* memfault (static): memory requests that can fail with ENOMEM, and a thread creation that
 * can fail with EAGAIN. Every failure is handled: the guest reports it and carries on.
 *
 * Prints one line per step: "step K KIND ok|ENOMEM|EAGAIN", then "done".
 *   steps 0-4:  mmap of 1 MiB, anonymous
 *   steps 5-9:  malloc of 256 KiB (served by mmap; glibc may fall back to brk)
 *   step 10:    pthread_create
 *
 * memfault limit: map 1 MiB at a time (writable, touched) up to 100 MiB; print
 * "limit: ENOMEM at MiB K" for the first refused one (or "limit: none"), then try a
 * malloc of 2 MiB ("malloc ok|ENOMEM"), then "done".
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void *worker(void *a) { return a; }

static int limit(void) {
    int k;
    for (k = 0; k < 100; k++) {
        char *p = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            printf("limit: %s at MiB %d\n", strerrorname_np(errno), k);
            break;
        }
        p[0] = 1;
    }
    if (k == 100) printf("limit: none\n");
    errno = 0;
    char *volatile m = malloc(2 << 20); /* volatile: the compiler may not elide the call */
    printf("malloc %s\n", m ? "ok" : strerrorname_np(errno));
    printf("done\n");
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 1 && strcmp(argv[1], "limit") == 0) return limit();
    int k = 0;
    for (int i = 0; i < 5; i++, k++) {
        void *p = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            printf("step %d mmap %s\n", k, strerrorname_np(errno));
        } else {
            memset(p, 1, 4096);
            printf("step %d mmap ok\n", k);
        }
    }
    for (int i = 0; i < 5; i++, k++) {
        errno = 0;
        char *p = malloc(256 << 10);
        if (!p) {
            printf("step %d malloc %s\n", k, strerrorname_np(errno));
        } else {
            p[0] = 1;
            printf("step %d malloc ok\n", k);
        }
    }
    pthread_t t;
    int r = pthread_create(&t, NULL, worker, NULL);
    if (r != 0) {
        printf("step %d thread %s\n", k, strerrorname_np(r));
    } else {
        pthread_join(t, NULL);
        printf("step %d thread ok\n", k);
    }
    printf("done\n");
    return 0;
}
