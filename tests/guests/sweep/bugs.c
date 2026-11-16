/* The sweep guest: two planted bugs, each switchable.
 *   bugs [race] [fserr] [never]
 *     race   two threads increment a counter with a read, a system call and a write, and an
 *            `always` checks the total: on some schedules an update is lost
 *     fserr  a write or fsync error on /work/data exits 3 instead of being retried
 *     never  a `sometimes` (rare-state) that never holds
 *     point  a fault point (tried-point) evaluated 50 times; it changes nothing
 *   Without a word, the same work done right: the increment is atomic and errors are retried.
 *   cat FILE   print FILE and exit 4 (a failure whose evidence is a host file) */
#include "patina.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int race, fserr, never, point;
static volatile long counter;
static long written;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static void *bump(void *arg) {
    (void)arg;
    for (int i = 0; i < 10; i++) {
        if (race) {
            long v = counter;
            getppid(); /* a system call between the read and the write */
            counter = v + 1;
        } else {
            pthread_mutex_lock(&mu);
            counter++;
            pthread_mutex_unlock(&mu);
        }
    }
    return 0;
}

static void store(void) {
    for (int attempt = 0; attempt < 100; attempt++) {
        int fd = open("/work/data", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) continue;
        static const char data[] = "0123456789abcdef0123456789abcdef0123456789abcdef";
        int ok = 1;
        for (int i = 0; i < 20 && ok; i++) {
            /* A short write is not an error: write the rest. */
            for (size_t off = 0; ok && off < sizeof data;) {
                ssize_t n = write(fd, data + off, sizeof data - off);
                ok = n > 0;
                off += ok ? (size_t)n : 0;
                written += ok ? n : 0;
            }
        }
        ok = ok && fsync(fd) == 0;
        close(fd);
        if (ok) return;
        if (fserr) {
            /* Numbers that vary by seed: the signature collapses them. */
            fprintf(stderr, "store failed after %ld bytes\n", written);
            exit(3);
        }
    }
    exit(5);
}

int main(int argc, char **argv) {
    if (argc > 2 && !strcmp(argv[1], "cat")) {
        char buf[256];
        int fd = open(argv[2], O_RDONLY);
        ssize_t n = fd < 0 ? 0 : read(fd, buf, sizeof buf);
        if (n > 0) fwrite(buf, 1, (size_t)n, stdout);
        return 4;
    }
    for (int i = 1; i < argc; i++) {
        race |= !strcmp(argv[i], "race");
        fserr |= !strcmp(argv[i], "fserr");
        never |= !strcmp(argv[i], "never");
        point |= !strcmp(argv[i], "point");
    }
    pthread_t t[2];
    for (int i = 0; i < 2; i++) pthread_create(&t[i], 0, bump, 0);
    for (int i = 0; i < 2; i++) pthread_join(t[i], 0);
    PATINA_ALWAYS(counter == 20, "no-lost-update", "an increment was lost");
    PATINA_SOMETIMES(counter == 20, "all-counted");
    /* Holds on every run unless "never" asks for a state that cannot happen. */
    PATINA_SOMETIMES(never ? counter > 100 : counter == 20, "rare-state");
    for (int i = 0; point && i < 50; i++) (void)PATINA_BUGGIFY("tried-point");
    store();
    return 0;
}
