/* blocking I/O item 7: two threads contend for flock and for F_OFD_SETLKW on one file; inside the
 * critical section they make syscalls (switch points); mutual exclusion must hold. */
#include "common.h"
#include <sys/file.h>

enum { ITER = 200 };
static const char *F = "/work/lockfile";
static int inside, violations, mode;
static long entries;

static void lock(int fd, int on) {
    if (mode == 0) {
        CHECK(flock(fd, on ? LOCK_EX : LOCK_UN) == 0, "flock");
    } else {
        struct flock l = {.l_type = on ? F_WRLCK : F_UNLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0};
        CHECK(fcntl(fd, on ? F_OFD_SETLKW : F_OFD_SETLK, &l) == 0, "ofd lock");
    }
}

static void *contender(void *x) {
    (void)x;
    int fd = open(F, O_RDWR);
    CHECK(fd >= 0, "open");
    for (int i = 0; i < ITER; i++) {
        lock(fd, 1);
        if (inside) violations++;
        inside = 1;
        entries++;
        getppid();
        sched_yield();
        getppid();
        inside = 0;
        lock(fd, 0);
        sched_yield();
    }
    close(fd);
    return NULL;
}

int main(void) {
    int fd = open(F, O_RDWR | O_CREAT, 0600);
    CHECK(fd >= 0, "create");
    close(fd);
    const char *names[2] = {"flock", "ofd"};
    for (mode = 0; mode < 2; mode++) {
        pthread_t a, b;
        entries = violations = 0;
        spawn(&a, contender, NULL);
        spawn(&b, contender, NULL);
        pthread_join(a, NULL);
        pthread_join(b, NULL);
        printf("%s entries %ld violations %d\n", names[mode], entries, violations);
        CHECK(violations == 0 && entries == 2 * ITER, "mutual exclusion");
    }
    return 0;
}
