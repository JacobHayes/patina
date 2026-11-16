/* blocking I/O item 6: a thread blocked reading a pipe nobody writes; every other thread has
 * exited (the write end stays open). Expected outcome: deadlock naming the descriptor. */
#include "common.h"

static int p[2];
static void *reader(void *x) {
    (void)x;
    char b;
    ssize_t r = read(p[0], &b, 1);
    printf("unexpected read %zd\n", r);
    return NULL;
}

int main(void) {
    CHECK(pipe(p) == 0, "pipe");
    printf("read fd %d\n", p[0]);
    fflush(stdout);
    pthread_t t;
    spawn(&t, reader, NULL);
    pthread_exit(NULL);
}
