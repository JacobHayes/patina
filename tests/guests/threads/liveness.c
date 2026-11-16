// A thread sleeps 1 s in a loop forever; main joins it.
#include <pthread.h>
#include <time.h>

static void *sleeper(void *x) {
    (void)x;
    struct timespec t = {1, 0};
    for (;;) nanosleep(&t, NULL);
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, sleeper, NULL);
    pthread_join(t, NULL);
    return 0;
}
