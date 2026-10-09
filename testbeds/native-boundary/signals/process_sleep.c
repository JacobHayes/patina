/* Class pairing: native_signals' interruption and internal-fatal detectors.
 * Shared POSIX process answers and non-interrupted sleep must work without SUD,
 * including on Darwin; no Linux signal-delivery semantics are assumed here. */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(void) {
#ifdef __APPLE__
    /* The exported-boundary ownership matrix pairs this previously uncovered
     * Darwin adapter with a real caller, including its invalid output case. */
    uint64_t thread_id = 0, current_id = 0;
    assert(pthread_threadid_np(NULL, &thread_id) == 0 && thread_id != 0);
    assert(pthread_threadid_np(pthread_self(), &current_id) == 0);
    assert(current_id == thread_id);
    assert(pthread_threadid_np(NULL, NULL) == EINVAL);
#endif
    int status = 123;
    errno = 0;
    assert(waitpid(-1, &status, WNOHANG) == -1);
    assert(errno == ECHILD);
    assert(status == 123);
    /* The parent is the pid namespace's init. */
    assert(getppid() == 1);
    struct timespec before, after;
    assert(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    assert(sleep(2) == 0);
    assert(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    /* The sleep, and the calls charged around it. */
    const int64_t slept = (int64_t)(after.tv_sec - before.tv_sec) * 1000000000 +
                          (after.tv_nsec - before.tv_nsec);
    assert(slept >= 2000000000 && slept < 2001000000);
    puts("PROCESS_SLEEP_OK");
    return 0;
}
