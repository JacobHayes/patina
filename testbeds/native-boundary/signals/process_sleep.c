/* Class pairing: native_signals' interruption and internal-fatal detectors.
 * Shared POSIX process answers and non-interrupted sleep must work without SUD,
 * including on Darwin; no Linux signal-delivery semantics are assumed here. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    int status = 123;
    errno = 0;
    assert(waitpid(-1, &status, WNOHANG) == -1);
    assert(errno == ECHILD);
    assert(status == 123);
    assert(getppid() == 2);
    struct timespec before, after;
    assert(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    assert(sleep(2) == 0);
    assert(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    assert(after.tv_sec - before.tv_sec == 2);
    assert(after.tv_nsec == before.tv_nsec);
    puts("PROCESS_SLEEP_OK");
    return 0;
}
