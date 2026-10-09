/* Class pairing: when a libc door's errno is written relative to the
 * handlers its call ran (src/abi.rs set_host_errno, c/posix/delivery.c). A
 * second thread interrupts the main thread blocked in syscall(SYS_read) on
 * an empty pipe. `entry`: without SA_RESTART, the handler sees the errno the
 * call met (glibc's syscall.S writes EINTR after the kernel's return ran
 * it), and the call then fails EINTR. `restart`: under SA_RESTART the
 * handler sets errno and the restarted read succeeds on the later write, so
 * the handler's errno stands. Each case prints what it saw. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static pthread_t main_thread;
static int fds[2];
static volatile int seen = -1;

static void on_usr1(int sig) {
    (void)sig;
    seen = errno;
    errno = ERANGE;
}

static void pause_ms(long ms) {
    struct timespec wait = {0, ms * 1000000L};
    nanosleep(&wait, NULL);
}

static void *interrupt(void *write_after) {
    pause_ms(50);
    assert(pthread_kill(main_thread, SIGUSR1) == 0);
    if (write_after) {
        pause_ms(50);
        assert(write(fds[1], "x", 1) == 1);
    }
    return NULL;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    int restart = strcmp(argv[1], "restart") == 0;
    assert(restart || strcmp(argv[1], "entry") == 0);
    main_thread = pthread_self();
    assert(pipe(fds) == 0);
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_usr1;
    action.sa_flags = restart ? SA_RESTART : 0;
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    pthread_t helper;
    assert(pthread_create(&helper, NULL, interrupt, restart ? &helper : NULL) == 0);
    char byte;
    errno = EDOM;
    long got = syscall(SYS_read, fds[0], &byte, 1);
    int after = errno;
    assert(pthread_join(helper, NULL) == 0);
    printf("%s: got=%ld handler-saw=%s errno-after=%s\n", argv[1], got,
           seen == EDOM ? "EDOM" : seen == EINTR ? "EINTR" : "other",
           after == EINTR ? "EINTR" : after == ERANGE ? "ERANGE" : after == EDOM ? "EDOM" : "other");
    return 0;
}
