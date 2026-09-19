/* Class pairing: the signals-family no-restart/temporary-mask tests in
 * src/thread/readiness/tests.rs. Exercise the real C adapters as well as their
 * Rust core: each call must actually park before a helper generates SIGUSR1. */
#define _GNU_SOURCE
#include "patina_native.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

enum wait_call { WAIT_POLL, WAIT_PPOLL, WAIT_SELECT, WAIT_PSELECT, WAIT_EPOLL, WAIT_SLEEP };
static const struct {
    const char *name;
    enum wait_call call;
    int temporary_mask;
} cases[] = {
    {"poll", WAIT_POLL, 0}, {"ppoll", WAIT_PPOLL, 1}, {"select", WAIT_SELECT, 0},
    {"pselect", WAIT_PSELECT, 1}, {"epoll", WAIT_EPOLL, 1}, {"sleep", WAIT_SLEEP, 0}
};
static const long WAKE_DELAY_NS = 10000000;
static volatile sig_atomic_t handled;
static void handler(int sig) { assert(sig == SIGUSR1); ++handled; }
static void *wake(void *arg) {
    (void)arg;
    struct timespec delay = {0, WAKE_DELAY_NS};
    assert(nanosleep(&delay, NULL) == 0);
    assert(kill(getpid(), SIGUSR1) == 0);
    return NULL;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    int matched = 0;
    struct sigaction action = {.sa_handler = handler, .sa_flags = SA_RESTART};
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    int pipefd[2];
    assert(pipe(pipefd) == 0);
    int ep = epoll_create1(0);
    assert(ep >= 0);
    struct epoll_event interest = {.events = EPOLLIN, .data.u64 = 7};
    assert(epoll_ctl(ep, EPOLL_CTL_ADD, pipefd[0], &interest) == 0);
    for (size_t row = 0; row < sizeof(cases) / sizeof(cases[0]); ++row) {
        if (strcmp(argv[1], cases[row].name) != 0) continue;
        matched++;
        sigset_t original, empty, after;
        sigemptyset(&original);
        sigemptyset(&empty);
        if (cases[row].temporary_mask) sigaddset(&original, SIGUSR1);
        assert(sigprocmask(SIG_SETMASK, &original, NULL) == 0);
        pthread_t helper;
        assert(pthread_create(&helper, NULL, wake, NULL) == 0);
        struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN};
        struct timeval tv = {1, 0};
        struct timespec ts = {1, 0};
        fd_set read;
        FD_ZERO(&read);
        FD_SET(pipefd[0], &read);
        int rc;
        switch (cases[row].call) {
        case WAIT_POLL: rc = poll(&pfd, 1, 1000); break;
        case WAIT_PPOLL: rc = ppoll(&pfd, 1, &ts, &empty); break;
        case WAIT_SELECT: rc = select(pipefd[0] + 1, &read, NULL, NULL, &tv); break;
        case WAIT_PSELECT: rc = pselect(pipefd[0] + 1, &read, NULL, NULL, &ts, &empty); break;
        case WAIT_EPOLL: rc = epoll_pwait(ep, &interest, 1, 1000, &empty); break;
        case WAIT_SLEEP: rc = (int)sleep(1); break;
        default: assert(!"invalid wait case"); return 1;
        }
        if (cases[row].call == WAIT_SLEEP) assert(rc == 1);
        else assert(rc == -1 && errno == EINTR);
        assert(handled == 1);
        /* libc ppoll/pselect never write the caller's timeout, unlike raw rows. */
        assert(ts.tv_sec == 1 && ts.tv_nsec == 0);
        if (cases[row].call == WAIT_SELECT)
            assert(tv.tv_sec == 0 && tv.tv_usec == 1000000 - WAKE_DELAY_NS / 1000);
        assert(sigprocmask(SIG_SETMASK, NULL, &after) == 0);
        assert(sigismember(&after, SIGUSR1) == sigismember(&original, SIGUSR1));
        assert(pthread_join(helper, NULL) == 0);
    }
    assert(matched == 1);
    assert(close(ep) == 0);
    assert(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    puts("NATIVE_SIGNAL_READINESS_OK");
    assert(patina_shutdown() == 0);
    return 0;
}
