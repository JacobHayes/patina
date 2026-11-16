/* blocking I/O item 4: timeouts in virtual time. argv[1] = poll | epoll | timerfd | rcvtimeo. */
#include "common.h"
#include <poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>

int main(int argc, char **argv) {
    const char *m = argc > 1 ? argv[1] : "poll";
    int p[2];
    CHECK(pipe(p) == 0, "pipe");
    uint64_t t0 = now_ns();
    if (strcmp(m, "poll") == 0) {
        struct pollfd f = {p[0], POLLIN, 0};
        int r = poll(&f, 1, 10000);
        uint64_t dt = now_ns() - t0;
        printf("poll ret %d elapsed_ns %llu\n", r, (unsigned long long)dt);
        CHECK(r == 0 && dt >= 10000000000ull, "poll");
    } else if (strcmp(m, "epoll") == 0) {
        int ep = epoll_create1(0);
        struct epoll_event e = {.events = EPOLLIN};
        CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &e) == 0, "epoll_ctl");
        t0 = now_ns();
        int r = epoll_wait(ep, &e, 1, 10000);
        uint64_t dt = now_ns() - t0;
        printf("epoll_wait ret %d elapsed_ns %llu\n", r, (unsigned long long)dt);
        CHECK(r == 0 && dt >= 10000000000ull, "epoll_wait");
    } else if (strcmp(m, "timerfd") == 0) {
        int t = timerfd_create(CLOCK_MONOTONIC, 0);
        CHECK(t >= 0, "timerfd_create");
        struct itimerspec its = {{1, 0}, {1, 0}};
        t0 = now_ns();
        CHECK(timerfd_settime(t, 0, &its, NULL) == 0, "settime");
        uint64_t total = 0;
        for (int i = 1; i <= 100; i++) {
            uint64_t v;
            CHECK(read(t, &v, 8) == 8, "read");
            uint64_t dt = now_ns() - t0;
            total += v;
            printf("read %d expirations %llu at_ns %llu\n", i, (unsigned long long)v, (unsigned long long)dt);
        }
        printf("timerfd total %llu\n", (unsigned long long)total);
        struct itimerspec cur;
        CHECK(timerfd_gettime(t, &cur) == 0, "gettime");
        printf("gettime interval %ld.%09ld\n", (long)cur.it_interval.tv_sec, cur.it_interval.tv_nsec);
    } else if (strcmp(m, "rcvtimeo") == 0) {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        struct timeval tv = {2, 0};
        CHECK(setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0, "setsockopt");
        char b;
        t0 = now_ns();
        ssize_t r = recv(sv[0], &b, 1, 0);
        int err = errno;
        uint64_t dt = now_ns() - t0;
        printf("recv ret %zd errno %s elapsed_ns %llu\n", r, err == EAGAIN ? "EAGAIN" : "other", (unsigned long long)dt);
        CHECK(r == -1 && err == EAGAIN && dt >= 2000000000ull, "rcvtimeo");
    }
    return 0;
}
