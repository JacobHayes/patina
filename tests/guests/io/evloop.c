/* An event loop over 32 socketpairs (half level-triggered, half edge-
 * triggered), 4 eventfds and a periodic timerfd, fed by 4 worker threads; the same with
 * poll and with select. argv[1] = epoll | poll | select. Every event is printed in the
 * order the loop saw it (that order is part of what must be identical across runs). */
#include "common.h"
#include <poll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/timerfd.h>

enum { NP = 32, NW = 4, ROUNDS = 20, TICKS = 5 };
static int sp[NP][2], efd[NW], tfd;
static long expect_bytes[NP];

static int msg(char *m, int w, int r, int j) { return snprintf(m, 32, "w%d r%d p%d;", w, r, j); }

static void *worker(void *x) {
    int w = (int)(intptr_t)x;
    for (int r = 0; r < ROUNDS; r++) {
        for (int k = 0; k < NP / NW; k++) {
            int j = w * (NP / NW) + k;
            char m[32];
            int n = msg(m, w, r, j);
            CHECK(write(sp[j][1], m, n) == n, "worker write");
        }
        uint64_t one = 1;
        CHECK(write(efd[w], &one, 8) == 8, "eventfd write");
        struct timespec ts = {0, 3000000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static long got_bytes[NP];
static long ev_count[NW];
static int ticks;

/* Returns 1 while more is expected. */
static int more(void) {
    for (int j = 0; j < NP; j++)
        if (got_bytes[j] < expect_bytes[j]) return 1;
    for (int w = 0; w < NW; w++)
        if (ev_count[w] < ROUNDS) return 1;
    return ticks < TICKS;
}

static void on_sock(int j, int edge) {
    char buf[4096];
    long total = 0;
    for (;;) {
        ssize_t r = read(sp[j][0], buf, edge ? 7 : sizeof buf); /* small reads: edge mode must drain */
        if (r < 0 && errno == EAGAIN) break;
        CHECK(r > 0, "sock read");
        total += r;
        if (!edge) break;
    }
    got_bytes[j] += total;
    printf("sock %d %s %ld\n", j, edge ? "et" : "lt", total);
}

static void on_event(int w) {
    uint64_t v;
    CHECK(read(efd[w], &v, 8) == 8, "eventfd read");
    ev_count[w] += (long)v;
    printf("eventfd %d +%llu\n", w, (unsigned long long)v);
}

static void on_timer(void) {
    uint64_t v;
    CHECK(read(tfd, &v, 8) == 8, "timerfd read");
    ticks += (int)v;
    printf("timer +%llu\n", (unsigned long long)v);
    if (ticks >= TICKS) {
        struct itimerspec off = {{0, 0}, {0, 0}};
        CHECK(timerfd_settime(tfd, 0, &off, NULL) == 0, "disarm");
        printf("timer disarmed\n");
    }
}

static void loop_epoll(void) {
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0, "epoll_create1");
    for (int j = 0; j < NP; j++) {
        struct epoll_event e = {.events = EPOLLIN | (j % 2 ? EPOLLET : 0), .data.u64 = j};
        CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, sp[j][0], &e) == 0, "epoll_ctl");
    }
    for (int w = 0; w < NW; w++) {
        struct epoll_event e = {.events = EPOLLIN, .data.u64 = 100 + w};
        CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, efd[w], &e) == 0, "epoll_ctl");
    }
    struct epoll_event e = {.events = EPOLLIN, .data.u64 = 200};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, tfd, &e) == 0, "epoll_ctl");
    while (more()) {
        struct epoll_event ev[16];
        int n = epoll_wait(ep, ev, 16, 1000);
        CHECK(n > 0, "epoll_wait %d", n);
        printf("wait %d\n", n);
        for (int i = 0; i < n; i++) {
            uint64_t d = ev[i].data.u64;
            if (d < NP) on_sock((int)d, d % 2);
            else if (d < 200) on_event((int)d - 100);
            else on_timer();
        }
    }
    close(ep);
}

static void loop_poll(void) {
    struct pollfd p[NP + NW + 1];
    while (more()) {
        int k = 0;
        for (int j = 0; j < NP; j++) p[k++] = (struct pollfd){sp[j][0], POLLIN, 0};
        for (int w = 0; w < NW; w++) p[k++] = (struct pollfd){efd[w], POLLIN, 0};
        p[k++] = (struct pollfd){tfd, POLLIN, 0};
        int n = poll(p, k, 1000);
        CHECK(n > 0, "poll %d", n);
        printf("wait %d\n", n);
        for (int j = 0; j < NP; j++)
            if (p[j].revents & POLLIN) on_sock(j, 0);
        for (int w = 0; w < NW; w++)
            if (p[NP + w].revents & POLLIN) on_event(w);
        if (p[NP + NW].revents & POLLIN) on_timer();
    }
}

static void loop_select(void) {
    while (more()) {
        fd_set r;
        FD_ZERO(&r);
        int maxfd = 0;
#define ADD(f) do { FD_SET(f, &r); if ((f) > maxfd) maxfd = (f); } while (0)
        for (int j = 0; j < NP; j++) ADD(sp[j][0]);
        for (int w = 0; w < NW; w++) ADD(efd[w]);
        ADD(tfd);
        struct timeval tv = {1, 0};
        int n = select(maxfd + 1, &r, NULL, NULL, &tv);
        CHECK(n > 0, "select %d", n);
        printf("wait %d\n", n);
        for (int j = 0; j < NP; j++)
            if (FD_ISSET(sp[j][0], &r)) on_sock(j, 0);
        for (int w = 0; w < NW; w++)
            if (FD_ISSET(efd[w], &r)) on_event(w);
        if (FD_ISSET(tfd, &r)) on_timer();
    }
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "epoll";
    for (int j = 0; j < NP; j++) {
        CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp[j]) == 0, "socketpair");
        if (j % 2 && strcmp(mode, "epoll") == 0) fcntl(sp[j][0], F_SETFL, O_NONBLOCK);
        int w = j / (NP / NW);
        for (int r = 0; r < ROUNDS; r++) {
            char m[32];
            expect_bytes[j] += msg(m, w, r, j);
        }
    }
    for (int w = 0; w < NW; w++) CHECK((efd[w] = eventfd(0, EFD_CLOEXEC)) >= 0, "eventfd");
    tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    CHECK(tfd >= 0, "timerfd_create");
    struct itimerspec its = {{0, 10000000}, {0, 10000000}};
    CHECK(timerfd_settime(tfd, 0, &its, NULL) == 0, "timerfd_settime");
    pthread_t t[NW];
    for (int w = 0; w < NW; w++) spawn(&t[w], worker, (void *)(intptr_t)w);
    if (strcmp(mode, "epoll") == 0) loop_epoll();
    else if (strcmp(mode, "poll") == 0) loop_poll();
    else loop_select();
    for (int w = 0; w < NW; w++) pthread_join(t[w], NULL);
    long total = 0;
    for (int j = 0; j < NP; j++) {
        CHECK(got_bytes[j] == expect_bytes[j], "pair %d got %ld want %ld", j, got_bytes[j], expect_bytes[j]);
        total += got_bytes[j];
    }
    printf("evloop %s ok bytes=%ld ticks=%d\n", mode, total, ticks);
    return 0;
}
