/* Timeouts in virtual time. argv[1] = poll | epoll | timerfd | timerfd2 | timerfd-exec | rcvtimeo. */
#include "common.h"
#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>

extern char **environ;

static uint64_t rd8(int fd) {
    uint64_t v = 0;
    CHECK(read(fd, &v, 8) == 8, "read %d", fd);
    return v;
}

/* The new image of `timerfd-exec`: the timers kept open are still timerfds with their setting,
 * clock and duplicates; the close-on-exec one is gone. A spawned image (vfork and exec) shares
 * them too. */
static int exec_child(int t1, int t2, int t3, int t4) {
    struct itimerspec cur, off = {{0, 0}, {0, 0}};
    CHECK(fcntl(t2, F_GETFD) == -1 && errno == EBADF, "close-on-exec timerfd still open");
    CHECK(timerfd_gettime(t1, &cur) == 0, "gettime after exec");
    CHECK(cur.it_interval.tv_sec == 1 && cur.it_interval.tv_nsec == 0, "interval after exec");
    CHECK(cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec > 0, "still armed after exec");
    CHECK(rd8(t1) >= 1, "expiry after exec");
    // t3 is a duplicate of t1: disarming one disarms both.
    CHECK(timerfd_settime(t3, 0, &off, NULL) == 0, "disarm the duplicate");
    CHECK(timerfd_gettime(t1, &cur) == 0 && cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec == 0,
          "duplicate names the same timer");
    // t4 keeps CLOCK_REALTIME: an absolute realtime expiry 2 s ahead fires.
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    struct itimerspec abs = {{0, 0}, {now.tv_sec + 2, now.tv_nsec}};
    CHECK(timerfd_settime(t4, TFD_TIMER_ABSTIME, &abs, NULL) == 0, "realtime settime");
    CHECK(rd8(t4) == 1, "realtime expiry");
    // A spawned program (vfork and exec) inherits t4 and reads its next expiry.
    struct itimerspec per = {{1, 0}, {1, 0}};
    CHECK(timerfd_settime(t4, 0, &per, NULL) == 0, "periodic settime");
    char a4[16];
    snprintf(a4, sizeof a4, "%d", t4);
    char *args[] = {"/proc/self/exe", "timerfd-spawned", a4, NULL};
    pid_t pid;
    CHECK(posix_spawn(&pid, "/proc/self/exe", NULL, NULL, args, environ) == 0, "posix_spawn");
    int st;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0, "spawned image");
    CHECK(timerfd_gettime(t4, &cur) == 0 && cur.it_interval.tv_sec == 1, "held after the spawned exit");
    close(t1);
    close(t3);
    CHECK(rd8(t4) >= 1, "t4 after closing t1");
    printf("timerfd-exec ok\n");
    return 0;
}

int main(int argc, char **argv) {
    const char *m = argc > 1 ? argv[1] : "poll";
    if (strcmp(m, "timerfd-exec-child") == 0 && argc == 6)
        return exec_child(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
    if (strcmp(m, "timerfd-spawned") == 0 && argc == 3) {
        struct itimerspec cur;
        int t = atoi(argv[2]);
        CHECK(timerfd_gettime(t, &cur) == 0 && cur.it_interval.tv_sec == 1, "spawned gettime");
        CHECK(rd8(t) >= 1, "spawned read");
        return 0;
    }
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
    } else if (strcmp(m, "timerfd2") == 0) {
        // Two timers at once: each keeps its own setting and fires at its own time.
        int a = timerfd_create(CLOCK_MONOTONIC, 0), b = timerfd_create(CLOCK_MONOTONIC, 0);
        CHECK(a >= 0 && b >= 0, "timerfd_create");
        struct itimerspec ia = {{0, 0}, {1, 0}}, ib = {{0, 0}, {3, 0}}, cur;
        t0 = now_ns();
        CHECK(timerfd_settime(a, 0, &ia, NULL) == 0 && timerfd_settime(b, 0, &ib, NULL) == 0, "settime");
        CHECK(timerfd_gettime(a, &cur) == 0 && cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec > 0, "gettime a");
        CHECK(timerfd_gettime(b, &cur) == 0 && cur.it_value.tv_sec == 2, "gettime b");
        uint64_t va, vb;
        CHECK(read(a, &va, 8) == 8 && va == 1, "read a");
        uint64_t da = now_ns() - t0;
        CHECK(read(b, &vb, 8) == 8 && vb == 1, "read b");
        uint64_t db = now_ns() - t0;
        printf("timerfd2 a after %llu s, b after %llu s\n", (unsigned long long)(da / 1000000000ull),
               (unsigned long long)(db / 1000000000ull));
        CHECK(da >= 1000000000ull && db >= 3000000000ull, "expiry times");
    } else if (strcmp(m, "timerfd-exec") == 0) {
        // Timers kept open across execve (one close-on-exec, one a duplicate, one realtime).
        int t1 = timerfd_create(CLOCK_MONOTONIC, 0);
        int t2 = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
        int t3 = dup(t1);
        int t4 = timerfd_create(CLOCK_REALTIME, 0);
        CHECK(t1 >= 0 && t2 >= 0 && t3 >= 0 && t4 >= 0, "timerfd_create");
        struct itimerspec per = {{1, 0}, {1, 0}}, five = {{0, 0}, {5, 0}};
        CHECK(timerfd_settime(t1, 0, &per, NULL) == 0 && timerfd_settime(t2, 0, &five, NULL) == 0, "settime");
        CHECK(rd8(t1) == 1, "first expiry");
        char a[4][16];
        int fds[4] = {t1, t2, t3, t4};
        for (int i = 0; i < 4; i++) snprintf(a[i], sizeof a[i], "%d", fds[i]);
        execl("/proc/self/exe", "timeouts", "timerfd-exec-child", a[0], a[1], a[2], a[3], (char *)NULL);
        CHECK(0, "execl");
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
