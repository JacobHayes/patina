// sig-fd [exec-child FD]: signalfd as Linux has it. Every check prints what failed and exits 3;
// all held: prints "ok", exits 0.
//
// - read: EAGAIN with nothing pending; records for kill (SI_USER, pid, uid), sigqueue (SI_QUEUE,
//   value), SIGCHLD (pid, status); several records in one read, real-time signals queued; a
//   buffer smaller than a record is EINVAL; reading consumes (sigpending no longer shows it);
//   a signal outside the mask is not read.
// - flags: SFD_NONBLOCK, SFD_CLOEXEC; a mask update on an existing descriptor.
// - readiness: poll, select, level-triggered epoll; edge-triggered epoll reports a new signal
//   once, and again only for another one.
// - wake-ups: a blocking read, poll and epoll_wait in one thread end when a second process
//   sends the signal later (the schedule decides when).
// - threads: a thread-directed signal is read only by its thread; a process-directed one by
//   either.
// - fork: the child reads its own pending signals through the inherited descriptor, not the
//   parent's; exec: a descriptor without close-on-exec still reads in the new image.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c, ...)                                   \
    do {                                                \
        if (!(c)) {                                     \
            printf("FAIL line %d: ", __LINE__);         \
            printf(__VA_ARGS__);                        \
            printf(" (errno %d)\n", errno);             \
            fflush(stdout);                             \
            _exit(3);                                   \
        }                                               \
    } while (0)

static sigset_t set_of(int a, int b) {
    sigset_t s;
    sigemptyset(&s);
    if (a) sigaddset(&s, a);
    if (b) sigaddset(&s, b);
    return s;
}

static int readable(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    int r = poll(&p, 1, 0);
    CHECK(r >= 0, "poll");
    return r == 1 && (p.revents & POLLIN);
}

static int rd(int fd, struct signalfd_siginfo *si) {
    ssize_t r = read(fd, si, sizeof *si);
    if (r < 0) return -errno;
    CHECK(r == sizeof *si, "short read %zd", r);
    return si->ssi_signo;
}

static void basic(void) {
    sigset_t m = set_of(SIGUSR1, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &m, NULL);
    sigset_t u2 = set_of(SIGUSR2, 0);
    sigprocmask(SIG_BLOCK, &u2, NULL);
    int fd = signalfd(-1, &m, SFD_NONBLOCK | SFD_CLOEXEC);
    CHECK(fd >= 0, "signalfd");
    CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC, "SFD_CLOEXEC");
    CHECK(fcntl(fd, F_GETFL) & O_NONBLOCK, "SFD_NONBLOCK");
    struct signalfd_siginfo si;
    CHECK(rd(fd, &si) == -EAGAIN, "empty read");
    CHECK(!readable(fd), "readable while empty");
    char small[64];
    kill(getpid(), SIGUSR1);
    CHECK(read(fd, small, sizeof small) < 0 && errno == EINVAL, "small buffer");
    CHECK(readable(fd), "not readable with SIGUSR1 pending");
    CHECK(rd(fd, &si) == SIGUSR1, "read SIGUSR1");
    CHECK(si.ssi_code == SI_USER && (pid_t)si.ssi_pid == getpid() && si.ssi_uid == getuid(),
          "kill record code %d pid %u uid %u", si.ssi_code, si.ssi_pid, si.ssi_uid);
    sigset_t p;
    sigpending(&p);
    CHECK(!sigismember(&p, SIGUSR1), "still pending after read");
    CHECK(!readable(fd), "readable after read");
    // Outside the mask: stays pending, never read.
    kill(getpid(), SIGUSR2);
    CHECK(rd(fd, &si) == -EAGAIN && !readable(fd), "SIGUSR2 read through a mask without it");
    sigpending(&p);
    CHECK(sigismember(&p, SIGUSR2), "SIGUSR2 not pending");
    // sigqueue and several records in one read, real-time signals queued.
    union sigval v = {.sival_int = 42};
    sigqueue(getpid(), SIGRTMIN, v);
    v.sival_int = 43;
    sigqueue(getpid(), SIGRTMIN, v);
    kill(getpid(), SIGUSR1);
    struct signalfd_siginfo many[4];
    ssize_t r = read(fd, many, sizeof many);
    CHECK(r == 3 * (ssize_t)sizeof si, "read of three: %zd", r);
    CHECK(many[0].ssi_signo == SIGUSR1, "first %u", many[0].ssi_signo);
    CHECK(many[1].ssi_signo == (unsigned)SIGRTMIN && many[1].ssi_code == SI_QUEUE && many[1].ssi_int == 42 &&
              many[2].ssi_int == 43,
          "queued %u %d %d %d", many[1].ssi_signo, many[1].ssi_code, many[1].ssi_int, many[2].ssi_int);
    // A mask update: now SIGUSR2 (pending) is read.
    sigset_t m2 = set_of(SIGUSR2, 0);
    CHECK(signalfd(fd, &m2, 0) == fd, "mask update");
    CHECK(readable(fd) && rd(fd, &si) == SIGUSR2, "SIGUSR2 after the update");
    sigset_t bad;
    CHECK(signalfd(0, &m2, 0) < 0 && errno == EINVAL, "update of a descriptor that is not one");
    CHECK(syscall(SYS_signalfd4, -1, &m2, 4, 0) < 0 && errno == EINVAL, "mask size");
    (void)bad;
    close(fd);
}

static void readiness(void) {
    sigset_t m = set_of(SIGUSR1, 0);
    int fd = signalfd(-1, &m, SFD_NONBLOCK);
    struct signalfd_siginfo si;
    fd_set s;
    struct timeval z = {0, 0};
    FD_ZERO(&s);
    FD_SET(fd, &s);
    CHECK(select(fd + 1, &s, NULL, NULL, &z) == 0, "select empty");
    kill(getpid(), SIGUSR1);
    FD_ZERO(&s);
    FD_SET(fd, &s);
    CHECK(select(fd + 1, &s, NULL, NULL, &z) == 1, "select pending");
    int lt = epoll_create1(0), et = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN}, out[2];
    epoll_ctl(lt, EPOLL_CTL_ADD, fd, &ev);
    ev.events = EPOLLIN | EPOLLET;
    epoll_ctl(et, EPOLL_CTL_ADD, fd, &ev);
    CHECK(epoll_wait(lt, out, 2, 0) == 1 && epoll_wait(lt, out, 2, 0) == 1, "level-triggered");
    CHECK(epoll_wait(et, out, 2, 0) == 1, "edge-triggered first");
    CHECK(epoll_wait(et, out, 2, 0) == 0, "edge-triggered repeats without a new signal");
    CHECK(rd(fd, &si) == SIGUSR1, "read");
    CHECK(epoll_wait(lt, out, 2, 0) == 0 && epoll_wait(et, out, 2, 0) == 0, "ready after read");
    kill(getpid(), SIGUSR1);
    CHECK(epoll_wait(et, out, 2, 0) == 1, "edge-triggered second signal");
    CHECK(rd(fd, &si) == SIGUSR1, "read 2");
    close(lt);
    close(et);
    close(fd);
}

// A second process sends SIGUSR1 to us after a few calls of its own while this thread blocks.
static void later(int how) {
    sigset_t m = set_of(SIGUSR1, 0);
    int fd = signalfd(-1, &m, how == 0 ? 0 : SFD_NONBLOCK);
    pid_t me = getpid();
    pid_t c = fork();
    if (c == 0) {
        for (int i = 0; i < 30; i++) getppid();
        kill(me, SIGUSR1);
        _exit(0);
    }
    struct signalfd_siginfo si;
    if (how == 0) {
        CHECK(rd(fd, &si) == SIGUSR1, "blocking read");
    } else if (how == 1) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        CHECK(poll(&p, 1, -1) == 1, "poll wake");
        CHECK(rd(fd, &si) == SIGUSR1, "read after poll");
    } else {
        int ep = epoll_create1(0);
        struct epoll_event ev = {.events = EPOLLIN | (how == 3 ? EPOLLET : 0)}, out;
        epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
        CHECK(epoll_wait(ep, &out, 1, -1) == 1, "epoll wake");
        CHECK(rd(fd, &si) == SIGUSR1, "read after epoll");
        close(ep);
    }
    CHECK((pid_t)si.ssi_pid == c, "sender pid %u", si.ssi_pid);
    waitpid(c, NULL, 0);
    // SIGCHLD record (SIGCHLD blocked by main).
    sigset_t ch = set_of(SIGCHLD, 0);
    int cfd = signalfd(-1, &ch, 0);
    CHECK(rd(cfd, &si) == SIGCHLD && (pid_t)si.ssi_pid == c && si.ssi_code == CLD_EXITED && si.ssi_status == 0,
          "SIGCHLD record pid %u code %d status %d", si.ssi_pid, si.ssi_code, si.ssi_status);
    close(cfd);
    close(fd);
}

static int tfd;
static pid_t ttid;
static volatile int tstate;

static void *thread_reader(void *a) {
    (void)a;
    ttid = gettid();
    __atomic_store_n(&tstate, 1, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(&tstate, __ATOMIC_SEQ_CST) != 2) sched_yield();
    struct signalfd_siginfo si;
    CHECK(rd(tfd, &si) == SIGUSR2 && si.ssi_code == SI_TKILL, "thread reads its own signal");
    CHECK(rd(tfd, &si) == -EAGAIN, "thread: nothing more");
    return NULL;
}

static void threads(void) {
    sigset_t m = set_of(SIGUSR2, SIGUSR1);
    tfd = signalfd(-1, &m, SFD_NONBLOCK);
    pthread_t t;
    pthread_create(&t, NULL, thread_reader, NULL);
    while (__atomic_load_n(&tstate, __ATOMIC_SEQ_CST) != 1) sched_yield();
    syscall(SYS_tgkill, getpid(), ttid, SIGUSR2);
    struct signalfd_siginfo si;
    CHECK(rd(tfd, &si) == -EAGAIN && !readable(tfd), "main sees the thread's signal");
    __atomic_store_n(&tstate, 2, __ATOMIC_SEQ_CST);
    pthread_join(t, NULL);
    kill(getpid(), SIGUSR1);
    CHECK(rd(tfd, &si) == SIGUSR1, "process-directed");
    close(tfd);
}

static void forked(char *self) {
    sigset_t m = set_of(SIGUSR1, SIGUSR2);
    int fd = signalfd(-1, &m, SFD_NONBLOCK);
    kill(getpid(), SIGUSR1); // the parent's, not the child's
    pid_t c = fork();
    if (c == 0) {
        struct signalfd_siginfo si;
        CHECK(rd(fd, &si) == -EAGAIN, "child sees the parent's pending signal");
        kill(getpid(), SIGUSR2);
        CHECK(rd(fd, &si) == SIGUSR2, "child reads its own");
        // exec with the descriptor kept open: the new image reads through it.
        char a[16];
        snprintf(a, sizeof a, "%d", fd);
        execl(self, self, "exec-child", a, (char *)NULL);
        _exit(5);
    }
    int st;
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child status %d", st);
    struct signalfd_siginfo si;
    CHECK(rd(fd, &si) == SIGUSR1, "parent reads its own after the fork");
    close(fd);
}

static int exec_child(int fd) {
    struct signalfd_siginfo si;
    CHECK(rd(fd, &si) == -EAGAIN, "exec: nothing pending");
    kill(getpid(), SIGUSR1);
    CHECK(readable(fd), "exec: readable");
    CHECK(rd(fd, &si) == SIGUSR1, "exec: read");
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 3 && !strcmp(argv[1], "exec-child")) return exec_child(atoi(argv[2]));
    sigset_t all = set_of(SIGUSR1, SIGUSR2);
    sigaddset(&all, SIGCHLD);
    sigaddset(&all, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &all, NULL);
    basic();
    readiness();
    for (int how = 0; how < 4; how++) later(how);
    threads();
    forked(argv[0]);
    printf("ok\n");
    return 0;
}
