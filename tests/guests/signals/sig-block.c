// sig-block CLASS restart|plain proc|thread: one signal must end every kind of blocking wait.
//
// A waiter process W blocks in one call of CLASS until its SIGUSR1 handler makes the wait
// done (writes the pipe it reads, releases the lock it waits for, kills the child it waits
// on, ...). The parent sends SIGUSR1 once, at a moment the schedule decides: before W
// blocks, while W is parked, or while W is runnable between two attempts of the wait. A
// third process keeps pipe traffic going meanwhile, so a parked I/O wait is woken often to
// check again. "proc": W is one thread and gets kill(W); "thread": a second thread of W
// makes the call and gets tgkill, its main thread blocking SIGUSR1 and joining it. For
// nanosleep, clock_nanosleep and pause, whose loop checks the handler's flag before the call
// (a signal between the two leaves the call waiting, natively too), the parent sends one a
// second until W ends.
//
// W checks Linux's rules for the interrupted call (signal(7)): with SA_RESTART a restartable
// call (read, write, accept, connect, recv, flock, fcntl F_OFD_SETLKW, open of a FIFO,
// futex wait without a timeout, wait4, waitid, read of a signalfd) never answers EINTR; every
// call returns once the handler ran. (For "signalfd" the handler raises the SIGUSR2 the
// signalfd reads.) W exits 0 when they held, 3 when one did not (naming it); the parent
// exits with W's status. A signal lost by the system leaves W blocked: the run never ends.
//
// CLASS "pselect0"/"ppoll0": the pselect idiom, a zero timeout under an empty mask while
// SIGUSR1 is blocked: once SIGUSR1 is pending the call answers EINTR and the handler runs
// (a 0 leaves it blocked, and the loop never ends). "epoll_pwait2" is epoll_pwait with a timespec.
//
// CLASS "vfork" (proc only): W's main thread M, not blocking SIGUSR1, is in vfork (its child
// sleeps before it exits) while a second thread T is parked reading the pipe; kill(W) may be
// meant for M, whose vfork wait a signal does not end. The handler (run by M afterwards, or by
// T) writes the pipe, so T always ends.
//
// CLASS "retarget": W's main thread M (in pause) and a thread T parked reading the pipe, with
// no traffic; the parent sends SIGURG then SIGUSR2 to W. M takes SIGUSR2 first (lower
// number), whose handler blocks SIGURG and waits until SIGURG was handled: SIGURG must reach
// T, as the kernel passes a process-directed signal on when the thread it was meant for
// blocks it.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *cls;
static int restart, threaded;
static int sp[2], q[2], lfd[2], ls = -1;
static volatile uint32_t word;
static volatile sig_atomic_t got, got_urg;
static volatile pid_t child = -1;
static struct sockaddr_un addr;
static socklen_t alen;
static char fifo[64];
static int recv_pair[2];

static void fail(const char *what, long r, int e) {
    printf("%s %s %s: %s returned %ld errno %d\n", cls, restart ? "restart" : "plain", threaded ? "thread" : "proc", what, r, e);
    fflush(stdout);
    _exit(3);
}

static void on_usr1(int s) {
    (void)s;
    int e = errno;
    got = 1;
    if (write(sp[1], "x", 1) != 1) _exit(4);
    word = 1;
    if (!strcmp(cls, "write")) {
        char b[4096];
        while (read(q[0], b, sizeof b) > 0) {}
    } else if (!strcmp(cls, "accept")) {
        int c = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (c < 0 || connect(c, (struct sockaddr *)&addr, alen)) _exit(4);
    } else if (!strcmp(cls, "connect")) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) _exit(4);
    } else if (!strcmp(cls, "recv")) {
        if (send(recv_pair[1], "x", 1, 0) != 1) _exit(4);
    } else if (!strcmp(cls, "flock") || !strcmp(cls, "ofdlock")) {
        if (!strcmp(cls, "flock")) {
            if (flock(lfd[0], LOCK_UN)) _exit(4);
        } else {
            struct flock fl = {.l_type = F_UNLCK, .l_whence = SEEK_SET};
            if (fcntl(lfd[0], F_OFD_SETLK, &fl)) _exit(4);
        }
    } else if (!strcmp(cls, "fifo")) {
        // A writer: kept open, so the reader's open (restarted, or called again) finds one.
        // (The interrupted open no longer counts as a reader, so O_WRONLY would fail.)
        int w = open(fifo, O_RDWR | O_NONBLOCK);
        if (w < 0 || write(w, "x", 1) != 1) _exit(4);
    } else if (!strcmp(cls, "wait4") || !strcmp(cls, "waitid")) {
        kill(child, SIGKILL);
    } else if (!strcmp(cls, "signalfd")) {
        syscall(SYS_tgkill, getpid(), gettid(), SIGUSR2); // to the waiting thread itself
    }
    errno = e;
}

static void on_urg(int s) {
    (void)s;
    got_urg = 1;
}

static void on_usr2(int s) {
    (void)s;
    struct timespec t = {0, 1000000};
    while (!got_urg) nanosleep(&t, NULL);
}

static void handler(int sig, void (*f)(int), int flags, int block) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = f;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);
    if (block) sigaddset(&sa.sa_mask, block);
    sigaction(sig, &sa, NULL);
}

static void mask(int how, int sig) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, sig);
    pthread_sigmask(how, &s, NULL);
}

// One result of the call: EINTR is allowed unless the call is restartable under SA_RESTART;
// any other error is a failure.
static int restartable(void) {
    static const char *r[] = {"read", "write", "accept", "connect", "recv", "flock", "ofdlock", "fifo", "futex", "wait4", "waitid", "signalfd", 0};
    for (int i = 0; r[i]; i++)
        if (!strcmp(cls, r[i])) return 1;
    return 0;
}

static int interrupted(const char *what, long r, int e) {
    if (r >= 0) return 0;
    if (e == EINTR && !(restart && restartable())) return 1;
    fail(what, r, e);
    return 0;
}

static void setup(void) {
    if (pipe2(sp, O_CLOEXEC)) _exit(2);
    if (!strcmp(cls, "write")) {
        if (pipe2(q, O_NONBLOCK)) _exit(2);
        char b[4096] = {0};
        while (write(q[1], b, sizeof b) > 0) {}
        if (fcntl(q[1], F_SETFL, 0)) _exit(2);
    } else if (!strcmp(cls, "accept") || !strcmp(cls, "connect")) {
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path + 1, sizeof addr.sun_path - 1, "sig-block-%d", getpid());
        alen = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(addr.sun_path + 1);
        ls = socket(AF_UNIX, SOCK_STREAM, 0);
        if (ls < 0 || bind(ls, (struct sockaddr *)&addr, alen) || listen(ls, 0)) _exit(2);
        if (!strcmp(cls, "connect")) {
            // The backlog holds one connection: the next connect blocks.
            int c = socket(AF_UNIX, SOCK_STREAM, 0);
            if (c < 0 || connect(c, (struct sockaddr *)&addr, alen)) _exit(2);
        }
    } else if (!strcmp(cls, "recv")) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, recv_pair)) _exit(2);
    } else if (!strcmp(cls, "flock") || !strcmp(cls, "ofdlock")) {
        lfd[0] = open("/tmp/sig-block.lock", O_RDWR | O_CREAT, 0600);
        lfd[1] = open("/tmp/sig-block.lock", O_RDWR);
        if (lfd[0] < 0 || lfd[1] < 0) _exit(2);
        if (!strcmp(cls, "flock")) {
            if (flock(lfd[0], LOCK_EX)) _exit(2);
        } else {
            struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
            if (fcntl(lfd[0], F_OFD_SETLK, &fl)) _exit(2);
        }
    } else if (!strcmp(cls, "fifo")) {
        snprintf(fifo, sizeof fifo, "/tmp/sig-block-%d", getpid());
        if (mkfifo(fifo, 0600)) _exit(2);
    } else if (!strcmp(cls, "signalfd")) {
        mask(SIG_BLOCK, SIGUSR2); // inherited by the worker thread
    } else if (!strcmp(cls, "wait4") || !strcmp(cls, "waitid")) {
        pid_t c = fork();
        if (c == 0) {
            for (;;) pause();
        }
        child = c;
    }
}

static void wait_once(void) {
    char c;
    long r;
    struct timespec forever = {100000, 0};
    if (!strcmp(cls, "read")) {
        while ((r = read(sp[0], &c, 1)) != 1) interrupted("read", r, errno);
    } else if (!strcmp(cls, "write")) {
        while ((r = write(q[1], "x", 1)) != 1) interrupted("write", r, errno);
    } else if (!strcmp(cls, "accept")) {
        while ((r = accept(ls, NULL, NULL)) < 0) interrupted("accept", r, errno);
    } else if (!strcmp(cls, "connect")) {
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        while ((r = connect(s, (struct sockaddr *)&addr, alen)) != 0) {
            // A connect interrupted and called again finds the first attempt's state.
            if (errno == EISCONN) break;
            interrupted("connect", r, errno);
        }
    } else if (!strcmp(cls, "recv")) {
        while ((r = recv(recv_pair[0], &c, 1, 0)) != 1) interrupted("recv", r, errno);
    } else if (!strcmp(cls, "flock")) {
        while ((r = flock(lfd[1], LOCK_EX)) != 0) interrupted("flock", r, errno);
    } else if (!strcmp(cls, "ofdlock")) {
        struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
        while ((r = fcntl(lfd[1], F_OFD_SETLKW, &fl)) != 0) interrupted("fcntl", r, errno);
    } else if (!strcmp(cls, "fifo")) {
        while ((r = open(fifo, O_RDONLY)) < 0) interrupted("open", r, errno);
    } else if (!strcmp(cls, "signalfd")) {
        // A blocking read of a signalfd for SIGUSR2 (blocked since setup), which the
        // handler raises.
        sigset_t s;
        sigemptyset(&s);
        sigaddset(&s, SIGUSR2);
        int fd = signalfd(-1, &s, 0);
        struct signalfd_siginfo si;
        while ((r = read(fd, &si, sizeof si)) != sizeof si) interrupted("read", r, errno);
    } else if (!strcmp(cls, "epoll")) {
        int ep = epoll_create1(0);
        struct epoll_event ev = {.events = EPOLLIN}, out;
        epoll_ctl(ep, EPOLL_CTL_ADD, sp[0], &ev);
        while ((r = epoll_wait(ep, &out, 1, -1)) != 1) interrupted("epoll_wait", r, errno);
    } else if (!strcmp(cls, "poll")) {
        struct pollfd p = {.fd = sp[0], .events = POLLIN};
        while ((r = poll(&p, 1, -1)) != 1) interrupted("poll", r, errno);
    } else if (!strcmp(cls, "select")) {
        for (;;) {
            fd_set s;
            FD_ZERO(&s);
            FD_SET(sp[0], &s);
            if ((r = select(sp[0] + 1, &s, NULL, NULL, NULL)) == 1) break;
            interrupted("select", r, errno);
        }
    } else if (!strcmp(cls, "pselect0") || !strcmp(cls, "ppoll0")) {
        sigset_t none;
        sigemptyset(&none);
        struct timespec zero = {0, 0};
        while (!got) {
            if (!strcmp(cls, "ppoll0"))
                r = ppoll(NULL, 0, &zero, &none);
            else
                r = pselect(0, NULL, NULL, NULL, &zero, &none);
            // 0 while SIGUSR1 is pending keeps it blocked: the loop never ends.
            if (r != 0) interrupted(cls, r, errno);
        }
    } else if (!strcmp(cls, "ppoll") || !strcmp(cls, "pselect") || !strcmp(cls, "epoll_pwait") ||
               !strcmp(cls, "epoll_pwait2")) {
        // SIGUSR1 is blocked outside the wait; the wait's own mask lets it in. After the
        // wait the old mask is back.
        sigset_t none, now;
        sigemptyset(&none);
        int ep = epoll_create1(0);
        struct epoll_event ev = {.events = EPOLLIN}, out;
        epoll_ctl(ep, EPOLL_CTL_ADD, sp[0], &ev);
        for (;;) {
            struct pollfd p = {.fd = sp[0], .events = POLLIN};
            fd_set s;
            FD_ZERO(&s);
            FD_SET(sp[0], &s);
            if (!strcmp(cls, "ppoll"))
                r = ppoll(&p, 1, NULL, &none);
            else if (!strcmp(cls, "pselect"))
                r = pselect(sp[0] + 1, &s, NULL, NULL, NULL, &none);
            else if (!strcmp(cls, "epoll_pwait"))
                r = epoll_pwait(ep, &out, 1, -1, &none);
            else
                r = syscall(SYS_epoll_pwait2, ep, &out, 1, NULL, &none, 8);
            pthread_sigmask(SIG_BLOCK, NULL, &now);
            if (!sigismember(&now, SIGUSR1)) fail("mask after the wait", r, 0);
            if (r == 1) break;
            interrupted(cls, r, errno);
        }
    } else if (!strcmp(cls, "futex")) {
        while (!word) {
            r = syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
            if (r < 0 && errno != EAGAIN) interrupted("futex", r, errno);
        }
    } else if (!strcmp(cls, "futex_timeout")) {
        while (!word) {
            r = syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, &forever, NULL, 0);
            if (r < 0 && errno != EAGAIN) interrupted("futex", r, errno);
        }
    } else if (!strcmp(cls, "nanosleep")) {
        while (!got) {
            r = nanosleep(&forever, NULL);
            interrupted("nanosleep", r ? r : -1, r ? errno : 0);
        }
    } else if (!strcmp(cls, "clock_nanosleep")) {
        while (!got) {
            r = clock_nanosleep(CLOCK_MONOTONIC, 0, &forever, NULL);
            if (r != EINTR) fail("clock_nanosleep", r, r);
        }
    } else if (!strcmp(cls, "wait4")) {
        int st;
        while ((r = wait4(child, &st, 0, NULL)) != child) interrupted("wait4", r, errno);
    } else if (!strcmp(cls, "waitid")) {
        siginfo_t si;
        while ((r = waitid(P_PID, child, &si, WEXITED)) != 0) interrupted("waitid", r, errno);
    } else if (!strcmp(cls, "sigsuspend")) {
        sigset_t none;
        sigemptyset(&none);
        while (!got) {
            r = sigsuspend(&none);
            interrupted("sigsuspend", r, errno);
        }
    } else if (!strcmp(cls, "pause")) {
        while (!got) {
            r = pause();
            interrupted("pause", r, errno);
        }
    } else if (!strcmp(cls, "sigtimedwait")) {
        sigset_t s;
        sigemptyset(&s);
        sigaddset(&s, SIGUSR1);
        while ((r = sigtimedwait(&s, NULL, NULL)) != SIGUSR1) interrupted("sigtimedwait", r, errno);
        got = 1;
    } else {
        fprintf(stderr, "unknown class %s\n", cls);
        _exit(2);
    }
}

static int blocked_outside(void) {
    return !strcmp(cls, "ppoll") || !strcmp(cls, "pselect") || !strcmp(cls, "epoll_pwait") ||
           !strcmp(cls, "epoll_pwait2") || !strcmp(cls, "pselect0") || !strcmp(cls, "ppoll0") ||
           !strcmp(cls, "sigsuspend") || !strcmp(cls, "sigtimedwait");
}

static int ready_fd;

static void *worker(void *a) {
    (void)a;
    if (blocked_outside()) mask(SIG_BLOCK, SIGUSR1);
    else mask(SIG_UNBLOCK, SIGUSR1);
    pid_t tid = gettid();
    if (write(ready_fd, &tid, sizeof tid) != sizeof tid) _exit(2);
    wait_once();
    return NULL;
}

static void *reader(void *a) {
    (void)a;
    char c;
    long r;
    while ((r = read(sp[0], &c, 1)) != 1) interrupted("read", r, errno);
    return NULL;
}

static int waiter(int rfd) {
    ready_fd = rfd;
    if (!strcmp(cls, "retarget")) {
        if (pipe2(sp, O_CLOEXEC)) _exit(2);
        handler(SIGURG, on_urg, SA_RESTART, 0);
        handler(SIGUSR2, on_usr2, SA_RESTART, SIGURG);
        pthread_t t;
        pthread_create(&t, NULL, reader, NULL);
        pid_t tid = 0;
        if (write(rfd, &tid, sizeof tid) != sizeof tid) _exit(2);
        // The reader ends once the pipe has a byte: written after both signals were handled.
        while (!got_urg) pause();
        if (write(sp[1], "x", 1) != 1) _exit(2);
        pthread_join(t, NULL);
        return 0;
    }
    if (!strcmp(cls, "vfork")) {
        if (pipe2(sp, O_CLOEXEC)) _exit(2);
        handler(SIGUSR1, on_usr1, SA_RESTART, 0);
        pthread_t t;
        pthread_create(&t, NULL, reader, NULL);
        pid_t tid = 0;
        if (write(rfd, &tid, sizeof tid) != sizeof tid) _exit(2);
        for (int i = 0; i < 3; i++) {
            pid_t c = vfork();
            if (c == 0) {
                struct timespec d = {0, 50000000};
                nanosleep(&d, NULL);
                _exit(0);
            }
            if (c < 0 || waitpid(c, NULL, 0) != c) _exit(2);
        }
        pthread_join(t, NULL);
        return 0;
    }
    setup();
    handler(SIGUSR1, on_usr1, restart ? SA_RESTART : 0, 0);
    if (threaded) {
        mask(SIG_BLOCK, SIGUSR1);
        pthread_t t;
        pthread_create(&t, NULL, worker, NULL);
        pthread_join(t, NULL);
    } else {
        worker(NULL);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: sig-block CLASS restart|plain proc|thread\n");
        return 2;
    }
    cls = argv[1];
    restart = !strcmp(argv[2], "restart");
    threaded = !strcmp(argv[3], "thread");
    setvbuf(stdout, NULL, _IONBF, 0);
    int ready[2], busy[2];
    if (pipe(ready) || pipe(busy)) return 2;
    pid_t w = fork();
    if (w == 0) _exit(waiter(ready[1]));
    // No traffic for "retarget" and "vfork": the reader stays parked while the signals arrive.
    pid_t b = strcmp(cls, "retarget") && strcmp(cls, "vfork") ? fork() : -1;
    if (b == 0) {
        char c = 0;
        for (int i = 0; i < 300; i++)
            if (write(busy[1], &c, 1) != 1 || read(busy[0], &c, 1) != 1) _exit(2);
        _exit(0);
    }
    pid_t tid;
    if (read(ready[0], &tid, sizeof tid) != sizeof tid) return 2;
    for (int i = 0; i < 20; i++) getppid();
    if (!strcmp(cls, "retarget")) {
        kill(w, SIGURG);
        kill(w, SIGUSR2);
    }
    // nanosleep, clock_nanosleep and pause check the flag the handler sets, then make the call:
    // a signal can come between the two (natively too, wherever the program is interrupted),
    // and the call then waits for the next one. Those get one a (virtual) second until W ends.
    int again = !strcmp(cls, "nanosleep") || !strcmp(cls, "clock_nanosleep") || !strcmp(cls, "pause");
    int st, reaped = 0;
    while (strcmp(cls, "retarget")) {
        if (threaded)
            syscall(SYS_tgkill, w, tid, SIGUSR1);
        else
            kill(w, SIGUSR1);
        if (!again) break;
        struct timespec sec = {1, 0};
        nanosleep(&sec, NULL);
        if (waitpid(w, &st, WNOHANG) == w) {
            reaped = 1;
            break;
        }
    }
    if (!reaped) waitpid(w, &st, 0);
    if (b > 0) waitpid(b, NULL, 0);
    if (!WIFEXITED(st)) {
        printf("waiter killed by signal %d\n", WTERMSIG(st));
        return 3;
    }
    if (WEXITSTATUS(st) == 0) printf("ok\n");
    return WEXITSTATUS(st);
}
