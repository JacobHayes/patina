// W8 `sockets`: TCP-style code written against ordinary AF_INET/AF_INET6 calls.
// One program, one mode per scenario; every mode prints what it observed and ends with
// "PASS <mode>" (exit 0) or "FAIL <mode>: why" (exit 1). Times are CLOCK_MONOTONIC, which
// under patina is virtual time.
//
//   sockets all                 W8: blocking pair, half-close, epoll LT+ET with 50 clients,
//                               an 8 MiB transfer with a slow reader, connect to a closed port
//   sockets <semantic test>     names refused addrinuse halfclose eof rst epipe sigpipe-kill
//                               rcvtimeo peek waitall sendfile big MIB v6
//   sockets epoll lt|et [CLIENTS MSGS]
//   sockets nbconnect [MIN_MS]  POLLOUT of a non-blocking connect: when (virtual ms)
//   sockets xfer KIB [MIN_MS]   one transfer, prints virtual ms
//   (fault scenarios; the argument is what the run expects, so the same mode fails when the
//   fault is off)
//   sockets chunk naive|correct, reset [reset], connect [connected|refused|timeout],
//           partition [partitioned], halfclose-delay [MIN_MS]
//   sockets chaos CLIENTS MSGS  fault-tolerant traffic (for runs with mixed network faults)
//   sockets pingpong N          N one-byte round trips between two processes (cost)
//   sockets forkserver | execinherit | exitclose [MIN_MS]      (processes)
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *mode = "?";

static void fail(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("FAIL %s: ", mode);
    vprintf(fmt, ap);
    printf(" (errno %d %s)\n", errno, strerror(errno));
    fflush(stdout);
    va_end(ap);
    exit(1);
}
#define CHECK(c, ...) do { if (!(c)) fail(__VA_ARGS__); } while (0)

static long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}
static long long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000LL + t.tv_nsec / 1000;
}
static void sleep_ms(int ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&t, 0);
}

static struct sockaddr_in loop4(int port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

static int port_of(int fd) {
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    CHECK(getsockname(fd, (void *)&a, &l) == 0, "getsockname");
    return ntohs(a.sin_port);
}

/// A listener on 127.0.0.1:0; returns the fd, the port in *port.
static int listener(int *port, int flags) {
    int l = socket(AF_INET, SOCK_STREAM | flags, 0);
    CHECK(l >= 0, "socket");
    int one = 1;
    CHECK(setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0, "SO_REUSEADDR");
    struct sockaddr_in a = loop4(0);
    CHECK(bind(l, (void *)&a, sizeof a) == 0, "bind");
    CHECK(listen(l, 128) == 0, "listen");
    *port = port_of(l);
    return l;
}

static int dial(int port) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(c >= 0, "socket");
    struct sockaddr_in a = loop4(port);
    CHECK(connect(c, (void *)&a, sizeof a) == 0, "connect to %d", port);
    return c;
}

static ssize_t write_full(int fd, const void *p, size_t n) {
    size_t d = 0;
    while (d < n) {
        ssize_t r = write(fd, (const char *)p + d, n - d);
        if (r < 0) {
            if (errno == EINTR) continue;
            return d ? (ssize_t)d : -1;
        }
        d += r;
    }
    return d;
}

static ssize_t read_full(int fd, void *p, size_t n) {
    size_t d = 0;
    while (d < n) {
        ssize_t r = read(fd, (char *)p + d, n - d);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        d += r;
    }
    return d;
}

static uint64_t fnv(uint64_t h, const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 0x100000001b3ULL;
    return h;
}

static void fill(unsigned char *p, size_t n, uint64_t off) {
    for (size_t i = 0; i < n; i++) p[i] = (unsigned char)((off + i) * 2654435761u >> 13);
}

static int wait_child(pid_t p) {
    int st;
    CHECK(waitpid(p, &st, 0) == p, "waitpid");
    if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);
    return WEXITSTATUS(st);
}

// ---- W8 parts ----

/// A 32-byte message naming client `i`, message `k`.
static void msg32(char *m, int i, int k) {
    char t[48];
    memset(m, '.', 32);
    int n = snprintf(t, sizeof t, "c%03d m%05d ", i % 1000, k % 100000);
    memcpy(m, t, n < 32 ? n : 32);
}

/// Blocking request/response pair across two processes, then half-close.
static void blocking_pair(int rounds) {
    int port, l = listener(&port, 0);
    pid_t p = fork();
    if (p == 0) {
        close(l);
        int c = dial(port);
        char buf[64];
        for (int i = 0; i < rounds; i++) {
            int n = snprintf(buf, sizeof buf, "ping %d", i);
            CHECK(write_full(c, buf, n) == n, "client write");
            char r[64];
            CHECK(read_full(c, r, n) == n, "client read");
            CHECK(r[1] == 'o' && memcmp(r + 4, buf + 4, n - 4) == 0, "client echo %d", i);
        }
        CHECK(shutdown(c, SHUT_WR) == 0, "shutdown");
        // Half-closed: the server still answers with a summary, then EOF.
        char sum[64];
        ssize_t n = read_full(c, sum, sizeof sum);
        CHECK(n > 0, "summary after half-close");
        printf("client: summary '%.*s'\n", (int)n, sum);
        fflush(stdout);
        close(c);
        _exit(0);
    }
    int s = accept(l, 0, 0);
    CHECK(s >= 0, "accept");
    char buf[64];
    int count = 0;
    for (;;) {
        ssize_t n = read(s, buf, sizeof buf);
        CHECK(n >= 0, "server read");
        if (n == 0) break;
        buf[1] = 'o';
        CHECK(write_full(s, buf, n) == n, "server write");
        count++;
    }
    char sum[64];
    int n = snprintf(sum, sizeof sum, "server saw %d reads", count);
    CHECK(write_full(s, sum, n) == n, "server summary");
    close(s);
    close(l);
    CHECK(wait_child(p) == 0, "client process");
    printf("blocking pair: %d rounds ok\n", rounds);
}

/// epoll echo server (level or edge triggered) in this process; `clients` non-blocking
/// clients in a child process, each sending `msgs` 32-byte messages and checking the echoes.
static void epoll_echo(int edge, int clients, int msgs) {
    int port, l = listener(&port, SOCK_NONBLOCK);
    pid_t p = fork();
    if (p == 0) {
        close(l);
        int *fd = calloc(clients, sizeof(int));
        int *sent = calloc(clients, sizeof(int)), *got = calloc(clients, sizeof(int));
        char (*rb)[32] = calloc(clients, 32);
        int *rbn = calloc(clients, sizeof(int));
        struct pollfd *pf = calloc(clients, sizeof *pf);
        for (int i = 0; i < clients; i++) {
            fd[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            struct sockaddr_in a = loop4(port);
            int r = connect(fd[i], (void *)&a, sizeof a);
            CHECK(r == -1 && errno == EINPROGRESS, "non-blocking connect %d", i);
        }
        int done = 0;
        while (done < clients) {
            for (int i = 0; i < clients; i++) {
                pf[i].fd = got[i] == msgs ? -1 : fd[i];
                pf[i].events = POLLIN | (sent[i] < msgs && sent[i] == got[i] ? POLLOUT : 0);
            }
            int n = poll(pf, clients, 10000);
            CHECK(n > 0, "client poll");
            for (int i = 0; i < clients; i++) {
                if (pf[i].revents & POLLOUT) {
                    if (sent[i] == 0) {
                        int e = -1;
                        socklen_t el = sizeof e;
                        CHECK(getsockopt(fd[i], SOL_SOCKET, SO_ERROR, &e, &el) == 0 && e == 0, "SO_ERROR %d", i);
                    }
                    char m[32];
                    msg32(m, i, sent[i]);
                    ssize_t w = write(fd[i], m, 32);
                    CHECK(w == 32, "client %d write", i);
                    sent[i]++;
                }
                if (pf[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                    ssize_t r = read(fd[i], rb[i] + rbn[i], 32 - rbn[i]);
                    if (r < 0 && errno == EAGAIN) continue;
                    CHECK(r > 0, "client %d read", i);
                    rbn[i] += r;
                    if (rbn[i] == 32) {
                        char m[32];
                        msg32(m, i, got[i]);
                        CHECK(memcmp(m, rb[i], 32) == 0, "echo %d/%d", i, got[i]);
                        rbn[i] = 0;
                        if (++got[i] == msgs) {
                            close(fd[i]);
                            done++;
                        }
                    }
                }
            }
        }
        _exit(0);
    }
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = l};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, l, &ev) == 0, "epoll_ctl listener");
    int closed = 0, accepted = 0;
    long echoed = 0;
    struct epoll_event evs[64];
    while (closed < clients) {
        int n = epoll_wait(ep, evs, 64, 10000);
        CHECK(n > 0, "epoll_wait (closed %d accepted %d)", closed, accepted);
        for (int k = 0; k < n; k++) {
            int f = evs[k].data.fd;
            if (f == l) {
                for (;;) {
                    int s = accept4(l, 0, 0, SOCK_NONBLOCK);
                    if (s < 0) {
                        CHECK(errno == EAGAIN, "accept4");
                        break;
                    }
                    accepted++;
                    struct epoll_event e2 = {.events = EPOLLIN | EPOLLRDHUP | (edge ? EPOLLET : 0), .data.fd = s};
                    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, s, &e2) == 0, "epoll_ctl conn");
                    if (!edge) break; // level triggered: the rest is reported again
                }
                continue;
            }
            // Echo what is there; edge triggered reads until EAGAIN.
            for (;;) {
                char buf[4096];
                ssize_t r = read(f, buf, edge ? sizeof buf : 100);
                if (r < 0 && errno == EAGAIN) break;
                CHECK(r >= 0, "server read");
                if (r == 0) {
                    close(f);
                    closed++;
                    break;
                }
                CHECK(write_full(f, buf, r) == r, "server write");
                echoed += r;
                if (!edge) break;
            }
        }
    }
    close(ep);
    close(l);
    CHECK(wait_child(p) == 0, "clients");
    CHECK(echoed == (long)clients * msgs * 32, "echoed %ld bytes", echoed);
    printf("epoll %s: %d clients x %d messages echoed (%ld bytes)\n", edge ? "et" : "lt", clients, msgs, echoed);
}

/// A transfer of `bytes` from a child to this process; the reader sleeps `sleep_every` ms
/// every 256 KiB (a slow reader). Returns virtual ms.
static long long transfer(long bytes, int slow_ms) {
    int port, l = listener(&port, 0);
    pid_t p = fork();
    if (p == 0) {
        close(l);
        int c = dial(port);
        static unsigned char b[65536];
        long off = 0;
        uint64_t h = 0xcbf29ce484222325ULL;
        while (off < bytes) {
            size_t n = bytes - off < (long)sizeof b ? (size_t)(bytes - off) : sizeof b;
            fill(b, n, off);
            h = fnv(h, b, n);
            CHECK(write_full(c, b, n) == (ssize_t)n, "sender write at %ld", off);
            off += n;
        }
        printf("sender: %ld bytes hash %016llx\n", off, (unsigned long long)h);
        fflush(stdout);
        close(c);
        _exit(0);
    }
    int s = accept(l, 0, 0);
    CHECK(s >= 0, "accept");
    long long t0 = now_ms();
    static unsigned char b[100000];
    long got = 0, next_nap = 256 << 10;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (;;) {
        ssize_t r = read(s, b, sizeof b);
        CHECK(r >= 0, "reader");
        if (r == 0) break;
        for (ssize_t i = 0; i < r; i++) {
            unsigned char x;
            fill(&x, 1, got + i);
            if (x != b[i]) fail("byte %ld differs", got + i);
        }
        h = fnv(h, b, r);
        got += r;
        if (slow_ms && got >= next_nap) {
            sleep_ms(slow_ms);
            next_nap += 256 << 10;
        }
    }
    long long ms = now_ms() - t0;
    close(s);
    close(l);
    CHECK(wait_child(p) == 0, "sender process");
    CHECK(got == bytes, "got %ld of %ld", got, bytes);
    printf("transfer: %ld bytes hash %016llx in %lld virtual ms\n", got, (unsigned long long)h, ms);
    return ms;
}

/// Connect to a port nobody listens on: blocking and non-blocking.
static void refused(void) {
    int port, l = listener(&port, 0);
    close(l); // the port is free again
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = loop4(port);
    int r = connect(c, (void *)&a, sizeof a);
    CHECK(r == -1 && errno == ECONNREFUSED, "blocking connect to a closed port: %d", r);
    close(c);
    printf("blocking connect: ECONNREFUSED\n");
    c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    r = connect(c, (void *)&a, sizeof a);
    CHECK(r == -1 && errno == EINPROGRESS, "non-blocking connect: %d", r);
    struct pollfd pf = {.fd = c, .events = POLLOUT};
    CHECK(poll(&pf, 1, 5000) == 1, "poll");
    int e = 0;
    socklen_t el = sizeof e;
    CHECK(getsockopt(c, SOL_SOCKET, SO_ERROR, &e, &el) == 0, "SO_ERROR");
    CHECK(e == ECONNREFUSED, "SO_ERROR %d", e);
    printf("non-blocking connect: revents 0x%x, SO_ERROR ECONNREFUSED\n", pf.revents);
    e = -1;
    getsockopt(c, SOL_SOCKET, SO_ERROR, &e, &el);
    CHECK(e == 0, "SO_ERROR cleared: %d", e);
    // The error taken, a second connect reports the failure as ECONNABORTED (the kernel's
    // sock_error with no pending error).
    r = connect(c, (void *)&a, sizeof a);
    CHECK(r == -1 && errno == ECONNABORTED, "connect after SO_ERROR: %d %d", r, errno);
    close(c);
    // Learning the result by a second connect (hiredis): the pending error itself.
    c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    r = connect(c, (void *)&a, sizeof a);
    CHECK(r == -1 && errno == EINPROGRESS, "non-blocking connect: %d", r);
    pf.fd = c;
    CHECK(poll(&pf, 1, 5000) == 1, "poll");
    r = connect(c, (void *)&a, sizeof a);
    CHECK(r == -1 && errno == ECONNREFUSED, "second connect: %d %d", r, errno);
    printf("second connect: ECONNREFUSED\n");
    // A third connect is a new attempt (the kernel's TCP socket is closed and unconnected
    // again), and fails the same way.
    struct stat st0, st1;
    CHECK(fstat(c, &st0) == 0, "fstat");
    r = connect(c, (void *)&a, sizeof a);
    CHECK(r == -1 && errno == EINPROGRESS, "third connect: %d %d", r, errno);
    CHECK(poll(&pf, 1, 5000) == 1, "poll");
    r = connect(c, (void *)&a, sizeof a);
    CHECK(r == -1 && errno == ECONNREFUSED, "fourth connect: %d %d", r, errno);
    CHECK(fstat(c, &st1) == 0 && st1.st_ino == st0.st_ino, "the socket's inode changed");
    printf("third connect: EINPROGRESS, then ECONNREFUSED\n");
    close(c);
    // A blocking client probing for a server on one socket: refused twice, then the server
    // listens and the same socket connects.
    c = socket(AF_INET, SOCK_STREAM, 0);
    for (int k = 0; k < 2; k++) {
        r = connect(c, (void *)&a, sizeof a);
        CHECK(r == -1 && errno == ECONNREFUSED, "probe %d: %d %d", k, r, errno);
    }
    int one = 1;
    l = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0, "SO_REUSEADDR");
    CHECK(bind(l, (void *)&a, sizeof a) == 0 && listen(l, 8) == 0, "listen again");
    CHECK(connect(c, (void *)&a, sizeof a) == 0, "probe connect: %d", errno);
    int sv = accept(l, NULL, NULL);
    CHECK(sv >= 0 && write(c, "x", 1) == 1, "accept and write");
    char ch = 0;
    CHECK(read(sv, &ch, 1) == 1 && ch == 'x', "read");
    close(sv);
    close(c);
    printf("probe loop: refused twice, then connected\n");
    // An explicitly bound client keeps its port across attempts.
    int bport, b = listener(&bport, 0);
    close(b);
    c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ba = loop4(bport);
    CHECK(bind(c, (void *)&ba, sizeof ba) == 0, "client bind");
    close(l); // nobody listens now
    for (int k = 0; k < 3; k++) {
        r = connect(c, (void *)&a, sizeof a);
        CHECK(r == -1 && errno == ECONNREFUSED, "bound probe %d: %d %d", k, r, errno);
    }
    CHECK(port_of(c) == bport, "bound port %d after attempts, was %d", port_of(c), bport);
    close(c);
    printf("bound client: port kept over three attempts\n");
    // Unix sockets: a missing path, then a refused one, then a listener; one socket throughout.
    struct sockaddr_un u = {.sun_family = AF_UNIX};
    snprintf(u.sun_path, sizeof u.sun_path, "/tmp/refused-%d.sock", getpid());
    unlink(u.sun_path);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    r = connect(c, (void *)&u, sizeof u);
    CHECK(r == -1 && errno == ENOENT, "unix connect, no file: %d %d", r, errno);
    int ul = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(bind(ul, (void *)&u, sizeof u) == 0, "unix bind");
    r = connect(c, (void *)&u, sizeof u);
    CHECK(r == -1 && errno == ECONNREFUSED, "unix connect, not listening: %d %d", r, errno);
    CHECK(listen(ul, 8) == 0, "unix listen");
    CHECK(connect(c, (void *)&u, sizeof u) == 0, "unix connect: %d", errno);
    close(c);
    close(ul);
    unlink(u.sun_path);
    printf("unix: ENOENT, ECONNREFUSED, then connected\n");
}

// ---- semantic tests ----

static void t_names(void) {
    int port, l = listener(&port, 0);
    CHECK(port >= 32768, "port %d", port);
    pid_t p = fork();
    if (p == 0) {
        int c = dial(port);
        struct sockaddr_in me, peer;
        socklen_t ml = sizeof me, pl = sizeof peer;
        CHECK(getsockname(c, (void *)&me, &ml) == 0 && ml == sizeof me, "client getsockname");
        CHECK(getpeername(c, (void *)&peer, &pl) == 0 && pl == sizeof peer, "client getpeername");
        CHECK(me.sin_family == AF_INET && peer.sin_family == AF_INET, "families");
        CHECK(ntohs(peer.sin_port) == port && peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK), "peer");
        CHECK(write_full(c, &me.sin_port, 2) == 2, "send port");
        close(c);
        _exit(0);
    }
    struct sockaddr_in pa;
    socklen_t pl = sizeof pa;
    int s = accept(l, (void *)&pa, &pl);
    CHECK(s >= 0 && pl == sizeof pa && pa.sin_family == AF_INET, "accept address");
    uint16_t cport;
    CHECK(read_full(s, &cport, 2) == 2, "read port");
    CHECK(pa.sin_port == cport, "accepted port %d, client says %d", ntohs(pa.sin_port), ntohs(cport));
    struct sockaddr_in me, peer;
    socklen_t ml = sizeof me;
    pl = sizeof peer;
    CHECK(getsockname(s, (void *)&me, &ml) == 0 && ntohs(me.sin_port) == port, "server getsockname");
    CHECK(getpeername(s, (void *)&peer, &pl) == 0 && peer.sin_port == cport, "server getpeername");
    int v = 0;
    socklen_t vl = sizeof v;
    CHECK(getsockopt(s, SOL_SOCKET, SO_DOMAIN, &v, &vl) == 0 && v == AF_INET, "SO_DOMAIN %d", v);
    CHECK(getsockopt(s, SOL_SOCKET, SO_PROTOCOL, &v, &vl) == 0 && v == IPPROTO_TCP, "SO_PROTOCOL %d", v);
    CHECK(getsockopt(l, SOL_SOCKET, SO_ACCEPTCONN, &v, &vl) == 0 && v == 1, "SO_ACCEPTCONN");
    int one = 1;
    CHECK(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) == 0, "TCP_NODELAY");
    CHECK(getsockopt(s, IPPROTO_TCP, TCP_NODELAY, &v, &vl) == 0 && v == 1, "TCP_NODELAY back");
    errno = 0;
    CHECK(getsockopt(s, IPPROTO_TCP, TCP_INFO, &v, &vl) == -1 && errno == ENOPROTOOPT, "TCP_INFO refused");
    printf("listener port %d, client port %d, both AF_INET 127.0.0.1\n", port, ntohs(cport));
    close(s);
    close(l);
    CHECK(wait_child(p) == 0, "child");
}

static void t_addrinuse(void) {
    int port, l = listener(&port, 0);
    int b = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = loop4(port);
    int r = bind(b, (void *)&a, sizeof a);
    CHECK(r == -1 && errno == EADDRINUSE, "second bind to %d: %d", port, r);
    close(l);
    r = bind(b, (void *)&a, sizeof a);
    CHECK(r == 0, "bind after the first closed");
    printf("EADDRINUSE while bound, free after close\n");
}

static void t_halfclose(void) {
    blocking_pair(3);
}

static void t_eof(void) {
    int port, l = listener(&port, 0);
    pid_t p = fork();
    if (p == 0) {
        int c = dial(port);
        CHECK(write_full(c, "bye", 3) == 3, "write");
        close(c);
        _exit(0);
    }
    int s = accept(l, 0, 0);
    char b[8];
    CHECK(read_full(s, b, 8) == 3, "data then EOF");
    CHECK(read(s, b, 8) == 0, "EOF again");
    CHECK(wait_child(p) == 0, "child");
    printf("peer close: data, then EOF\n");
}

static void t_rst(void) {
    int port, l = listener(&port, 0);
    int c = dial(port);
    int s = accept(l, 0, 0);
    CHECK(write_full(c, "unread", 6) == 6, "write");
    sleep_ms(10);
    close(s); // closes with 6 unread bytes: TCP sends a RST
    sleep_ms(10);
    char b[8];
    ssize_t r = read(c, b, 8);
    CHECK(r == -1 && errno == ECONNRESET, "read after the peer reset: %zd", r);
    r = read(c, b, 8);
    CHECK(r == 0, "then EOF: %zd", r);
    printf("close with unread data: peer read ECONNRESET, then EOF\n");
}

static volatile int pipes;
static void on_pipe(int s) { (void)s; pipes++; }

static void t_epipe(void) {
    signal(SIGPIPE, on_pipe);
    int port, l = listener(&port, 0);
    int c = dial(port);
    int s = accept(l, 0, 0);
    close(s);
    sleep_ms(10);
    int writes = 0;
    ssize_t r;
    while ((r = write(c, "x", 1)) == 1) {
        writes++;
        sleep_ms(10);
        CHECK(writes < 100, "no EPIPE after 100 writes");
    }
    CHECK(r == -1 && errno == EPIPE, "write after the peer closed: %zd", r);
    CHECK(pipes == 1, "SIGPIPE count %d", pipes);
    r = send(c, "x", 1, MSG_NOSIGNAL);
    CHECK(r == -1 && errno == EPIPE && pipes == 1, "MSG_NOSIGNAL: %zd, %d signals", r, pipes);
    printf("write after peer close: %d writes accepted, then EPIPE with SIGPIPE; MSG_NOSIGNAL: EPIPE only\n", writes);
}

static void t_sigpipe_kill(void) {
    pid_t p = fork();
    if (p == 0) {
        signal(SIGPIPE, SIG_DFL);
        int port, l = listener(&port, 0);
        int c = dial(port);
        int s = accept(l, 0, 0);
        close(s);
        for (int i = 0; i < 100; i++) {
            write(c, "x", 1);
            sleep_ms(10);
        }
        _exit(0);
    }
    int st = wait_child(p);
    CHECK(st == 128 + SIGPIPE, "child status %d", st);
    printf("default SIGPIPE: the writer is killed by signal %d\n", SIGPIPE);
}

static void t_rcvtimeo(void) {
    int port, l = listener(&port, 0);
    int c = dial(port);
    struct timeval tv = {2, 500000};
    CHECK(setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0, "SO_RCVTIMEO");
    long long t0 = now_ms();
    char b[4];
    ssize_t r = read(c, b, 4);
    long long dt = now_ms() - t0;
    CHECK(r == -1 && errno == EAGAIN, "read: %zd", r);
    CHECK(dt >= 2500 && dt < 2600, "timed out after %lld ms", dt);
    printf("SO_RCVTIMEO 2.5 s: EAGAIN after %lld virtual ms\n", dt);
    close(l);
}

static void t_peek(void) {
    int port, l = listener(&port, 0);
    int c = dial(port);
    int s = accept(l, 0, 0);
    CHECK(write_full(c, "peekaboo", 8) == 8, "write");
    char b[16];
    ssize_t r = recv(s, b, 4, MSG_PEEK | MSG_WAITALL);
    CHECK(r == 4 && memcmp(b, "peek", 4) == 0, "peek: %zd", r);
    r = recv(s, b, 16, MSG_PEEK);
    CHECK(r == 8, "peek all: %zd", r);
    r = recv(s, b, 16, 0);
    CHECK(r == 8 && memcmp(b, "peekaboo", 8) == 0, "read: %zd", r);
    printf("MSG_PEEK leaves the bytes; the read gets them\n");
}

static void t_waitall(void) {
    int port, l = listener(&port, 0);
    pid_t p = fork();
    if (p == 0) {
        int c = dial(port);
        for (int i = 0; i < 10; i++) {
            CHECK(write_full(c, "0123456789", 10) == 10, "write");
            sleep_ms(5);
        }
        close(c);
        _exit(0);
    }
    int s = accept(l, 0, 0);
    char b[100];
    ssize_t r = recv(s, b, 100, MSG_WAITALL);
    CHECK(r == 100, "MSG_WAITALL: %zd", r);
    CHECK(wait_child(p) == 0, "child");
    printf("MSG_WAITALL: 100 bytes sent as 10 writes, one recv\n");
}

static void t_sendfile(void) {
    const long n = 1 << 20;
    int f = open("/work/sendfile.dat", O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(f >= 0, "open");
    unsigned char *b = malloc(n);
    fill(b, n, 0);
    CHECK(write_full(f, b, n) == n, "file write");
    uint64_t want = fnv(0xcbf29ce484222325ULL, b, n);
    int port, l = listener(&port, 0);
    pid_t p = fork();
    if (p == 0) {
        int c = dial(port);
        off_t off = 0;
        ssize_t r = sendfile(c, f, &off, n);
        CHECK(r == n && off == n, "sendfile: %zd", r);
        close(c);
        _exit(0);
    }
    int s = accept(l, 0, 0);
    ssize_t r = read_full(s, b, n);
    CHECK(r == n, "received %zd", r);
    CHECK(fnv(0xcbf29ce484222325ULL, b, n) == want, "content differs");
    CHECK(wait_child(p) == 0, "child");
    printf("sendfile: 1 MiB from /work to a socket, content equal\n");
}

static void t_v6(void) {
    // A dual-stack listener on [::]:0 accepts IPv4 and IPv6 clients.
    int l = socket(AF_INET6, SOCK_STREAM, 0);
    int zero = 0;
    CHECK(setsockopt(l, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero) == 0, "V6ONLY");
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    CHECK(bind(l, (void *)&a, sizeof a) == 0 && listen(l, 8) == 0, "bind/listen");
    socklen_t al = sizeof a;
    CHECK(getsockname(l, (void *)&a, &al) == 0 && al == sizeof a && a.sin6_family == AF_INET6, "name");
    int port = ntohs(a.sin6_port);
    int c4 = dial(port);
    (void)c4;
    struct sockaddr_in6 c6a = a;
    c6a.sin6_addr = in6addr_loopback;
    int c6 = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(connect(c6, (void *)&c6a, sizeof c6a) == 0, "v6 connect");
    char s1[INET6_ADDRSTRLEN], s2[INET6_ADDRSTRLEN];
    struct sockaddr_in6 p1, p2;
    socklen_t l1 = sizeof p1, l2 = sizeof p2;
    int a1 = accept(l, (void *)&p1, &l1), a2 = accept(l, (void *)&p2, &l2);
    CHECK(a1 >= 0 && a2 >= 0 && p1.sin6_family == AF_INET6 && p2.sin6_family == AF_INET6, "accept");
    inet_ntop(AF_INET6, &p1.sin6_addr, s1, sizeof s1);
    inet_ntop(AF_INET6, &p2.sin6_addr, s2, sizeof s2);
    printf("dual-stack listener on [::]:%d accepted [%s] and [%s]\n", port, s1, s2);
    CHECK(strcmp(s1, "::ffff:127.0.0.1") == 0 && strcmp(s2, "::1") == 0, "peer addresses");
    // An AF_INET listener does not accept an IPv6 client.
    int port4, l4 = listener(&port4, 0);
    c6a.sin6_port = htons(port4);
    int c = socket(AF_INET6, SOCK_STREAM, 0);
    int r = connect(c, (void *)&c6a, sizeof c6a);
    CHECK(r == -1 && errno == ECONNREFUSED, "v6 client to a v4 listener: %d", r);
    close(l4);
    // Raw sockets are refused at creation; an unknown address is unreachable.
    CHECK(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) == -1, "raw socket");
    struct sockaddr_in far = loop4(80);
    far.sin_addr.s_addr = inet_addr("192.0.2.1");
    c = socket(AF_INET, SOCK_STREAM, 0);
    r = connect(c, (void *)&far, sizeof far);
    CHECK(r == -1 && errno == ENETUNREACH, "connect to 192.0.2.1: %d", r);
    printf("v6 client to a v4-only listener: ECONNREFUSED; raw refused; 192.0.2.1 unreachable\n");
}

// ---- fault scenarios ----

/// Messages of 100 bytes; `naive` assumes one read returns one message.
static void chunk(int naive) {
    int port, l = listener(&port, 0);
    pid_t p = fork();
    if (p == 0) {
        int c = dial(port);
        char m[100];
        for (int i = 0; i < 5; i++) {
            memset(m, 'a' + i, sizeof m);
            CHECK(write_full(c, m, 100) == 100, "write");
            sleep_ms(50);
        }
        close(c);
        _exit(0);
    }
    int s = accept(l, 0, 0);
    int reads = 0, minr = 1 << 30, maxr = 0;
    for (int i = 0; i < 5; i++) {
        char m[100];
        ssize_t r;
        if (naive) {
            r = read(s, m, 100);
            reads++;
            if (r != 100) fail("naive receiver: message %d came as a read of %zd bytes", i, r);
        } else {
            size_t got = 0;
            while (got < 100) {
                r = read(s, m + got, 100 - got);
                CHECK(r > 0, "read");
                reads++;
                if (r < minr) minr = r;
                if (r > maxr) maxr = r;
                got += r;
            }
            for (int k = 0; k < 100; k++) CHECK(m[k] == 'a' + i, "content");
        }
    }
    wait_child(p);
    if (naive) printf("naive receiver: 5 messages in 5 reads\n");
    else printf("correct receiver: 5 messages in %d reads, sizes %d..%d\n", reads, minr, maxr);
}

/// A client streams data; with net-reset-permille the connection is reset mid-stream and
/// both ends see it.
static void reset(int want_reset) {
    int port, l = listener(&port, 0);
    pid_t p = fork();
    if (p == 0) {
        signal(SIGPIPE, SIG_IGN);
        int c = dial(port);
        char b[1000];
        memset(b, 'r', sizeof b);
        for (int i = 0; i < 200; i++) {
            ssize_t r = write(c, b, sizeof b);
            if (r < 0) {
                printf("client: write %d -> %s\n", i, strerror(errno));
                fflush(stdout);
                _exit(2);
            }
            sleep_ms(1);
        }
        printf("client: 200 writes done\n");
        fflush(stdout);
        close(c);
        _exit(0);
    }
    int s = accept(l, 0, 0);
    long got = 0;
    int server_reset = 0;
    for (;;) {
        char b[4096];
        ssize_t r = read(s, b, sizeof b);
        if (r < 0) {
            printf("server: read after %ld bytes -> %s\n", got, strerror(errno));
            server_reset = errno == ECONNRESET;
            break;
        }
        if (r == 0) {
            printf("server: EOF after %ld bytes\n", got);
            break;
        }
        got += r;
    }
    fflush(stdout);
    int st = wait_child(p);
    printf("client exit %d\n", st);
    if (want_reset) CHECK(server_reset && st == 2, "both ends see the reset");
    else CHECK(!server_reset && st == 0 && got == 200000, "clean stream");
}

/// Connect with a fault on the handshake: prints what connect returned and when.
static void connect_fault(const char *want) {
    int port, l = listener(&port, 0);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = loop4(port);
    long long t0 = now_ms();
    int r = connect(c, (void *)&a, sizeof a);
    long long dt = now_ms() - t0;
    int e = r == 0 ? 0 : errno;
    printf("connect -> %s after %lld virtual ms\n", r == 0 ? "connected" : strerror(e), dt);
    close(l);
    if (!strcmp(want, "connected")) CHECK(r == 0, "connected");
    else if (!strcmp(want, "refused")) CHECK(r == -1 && e == ECONNREFUSED, "refused");
    else if (!strcmp(want, "timeout")) CHECK(r == -1 && e == ETIMEDOUT && dt >= 60000, "timed out");
    else fail("unknown expectation %s", want);
}

/// A client sends a numbered message every second for 20 s; the server notes arrival times.
/// A request with a 5 s application timeout is made at 8 s (SO_RCVTIMEO on the client).
static void partition(int want_partition) {
    long long base = now_ms();
    int port, l = listener(&port, 0);
    pid_t p = fork();
    if (p == 0) {
        int c = dial(port);
        for (int i = 0; i < 20; i++) {
            char m[16];
            snprintf(m, sizeof m, "tick %02d", i);
            CHECK(write_full(c, m, 8) == 8, "tick %d", i);
            if (i == 8) {
                // The request: the server answers each "tick 08" at once.
                struct timeval tv = {5, 0};
                setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
                long long t0 = now_ms();
                char b[8];
                ssize_t r = read_full(c, b, 4);
                long long dt = now_ms() - t0;
                if (r == 4) printf("client: answer after %lld ms\n", dt);
                else printf("client: application timeout after %lld ms (%s)\n", dt, strerror(errno));
                fflush(stdout);
                if (want_partition) CHECK(r != 4 && dt >= 5000 && dt < 6000, "application timeout");
                else CHECK(r == 4, "answer");
            }
            sleep_ms(1000);
        }
        close(c);
        _exit(0);
    }
    int s = accept(l, 0, 0);
    int n = 0, in_window = 0, after = 0;
    for (;;) {
        char m[8];
        ssize_t r = read_full(s, m, 8);
        if (r != 8) break;
        long long t = now_ms() - base;
        printf("server: '%.7s' at %lld ms\n", m, t);
        fflush(stdout);
        n++;
        if (t > 5100 && t < 15000) in_window++;
        if (t >= 15000) after++;
        if (memcmp(m, "tick 08", 7) == 0) write_full(s, "ack!", 4);
    }
    wait_child(p);
    CHECK(n == 20, "all 20 ticks arrived (%d)", n);
    if (want_partition) CHECK(in_window == 0 && after > 0, "nothing inside the partition, delivery after");
    else CHECK(in_window > 0, "deliveries inside the window");
}

/// The client closes; the server writes in the meantime and notes when EOF arrives.
static void halfclose_delay(long long min_ms) {
    int port, l = listener(&port, 0);
    signal(SIGPIPE, SIG_IGN);
    int c = dial(port);
    int s = accept(l, 0, 0);
    CHECK(shutdown(c, SHUT_WR) == 0, "shutdown");
    long long t0 = now_ms();
    int ok_writes = 0;
    for (;;) {
        char b[4];
        ssize_t r = recv(s, b, 4, MSG_DONTWAIT);
        if (r == 0) break;
        CHECK(r < 0 && errno == EAGAIN, "server recv %zd", r);
        if (write(s, "abcd", 4) == 4) ok_writes++;
        sleep_ms(100);
    }
    long long dt = now_ms() - t0;
    printf("EOF reached the server %lld virtual ms after the client's shutdown; %d server writes went through meanwhile\n", dt, ok_writes);
    close(s);
    char b[4096];
    ssize_t r = read_full(c, b, sizeof b);
    printf("the half-closed client still read %zd bytes\n", r);
    CHECK(r == 4L * ok_writes, "the half-closed client reads every server write");
    CHECK(dt >= min_ms, "EOF after %lld ms, wanted at least %lld", dt, min_ms);
}

/// N one-byte request/reply round trips between two processes.
static void pingpong(int n) {
    int port, l = listener(&port, 0);
    pid_t p = fork();
    if (p == 0) {
        int s = accept(l, 0, 0);
        char b;
        while (read(s, &b, 1) == 1) CHECK(write(s, &b, 1) == 1, "echo");
        _exit(0);
    }
    int c = dial(port);
    for (int i = 0; i < n; i++) {
        char b = (char)i;
        CHECK(write(c, &b, 1) == 1, "write");
        CHECK(read(c, &b, 1) == 1 && b == (char)i, "reply %d", i);
    }
    close(c);
    wait_child(p);
    printf("%d round trips\n", n);
}

/// Fault-tolerant traffic for runs with mixed network faults: a poll echo server in a child
/// process; the parent runs CLIENTS clients one after another (up to 3 connect attempts each),
/// each sending MSGS 32-byte messages and reading the echoes. Every error is reported, not
/// fatal; exit 0 unless the program itself is broken.
static void chaos(int clients, int msgs) {
    signal(SIGPIPE, SIG_IGN);
    int port, l = listener(&port, SOCK_NONBLOCK);
    pid_t srv = fork();
    if (srv == 0) {
        struct pollfd pf[64];
        int n = 1;
        pf[0] = (struct pollfd){.fd = l, .events = POLLIN};
        for (;;) {
            CHECK(poll(pf, n, -1) > 0, "poll");
            for (int i = n - 1; i >= 1; i--) {
                if (!pf[i].revents) continue;
                char b[512];
                ssize_t r = read(pf[i].fd, b, sizeof b);
                if (r > 0 && write_full(pf[i].fd, b, r) == r) continue;
                close(pf[i].fd);
                pf[i] = pf[--n];
            }
            if (pf[0].revents & POLLIN) {
                int c = accept4(l, 0, 0, SOCK_NONBLOCK);
                if (c >= 0 && n < 64) pf[n++] = (struct pollfd){.fd = c, .events = POLLIN};
                else if (c >= 0) close(c);
            }
        }
    }
    close(l);
    int done = 0, failed = 0;
    for (int i = 0; i < clients; i++) {
        int c = -1, e = 0, tries = 0;
        long long t0 = now_ms();
        while (c < 0 && tries < 3) {
            tries++;
            c = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in a = loop4(port);
            if (connect(c, (void *)&a, sizeof a) < 0) {
                e = errno;
                close(c);
                c = -1;
            }
        }
        if (c < 0) {
            printf("client %d: connect failed after %d tries: %s at %lld ms\n", i, tries, strerror(e), now_ms() - t0);
            failed++;
            continue;
        }
        int k = 0;
        for (; k < msgs; k++) {
            char m[32], b[32];
            msg32(m, i, k);
            if (write_full(c, m, 32) != 32) { e = errno; break; }
            ssize_t r = read_full(c, b, 32);
            if (r != 32) { e = r < 0 ? errno : 0; break; }
            CHECK(memcmp(m, b, 32) == 0, "echo content");
        }
        close(c);
        if (k == msgs) done++;
        else {
            failed++;
            printf("client %d: %d of %d echoed, then %s\n", i, k, msgs, e ? strerror(e) : "EOF");
        }
    }
    kill(srv, SIGKILL);
    wait_child(srv);
    printf("chaos: %d clients complete, %d hit a fault, %lld virtual ms\n", done, failed, now_ms());
}

// ---- processes ----

static void forkserver(void) {
    int port, l = listener(&port, 0);
    pid_t clients = fork();
    if (clients == 0) {
        close(l);
        for (int i = 0; i < 3; i++) {
            int c = dial(port);
            char m[16];
            int n = snprintf(m, sizeof m, "client %d", i);
            CHECK(write_full(c, m, n) == n, "write");
            char r[64];
            ssize_t k = read_full(c, r, sizeof r);
            CHECK(k > 0, "reply");
            printf("%.*s\n", (int)k, r);
            fflush(stdout);
            close(c);
        }
        _exit(0);
    }
    for (int i = 0; i < 3; i++) {
        int s = accept(l, 0, 0);
        CHECK(s >= 0, "accept");
        pid_t h = fork();
        if (h == 0) {
            close(l);
            char m[16];
            ssize_t n = read(s, m, sizeof m);
            char r[64];
            int k = snprintf(r, sizeof r, "handler %d (pid %d) got '%.*s'", i, getpid(), (int)n, m);
            write_full(s, r, k);
            close(s);
            _exit(0);
        }
        close(s); // the handler holds the connection now
        CHECK(wait_child(h) == 0, "handler");
    }
    CHECK(wait_child(clients) == 0, "clients");
}

static void execinherit(const char *self) {
    int port, l = listener(&port, 0);
    int c = dial(port);
    int s = accept(l, 0, 0);
    pid_t p = fork();
    if (p == 0) {
        close(s);
        close(l);
        char fd[16];
        snprintf(fd, sizeof fd, "%d", c);
        execl(self, self, "exec-child", fd, (char *)0);
        _exit(127);
    }
    close(c);
    char b[64];
    ssize_t n = read(s, b, sizeof b);
    CHECK(n > 0, "read from the exec'd child");
    printf("server got '%.*s'\n", (int)n, b);
    CHECK(write_full(s, "welcome", 7) == 7, "write");
    CHECK(read(s, b, sizeof b) == 0, "EOF after the child exits");
    CHECK(wait_child(p) == 0, "child");
}

static void exec_child(int fd) {
    struct sockaddr_in me;
    socklen_t ml = sizeof me;
    CHECK(getsockname(fd, (void *)&me, &ml) == 0 && me.sin_family == AF_INET, "inherited socket name");
    char m[64];
    int n = snprintf(m, sizeof m, "hello from an exec'd image on port %d", ntohs(me.sin_port));
    CHECK(write_full(fd, m, n) == n, "write");
    char b[16];
    ssize_t k = read_full(fd, b, 7);
    CHECK(k == 7, "read");
    printf("exec'd child got '%.7s'\n", b);
    exit(0); // no close: the exit closes it
}

static void exitclose(long long min_ms) {
    int port, l = listener(&port, 0);
    pid_t p = fork();
    if (p == 0) {
        int c = dial(port);
        CHECK(write_full(c, "x", 1) == 1, "write");
        sleep_ms(1000);
        _exit(0); // the only reference is closed by the exit
    }
    int s = accept(l, 0, 0);
    char b[4];
    CHECK(read(s, b, 4) == 1, "first byte");
    long long t0 = now_ms();
    CHECK(read(s, b, 4) == 0, "EOF");
    long long dt = now_ms() - t0;
    printf("EOF %lld virtual ms after the first byte (the child slept 1000 ms, then exited)\n", dt);
    CHECK(dt >= min_ms, "EOF after %lld ms, before the exit and FIN delay (%lld)", dt, min_ms);
    wait_child(p);
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    if (argc < 2) return 2;
    mode = argv[1];
    const char *m = argv[1];
    if (!strcmp(m, "exec-child")) {
        exec_child(atoi(argv[2]));
        return 0;
    }
    if (!strcmp(m, "all")) {
        blocking_pair(20);
        epoll_echo(0, 50, 20);
        epoll_echo(1, 50, 20);
        transfer(8 << 20, 1);
        refused();
    } else if (!strcmp(m, "names")) t_names();
    else if (!strcmp(m, "refused")) refused();
    else if (!strcmp(m, "addrinuse")) t_addrinuse();
    else if (!strcmp(m, "halfclose")) t_halfclose();
    else if (!strcmp(m, "eof")) t_eof();
    else if (!strcmp(m, "rst")) t_rst();
    else if (!strcmp(m, "epipe")) t_epipe();
    else if (!strcmp(m, "sigpipe-kill")) t_sigpipe_kill();
    else if (!strcmp(m, "rcvtimeo")) t_rcvtimeo();
    else if (!strcmp(m, "peek")) t_peek();
    else if (!strcmp(m, "waitall")) t_waitall();
    else if (!strcmp(m, "sendfile")) t_sendfile();
    else if (!strcmp(m, "v6")) t_v6();
    else if (!strcmp(m, "big")) transfer((long)atoi(argv[2]) << 20, 2);
    else if (!strcmp(m, "xfer")) {
        long long ms = transfer((long)atoi(argv[2]) << 10, 0);
        if (argc > 3) CHECK(ms >= atoll(argv[3]), "transfer took %lld virtual ms", ms);
    }
    else if (!strcmp(m, "epoll")) {
        int clients = argc > 3 ? atoi(argv[3]) : 50, msgs = argc > 4 ? atoi(argv[4]) : 100;
        epoll_echo(!strcmp(argv[2], "et"), clients, msgs);
    } else if (!strcmp(m, "nbconnect")) {
        int port;
        listener(&port, 0);
        int c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        struct sockaddr_in a = loop4(port);
        long long t0 = now_us();
        CHECK(connect(c, (void *)&a, sizeof a) == -1 && errno == EINPROGRESS, "EINPROGRESS");
        int polls = 0;
        struct pollfd pf = {.fd = c, .events = POLLOUT};
        for (;;) {
            polls++;
            if (poll(&pf, 1, 0) == 1) break;
            // Not writable yet: also check that send says EAGAIN and getpeername ENOTCONN.
            CHECK(send(c, "x", 1, MSG_DONTWAIT) == -1 && errno == EAGAIN, "send before established");
            struct sockaddr_in pa;
            socklen_t pl = sizeof pa;
            CHECK(getpeername(c, (void *)&pa, &pl) == -1 && errno == ENOTCONN, "getpeername before established");
            sleep_ms(10);
        }
        long long dt = now_us() - t0;
        int e = -1;
        socklen_t el = sizeof e;
        getsockopt(c, SOL_SOCKET, SO_ERROR, &e, &el);
        printf("POLLOUT first seen %lld.%03lld virtual ms after connect (%d polls), SO_ERROR %d\n", dt / 1000, dt % 1000, polls, e);
        CHECK(e == 0, "SO_ERROR");
        if (argc > 2) CHECK(dt >= atoll(argv[2]) * 1000, "POLLOUT before the handshake");
    } else if (!strcmp(m, "chunk")) chunk(!strcmp(argv[2], "naive"));
    else if (!strcmp(m, "reset")) reset(argc > 2 && !strcmp(argv[2], "reset"));
    else if (!strcmp(m, "connect")) connect_fault(argc > 2 ? argv[2] : "connected");
    else if (!strcmp(m, "partition")) partition(argc > 2 && !strcmp(argv[2], "partitioned"));
    else if (!strcmp(m, "halfclose-delay")) halfclose_delay(argc > 2 ? atoll(argv[2]) : 0);
    else if (!strcmp(m, "pingpong")) pingpong(atoi(argv[2]));
    else if (!strcmp(m, "chaos")) chaos(atoi(argv[2]), atoi(argv[3]));
    else if (!strcmp(m, "forkserver")) forkserver();
    else if (!strcmp(m, "execinherit")) execinherit(argv[0]);
    else if (!strcmp(m, "exitclose")) exitclose(argc > 2 ? atoll(argv[2]) : 1000);
    else {
        printf("unknown mode %s\n", m);
        return 2;
    }
    printf("PASS %s\n", m);
    return 0;
}
