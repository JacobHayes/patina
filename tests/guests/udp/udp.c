// UDP sockets written against ordinary AF_INET/AF_INET6 calls. Each mode prints what it
// observed and ends with "PASS <mode>" (exit 0) or "FAIL <mode>: why" (exit 1). Times are
// CLOCK_MONOTONIC, virtual under patina.
//
//   udp rpc retry|noretry [N]  a client process asks a server process N questions; `retry`
//                              resends after a 20 ms timeout, `noretry` waits forever for each
//                              answer (a lost datagram hangs it: a deadlock under patina)
//   udp order trust|seq [N]    a burst of N numbered datagrams; `trust` fails if they arrive out of
//                              order, `seq` puts them back in order by number
//   udp semantics              names, ephemeral ports, peek, truncation, recvmmsg/sendmmsg,
//                              poll, ECONNREFUSED, SO_RCVBUF drops, reuse options, v6, refusals
//   udp fork                   a bound socket shared by a parent and its child
//   udp dns                    getaddrinfo of localhost and of an unknown name
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
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

/// A UDP socket bound to 127.0.0.1:port (0: ephemeral).
static int bound(int port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(s >= 0, "socket");
    struct sockaddr_in a = loop4(port);
    CHECK(bind(s, (void *)&a, sizeof a) == 0, "bind %d", port);
    return s;
}

// ---- rpc: request/response with or without retry ----

static void rpc(int retry, int n) {
    int srv = bound(0), port = port_of(srv);
    pid_t p = fork();
    if (p == 0) {
        // The server answers each question "q K" with "a K", forever.
        char b[64];
        struct sockaddr_in from;
        for (;;) {
            socklen_t fl = sizeof from;
            ssize_t r = recvfrom(srv, b, sizeof b - 1, 0, (void *)&from, &fl);
            if (r <= 0) continue;
            b[r] = 0;
            int k;
            if (sscanf(b, "q %d", &k) != 1) continue;
            int m = snprintf(b, sizeof b, "a %d", k);
            sendto(srv, b, m, 0, (void *)&from, fl);
        }
    }
    close(srv);
    int c = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to = loop4(port);
    CHECK(connect(c, (void *)&to, sizeof to) == 0, "connect");
    int resent = 0;
    for (int k = 0; k < n; k++) {
        char q[32], b[64];
        int m = snprintf(q, sizeof q, "q %d", k);
        CHECK(send(c, q, m, 0) == m, "send");
        for (;;) {
            struct pollfd pf = {c, POLLIN, 0};
            int r = poll(&pf, 1, retry ? 20 : -1);
            if (r == 0) {
                resent++;
                CHECK(send(c, q, m, 0) == m, "resend");
                continue;
            }
            ssize_t got = recv(c, b, sizeof b - 1, 0);
            CHECK(got > 0, "recv");
            b[got] = 0;
            int a;
            CHECK(sscanf(b, "a %d", &a) == 1, "answer %s", b);
            if (a == k) break;
            // An answer to an earlier question (a duplicate or a late one): ignore it.
            CHECK(retry && a < k, "answer %d to question %d", a, k);
        }
    }
    kill(p, SIGKILL);
    waitpid(p, 0, 0);
    printf("rpc: %d answers, %d resends\n", n, resent);
}

// ---- order: a burst of numbered datagrams ----

static void order(int trust, int n) {
    int r = bound(0), port = port_of(r);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to = loop4(port);
    for (int k = 0; k < n; k++)
        CHECK(sendto(s, &k, sizeof k, 0, (void *)&to, sizeof to) == sizeof k, "sendto");
    int seen[256] = {0}, next = 0, ooo = 0;
    for (int k = 0; k < n; k++) {
        int v;
        CHECK(recv(r, &v, sizeof v, 0) == sizeof v, "recv");
        if (v != next) ooo++;
        if (trust) CHECK(v == next, "datagram %d arrived when %d was expected", v, next);
        seen[v % 256] = 1;
        while (seen[next % 256] && next < n) seen[next++ % 256] = 0;
    }
    printf("order: %d datagrams, %d out of order\n", n, ooo);
}

// ---- semantics ----

static int shut_fd, poll_got = -2;
static void *poller(void *arg) {
    (void)arg;
    struct pollfd pf = {shut_fd, POLLIN, 0};
    poll_got = poll(&pf, 1, 5000);
    return NULL;
}

static void semantics(void) {
    // Ephemeral ports come from the run's counter; getsockname shows the bound address.
    int a = bound(0), b = bound(0);
    int pa = port_of(a), pb = port_of(b);
    CHECK(pa >= 32768 && pb >= 32768 && pa != pb, "ephemeral %d %d", pa, pb);
    struct sockaddr_in ta = loop4(pa), from;
    socklen_t fl = sizeof from;
    // sendto/recvfrom with addresses; MSG_PEEK; MSG_TRUNC; FIONREAD.
    CHECK(sendto(b, "hello world", 11, 0, (void *)&ta, sizeof ta) == 11, "sendto");
    char buf[64];
    CHECK(recv(a, buf, sizeof buf, MSG_PEEK) == 11, "peek");
    int q = -1;
    CHECK(ioctl(a, FIONREAD, &q) == 0 && q == 11, "FIONREAD %d", q);
    CHECK(recv(a, buf, 5, MSG_TRUNC) == 11 && memcmp(buf, "hello", 5) == 0, "MSG_TRUNC");
    CHECK(recv(a, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN, "EAGAIN after the one datagram");
    CHECK(sendto(b, "0123456789", 10, 0, (void *)&ta, sizeof ta) == 10, "sendto 2");
    struct iovec iv = {buf, 4};
    struct msghdr mh = {.msg_name = &from, .msg_namelen = sizeof from, .msg_iov = &iv, .msg_iovlen = 1};
    CHECK(recvmsg(a, &mh, 0) == 4 && (mh.msg_flags & MSG_TRUNC), "recvmsg truncation flag");
    CHECK(ntohs(from.sin_port) == pb && from.sin_addr.s_addr == htonl(INADDR_LOOPBACK), "source");
    // sendmmsg / recvmmsg.
    struct mmsghdr mm[3];
    char p3[3][8];
    struct iovec v3[3];
    memset(mm, 0, sizeof mm);
    for (int i = 0; i < 3; i++) {
        snprintf(p3[i], 8, "m%d", i);
        v3[i] = (struct iovec){p3[i], 2};
        mm[i].msg_hdr = (struct msghdr){.msg_name = &ta, .msg_namelen = sizeof ta, .msg_iov = &v3[i], .msg_iovlen = 1};
    }
    CHECK(sendmmsg(b, mm, 3, 0) == 3, "sendmmsg");
    struct pollfd pf = {a, POLLIN, 0};
    CHECK(poll(&pf, 1, 1000) == 1 && (pf.revents & POLLIN), "poll");
    usleep(1000); // all three have arrived (the delay is far below 1 ms)
    char r3[3][8];
    for (int i = 0; i < 3; i++) {
        v3[i] = (struct iovec){r3[i], 8};
        mm[i].msg_hdr = (struct msghdr){.msg_iov = &v3[i], .msg_iovlen = 1};
    }
    int got = recvmmsg(a, mm, 3, MSG_DONTWAIT, 0);
    CHECK(got == 3 && mm[0].msg_len == 2, "recvmmsg %d", got);
    // A connected socket: getpeername; ECONNREFUSED after sending to a port nobody holds,
    // reported once (SO_ERROR reads and clears it); an unconnected socket hears nothing.
    int c = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dead = loop4(9);
    CHECK(getpeername(c, (void *)&from, &fl) == -1 && errno == ENOTCONN, "ENOTCONN");
    CHECK(connect(c, (void *)&dead, sizeof dead) == 0, "connect");
    fl = sizeof from;
    CHECK(getpeername(c, (void *)&from, &fl) == 0 && ntohs(from.sin_port) == 9, "getpeername");
    CHECK(send(c, "x", 1, 0) == 1, "send to a closed port");
    pf = (struct pollfd){c, POLLIN, 0};
    CHECK(poll(&pf, 1, 1000) == 1, "the error wakes a poller");
    CHECK(recv(c, buf, sizeof buf, 0) == -1 && errno == ECONNREFUSED, "ECONNREFUSED");
    CHECK(send(c, "x", 1, 0) == 1, "send again");
    usleep(1000);
    int err = 0;
    socklen_t el = sizeof err;
    CHECK(getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == ECONNREFUSED, "SO_ERROR %d", err);
    CHECK(getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0, "SO_ERROR cleared");
    // FIONREAD leaves a pending error pending.
    CHECK(send(c, "x", 1, 0) == 1, "send a third time");
    usleep(1000);
    CHECK(ioctl(c, FIONREAD, &q) == 0 && q == 0, "FIONREAD with an error pending: %d", q);
    CHECK(recv(c, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == ECONNREFUSED, "error kept by FIONREAD");
    // A sender that ignores errors (fire and forget) can still receive afterwards.
    for (int i = 0; i < 2000; i++) {
        send(c, "x", 1, 0);
        usleep(100);
    }
    usleep(1000);
    getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &el);
    CHECK(connect(c, (void *)&ta, sizeof ta) == 0, "connect to a");
    struct sockaddr_in tc = loop4(port_of(c));
    CHECK(sendto(a, "back", 4, 0, (void *)&tc, sizeof tc) == 4, "send to c");
    usleep(1000); // delivered before c reads
    struct timeval tv = {5, 0};
    CHECK(setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0, "SO_RCVTIMEO");
    CHECK(recv(c, buf, sizeof buf, 0) == 4, "receive after 2000 refused sends: errno %d", errno);
    CHECK(sendto(b, "x", 1, 0, (void *)&dead, sizeof dead) == 1, "unconnected send to a closed port");
    usleep(1000);
    CHECK(getsockopt(b, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0, "unconnected: no error");
    // SO_RCVBUF: a receiver that does not read loses what does not fit.
    int small = 4096, sent = 0, kept = 0;
    CHECK(setsockopt(a, SOL_SOCKET, SO_RCVBUF, &small, sizeof small) == 0, "SO_RCVBUF");
    char big[1000] = {0};
    for (int i = 0; i < 50; i++) sent += sendto(b, big, sizeof big, 0, (void *)&ta, sizeof ta) == sizeof big;
    usleep(1000);
    while (recv(a, big, sizeof big, MSG_DONTWAIT) > 0) kept++;
    CHECK(sent == 50 && kept > 0 && kept < 50, "SO_RCVBUF %d: kept %d of %d", small, kept, sent);
    // Reuse: a second bind needs SO_REUSEADDR on both.
    int r1 = socket(AF_INET, SOCK_DGRAM, 0), r2 = socket(AF_INET, SOCK_DGRAM, 0), one = 1;
    struct sockaddr_in rp = loop4(40000);
    CHECK(bind(r1, (void *)&rp, sizeof rp) == 0, "bind 40000");
    CHECK(bind(r2, (void *)&rp, sizeof rp) == -1 && errno == EADDRINUSE, "EADDRINUSE");
    close(r1);
    r1 = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(r1, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(r2, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    CHECK(bind(r1, (void *)&rp, sizeof rp) == 0 && bind(r2, (void *)&rp, sizeof rp) == 0, "SO_REUSEADDR");
    // IPv6, dual stack: a [::] socket hears 127.0.0.1 as ::ffff:127.0.0.1.
    int s6 = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 a6 = {.sin6_family = AF_INET6, .sin6_addr = in6addr_any};
    CHECK(bind(s6, (void *)&a6, sizeof a6) == 0, "bind [::]");
    socklen_t l6 = sizeof a6;
    getsockname(s6, (void *)&a6, &l6);
    struct sockaddr_in t6 = loop4(ntohs(a6.sin6_port));
    CHECK(sendto(b, "v4", 2, 0, (void *)&t6, sizeof t6) == 2, "to [::] over v4");
    struct sockaddr_in6 f6;
    l6 = sizeof f6;
    CHECK(recvfrom(s6, buf, sizeof buf, 0, (void *)&f6, &l6) == 2, "recv on [::]");
    char s[64];
    inet_ntop(AF_INET6, &f6.sin6_addr, s, sizeof s);
    CHECK(strcmp(s, "::ffff:127.0.0.1") == 0, "v4-mapped source %s", s);
    // Refused or unreachable: multicast, an address outside the run, too large.
    struct sockaddr_in m = loop4(5353), far = loop4(53);
    m.sin_addr.s_addr = inet_addr("224.0.0.251");
    far.sin_addr.s_addr = inet_addr("192.0.2.1");
    CHECK(sendto(b, "x", 1, 0, (void *)&m, sizeof m) == -1 && errno == ENETUNREACH, "multicast");
    CHECK(sendto(b, "x", 1, 0, (void *)&far, sizeof far) == -1 && errno == ENETUNREACH, "outside");
    static char huge[70000];
    CHECK(sendto(b, huge, sizeof huge, 0, (void *)&ta, sizeof ta) == -1 && errno == EMSGSIZE, "EMSGSIZE");
    CHECK(send(b, "x", 1, 0) == -1 && errno == EDESTADDRREQ, "EDESTADDRREQ");
    int ty = 0;
    el = sizeof ty;
    CHECK(getsockopt(b, SOL_SOCKET, SO_TYPE, &ty, &el) == 0 && ty == SOCK_DGRAM, "SO_TYPE");
    // shutdown(SHUT_RD) wakes a thread polling the socket.
    pthread_t th;
    shut_fd = bound(0);
    CHECK(pthread_create(&th, NULL, poller, NULL) == 0, "pthread_create");
    usleep(1000);
    shutdown(shut_fd, SHUT_RD);
    CHECK(pthread_join(th, NULL) == 0 && poll_got == 1, "shutdown did not wake the poller: %d", poll_got);
    printf("semantics: ephemeral %d %d, kept %d of 50 at SO_RCVBUF 4096\n", pa, pb, kept);
}

// ---- fork: one bound socket, two processes ----

static void forked(void) {
    int s = bound(0), port = port_of(s);
    pid_t p = fork();
    if (p == 0) {
        char b[8];
        // The child takes one datagram and answers from the shared socket.
        struct sockaddr_in f;
        socklen_t fl = sizeof f;
        CHECK(recvfrom(s, b, sizeof b, 0, (void *)&f, &fl) == 4, "child recv");
        CHECK(sendto(s, "pong", 4, 0, (void *)&f, fl) == 4, "child send");
        _exit(0);
    }
    int c = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to = loop4(port);
    CHECK(sendto(c, "ping", 4, 0, (void *)&to, sizeof to) == 4, "send");
    char b[8];
    CHECK(recv(c, b, sizeof b, 0) == 4 && memcmp(b, "pong", 4) == 0, "pong");
    int st;
    waitpid(p, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child");
    close(s);
    // The port is free again once the last descriptor is closed.
    int again = bound(port);
    printf("fork: shared socket answered, port %d rebound\n", port);
    close(again);
}

// ---- dns ----

static void lookup(const char *name) {
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *res = 0;
    int r = getaddrinfo(name, "80", &hints, &res);
    if (r != 0) {
        printf("%s: error %d (%s)\n", name, r, gai_strerror(r));
        return;
    }
    printf("%s:", name);
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        char s[64];
        void *a = p->ai_family == AF_INET ? (void *)&((struct sockaddr_in *)p->ai_addr)->sin_addr
                                          : (void *)&((struct sockaddr_in6 *)p->ai_addr)->sin6_addr;
        inet_ntop(p->ai_family, a, s, sizeof s);
        printf(" %s", s);
    }
    printf("\n");
    freeaddrinfo(res);
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    mode = argc > 1 ? argv[1] : "?";
    const char *arg = argc > 2 ? argv[2] : "";
    int n = argc > 3 ? atoi(argv[3]) : 20;
    if (!strcmp(mode, "rpc")) rpc(!strcmp(arg, "retry"), n);
    else if (!strcmp(mode, "order")) order(!strcmp(arg, "trust"), n);
    else if (!strcmp(mode, "semantics")) semantics();
    else if (!strcmp(mode, "fork")) forked();
    else if (!strcmp(mode, "dns")) {
        lookup("localhost");
        lookup("unknown.example");
    } else fail("unknown mode");
    printf("PASS %s\n", mode);
    return 0;
}
