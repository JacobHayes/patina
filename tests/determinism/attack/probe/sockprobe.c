/* determinism hardening attack guest: AF_UNIX socket options and control messages that could
 * carry host state (cookies, timestamps, pidfds). */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/net_tstamp.h>

static void hex(const char *tag, const void *p, size_t n) {
    const unsigned char *b = p;
    printf("%s ", tag);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static void opt8(const char *tag, int s, int o) {
    unsigned char v[8] = {0}; socklen_t l = 8;
    int r = getsockopt(s, SOL_SOCKET, o, v, &l);
    printf("%s opt %d r=%d e=%d l=%u ", tag, o, r, r ? errno : 0, l); hex("", v, 8);
}

static void ts_test(const char *tag, int opt, int val) {
    int sv[2]; socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    int r = setsockopt(sv[1], SOL_SOCKET, opt, &val, sizeof val);
    printf("%s set opt %d r=%d e=%d\n", tag, opt, r, r ? errno : 0);
    send(sv[0], "x", 1, 0);
    char d[8], c[512]; struct iovec io = {d, sizeof d};
    struct msghdr m = {0}; m.msg_iov = &io; m.msg_iovlen = 1; m.msg_control = c; m.msg_controllen = sizeof c;
    ssize_t n = recvmsg(sv[1], &m, 0);
    printf("%s recv n=%zd ctl=%zu ", tag, n, (size_t)m.msg_controllen);
    hex("", c, m.msg_controllen > 128 ? 128 : m.msg_controllen);
    close(sv[0]); close(sv[1]);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    opt8("pair", sv[0], 57);  /* SO_COOKIE */
    opt8("pair", sv[0], 71);  /* SO_NETNS_COOKIE */
    opt8("pair", sv[0], 49);  /* SO_INCOMING_CPU */
    ts_test("tsval", SO_TIMESTAMP, 1);
    ts_test("tsns", SO_TIMESTAMPNS, 1);
    ts_test("tsing", SO_TIMESTAMPING, SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE);
    ts_test("passcred", SO_PASSCRED, 1);
    ts_test("passsec", 34, 1);   /* SO_PASSSEC */
    ts_test("passpidfd", 76, 1); /* SO_PASSPIDFD */
    ts_test("rxq", 40, 1);       /* SO_RXQ_OVFL */
    /* SO_PEERPIDFD of a child that exits; poll the pidfd before and after */
    int cv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, cv);
    pid_t c = fork();
    if (c == 0) { close(cv[0]); char b; read(cv[1], &b, 1); _exit(3); }
    close(cv[1]);
    int pfd = -1; socklen_t l = sizeof pfd;
    int r = getsockopt(cv[0], SOL_SOCKET, 77, &pfd, &l);
    printf("peerpidfd r=%d e=%d fd=%d\n", r, r ? errno : 0, pfd);
    write(cv[0], "g", 1);
    int ready = 0, spins = 0;
    if (pfd >= 0) {
        for (spins = 0; spins < 2000; spins++) {
            struct pollfd p = {pfd, POLLIN, 0};
            ready = poll(&p, 1, 0);
            if (ready) break;
        }
    }
    printf("pidfd ready=%d after %d polls\n", ready, spins);
    int st; waitpid(c, &st, 0); printf("child status %x\n", st);
    return 0;
}
