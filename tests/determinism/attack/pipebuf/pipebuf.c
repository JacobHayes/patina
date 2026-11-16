/* Pipe and AF_UNIX buffer boundaries: non-blocking writes of every size around capacity
 * with a reader draining odd amounts; FIONREAD, F_GETPIPE_SZ, SIOCOUTQ-like queries. */
#define _GNU_SOURCE
#include "../common.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
static char buf[1 << 18];
static void drive(const char *tag, int r, int w) {
    fcntl(w, F_SETFL, O_NONBLOCK); fcntl(r, F_SETFL, O_NONBLOCK);
    uint64_t h = FNV0; int lines = 0;
    for (int sz = 1; sz < 140000; sz += (sz < 4200 ? 97 : 1531)) {
        ssize_t n = write(w, buf, sz);
        int q = -1; ioctl(r, FIONREAD, &q);
        int dr = (sz * 7 + 13) % 6007;
        ssize_t m = read(r, buf + 100000, dr);
        long rec[5] = {sz, n, n < 0 ? errno : 0, q, m};
        h = fnv_add(h, rec, sizeof rec);
        if (lines++ < 12) printf("%s sz=%d n=%zd q=%d drained=%zd\n", tag, sz, n, q, m);
    }
    for (;;) { ssize_t m = read(r, buf, sizeof buf); if (m <= 0) break; h = fnv_add(h, &m, sizeof m); }
    printf("%s hash %016llx\n", tag, (unsigned long long)h);
}
int main(void) {
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (char)(i * 131);
    int p[2]; if (pipe(p)) return 1;
    printf("pipe size %d\n", fcntl(p[1], F_GETPIPE_SZ));
    drive("pipe", p[0], p[1]);
    int s[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, s);
    int v; socklen_t l = sizeof v; getsockopt(s[0], SOL_SOCKET, SO_SNDBUF, &v, &l); printf("stream sndbuf %d\n", v);
    drive("ustream", s[1], s[0]);
    int d[2]; socketpair(AF_UNIX, SOCK_DGRAM, 0, d);
    drive("udgram", d[1], d[0]);
    int q[2]; socketpair(AF_UNIX, SOCK_SEQPACKET, 0, q);
    drive("useqp", q[1], q[0]);
    return 0;
}
