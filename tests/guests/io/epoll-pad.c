// The same epoll events with different padding (arm64: bytes 4 to 8 of each struct
// epoll_event, which the kernel neither reads nor writes): two EPOLL_CTL_MOD calls whose
// events differ only there, and two epoll_wait calls into buffers prefilled differently.
// tests/io/09-epoll-pad compares their records' hashes in the boundary log.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

static void fill(struct epoll_event *e, int byte, uint64_t data) {
    memset(e, byte, sizeof *e);
    e->events = EPOLLIN;
    e->data.u64 = data;
}

int main(void) {
    int p[2];
    if (pipe(p) || write(p[1], "x", 1) != 1)
        return 1;
    int ep = epoll_create1(0);
    struct epoll_event ev[4];
    fill(ev, 0, 7);
    if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, p[0], ev))
        return 2;
    for (int byte = 0; byte <= 0xa5; byte += 0xa5) {
        fill(ev, byte, 7);
        if (epoll_ctl(ep, EPOLL_CTL_MOD, p[0], ev))
            return 3;
    }
    int n[2];
    for (int i = 0; i < 2; i++) {
        memset(ev, i ? 0xa5 : 0, sizeof ev);
        n[i] = epoll_wait(ep, ev, 4, 0);
        if (n[i] != 1 || ev[0].data.u64 != 7)
            return 4;
    }
    printf("ok %d %d\n", n[0], n[1]);
    return 0;
}
