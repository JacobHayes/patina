/* epoll_wait order with 500 descriptors made ready in a seeded order (level and edge),
 * plus poll and select over the same set. */
#define _GNU_SOURCE
#include "../common.h"
#include <poll.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/eventfd.h>
#include <unistd.h>
#define N 500
int main(void) {
    int r[N], w[N]; uint64_t st = 0x9e3779b97f4a7c15ull;
    for (int i = 0; i < N; i++) { int p[2]; if (pipe(p)) return 1; r[i] = p[0]; w[i] = p[1]; }
    int ep = epoll_create1(0), ee = epoll_create1(0);
    for (int i = 0; i < N; i++) {
        struct epoll_event e = {.events = EPOLLIN, .data.u32 = i}; epoll_ctl(ep, EPOLL_CTL_ADD, r[i], &e);
        e.events = EPOLLIN | EPOLLET; epoll_ctl(ee, EPOLL_CTL_ADD, r[i], &e);
    }
    int order[N]; for (int i = 0; i < N; i++) order[i] = i;
    for (int i = N - 1; i > 0; i--) { st ^= st << 13; st ^= st >> 7; st ^= st << 17; int j = st % (i + 1); int t = order[i]; order[i] = order[j]; order[j] = t; }
    for (int i = 0; i < N; i++) write(w[order[i]], "x", 1);
    struct epoll_event ev[N]; uint64_t h = FNV0;
    for (int round = 0; round < 3; round++) {
        int n = epoll_wait(ep, ev, 97, 0); h = fnv_add(h, &n, sizeof n);
        for (int i = 0; i < n; i++) h = fnv_add(h, &ev[i].data.u32, 4);
        printf("lt round %d n=%d first %u last %u\n", round, n, n ? ev[0].data.u32 : 0, n ? ev[n - 1].data.u32 : 0);
    }
    int n = epoll_wait(ee, ev, N, 0); h = fnv_add(h, &n, sizeof n);
    for (int i = 0; i < n; i++) h = fnv_add(h, &ev[i].data.u32, 4);
    printf("et n=%d first %u last %u hash %016llx\n", n, n ? ev[0].data.u32 : 0, n ? ev[n - 1].data.u32 : 0, (unsigned long long)h);
    char c; for (int i = 0; i < N; i += 3) read(r[i], &c, 1);
    struct pollfd pf[N]; for (int i = 0; i < N; i++) { pf[i].fd = r[i]; pf[i].events = POLLIN; }
    int pn = poll(pf, N, 0); uint64_t ph = FNV0; for (int i = 0; i < N; i++) ph = fnv_add(ph, &pf[i].revents, 2);
    printf("poll n=%d hash %016llx\n", pn, (unsigned long long)ph);
    fd_set s; FD_ZERO(&s); int mx = 0; for (int i = 0; i < 200; i++) { FD_SET(r[i], &s); if (r[i] > mx) mx = r[i]; }
    struct timeval tv = {0, 0}; int sn = select(mx + 1, &s, 0, 0, &tv);
    printf("select n=%d hash %016llx\n", sn, (unsigned long long)fnv_add(FNV0, &s, sizeof s));
    n = epoll_wait(ep, ev, N, 0); h = FNV0; for (int i = 0; i < n; i++) h = fnv_add(h, &ev[i].data.u32, 4);
    printf("lt after drain n=%d hash %016llx\n", n, (unsigned long long)h);
    return 0;
}
