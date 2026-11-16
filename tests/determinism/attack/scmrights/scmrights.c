/* SCM_RIGHTS: pass descriptors, close the carrying socket with descriptors in flight, and
 * observe when the passed objects are released (a pipe's writer end in flight: the reader
 * sees EOF only once it is released). */
#define _GNU_SOURCE
#include "../common.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int sendfd(int s, int fd) {
    char c = 'x'; struct iovec io = {&c, 1}; char ctl[CMSG_SPACE(sizeof(int))];
    struct msghdr m = {0}; m.msg_iov = &io; m.msg_iovlen = 1; m.msg_control = ctl; m.msg_controllen = sizeof ctl;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&m); cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS; cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof fd);
    return sendmsg(s, &m, 0);
}
int main(void) {
    for (int round = 0; round < 50; round++) {
        int p[2]; if (pipe(p)) return 1;
        int s[2]; socketpair(AF_UNIX, SOCK_DGRAM, 0, s);
        sendfd(s[0], p[1]);
        close(p[1]);
        if (round % 2) {
            /* garbage cycle: s[1] (holding the writer end) is sent into its own receive queue,
             * so only the kernel's unix garbage collector can release it */
            sendfd(s[0], s[1]);
        }
        close(s[0]); close(s[1]); /* the writer end is now only in flight */
        int seen = -1;
        for (int i = 0; i < 200; i++) {
            struct pollfd pf = {p[0], POLLIN, 0};
            int r = poll(&pf, 1, 0);
            if (r > 0 && (pf.revents & POLLHUP)) { seen = i; break; }
            getppid();
        }
        printf("round %d hup after %d polls\n", round, seen);
        close(p[0]);
    }
    return 0;
}
