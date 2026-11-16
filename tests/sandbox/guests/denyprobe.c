/* sandbox hardening guest: requests of the open-ended calls that no row lists (ioctl requests, fcntl
 * commands, prctl options, socket options). Each must be refused with its documented errno
 * and recorded; the run goes on. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

static void r(const char *what, long v) { printf("%-40s r=%ld errno=%d\n", what, v, v < 0 ? errno : 0); }

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 1 << 16);
    int f = open("/work/f", O_CREAT | O_RDWR, 0644);
    long v = 0;
    r("ioctl FS_IOC_GETVERSION", ioctl(f, 0x80087601, &v));
    r("ioctl FS_IOC_FIEMAP", ioctl(f, 0xc020660b, &v));
    r("ioctl TCGETS (terminal)", ioctl(f, 0x5401, &v));
    r("fcntl F_GETOWN", fcntl(f, F_GETOWN));
    r("fcntl F_SETLEASE", fcntl(f, F_SETLEASE, F_RDLCK));
    r("fcntl F_NOTIFY", fcntl(f, 1026, 0));
    r("prctl PR_GET_TIMERSLACK", prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0));
    r("prctl PR_GET_SECCOMP", prctl(PR_GET_SECCOMP, 0, 0, 0, 0));
    r("prctl PR_GET_NO_NEW_PRIVS", prctl(39, 0, 0, 0, 0));
    int sp[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    unsigned char b[64]; socklen_t l = sizeof b;
    r("getsockopt SO_COOKIE", getsockopt(sp[0], SOL_SOCKET, 57, b, &l));
    l = sizeof b; r("getsockopt SO_PEERGROUPS", getsockopt(sp[0], SOL_SOCKET, 59, b, &l));
    l = sizeof b; r("getsockopt SO_MEMINFO", getsockopt(sp[0], SOL_SOCKET, 55, b, &l));
    int one = 1;
    r("setsockopt SO_TIMESTAMP", setsockopt(sp[0], SOL_SOCKET, 29, &one, sizeof one));
    l = sizeof b; r("getsockopt SOL_IP 1", getsockopt(sp[0], 0, 1, b, &l));
    l = sizeof b; r("getsockopt SO_TYPE (listed)", getsockopt(sp[0], SOL_SOCKET, SO_TYPE, b, &l));
    l = sizeof b; r("getsockopt on a file (ENOTSOCK)", getsockopt(f, SOL_SOCKET, 57, b, &l));
    return 0;
}
