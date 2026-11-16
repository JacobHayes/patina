/* sandbox hardening guest: the 29 rows (not Deny or Stop) that no determinism hardening run reached, each called once or more
 * the way a program would, with its result printed. Run under the determinism hardening protocol. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static void r(const char *what, long v) { printf("%-24s r=%ld errno=%d\n", what, v, v < 0 ? errno : 0); }
static volatile int got;
static void h(int s) { got += s; }

struct xattr_args { unsigned long long value; unsigned int size, flags; };

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 1 << 16);
    signal(SIGUSR1, h); signal(SIGALRM, h);
    int p[2]; pipe(p); write(p[1], "x", 1);
    fd_set rs; FD_ZERO(&rs); FD_SET(p[0], &rs); struct timeval tv = {0, 1000};
    r("select", syscall(SYS_select, p[0] + 1, &rs, 0, 0, &tv));
    struct pollfd pf = {p[0], POLLIN, 0}; struct timespec ts = {0, 1000};
    r("ppoll", syscall(SYS_ppoll, &pf, 1, &ts, 0, 8));
    int ep = syscall(SYS_epoll_create, 4); r("epoll_create", ep);
    struct epoll_event ev = {EPOLLIN, {.u64 = 7}}; epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev);
    struct epoll_event out[2]; r("epoll_pwait2", syscall(SYS_epoll_pwait2, ep, out, 2, &ts, 0, 8));
    struct itimerval it = {{0, 0}, {0, 20000}}, old;
    r("setitimer", setitimer(ITIMER_REAL, &it, &old));
    r("getitimer", syscall(SYS_getitimer, ITIMER_REAL, &old));
    r("pause", syscall(SYS_pause));
    r("alarm", syscall(SYS_alarm, 0));
    r("alarm-set", syscall(SYS_alarm, 1));
    r("alarm-cancel", syscall(SYS_alarm, 0));
    sigset_t m; sigemptyset(&m); sigaddset(&m, SIGUSR2); sigprocmask(SIG_BLOCK, &m, 0);
    raise(SIGUSR2);
    siginfo_t si; r("rt_sigtimedwait", syscall(SYS_rt_sigtimedwait, &m, &si, &ts, 8));
    memset(&si, 0, sizeof si); si.si_code = SI_QUEUE; si.si_signo = SIGUSR1;
    r("rt_sigqueueinfo", syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1, &si));
    r("rt_tgsigqueueinfo", syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), SIGUSR1, &si));
    r("tkill", syscall(SYS_tkill, gettid(), SIGUSR1));
    r("restart_syscall", syscall(SYS_restart_syscall));
    printf("signals seen %d\n", got);
    long c = syscall(SYS_fork);
    if (c == 0) {
        r("setpgid", setpgid(0, 0));
        r("getpgid", syscall(SYS_getpgid, 0) == getpid() ? 0 : -1);
        r("setsid", setsid() > 0 ? 0 : -1);
        _exit(3);
    }
    int st = 0; waitpid(c, &st, 0); r("fork", WEXITSTATUS(st));
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    r("sched_setaffinity", syscall(SYS_sched_setaffinity, 0, sizeof cs, &cs));
    unsigned cpu = 99, node = 99; r("getcpu", syscall(SYS_getcpu, &cpu, &node, 0)); printf("cpu %u node %u\n", cpu, node);
    int q[2]; pipe(q); int q2[2]; pipe(q2);
    write(q[1], "tee-data", 8);
    r("tee", syscall(SYS_tee, q[0], q2[1], 8, 0));
    char buf[16] = "vmsplice"; struct iovec iv = {buf, 8};
    r("vmsplice", syscall(SYS_vmsplice, q2[1], &iv, 1, 0));
    int sp[2]; socketpair(AF_UNIX, SOCK_DGRAM, 0, sp);
    struct mmsghdr mm[2]; struct iovec v2[2] = {{"a", 1}, {"bc", 2}};
    memset(mm, 0, sizeof mm); mm[0].msg_hdr.msg_iov = &v2[0]; mm[0].msg_hdr.msg_iovlen = 1;
    mm[1].msg_hdr.msg_iov = &v2[1]; mm[1].msg_hdr.msg_iovlen = 1;
    r("sendmmsg", syscall(SYS_sendmmsg, sp[0], mm, 2, 0));
    char rb[2][8]; struct iovec rv[2] = {{rb[0], 8}, {rb[1], 8}}; struct mmsghdr rm[2]; memset(rm, 0, sizeof rm);
    rm[0].msg_hdr.msg_iov = &rv[0]; rm[0].msg_hdr.msg_iovlen = 1; rm[1].msg_hdr.msg_iov = &rv[1]; rm[1].msg_hdr.msg_iovlen = 1;
    r("recvmmsg", syscall(SYS_recvmmsg, sp[1], rm, 2, MSG_DONTWAIT, 0));
    void *pg = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    r("pkey_mprotect", syscall(SYS_pkey_mprotect, pg, 4096, PROT_READ, -1));
    int f = open("/work/x", O_CREAT | O_RDWR, 0644);
    struct xattr_args xa = {(unsigned long long)"val", 3, 0};
    r("setxattrat", syscall(463, AT_FDCWD, "/work/x", 0, "user.k", &xa, sizeof xa));
    char vb[16] = {0}; struct xattr_args xg = {(unsigned long long)vb, sizeof vb, 0};
    r("getxattrat", syscall(464, AT_FDCWD, "/work/x", 0, "user.k", &xg, sizeof xg));
    char lb[64]; r("listxattrat", syscall(465, f, "", AT_EMPTY_PATH, lb, sizeof lb));
    r("removexattrat", syscall(466, AT_FDCWD, "/work/x", 0, "user.k"));
    char *argv[] = {"true", 0}, *envp[] = {0};
    int t = open("/usr/bin/true", O_RDONLY);
    c = syscall(SYS_fork);
    if (c == 0) { syscall(SYS_execveat, t, "", argv, envp, AT_EMPTY_PATH); _exit(127); }
    waitpid(c, &st, 0); r("execveat", WEXITSTATUS(st));
    return 0;
}
