/* Argument registers a call does not read: every call the runtime passes, rewrites or answers
 * whose later arguments are read only for some values of the earlier ones (a flag, a command,
 * a NULL pointer), made with JUNK in the arguments it ignores. The boundary log must not show
 * them: two runs with different JUNK of the same length give one digest (as a program whose
 * libc leaves a different scratch value in a register on another CPU must).
 *   deadargs JUNK     JUNK: 16 hex digits (its low 32 bits, as a descriptor, are a hidden one)
 * Every call must also answer as it does natively (the comment on each line): a register the
 * call ignores is neither a hidden descriptor nor a pointer that is checked. Prints nothing;
 * exit status 1 names the first call that answered otherwise on stderr. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long J;
static int bad;

static long rs(long r) { return r < 0 ? -errno : r; }

/* want(NAME, RESULT, OK): OK is the answer's test. */
#define want(name, r, ok)                                              \
    do {                                                               \
        long v_ = (r);                                                 \
        if (!(ok)) {                                                   \
            fprintf(stderr, "deadargs: %s answered %ld\n", name, v_); \
            bad = 1;                                                   \
        }                                                              \
    } while (0)
#define zero(name, r) want(name, r, v_ == 0)
#define nonneg(name, r) want(name, r, v_ >= 0)

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    J = (long)strtoull(argv[1], 0, 16);
    char path[] = "/tmp/deadargs-XXXXXX";
    int fd = mkstemp(path);
    int sv[2], ep = epoll_create1(0);
    if (fd < 0 || ep < 0 || socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) return 3;
    char buf[64] = "0123456789abcdef";
    struct iovec iov = {buf, 16};
    if (write(fd, buf, 16) != 16) return 4;

    /* mremap: the new address only with MREMAP_FIXED or MREMAP_DONTUNMAP. */
    char *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    want("mremap", rs(syscall(SYS_mremap, m, 4096, 4096, 0, J)), v_ == (long)m);
    /* mmap: no descriptor for an anonymous mapping (JUNK as a descriptor is a hidden one). */
    long a = rs(syscall(SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, J, 0));
    nonneg("mmap-anonymous", a);
    /* open, openat: the mode only when creating. */
    nonneg("openat", rs(syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, J)));
#ifdef SYS_open
    nonneg("open", rs(syscall(SYS_open, path, O_RDONLY | O_CLOEXEC, J)));
#endif
    /* mknodat: the device only for a device node. */
    char fifo[64];
    snprintf(fifo, sizeof fifo, "%s.fifo", path);
    zero("mknodat", rs(syscall(SYS_mknodat, AT_FDCWD, fifo, S_IFIFO | 0600, J)));
    unlink(fifo);
#ifdef SYS_mknod
    zero("mknod", rs(syscall(SYS_mknod, fifo, S_IFIFO | 0600, J)));
    unlink(fifo);
#endif
    /* fcntl, ioctl, prctl: what the command reads. */
    nonneg("fcntl-getfd", rs(syscall(SYS_fcntl, fd, F_GETFD, J)));
    nonneg("fcntl-getfl", rs(syscall(SYS_fcntl, fd, F_GETFL, J)));
    zero("ioctl-fioclex", rs(syscall(SYS_ioctl, fd, FIOCLEX, J)));
    nonneg("prctl-get-dumpable", rs(syscall(SYS_prctl, PR_GET_DUMPABLE, J, J, J, J)));
    zero("prctl-set-name", rs(syscall(SYS_prctl, PR_SET_NAME, "deadargs", J, J, J)));
    /* PR_SET_VMA with a sub-option other than PR_SET_VMA_ANON_NAME: EINVAL before the rest. */
    want("prctl-set-vma-other", rs(syscall(SYS_prctl, 0x53564d41, 1, J, J, J)), v_ == -EINVAL);
    /* An unknown fcntl command reads nothing more (refused). */
    want("fcntl-unknown", rs(syscall(SYS_fcntl, fd, 99999, J)), v_ == -EINVAL);
#ifdef SYS_arch_prctl
    /* ARCH_GET_CPUID ignores its argument (the runtime answers EINVAL, natively 0 or 1). */
    syscall(SYS_arch_prctl, 0x1011, J);
#endif
    /* futex: by operation. */
    uint32_t word = 1;
    zero("futex-wake", rs(syscall(SYS_futex, &word, FUTEX_WAKE_PRIVATE, 1, J, J, J)));
    want("futex-wait", rs(syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 2, 0, J, J)), v_ == -EAGAIN);
    zero("futex-wake-bitset", rs(syscall(SYS_futex, &word, FUTEX_WAKE_BITSET_PRIVATE, 1, J, J, 1)));
    /* clone without CLONE_VM (a fork): no tid words, no TLS. */
    long pid = syscall(SYS_clone, SIGCHLD, 0, J, J, J);
    if (pid == 0) syscall(SYS_exit_group, 0);
    int st = -1;
    want("clone", pid, v_ > 0 && waitpid(pid, &st, 0) == pid && st == 0);
    /* epoll_ctl: no event for EPOLL_CTL_DEL. */
    struct epoll_event ev = {.events = EPOLLIN};
    zero("epoll_ctl-add", rs(syscall(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, sv[1], &ev)));
    zero("epoll_ctl-del", rs(syscall(SYS_epoll_ctl, ep, EPOLL_CTL_DEL, sv[1], J)));
    /* ppoll, epoll_pwait: no signal-set size without a set. */
    struct timespec z = {0, 0};
    struct pollfd p = {sv[0], POLLOUT, 0};
    want("ppoll", rs(syscall(SYS_ppoll, &p, 1, &z, 0, J)), v_ == 1);
    struct epoll_event evs[2];
    zero("epoll_pwait", rs(syscall(SYS_epoll_pwait, ep, evs, 2, 0, 0, J)));
    /* sendto, recvfrom, accept4: no address length without an address. */
    want("sendto", rs(syscall(SYS_sendto, sv[0], buf, 16, 0, 0, J)), v_ == 16);
    want("recvfrom", rs(syscall(SYS_recvfrom, sv[1], buf, 16, MSG_DONTWAIT, 0, J)), v_ == 16);
    int l = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sa_family_t an = AF_UNIX; /* autobind */
    if (l < 0 || bind(l, (struct sockaddr *)&an, sizeof an) || listen(l, 1)) return 5;
    want("accept4", rs(syscall(SYS_accept4, l, 0, J, 0)), v_ == -EAGAIN);
    /* clock_nanosleep: no remaining time for an absolute sleep. */
    zero("clock_nanosleep", rs(syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, TIMER_ABSTIME, &z, J)));
    /* preadv, pwritev, preadv2: the high half of the offset is shifted out on a 64-bit kernel. */
    want("preadv", rs(syscall(SYS_preadv, fd, &iov, 1, 0, J)), v_ == 16);
    want("pwritev", rs(syscall(SYS_pwritev, fd, &iov, 1, 0, J)), v_ == 16);
    want("preadv2", rs(syscall(SYS_preadv2, fd, &iov, 1, 0, J, 0)), v_ == 16);
    /* getcpu: the third argument is unused. */
    unsigned cpu, node;
    zero("getcpu", rs(syscall(SYS_getcpu, &cpu, &node, J)));
    /* The SDK channel: HELLO reads only the operation (natively ENOSYS). */
    syscall(0x7061, 1, J, J);
    unlink(path);
    return bad;
}
