/* Containment of system call arguments: pointers into the runtime's region, passed to calls the
 * kernel would read or write through (both directions, direct and inside iovecs and msghdrs),
 * and the memory calls on ranges there.
 *   ptrprobe ADDR...   ADDR: page addresses in the runtime's region (the script takes them from
 *                      proto::layout and the runtime binary)
 * For each address and call it prints `CALL ADDR RESULT` (-errno on failure). Natively nothing
 * is mapped at those addresses, so a native run prints what the kernel answers for a hole;
 * under Patina the lines must be the same, and every result must equal the one for a hole the
 * program made itself (else `DIFF` and exit 1). `learned HASH` hashes every byte that came back
 * through the pipe or the socket after the calls that send (none: nothing of the runtime's).
 * After a refused receive the program's own bytes may still be queued where the kernel, faulting
 * part-way, would have dropped them (a datagram): those are drained, not compared.
 * The `dead-` probes put the address in an argument the call does not read for the values of
 * the others (it answers as for any value there).
 * `story` lines are where the region is not a plain hole: `munmap` there answers EINVAL (as
 * above the top of user space), and a buffer that starts in program memory and runs into the
 * region is refused whole (EFAULT, nothing moved) where the kernel would move the first part;
 * `/proc/self/task/<tid>/mem`, named through the task directory, is not there (ENOENT). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
static int pip[2], sv[2], filefd, dfd, ep, lst;
static char *dm;
static char *argv0;
static uint64_t learned = 0xcbf29ce484222325ull;
static const char data[16] = "0123456789abcdef";

static long rs(long r) { return r < 0 ? -errno : r; }

/* Take whatever the pipe, the socket and the file hold; hash it (`h`) and count it. */
static long drain(uint64_t *h) {
    char b[512];
    long n, total = 0;
    while ((n = read(pip[0], b, sizeof b)) > 0 || (n = recv(sv[1], b, sizeof b, MSG_DONTWAIT)) > 0 ||
           ((n = pread(filefd, b, sizeof b, 0)) > 0 && ftruncate(filefd, 0) == 0)) {
        total += n;
        if (h)
            for (long i = 0; i < n; i++) *h = (*h ^ (uint8_t)b[i]) * 0x100000001b3ull;
    }
    return total;
}

static void fill_pipe(void) { write(pip[1], data, 16); }
static void fill_sock(void) { send(sv[0], data, 16, 0); }

typedef long (*probe)(char *a);

/* out: the kernel reads at `a` */
static long p_write(char *a) { return rs(syscall(SYS_write, pip[1], a, 16)); }
static long p_writev(char *a) {
    struct iovec v = {a, 16};
    return rs(syscall(SYS_writev, pip[1], &v, 1));
}
static long p_writev_array(char *a) { return rs(syscall(SYS_writev, pip[1], a, 1)); }
static long p_pwrite64(char *a) { return rs(syscall(SYS_pwrite64, filefd, a, 16, 0)); }
static long p_sendmsg(char *a) {
    struct iovec v = {a, 16};
    struct msghdr m = {.msg_iov = &v, .msg_iovlen = 1};
    return rs(syscall(SYS_sendmsg, sv[0], &m, 0));
}
static long p_sendmsg_control(char *a) {
    struct iovec v = {(void *)data, 16};
    struct msghdr m = {.msg_iov = &v, .msg_iovlen = 1, .msg_control = a, .msg_controllen = 24};
    return rs(syscall(SYS_sendmsg, sv[0], &m, 0));
}
static long p_sendmsg_hdr(char *a) { return rs(syscall(SYS_sendmsg, sv[0], a, 0)); }
static long p_sendto_addr(char *a) { return rs(syscall(SYS_sendto, sv[0], data, 16, 0, a, 16)); }
static long p_openat(char *a) {
    long r = rs(syscall(SYS_openat, AT_FDCWD, a, O_RDONLY));
    if (r >= 0) close(r);
    return r;
}
static long p_futex_wake(char *a) { return rs(syscall(SYS_futex, a, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0)); }
static long p_execve_argv(char *a) { return rs(syscall(SYS_execve, argv0, a, environ)); }
static long p_pselect6(char *a) {
    struct timespec z = {0, 0};
    return rs(syscall(SYS_pselect6, pip[0] + 1, a, 0, 0, &z, 0));
}
/* in: the kernel writes at `a` */
static long p_read(char *a) { fill_pipe(); return rs(syscall(SYS_read, pip[0], a, 16)); }
static long p_readv(char *a) {
    struct iovec v = {a, 16};
    fill_pipe();
    return rs(syscall(SYS_readv, pip[0], &v, 1));
}
static long p_recvmsg(char *a) {
    struct iovec v = {a, 16};
    struct msghdr m = {.msg_iov = &v, .msg_iovlen = 1};
    fill_sock();
    return rs(syscall(SYS_recvmsg, sv[1], &m, MSG_DONTWAIT));
}
static long p_recvmsg_hdr(char *a) { fill_sock(); return rs(syscall(SYS_recvmsg, sv[1], a, MSG_DONTWAIT)); }
static long p_getdents64(char *a) {
    lseek(dfd, 0, SEEK_SET);
    return rs(syscall(SYS_getdents64, dfd, a, 4096));
}
static long p_fstat(char *a) { return rs(syscall(SYS_fstat, filefd, a)); }
static long p_pipe2(char *a) { return rs(syscall(SYS_pipe2, a, 0)); }
static long p_clock_gettime(char *a) { return rs(syscall(SYS_clock_gettime, CLOCK_MONOTONIC, a)); }
static long p_getrandom(char *a) { return rs(syscall(SYS_getrandom, a, 16, 0)); }
static long p_epoll_pwait(char *a) { return rs(syscall(SYS_epoll_pwait, ep, a, 4, 0, 0, 8)); }
static long p_ppoll(char *a) {
    struct timespec z = {0, 0};
    return rs(syscall(SYS_ppoll, a, 1, &z, 0, 8));
}
static long p_fcntl_getlk(char *a) { return rs(syscall(SYS_fcntl, filefd, F_GETLK, a)); }
static long p_fcntl_rw_hint(char *a) { return rs(syscall(SYS_fcntl, filefd, 1035 /* F_GET_RW_HINT */, a)); }
static long p_getsockopt(char *a) {
    socklen_t n = 4;
    return rs(syscall(SYS_getsockopt, sv[0], SOL_SOCKET, SO_TYPE, a, &n));
}
/* ranges */
static long p_mprotect(char *a) { return rs(syscall(SYS_mprotect, a, 4096, PROT_READ)); }
static long p_madvise(char *a) { return rs(syscall(SYS_madvise, a, 4096, MADV_DONTNEED)); }
static long p_msync(char *a) { return rs(syscall(SYS_msync, a, 4096, MS_ASYNC)); }
static long p_mremap(char *a) { return rs(syscall(SYS_mremap, a, 4096, 8192, MREMAP_MAYMOVE, 0)); }
/* dead: the call does not read the register holding `a` */
static long p_dead_mremap(char *a) {
    long r = rs(syscall(SYS_mremap, dm, 4096, 4096, 0, a));
    return r == (long)dm ? 0 : r;
}
static long p_dead_epoll_ctl_del(char *a) {
    struct epoll_event ev = {.events = EPOLLIN};
    epoll_ctl(ep, EPOLL_CTL_ADD, pip[0], &ev);
    return rs(syscall(SYS_epoll_ctl, ep, EPOLL_CTL_DEL, pip[0], a));
}
static long p_dead_recvfrom(char *a) {
    char b[16];
    fill_sock();
    return rs(syscall(SYS_recvfrom, sv[1], b, 16, MSG_DONTWAIT, 0, a));
}
static long p_dead_accept4(char *a) { return rs(syscall(SYS_accept4, lst, 0, a, 0)); }
static long p_dead_futex_wake(char *a) {
    static uint32_t w;
    return rs(syscall(SYS_futex, &w, FUTEX_WAKE_PRIVATE, 1, a, a, 0));
}
static long p_dead_fcntl_getfd(char *a) { return rs(syscall(SYS_fcntl, filefd, F_GETFD, a)); }
static long p_dead_clock_nanosleep(char *a) {
    struct timespec z = {0, 0};
    return rs(syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, TIMER_ABSTIME, &z, a));
}

static const struct {
    const char *name;
    probe f;
    int sends; /* the kernel reads at the address: what arrives is hashed */
} probes[] = {
    {"write", p_write, 1}, {"writev", p_writev, 1}, {"writev-array", p_writev_array, 1},
    {"pwrite64", p_pwrite64, 1}, {"sendmsg", p_sendmsg, 1}, {"sendmsg-control", p_sendmsg_control, 1},
    {"sendmsg-hdr", p_sendmsg_hdr, 1}, {"sendto-addr", p_sendto_addr, 1}, {"openat", p_openat, 1},
    {"futex-wake", p_futex_wake, 1}, {"execve-argv", p_execve_argv, 1}, {"read", p_read},
    {"readv", p_readv}, {"recvmsg", p_recvmsg}, {"recvmsg-hdr", p_recvmsg_hdr},
    {"getdents64", p_getdents64}, {"fstat", p_fstat}, {"pipe2", p_pipe2},
    {"clock_gettime", p_clock_gettime}, {"getrandom", p_getrandom},
    {"epoll_pwait", p_epoll_pwait}, {"ppoll", p_ppoll}, {"pselect6", p_pselect6, 1},
    {"fcntl-getlk", p_fcntl_getlk}, {"fcntl-rw-hint", p_fcntl_rw_hint}, {"getsockopt", p_getsockopt},
    {"mprotect", p_mprotect},
    {"madvise", p_madvise}, {"msync", p_msync}, {"mremap", p_mremap},
    {"dead-mremap", p_dead_mremap}, {"dead-epoll_ctl-del", p_dead_epoll_ctl_del},
    {"dead-recvfrom", p_dead_recvfrom}, {"dead-accept4", p_dead_accept4},
    {"dead-futex-wake", p_dead_futex_wake}, {"dead-fcntl-getfd", p_dead_fcntl_getfd},
    {"dead-clock_nanosleep", p_dead_clock_nanosleep},
};

int main(int argc, char **argv) {
    argv0 = argv[0];
    if (pipe2(pip, O_NONBLOCK) || socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) return 3;
    char path[] = "/tmp/ptrprobe-XXXXXX";
    filefd = mkstemp(path);
    dfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLOUT};
    if (filefd < 0 || dfd < 0 || ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, pip[1], &ev)) return 4;
    unlink(path);
    dm = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    lst = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sa_family_t an = AF_UNIX; /* autobind */
    if (dm == MAP_FAILED || lst < 0 || bind(lst, (struct sockaddr *)&an, sizeof an) || listen(lst, 1)) return 6;
    /* A hole of the program's own making. */
    char *hole = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (hole == MAP_FAILED || munmap(hole, 4096)) return 5;
    int diffs = 0;
    for (int k = 1; k < argc; k++) {
        char *a = (char *)strtoull(argv[k], 0, 0);
        for (size_t i = 0; i < sizeof probes / sizeof probes[0]; i++) {
            uint64_t *h_out = probes[i].sends ? &learned : 0;
            long r = probes[i].f(a);
            drain(h_out);
            long h = probes[i].f(hole);
            drain(h_out);
            printf("%s %p %ld\n", probes[i].name, a, r);
            if (r != h) {
                printf("DIFF %s %p: %ld, for a hole %ld\n", probes[i].name, a, r, h);
                diffs++;
            }
        }
        printf("story munmap %p %ld\n", a, rs(syscall(SYS_munmap, a, 4096)));
    }
    printf("learned %016llx\n", (unsigned long long)learned);
    /* A buffer from the page below the region into it. */
    char *below = (char *)0x600000000000ull - 4096;
    if (mmap(below, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) == below) {
        memset(below, 'S', 4096);
        long r = rs(syscall(SYS_write, pip[1], below, 8192));
        printf("story straddle-write %ld drained %ld\n", r, drain(0));
    }
    int td = open("/proc/self/task", O_RDONLY | O_DIRECTORY);
    char name[32];
    snprintf(name, sizeof name, "%ld/mem", (long)syscall(SYS_gettid));
    long m = td < 0 ? -errno : rs(syscall(SYS_openat, td, name, O_RDONLY));
    printf("story task-mem %ld\n", m > 0 ? 0 : m);
    return diffs ? 1 : 0;
}
