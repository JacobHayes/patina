/* The program's descriptor space: RLIMIT_NOFILE set and enforced as on Linux, and nothing it
 * can do names, allocates or sees a number of the runtime's.
 *   fdspace        limits: fill to the soft limit, F_DUPFD, dup2, raising, lowering, fork,
 *                  exec, close_range, /proc/self/fd, calls on hidden numbers
 *   fdspace spin   a CPU-bound stretch with no system call first (long enough for the stall
 *                  watchdog to send a spin probe), then the calls on hidden numbers (the
 *                  probe's among them), the fill and the listing
 * Prints one line per fact; the same output natively and under patina. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void lim(const char *tag) {
    struct rlimit r;
    getrlimit(RLIMIT_NOFILE, &r);
    printf("%s nofile %llu %llu\n", tag, (unsigned long long)r.rlim_cur, (unsigned long long)r.rlim_max);
}

static int setlim(unsigned long soft, unsigned long hard) {
    struct rlimit r = {soft, hard};
    errno = 0;
    return setrlimit(RLIMIT_NOFILE, &r) == 0 ? 0 : errno;
}

/* Open /dev/null until it fails: every number in order, then the count and errno. */
static int fill(const char *tag) {
    int n = 0, e;
    printf("%s fds", tag);
    for (;;) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) {
            e = errno;
            break;
        }
        printf(" %d", fd);
        if (++n > 70000) break;
    }
    printf("\n%s opened %d errno %d\n", tag, n, e);
    return n;
}

static void after_full(const char *tag) {
    int p[2], r;
    errno = 0;
    r = pipe(p);
    printf("%s pipe %d errno %d\n", tag, r, errno);
    errno = 0;
    r = socket(AF_UNIX, SOCK_STREAM, 0);
    printf("%s socket %d errno %d\n", tag, r, errno);
    errno = 0;
    r = dup(0);
    printf("%s dup %d errno %d\n", tag, r, errno);
    errno = 0;
    r = fcntl(0, F_DUPFD, 5);
    printf("%s F_DUPFD 5 %d errno %d\n", tag, r, errno);
    /* What does not allocate still works with a full table. */
    struct stat st;
    printf("%s stat %d\n", tag, stat("/guest", &st));
}

/* A descriptor sent in SCM_RIGHTS before the table filled, received after: the data arrives,
 * the descriptor does not (MSG_CTRUNC); with one number free, it arrives there. */
static int sp[2];
static void send_one(void) {
    char c = 'x', buf[CMSG_SPACE(sizeof(int))];
    struct iovec io = {&c, 1};
    struct msghdr m = {0};
    m.msg_iov = &io, m.msg_iovlen = 1, m.msg_control = buf, m.msg_controllen = sizeof buf;
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET, h->cmsg_type = SCM_RIGHTS, h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &(int){0}, sizeof(int));
    sendmsg(sp[0], &m, 0);
}
static void recv_one(const char *tag) {
    char c, buf[CMSG_SPACE(sizeof(int))];
    struct iovec io = {&c, 1};
    struct msghdr m = {0};
    m.msg_iov = &io, m.msg_iovlen = 1, m.msg_control = buf, m.msg_controllen = sizeof buf;
    int r = recvmsg(sp[1], &m, 0);
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    int fd = -1;
    if (h && h->cmsg_type == SCM_RIGHTS) memcpy(&fd, CMSG_DATA(h), sizeof fd);
    printf("%s recvmsg %d ctrunc %d fd %d\n", tag, r, !!(m.msg_flags & MSG_CTRUNC), fd);
}

static void dups(const char *tag) {
    static const int at[] = {1023, 1024, 2047, 2048, 2999, 3000, 3090, 3093, 3100, 4031, 4095, 4096, 1000000};
    for (unsigned i = 0; i < sizeof at / sizeof *at; i++) {
        errno = 0;
        int r = dup2(0, at[i]);
        printf("%s dup2 %d %d errno %d\n", tag, at[i], r, errno);
        if (r >= 0) close(r);
        errno = 0;
        r = fcntl(0, F_DUPFD, at[i]);
        printf("%s F_DUPFD %d %d errno %d\n", tag, at[i], r, errno);
        if (r >= 0) close(r);
        errno = 0;
        r = dup3(0, at[i], O_CLOEXEC);
        printf("%s dup3 %d %d errno %d\n", tag, at[i], r, errno);
        if (r >= 0) close(r);
    }
}

/* Numbers no program descriptor has: every call on them answers as for a closed one. */
static void hidden(void) {
    static const int at[] = {2999, 3000, 3008, 3090, 3091, 3092, 3093, 3100, 4032, 4095};
    for (unsigned i = 0; i < sizeof at / sizeof *at; i++) {
        int fd = at[i];
        struct stat st;
        errno = 0;
        int a = fstat(fd, &st), ea = errno;
        errno = 0;
        int b = fcntl(fd, F_GETFD), eb = errno;
        struct pollfd p = {fd, POLLIN, 0};
        int c = poll(&p, 1, 0);
        errno = 0;
        int d = close(fd), ed = errno;
        printf("hidden %d fstat %d/%d fcntl %d/%d poll %d/%x close %d/%d\n", fd, a, ea, b, eb, c, p.revents, d, ed);
        /* Calls that read a descriptor as a value or from a structure. */
        int dst = open("/dev/null", O_WRONLY);
        errno = 0;
        int q = fcntl(dst, 1027 /* F_DUPFD_QUERY */, fd), eq = errno;
        errno = 0;
        int k = ioctl(dst, 0x40049409 /* FICLONE */, fd), ek = errno;
        long long range[4] = {fd, 0, 0, 0};
        errno = 0;
        int g = ioctl(dst, 0x4020940d /* FICLONERANGE */, range), eg = errno;
        siginfo_t si;
        errno = 0;
        int w = waitid(3 /* P_PIDFD */, fd, &si, WEXITED | WNOHANG), ew = errno;
        close(dst);
        printf("hidden %d dupfd-query %d/%d ficlone %d/%d ficlonerange %d/%d waitid-pidfd %d/%d\n", fd, q, eq, k, ek,
               g, eg, w, ew);
    }
}

static void listing(const char *tag) {
    DIR *d = opendir("/proc/self/fd");
    int n[8192], k = 0;
    struct dirent *e;
    while (d && (e = readdir(d)) && k < 8192)
        if (e->d_name[0] != '.') n[k++] = atoi(e->d_name);
    for (int i = 1; i < k; i++)
        for (int j = i; j > 0 && n[j - 1] > n[j]; j--) {
            int t = n[j]; n[j] = n[j - 1]; n[j - 1] = t;
        }
    printf("%s /proc/self/fd %d:", tag, k);
    int run = 0;
    for (int i = 0; i < k; i++) {
        /* Ranges as a-b, so a full table prints short. */
        if (i + 1 < k && n[i + 1] == n[i] + 1) { if (!run) { printf(" %d-", n[i]); run = 1; } continue; }
        if (run) printf("%d", n[i]); else printf(" %d", n[i]);
        run = 0;
    }
    printf("\n");
    if (d) closedir(d);
}

static volatile unsigned long sink;

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "show")) { /* after exec */
        lim("exec");
        return 0;
    }
    /* Natively the limits are the caller's: start from the ones a guest starts with. */
    if (setlim(1024, 2048)) { printf("setup failed\n"); return 1; }
    lim("start");
    if (argc > 1 && !strcmp(argv[1], "spin")) {
        unsigned long x = 1;
        for (unsigned long i = 0; i < 200000000ul; i++) x = x * 6364136223846793005ul + i;
        sink = x;
        printf("spin done\n");
        hidden();
        fill("spin");
        close(1023);
        listing("spin");
        return 0;
    }
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    send_one();
    send_one();
    fill("soft");
    after_full("soft");
    recv_one("full");
    close(1000);
    recv_one("one free");
    close(1023);
    listing("full");
    close_range(3, ~0U, 0);
    listing("closed");
    dups("soft");
    hidden();
    printf("raise above hard %d\n", setlim(2048, 4096));
    printf("soft above hard %d\n", setlim(4096, 2048));
    printf("raise to hard %d\n", setlim(2048, 2048) == 0 ? 0 : -1);
    setlim(2048, 2048);
    lim("raised");
    fill("hard");
    after_full("hard");
    dups("hard");
    close_range(3, ~0U, CLOSE_RANGE_CLOEXEC);
    printf("cloexec 3 %d\n", fcntl(3, F_GETFD));
    close_range(3, ~0U, 0);
    printf("lower hard %d\n", setlim(1024, 1500));
    lim("lowered");
    printf("raise again %d\n", setlim(1024, 2048));
    printf("soft 0 %d\n", setlim(0, 1500));
    errno = 0;
    int z = open("/dev/null", O_RDONLY);
    printf("soft 0 open %d errno %d\n", z, errno);
    setlim(1024, 1500);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        lim("child");
        fflush(stdout);
        _exit(0);
    }
    waitpid(c, NULL, 0);
    c = fork();
    if (c == 0) {
        execl(argv[0], argv[0], "show", (char *)0);
        _exit(9);
    }
    int st;
    waitpid(c, &st, 0);
    printf("exec status %d\n", WEXITSTATUS(st));
    listing("end");
    return 0;
}
