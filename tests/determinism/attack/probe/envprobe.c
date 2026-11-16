/* determinism hardening attack guest: everything a process inherits or can query about its
 * environment, its descriptors and its limits.  Prints one line per value. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <linux/fs.h>
#include <unistd.h>

static void hex(const char *tag, const void *p, size_t n) {
    const unsigned char *b = p;
    printf("%s ", tag);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static void statx_all(const char *tag, int dirfd, const char *path, int flags) {
    unsigned char buf[256];
    memset(buf, 0xa5, sizeof buf);
    long r = syscall(SYS_statx, dirfd, path, flags, 0x0fffffffu, buf);
    printf("%s statx r=%ld errno=%d\n", tag, r, r ? errno : 0);
    if (!r) hex(tag, buf, sizeof buf);
}

static void fd_report(const char *tag, int fd) {
    struct stat st; struct statfs sf; char l[300];
    char t[64];
    memset(&st, 0, sizeof st); memset(&sf, 0, sizeof sf);
    int r = fstat(fd, &st);
    printf("%s fstat r=%d\n", tag, r);
    if (!r) hex(tag, &st, sizeof st);
    snprintf(t, sizeof t, "%s.x", tag);
    statx_all(t, fd, "", AT_EMPTY_PATH);
    r = fstatfs(fd, &sf);
    printf("%s fstatfs r=%d\n", tag, r);
    if (!r) hex(tag, &sf, sizeof sf);
    printf("%s fl=%x fdfl=%x seek=%ld\n", tag, fcntl(fd, F_GETFL), fcntl(fd, F_GETFD), (long)lseek(fd, 0, SEEK_CUR));
    snprintf(l, sizeof l, "/proc/self/fd/%d", fd);
    char lk[300]; ssize_t n = readlink(l, lk, sizeof lk - 1);
    if (n >= 0) lk[n] = 0; else snprintf(lk, sizeof lk, "err%d", errno);
    printf("%s link %s\n", tag, lk);
    if (!lstat(l, &st)) hex("lstat-fdlink", &st, sizeof st);
    else printf("lstat-fdlink err %d\n", errno);
    if (!stat(l, &st)) hex("stat-fdlink", &st, sizeof st);
    else printf("stat-fdlink err %d\n", errno);
    int v = 0;
    printf("%s FIONREAD %d %d\n", tag, ioctl(fd, FIONREAD, &v), v);
    unsigned fl = 0;
    printf("%s GETFLAGS %d %d %x\n", tag, ioctl(fd, FS_IOC_GETFLAGS, &fl), errno, fl);
    int bsz = 0;
    printf("%s FIGETBSZ %d %d\n", tag, ioctl(fd, FIGETBSZ, &bsz), bsz);
    struct fsxattr fx; memset(&fx, 0, sizeof fx);
    long rr = ioctl(fd, FS_IOC_FSGETXATTR, &fx);
    printf("%s FSGETXATTR %ld %d\n", tag, rr, rr ? errno : 0);
    if (!rr) hex("fsx", &fx, sizeof fx);
    if (fd > 2) printf("%s SEEK_DATA %ld SEEK_HOLE %ld\n", tag, (long)lseek(fd, 0, SEEK_DATA), (long)lseek(fd, 0, SEEK_HOLE));
}

static void sock_report(const char *tag, int s) {
    static const int opts[] = {SO_TYPE, SO_ERROR, SO_SNDBUF, SO_RCVBUF, SO_RCVLOWAT, SO_SNDLOWAT,
        SO_PASSCRED, SO_ACCEPTCONN, SO_DOMAIN, SO_PROTOCOL, SO_PEEK_OFF, 57 /*SO_COOKIE*/,
        71 /*SO_NETNS_COOKIE*/, 55 /*SO_MEMINFO*/, 56 /*SO_INCOMING_NAPI_ID*/, 49 /*SO_INCOMING_CPU*/,
        SO_MARK, SO_PRIORITY, 77 /*SO_PEERPIDFD*/, SO_PEERCRED, 59 /*SO_PEERGROUPS*/, 31 /*SO_PEERSEC*/,
        SO_TIMESTAMP, 8 /*KEEPALIVE*/, SO_BUSY_POLL, 82 /* SO_RCVMARK */, 83};
    for (unsigned i = 0; i < sizeof opts / sizeof *opts; i++) {
        unsigned char v[128]; socklen_t l = sizeof v; memset(v, 0, sizeof v);
        int r = getsockopt(s, SOL_SOCKET, opts[i], v, &l);
        printf("%s sockopt %d r=%d e=%d l=%u ", tag, opts[i], r, r ? errno : 0, l);
        hex("", v, r ? 0 : (l > 64 ? 64 : l));
    }
    struct sockaddr_un a; socklen_t al = sizeof a; memset(&a, 0, sizeof a);
    int r = getsockname(s, (void *)&a, &al);
    printf("%s name r=%d l=%u ", tag, r, al); hex("", &a, al < sizeof a ? al : sizeof a);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    setvbuf(stdout, NULL, _IOLBF, 1 << 16);
    mode_t um = umask(022); umask(um);
    printf("umask %o\n", um);
    for (int s = 1; s < 65; s++) {
        struct sigaction sa; memset(&sa, 0, sizeof sa);
        if (sigaction(s, NULL, &sa) == 0)
            printf("sig %d handler %lx flags %lx\n", s, (unsigned long)sa.sa_handler, (unsigned long)sa.sa_flags);
    }
    sigset_t m; sigprocmask(SIG_BLOCK, NULL, &m); hex("sigmask", &m, 8);
    sigpending(&m); hex("sigpending", &m, 8);
    for (int r = 0; r < 16; r++) {
        struct rlimit rl; getrlimit(r, &rl);
        printf("rlimit %d %lx %lx\n", r, (unsigned long)rl.rlim_cur, (unsigned long)rl.rlim_max);
    }
    printf("ids %d %d %d %d %d %d %d\n", getpid(), getppid(), getuid(), geteuid(), getgid(), getpgrp(), getsid(0));
    gid_t gs[64]; int ng = getgroups(64, gs); printf("groups %d", ng);
    for (int i = 0; i < ng; i++) printf(" %d", gs[i]);
    printf("\n");
    printf("prctl dumpable %d\n", prctl(PR_GET_DUMPABLE));
    char cwd[512]; printf("cwd %s\n", getcwd(cwd, sizeof cwd) ? cwd : "?");
    
    fflush(stdout);
    for (int fd = 0; fd < 3; fd++) { char t[16]; snprintf(t, sizeof t, "fd%d", fd); fd_report(t, fd); }
    fd_report("work", open("/work", O_RDONLY | O_DIRECTORY));
    fd_report("usr", open("/usr", O_RDONLY | O_DIRECTORY));
    fd_report("libc", open("/usr/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY));
    fd_report("devnull", open("/dev/null", O_RDONLY));
    fd_report("dev", open("/dev", O_RDONLY | O_DIRECTORY));
    fd_report("cpuinfo", open("/proc/cpuinfo", O_RDONLY));
    fd_report("selfstat", open("/proc/self/stat", O_RDONLY));
    int p[2]; if (pipe(p)) return 9; fd_report("pipe", p[0]);
    printf("pipesz %d\n", fcntl(p[1], F_GETPIPE_SZ));
    int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp); fd_report("usock", sp[0]); sock_report("usock", sp[0]);
    int dg[2]; socketpair(AF_UNIX, SOCK_DGRAM, 0, dg); sock_report("udg", dg[0]);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0); struct sockaddr_un a = {.sun_family = AF_UNIX};
    strcpy(a.sun_path + 1, "determinism"); bind(ls, (void *)&a, sizeof(sa_family_t) + 4); listen(ls, 1); sock_report("ulisten", ls);
    int ws = socket(AF_INET, SOCK_STREAM, 0); sock_report("inet", ws);
    int mf = memfd_create("determinism", 0); fd_report("memfd", mf);
    /* writes of every byte to stdout's file: its blocks */
    static char big[1 << 20]; memset(big, 'z', sizeof big);
    fflush(stdout);
    int bigfd = open("/work/big", O_CREAT | O_RDWR, 0644);
    ssize_t w = write(bigfd, big, sizeof big);
    printf("bigwrite %zd %d\n", w, w < 0 ? errno : 0);
    w = pwrite(bigfd, big, 4096, 64ll << 20);
    printf("bigwrite64M %zd %d\n", w, w < 0 ? errno : 0);
    void *mm = mmap(NULL, 1ull << 36, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    printf("mmap64G %s %d\n", mm == MAP_FAILED ? "fail" : "ok", mm == MAP_FAILED ? errno : 0);
    void *br = sbrk(0); int br2 = brk((char *)br + (1ull << 33)) ; printf("brk8G %d\n", br2);
    int nfd = 0; int last = -1;
    for (;;) { int f = dup(0); if (f < 0) { printf("dup stop errno %d at %d last %d\n", errno, nfd, last); break; } nfd++; last = f; if (nfd > 5000) break; }
    fflush(stdout);
    return 0;
}
