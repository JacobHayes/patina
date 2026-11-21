// files fs-tour: every call of the files classes at least once on /work, through raw syscalls,
// printing every return value and every byte of every stat/statx/statfs/getdents buffer.
// Lines whose answer is virtual by design (limits, system information, refused interfaces)
// start with "virt "; the differential test masks their values. On an architecture without
// a legacy call (arm64 has no open, stat, mkdir...) its line makes the call's *at form; utimes,
// futimesat, utime and getdents, which have no equivalent, are left out there.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef SYS_open // the generic table (arm64): the *at forms the legacy calls stand for
#define SYS_open SYS_openat, AT_FDCWD
#define SYS_creat SYS_openat, AT_FDCWD
#define CREAT_FLAGS O_CREAT | O_WRONLY | O_TRUNC,
#define SYS_mkdir SYS_mkdirat, AT_FDCWD
#define SYS_mknod SYS_mknodat, AT_FDCWD
#define SYS_readlink SYS_readlinkat, AT_FDCWD
#define SYS_access SYS_faccessat, AT_FDCWD
#define SYS_chmod SYS_fchmodat, AT_FDCWD
#define EVENTFD(n) syscall(SYS_eventfd2, n, 0)
#define SYMLINK(t, l) syscall(SYS_symlinkat, t, AT_FDCWD, l)
#define LINK(a, b) syscall(SYS_linkat, AT_FDCWD, a, AT_FDCWD, b, 0)
#define STAT(p, b) syscall(SYS_newfstatat, AT_FDCWD, p, b, 0)
#define LSTAT(p, b) syscall(SYS_newfstatat, AT_FDCWD, p, b, AT_SYMLINK_NOFOLLOW)
#define CHOWN(p, u, g) syscall(SYS_fchownat, AT_FDCWD, p, u, g, 0)
#define UNLINK(p) syscall(SYS_unlinkat, AT_FDCWD, p, 0)
#define LCHOWN(p, u, g) syscall(SYS_fchownat, AT_FDCWD, p, u, g, AT_SYMLINK_NOFOLLOW)
#define RENAME(a, b) syscall(SYS_renameat, AT_FDCWD, a, AT_FDCWD, b)
#define RMDIR(p) syscall(SYS_unlinkat, AT_FDCWD, p, AT_REMOVEDIR)
#define DUP2(a, b) syscall(SYS_dup3, a, b, 0)
#define PIPE(p) syscall(SYS_pipe2, p, 0)
#else
#define CREAT_FLAGS
#define EVENTFD(n) syscall(SYS_eventfd, n)
#define SYMLINK(t, l) syscall(SYS_symlink, t, l)
#define LINK(a, b) syscall(SYS_link, a, b)
#define STAT(p, b) syscall(SYS_stat, p, b)
#define LSTAT(p, b) syscall(SYS_lstat, p, b)
#define CHOWN(p, u, g) syscall(SYS_chown, p, u, g)
#define UNLINK(p) syscall(SYS_unlink, p)
#define LCHOWN(p, u, g) syscall(SYS_lchown, p, u, g)
#define RENAME(a, b) syscall(SYS_rename, a, b)
#define RMDIR(p) syscall(SYS_rmdir, p)
#define DUP2(a, b) syscall(SYS_dup2, a, b)
#define PIPE(p) syscall(SYS_pipe, p)
#endif

static long R(const char *what, long r) {
    if (r < 0) printf("%s = -1 errno %d\n", what, errno);
    else printf("%s = %ld\n", what, r);
    return r;
}
static long V(const char *what, long r) { // virtual by design
    if (r < 0) printf("virt %s = -1 errno %d\n", what, errno);
    else printf("virt %s = %ld\n", what, r);
    return r;
}
static void hex(const char *kind, const char *label, const void *p, size_t n) {
    const unsigned char *b = p;
    printf("%s %s ", kind, label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}
static void st(const char *label, long r, const void *buf) {
    R(label, r);
    if (r == 0) hex("stat", label, buf, sizeof(struct stat));
}
static void stx(const char *label, long r, const void *buf) {
    R(label, r);
    if (r == 0) hex("statx", label, buf, 256);
}
static void stfs(const char *label, long r, const void *buf) {
    R(label, r);
    if (r == 0) hex("statfs", label, buf, 120);
}
static void dents(const char *label, int fd, long nr) {
    char buf[4096];
    for (;;) {
        long n = syscall(nr, fd, buf, sizeof buf);
        R(label, n);
        if (n <= 0) break;
        hex("dents", label, buf, n);
    }
}
static void rl(const char *label, long r, const char *buf) {
    R(label, r);
    if (r > 0) printf("link %s %.*s\n", label, (int)r, buf);
}

int main(void) {
    char sb[256], buf[8192];
    long fd, fd2, r;
    const char *W = "/work";
    R("chdir", syscall(SYS_chdir, W));
    R("umask", syscall(SYS_umask, 022));
    char cwd[256];
    r = R("getcwd", syscall(SYS_getcwd, cwd, sizeof cwd));
    if (r > 0) printf("cwd %s\n", cwd);

    // ---- creation ----
    R("mkdir", syscall(SYS_mkdir, "/work/d1", 0755));
    R("mkdirat", syscall(SYS_mkdirat, AT_FDCWD, "d1/sub", 0700));
    fd = R("open-creat", syscall(SYS_open, "/work/a.txt", O_CREAT | O_RDWR | O_TRUNC, 0644));
    R("write", syscall(SYS_write, fd, "hello world\n", 12));
    R("pwrite64", syscall(SYS_pwrite64, fd, "HELLO", 5, 0));
    struct iovec iov[2] = {{"abc", 3}, {"defgh", 5}};
    R("writev", syscall(SYS_writev, fd, iov, 2));
    R("pwritev", syscall(SYS_pwritev, fd, iov, 2, 100, 0));
    R("pwritev2", syscall(SYS_pwritev2, fd, iov, 2, (long)-1, 0, 0));
    R("lseek-set", syscall(SYS_lseek, fd, 0, SEEK_SET));
    memset(buf, 0, sizeof buf);
    r = R("read", syscall(SYS_read, fd, buf, 64));
    hex("data", "read", buf, r > 0 ? r : 0);
    r = R("pread64", syscall(SYS_pread64, fd, buf, 16, 96));
    hex("data", "pread64", buf, r > 0 ? r : 0);
    char b1[4], b2[6];
    struct iovec riov[2] = {{b1, 4}, {b2, 6}};
    R("lseek-set2", syscall(SYS_lseek, fd, 0, SEEK_SET));
    R("readv", syscall(SYS_readv, fd, riov, 2));
    hex("data", "readv", b1, 4), hex("data", "readv2", b2, 6);
    R("preadv", syscall(SYS_preadv, fd, riov, 2, 100, 0));
    R("preadv2", syscall(SYS_preadv2, fd, riov, 2, 0, 0, 0));
    R("lseek-end", syscall(SYS_lseek, fd, 0, SEEK_END));
    R("lseek-cur", syscall(SYS_lseek, fd, (long)-3, SEEK_CUR));
    R("ftruncate", syscall(SYS_ftruncate, fd, 8192));
    R("fallocate", syscall(SYS_fallocate, fd, 0, 8192, 8192));
    R("fallocate-punch", syscall(SYS_fallocate, fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 4096, 4096));
    R("lseek-data", syscall(SYS_lseek, fd, 0, SEEK_DATA));
    R("lseek-hole", syscall(SYS_lseek, fd, 0, SEEK_HOLE));
    R("fadvise64", syscall(SYS_fadvise64, fd, 0, 0, POSIX_FADV_SEQUENTIAL));
    R("readahead", syscall(SYS_readahead, fd, 0, 4096));
    R("fsync", syscall(SYS_fsync, fd));
    R("fdatasync", syscall(SYS_fdatasync, fd));
    R("sync_file_range", syscall(SYS_sync_file_range, fd, 0, 0, 0));
    R("syncfs", syscall(SYS_syncfs, fd));
    R("sync", syscall(SYS_sync));
    R("fsync-badf", syscall(SYS_fsync, 999));
    st("fstat-a", syscall(SYS_fstat, fd, sb), sb);
    R("creat", syscall(SYS_creat, "/work/b.txt", CREAT_FLAGS 0600));
    struct open_how how = {.flags = O_CREAT | O_WRONLY, .mode = 0640, .resolve = RESOLVE_NO_SYMLINKS};
    fd2 = R("openat2", syscall(SYS_openat2, AT_FDCWD, "c.txt", &how, sizeof how));
    R("write-c", syscall(SYS_write, fd2, "ccc", 3));
    R("close-c", syscall(SYS_close, fd2));
    fd2 = R("openat-direct", syscall(SYS_openat, AT_FDCWD, "c.txt", O_RDONLY | O_DIRECT));
    if (fd2 >= 0) R("close-direct", syscall(SYS_close, fd2));
    R("mknod-fifo", syscall(SYS_mknod, "/work/fifo", S_IFIFO | 0644, 0));
    R("mknodat-reg", syscall(SYS_mknodat, AT_FDCWD, "d1/reg", S_IFREG | 0600, 0));
    R("symlink", SYMLINK("a.txt", "/work/sl"));
    R("symlinkat", syscall(SYS_symlinkat, "../a.txt", AT_FDCWD, "d1/sl2"));
    r = syscall(SYS_readlink, "/work/sl", buf, sizeof buf);
    rl("readlink", r, buf);
    r = syscall(SYS_readlinkat, AT_FDCWD, "d1/sl2", buf, sizeof buf);
    rl("readlinkat", r, buf);
    R("link", LINK("/work/a.txt", "/work/a.hard"));
    R("linkat", syscall(SYS_linkat, AT_FDCWD, "b.txt", AT_FDCWD, "d1/b.hard", 0));
    long tf = R("open-tmpfile", syscall(SYS_openat, AT_FDCWD, "/work", O_TMPFILE | O_RDWR, 0600));
    if (tf >= 0) {
        R("write-tmpfile", syscall(SYS_write, tf, "tmp", 3));
        char lp[64];
        snprintf(lp, sizeof lp, "/proc/self/fd/%ld", tf);
        R("linkat-procfd", syscall(SYS_linkat, AT_FDCWD, lp, AT_FDCWD, "tmp.named", AT_SYMLINK_FOLLOW));
        R("linkat-empty", syscall(SYS_linkat, tf, "", AT_FDCWD, "tmp.named2", AT_EMPTY_PATH));
        R("close-tmpfile", syscall(SYS_close, tf));
    }

    // ---- stat family ----
    st("stat", STAT("/work/a.txt", sb), sb);
    st("lstat", LSTAT("/work/sl", sb), sb);
    st("newfstatat", syscall(SYS_newfstatat, AT_FDCWD, "d1", sb, 0), sb);
    st("newfstatat-nofollow", syscall(SYS_newfstatat, AT_FDCWD, "d1/sl2", sb, AT_SYMLINK_NOFOLLOW), sb);
    st("newfstatat-empty", syscall(SYS_newfstatat, fd, "", sb, AT_EMPTY_PATH), sb);
    st("stat-root", STAT("/work", sb), sb);
    st("stat-fifo", STAT("/work/fifo", sb), sb);
    st("stat-enoent", STAT("/work/nope", sb), sb);
    unsigned mask = STATX_BASIC_STATS | STATX_BTIME | STATX_MNT_ID;
    stx("statx", syscall(SYS_statx, AT_FDCWD, "/work/a.txt", 0, mask, sb), sb);
    stx("statx-dir", syscall(SYS_statx, AT_FDCWD, "d1", 0, mask, sb), sb);
    stx("statx-empty", syscall(SYS_statx, fd, "", AT_EMPTY_PATH, mask, sb), sb);
    stx("statx-nofollow", syscall(SYS_statx, AT_FDCWD, "sl", AT_SYMLINK_NOFOLLOW, mask, sb), sb);
    stfs("statfs", syscall(SYS_statfs, "/work", sb), sb);
    stfs("fstatfs", syscall(SYS_fstatfs, fd, sb), sb);

    // ---- access, cwd ----
    R("access", syscall(SYS_access, "/work/a.txt", R_OK | W_OK));
    R("access-enoent", syscall(SYS_access, "/work/nope", F_OK));
    R("faccessat", syscall(SYS_faccessat, AT_FDCWD, "d1", X_OK));
    R("faccessat2", syscall(SYS_faccessat2, AT_FDCWD, "sl", R_OK, AT_SYMLINK_NOFOLLOW));
    long dfd = R("open-dir", syscall(SYS_openat, AT_FDCWD, "d1", O_RDONLY | O_DIRECTORY));
    R("fchdir", syscall(SYS_fchdir, dfd));
    r = R("getcwd-d1", syscall(SYS_getcwd, cwd, sizeof cwd));
    if (r > 0) printf("cwd %s\n", cwd);
    R("chdir-back", syscall(SYS_chdir, ".."));

    // ---- attributes and times ----
    R("chmod", syscall(SYS_chmod, "/work/a.txt", 0600));
    R("fchmod", syscall(SYS_fchmod, fd, 0640));
    R("fchmodat", syscall(SYS_fchmodat, AT_FDCWD, "b.txt", 0644));
    R("fchmodat2", syscall(SYS_fchmodat2, AT_FDCWD, "c.txt", 0644, 0));
    uid_t u = syscall(SYS_getuid);
    gid_t g = syscall(SYS_getgid);
    R("chown", CHOWN("/work/a.txt", u, g));
    R("lchown", LCHOWN("/work/sl", u, g));
    R("fchown", syscall(SYS_fchown, fd, -1, -1));
    R("fchownat", syscall(SYS_fchownat, AT_FDCWD, "b.txt", u, g, 0));
    R("truncate", syscall(SYS_truncate, "/work/b.txt", 100));
    struct timespec ts[2] = {{1000000000, 5}, {1100000000, 7}};
    R("utimensat", syscall(SYS_utimensat, AT_FDCWD, "a.txt", ts, 0));
    struct timespec tn[2] = {{0, UTIME_NOW}, {0, UTIME_OMIT}};
    R("utimensat-now-omit", syscall(SYS_utimensat, AT_FDCWD, "b.txt", tn, 0));
    R("futimens", syscall(SYS_utimensat, fd, NULL, ts, 0));
    R("utimensat-null", syscall(SYS_utimensat, AT_FDCWD, "c.txt", NULL, 0));
    struct timeval tv[2] = {{1200000000, 1}, {1300000000, 2}};
#ifdef SYS_utimes
    R("utimes", syscall(SYS_utimes, "/work/d1/reg", tv));
    R("futimesat", syscall(SYS_futimesat, AT_FDCWD, "d1/b.hard", tv));
    struct { long a, m; } ub = {1400000000, 1500000000};
    R("utime", syscall(SYS_utime, "/work/c.txt", &ub));
#else
    (void)tv;
#endif
    R("utimensat-badns", syscall(SYS_utimensat, AT_FDCWD, "a.txt", (struct timespec[2]){{0, 2000000000}, {0, 0}}, 0));

    // ---- extended attributes ----
    R("setxattr", syscall(SYS_setxattr, "/work/a.txt", "user.one", "1", 1, 0));
    R("setxattr2", syscall(SYS_setxattr, "/work/a.txt", "user.two", "22", 2, 0));
    R("fsetxattr", syscall(SYS_fsetxattr, fd, "user.three", "333", 3, 0));
    R("lsetxattr-symlink", syscall(SYS_lsetxattr, "/work/sl", "user.x", "x", 1, 0));
    r = R("getxattr", syscall(SYS_getxattr, "/work/a.txt", "user.two", buf, sizeof buf));
    hex("data", "getxattr", buf, r > 0 ? r : 0);
    R("lgetxattr", syscall(SYS_lgetxattr, "/work/a.txt", "user.one", buf, sizeof buf));
    R("fgetxattr", syscall(SYS_fgetxattr, fd, "user.three", buf, sizeof buf));
    R("getxattr-nodata", syscall(SYS_getxattr, "/work/a.txt", "user.none", buf, sizeof buf));
    r = R("listxattr", syscall(SYS_listxattr, "/work/a.txt", buf, sizeof buf));
    hex("data", "listxattr", buf, r > 0 ? r : 0);
    R("llistxattr", syscall(SYS_llistxattr, "/work/sl", buf, sizeof buf));
    r = R("flistxattr", syscall(SYS_flistxattr, fd, buf, sizeof buf));
    hex("data", "flistxattr", buf, r > 0 ? r : 0);
    R("removexattr", syscall(SYS_removexattr, "/work/a.txt", "user.one"));
    R("lremovexattr", syscall(SYS_lremovexattr, "/work/a.txt", "user.two"));
    R("fremovexattr", syscall(SYS_fremovexattr, fd, "user.three"));

    // ---- copies ----
    long cfd = R("open-copy", syscall(SYS_openat, AT_FDCWD, "copy.bin", O_CREAT | O_RDWR, 0644));
    loff_t in_off = 0, out_off = 0;
    R("copy_file_range", syscall(SYS_copy_file_range, fd, &in_off, cfd, &out_off, 64, 0));
    R("lseek-a0", syscall(SYS_lseek, fd, 0, SEEK_SET));
    R("sendfile", syscall(SYS_sendfile, cfd, fd, NULL, 32));
    st("fstat-copy", syscall(SYS_fstat, cfd, sb), sb);

    // ---- renames and removals ----
    R("rename", RENAME("/work/c.txt", "/work/c2.txt"));
    R("renameat", syscall(SYS_renameat, AT_FDCWD, "b.txt", AT_FDCWD, "d1/b2.txt"));
    R("renameat2-noreplace", syscall(SYS_renameat2, AT_FDCWD, "c2.txt", AT_FDCWD, "a.txt", RENAME_NOREPLACE));
    R("renameat2-exchange", syscall(SYS_renameat2, AT_FDCWD, "c2.txt", AT_FDCWD, "copy.bin", RENAME_EXCHANGE));
    R("rename-over", RENAME("/work/a.hard", "/work/c2.txt"));
    R("unlink", UNLINK("/work/sl"));
    R("unlinkat", syscall(SYS_unlinkat, AT_FDCWD, "d1/sl2", 0));
    R("unlinkat-dir", syscall(SYS_unlinkat, AT_FDCWD, "d1/sub", AT_REMOVEDIR));
    R("mkdir-gone", syscall(SYS_mkdir, "/work/gone", 0755));
    R("rmdir", RMDIR("/work/gone"));
    R("rmdir-notempty", RMDIR("/work/d1"));

    // ---- descriptors ----
    R("dup", syscall(SYS_dup, fd));
    R("dup2", DUP2(fd, 20));
    R("dup3", syscall(SYS_dup3, fd, 21, O_CLOEXEC));
    V("dup2-hidden", DUP2(fd, 3001)); // hidden descriptors
    R("fcntl-getfd", syscall(SYS_fcntl, 21, F_GETFD));
    R("fcntl-setfd", syscall(SYS_fcntl, 21, F_SETFD, 0));
    R("fcntl-getfl", syscall(SYS_fcntl, fd, F_GETFL));
    R("fcntl-setfl", syscall(SYS_fcntl, fd, F_SETFL, O_APPEND));
    R("fcntl-dupfd", syscall(SYS_fcntl, fd, F_DUPFD, 30));
    R("fcntl-dupfd-cloexec", syscall(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 40));
    struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 10};
    R("fcntl-setlk", syscall(SYS_fcntl, fd, F_SETLK, &fl));
    R("fcntl-setlkw", syscall(SYS_fcntl, fd, F_SETLKW, &fl));
    fl.l_type = F_RDLCK;
    R("fcntl-getlk", syscall(SYS_fcntl, fd, F_GETLK, &fl));
    printf("flock-type %d\n", fl.l_type);
    struct flock ofd = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 20, .l_len = 5};
    R("fcntl-ofd-setlk", syscall(SYS_fcntl, fd, F_OFD_SETLK, &ofd));
    R("flock", syscall(SYS_flock, fd, LOCK_EX));
    R("flock-un", syscall(SYS_flock, fd, LOCK_UN));
    int p[2];
    R("pipe2", syscall(SYS_pipe2, p, O_CLOEXEC | O_NONBLOCK));
    printf("pipe fds %d %d\n", p[0], p[1]);
    R("pipe-write", syscall(SYS_write, p[1], "xyz", 3));
    int nread = -1;
    R("ioctl-fionread", syscall(SYS_ioctl, p[0], FIONREAD, &nread));
    printf("fionread %d\n", nread);
    R("pipe-read", syscall(SYS_read, p[0], buf, 16));
    R("pipe-read-empty", syscall(SYS_read, p[0], buf, 16));
    R("fcntl-getpipe-sz", syscall(SYS_fcntl, p[0], F_GETPIPE_SZ));
    st("fstat-pipe", syscall(SYS_fstat, p[0], sb), sb);
    char lp[64];
    snprintf(lp, sizeof lp, "/proc/self/fd/%d", p[0]);
    r = syscall(SYS_readlink, lp, buf, sizeof buf);
    rl("readlink-pipe", r, buf);
    int p2[2];
    R("pipe", PIPE(p2));
    st("fstat-pipe2", syscall(SYS_fstat, p2[1], sb), sb);
    long efd = R("eventfd2", syscall(SYS_eventfd2, 3, EFD_CLOEXEC));
    long efd1 = R("eventfd", EVENTFD(0));
    R("close-eventfd", syscall(SYS_close, efd1));
    long mfd = R("memfd_create", syscall(SYS_memfd_create, "tour", 0));
    R("write-memfd", syscall(SYS_write, mfd, "memfd", 5));
    snprintf(lp, sizeof lp, "/proc/self/fd/%ld", mfd);
    r = syscall(SYS_readlink, lp, buf, sizeof buf);
    rl("readlink-memfd", r, buf);
    int one = 1;
    R("ioctl-fionbio", syscall(SYS_ioctl, fd, FIONBIO, &one));
    R("ioctl-fioclex", syscall(SYS_ioctl, fd, FIOCLEX));
    R("ioctl-fionclex", syscall(SYS_ioctl, fd, FIONCLEX));
    char tbuf[64];
    R("ioctl-tcgets", syscall(SYS_ioctl, fd, 0x5401, tbuf));
    R("ioctl-tiocgwinsz", syscall(SYS_ioctl, 1, 0x5413, tbuf));
    R("close-hidden", syscall(SYS_close, 3000));
    R("close_range", syscall(SYS_close_range, 30, ~0U, 0));
    R("fcntl-closed", syscall(SYS_fcntl, 40, F_GETFD));
    R("fstat-hidden", syscall(SYS_fstat, 3002, sb));
    snprintf(lp, sizeof lp, "/proc/self/fd/%ld", efd);
    r = syscall(SYS_readlink, lp, buf, sizeof buf);
    rl("readlink-eventfd", r, buf);
    R("readlink-hidden", syscall(SYS_readlink, "/proc/self/fd/3001", buf, sizeof buf));
    R("open-hidden", syscall(SYS_open, "/proc/self/fd/3001", O_RDONLY));

    // ---- directory listings ----
    long wfd = R("open-work", syscall(SYS_openat, AT_FDCWD, "/work", O_RDONLY | O_DIRECTORY));
    dents("getdents64", wfd, SYS_getdents64);
    R("lseek-dir", syscall(SYS_lseek, wfd, 0, SEEK_SET));
#ifdef SYS_getdents
    dents("getdents", wfd, SYS_getdents);
#endif
    dents("getdents64-d1", dfd, SYS_getdents64);

    // ---- memory ----
    long a1 = syscall(SYS_mmap, 0, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("addr mmap-anon %lx\n", a1);
#ifndef __x86_64__
    // 0x40 is MAP_32BIT on x86_64 only: the generic kernel ignores the bit for a private mapping.
    long a40 = syscall(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | 0x40, -1, 0);
    R("mmap-0x40", a40 < 0 ? a40 : 0);
#endif
    memset((void *)a1, 7, 1 << 20);
    R("mprotect", syscall(SYS_mprotect, a1, 4096, PROT_READ));
    R("madvise-dontneed", syscall(SYS_madvise, a1 + 8192, 8192, MADV_DONTNEED));
    printf("after-dontneed %d\n", ((char *)a1)[8192]);
    // MADV_FREE is refused under patina (EINVAL, the pages as they were); natively 0.
    printf("virt madvise-free %ld\n", syscall(SYS_madvise, a1 + 65536, 65536, MADV_FREE));
    printf("virt after-free %d\n", ((char *)a1)[65536]);
    R("mprotect-back", syscall(SYS_mprotect, a1, 4096, PROT_READ | PROT_WRITE));
    long a2 = syscall(SYS_mremap, a1, 1 << 20, 4 << 20, MREMAP_MAYMOVE);
    printf("addr mremap %lx\n", a2);
    printf("after-mremap %d %d\n", ((char *)a2)[20000], ((char *)a2)[(1 << 20) + 5]);
    printf("virt after-mremap-freed %d\n", ((char *)a2)[100000]);
    long mf = syscall(SYS_mmap, 0, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    printf("addr mmap-file %lx\n", mf);
    hex("data", "mmap-file", (void *)mf, 16);
    memcpy((void *)mf + 200, "MAPPED", 6);
    R("msync", syscall(SYS_msync, mf, 8192, MS_SYNC));
    R("msync-unaligned", syscall(SYS_msync, mf + 1, 8192, MS_SYNC));
    R("pread-mapped", syscall(SYS_pread64, fd, buf, 6, 200));
    hex("data", "pread-mapped", buf, 6);
    R("munmap-file", syscall(SYS_munmap, mf, 8192));
    R("mlock", syscall(SYS_mlock, a2, 4096));
    R("munlock", syscall(SYS_munlock, a2, 4096));
    R("mlock2", syscall(SYS_mlock2, a2, 4096, 0));
    R("mlockall", syscall(SYS_mlockall, MCL_CURRENT));
    R("munlockall", syscall(SYS_munlockall));
    R("munmap", syscall(SYS_munmap, a2, 4 << 20));
    long b0 = syscall(SYS_brk, 0);
    printf("addr brk0 %lx\n", b0);
    long bg = syscall(SYS_brk, b0 + 100000);
    printf("brk-grow %ld\n", bg - b0);
    memset((void *)b0, 1, 100000);
    long bs = syscall(SYS_brk, b0);
    printf("brk-shrink %ld\n", bs - b0);
    unsigned char vec[4];
    V("mincore", syscall(SYS_mincore, a2, 4096, vec));

    // ---- credentials and identity ----
    R("getuid", syscall(SYS_getuid));
    R("geteuid", syscall(SYS_geteuid));
    R("getgid", syscall(SYS_getgid));
    R("getegid", syscall(SYS_getegid));
    uid_t ru, eu, su;
    R("getresuid", syscall(SYS_getresuid, &ru, &eu, &su));
    printf("resuid %u %u %u\n", ru, eu, su);
    gid_t rg, eg, sg;
    R("getresgid", syscall(SYS_getresgid, &rg, &eg, &sg));
    printf("resgid %u %u %u\n", rg, eg, sg);
    gid_t groups[16];
    r = R("getgroups", syscall(SYS_getgroups, 16, groups));
    for (long i = 0; i < r; i++) printf("group %u\n", groups[i]);
    R("setuid-same", syscall(SYS_setuid, u));
    R("setgid-same", syscall(SYS_setgid, g));
    R("setreuid", syscall(SYS_setreuid, -1, -1));
    R("setregid", syscall(SYS_setregid, -1, -1));
    R("setresuid", syscall(SYS_setresuid, -1, -1, -1));
    R("setresgid", syscall(SYS_setresgid, -1, -1, -1));
    R("setfsuid", syscall(SYS_setfsuid, u));
    R("setfsgid", syscall(SYS_setfsgid, g));
    R("setgroups", syscall(SYS_setgroups, 0, NULL));
    struct { uint32_t version; int pid; } hdr = {0x20080522, 0};
    uint32_t data[6];
    R("capget", syscall(SYS_capget, &hdr, data));
    printf("caps %x %x %x\n", data[0], data[1], data[2]);
    R("capset", syscall(SYS_capset, &hdr, data));
    char un[390];
    R("uname", syscall(SYS_uname, un));
    printf("uname %s %s %s\n", un, un + 65, un + 130);
    R("sethostname", syscall(SYS_sethostname, "x", 1));
    R("setdomainname", syscall(SYS_setdomainname, "x", 1));
    char comm[17] = {0};
    R("prctl-get-name", syscall(SYS_prctl, PR_GET_NAME, comm));
    printf("comm %s\n", comm);

    // ---- limits and system information (virtual by design) ----
    struct { unsigned long cur, max; } lim;
    V("getrlimit-nofile", syscall(SYS_getrlimit, RLIMIT_NOFILE, &lim));
    printf("virt nofile %lu %lu\n", lim.cur, lim.max);
    V("getrlimit-stack", syscall(SYS_getrlimit, RLIMIT_STACK, &lim));
    printf("virt stack %lu %lu\n", lim.cur, lim.max);
    V("setrlimit", syscall(SYS_setrlimit, RLIMIT_CORE, &lim));
    V("prlimit64", syscall(SYS_prlimit64, 0, RLIMIT_AS, NULL, &lim));
    printf("virt as %lu %lu\n", lim.cur, lim.max);
    unsigned char si[112];
    V("sysinfo", syscall(SYS_sysinfo, si));
    hex("virt", "sysinfo", si, 112);
    unsigned char ru2[144];
    V("getrusage", syscall(SYS_getrusage, 0, ru2));
    hex("virt", "getrusage", ru2, 144);
    int mode = -1;
    V("get_mempolicy", syscall(SYS_get_mempolicy, &mode, NULL, 0, 0, 0));
    printf("virt mempolicy %d\n", mode);

    // ---- refused interfaces (virtual by design) ----
    V("io_setup", syscall(SYS_io_setup, 1, &(long){0}));
    V("inotify_init1", syscall(SYS_inotify_init1, 0));
    V("semget", syscall(SYS_semget, 0, 1, 0600));
    V("personality", syscall(SYS_personality, 0xffffffff));
    V("unshare", syscall(SYS_unshare, 0));
    V("mount", syscall(SYS_mount, "none", "/work", "tmpfs", 0, NULL));
    V("chroot", syscall(SYS_chroot, "/work"));
    V("pidfd_open", syscall(SYS_pidfd_open, getpid(), 0));

    R("close", syscall(SYS_close, fd));
    R("close-again", syscall(SYS_close, fd));
    fflush(stdout);
    return 0;
}
