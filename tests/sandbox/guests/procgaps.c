/* Calls a headless browser makes that Patina once ended the run on, each checked against what
 * the kernel answers an unprivileged process; a line `FAIL ...` and exit 1 when one differs.
 *   procgaps sched   scheduling attributes: getters, setters, inheritance by threads, fork, exec
 *   procgaps clone   clone with CLONE_NEW* flags: EPERM, as unshare
 *   procgaps nlink   /proc/self/task's link count follows the thread count
 *   procgaps proc    /proc, /proc/self and /proc/self/fd as directories (listing, relative
 *                    opens) and every way out of the policy through them: refused
 *   procgaps all     each of the above, and statfs of /dev/shm */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/openat2.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
static const char *self_path;

/* expect WHAT R ERR: the call returned R with errno ERR (ERR 0: success, R >= 0). */
static void expect(const char *what, long r, int want_err, long got_r, int got_err) {
    int ok = want_err ? (got_r == -1 && got_err == want_err) : (got_r == r);
    printf("%-52s r=%ld errno=%d%s\n", what, got_r, got_r < 0 ? got_err : 0, ok ? "" : "  FAIL");
    if (!ok) {
        printf("FAIL %s: want r=%ld errno=%d\n", what, want_err ? -1 : r, want_err);
        fails++;
    }
}
#define EXPECT(what, r, err, call) do { errno = 0; long got_ = (long)(call); expect(what, r, err, got_, errno); } while (0)

struct attr {
    uint32_t size, policy;
    uint64_t flags;
    int32_t nice;
    uint32_t prio;
    uint64_t runtime, deadline, period;
    uint32_t util_min, util_max;
};

static long getattr_(pid_t pid, struct attr *a, unsigned size) { return syscall(SYS_sched_getattr, pid, a, size, 0); }
static long setattr_(pid_t pid, struct attr *a) { return syscall(SYS_sched_setattr, pid, a, 0); }
static long getprio(pid_t who) { return syscall(SYS_getpriority, PRIO_PROCESS, who); } /* 20 - nice */

static pid_t thread_tid;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int stage;

static void *thread_main(void *arg) {
    (void)arg;
    EXPECT("thread: inherits nice 7", 13, 0, getprio(0));
    EXPECT("thread: setpriority 10 (its own)", 0, 0, setpriority(PRIO_PROCESS, 0, 10));
    pthread_mutex_lock(&mu);
    thread_tid = gettid();
    stage = 1;
    pthread_cond_broadcast(&cv);
    while (stage != 2)
        pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
    return NULL;
}

static void sched_part(void) {
    struct sched_param sp = {0};
    struct attr a;
    EXPECT("getpriority: nice 0", 20, 0, getprio(0));
    EXPECT("sched_getscheduler: SCHED_OTHER", SCHED_OTHER, 0, sched_getscheduler(0));
    sp.sched_priority = 99;
    EXPECT("sched_getparam", 0, 0, sched_getparam(0, &sp));
    EXPECT("sched_getparam: priority 0", 0, 0, sp.sched_priority);
    memset(&a, 0xff, sizeof a);
    EXPECT("sched_getattr (56)", 0, 0, getattr_(0, &a, sizeof a));
    EXPECT("sched_getattr: size 56", 56, 0, a.size);
    EXPECT("sched_getattr: SCHED_OTHER nice 0", 0, 0, a.policy | a.nice | a.prio | a.flags);
    EXPECT("sched_getattr (47): EINVAL", 0, EINVAL, getattr_(0, &a, 47));
    EXPECT("sched_getattr (flags): EINVAL", 0, EINVAL, syscall(SYS_sched_getattr, 0, &a, 56, 1));
    EXPECT("getpriority of no thread: ESRCH", 0, ESRCH, getprio(99999));
    EXPECT("getpriority bad which: EINVAL", 0, EINVAL, syscall(SYS_getpriority, 7, 0));
    EXPECT("sched_get_priority_max FIFO", 99, 0, sched_get_priority_max(SCHED_FIFO));
    EXPECT("sched_get_priority_min RR", 1, 0, sched_get_priority_min(SCHED_RR));
    EXPECT("sched_get_priority_max OTHER", 0, 0, sched_get_priority_max(SCHED_OTHER));
    EXPECT("sched_get_priority_min DEADLINE", 0, 0, sched_get_priority_min(6));
    EXPECT("sched_get_priority_max 4: EINVAL", 0, EINVAL, sched_get_priority_max(4));
    EXPECT("membarrier query: ENOSYS", 0, ENOSYS, syscall(SYS_membarrier, 0, 0, 0));
    EXPECT("setpriority 5", 0, 0, setpriority(PRIO_PROCESS, 0, 5));
    EXPECT("getpriority: nice 5", 15, 0, getprio(0));
    EXPECT("setpriority 3 (lower): EACCES", 0, EACCES, setpriority(PRIO_PROCESS, 0, 3));
    EXPECT("setpriority 5 (same)", 0, 0, setpriority(PRIO_PROCESS, 0, 5));
    EXPECT("setpriority by own tid 6", 0, 0, setpriority(PRIO_PROCESS, gettid(), 6));
    /* The run's threads only (natively the supervisor, PID 1, would count too). */
    printf("getpriority PRIO_PGRP 0 %ld, PRIO_USER 0 %ld\n", syscall(SYS_getpriority, PRIO_PGRP, 0), syscall(SYS_getpriority, PRIO_USER, 0));
    EXPECT("getpriority PRIO_USER 4242: ESRCH", 0, ESRCH, syscall(SYS_getpriority, PRIO_USER, 4242));
    sp.sched_priority = 1;
    EXPECT("sched_setscheduler FIFO 1: EPERM", 0, EPERM, sched_setscheduler(0, SCHED_FIFO, &sp));
    EXPECT("sched_setscheduler RR 1: EPERM", 0, EPERM, sched_setscheduler(0, SCHED_RR, &sp));
    EXPECT("sched_setscheduler OTHER 1: EINVAL", 0, EINVAL, sched_setscheduler(0, SCHED_OTHER, &sp));
    sp.sched_priority = 0;
    EXPECT("sched_setscheduler FIFO 0: EINVAL", 0, EINVAL, sched_setscheduler(0, SCHED_FIFO, &sp));
    EXPECT("sched_setscheduler DEADLINE: EINVAL", 0, EINVAL, sched_setscheduler(0, 6, &sp));
    EXPECT("sched_setscheduler 4: EINVAL", 0, EINVAL, sched_setscheduler(0, 4, &sp));
    EXPECT("sched_setscheduler NULL: EINVAL", 0, EINVAL, syscall(SYS_sched_setscheduler, 0, SCHED_OTHER, NULL));
    EXPECT("sched_setscheduler BATCH", 0, 0, sched_setscheduler(0, SCHED_BATCH, &sp));
    EXPECT("sched_getscheduler: SCHED_BATCH", SCHED_BATCH, 0, sched_getscheduler(0));
    EXPECT("getpriority: nice kept (6)", 14, 0, getprio(0));
    EXPECT("sched_setparam 0", 0, 0, sched_setparam(0, &sp));
    sp.sched_priority = 5;
    EXPECT("sched_setparam 5: EINVAL", 0, EINVAL, sched_setparam(0, &sp));
    memset(&a, 0, sizeof a);
    a.size = 48, a.policy = SCHED_OTHER, a.nice = 7;
    EXPECT("sched_setattr OTHER nice 7", 0, 0, setattr_(0, &a));
    memset(&a, 0xff, sizeof a);
    EXPECT("sched_getattr (48)", 0, 0, getattr_(0, &a, 48));
    EXPECT("sched_getattr: size 48", 48, 0, a.size);
    EXPECT("sched_getattr: SCHED_OTHER", SCHED_OTHER, 0, a.policy);
    EXPECT("sched_getattr: nice 7", 7, 0, a.nice);
    EXPECT("sched_getattr: tail untouched", 0xffffffffL, 0, a.util_min);
    memset(&a, 0, sizeof a);
    a.size = 48, a.policy = SCHED_OTHER, a.nice = 6;
    EXPECT("sched_setattr nice 6 (lower): EPERM", 0, EPERM, setattr_(0, &a));
    a.nice = 7, a.policy = 6, a.runtime = 1000000, a.deadline = 2000000, a.period = 4000000;
    EXPECT("sched_setattr DEADLINE: EPERM", 0, EPERM, setattr_(0, &a));
    a.runtime = 0;
    EXPECT("sched_setattr DEADLINE no runtime: EINVAL", 0, EINVAL, setattr_(0, &a));
    memset(&a, 0, sizeof a);
    a.size = 56, a.nice = 7, a.flags = 0x20, a.util_min = 10, a.util_max = 1024;
    /* As on a kernel without utilisation clamping (natively, on one with it: 0). */
    EXPECT("sched_setattr UTIL_CLAMP_MIN: EOPNOTSUPP", 0, EOPNOTSUPP, setattr_(0, &a));
    a.flags = 0x100;
    EXPECT("sched_setattr unknown flag: EINVAL", 0, EINVAL, setattr_(0, &a));
    memset(&a, 0, sizeof a);
    a.size = 8;
    EXPECT("sched_setattr size 8: E2BIG", 0, E2BIG, setattr_(0, &a));
    EXPECT("sched_setattr size 8: size written back", 56, 0, a.size);
    char big[64] = {0};
    ((struct attr *)big)->size = 64, ((struct attr *)big)->nice = 7, big[60] = 1;
    EXPECT("sched_setattr nonzero tail: E2BIG", 0, E2BIG, setattr_(0, (struct attr *)big));
    big[60] = 0;
    EXPECT("sched_setattr zero tail", 0, 0, setattr_(0, (struct attr *)big));
    memset(&a, 0, sizeof a);
    a.size = 48, a.flags = 0x08 | 0x10; /* KEEP_POLICY | KEEP_PARAMS */
    EXPECT("sched_setattr KEEP_ALL", 0, 0, setattr_(0, &a));
    EXPECT("getpriority: nice 7", 13, 0, getprio(0));
    EXPECT("nice(0) (glibc)", 7, 0, nice(0));

    pthread_t t;
    pthread_create(&t, NULL, thread_main, NULL);
    pthread_mutex_lock(&mu);
    while (stage != 1)
        pthread_cond_wait(&cv, &mu);
    EXPECT("getpriority of the thread: nice 10", 10, 0, getprio(thread_tid));
    EXPECT("getpriority own: nice 7", 13, 0, getprio(0));
    EXPECT("getpriority PRIO_PROCESS pid: the main thread", 13, 0, getprio(getpid()));
    printf("getpriority PRIO_PGRP 0 with the thread %ld\n", syscall(SYS_getpriority, PRIO_PGRP, 0));
    EXPECT("setpriority of the thread 9 (lower): EACCES", 0, EACCES, setpriority(PRIO_PROCESS, thread_tid, 9));
    EXPECT("sched_setscheduler of the thread IDLE", 0, 0, sched_setscheduler(thread_tid, SCHED_IDLE, &(struct sched_param){0}));
    EXPECT("sched_getscheduler of the thread: SCHED_IDLE", SCHED_IDLE, 0, sched_getscheduler(thread_tid));
    EXPECT("sched_setscheduler of the thread OTHER: EPERM", 0, EPERM, sched_setscheduler(thread_tid, SCHED_OTHER, &(struct sched_param){0}));
    stage = 2;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
    pthread_join(t, NULL);

    EXPECT("sched_setscheduler IDLE|RESET_ON_FORK", 0, 0, sched_setscheduler(0, SCHED_IDLE | SCHED_RESET_ON_FORK, &(struct sched_param){0}));
    EXPECT("sched_getscheduler: IDLE|RESET_ON_FORK", SCHED_IDLE | SCHED_RESET_ON_FORK, 0, sched_getscheduler(0));
    EXPECT("clearing RESET_ON_FORK: EPERM", 0, EPERM, sched_setscheduler(0, SCHED_IDLE, &(struct sched_param){0}));
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        EXPECT("fork child: nice 7", 13, 0, getprio(0));
        EXPECT("fork child: SCHED_IDLE, reset-on-fork cleared", SCHED_IDLE, 0, sched_getscheduler(0));
        EXPECT("fork child: setpriority 12", 0, 0, setpriority(PRIO_PROCESS, 0, 12));
        fflush(stdout);
        execl(self_path, self_path, "sched-exec", (char *)NULL);
        _exit(3);
    }
    int st = 0;
    waitpid(c, &st, 0);
    EXPECT("child after exec: exit 0", 0, 0, WIFEXITED(st) ? WEXITSTATUS(st) : 128);
    EXPECT("parent: nice still 7", 13, 0, getprio(0));
}

static void clone_part(void) {
    static const struct { const char *name; unsigned long flags; } ns[] = {
        {"CLONE_NEWUSER", CLONE_NEWUSER}, {"CLONE_NEWPID", CLONE_NEWPID}, {"CLONE_NEWNET", CLONE_NEWNET},
        {"CLONE_NEWNS", CLONE_NEWNS}, {"CLONE_NEWUTS", CLONE_NEWUTS}, {"CLONE_NEWIPC", CLONE_NEWIPC},
        {"CLONE_NEWCGROUP", CLONE_NEWCGROUP}, {"CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET", CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET},
    };
    char what[96];
    for (size_t i = 0; i < sizeof ns / sizeof *ns; i++) {
        snprintf(what, sizeof what, "clone %s: EPERM", ns[i].name);
        EXPECT(what, 0, EPERM, syscall(SYS_clone, ns[i].flags | SIGCHLD, 0, 0, 0, 0));
    }
    EXPECT("unshare CLONE_NEWUSER: EPERM", 0, EPERM, unshare(CLONE_NEWUSER));
    /* A plain fork still works after the refusals. */
    fflush(stdout);
    pid_t c = fork();
    if (c == 0)
        _exit(0);
    int st = 1;
    EXPECT("fork after the refusals", c, 0, waitpid(c, &st, 0));
}

/* ---- nlink: /proc/self/task's link count is 2 + the threads ---- */

static pthread_barrier_t bar;
static void *parked(void *arg) {
    (void)arg;
    pthread_barrier_wait(&bar); /* started */
    pthread_barrier_wait(&bar); /* checked */
    return NULL;
}

static int count_entries(int dfd, int numeric_only) {
    int d = dup(dfd);
    DIR *dir = fdopendir(d);
    rewinddir(dir);
    int n = 0;
    struct dirent *e;
    while ((e = readdir(dir)))
        if (!numeric_only || (e->d_name[0] >= '0' && e->d_name[0] <= '9'))
            n++;
    closedir(dir);
    return n;
}

static void nlink_part(void) {
    struct stat st;
    int procfd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int task = open("/proc/self/task", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("stat /proc/self/task", 0, 0, stat("/proc/self/task", &st));
    EXPECT("nlink, one thread: 3", 3, 0, st.st_nlink);
    EXPECT("fstatat(/proc, self/task/) (zygote's form)", 0, 0, fstatat(procfd, "self/task/", &st, 0));
    EXPECT("nlink: 3", 3, 0, st.st_nlink);
    EXPECT("task entries: 1", 1, 0, count_entries(task, 1));
    pthread_barrier_init(&bar, NULL, 3);
    pthread_t t[2];
    for (int i = 0; i < 2; i++)
        pthread_create(&t[i], NULL, parked, NULL);
    pthread_barrier_wait(&bar);
    EXPECT("fstat of the task directory", 0, 0, fstat(task, &st));
    EXPECT("nlink, three threads: 5", 5, 0, st.st_nlink);
    struct statx sx;
    EXPECT("statx /proc/self/task", 0, 0, statx(AT_FDCWD, "/proc/self/task", 0, STATX_NLINK, &sx));
    EXPECT("statx nlink: 5", 5, 0, sx.stx_nlink);
    EXPECT("task entries: 3", 3, 0, count_entries(task, 1));
    pthread_barrier_wait(&bar);
    for (int i = 0; i < 2; i++)
        pthread_join(t[i], NULL);
    EXPECT("fstatat(/proc, self/task/) after the joins", 0, 0, fstatat(procfd, "self/task/", &st, 0));
    EXPECT("nlink: 3 again", 3, 0, st.st_nlink);
    close(task);
    close(procfd);
}

/* ---- proc: /proc directories, and every way out of the policy through them ---- */

static int workfd, marker, procfd, fddir, selfdir, taskdir;
static pid_t child;

static void fdlink(int fd, char *out, size_t n) {
    char p[64];
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    ssize_t k = readlink(p, out, n - 1);
    out[k > 0 ? k : 0] = 0;
}

/* The invariant: through a directory descriptor, a name reaches what the absolute path
 * reaches (refused alike, the same errno), and when allowed, the same object. */
static void same(int dirfd, const char *base, const char *rel) {
    char abs_[512], what[600];
    snprintf(abs_, sizeof abs_, "%s/%s", base, rel);
    errno = 0;
    int a = openat(dirfd, rel, O_RDONLY | O_CLOEXEC);
    int ea = errno;
    errno = 0;
    int b = open(abs_, O_RDONLY | O_CLOEXEC);
    int eb = errno;
    char la[256] = "", lb[256] = "";
    if (a >= 0) fdlink(a, la, sizeof la);
    if (b >= 0) fdlink(b, lb, sizeof lb);
    int ok = (a >= 0) == (b >= 0) && (a >= 0 || ea == eb) && strcmp(la, lb) == 0;
    snprintf(what, sizeof what, "%s + %s", base, rel);
    printf("%-60s %s%s\n", what, a >= 0 ? la : strerror(ea), ok ? "" : "  FAIL");
    if (!ok) {
        printf("FAIL %s: through the descriptor %d errno=%d %s, by path %d errno=%d %s\n", what, a, ea, la, b, eb, lb);
        fails++;
    }
    if (a >= 0) close(a);
    if (b >= 0) close(b);
}

/* refused PATH: open answers ENOENT. */
static void refused(const char *what, int dirfd, const char *p) {
    char w[300];
    snprintf(w, sizeof w, "refused: %s", what);
    EXPECT(w, 0, ENOENT, openat(dirfd, p, O_RDONLY | O_CLOEXEC));
}

static int listing(int dfd, char names[][32], int max) {
    int n = 0;
    char buf[4096];
    lseek(dfd, 0, SEEK_SET);
    for (;;) {
        long r = syscall(SYS_getdents64, dfd, buf, sizeof buf);
        if (r <= 0)
            break;
        for (long off = 0; off < r;) {
            struct { uint64_t ino; int64_t off; unsigned short reclen; unsigned char type; char name[]; } *e = (void *)(buf + off);
            if (n < max)
                snprintf(names[n++], 32, "%s", e->name);
            off += e->reclen;
        }
    }
    return n;
}

static int listed(char names[][32], int n, const char *name) {
    for (int i = 0; i < n; i++)
        if (!strcmp(names[i], name))
            return 1;
    return 0;
}

static void proc_part(void) {
    char p[256], l[256], own[16], kid[16];
    mkdir("/work/d", 0755);
    symlink("/proc/1/task/1/fd", "/work/A");
    symlink("/proc", "/work/P");
    symlink("/proc/1", "/work/p1");
    workfd = open("/work", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    marker = open("/work/marker", O_CREAT | O_RDWR | O_CLOEXEC, 0644);
    procfd = open("/proc", O_RDONLY | O_DIRECTORY);
    EXPECT("open /proc (directory)", procfd, 0, procfd);
    fddir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    EXPECT("open /proc/self/fd (directory)", fddir, 0, fddir);
    selfdir = open("/proc/self", O_RDONLY | O_DIRECTORY);
    EXPECT("open /proc/self (directory)", selfdir, 0, selfdir);
    taskdir = open("/proc/self/task", O_RDONLY | O_DIRECTORY);
    int opath = open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC);
    EXPECT("open /proc O_PATH", opath, 0, opath);
    struct stat st;
    EXPECT("fstat /proc: a directory", S_IFDIR, 0, fstat(procfd, &st) == 0 ? (long)(st.st_mode & S_IFMT) : -1);
    struct statfs sf;
    EXPECT("fstatfs /proc: procfs", 0x9fa0, 0, fstatfs(procfd, &sf) == 0 ? (long)sf.f_type : -1);
    fdlink(procfd, l, sizeof l);
    EXPECT("readlink /proc/self/fd/<procfd>: /proc", 0, 0, strcmp(l, "/proc"));
    fflush(stdout);
    child = fork();
    if (child == 0) {
        pause();
        _exit(0);
    }
    snprintf(own, sizeof own, "%d", getpid());
    snprintf(kid, sizeof kid, "%d", child);

    /* Through /proc: what the absolute path reaches, and nothing it does not. */
    const char *rels[] = {"self/maps", "self/status", "cpuinfo", "sys/kernel/random/boot_id", "self",
        "self/task", "self/fd", "self/fd/0", "1", "1/environ", "1/fd/3", "1/fd/3001", "self/fd/3000",
        "self/fd/3001", "thread-self", "thread-self/maps", "self/mem", "self/cwd", "self/root/etc/hostname",
        "self/../1/environ", "self/task/../../1/environ", "kallsyms", "sys", "../proc/1/environ",
        "../work/P/1/environ", "../work/p1/fd/3001", "./self/./maps", "self/exe", "self/environ"};
    for (size_t i = 0; i < sizeof rels / sizeof *rels; i++)
        same(procfd, "/proc", rels[i]);
    same(procfd, "/proc", own);
    snprintf(p, sizeof p, "%s/maps", own); same(procfd, "/proc", p);
    snprintf(p, sizeof p, "%s/status", kid); same(procfd, "/proc", p);
    same(procfd, "/proc", kid);
    snprintf(p, sizeof p, "self/task/%d/mem", gettid()); same(procfd, "/proc", p);
    snprintf(p, sizeof p, "self/fd/%d/1/environ", procfd); same(procfd, "/proc", p);
    snprintf(p, sizeof p, "self/fd/%d/self/maps", procfd); same(procfd, "/proc", p);
    snprintf(p, sizeof p, "self/fd/%d/A/../../../fd/%d", workfd, marker); same(procfd, "/proc", p);
    /* Through /proc/self, /proc/self/fd and /proc/self/task, likewise. */
    const char *srels[] = {"maps", "mem", "cwd", "root", "environ", "fd", "fd/3001", "task", "../1/environ",
        "../../work/P/1/environ", "exe"};
    for (size_t i = 0; i < sizeof srels / sizeof *srels; i++)
        same(selfdir, "/proc/self", srels[i]);
    const char *frels[] = {"0", "1", "2", "3000", "3001", "3002", "../maps", "../../1/fd/3001", "../mem"};
    for (size_t i = 0; i < sizeof frels / sizeof *frels; i++)
        same(fddir, "/proc/self/fd", frels[i]);
    snprintf(p, sizeof p, "%d", marker); same(fddir, "/proc/self/fd", p);
    snprintf(p, sizeof p, "%d/A/../../../fd/%d", workfd, marker); same(fddir, "/proc/self/fd", p);
    snprintf(p, sizeof p, "%d/mem", gettid()); same(taskdir, "/proc/self/task", p);
    same(taskdir, "/proc/self/task", "../../1/environ");

    /* Refused outright, by every path. */
    refused("/proc/1/environ", AT_FDCWD, "/proc/1/environ");
    refused("/proc/1/fd/3001 via /proc", procfd, "1/fd/3001");
    refused("/proc/self/fd/3001 via /proc/self/fd", fddir, "3001");
    refused("/proc/thread-self/maps", AT_FDCWD, "/proc/thread-self/maps");
    snprintf(l, sizeof l, "/proc/%s/status", kid);
    refused("another process's /proc/PID/status", AT_FDCWD, l);
    refused("/proc/../work/P/1/environ", AT_FDCWD, "/proc/../work/P/1/environ");
    refused("/work/p1/environ", AT_FDCWD, "/work/p1/environ");
    snprintf(p, sizeof p, "/proc/self/fd/%d/p1/environ", workfd);
    refused("/proc/self/fd/<work>/p1/environ", AT_FDCWD, p);
    for (int n = 3000; n < 3006; n++) {
        snprintf(p, sizeof p, "/proc/self/fd/%d", n);
        EXPECT("readlink a runtime descriptor: ENOENT", 0, ENOENT, readlink(p, l, sizeof l));
        snprintf(p, sizeof p, "%d", n);
        EXPECT("readlinkat(fd dir, runtime descriptor): ENOENT", 0, ENOENT, readlinkat(fddir, p, l, sizeof l));
        EXPECT("fstatat(fd dir, runtime descriptor): ENOENT", 0, ENOENT, fstatat(fddir, p, &st, 0));
    }
    /* A magic link followed by `..`: the program's own descriptor, never another process's. */
    snprintf(p, sizeof p, "/proc/self/fd/%d/A/../../../fd/%d", workfd, marker);
    int m2 = open(p, O_RDONLY | O_CLOEXEC);
    if (m2 >= 0) fdlink(m2, l, sizeof l); else snprintf(l, sizeof l, "errno %d", errno);
    EXPECT("fd/<work>/A/../../../fd/<marker>: the marker", 0, 0, strcmp(l, "/work/marker"));
    struct open_how how = {.flags = O_RDONLY, .resolve = RESOLVE_IN_ROOT};
    EXPECT("openat2(/proc, /1/environ, IN_ROOT): ENOENT", 0, ENOENT, syscall(SYS_openat2, procfd, "/1/environ", &how, sizeof how));
    how.resolve = RESOLVE_BENEATH;
    EXPECT("openat2(/proc, 1/environ, BENEATH): ENOENT", 0, ENOENT, syscall(SYS_openat2, procfd, "1/environ", &how, sizeof how));
    EXPECT("openat(/proc, ../work/created, O_CREAT)", 0, 0, openat(procfd, "../work/created", O_CREAT | O_WRONLY | O_CLOEXEC, 0644) >= 0 ? 0 : -1);
    EXPECT("/work/created exists", 0, 0, access("/work/created", F_OK));

    /* Never the working directory. */
    getcwd(l, sizeof l);
    EXPECT("fchdir /proc: EACCES", 0, EACCES, fchdir(procfd));
    EXPECT("fchdir /proc O_PATH: EACCES", 0, EACCES, fchdir(opath));
    EXPECT("fchdir /proc/self/fd: EACCES", 0, EACCES, fchdir(fddir));
    EXPECT("fchdir /proc/self: EACCES", 0, EACCES, fchdir(selfdir));
    EXPECT("chdir /proc: EACCES", 0, EACCES, chdir("/proc"));
    EXPECT("chdir /proc/self/fd: EACCES", 0, EACCES, chdir("/proc/self/fd"));
    EXPECT("chdir /work/P: EACCES", 0, EACCES, chdir("/work/P"));
    snprintf(p, sizeof p, "/proc/self/fd/%d", procfd);
    EXPECT("chdir /proc/self/fd/<procfd>: EACCES", 0, EACCES, chdir(p));
    snprintf(p, sizeof p, "/proc/self/fd/%d", taskdir);
    EXPECT("chdir /proc/self/fd/<taskdir>: EACCES", 0, EACCES, chdir(p));
    char cwd[256];
    getcwd(cwd, sizeof cwd);
    EXPECT("working directory unchanged", 0, 0, strcmp(l, cwd));

    /* Listings: what the policy allows, every name opening; in a fixed order. */
    static char names[2][128][32];
    int n = listing(procfd, names[0], 128);
    EXPECT("/proc lists self", 1, 0, listed(names[0], n, "self"));
    EXPECT("/proc lists this process", 1, 0, listed(names[0], n, own));
    EXPECT("/proc lists cpuinfo", 1, 0, listed(names[0], n, "cpuinfo"));
    EXPECT("/proc does not list pid 1", 0, 0, listed(names[0], n, "1"));
    EXPECT("/proc does not list another process", 0, 0, listed(names[0], n, kid));
    EXPECT("/proc does not list thread-self", 0, 0, listed(names[0], n, "thread-self"));
    EXPECT("/proc does not list kallsyms", 0, 0, listed(names[0], n, "kallsyms"));
    for (int i = 0; i < n; i++) {
        snprintf(p, sizeof p, "/proc lists %s, which opens", names[0][i]);
        int f = openat(procfd, names[0][i], O_RDONLY | O_CLOEXEC);
        EXPECT(p, 0, 0, f >= 0 ? 0 : -1);
        if (f >= 0) close(f);
    }
    EXPECT("/proc listed again: the same", n, 0, listing(procfd, names[1], 128));
    EXPECT("/proc listed again: the same order", 0, 0, memcmp(names[0], names[1], sizeof names[0]));
    n = listing(selfdir, names[0], 128);
    for (int i = 0; i < n; i++) {
        snprintf(p, sizeof p, "/proc/self lists %s, which opens", names[0][i]);
        int f = openat(selfdir, names[0][i], O_RDONLY | O_CLOEXEC);
        EXPECT(p, 0, 0, f >= 0 ? 0 : -1);
        if (f >= 0) close(f);
    }
    EXPECT("/proc/self lists fd", 1, 0, listed(names[0], n, "fd"));
    EXPECT("/proc/self does not list mem", 0, 0, listed(names[0], n, "mem"));
    /* /proc/self/fd: exactly the descriptors fcntl finds open, ascending, none of the runtime's. */
    n = listing(fddir, names[0], 128);
    int k = 2, prev = -1, bad = 0;
    for (int i = 0; i < n; i++) {
        if (names[0][i][0] == '.')
            continue;
        int v = atoi(names[0][i]);
        if (v <= prev || v >= 3000 || fcntl(v, F_GETFD) < 0)
            bad++;
        prev = v;
        k++;
    }
    int open_fds = 0;
    for (int v = 0; v < 3000; v++)
        open_fds += fcntl(v, F_GETFD) >= 0;
    EXPECT("/proc/self/fd: only open descriptors, ascending, below 3000", 0, 0, bad);
    EXPECT("/proc/self/fd: every open descriptor (and . ..)", open_fds + 2, 0, k);
    char tiny[8];
    EXPECT("getdents into 8 bytes: EINVAL", 0, EINVAL, (lseek(procfd, 0, SEEK_SET), syscall(SYS_getdents64, procfd, tiny, sizeof tiny)));

    /* A policy directory does not travel to another process. */
    int sp[2];
    socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp);
    char c = 'x';
    struct iovec io = {&c, 1};
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int))]; } u;
    struct msghdr mh = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = u.b, .msg_controllen = sizeof u.b};
    CMSG_FIRSTHDR(&mh)->cmsg_level = SOL_SOCKET, CMSG_FIRSTHDR(&mh)->cmsg_type = SCM_RIGHTS;
    CMSG_FIRSTHDR(&mh)->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(CMSG_FIRSTHDR(&mh)), &procfd, sizeof(int));
    EXPECT("SCM_RIGHTS of /proc: EBADF", 0, EBADF, sendmsg(sp[0], &mh, 0));
    memcpy(CMSG_DATA(CMSG_FIRSTHDR(&mh)), &marker, sizeof(int));
    EXPECT("SCM_RIGHTS of a file", 1, 0, sendmsg(sp[0], &mh, 0));

    /* A vfork child cannot keep one (it shares its parent's marks, not its descriptors):
     * not by open, dup, F_DUPFD or reopening /proc/self/fd/N; nor make one its directory. */
    static volatile long vr[6], ve[6];
    snprintf(p, sizeof p, "/proc/self/fd/%d", procfd);
    if (vfork() == 0) {
        errno = 0, vr[0] = open("/proc", O_RDONLY | O_DIRECTORY), ve[0] = errno;
        errno = 0, vr[1] = dup(procfd), ve[1] = errno;
        errno = 0, vr[2] = fcntl(fddir, F_DUPFD, 10), ve[2] = errno;
        errno = 0, vr[3] = open(p, O_RDONLY), ve[3] = errno;
        errno = 0, vr[4] = fchdir(procfd), ve[4] = errno;
        errno = 0, vr[5] = dup2(selfdir, 40), ve[5] = errno;
        _exit(0);
    }
    const char *vw[] = {"open /proc", "dup /proc", "F_DUPFD /proc/self/fd", "open /proc/self/fd/<procfd>",
        "fchdir /proc", "dup2 /proc/self"};
    for (int i = 0; i < 6; i++) {
        snprintf(l, sizeof l, "vfork child: %s: EACCES", vw[i]);
        EXPECT(l, 0, EACCES, (errno = (int)ve[i], vr[i]));
    }

    /* Answers as Linux gives them. */
    EXPECT("access /proc X_OK", 0, 0, access("/proc", X_OK));
    EXPECT("access /proc/self/fd R_OK|X_OK", 0, 0, access("/proc/self/fd", R_OK | X_OK));
    EXPECT("access /proc W_OK: EACCES", 0, EACCES, access("/proc", W_OK));
    EXPECT("open /proc O_WRONLY: EISDIR", 0, EISDIR, open("/proc", O_WRONLY));
    EXPECT("open /proc/self/fd O_RDWR: EISDIR", 0, EISDIR, open("/proc/self/fd", O_RDWR));
    snprintf(p, sizeof p, "/proc/self/fd/%d", procfd);
    EXPECT("lstat /proc/self/fd/<procfd>: a link", S_IFLNK, 0, lstat(p, &st) == 0 ? (long)(st.st_mode & S_IFMT) : -1);
    EXPECT("stat /proc/self/fd/<procfd>: a directory", S_IFDIR, 0, stat(p, &st) == 0 ? (long)(st.st_mode & S_IFMT) : -1);
    int re = open(p, O_RDONLY | O_CLOEXEC);
    EXPECT("open /proc/self/fd/<procfd>: /proc again", 0, 0, re >= 0 && fstat(re, &st) == 0 && S_ISDIR(st.st_mode) ? 0 : -1);
    if (re >= 0) {
        same(re, "/proc", "1/environ");
        same(re, "/proc", "self/maps");
        close(re);
    }
    how.resolve = RESOLVE_NO_SYMLINKS;
    long ar = syscall(SYS_openat2, procfd, "/work/marker", &how, sizeof how);
    EXPECT("openat2(/proc, absolute /work/marker, NO_SYMLINKS)", 0, 0, ar >= 0 ? 0 : -1);
    if (ar >= 0) close(ar);

    /* A fork child's inherited /proc/self/fd lists the child's descriptors. */
    fflush(stdout);
    pid_t fk = fork();
    if (fk == 0) {
        int extra = open("/work/marker", O_RDONLY);
        dup2(extra, 77);
        char nm[128][32];
        snprintf(p, sizeof p, "%d", extra);
        int nn = listing(fddir, nm, 128);
        _exit(listed(nm, nn, p) && listed(nm, nn, "77") ? 0 : 1);
    }
    int fst = 0;
    waitpid(fk, &fst, 0);
    EXPECT("fork child lists its own descriptors", 0, 0, WIFEXITED(fst) ? WEXITSTATUS(fst) : 128);

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    /* Across exec, the inherited directories are still policed. */
    fflush(stdout);
    pid_t e = fork();
    if (e == 0) {
        char a[16], b[16], c2[16], d[16];
        snprintf(a, sizeof a, "%d", procfd);
        snprintf(b, sizeof b, "%d", fddir);
        snprintf(c2, sizeof c2, "%d", selfdir);
        snprintf(d, sizeof d, "%d", taskdir);
        execl(self_path, self_path, "proc-exec", a, b, c2, d, (char *)NULL);
        _exit(3);
    }
    int stt = 0;
    waitpid(e, &stt, 0);
    EXPECT("exec'd image: exit 0", 0, 0, WIFEXITED(stt) ? WEXITSTATUS(stt) : 128);
}

static void proc_exec(int pfd, int ffd, int sfd, int tfd) {
    struct stat st;
    EXPECT("after exec: /proc is still a directory", S_IFDIR, 0, fstat(pfd, &st) == 0 ? (long)(st.st_mode & S_IFMT) : -1);
    same(pfd, "/proc", "self/maps");
    same(pfd, "/proc", "1/environ");
    same(pfd, "/proc", "1/fd/3001");
    same(ffd, "/proc/self/fd", "3001");
    same(ffd, "/proc/self/fd", "../../1/environ");
    same(sfd, "/proc/self", "maps");
    same(sfd, "/proc/self", "../1/environ");
    same(tfd, "/proc/self/task", "../maps");
    struct stat ts;
    EXPECT("after exec: /proc/self/task nlink 3", 3, 0, fstat(tfd, &ts) == 0 ? (long)ts.st_nlink : -1);
    EXPECT("after exec: fchdir /proc: EACCES", 0, EACCES, fchdir(pfd));
    char names[64][32];
    int n = listing(pfd, names, 64);
    EXPECT("after exec: /proc does not list pid 1", 0, 0, listed(names, n, "1"));
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 1 << 16);
    self_path = argv[0];
    const char *m = argc > 1 ? argv[1] : "all";
    int all = !strcmp(m, "all");
    if (!strcmp(m, "sched-exec")) {
        EXPECT("after exec: nice 12", 8, 0, getprio(0));
        EXPECT("after exec: SCHED_IDLE", SCHED_IDLE, 0, sched_getscheduler(0));
        return fails != 0;
    }
    if (!strcmp(m, "proc-exec")) {
        proc_exec(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
        return fails != 0;
    }
    if (all || !strcmp(m, "sched"))
        sched_part();
    if (all || !strcmp(m, "clone"))
        clone_part();
    if (all || !strcmp(m, "nlink"))
        nlink_part();
    if (all || !strcmp(m, "proc"))
        proc_part();
    if (all) {
        struct statfs sf;
        EXPECT("statfs /dev/shm", 0, 0, statfs("/dev/shm", &sf));
        EXPECT("statfs /dev/shm: the configured 256 MiB", 256L << 20, 0, (long)(sf.f_blocks * sf.f_bsize));
    }
    printf("%s: %d failed\n", m, fails);
    return fails != 0;
}
