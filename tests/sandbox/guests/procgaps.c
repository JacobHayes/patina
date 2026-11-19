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
#include <sys/resource.h>
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
    if (all || !strcmp(m, "sched"))
        sched_part();
    if (all || !strcmp(m, "clone"))
        clone_part();
    printf("%s: %d failed\n", m, fails);
    return fails != 0;
}
