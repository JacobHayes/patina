/* W7 fork-exec: a fork tree 3 deep, vfork, posix_spawn, exec of
 * static, dynamic, Go and #! targets, pipes between siblings, waitpid in every mode, a SIGCHLD
 * handler, kill between siblings, orphans, zombies, and N daemons (default 200) left running
 * at exit. Every line it prints is a function of the run (PIDs included). A failed check
 * prints "INVARIANT <name>" on stderr and exits 1. Usage: fork-exec [daemons N] */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void say(const char *fmt, ...) {
    char b[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap);
    va_end(ap);
    (void)!write(1, b, n);
}

static void check(int ok, const char *name) {
    if (!ok) {
        char b[128];
        int n = snprintf(b, sizeof b, "INVARIANT %s (pid %d errno %d)\n", name, getpid(), errno);
        (void)!write(2, b, n);
        _exit(1);
    }
}

static volatile int chld_count;
static volatile int chld_last_pid;
static void on_chld(int sig, siginfo_t *si, void *uc) {
    (void)sig, (void)uc;
    chld_count++;
    chld_last_pid = si->si_pid;
}

static void tree(int depth) {
    say("tree depth=%d pid=%d ppid=%d\n", depth, getpid(), getppid());
    if (depth == 3) _exit(depth);
    pid_t c[2];
    for (int i = 0; i < 2; i++) {
        c[i] = fork();
        check(c[i] >= 0, "tree-fork");
        if (c[i] == 0) tree(depth + 1);
    }
    for (int i = 0; i < 2; i++) {
        int st;
        check(waitpid(c[i], &st, 0) == c[i], "tree-wait");
        say("tree depth=%d pid=%d child=%d status=%d\n", depth, getpid(), c[i], WEXITSTATUS(st));
    }
    if (depth > 0) _exit(depth);
}

static int run_wait(pid_t c) {
    int st;
    check(waitpid(c, &st, 0) == c, "wait-exec");
    return st;
}

static void execs(void) {
    char *av[] = {"show", "from-vfork", NULL};
    pid_t c = vfork();
    if (c == 0) {
        execve("/guest/exec-show-static", av, environ);
        _exit(127);
    }
    say("vfork child=%d status=%d\n", c, run_wait(c));
    const char *t[] = {"/guest/exec-show-dyn", "/guest/exec-show-go", "/guest/exec-files/show.sh"};
    for (int i = 0; i < 3; i++) {
        char *a2[] = {"show", "from-spawn", NULL};
        check(posix_spawn(&c, t[i], NULL, NULL, a2, environ) == 0, "spawn");
        say("spawn %s child=%d status=%d\n", t[i], c, run_wait(c));
    }
}

static void sibling_pipes(void) {
    int p[2], q[2];
    check(pipe(p) == 0 && pipe(q) == 0, "pipe");
    pid_t a = fork();
    if (a == 0) {
        close(p[0]), close(q[0]), close(q[1]);
        for (int i = 0; i < 2000; i++) {
            char b[32];
            int n = snprintf(b, sizeof b, "line %d\n", i);
            check(write(p[1], b, n) == n, "sib-write");
        }
        _exit(0);
    }
    pid_t b = fork();
    if (b == 0) {
        close(p[1]), close(q[0]);
        unsigned long sum = 0, bytes = 0;
        char buf[777];
        ssize_t n;
        while ((n = read(p[0], buf, sizeof buf)) > 0)
            for (ssize_t i = 0; i < n; i++) sum = sum * 31 + (unsigned char)buf[i], bytes++;
        char r[64];
        int k = snprintf(r, sizeof r, "%lu %lu", bytes, sum);
        check(write(q[1], r, k) == k, "sib-report");
        _exit(0);
    }
    close(p[0]), close(p[1]), close(q[1]);
    char r[64] = {0};
    check(read(q[0], r, sizeof r - 1) > 0, "sib-read");
    close(q[0]);
    say("siblings a=%d b=%d result=%s\n", a, b, r);
    run_wait(a), run_wait(b);
}

static pid_t child_exit(int code) {
    pid_t c = fork();
    if (c == 0) _exit(code);
    return c;
}

static void wait_modes(void) {
    int st;
    pid_t c = child_exit(3);
    check(waitpid(c, &st, 0) == c && WEXITSTATUS(st) == 3, "waitpid-pid");
    say("waitpid(pid) %d -> %d\n", c, WEXITSTATUS(st));
    c = child_exit(4);
    pid_t w = waitpid(-1, &st, 0);
    check(w == c, "waitpid-any");
    say("waitpid(-1) %d -> %d\n", w, WEXITSTATUS(st));
    c = child_exit(5);
    w = waitpid(0, &st, 0);
    check(w == c, "waitpid-group");
    say("waitpid(0) %d -> %d\n", w, WEXITSTATUS(st));
    c = fork();
    if (c == 0) {
        setpgid(0, 0);
        _exit(6);
    }
    setpgid(c, c);
    w = waitpid(-c, &st, 0);
    check(w == c, "waitpid-pgid");
    say("waitpid(-pgid) %d -> %d\n", w, WEXITSTATUS(st));
    c = child_exit(7);
    int polls = 0;
    while ((w = waitpid(c, &st, WNOHANG)) == 0) polls++, usleep(100);
    check(w == c, "waitpid-wnohang");
    say("waitpid(WNOHANG) %d -> %d after %d polls\n", w, WEXITSTATUS(st), polls);
    c = child_exit(8);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    check(waitid(P_PID, c, &si, WEXITED | WNOWAIT) == 0 && si.si_pid == c, "waitid-nowait");
    say("waitid(WNOWAIT) %d code=%d status=%d\n", si.si_pid, si.si_code, si.si_status);
    check(waitpid(c, &st, 0) == c, "waitid-then-wait");
    c = child_exit(9);
    struct rusage ru;
    w = wait4(c, &st, 0, &ru);
    check(w == c, "wait4-pid");
    say("wait4 %d -> %d utime=%ld.%06ld maxrss=%ld\n", w, WEXITSTATUS(st), ru.ru_utime.tv_sec, ru.ru_utime.tv_usec, ru.ru_maxrss);
    c = child_exit(10);
    memset(&si, 0, sizeof si);
    check(waitid(P_ALL, 0, &si, WEXITED) == 0 && si.si_pid == c, "waitid-all");
    say("waitid(P_ALL) %d code=%d status=%d\n", si.si_pid, si.si_code, si.si_status);
    check(waitpid(-1, &st, WNOHANG) == -1 && errno == ECHILD, "echild");
    say("no children: ECHILD\n");
}

static volatile int usr1;
static void on_usr1(int s) { (void)s, usr1 = 1; }

static void sibling_kill(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t m, old, none;
    sigemptyset(&m), sigaddset(&m, SIGUSR1), sigemptyset(&none);
    sigprocmask(SIG_BLOCK, &m, &old);
    pid_t a = fork();
    if (a == 0) {
        while (!usr1) sigsuspend(&none);
        _exit(11);
    }
    pid_t b = fork();
    if (b == 0) _exit(kill(a, SIGUSR1) == 0 ? 0 : 1);
    sigprocmask(SIG_SETMASK, &old, NULL);
    int sa_, sb;
    waitpid(a, &sa_, 0), waitpid(b, &sb, 0);
    check(WEXITSTATUS(sa_) == 11 && WEXITSTATUS(sb) == 0, "sibling-kill");
    say("sibling kill %d -> %d: statuses %d %d\n", b, a, WEXITSTATUS(sa_), WEXITSTATUS(sb));
    signal(SIGUSR1, SIG_DFL);
}

static void orphans(void) {
    int p[2];
    check(pipe(p) == 0, "orphan-pipe");
    pid_t c = fork();
    if (c == 0) {
        pid_t g = fork();
        if (g == 0) {
            close(p[0]);
            pid_t before = getppid();
            while (getppid() != 1) usleep(1000);
            char b[96];
            int n = snprintf(b, sizeof b, "orphan pid=%d ppid before=%d after=%d\n", getpid(), before, getppid());
            (void)!write(p[1], b, n);
            _exit(0);
        }
        _exit(0);
    }
    close(p[1]);
    run_wait(c);
    char b[96] = {0};
    check(read(p[0], b, sizeof b - 1) > 0, "orphan-read");
    close(p[0]);
    say("%s", b);
}

static void zombies(void) {
    pid_t z = child_exit(12);
    usleep(10000);
    check(kill(z, 0) == 0, "zombie-exists");
    say("zombie %d: kill(pid, 0) = 0\n", z);
    int st;
    check(waitpid(z, &st, WNOHANG) == z && WEXITSTATUS(st) == 12, "zombie-wait");
    errno = 0;
    check(kill(z, 0) == -1 && errno == ESRCH, "zombie-gone");
    say("zombie %d reaped: status %d, then ESRCH\n", z, WEXITSTATUS(st));
}

static void daemons(int n) {
    for (int i = 0; i < n; i++) {
        pid_t c = fork();
        check(c >= 0, "daemon-fork");
        if (c == 0) {
            setsid();
            if (fork() != 0) _exit(0);
            for (int s = 1; s < 65; s++) signal(s, SIG_IGN);
            for (int fd = 0; fd < 1024; fd++) close(fd);
            for (;;) pause();
        }
        run_wait(c);
    }
    say("daemons: %d started\n", n);
}

int main(int argc, char **argv) {
    int nd = 200;
    if (argc > 2 && !strcmp(argv[1], "daemons")) nd = atoi(argv[2]);
    struct sigaction sa = {0};
    sa.sa_sigaction = on_chld;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    say("main pid=%d ppid=%d\n", getpid(), getppid());
    tree(0);
    execs();
    sibling_pipes();
    wait_modes();
    sibling_kill();
    orphans();
    zombies();
    say("sigchld deliveries=%d last=%d\n", chld_count, chld_last_pid);
    check(chld_count > 0, "sigchld");
    daemons(nd);
    say("ok\n");
    return 0;
}
