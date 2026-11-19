#define _GNU_SOURCE
/* The exec matrix. For every target and every method (fork+execve, vfork+execve,
 * posix_spawn) start the target with descriptor 5 inherited (not close-on-exec) and
 * descriptor 6 close-on-exec, EXEC_SHOW_ENV=<method>:<target> in the environment, wait for it and
 * print its status. Then the failures: each method reports the errno the kernel gives (also
 * E2BIG for an argument longer than the kernel copies and for vectors past its total bound).
 * Output lines: "== <method> <target>" then the child's own lines, then "status <n>";
 * "fail <method> <case> <errno name>". */
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static const char *targets[] = {
    "/guest/exec-show-static", "/guest/exec-show-spie", "/guest/exec-show-dyn", "/guest/exec-show-rs",
    "/guest/exec-show-go", "/guest/exec-files/show.sh", "/guest/exec-files/show.py", "/guest/exec-files/show-arg.py",
};
static const char *fails[][2] = {
    {"missing", "/guest/exec-files/no-such-file"},
    {"noexec", "/guest/exec-files/noexec.sh"},
    {"plain", "/guest/exec-files/plain.txt"},
    {"directory", "/guest/exec-files/adir"},
};

static const char *ename(int e) {
    switch (e) {
    case 0: return "0";
    case ENOENT: return "ENOENT";
    case EACCES: return "EACCES";
    case ENOEXEC: return "ENOEXEC";
    case E2BIG: return "E2BIG";
    default: return strerror(e);
    }
}

/* One string of MAX_ARG_STRLEN bytes (past the kernel's per-string bound), and one of 120000
 * bytes repeated 64 times (each within it, together past any total bound: at most 6 MiB). */
static char longarg[32 * 4096 + 1];
static char bigarg[120000 + 1];
static char *longav[] = {"x", longarg, NULL};
static char *bigav[66];

static volatile int vfork_errno;

/* Start `path` by `method`; return the child's pid, or -errno if the start failed. */
static int start(const char *method, const char *path, char **av, char **ev) {
    if (!strcmp(method, "fork")) {
        int p[2];
        if (pipe2(p, O_CLOEXEC)) return -errno;
        pid_t c = fork();
        if (c == 0) {
            close(p[0]);
            execve(path, av, ev);
            int e = errno;
            (void)!write(p[1], &e, sizeof e);
            _exit(127);
        }
        close(p[1]);
        int e = 0;
        ssize_t n = read(p[0], &e, sizeof e);
        close(p[0]);
        if (n == sizeof e) {
            waitpid(c, NULL, 0);
            return -e;
        }
        return c;
    }
    if (!strcmp(method, "vfork")) {
        vfork_errno = 0;
        pid_t c = vfork();
        if (c == 0) {
            execve(path, av, ev);
            vfork_errno = errno;
            _exit(127);
        }
        if (vfork_errno) {
            waitpid(c, NULL, 0);
            return -vfork_errno;
        }
        return c;
    }
    pid_t c;
    int r = posix_spawn(&c, path, NULL, NULL, av, ev);
    return r ? -r : c;
}

int main(int argc, char **argv) {
    const char *methods[] = {"fork", "vfork", "spawn"};
    int null5 = open("/dev/null", O_RDONLY);
    if (null5 != 5) dup2(null5, 5), close(null5);
    int null6 = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null6 != 6) dup3(null6, 6, O_CLOEXEC), close(null6);
    setvbuf(stdout, NULL, _IONBF, 0);
    for (size_t t = 0; t < sizeof targets / sizeof *targets; t++) {
        for (int m = 0; m < 3; m++) {
            char env[256];
            snprintf(env, sizeof env, "EXEC_SHOW_ENV=%s:%s", methods[m], targets[t]);
            char *ev[] = {env, "PATH=/usr/bin:/bin", NULL};
            char *av[] = {"show-argv0", "one", "two words", NULL};
            printf("== %s %s\n", methods[m], targets[t]);
            int c = start(methods[m], targets[t], av, ev);
            if (c < 0) {
                printf("start failed %s\n", ename(-c));
                continue;
            }
            int st;
            waitpid(c, &st, 0);
            printf("status %d\n", st);
        }
    }
    memset(longarg, 'a', sizeof longarg - 1);
    memset(bigarg, 'b', sizeof bigarg - 1);
    bigav[0] = "x";
    for (int i = 1; i < 65; i++) bigav[i] = bigarg;
    for (size_t f = 0; f < sizeof fails / sizeof *fails + 2; f++) {
        int big = f >= sizeof fails / sizeof *fails;
        const char *name = !big ? fails[f][0] : f == sizeof fails / sizeof *fails ? "longarg" : "bigvec";
        const char *path = !big ? fails[f][1] : "/guest/exec-show-static";
        for (int m = 0; m < 3; m++) {
            char *av[] = {"x", NULL};
            char **use = !big ? av : name[0] == 'l' ? longav : bigav;
            int c = start(methods[m], path, use, environ);
            if (c >= 0) {
                int st;
                waitpid(c, &st, 0);
                printf("fail %s %s started status %d\n", methods[m], name, st);
            } else {
                printf("fail %s %s %s\n", methods[m], name, ename(-c));
            }
        }
    }
    return 0;
}
