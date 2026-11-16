/* Exit ordering. 50 children each write a line to one shared pipe and exit with
 * their index. The parent reads until EOF, then waits in a loop. A SIGCHLD handler reaps what
 * has exited (waitpid(-1, WNOHANG) in a loop) and counts the children it reaped. Printed: the
 * bytes read (as lines), the (pid, status) sequence of every reap with who reaped it, the
 * handler's delivery count and reap count. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define N 50
static volatile int deliveries, reaped_h, nrec;
static int rec_pid[N + 1], rec_st[N + 1];
static char rec_who[N + 1];

static void on_chld(int s) {
    (void)s;
    int e = errno, st;
    pid_t p;
    deliveries++;
    while ((p = waitpid(-1, &st, WNOHANG)) > 0) {
        rec_pid[nrec] = p, rec_st[nrec] = WEXITSTATUS(st), rec_who[nrec] = 'h', nrec++;
        reaped_h++;
    }
    errno = e;
}

int main(void) {
    int p[2];
    if (pipe(p)) return 1;
    struct sigaction sa = {0};
    sa.sa_handler = on_chld;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    for (int i = 0; i < N; i++) {
        pid_t c = fork();
        if (c == 0) {
            close(p[0]);
            char b[64];
            int n = snprintf(b, sizeof b, "child %d pid %d\n", i, getpid());
            (void)!write(p[1], b, n);
            _exit(i);
        }
    }
    close(p[1]);
    char buf[8192];
    size_t total = 0;
    ssize_t n;
    while ((n = read(p[0], buf + total, sizeof buf - total)) > 0) total += n;
    (void)!write(1, buf, total);
    int st;
    pid_t c;
    while ((c = wait(&st)) > 0) {
        sigset_t m;
        sigemptyset(&m), sigaddset(&m, SIGCHLD);
        sigprocmask(SIG_BLOCK, &m, NULL);
        rec_pid[nrec] = c, rec_st[nrec] = WEXITSTATUS(st), rec_who[nrec] = 'w', nrec++;
        sigprocmask(SIG_UNBLOCK, &m, NULL);
    }
    for (int i = 0; i < nrec; i++) printf("reaped %c pid=%d status=%d\n", rec_who[i], rec_pid[i], rec_st[i]);
    printf("total reaped=%d handler-reaped=%d deliveries=%d bytes=%zu\n", nrec, reaped_h, deliveries, total);
    if (nrec != N) {
        fprintf(stderr, "INVARIANT exit-order-count %d\n", nrec);
        return 1;
    }
    return 0;
}
