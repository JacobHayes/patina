/* processes item 6: cross-process signals.
 * - kill between siblings (SIGUSR2 from one child to another, which waits in sigsuspend);
 * - kill to a process group (three children in a new group, SIGUSR1 to -pgid; each exits
 *   with the number of signals its handler saw);
 * - SIGTERM with the default action kills a child blocked in read; wait shows the signal.
 * - SIGKILL kills a child that ignores everything else.
 * Every wait status is printed. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int got;
static void on_sig(int s) { (void)s, got++; }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int bad = 0, st;
    struct sigaction sa = {0};
    sa.sa_handler = on_sig;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigset_t m, none;
    sigemptyset(&m), sigaddset(&m, SIGUSR1), sigaddset(&m, SIGUSR2), sigemptyset(&none);
    sigprocmask(SIG_BLOCK, &m, NULL);

    /* siblings */
    pid_t a = fork();
    if (a == 0) {
        while (!got) sigsuspend(&none);
        _exit(20 + got);
    }
    pid_t b = fork();
    if (b == 0) _exit(kill(a, SIGUSR2) == 0 ? 0 : 1);
    waitpid(b, &st, 0);
    printf("sender %d status %d\n", b, st);
    waitpid(a, &st, 0);
    printf("receiver %d exited=%d status=%d\n", a, WIFEXITED(st), WEXITSTATUS(st));
    bad |= !(WIFEXITED(st) && WEXITSTATUS(st) == 21);

    /* process group */
    pid_t g[3];
    int pp[2];
    if (pipe(pp)) return 1;
    for (int i = 0; i < 3; i++) {
        g[i] = fork();
        if (g[i] == 0) {
            setpgid(0, i == 0 ? 0 : g[0]);
            close(pp[0]);
            (void)!write(pp[1], "r", 1);
            while (!got) sigsuspend(&none);
            _exit(30 + got);
        }
        setpgid(g[i], g[0]);
    }
    close(pp[1]);
    char c3[3];
    for (int i = 0; i < 3; i++) (void)!read(pp[0], c3, 1);
    printf("group %d: kill(-pgid)=%d\n", g[0], kill(-g[0], SIGUSR1));
    for (int i = 0; i < 3; i++) {
        waitpid(g[i], &st, 0);
        printf("member %d pgid-was %d exited=%d status=%d\n", g[i], g[0], WIFEXITED(st), WEXITSTATUS(st));
        bad |= !(WIFEXITED(st) && WEXITSTATUS(st) == 31);
    }
    errno = 0;
    int kr = kill(-g[0], SIGUSR1);
    printf("kill(-pgid) after: %d %s\n", kr, kr == 0 ? "ok" : errno == ESRCH ? "ESRCH" : strerror(errno));

    /* SIGTERM default action on a child blocked in read */
    int p[2];
    if (pipe(p)) return 1;
    pid_t r = fork();
    if (r == 0) {
        sigprocmask(SIG_UNBLOCK, &m, NULL);
        signal(SIGTERM, SIG_DFL);
        close(p[1]);
        char x;
        ssize_t n = read(p[0], &x, 1);
        _exit(n == 0 ? 50 : 51);
    }
    close(p[0]);
    usleep(1000);
    kill(r, SIGTERM);
    waitpid(r, &st, 0);
    printf("reader %d signaled=%d termsig=%d status=0x%x\n", r, WIFSIGNALED(st), WIFSIGNALED(st) ? WTERMSIG(st) : 0, st);
    bad |= !(WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);
    siginfo_t si;
    pid_t r2 = fork();
    if (r2 == 0) {
        for (int s = 1; s < 32; s++) signal(s, SIG_IGN);
        for (;;) pause();
    }
    usleep(1000);
    kill(r2, SIGTERM);
    kill(r2, SIGKILL);
    memset(&si, 0, sizeof si);
    waitid(P_PID, r2, &si, WEXITED);
    printf("ignorer %d code=%d status=%d\n", r2, si.si_code, si.si_status);
    bad |= !(si.si_code == CLD_KILLED && si.si_status == SIGKILL);
    close(p[1]);
    if (bad) {
        fprintf(stderr, "INVARIANT xsig\n");
        return 1;
    }
    return 0;
}
