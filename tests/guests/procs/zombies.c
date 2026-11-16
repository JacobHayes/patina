/* Zombies and orphans.
 * A child exits while the parent sleeps: it is a zombie until waited (kill(pid, 0) succeeds,
 * waitpid then returns it, and kill(pid, 0) fails with ESRCH afterwards). A grandchild whose
 * parent died reports getppid() == 1. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pid_t z = fork();
    if (z == 0) _exit(42);
    sleep(1);
    int k0 = kill(z, 0);
    printf("zombie pid=%d kill0=%d\n", z, k0);
    int st;
    pid_t w = waitpid(z, &st, WNOHANG);
    printf("waitpid=%d exited=%d status=%d\n", w, WIFEXITED(st), WEXITSTATUS(st));
    errno = 0;
    int k1 = kill(z, 0);
    printf("after reap kill0=%d errno=%s\n", k1, errno == ESRCH ? "ESRCH" : strerror(errno));
    int p[2];
    if (pipe(p)) return 1;
    pid_t c = fork();
    if (c == 0) {
        pid_t g = fork();
        if (g == 0) {
            close(p[0]);
            pid_t before = getppid();
            while (getppid() != 1) usleep(1000);
            char b[96];
            int n = snprintf(b, sizeof b, "grandchild pid=%d ppid-before=%d ppid-after=%d\n", getpid(), before, getppid());
            (void)!write(p[1], b, n);
            _exit(0);
        }
        _exit(0);
    }
    close(p[1]);
    waitpid(c, &st, 0);
    char b[96] = {0};
    ssize_t n = read(p[0], b, sizeof b - 1);
    printf("%s", n > 0 ? b : "no report\n");
    int ok = k0 == 0 && w == z && WEXITSTATUS(st) == 0 && k1 == -1 && strstr(b, "ppid-after=1\n");
    if (!ok) {
        fprintf(stderr, "INVARIANT zombies\n");
        return 1;
    }
    return 0;
}
