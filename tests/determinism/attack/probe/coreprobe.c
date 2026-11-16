/* determinism hardening attack guest: deaths by core-dumping signals, as seen by the parent. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    int sigs[] = {SIGQUIT, SIGSEGV, SIGABRT, SIGBUS, SIGTERM};
    for (unsigned i = 0; i < 5; i++) {
        int p[2]; if (pipe(p)) return 1;
        pid_t c = fork();
        if (c == 0) { close(p[0]); write(p[1], "r", 1); for (;;) usleep(1000); }
        char b; read(p[0], &b, 1);
        kill(c, sigs[i]);
        int st; waitpid(c, &st, 0);
        printf("kill %d status %x core %d\n", sigs[i], st, WCOREDUMP(st) ? 1 : 0);
    }
    pid_t c = fork();
    if (c == 0) { *(volatile int *)0 = 1; _exit(0); }
    int st; waitpid(c, &st, 0);
    printf("segv-self status %x core %d\n", st, WCOREDUMP(st) ? 1 : 0);
    c = fork();
    if (c == 0) { abort(); }
    waitpid(c, &st, 0);
    printf("abort-self status %x core %d\n", st, WCOREDUMP(st) ? 1 : 0);
    return 0;
}
