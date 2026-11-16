/* processes item 7: containment. Starts N daemons (default 200): double fork, setsid, every signal
 * ignored, every descriptor below 1024 closed, then sleep forever. Then, with "linger K",
 * keeps the run alive for K getppid calls, and exits 0: the run ends when this process exits.
 * Usage: daemons [N [linger K]] */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 200;
    long linger = argc > 3 && !strcmp(argv[2], "linger") ? atol(argv[3]) : 0;
    for (int i = 0; i < n; i++) {
        pid_t c = fork();
        if (c < 0) return 1;
        if (c == 0) {
            setsid();
            if (fork() != 0) _exit(0);
            for (int s = 1; s < 65; s++) signal(s, SIG_IGN);
            for (int fd = 0; fd < 1024; fd++) close(fd);
            for (;;) pause();
        }
        int st;
        waitpid(c, &st, 0);
    }
    printf("daemons started: %d\n", n);
    fflush(stdout);
    for (long i = 0; i < linger; i++) getppid();
    return 0;
}
