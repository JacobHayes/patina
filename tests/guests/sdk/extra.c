/* Engine properties of the SDK channel, shown once in C (sdk-extra MODE):
 *   fork        a child started by fork and one started by execve report into the run's table
 *   ready       a fault point before and after the program creates /tmp/setup-done, which
 *               main's `ready` probe waits for (it then waits 1 s for the probe to pass)    */
#include "patina.h"
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    if (!strcmp(mode, "exec-child")) {
        PATINA_REACHABLE("exec-child");
        return 0;
    }
    if (!strcmp(mode, "fork")) {
        int st;
        pid_t p = fork();
        if (p == 0) {
            PATINA_REACHABLE("forked-child");
            _exit(0);
        }
        waitpid(p, &st, 0);
        p = fork();
        if (p == 0) {
            execl(argv[0], argv[0], "exec-child", (char *)0);
            _exit(127);
        }
        waitpid(p, &st, 0);
        PATINA_REACHABLE("parent-done");
        return WIFEXITED(st) ? WEXITSTATUS(st) : 3;
    }
    if (!strcmp(mode, "ready")) {
        char before[6] = {0}, after[6] = {0};
        for (int i = 0; i < 5; i++) before[i] = PATINA_BUGGIFY("ready-point") ? '1' : '0';
        close(open("/tmp/setup-done", O_CREAT | O_WRONLY, 0644));
        struct timespec t = {1, 0};
        nanosleep(&t, 0);
        for (int i = 0; i < 5; i++) after[i] = PATINA_BUGGIFY("ready-point") ? '1' : '0';
        printf("before=%s after=%s\n", before, after);
        return 0;
    }
    return 2;
}
