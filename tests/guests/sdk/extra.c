/* Engine properties of the SDK channel, shown once in C (sdk-extra MODE):
 *   fork        a child started by fork and one started by execve report into the run's table
 *   setup       a fault point before and after `setup-complete`
 *   setup-fail  a setup that fails where the fault point `setup-fail` fires, then the mark      */
#include "patina.h"
#include <stdio.h>
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
    if (!strcmp(mode, "setup")) {
        char before[6] = {0}, after[6] = {0};
        for (int i = 0; i < 5; i++) before[i] = PATINA_BUGGIFY("setup-point") ? '1' : '0';
        patina_setup_complete();
        for (int i = 0; i < 5; i++) after[i] = PATINA_BUGGIFY("setup-point") ? '1' : '0';
        printf("before=%s after=%s\n", before, after);
        return 0;
    }
    if (!strcmp(mode, "setup-fail")) {
        if (PATINA_BUGGIFY("setup-fail")) return 3;
        patina_setup_complete();
        return 0;
    }
    return 2;
}
