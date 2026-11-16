/* processes cost: N times fork + execve("/bin/true") + waitpid. Usage: spawn-cost N */
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 1;
    for (int i = 0; i < n; i++) {
        pid_t c = fork();
        if (c == 0) {
            execl("/bin/true", "true", (char *)0);
            _exit(127);
        }
        int st;
        if (waitpid(c, &st, 0) != c || st != 0) return 1;
    }
    return 0;
}
