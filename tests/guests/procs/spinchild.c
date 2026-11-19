// procs spinchild: forks a child that computes forever (no system call) while the parent
// waits for it. A thread computing alone is never a stall, so the run goes on until the
// child is killed from outside.
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    pid_t p = fork();
    if (p == 0)
        for (volatile unsigned long i = 0;; i++) {}
    int st;
    waitpid(p, &st, 0);
    return 0;
}
