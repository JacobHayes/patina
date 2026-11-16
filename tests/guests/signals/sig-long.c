// A long-running guest with a SIGUSR1 handler. The test sends a real SIGUSR1
// to its host PID from outside the sandbox; the run must end as infra and the handler
// must not have run (it would print a line).
#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void on_usr1(int sig) {
    (void)sig;
    if (write(1, "handler ran\n", 12) != 12) _exit(3);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);
    if (write(1, "started\n", 8) != 8) return 3;
    for (long i = 0; i < 100000000L; i++) syscall(SYS_getppid);
    return 0;
}
