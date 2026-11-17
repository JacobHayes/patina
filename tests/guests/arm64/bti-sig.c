/* A signal handler in a BTI-guarded shared object (bti-sig-lib.c, libbtisig.so next to this
 * program). bti-sig pad: the handler starts with a landing pad; prints "handled 1".
 * bti-sig bare: it does not; on a BTI host the program dies of SIGILL at the handler's first
 * instruction, as without Patina; elsewhere prints "handled 2". */
#include <signal.h>
#include <stdio.h>
#include <string.h>

int bti_result(void);
void h_pad(int);
void h_bare(int);

int main(int argc, char **argv) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = argc > 1 && !strcmp(argv[1], "bare") ? h_bare : h_pad;
    sigaction(SIGUSR1, &sa, 0);
    fflush(stdout);
    raise(SIGUSR1);
    printf("handled %d\n", bti_result());
    return 0;
}
