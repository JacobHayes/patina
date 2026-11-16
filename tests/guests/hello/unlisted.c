// the skeleton guest: an unlisted-but-denied call continues with ENOSYS; ptrace ends the run.
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    char params[120];
    memset(params, 0, sizeof params);
    long r = syscall(SYS_io_uring_setup, 4, params);
    printf("io_uring_setup %ld errno %d\n", r, r < 0 ? errno : 0);
    fflush(stdout);
    r = syscall(SYS_ptrace, 0 /* PTRACE_TRACEME */, 0, 0, 0);
    printf("ptrace returned %ld\n", r);
    return 0;
}
