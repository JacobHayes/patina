// Cost probe: N getppid calls (N from argv[1]); prints the last result.
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 0, r = 0;
    for (long i = 0; i < n; i++) r = syscall(SYS_getppid);
    printf("getppid %ld x %ld\n", r, n);
    return 0;
}
