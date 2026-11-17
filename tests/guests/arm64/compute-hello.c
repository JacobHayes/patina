/* A compute-point hook's first call (COMPUTE_HELLO on the SDK system call): compute points are
 * a part not ported to arm64 yet. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    long r = syscall(0x7061, 8L, 1L | 1L << 8, 0L);
    printf("compute hello: %ld\n", r);
    return 0;
}
