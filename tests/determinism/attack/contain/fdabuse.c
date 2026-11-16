/* Containment and robustness: hidden descriptors, descriptors above them, and the host
 * stdout file. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#define T(x) do { errno = 0; long _r = (long)(x); dprintf(2, "%-40s r=%ld errno=%d\n", #x, _r, _r < 0 ? errno : 0); } while (0)
int main(void) {
    
    T(fcntl(3000, F_GETFD));
    T(fcntl(3001, F_GETFL));
    T(dup2(1, 3001));
    T(dup3(1, 3002, 0));
    T(fcntl(1, F_DUPFD, 2999));
    T(fcntl(1, F_DUPFD, 2999));
    T(close(3003));
    T(mmap(0, 4096, PROT_READ, MAP_SHARED, 3001, 0) == MAP_FAILED ? -1 : 0);
    T(syscall(SYS_close_range, 3, ~0u, 0));
    struct timespec t; T(clock_gettime(CLOCK_MONOTONIC, &t));
    T(write(1, "still alive\n", 12));
    T(fchmod(1, 0600));
    T(fsetxattr(1, "user.determinism", "x", 1, 0));
    T(futimens(1, NULL));
    T(ftruncate(1, 1ll << 30));
    struct stat st; fstat(1, &st); dprintf(2, "stdout size %lld blocks %lld\n", (long long)st.st_size, (long long)st.st_blocks);
    T(ftruncate(1, 0));
    T(lseek(1, 0, SEEK_SET));
    T(fallocate(1, 0, 0, 1 << 20));
    T(flock(1, LOCK_EX | LOCK_NB));
    T(open("/proc/self/fd/1", O_RDWR | O_TRUNC));
    return 0;
}
