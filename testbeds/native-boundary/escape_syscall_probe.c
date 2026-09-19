#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
#ifdef SYS_openat
    long fd = syscall(SYS_openat, AT_FDCWD, "/etc/hostname", O_RDONLY);
#else
    long fd = syscall(SYS_open, "/etc/hostname", O_RDONLY);
#endif
    if (fd >= 0) syscall(SYS_close, fd);
    return 0;
}
