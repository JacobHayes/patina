// What differs between hosts unless the sandbox fixes it: the owner and device of a host
// file and of a sandbox file, the mount table, the CPU count, and a system call made with
// leftover values in registers the call does not read (as a cpuid result would leave them).
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static void st(const char *p) {
    struct stat s;
    if (stat(p, &s) != 0) {
        printf("stat %s failed\n", p);
        return;
    }
    printf("stat %s uid=%u gid=%u dev=%u:%u\n", p, s.st_uid, s.st_gid, major(s.st_dev), minor(s.st_dev));
}

int main(void) {
    int fd = open("/work/own", O_CREAT | O_WRONLY, 0644);
    close(fd);
    st("/usr/bin/sh");
    st("/work/own");
    cpu_set_t set;
    CPU_ZERO(&set);
    sched_getaffinity(0, sizeof set, &set);
    printf("cpus %d\n", CPU_COUNT(&set));
    char buf[8192];
    fd = open("/proc/self/mountinfo", O_RDONLY);
    int n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    fputs(buf, stdout);
    // getppid takes no arguments: rdi..r9 hold leftovers the kernel ignores.
    long r;
    register long r10 __asm__("r10") = 0x5a5a5a5a;
    register long r8 __asm__("r8") = 0x6b6b6b6b;
    register long r9 __asm__("r9") = 0x7c7c7c7c;
    __asm__ volatile("syscall" : "=a"(r) : "a"(110L), "D"(0x1111L), "S"(0x2222L), "d"(0x3333L), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    printf("getppid %ld\n", r);
    fflush(stdout);
    return 0;
}
