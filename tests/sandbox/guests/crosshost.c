// What differs between hosts unless the sandbox fixes it: the owner and device of a host
// file and of a sandbox file, the mount table, the CPU count, and a system call made with
// leftover values in registers the call does not read (as a cpuid result would leave them).
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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
    // getppid takes no arguments: the argument registers hold leftovers the kernel ignores.
    long r;
#ifdef __x86_64__
    register long r10 __asm__("r10") = 0x5a5a5a5a;
    register long r8 __asm__("r8") = 0x6b6b6b6b;
    register long r9 __asm__("r9") = 0x7c7c7c7c;
    __asm__ volatile("syscall" : "=a"(r) : "a"(110L), "D"(0x1111L), "S"(0x2222L), "d"(0x3333L), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
#else
    register long x0 __asm__("x0") = 0x1111, x1 __asm__("x1") = 0x2222, x2 __asm__("x2") = 0x3333;
    register long x3 __asm__("x3") = 0x5a5a5a5a, x4 __asm__("x4") = 0x6b6b6b6b, x5 __asm__("x5") = 0x7c7c7c7c;
    register long x8 __asm__("x8") = SYS_getppid;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8) : "memory");
    r = x0;
#endif
    printf("getppid %ld\n", r);
    fflush(stdout);
    return 0;
}
