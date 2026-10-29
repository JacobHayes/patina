/* A shared library for glibc_internal_probe.c: code outside the main
 * executable that reaches the kernel without an interposed call, as a
 * library's own code does.
 *
 *   loadavg  glibc's getloadavg, whose read of /proc/loadavg is glibc's own
 *            internal open/read/close
 *   raw      an inline getpid instruction */
#define _DEFAULT_SOURCE
#include <stdlib.h>

int probe_library_loadavg(double loads[3]) { return getloadavg(loads, 3); }

long probe_library_raw_getpid(void) {
#if defined(__x86_64__)
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(39L) : "rcx", "r11", "memory");
    return ret;
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = 172;
    register long x0 __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory");
    return x0;
#endif
}
