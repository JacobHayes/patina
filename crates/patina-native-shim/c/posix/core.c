/*
 * Core: feature macros, headers, the shared errno/deny helpers, and the
 * weak-hook stubs.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

#ifdef __linux__
#define _GNU_SOURCE 1
#define _LARGEFILE64_SOURCE 1

#endif

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1

#endif

#include "patina_native.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>

#ifdef __linux__
#include <sys/statfs.h>

#endif

#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <utime.h>
#include <sys/utsname.h>

#ifdef __linux__
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <linux/audit.h>
#include <linux/futex.h>
#include <linux/prctl.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <ucontext.h>

#endif

#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <crt_externs.h>
#include <libproc.h>
#include <mach/host_info.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/machine.h>
#include <mach/processor_info.h>
#include <mach/vm_statistics.h>
#include <mach-o/dyld.h>
#include <os/lock.h>
#include <stddef.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

#endif

static int fail_int(int result) {
    if (result < 0) errno = patina_errno();
    return result;
}

static ssize_t fail_size(intptr_t result) {
    if (result < 0) errno = patina_errno();
    return (ssize_t)result;
}

/* The platform's AT_FDCWD on the wire: the runtime's path resolver takes the
 * Linux value (PATINA_AT_FDCWD) whatever this libc spells it as, so every *at
 * interposer maps its dirfd through here. */
static int32_t patina_at(int dirfd) {
    return dirfd == AT_FDCWD ? PATINA_AT_FDCWD : dirfd;
}

/* Loud fail-closed: one deterministic diagnostic line on captured stderr,
 * then a recoverable ENOSYS. Never falls through to the host. The line goes
 * to the captured-stderr SINK directly (not through the interposed write on
 * guest number 2): a runtime diagnostic must reach the supervisor even after
 * the guest dup2'd a file over its stderr. */
static int patina_posix_deny(const char *message) {
    (void)patina_stdio_write(2, message, strlen(message));
    errno = ENOSYS;
    return -1;
}

#ifdef __linux__
/*
 * zstd's static library references these weak tracing hooks (Linux corpus only;
 * the macOS zstd build config does not surface them). The zstd_trace.h contract
 * is that a begin() returning 0 disables tracing, so provide no-op strong defs —
 * begin returns 0, end is inert — which satisfy the weak references so the
 * symbols drop off the import table. Opaque pointer parameters: C linkage does
 * not encode argument types, so the names bind regardless of the real structs.
 */
unsigned long long ZSTD_trace_compress_begin(const void *cctx) {
    (void)cctx;
    return 0;
}
void ZSTD_trace_compress_end(unsigned long long ctx, const void *trace) {
    (void)ctx;
    (void)trace;
}
unsigned long long ZSTD_trace_decompress_begin(const void *dctx) {
    (void)dctx;
    return 0;
}
void ZSTD_trace_decompress_end(unsigned long long ctx, const void *trace) {
    (void)ctx;
    (void)trace;
}
#endif

#ifdef __linux__
static int signal_result(int64_t rc) {
    patina_signal_deliver();
    if (rc < 0) { errno = (int)-rc; return -1; }
    return (int)rc;
}
#endif
