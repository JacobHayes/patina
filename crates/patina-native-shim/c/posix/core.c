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
#include <net/if.h>
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
#include <sys/sendfile.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
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
#include <ifaddrs.h>
#include <linux/audit.h>
#include <linux/futex.h>
#include <linux/if_link.h>
#include <linux/prctl.h>
#include <netpacket/packet.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/pidfd.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <termios.h>
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

/* Defined in stdio.c and registered at startup (init.c): the flush the
 * runtime makes on its exit paths, and the hand-over of buffered stdout the
 * runtime makes before every refusal ends the run. */
static void patina_stdio_flush_at_exit(void);
static size_t patina_stdio_take_pending(const void **bytes);

/*
 * A lock the POSIX layer takes for libc's own state (a stream's `_IO_lock_t`,
 * the environment's `envlock`), over the scheduler's mutex so concurrent
 * threads queue on it: whether it was taken. After `main` returns only the root
 * task runs — every other task stays parked where it was, at a scheduling
 * point, with the state consistent — so there is nothing to exclude, and
 * waiting on a lock a parked task holds would be a scheduling operation past
 * the end of the run, which the runtime refuses. None is taken then, as
 * glibc's exit flush (`_IO_cleanup`) takes none.
 */
static int patina_internal_lock(pthread_mutex_t *lock) {
    if (patina_in_teardown()) return 0;
    return patina_mutex_lock(lock) == 0;
}

static void patina_internal_unlock(pthread_mutex_t *lock, int held) {
    if (held) (void)patina_mutex_unlock(lock);
}

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

#ifdef __APPLE__
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

#endif

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

/* glibc's `__fortify_fail` (debug/fortify_fail.c), the `_FORTIFY_SOURCE`
 * entries' answer to a call the compiler proved wrong: "*** MESSAGE ***:
 * terminated" on stderr in one write, then SIGABRT (a guest abort). */
_Noreturn static void patina_fortify_fail(const char *message) {
    static const char head[] = "*** ";
    static const char tail[] = " ***: terminated\n";
    char line[128];
    size_t at = 0;
    for (size_t i = 0; i < sizeof head - 1; ++i) line[at++] = head[i];
    for (; *message != '\0' && at < sizeof line - sizeof tail; ++message) line[at++] = *message;
    for (size_t i = 0; i < sizeof tail - 1; ++i) line[at++] = tail[i];
    (void)patina_stdio_write(2, line, at);
    patina_abort();
}

/* glibc's `__chk_fail` (debug/chk_fail.c): a buffer smaller than the call may
 * write. */
_Noreturn static void patina_chk_fail(void) {
    patina_fortify_fail("buffer overflow detected");
}
#endif
