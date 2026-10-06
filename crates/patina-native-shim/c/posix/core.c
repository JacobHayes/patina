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
#include <sys/ptrace.h>
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

/* Rust-owned errno adapters shared by remaining C slices. */
extern int fail_int(int result);
extern ssize_t fail_size(intptr_t result);
extern int patina_deterministic_getentropy(void *destination, size_t length);
extern ssize_t patina_deterministic_getrandom(void *destination, size_t length, unsigned int flags);

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
/*
 * A thread ends: with pthread_exit's value, or with PTHREAD_CANCELED when it
 * acts on a cancellation (glibc's __do_cancel). The model takes the value,
 * then glibc's own pthread_exit unwinds, called here in C once no Rust frame
 * is left on the stack: its forced unwind could not cross one.
 */
__attribute__((noreturn)) static void patina_exit_thread(void *value) {
    patina_host_pthread_exit_fn host_exit = patina_thread_exiting(value);
    host_exit(value);
}

__attribute__((noreturn)) static void patina_act_on_cancel(void) {
    patina_exit_thread(PTHREAD_CANCELED);
}

/*
 * A cancellation point the model acts at, as glibc's cancellable syscalls
 * are: a pending cancel acts at the entry, and one that arrives while the
 * thread waits inside acts as the wait returns.
 */
#define PATINA_CANCEL_ENTER(outer)            \
    int32_t outer = patina_cancel_enter();    \
    if (outer < 0) patina_act_on_cancel()
#define PATINA_CANCEL_LEAVE(outer)                               \
    do {                                                         \
        if (patina_cancel_leave(outer) < 0) patina_act_on_cancel(); \
    } while (0)

/*
 * Every other glibc cancellation point the shim defines: the model does not
 * act there, so a thread reaching one with a cancel to act on stops the run by
 * name, where glibc would end the thread at the entry. `name` is the glibc
 * cancellation point reached (patina-syscalls src/cancellation.rs lists them,
 * and a gate holds each wrapper to its check).
 */
#define PATINA_CANCEL_POINT(name) patina_cancel_point(name)

extern int signal_result(int64_t rc);

/* glibc's `__fortify_fail` (debug/fortify_fail.c), the `_FORTIFY_SOURCE`
 * entries' answer to a call the compiler proved wrong: "*** MESSAGE ***:
 * terminated" on stderr in one write, then SIGABRT (a guest abort). */
extern _Noreturn void patina_fortify_fail(const char *message);
extern _Noreturn void patina_chk_fail(void);
#else
/* macOS: cancellation is not modeled (pthread_cancel answers ENOSYS). */
#define PATINA_CANCEL_POINT(name) ((void)0)
#endif

/* Rust-owned environment state; private bridges for the remaining C callers. */
extern void patina_env_save_host(char **next);
extern void patina_environ_install(char **next);
extern void patina_capture_control_plane(void);
extern const char *patina_control_getenv(const char *name);
extern void patina_scrub_environ(void);
extern char *patina_env_lookup(const char *name);

/* Rust-owned fixed adapters referenced by the C route table. */
#ifdef __linux__
extern int mount(const char *source, const char *target, const char *type, unsigned long flags, const void *data);
extern int umount2(const char *target, int flags);
extern int pivot_root(const char *new_root, const char *put_old);
extern int open_tree(int dirfd, const char *path, unsigned int flags);
extern int move_mount(int from_dirfd, const char *from_path, int to_dirfd, const char *to_path, unsigned int flags);
extern int fsopen(const char *fs_name, unsigned int flags);
extern int fsconfig(int fd, unsigned int cmd, const char *key, const void *value, int aux);
extern int fsmount(int fd, unsigned int flags, unsigned int attr_flags);
extern int fspick(int dirfd, const char *path, unsigned int flags);
extern int mount_setattr(int dirfd, const char *path, unsigned int flags, void *attr, size_t size);
extern int acct(const char *path);
extern int vhangup(void);
extern int swapon(const char *path, int flags);
extern int swapoff(const char *path);
extern int reboot(int howto);
extern int init_module(void *image, unsigned long length, const char *params);
extern int delete_module(const char *name, unsigned int flags);
extern int quotactl(int cmd, const char *special, int id, char *addr);
extern int unshare(int flags);
extern int setns(int fd, int nstype);
extern int chroot(const char *path);
#ifdef __x86_64__
extern int iopl(int level);
extern int ioperm(unsigned long from, unsigned long count, int turn_on);
#endif
#endif

/* Darwin world-model constant still used by the platform adapters. */
#define PATINA_PHYSICAL_MEMORY_BYTES (UINT64_C(8) * 1024 * 1024 * 1024)
#ifdef __linux__
extern int __res_init(void);
extern int res_init(void);
#endif

#ifdef __linux__
extern int __poll_chk(struct pollfd *fds, nfds_t nfds, int timeout, size_t fdslen);
extern int __ppoll_chk(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *mask, size_t fdslen);
#endif

#ifdef __linux__
#include <pty.h>
#include <sys/file.h>
/* Rust-owned descriptor doors and the private buffering query. */
extern int patina_isatty(int fd);
extern int __open_2(const char *, int);
extern int __open64_2(const char *, int);
extern int __openat_2(int, const char *, int);
extern int __openat64_2(int, const char *, int);
extern ssize_t __readlink_chk(const char *, char *, size_t, size_t);
extern ssize_t __readlinkat_chk(int, const char *, char *, size_t, size_t);
_Static_assert(sizeof(struct statvfs) == 112 && offsetof(struct statvfs, f_type) == 88, "Rust Statvfs layout");
_Static_assert(sizeof(struct statvfs64) == 112 && offsetof(struct statvfs64, f_type) == 88, "Rust Statvfs64 layout");
extern ssize_t __recv_chk(int, void *, size_t, size_t, int);
extern ssize_t __recvfrom_chk(int, void *, size_t, size_t, int, struct sockaddr *, socklen_t *);
_Static_assert(sizeof(struct rtnl_link_stats) == 96 && offsetof(struct rtnl_link_stats, rx_nohandler) == 92, "Rust LinkStats layout");
extern ssize_t __read(int fd, void *destination, size_t length);
extern ssize_t __write(int fd, const void *source, size_t length);
extern ssize_t __read_chk(int fd, void *destination, size_t length, size_t buflen);
extern ssize_t __pread_chk(int fd, void *destination, size_t length, off_t offset, size_t buflen);
extern ssize_t __pread64_chk(int fd, void *destination, size_t length, off64_t offset, size_t buflen);
extern int __ptsname_r_chk(int fd, char *buf, size_t buflen, size_t nreal);
extern int __ttyname_r_chk(int fd, char *buf, size_t buflen, size_t nreal);
#endif

extern int patina_fd_stat(int, struct patina_metadata *, struct stat *) __attribute__((visibility("hidden")));
