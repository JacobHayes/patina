#ifdef __linux__
#define _GNU_SOURCE 1
#define _LARGEFILE64_SOURCE 1
#elif defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif

#include "patina_native.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#ifdef __linux__
#include <dlfcn.h>
#include <linux/futex.h>
#include <sys/random.h>
#include <sys/syscall.h>
#endif
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <crt_externs.h>
#include <mach/mach_time.h>

uint64_t mach_absolute_time(void) {
    uint64_t nanos = 0;
    if (patina_clock_now(PATINA_CLOCK_MONOTONIC, &nanos) != 0) __builtin_trap();
    return nanos;
}

kern_return_t mach_timebase_info(mach_timebase_info_t info) {
    if (info == NULL) return KERN_INVALID_ARGUMENT;
    info->numer = 1;
    info->denom = 1;
    return KERN_SUCCESS;
}

kern_return_t mach_wait_until(uint64_t deadline) {
    if (patina_sleep_until(PATINA_CLOCK_MONOTONIC, deadline) != 0) __builtin_trap();
    return KERN_SUCCESS;
}
#endif

static int fail_int(int result) {
    if (result < 0) errno = patina_errno();
    return result;
}

static ssize_t fail_size(intptr_t result) {
    if (result < 0) errno = patina_errno();
    return (ssize_t)result;
}

/* Loud fail-closed: one deterministic diagnostic line on captured stderr,
 * then a recoverable ENOSYS. Never falls through to the host. */
static int patina_posix_deny(const char *message) {
    write(2, message, strlen(message));
    errno = ENOSYS;
    return -1;
}

int clock_gettime(clockid_t clock_id, struct timespec *time) {
    uint32_t patina_clock;
    if (clock_id == CLOCK_REALTIME) patina_clock = PATINA_CLOCK_REALTIME;
    else if (clock_id == CLOCK_MONOTONIC
#ifdef __APPLE__
        || clock_id == CLOCK_UPTIME_RAW
#endif
    ) patina_clock = PATINA_CLOCK_MONOTONIC;
    else {
        errno = EINVAL;
        return -1;
    }
    uint64_t nanos = 0;
    if (patina_clock_now(patina_clock, &nanos) != 0) {
        errno = patina_errno();
        return -1;
    }
    time->tv_sec = (time_t)(nanos / UINT64_C(1000000000));
    time->tv_nsec = (long)(nanos % UINT64_C(1000000000));
    return 0;
}

int gettimeofday(struct timeval *restrict time, void *restrict zone) {
    (void)zone;
    uint64_t nanos = 0;
    if (patina_clock_now(PATINA_CLOCK_REALTIME, &nanos) != 0) {
        errno = patina_errno();
        return -1;
    }
    time->tv_sec = (time_t)(nanos / UINT64_C(1000000000));
    time->tv_usec = (suseconds_t)((nanos % UINT64_C(1000000000)) / UINT64_C(1000));
    return 0;
}

extern char **environ;

/* Snapshot of the PATINA_* control plane, captured before the ambient host
 * environment is scrubbed. The public interposed getenv always returns NULL;
 * shim-internal startup reads use patina_control_getenv so guest-visible
 * environment reads are completely empty and deterministic after init. */
static char **patina_control_plane = NULL;

static char **patina_environ_base(void) {
#ifdef __APPLE__
    return *_NSGetEnviron();
#else
    return environ;
#endif
}

static void patina_capture_control_plane(void) {
    if (patina_control_plane != NULL) return;
    char **base = patina_environ_base();
    if (base == NULL) return;
    size_t kept = 0;
    for (char **entry = base; *entry != NULL; ++entry) {
        if (strncmp(*entry, "PATINA_", 7) == 0) kept += 1;
    }
    char **snapshot = calloc(kept + 1, sizeof *snapshot);
    if (snapshot == NULL) {
        static const char message[] =
            "patina: failed to capture the PATINA_* control plane before scrubbing the environment\n";
        write(2, message, sizeof message - 1);
        abort();
    }
    size_t index = 0;
    for (char **entry = base; *entry != NULL; ++entry) {
        if (strncmp(*entry, "PATINA_", 7) == 0) {
            snapshot[index++] = *entry;
            patina_control_set_entry(*entry);
        }
    }
    snapshot[index] = NULL;
    patina_control_plane = snapshot;
}

/* Empty the live environ array in place. Every reader — the Linux `environ`
 * global, Darwin `_NSGetEnviron`, std::env::vars — then sees the deterministic
 * (empty) environment. The entry strings stay alive; the snapshot borrows them. */
static void patina_scrub_environ(void) {
    char **base = patina_environ_base();
    if (base == NULL) return;
    base[0] = NULL;
}

const char *patina_control_getenv(const char *name) {
    if (name == NULL || strncmp(name, "PATINA_", 7) != 0) return NULL;
    patina_capture_control_plane();
    size_t length = strlen(name);
    for (char **entry = patina_control_plane; entry != NULL && *entry != NULL; ++entry) {
        if (strncmp(*entry, name, length) == 0 && (*entry)[length] == '=') {
            return *entry + length + 1;
        }
    }
    return NULL;
}

char *getenv(const char *name) {
    (void)name;
    return NULL;
}

/* The deterministic environment is immutable: mutation through the host libc
 * would repopulate the scrubbed environ behind the runtime's back. */
int setenv(const char *name, const char *value, int overwrite) {
    (void)name; (void)value; (void)overwrite;
    return patina_posix_deny("patina: setenv is not modeled; the deterministic environment is immutable; failing closed\n");
}

int unsetenv(const char *name) {
    (void)name;
    return patina_posix_deny("patina: unsetenv is not modeled; the deterministic environment is immutable; failing closed\n");
}

int putenv(char *string) {
    (void)string;
    return patina_posix_deny("patina: putenv is not modeled; the deterministic environment is immutable; failing closed\n");
}

pid_t getpid(void) {
    return (pid_t)1;
}

pid_t getppid(void) {
    return (pid_t)0;
}

#ifdef __linux__
pid_t gettid(void) {
    return (pid_t)patina_thread_id();
}

int __res_init(void) {
    errno = ENOSYS;
    return -1;
}

int res_init(void) {
    return __res_init();
}
#elif defined(__APPLE__)
int pthread_threadid_np(pthread_t thread, uint64_t *thread_id) {
    if (thread_id == NULL) return EINVAL;
    if (thread != NULL && !pthread_equal(thread, pthread_self())) return ENOTSUP;
    *thread_id = (uint64_t)patina_thread_id();
    return 0;
}
#endif

int uname(struct utsname *name) {
    (void)name;
    errno = ENOSYS;
    return -1;
}

char *getcwd(char *destination, size_t length) {
    if (destination == NULL || length < 2) {
        errno = destination == NULL ? ENOSYS : ERANGE;
        return NULL;
    }
    destination[0] = '/';
    destination[1] = '\0';
    return destination;
}

char *realpath(const char *restrict path, char *restrict destination) {
    if (destination == NULL) {
        errno = ENOSYS;
        return NULL;
    }
    uint32_t kind = 0;
    uint64_t length = 0;
    if (patina_metadata(path, &kind, &length) != 0) {
        errno = patina_errno();
        return NULL;
    }
    (void)kind;
    (void)length;
    size_t path_length = strlen(path);
    if (path_length >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    memcpy(destination, path, path_length + 1);
    return destination;
}

int nanosleep(const struct timespec *duration, struct timespec *remaining) {
    if (duration == NULL || duration->tv_sec < 0 || duration->tv_nsec < 0 ||
        duration->tv_nsec >= 1000000000L) {
        errno = EINVAL;
        return -1;
    }
    uint64_t now = 0;
    if (patina_clock_now(PATINA_CLOCK_MONOTONIC, &now) != 0) {
        errno = patina_errno();
        return -1;
    }
    uint64_t seconds = (uint64_t)duration->tv_sec;
    if (seconds > UINT64_MAX / UINT64_C(1000000000)) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t delta = seconds * UINT64_C(1000000000) + (uint64_t)duration->tv_nsec;
    if (delta > UINT64_MAX - now) {
        errno = EOVERFLOW;
        return -1;
    }
    if (patina_sleep_until(PATINA_CLOCK_MONOTONIC, now + delta) != 0) {
        errno = patina_errno();
        return -1;
    }
    if (remaining != NULL) memset(remaining, 0, sizeof *remaining);
    return 0;
}

#ifdef __linux__
/*
 * Rust's std::thread::sleep on Linux sleeps through clock_nanosleep rather
 * than nanosleep. Unlike nanosleep, this call returns the error number
 * directly and never sets errno. Darwin has no clock_nanosleep.
 */
int clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *request,
                    struct timespec *remain) {
    uint32_t patina_clock;
    if (clock_id == CLOCK_REALTIME) patina_clock = PATINA_CLOCK_REALTIME;
    else if (clock_id == CLOCK_MONOTONIC) patina_clock = PATINA_CLOCK_MONOTONIC;
    else return EINVAL;
    if ((flags & ~TIMER_ABSTIME) != 0) return EINVAL;
    if (request == NULL || request->tv_sec < 0 || request->tv_nsec < 0 ||
        request->tv_nsec >= 1000000000L) {
        return EINVAL;
    }
    uint64_t seconds = (uint64_t)request->tv_sec;
    if (seconds > UINT64_MAX / UINT64_C(1000000000)) return EINVAL;
    uint64_t request_nanos = seconds * UINT64_C(1000000000) + (uint64_t)request->tv_nsec;
    uint64_t deadline = request_nanos;
    if ((flags & TIMER_ABSTIME) == 0) {
        uint64_t now = 0;
        if (patina_clock_now(patina_clock, &now) != 0) return patina_errno();
        if (request_nanos > UINT64_MAX - now) return EINVAL;
        deadline = now + request_nanos;
    }
    if (patina_sleep_until(patina_clock, deadline) != 0) return patina_errno();
    if (remain != NULL) memset(remain, 0, sizeof *remain);
    return 0;
}
#endif

int poll(struct pollfd *descriptors, nfds_t count, int timeout) {
    if (count != 0) {
        if (timeout != 0) {
            errno = ENOSYS;
            return -1;
        }
        for (nfds_t index = 0; index < count; ++index) {
            if (descriptors[index].events != 0) {
                errno = ENOSYS;
                return -1;
            }
            descriptors[index].revents = 0;
        }
        return 0;
    }
    if (timeout > 0) {
        struct timespec duration = {
            .tv_sec = (time_t)(timeout / 1000),
            .tv_nsec = (long)(timeout % 1000) * 1000000L,
        };
        if (nanosleep(&duration, NULL) != 0) return -1;
    }
    return 0;
}

int pause(void) {
    errno = ENOSYS;
    return -1;
}

int getentropy(void *destination, size_t length) {
    if (patina_entropy(destination, length) != 0) {
        errno = patina_errno();
        return -1;
    }
    return 0;
}

#ifdef __APPLE__
/* Rust std sources RandomState entropy from CommonCrypto on macOS. */
int32_t CCRandomGenerateBytes(void *destination, size_t length) {
    if (patina_entropy(destination, length) != 0) __builtin_trap();
    return 0; /* kCCSuccess */
}
#endif

#ifdef __linux__
ssize_t getrandom(void *destination, size_t length, unsigned int flags) {
    if ((flags & ~(GRND_NONBLOCK | GRND_RANDOM)) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (patina_entropy(destination, length) != 0) {
        errno = patina_errno();
        return -1;
    }
    return (ssize_t)length;
}

/*
 * Rust std on Linux lowers Mutex/Condvar/thread parking to raw SYS_futex
 * through this libc wrapper (not pthread), so route FUTEX_WAIT/WAKE through the
 * deterministic scheduler and fail closed on every other syscall number.
 */
long syscall(long number, ...) {
    if (number == SYS_futex) {
        va_list ap;
        va_start(ap, number);
        uint32_t *uaddr = va_arg(ap, uint32_t *);
        int futex_op = va_arg(ap, int);
        unsigned int val = va_arg(ap, unsigned int);
        /* const struct timespec *timeout follows (uint32_t *uaddr2, uint32_t
         * val3 after it are unused here). A NULL timeout waits forever; a
         * non-NULL one parks on the virtual-clock timer queue. */
        const struct timespec *timeout = va_arg(ap, const struct timespec *);
        va_end(ap);
        int op = futex_op & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
        if (op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET) {
            long result;
            if (timeout == NULL) {
                result = patina_futex_wait((uintptr_t)uaddr, (uint32_t)val);
            } else {
                /* FUTEX_WAIT: relative CLOCK_MONOTONIC timeout. FUTEX_WAIT_BITSET:
                 * absolute deadline, CLOCK_REALTIME iff FUTEX_CLOCK_REALTIME. */
                int absolute = (op == FUTEX_WAIT_BITSET);
                uint32_t clock = (absolute && (futex_op & FUTEX_CLOCK_REALTIME))
                                     ? PATINA_CLOCK_REALTIME
                                     : PATINA_CLOCK_MONOTONIC;
                if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
                    timeout->tv_nsec >= 1000000000L) {
                    errno = EINVAL;
                    return -1;
                }
                uint64_t seconds = (uint64_t)timeout->tv_sec;
                if (seconds > UINT64_MAX / UINT64_C(1000000000)) {
                    errno = EOVERFLOW;
                    return -1;
                }
                uint64_t timeout_nanos =
                    seconds * UINT64_C(1000000000) + (uint64_t)timeout->tv_nsec;
                result = patina_futex_wait_timed((uintptr_t)uaddr, (uint32_t)val,
                                                 clock, absolute, timeout_nanos);
            }
            if (result < 0) errno = patina_errno();
            return result;
        }
        if (op == FUTEX_WAKE || op == FUTEX_WAKE_BITSET) {
            return patina_futex_wake((uintptr_t)uaddr, (int)val);
        }
        errno = ENOSYS;
        return -1;
    }
    (void)number;
    errno = ENOSYS;
    return -1;
}

/*
 * Rust std probes for optional glibc symbols (e.g. __pthread_get_minstack) via
 * dlsym when spawning threads. Interpose it to resolve nothing: dynamic symbol
 * lookup is neutered fail-closed (no host symbol is ever returned) rather than
 * allowlisted, and std falls back to its defaults. dlopen/dlclose/dladdr are
 * not provided, so an unmanaged binary importing them is still audit-rejected.
 */
void *dlsym(void *handle, const char *symbol) {
    (void)handle;
    (void)symbol;
    return NULL;
}
#endif

struct patina_dir {
    void *state;
    char *path;
    uint64_t index;
    struct dirent entry;
#ifdef __linux__
    struct dirent64 entry64;
#endif
};

static unsigned char patina_dirent_type(uint32_t kind) {
    switch (kind) {
        case PATINA_ENTRY_DIRECTORY: return DT_DIR;
        case PATINA_ENTRY_SYMLINK: return DT_LNK;
        case PATINA_ENTRY_FILE:
        default: return DT_REG;
    }
}

static void patina_fill_dirent_common(struct dirent *entry, uint64_t index, uint32_t kind) {
    /* Deterministic synthetic inode: one-based snapshot index in driver order. */
    entry->d_ino = (ino_t)(index + 1);
    entry->d_reclen = (unsigned short)sizeof *entry;
#ifdef __APPLE__
    entry->d_namlen = (uint8_t)strlen(entry->d_name);
#endif
    entry->d_type = patina_dirent_type(kind);
}

DIR *opendir(const char *path) {
    void *state = NULL;
    if (patina_read_dir(path, &state) != 0) {
        errno = patina_errno();
        return NULL;
    }
    struct patina_dir *directory = calloc(1, sizeof *directory);
    if (directory == NULL) {
        patina_read_dir_free(state);
        errno = ENOMEM;
        return NULL;
    }
    size_t path_size = strlen(path) + 1;
    directory->path = malloc(path_size);
    if (directory->path == NULL) {
        free(directory);
        patina_read_dir_free(state);
        errno = ENOMEM;
        return NULL;
    }
    memcpy(directory->path, path, path_size);
    directory->state = state;
    return (DIR *)(void *)directory;
}

/* glibc declares the DIR/dirent parameters nonnull (NULL is caller UB, and
 * -Wnonnull-compare rejects defensive checks), so these trust the contract. */
struct dirent *readdir(DIR *dirp) {
    struct patina_dir *directory = (struct patina_dir *)(void *)dirp;
    uint32_t kind = 0;
    int result = patina_read_dir_next(directory->state, directory->entry.d_name,
                                      sizeof directory->entry.d_name, &kind);
    if (result < 0) {
        errno = patina_errno();
        return NULL;
    }
    if (result == 0) return NULL;
    patina_fill_dirent_common(&directory->entry, directory->index, kind);
    directory->index += 1;
    return &directory->entry;
}

int readdir_r(DIR *restrict dirp, struct dirent *restrict entry,
              struct dirent **restrict result) {
    errno = 0;
    struct dirent *next = readdir(dirp);
    if (next == NULL) {
        *result = NULL;
        return errno;
    }
    memcpy(entry, next, sizeof *entry);
    *result = entry;
    return 0;
}

#ifdef __linux__
struct dirent64 *readdir64(DIR *dirp) {
    struct patina_dir *directory = (struct patina_dir *)(void *)dirp;
    uint32_t kind = 0;
    int result = patina_read_dir_next(directory->state, directory->entry64.d_name,
                                      sizeof directory->entry64.d_name, &kind);
    if (result < 0) {
        errno = patina_errno();
        return NULL;
    }
    if (result == 0) return NULL;
    /* Deterministic synthetic inode: one-based snapshot index in driver order. */
    directory->entry64.d_ino = (ino64_t)(directory->index + 1);
    directory->entry64.d_reclen = (unsigned short)sizeof directory->entry64;
    directory->entry64.d_type = patina_dirent_type(kind);
    directory->index += 1;
    return &directory->entry64;
}
#endif

int closedir(DIR *dirp) {
    struct patina_dir *directory = (struct patina_dir *)(void *)dirp;
    patina_read_dir_free(directory->state);
    free(directory->path);
    free(directory);
    return 0;
}

void rewinddir(DIR *dirp) {
    struct patina_dir *directory = (struct patina_dir *)(void *)dirp;
    void *state = NULL;
    if (patina_read_dir(directory->path, &state) != 0) {
        errno = patina_errno();
        return;
    }
    patina_read_dir_free(directory->state);
    directory->state = state;
    directory->index = 0;
}

int dirfd(DIR *dirp) {
    (void)dirp;
    errno = ENOTSUP;
    return -1;
}

int symlink(const char *target, const char *link_path) {
    return fail_int(patina_symlink(target, link_path));
}

ssize_t readlink(const char *restrict path, char *restrict destination, size_t length) {
    return fail_size(patina_read_link(path, destination, length));
}

static int patina_posix_open(const char *path, int flags) {
    int supported = O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND | O_EXCL;
#ifdef O_CLOEXEC
    supported |= O_CLOEXEC;
#endif
#ifdef O_LARGEFILE
    supported |= O_LARGEFILE;
#endif
#ifdef O_NOFOLLOW
    supported |= O_NOFOLLOW;
#endif
    if ((flags & ~supported) != 0) {
        errno = ENOSYS;
        return -1;
    }
    uint32_t patina_flags = 0;
    switch (flags & O_ACCMODE) {
        case O_RDONLY: patina_flags |= PATINA_O_READ; break;
        case O_WRONLY: patina_flags |= PATINA_O_WRITE; break;
        case O_RDWR: patina_flags |= PATINA_O_READ | PATINA_O_WRITE; break;
        default: errno = EINVAL; return -1;
    }
    if (flags & O_CREAT) patina_flags |= PATINA_O_CREATE;
    if (flags & O_TRUNC) patina_flags |= PATINA_O_TRUNCATE;
    if (flags & O_APPEND) patina_flags |= PATINA_O_APPEND;
    if (flags & O_EXCL) patina_flags |= PATINA_O_EXCLUSIVE;
    return fail_int(patina_open(path, patina_flags));
}

int open(const char *path, int flags, ...) {
    return patina_posix_open(path, flags);
}

int fcntl(int fd, int command, ...) {
    /* Virtual sockets: report/adjust the blocking flag; cloexec is a no-op. */
    if (fd >= PATINA_SOCKET_FD_BASE) {
        if (command == F_GETFL) {
            int nonblocking = patina_net_is_nonblocking(fd);
            if (nonblocking < 0) {
                errno = EBADF;
                return -1;
            }
            return nonblocking ? O_NONBLOCK : 0;
        }
        if (command == F_SETFL) {
            va_list ap;
            va_start(ap, command);
            int flags = va_arg(ap, int);
            va_end(ap);
            return patina_net_set_nonblocking(fd, (flags & O_NONBLOCK) ? 1 : 0);
        }
        if (command == F_GETFD) return FD_CLOEXEC;
        if (command == F_SETFD) return 0;
        if (command == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
            || command == F_DUPFD_CLOEXEC
#endif
        )
            return patina_posix_deny("patina: duplicating a virtual socket descriptor is not modeled; failing closed\n");
        errno = EINVAL;
        return -1;
    }
#ifdef __APPLE__
    /* Rust std maps File::sync_all to F_FULLFSYNC on Darwin. */
    if (command == F_FULLFSYNC) return fail_int(patina_fsync(fd));
#endif
    if (command == F_GETFD) return FD_CLOEXEC;
    if (command == F_SETFD) return 0;
    if (command == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
        || command == F_DUPFD_CLOEXEC
#endif
    ) {
        if (fd >= 0 && fd <= 2)
            return patina_posix_deny("patina: duplicating a captured stdio descriptor is not modeled; failing closed\n");
        va_list ap;
        va_start(ap, command);
        int minimum = va_arg(ap, int);
        va_end(ap);
        int duplicate = patina_dup(fd);
        if (duplicate < 0) {
            errno = patina_errno();
            return -1;
        }
        if (duplicate < minimum) {
            /* Deterministic numbering is monotonic from 3; a minimum above the
             * counter cannot be honored without modeling sparse fd placement. */
            patina_close(duplicate);
            return patina_posix_deny("patina: F_DUPFD minimum above the deterministic descriptor counter is not modeled; failing closed\n");
        }
        return duplicate; /* CLOEXEC is a no-op: no exec under the runtime. */
    }
    errno = ENOSYS;
    return -1;
}

#ifdef __linux__
int open64(const char *path, int flags, ...) {
    return patina_posix_open(path, flags);
}
#endif

ssize_t read(int fd, void *destination, size_t length) {
    if (fd >= PATINA_SOCKET_FD_BASE) {
        int kind = patina_net_kind(fd);
        if (kind == 3) return fail_size(patina_net_stream_recv(fd, destination, length));
        if (kind == 0) return fail_size(patina_net_recv(fd, destination, length));
        errno = kind < 0 ? EBADF : ENOTCONN;
        return -1;
    }
    return fail_size(patina_read(fd, destination, length));
}

ssize_t write(int fd, const void *source, size_t length) {
    if (fd == 1 || fd == 2) return fail_size(patina_stdio_write(fd, source, length));
    if (fd >= PATINA_SOCKET_FD_BASE) {
        int kind = patina_net_kind(fd);
        if (kind == 3) return fail_size(patina_net_stream_send(fd, source, length));
        if (kind == 0) return fail_size(patina_net_send(fd, source, length));
        errno = kind < 0 ? EBADF : ENOTCONN;
        return -1;
    }
    return fail_size(patina_write(fd, source, length));
}

int close(int fd) {
    if (fd >= PATINA_SOCKET_FD_BASE) return fail_int(patina_net_close(fd));
    return fail_int(patina_close(fd));
}

int dup(int fd) {
    if (fd >= 0 && fd <= 2)
        return patina_posix_deny("patina: duplicating a captured stdio descriptor is not modeled; failing closed\n");
    if (fd >= PATINA_SOCKET_FD_BASE)
        return patina_posix_deny("patina: duplicating a virtual socket descriptor is not modeled; failing closed\n");
    return fail_int(patina_dup(fd));
}

int dup2(int oldfd, int newfd) {
    if (oldfd == newfd) {
        /* POSIX: equal descriptors validate oldfd and return newfd unchanged. */
        if (oldfd >= 0 && oldfd <= 2) return newfd;
        if (oldfd >= PATINA_SOCKET_FD_BASE) {
            if (patina_net_is_nonblocking(oldfd) < 0) { errno = EBADF; return -1; }
            return newfd;
        }
        uint32_t kind;
        uint64_t length, ino_v, atime_v, mtime_v;
        uint32_t nlink_v;
        if (patina_fd_metadata_full(oldfd, &kind, &length, &ino_v, &nlink_v, &atime_v, &mtime_v) != 0) {
            errno = patina_errno();
            return -1;
        }
        return newfd;
    }
    return patina_posix_deny("patina: dup2 to a chosen descriptor number is not modeled; failing closed\n");
}

#ifdef __linux__
int dup3(int oldfd, int newfd, int flags) {
    (void)oldfd;
    (void)flags;
    if (oldfd == newfd) { errno = EINVAL; return -1; } /* POSIX dup3 */
    return patina_posix_deny("patina: dup3 to a chosen descriptor number is not modeled; failing closed\n");
}
#endif

ssize_t writev(int fd, const struct iovec *vectors, int count) {
    if (count < 0 || (count > 0 && vectors == NULL)) {
        errno = EINVAL;
        return -1;
    }
    ssize_t total = 0;
    for (int index = 0; index < count; ++index) {
        ssize_t written = write(fd, vectors[index].iov_base, vectors[index].iov_len);
        if (written < 0) return total > 0 ? total : -1;
        total += written;
        if ((size_t)written < vectors[index].iov_len) break;
    }
    return total;
}

ssize_t readv(int fd, const struct iovec *vectors, int count) {
    if (count < 0 || (count > 0 && vectors == NULL)) {
        errno = EINVAL;
        return -1;
    }
    ssize_t total = 0;
    for (int index = 0; index < count; ++index) {
        ssize_t consumed = read(fd, vectors[index].iov_base, vectors[index].iov_len);
        if (consumed < 0) return total > 0 ? total : -1;
        total += consumed;
        if ((size_t)consumed < vectors[index].iov_len) break;
    }
    return total;
}

off_t lseek(int fd, off_t offset, int whence) {
    uint32_t patina_whence;
    switch (whence) {
        case SEEK_SET: patina_whence = PATINA_SEEK_START; break;
        case SEEK_CUR: patina_whence = PATINA_SEEK_CURRENT; break;
        case SEEK_END: patina_whence = PATINA_SEEK_END; break;
        default: errno = EINVAL; return (off_t)-1;
    }
    int64_t result = patina_seek(fd, (int64_t)offset, patina_whence);
    if (result < 0) errno = patina_errno();
    return (off_t)result;
}

int fsync(int fd) {
    return fail_int(patina_fsync(fd));
}

int ftruncate(int fd, off_t length) {
    if (length < 0) {
        errno = EINVAL;
        return -1;
    }
    return fail_int(patina_set_len(fd, (uint64_t)length));
}

#ifdef __linux__
off64_t lseek64(int fd, off64_t offset, int whence) {
    return (off64_t)lseek(fd, (off_t)offset, whence);
}

int ftruncate64(int fd, off64_t length) {
    return ftruncate(fd, (off_t)length);
}
#endif

struct patina_stat_values {
    uint32_t kind;
    uint64_t length;
    uint64_t ino;
    uint32_t nlink;
    uint64_t atime_nanos;
    uint64_t mtime_nanos;
};

static mode_t patina_mode_for_kind(uint32_t kind) {
    switch (kind) {
        case PATINA_ENTRY_DIRECTORY: return S_IFDIR | 0700;
        case PATINA_ENTRY_SYMLINK: return S_IFLNK | 0777;
        case PATINA_ENTRY_FILE:
        default: return S_IFREG | 0700;
    }
}

static void patina_split_nanos(uint64_t nanos, time_t *seconds, long *subseconds) {
    *seconds = (time_t)(nanos / UINT64_C(1000000000));
    *subseconds = (long)(nanos % UINT64_C(1000000000));
}

static int patina_metadata_values(const char *path, struct patina_stat_values *values) {
    return patina_metadata_full(path, &values->kind, &values->length, &values->ino,
                                &values->nlink, &values->atime_nanos, &values->mtime_nanos);
}

static int patina_fd_metadata_values(int fd, struct patina_stat_values *values) {
    return patina_fd_metadata_full(fd, &values->kind, &values->length, &values->ino,
                                   &values->nlink, &values->atime_nanos, &values->mtime_nanos);
}

static int patina_resolve_symlink_target(const char *link_path, const char *target,
                                         char *resolved, size_t resolved_len) {
    if (target[0] == '/') {
        size_t target_len = strlen(target);
        if (target_len >= resolved_len) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(resolved, target, target_len + 1);
        return 0;
    }
    const char *slash = strrchr(link_path, '/');
    size_t parent_len = 0;
    if (slash != NULL) parent_len = slash == link_path ? 1 : (size_t)(slash - link_path);
    size_t target_len = strlen(target);
    size_t separator = parent_len == 0 || (parent_len == 1 && link_path[0] == '/') ? 0 : 1;
    if (parent_len + separator + target_len + 1 > resolved_len) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (parent_len == 0) {
        memcpy(resolved, target, target_len + 1);
    } else {
        memcpy(resolved, link_path, parent_len);
        size_t offset = parent_len;
        if (separator) resolved[offset++] = '/';
        memcpy(resolved + offset, target, target_len + 1);
    }
    return 0;
}

static int patina_stat_metadata(const char *path, int follow_terminal_symlink,
                                struct patina_stat_values *values) {
    int result = patina_metadata_values(path, values);
    if (result < 0) {
        errno = patina_errno();
        return -1;
    }
    if (!follow_terminal_symlink || values->kind != PATINA_ENTRY_SYMLINK) return 0;

    char target[PATH_MAX];
    ssize_t target_len = readlink(path, target, sizeof target - 1);
    if (target_len < 0) return -1;
    target[target_len] = '\0';
    char resolved[PATH_MAX];
    if (patina_resolve_symlink_target(path, target, resolved, sizeof resolved) != 0) return -1;
    result = patina_metadata_values(resolved, values);
    if (result < 0) {
        errno = patina_errno();
        return -1;
    }
    if (values->kind == PATINA_ENTRY_SYMLINK) {
        errno = ELOOP;
        return -1;
    }
    return 0;
}

static int fill_stat(int result, const struct patina_stat_values *values, struct stat *status) {
    if (result < 0) return -1;
    if (status == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(status, 0, sizeof *status);
    status->st_mode = patina_mode_for_kind(values->kind);
    status->st_nlink = (nlink_t)values->nlink;
    status->st_ino = (ino_t)values->ino;
    status->st_size = (off_t)values->length;
#ifdef __APPLE__
    patina_split_nanos(values->atime_nanos, &status->st_atimespec.tv_sec,
                       &status->st_atimespec.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_mtimespec.tv_sec,
                       &status->st_mtimespec.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_ctimespec.tv_sec,
                       &status->st_ctimespec.tv_nsec);
#else
    patina_split_nanos(values->atime_nanos, &status->st_atim.tv_sec, &status->st_atim.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_mtim.tv_sec, &status->st_mtim.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_ctim.tv_sec, &status->st_ctim.tv_nsec);
#endif
    return 0;
}

int stat(const char *path, struct stat *status) {
    struct patina_stat_values values;
    int result = patina_stat_metadata(path, 1, &values);
    return fill_stat(result, &values, status);
}

int lstat(const char *path, struct stat *status) {
    struct patina_stat_values values;
    int result = patina_stat_metadata(path, 0, &values);
    return fill_stat(result, &values, status);
}

int fstat(int fd, struct stat *status) {
    struct patina_stat_values values;
    int result = patina_fd_metadata_values(fd, &values);
    if (result < 0) errno = patina_errno();
    return fill_stat(result, &values, status);
}

int fstatat(int directory, const char *restrict path, struct stat *restrict status, int flags) {
    if (directory != AT_FDCWD) {
        errno = ENOSYS;
        return -1;
    }
    if ((flags & ~AT_SYMLINK_NOFOLLOW) != 0) {
        errno = ENOSYS;
        return -1;
    }
    struct patina_stat_values values;
    int follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    int result = patina_stat_metadata(path, follow, &values);
    return fill_stat(result, &values, status);
}

#ifdef __linux__
static int fill_stat64(int result, const struct patina_stat_values *values, struct stat64 *status) {
    if (result < 0) return -1;
    if (status == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(status, 0, sizeof *status);
    status->st_mode = patina_mode_for_kind(values->kind);
    status->st_nlink = (nlink_t)values->nlink;
    status->st_ino = (ino64_t)values->ino;
    status->st_size = (off64_t)values->length;
    patina_split_nanos(values->atime_nanos, &status->st_atim.tv_sec, &status->st_atim.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_mtim.tv_sec, &status->st_mtim.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_ctim.tv_sec, &status->st_ctim.tv_nsec);
    return 0;
}

int stat64(const char *path, struct stat64 *status) {
    struct patina_stat_values values;
    int result = patina_stat_metadata(path, 1, &values);
    return fill_stat64(result, &values, status);
}

int lstat64(const char *path, struct stat64 *status) {
    struct patina_stat_values values;
    int result = patina_stat_metadata(path, 0, &values);
    return fill_stat64(result, &values, status);
}

int fstat64(int fd, struct stat64 *status) {
    struct patina_stat_values values;
    int result = patina_fd_metadata_values(fd, &values);
    if (result < 0) errno = patina_errno();
    return fill_stat64(result, &values, status);
}

int fstatat64(int directory, const char *restrict path, struct stat64 *restrict status, int flags) {
    if (directory != AT_FDCWD) {
        errno = ENOSYS;
        return -1;
    }
    if ((flags & ~AT_SYMLINK_NOFOLLOW) != 0) {
        errno = ENOSYS;
        return -1;
    }
    struct patina_stat_values values;
    int follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    int result = patina_stat_metadata(path, follow, &values);
    return fill_stat64(result, &values, status);
}

int statx(int directory, const char *restrict path, int flags, unsigned int mask,
          struct statx *restrict status) {
    (void)mask;
    if (directory != AT_FDCWD) {
        errno = ENOSYS;
        return -1;
    }
    struct patina_stat_values values;
    int follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    int result = patina_stat_metadata(path, follow, &values);
    if (result < 0) return -1;
    memset(status, 0, sizeof *status);
    status->stx_mask = STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_INO | STATX_SIZE |
                       STATX_ATIME | STATX_MTIME | STATX_CTIME;
    status->stx_mode = (uint16_t)patina_mode_for_kind(values.kind);
    status->stx_nlink = values.nlink;
    status->stx_ino = values.ino;
    status->stx_size = values.length;
    status->stx_atime.tv_sec = (int64_t)(values.atime_nanos / UINT64_C(1000000000));
    status->stx_atime.tv_nsec = (uint32_t)(values.atime_nanos % UINT64_C(1000000000));
    status->stx_mtime.tv_sec = (int64_t)(values.mtime_nanos / UINT64_C(1000000000));
    status->stx_mtime.tv_nsec = (uint32_t)(values.mtime_nanos % UINT64_C(1000000000));
    status->stx_ctime = status->stx_mtime;
    return 0;
}
#endif

int mkdir(const char *path, mode_t mode) {
    (void)mode;
    return fail_int(patina_mkdir(path));
}

int unlink(const char *path) {
    return fail_int(patina_unlink(path));
}

int rmdir(const char *path) {
    return fail_int(patina_rmdir(path));
}

int rename(const char *from, const char *to) {
    return fail_int(patina_rename(from, to));
}

/*
 * Managed threads and pthread synchronization. These interposers route the
 * guest's pthread usage (including Rust std::thread, Mutex, and Condvar)
 * through Patina's deterministic scheduler. pthread objects are identified by
 * their storage address; the created pthread_t is the real host handle so the
 * uninterposed pthread_self, pthread_equal, and *_np helpers remain consistent.
 *
 * pthread returns error numbers directly rather than through errno.
 */
/*
 * The interposer that owns thread creation. On macOS it is the ordinary strong
 * `pthread_create`; the shim reaches the real host vehicle through a distinct
 * symbol (pthread_create_suspended_np). glibc has no such variant, so on Linux
 * the interposer is `__wrap_pthread_create` and the real vehicle is
 * `__real_pthread_create`, both provided by `-Wl,--wrap=pthread_create`.
 */
#ifdef __linux__
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine)(void *), void *arg) {
    return patina_thread_create((void **)thread, (const void *)attr, start_routine, arg);
}
#else
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    return patina_thread_create((void **)thread, (const void *)attr, start_routine, arg);
}
#endif

int pthread_join(pthread_t thread, void **retval) {
    return patina_thread_join((void *)thread, retval);
}

int pthread_detach(pthread_t thread) {
    return patina_thread_detach((void *)thread);
}

void pthread_exit(void *retval) {
    patina_thread_exit(retval);
    __builtin_unreachable();
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    return patina_mutex_init((void *)mutex, (const void *)attr);
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
    return patina_mutex_lock((void *)mutex);
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
    return patina_mutex_trylock((void *)mutex);
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    return patina_mutex_unlock((void *)mutex);
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) {
    return patina_mutex_destroy((void *)mutex);
}

int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
    return patina_cond_init((void *)cond, (const void *)attr);
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    return patina_cond_wait((void *)cond, (void *)mutex);
}

int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                           const struct timespec *abstime) {
    return patina_cond_timedwait((void *)cond, (void *)mutex, (const void *)abstime);
}

#ifdef __APPLE__
/* Rust std lowers `Condvar::wait_timeout` on Darwin to this relative-deadline
 * variant. Convert the relative wait to an absolute deadline against the
 * interposed virtual CLOCK_REALTIME (the file-local clock_gettime above) and
 * take the ordinary timed-wait path, so timeouts stay on the virtual-clock
 * timer queue. */
int pthread_cond_timedwait_relative_np(pthread_cond_t *cond, pthread_mutex_t *mutex,
                                       const struct timespec *reltime) {
    if (reltime == NULL || reltime->tv_sec < 0 || reltime->tv_nsec < 0 ||
        reltime->tv_nsec >= 1000000000L) {
        return EINVAL;
    }
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) return errno;
    uint64_t now_nanos =
        (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    uint64_t rel_nanos =
        (uint64_t)reltime->tv_sec * UINT64_C(1000000000) + (uint64_t)reltime->tv_nsec;
    if (rel_nanos > UINT64_MAX - now_nanos) return EINVAL;
    uint64_t deadline = now_nanos + rel_nanos;
    struct timespec abstime = {
        .tv_sec = (time_t)(deadline / UINT64_C(1000000000)),
        .tv_nsec = (long)(deadline % UINT64_C(1000000000)),
    };
    return patina_cond_timedwait((void *)cond, (void *)mutex, (const void *)&abstime);
}
#endif

int pthread_cond_signal(pthread_cond_t *cond) {
    return patina_cond_signal((void *)cond);
}

int pthread_cond_broadcast(pthread_cond_t *cond) {
    return patina_cond_broadcast((void *)cond);
}

int pthread_cond_destroy(pthread_cond_t *cond) {
    return patina_cond_destroy((void *)cond);
}

/*
 * pthread synchronization Patina does not yet model deterministically is denied
 * (fail-closed) rather than allowed to fall through to the host, where it would
 * block a real thread outside the scheduler. Rust std::sync::RwLock uses a
 * futex on recent toolchains and never reaches these symbols; a C guest using
 * them gets a clear ENOSYS. (pthread_barrier_* and pthread_spin_* do not exist
 * on Darwin and are left to a future Linux-specific layer.)
 */
int pthread_cancel(pthread_t thread) {
    (void)thread;
    return ENOSYS;
}

int pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attr) {
    (void)lock;
    (void)attr;
    return ENOSYS;
}

int pthread_rwlock_destroy(pthread_rwlock_t *lock) {
    (void)lock;
    return ENOSYS;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *lock) {
    (void)lock;
    return ENOSYS;
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *lock) {
    (void)lock;
    return ENOSYS;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *lock) {
    (void)lock;
    return ENOSYS;
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *lock) {
    (void)lock;
    return ENOSYS;
}

int pthread_rwlock_unlock(pthread_rwlock_t *lock) {
    (void)lock;
    return ENOSYS;
}

/*
 * Virtual AF_INET/SOCK_DGRAM datagram sockets over SimNet. Only IPv4 datagrams
 * are supported; TCP (SOCK_STREAM), IPv6, and name resolution are denied
 * fail-closed. Sockets are fully virtual: no host network symbol is called.
 */
static int patina_parse_sockaddr(const struct sockaddr *addr, socklen_t len,
                                 uint32_t *ip, uint16_t *port) {
    if (addr == NULL || addr->sa_family != AF_INET ||
        len < (socklen_t)sizeof(struct sockaddr_in)) {
        return -1;
    }
    const struct sockaddr_in *in = (const struct sockaddr_in *)(const void *)addr;
    *ip = ntohl(in->sin_addr.s_addr);
    *port = ntohs(in->sin_port);
    return 0;
}

static void patina_fill_sockaddr(struct sockaddr *addr, socklen_t *len,
                                 uint32_t ip, uint16_t port) {
    if (addr == NULL || len == NULL) return;
    struct sockaddr_in in;
    memset(&in, 0, sizeof in);
    in.sin_family = AF_INET;
    in.sin_addr.s_addr = htonl(ip);
    in.sin_port = htons(port);
    socklen_t copy = *len < (socklen_t)sizeof in ? *len : (socklen_t)sizeof in;
    memcpy(addr, &in, copy);
    *len = (socklen_t)sizeof in;
}

int socket(int domain, int type, int protocol) {
    if (domain != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    int nonblocking = 0;
    int base = type;
#ifdef SOCK_NONBLOCK
    if (base & SOCK_NONBLOCK) {
        nonblocking = 1;
        base &= ~SOCK_NONBLOCK;
    }
#endif
#ifdef SOCK_CLOEXEC
    base &= ~SOCK_CLOEXEC;
#endif
    int stream = 0;
    if (base == SOCK_DGRAM) {
        if (protocol != 0 && protocol != IPPROTO_UDP) {
            errno = EPROTONOSUPPORT;
            return -1;
        }
        stream = 0;
    } else if (base == SOCK_STREAM) {
        if (protocol != 0 && protocol != IPPROTO_TCP) {
            errno = EPROTONOSUPPORT;
            return -1;
        }
        stream = 1;
    } else {
        errno = EPROTOTYPE;
        return -1;
    }
    int fd = patina_net_socket(stream, nonblocking);
    if (fd < 0) errno = patina_errno();
    return fd;
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    uint32_t ip;
    uint16_t port;
    if (patina_parse_sockaddr(addr, len, &ip, &port) != 0) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    return fail_int(patina_net_bind(fd, ip, port));
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    uint32_t ip;
    uint16_t port;
    if (patina_parse_sockaddr(addr, len, &ip, &port) != 0) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    if (fd >= PATINA_SOCKET_FD_BASE) {
        int kind = patina_net_kind(fd);
        if (kind == 3) {
            errno = EISCONN;
            return -1;
        }
        if (kind == 1) return fail_int(patina_net_tcp_connect(fd, ip, port));
        if (kind == 0) return fail_int(patina_net_connect(fd, ip, port));
        if (kind == 2) {
            errno = EOPNOTSUPP;
            return -1;
        }
        errno = EBADF;
        return -1;
    }
    return fail_int(patina_net_connect(fd, ip, port));
}

static int patina_stream_flags_supported(int flags) {
#ifdef MSG_NOSIGNAL
    flags &= ~MSG_NOSIGNAL;
#endif
    return flags == 0;
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *addr, socklen_t alen) {
    int kind = fd >= PATINA_SOCKET_FD_BASE ? patina_net_kind(fd) : -1;
    if (kind == 3) {
        if (addr != NULL) {
            errno = EISCONN;
            return -1;
        }
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_net_stream_send(fd, buf, len));
    }
    if (addr != NULL) {
        uint32_t ip;
        uint16_t port;
        if (patina_parse_sockaddr(addr, alen, &ip, &port) != 0) {
            errno = EAFNOSUPPORT;
            return -1;
        }
        return fail_size(patina_net_sendto(fd, buf, len, ip, port));
    }
    return fail_size(patina_net_send(fd, buf, len));
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    int kind = fd >= PATINA_SOCKET_FD_BASE ? patina_net_kind(fd) : -1;
    if (kind == 3) {
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_net_stream_send(fd, buf, len));
    }
    return fail_size(patina_net_send(fd, buf, len));
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *addr, socklen_t *alen) {
    int kind = fd >= PATINA_SOCKET_FD_BASE ? patina_net_kind(fd) : -1;
    if (kind == 3) {
        if (addr != NULL) {
            errno = EISCONN;
            return -1;
        }
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_net_stream_recv(fd, buf, len));
    }
    uint32_t ip = 0;
    uint16_t port = 0;
    ssize_t result = fail_size(patina_net_recvfrom(fd, buf, len, &ip, &port));
    if (result >= 0) patina_fill_sockaddr(addr, alen, ip, port);
    return result;
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    int kind = fd >= PATINA_SOCKET_FD_BASE ? patina_net_kind(fd) : -1;
    if (kind == 3) {
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_net_stream_recv(fd, buf, len));
    }
    return fail_size(patina_net_recv(fd, buf, len));
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
    uint32_t ip;
    uint16_t port;
    if (patina_net_getsockname(fd, &ip, &port) != 0) {
        errno = patina_errno();
        return -1;
    }
    patina_fill_sockaddr(addr, len, ip, port);
    return 0;
}

static int patina_zero_timeval(const void *value, socklen_t len) {
    if (value == NULL || len < (socklen_t)sizeof(struct timeval)) return 0;
    const struct timeval *time = (const struct timeval *)value;
    return time->tv_sec == 0 && time->tv_usec == 0;
}

static int patina_linger_off(const void *value, socklen_t len) {
    if (value == NULL || len < (socklen_t)sizeof(struct linger)) return 0;
    const struct linger *linger = (const struct linger *)value;
    return linger->l_onoff == 0;
}

/* Virtual sockets allow only deterministic no-op option writes. */
int setsockopt(int fd, int level, int optname, const void *value, socklen_t len) {
    if (fd < PATINA_SOCKET_FD_BASE) {
        errno = ENOTSOCK;
        return -1;
    }
    if (level == SOL_SOCKET) {
        switch (optname) {
            case SO_REUSEADDR:
#ifdef SO_REUSEPORT
            case SO_REUSEPORT:
#endif
#ifdef SO_NOSIGPIPE
            case SO_NOSIGPIPE:
#endif
            case SO_KEEPALIVE:
            case SO_BROADCAST:
                return 0;
            case SO_LINGER:
                if (patina_linger_off(value, len)) return 0;
                break;
            case SO_RCVTIMEO:
            case SO_SNDTIMEO:
                if (patina_zero_timeval(value, len)) return 0;
                break;
            default:
                break;
        }
    }
    if (level == IPPROTO_TCP && optname == TCP_NODELAY) return 0;
    errno = ENOPROTOOPT;
    return -1;
}

int getsockopt(int fd, int level, int optname, void *value, socklen_t *len) {
    (void)level;
    (void)optname;
    if (fd < PATINA_SOCKET_FD_BASE) {
        errno = ENOTSOCK;
        return -1;
    }
    if (value != NULL && len != NULL) memset(value, 0, *len);
    return 0;
}

int ioctl(int fd, unsigned long request, ...) {
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);
#ifdef FIONBIO
    if (request == (unsigned long)FIONBIO && fd >= PATINA_SOCKET_FD_BASE) {
        int on = arg != NULL ? *(int *)arg : 0;
        return patina_net_set_nonblocking(fd, on ? 1 : 0);
    }
#endif
#ifdef FIOCLEX
    if (request == (unsigned long)FIOCLEX) return 0;
#endif
#ifdef FIONCLEX
    if (request == (unsigned long)FIONCLEX) return 0;
#endif
    (void)fd;
    errno = ENOTTY;
    return -1;
}

int listen(int fd, int backlog) {
    if (fd < PATINA_SOCKET_FD_BASE) {
        errno = ENOTSOCK;
        return -1;
    }
    return fail_int(patina_net_listen(fd, backlog));
}

int accept(int fd, struct sockaddr *addr, socklen_t *len) {
    if (fd < PATINA_SOCKET_FD_BASE) {
        errno = ENOTSOCK;
        return -1;
    }
    uint32_t ip = 0;
    uint16_t port = 0;
    int accepted = patina_net_accept(fd, &ip, &port);
    if (accepted < 0) {
        errno = patina_errno();
        return -1;
    }
    patina_fill_sockaddr(addr, len, ip, port);
    return accepted;
}

#ifdef __linux__
int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
    int allowed = SOCK_CLOEXEC;
#ifdef SOCK_NONBLOCK
    allowed |= SOCK_NONBLOCK;
#endif
    if ((flags & ~allowed) != 0) {
        errno = EINVAL;
        return -1;
    }
    int accepted = accept(fd, addr, len);
    if (accepted < 0) return -1;
#ifdef SOCK_NONBLOCK
    if ((flags & SOCK_NONBLOCK) != 0) {
        if (patina_net_set_nonblocking(accepted, 1) != 0) {
            errno = patina_errno();
            return -1;
        }
    }
#endif
    return accepted;
}
#endif

int shutdown(int fd, int how) {
    if (fd < PATINA_SOCKET_FD_BASE) {
        errno = ENOTSOCK;
        return -1;
    }
    int patina_how;
    if (how == SHUT_RD) patina_how = 0;
    else if (how == SHUT_WR) patina_how = 1;
    else if (how == SHUT_RDWR) patina_how = 2;
    else {
        errno = EINVAL;
        return -1;
    }
    return fail_int(patina_net_shutdown(fd, patina_how));
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
    uint32_t ip;
    uint16_t port;
    if (patina_net_getpeername(fd, &ip, &port) != 0) {
        errno = patina_errno();
        return -1;
    }
    patina_fill_sockaddr(addr, len, ip, port);
    return 0;
}

/* IPv6 and DNS are out of scope: fail closed with clear errors. */

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    (void)node;
    (void)service;
    (void)hints;
    (void)res;
    return EAI_FAIL;
}

void freeaddrinfo(struct addrinfo *res) {
    (void)res;
}

/*
 * Deterministic process-state values. Process spawning and signals (fork,
 * exec-family, posix_spawn-family, kill, waitpid) are deliberately NOT provided
 * here so they remain unmanaged imports that `cargo patina native-audit`
 * rejects.
 */
uid_t getuid(void) { return (uid_t)1000; }
uid_t geteuid(void) { return (uid_t)1000; }
gid_t getgid(void) { return (gid_t)1000; }
gid_t getegid(void) { return (gid_t)1000; }

long sysconf(int name) {
#ifdef _SC_PAGESIZE
    if (name == _SC_PAGESIZE) return 4096;
#endif
#ifdef _SC_PAGE_SIZE
    if (name == _SC_PAGE_SIZE) return 4096;
#endif
#ifdef _SC_NPROCESSORS_ONLN
    if (name == _SC_NPROCESSORS_ONLN) return 1;
#endif
#ifdef _SC_NPROCESSORS_CONF
    if (name == _SC_NPROCESSORS_CONF) return 1;
#endif
#ifdef _SC_CLK_TCK
    if (name == _SC_CLK_TCK) return 100;
#endif
#ifdef _SC_OPEN_MAX
    if (name == _SC_OPEN_MAX) return 1024;
#endif
#ifdef _SC_NGROUPS_MAX
    if (name == _SC_NGROUPS_MAX) return 16;
#endif
    errno = EINVAL;
    return -1;
}

/*
 * Packaged startup. An ordinary program built with `cargo patina native-build`
 * must not need Patina-specific init calls: the boundary sits BELOW application
 * code. This constructor installs the deterministic runtime from the PATINA_*
 * protocol (idempotent) and registers finalization through atexit, so record
 * mode is finalized on any normal exit path (main return or exit()) without an
 * explicit patina_shutdown. A standalone run (no PATINA_MODE) is left
 * uninstalled; the first effect boundary then fails closed with a clear message
 * (see ensure_runtime in the Rust layer). The public interposed getenv returns
 * NULL for every name; startup reads the PATINA_* control plane through the
 * private snapshot accessor before scrubbing environ for guest code.
 */
static void patina_finalize_atexit(void) {
    patina_shutdown();
}

__attribute__((constructor)) static void patina_native_start(void) {
    atexit(patina_finalize_atexit);
    patina_capture_control_plane();
    if (patina_control_getenv("PATINA_MODE") != NULL) {
        patina_init_from_env();
    }
    patina_scrub_environ();
}
