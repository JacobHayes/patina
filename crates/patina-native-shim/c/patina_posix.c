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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#ifdef __linux__
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <linux/audit.h>
#include <linux/futex.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <ucontext.h>
#endif
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <crt_externs.h>
#include <mach/mach_time.h>
#include <mach-o/dyld.h>
#include <os/lock.h>
#include <stddef.h>
#include <sys/event.h>

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

/*
 * clock_gettime_nsec_np returns the clock value directly in nanoseconds (a
 * Darwin extension rustix's time module reaches for). Route it through the same
 * virtual clock as clock_gettime with the same clock-id mapping. The real API
 * returns 0 on an unrecognized clock id and sets errno EINVAL, so mirror that
 * failure return rather than inventing a sentinel.
 */
uint64_t clock_gettime_nsec_np(clockid_t clock_id) {
    uint32_t patina_clock;
    if (clock_id == CLOCK_REALTIME) patina_clock = PATINA_CLOCK_REALTIME;
    else if (clock_id == CLOCK_MONOTONIC || clock_id == CLOCK_MONOTONIC_RAW ||
             clock_id == CLOCK_UPTIME_RAW)
        patina_clock = PATINA_CLOCK_MONOTONIC;
    else {
        errno = EINVAL;
        return 0;
    }
    uint64_t nanos = 0;
    if (patina_clock_now(patina_clock, &nanos) != 0) {
        errno = patina_errno();
        return 0;
    }
    return nanos;
}

/*
 * os_unfair_lock (parking_lot_core's Darwin word lock). A bare u32 with no init
 * call, so the deterministic mutex table lazily registers it on first use. The
 * real primitive is non-recursive and traps on a recursive lock by the owner or
 * an unlock by a non-owner; the routed implementation aborts loudly on the same
 * misuse rather than succeeding silently. trylock yields 1 on acquisition and 0
 * when the lock is already held (by anyone), matching the real single-cmpxchg.
 */
void os_unfair_lock_lock(os_unfair_lock_t lock) {
    patina_os_unfair_lock_lock((void *)lock);
}

bool os_unfair_lock_trylock(os_unfair_lock_t lock) {
    return patina_os_unfair_lock_trylock((void *)lock) != 0;
}

void os_unfair_lock_unlock(os_unfair_lock_t lock) {
    patina_os_unfair_lock_unlock((void *)lock);
}

/*
 * libdispatch semaphores. Rust std's Darwin thread Parker blocks on a
 * libdispatch semaphore, so std::thread::park / park_timeout and everything
 * layered on them (mpsc/mpmc recv and recv_timeout, blocking channel and Once
 * paths) reach dispatch_semaphore_wait. Interpose the whole surface and route
 * it through the deterministic scheduler + virtual clock; without this the
 * Parker blocks a real host thread and reads host time outside the runtime.
 *
 * These are strong definitions, so std's references bind here at link time and
 * the real libdispatch symbols drop off the import table entirely. The shim's
 * own execution baton deliberately uses a distinct Mach semaphore, so it never
 * recurses into these interposers.
 */
uint64_t dispatch_time(uint64_t when, int64_t delta) {
    return patina_dispatch_time(when, delta);
}

void *dispatch_semaphore_create(intptr_t value) {
    return patina_dispatch_semaphore_create(value);
}

intptr_t dispatch_semaphore_wait(void *sem, uint64_t timeout) {
    return patina_dispatch_semaphore_wait(sem, timeout);
}

intptr_t dispatch_semaphore_signal(void *sem) {
    return patina_dispatch_semaphore_signal(sem);
}

void dispatch_release(void *object) {
    patina_dispatch_release(object);
}

/*
 * confstr reads host configuration strings (temp/cache directory, default PATH),
 * which are host-specific and nondeterministic. std::env::temp_dir queries
 * _CS_DARWIN_USER_TEMP_DIR; return a fixed deterministic path routed through the
 * deterministic filesystem, and report "no value" for everything else so callers
 * fall back to their own deterministic defaults.
 */
size_t confstr(int name, char *buf, size_t len) {
    const char *value = NULL;
    if (name == _CS_DARWIN_USER_TEMP_DIR) value = "/tmp/";
    if (value == NULL) {
        if (buf != NULL && len > 0) buf[0] = '\0';
        return 0;
    }
    size_t needed = strlen(value) + 1;
    if (buf != NULL && len > 0) {
        size_t copy = needed < len ? needed : len;
        memcpy(buf, value, copy);
        buf[copy - 1] = '\0';
    }
    return needed;
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

/*
 * isatty: whether a descriptor is a terminal is a nondeterministic property of
 * how the run was launched (pipe vs file vs tty), and programs branch on it —
 * search tools, for instance, derive heading/color/line-number defaults from it. A
 * fully interposed guest must never observe host terminal state, so report a
 * deterministic "not a terminal" for every descriptor: captured guest stdio is
 * never a tty under the runtime. Interposing here (rather than allow-listing the
 * import) makes guest output provably independent of host tty state instead of
 * merely "neutral given the flags". This is a strong definition, so the guest's
 * isatty reference binds here and the libc symbol drops off the import table.
 */
int isatty(int fd) {
    (void)fd;
    errno = ENOTTY;
    return 0;
}

/*
 * pthread_atfork: registers handlers to run around fork(). The whole fork/exec
 * process surface is a deterministic-runtime non-goal (denied by the audit, and
 * a managed guest never forks), so a registered handler could never actually
 * run. Rust std / libc startup nonetheless *reference* this symbol (e.g. thread
 * and once machinery pull it in), and left as a host import it taints the run's
 * determinism claim even though it is a pure no-op here. Interpose it with a
 * strong definition that ignores the registration and returns success: the guest
 * reference binds here and the libc symbol drops off the import table, so the
 * pre-run gate has nothing to flag. Ignoring the handlers is sound precisely
 * because the process-class surface that would invoke them is never reached.
 */
int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void)) {
    (void)prepare;
    (void)parent;
    (void)child;
    return 0;
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

/*
 * sched_yield / std::thread::yield_now. std's mpsc/mpmc backoff spins through
 * yield_now before it parks, so route the yield to a deterministic scheduling
 * point rather than yielding the host scheduler outside the runtime.
 */
int sched_yield(void) {
    return patina_sched_yield();
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
    if (number == SYS_getrandom) {
        /* The `getrandom` crate (rand::thread_rng and similar runtime-seeded
         * randomness) issues the raw SYS_getrandom syscall
         * through this wrapper rather than the libc getrandom() above. Route it to
         * the same deterministic entropy source; otherwise it returns ENOSYS and
         * the crate falls back to opening /dev/urandom, which the in-memory FS
         * lacks (ENOENT) — panicking every rng-using guest thread. GRND_* flags
         * are irrelevant: deterministic entropy never blocks and has one source. */
        va_list ap;
        va_start(ap, number);
        void *buffer = va_arg(ap, void *);
        size_t buffer_len = va_arg(ap, size_t);
        va_end(ap);
        if (patina_entropy(buffer, buffer_len) != 0) {
            errno = patina_errno();
            return -1;
        }
        return (long)buffer_len;
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
 *
 * The interposer is `__wrap_dlsym`: `cargo patina native-build` links
 * `-Wl,--wrap=dlsym`, so every guest/std reference to `dlsym` binds here while
 * the shim's own host-alias table reaches the real glibc resolver through the
 * distinct `__real_dlsym` (see the shim's Linux `hostapi` module). That table is
 * in turn how the shim reaches every real host vehicle — including the genuine
 * `pthread_create` behind the strong-def thread interposer above — so `dlsym`
 * stays neutered for guest code without denying the shim its one sanctioned
 * resolution primitive. `dlsym` is the only symbol wrapped at link time;
 * `pthread_create` deliberately is not (that would clash with libgcc's own
 * `__wrap_pthread_create` on x86).
 */
void *__wrap_dlsym(void *handle, const char *symbol) {
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

/*
 * The deterministic filesystem is path-based with no directory descriptors, so
 * the *at family is supported only for AT_FDCWD (a plain relative/absolute path)
 * and fails closed on a real dirfd, exactly like fstatat below. The variadic
 * mode is dropped just as `open` drops it. rustix's libc backend lowers its `fs`
 * calls onto these on both platforms, so they are strong defs in the common
 * section rather than Apple-only.
 */
int openat(int dirfd, const char *path, int flags, ...) {
    if (dirfd != AT_FDCWD) {
        errno = ENOSYS;
        return -1;
    }
    return patina_posix_open(path, flags);
}

int fcntl(int fd, int command, ...) {
#ifdef __APPLE__
    /* Virtual kqueue descriptors. F_DUPFD/F_DUPFD_CLOEXEC clone into a second fd
     * sharing the SAME registry (tokio's IO driver clones its selector through
     * F_DUPFD_CLOEXEC); the requested minimum is honored implicitly because the
     * deterministic fd counter always allocates above it. cloexec and the
     * blocking flag are no-ops on a kqueue. */
    if (fd >= PATINA_SOCKET_FD_BASE && patina_kqueue_is_kq(fd)) {
        if (command == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
            || command == F_DUPFD_CLOEXEC
#endif
        )
            return fail_int(patina_kqueue_dup(fd));
        if (command == F_GETFD) return FD_CLOEXEC;
        if (command == F_SETFD) return 0;
        if (command == F_SETFL) return 0;
        if (command == F_GETFL) return 0;
        errno = EINVAL;
        return -1;
    }
#endif
#ifdef __linux__
    /* Virtual epoll descriptors: the Linux mirror of the kqueue branch above.
     * F_DUPFD/F_DUPFD_CLOEXEC clone into a second fd sharing the SAME registry
     * (mio clones its selector this way); the requested minimum is honored
     * implicitly because the deterministic fd counter always allocates above
     * it. cloexec and the blocking flag are no-ops on an epoll fd. */
    if (fd >= PATINA_SOCKET_FD_BASE && patina_epoll_is_epoll(fd)) {
        if (command == F_DUPFD || command == F_DUPFD_CLOEXEC)
            return fail_int(patina_epoll_dup(fd));
        if (command == F_GETFD) return FD_CLOEXEC;
        if (command == F_SETFD) return 0;
        if (command == F_SETFL) return 0;
        if (command == F_GETFL) return 0;
        errno = EINVAL;
        return -1;
    }
#endif
    /* Virtual pipe/socketpair endpoints: same blocking-flag surface as sockets,
     * routed to the pipe table (cloexec is a no-op). F_DUPFD/F_DUPFD_CLOEXEC
     * alias the endpoint's channel side(s) refcounted (std's try_clone — tokio's
     * signal driver clones a socketpair end this way); as with kqueue fds the
     * requested minimum is honored implicitly because the deterministic fd
     * counter always allocates above it. */
    if (fd >= PATINA_SOCKET_FD_BASE && patina_pipe_is_endpoint(fd)) {
        if (command == F_GETFL) {
            int nonblocking = patina_pipe_is_nonblocking(fd);
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
            return patina_pipe_set_nonblocking(fd, (flags & O_NONBLOCK) ? 1 : 0);
        }
        if (command == F_GETFD) return FD_CLOEXEC;
        if (command == F_SETFD) return 0;
        if (command == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
            || command == F_DUPFD_CLOEXEC
#endif
        )
            return fail_int(patina_pipe_dup(fd));
        errno = EINVAL;
        return -1;
    }
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

/* glibc's LFS alias of openat (rustix's libc backend lowers its fs calls onto
 * the *64 names on 64-bit Linux). Same AT_FDCWD-only contract as openat. */
int openat64(int dirfd, const char *path, int flags, ...) {
    if (dirfd != AT_FDCWD) {
        errno = ENOSYS;
        return -1;
    }
    return patina_posix_open(path, flags);
}
#endif

ssize_t read(int fd, void *destination, size_t length) {
    if (fd >= PATINA_SOCKET_FD_BASE) {
        int kind = patina_net_kind(fd);
        if (kind == 3) return fail_size(patina_net_stream_recv(fd, destination, length));
        if (kind == 0) return fail_size(patina_net_recv(fd, destination, length));
        if (patina_pipe_is_endpoint(fd)) return fail_size(patina_pipe_read(fd, destination, length));
#ifdef __linux__
        if (patina_eventfd_is(fd)) return fail_size(patina_eventfd_read(fd, destination, length));
#endif
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
        if (patina_pipe_is_endpoint(fd)) return fail_size(patina_pipe_write(fd, source, length));
#ifdef __linux__
        if (patina_eventfd_is(fd)) return fail_size(patina_eventfd_write(fd, source, length));
#endif
        errno = kind < 0 ? EBADF : ENOTCONN;
        return -1;
    }
    return fail_size(patina_write(fd, source, length));
}

/* Positional I/O. Database-style file backends do ALL of their I/O through
 * pread/pwrite (read_exact_at/write_all_at), never seek+read/write, so these
 * must reach the deterministic filesystem or that I/O would bypass the crash
 * model entirely. They route to patina_p{read,write}, which the runtime
 * services as ONE positional operation (atomic w.r.t. the scheduler and cursor-
 * independent), NOT a caller-side seek+read that could interleave under
 * concurrency. Virtual sockets have no offset addressing, so a positional call
 * on a socket fd is ESPIPE, matching the kernel. */
ssize_t pread(int fd, void *destination, size_t length, off_t offset) {
    if (fd >= PATINA_SOCKET_FD_BASE) { errno = ESPIPE; return -1; }
    return fail_size(patina_pread(fd, destination, length, (int64_t)offset));
}

ssize_t pwrite(int fd, const void *source, size_t length, off_t offset) {
    if (fd == 1 || fd == 2 || fd >= PATINA_SOCKET_FD_BASE) { errno = ESPIPE; return -1; }
    return fail_size(patina_pwrite(fd, source, length, (int64_t)offset));
}

#ifdef __linux__
/* Large-file positional I/O variants. glibc std lowers positional reads/writes
 * on 64-bit off_t Linux to the *64 symbols (database file backends use them), so
 * they must reach the same deterministic positional I/O as pread/pwrite rather
 * than be denied. off64_t is always 64-bit, so the full offset is preserved. */
ssize_t pread64(int fd, void *destination, size_t length, off64_t offset) {
    if (fd >= PATINA_SOCKET_FD_BASE) { errno = ESPIPE; return -1; }
    return fail_size(patina_pread(fd, destination, length, (int64_t)offset));
}
ssize_t pwrite64(int fd, const void *source, size_t length, off64_t offset) {
    if (fd == 1 || fd == 2 || fd >= PATINA_SOCKET_FD_BASE) { errno = ESPIPE; return -1; }
    return fail_size(patina_pwrite(fd, source, length, (int64_t)offset));
}
#endif

/* Whole-file advisory lock (a single-opener database takes one via File::try_lock on open).
 * Routed to the runtime's per-inode lock table (patina_flock): a lone opener
 * always acquires, but two independent opens of the same file contend exactly
 * as a real flock would (LOCK_EX|LOCK_NB on the second → EWOULDBLOCK, i.e.
 * a database's already-open error). See the "Advisory file lock" row in
 * crates/patina-target/ESCAPE-CLASSES.md. Virtual sockets have no advisory-lock
 * model, so a flock on one fails closed. */
int flock(int fd, int operation) {
    if (fd >= PATINA_SOCKET_FD_BASE)
        return patina_posix_deny("patina: advisory locks on virtual sockets are not modeled; failing closed\n");
    return patina_flock(fd, operation);
}

int close(int fd) {
    if (fd >= PATINA_SOCKET_FD_BASE) {
#ifdef __APPLE__
        if (patina_kqueue_is_kq(fd)) return fail_int(patina_kqueue_close(fd));
#endif
#ifdef __linux__
        if (patina_epoll_is_epoll(fd)) return fail_int(patina_epoll_close(fd));
        if (patina_eventfd_is(fd)) return fail_int(patina_eventfd_close(fd));
#endif
        if (patina_pipe_is_endpoint(fd)) return fail_int(patina_pipe_close(fd));
        return fail_int(patina_net_close(fd));
    }
    return fail_int(patina_close(fd));
}

int dup(int fd) {
    if (fd >= 0 && fd <= 2)
        return patina_posix_deny("patina: duplicating a captured stdio descriptor is not modeled; failing closed\n");
    if (fd >= PATINA_SOCKET_FD_BASE) {
#ifdef __APPLE__
        /* A kqueue fd duplicates into a second fd sharing the SAME registry
         * (tokio's IO driver clones its selector this way). */
        if (patina_kqueue_is_kq(fd)) return fail_int(patina_kqueue_dup(fd));
#endif
#ifdef __linux__
        /* Same registry-aliasing dup for an epoll fd (mio's selector clone). */
        if (patina_epoll_is_epoll(fd)) return fail_int(patina_epoll_dup(fd));
        if (patina_eventfd_is(fd))
            return patina_posix_deny("patina: duplicating a virtual eventfd descriptor is not modeled; failing closed\n");
#endif
        /* A pipe/socketpair endpoint duplicates into a refcounted alias of the
         * same channel side(s); virtual sockets still fail closed. */
        if (patina_pipe_is_endpoint(fd)) return fail_int(patina_pipe_dup(fd));
        return patina_posix_deny("patina: duplicating a virtual socket descriptor is not modeled; failing closed\n");
    }
    return fail_int(patina_dup(fd));
}

int dup2(int oldfd, int newfd) {
    if (oldfd == newfd) {
        /* POSIX: equal descriptors validate oldfd and return newfd unchanged. */
        if (oldfd >= 0 && oldfd <= 2) return newfd;
        if (oldfd >= PATINA_SOCKET_FD_BASE) {
            if (patina_net_is_nonblocking(oldfd) < 0 && patina_pipe_is_endpoint(oldfd) == 0) {
                errno = EBADF;
                return -1;
            }
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

#ifdef __linux__
/* fdatasync: databases call it to make committed data durable. The deterministic
 * crash-model FS makes the file durable through the same sync path (it draws no
 * data-vs-metadata distinction), so route it to patina_fsync — a durability
 * guarantee at least as strong as fdatasync's, and deterministic. */
int fdatasync(int fd) {
    return fail_int(patina_fsync(fd));
}
#endif

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
 * *at removal/rename over the path-based deterministic filesystem: only AT_FDCWD
 * (a plain path) is modeled, any real dirfd fails closed. unlinkat routes to the
 * rmdir path when AT_REMOVEDIR is set, otherwise unlink; unknown flags fail
 * closed. renameat requires both dirfds be AT_FDCWD.
 */
int unlinkat(int dirfd, const char *path, int flags) {
    if (dirfd != AT_FDCWD) {
        errno = ENOSYS;
        return -1;
    }
    if ((flags & ~AT_REMOVEDIR) != 0) {
        errno = ENOSYS;
        return -1;
    }
    if (flags & AT_REMOVEDIR) return fail_int(patina_rmdir(path));
    return fail_int(patina_unlink(path));
}

int renameat(int olddirfd, const char *old_path, int newdirfd, const char *new_path) {
    if (olddirfd != AT_FDCWD || newdirfd != AT_FDCWD) {
        errno = ENOSYS;
        return -1;
    }
    return fail_int(patina_rename(old_path, new_path));
}

#ifdef __linux__
/*
 * glibc exports renameat2 (the flags-carrying rename). Only the plain
 * flags==0 case maps onto the deterministic rename; RENAME_EXCHANGE/NOREPLACE
 * are not modeled and fail closed.
 */
int renameat2(int olddirfd, const char *old_path, int newdirfd, const char *new_path,
              unsigned int flags) {
    if (olddirfd != AT_FDCWD || newdirfd != AT_FDCWD || flags != 0) {
        errno = ENOSYS;
        return -1;
    }
    return fail_int(patina_rename(old_path, new_path));
}
#endif

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
 * The strong interposer that owns thread creation on both platforms: every
 * guest/std `pthread_create` binds here and is routed through Patina's
 * deterministic scheduler. The shim reaches the *real* host creator through a
 * distinct, non-interposed vehicle so it never recurses into this definition —
 * on macOS `pthread_create_suspended_np` plus a mach `thread_resume`, on Linux
 * the genuine glibc `pthread_create` resolved through `dlsym(RTLD_NEXT, ...)`,
 * the same host-alias primitive that reaches the real `read`/`write`/`sem_*`.
 * See the shim's `spawn_host_thread`. (glibc ships `__wrap_pthread_create` in
 * libgcc's split-stack support on x86, so the shim must NOT use `--wrap` here.)
 */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    return patina_thread_create((void **)thread, (const void *)attr, start_routine, arg);
}

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

/*
 * `exit(3)` interposer. When the guest's `main` returns, the C runtime calls
 * `exit(status)`; a guest's own `exit`/`std::process::exit` routes here too. This
 * is the sole point that runs on the exiting thread AFTER its managed body but
 * BEFORE the C runtime drives the guest's thread-local destructors — whose
 * `--yield-points` yield hooks would otherwise record trailing, host-teardown-
 * ordering-dependent scheduling points that diverge record from replay (see
 * patina_exit and the shim's thread::sched_point). The teardown flag MUST be set
 * here, not via atexit: glibc runs __call_tls_dtors() BEFORE the atexit list, so
 * the packaged atexit finalizer is too late to precede the destructors.
 * `_exit`/`_Exit` bypass the destructors entirely and are deliberately not
 * interposed. patina_exit sets the flag and terminates through the real libc
 * `exit` (resolved via the shim host-alias table), so the atexit chain (trace
 * finalization in record mode) and the destructors still run, now with the flag
 * set. This interposer lives in the POSIX layer, so a consumer that links only
 * the C-ABI staticlib (no POSIX layer, no --wrap=dlsym) keeps libc's own `exit`
 * and never reaches the host-alias table at teardown.
 */
_Noreturn void exit(int status) {
    patina_exit(status);
}

#ifdef __linux__
/* ==========================================================================
 * Syscall-user-dispatch (SUD).
 *
 * Arms the kernel's syscall-user-dispatch so a guest's raw inline `syscall`
 * instruction (rustix's default linux_raw backend, hand-written asm, ...) —
 * invisible to the import audit and refused by the instruction scan — is trapped
 * into the deterministic runtime instead of escaping it. Design: SUD-DESIGN.md.
 *
 * Mode: allowed region = glibc's single executable segment, NULL selector, so
 * every syscall instruction OUTSIDE glibc text unconditionally delivers a
 * thread-directed SIGSYS (there is no guest-writable selector byte to protect).
 * The shim itself reaches the kernel only through glibc host aliases (audit
 * proven: shim/guest text contains zero syscall opcodes), so glibc text is the
 * exact allowed region. Two arming sites, zero selector sites, zero disarm
 * sites: the main thread here in `__libc_start_main`, every managed thread in
 * the Rust `thread_trampoline`. The config does not survive clone/fork/exec, so
 * each thread arms once.
 *
 * All host vehicles the SUD paths touch (prctl, sigaction, the /proc/self/maps
 * reader's open/read/close) are resolved through `__real_dlsym(RTLD_NEXT, ...)`
 * — the `-Wl,--wrap=dlsym` alias — so those names never appear as undefined
 * externals in the shim objects (host-alias doctrine) and so `open`/`read`
 * reach the REAL glibc descriptors rather than this shim's interposed
 * (deterministic-FS) strong defs.
 * ========================================================================== */

extern void *__real_dlsym(void *handle, const char *symbol);

/* prctl SUD op numbers (6.8 UAPI headers may predate the constants). */
#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
#ifndef PR_SYS_DISPATCH_OFF
#define PR_SYS_DISPATCH_OFF 0
#endif
#ifndef PR_SYS_DISPATCH_ON
#define PR_SYS_DISPATCH_ON 1
#endif
/* si_code for a syscall-user-dispatch SIGSYS. */
#ifndef SYS_USER_DISPATCH
#define SYS_USER_DISPATCH 2
#endif

typedef int (*patina_prctl_fn)(int, unsigned long, unsigned long, unsigned long,
                               void *);
typedef int (*patina_host_open_fn)(const char *, int, ...);
typedef ssize_t (*patina_host_read_fn)(int, void *, size_t);
typedef int (*patina_host_close_fn)(int);
typedef int (*patina_host_sigaction_fn)(int, const struct sigaction *,
                                        struct sigaction *);

static patina_prctl_fn patina_host_prctl;
static patina_host_open_fn patina_host_open;
static patina_host_read_fn patina_host_read_real;
static patina_host_close_fn patina_host_close_real;
static patina_host_sigaction_fn patina_host_sigaction;

/* The glibc allowed region (its one executable segment) and the main
 * executable's text span. Discovered once from /proc/self/maps at arming. */
static unsigned long patina_sud_libc_off;
static unsigned long patina_sud_libc_len;
static uintptr_t patina_sud_text_lo;
static uintptr_t patina_sud_text_hi;
static int patina_sud_armed; /* set once the main thread arms; gates thread arming */

/* Rust side of the boundary (see src/sud.rs / lib.rs). */
extern long patina_sud_dispatch(long nr, unsigned long a0, unsigned long a1,
                                unsigned long a2, unsigned long a3,
                                unsigned long a4, unsigned long a5,
                                uintptr_t call_addr);
_Noreturn void patina_sud_report_fatal(const char *message);
_Noreturn void patina_sud_report_fatal_addr(const char *message, long nr,
                                            uintptr_t addr);

/* Lazily resolve the REAL glibc sigaction through the wrap alias, so the shim's
 * own SIGSYS-hardening `sigaction` strong def below can forward to it without
 * naming `sigaction` as an undefined external. Shared by the SIGSYS installer
 * and the interposer. */
static patina_host_sigaction_fn patina_real_sigaction(void) {
    if (patina_host_sigaction == NULL) {
        patina_host_sigaction =
            (patina_host_sigaction_fn)__real_dlsym(RTLD_NEXT, "sigaction");
    }
    return patina_host_sigaction;
}

static int patina_env_has(const char *name, char **argv, int argc) {
    char **envp = argv + argc + 1;
    size_t nlen = strlen(name);
    for (char **e = envp; *e != NULL; e++) {
        if (strncmp(*e, name, nlen) == 0 && (*e)[nlen] == '=') return 1;
    }
    return 0;
}

static uintptr_t patina_parse_hex(const char **cursor) {
    uintptr_t value = 0;
    const char *s = *cursor;
    for (;;) {
        char c = *s;
        uintptr_t digit;
        if (c >= '0' && c <= '9') digit = (uintptr_t)(c - '0');
        else if (c >= 'a' && c <= 'f') digit = (uintptr_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') digit = (uintptr_t)(c - 'A' + 10);
        else break;
        value = (value << 4) | digit;
        s++;
    }
    *cursor = s;
    return value;
}

/* Slurp /proc/self/maps through the REAL glibc open/read/close (never the
 * interposed deterministic-FS strong defs). Fails closed (never a partial parse
 * on a guessed region) if the file is larger than the buffer. */
static int patina_sud_read_maps(char *buffer, size_t capacity, size_t *out_len) {
    int fd = patina_host_open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return -1;
    size_t total = 0;
    for (;;) {
        if (total >= capacity) {
            patina_host_close_real(fd);
            return -1;
        }
        ssize_t n = patina_host_read_real(fd, buffer + total, capacity - total);
        if (n < 0) {
            patina_host_close_real(fd);
            return -1;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    patina_host_close_real(fd);
    *out_len = total;
    return 0;
}

/* Discover (a) glibc's single executable segment (the allowed region) and (b)
 * the main executable's text span (which must contain the guest's syscall
 * sites). The text span is identified as the executable segment that contains
 * this handler's own code address — guest + shim + std share the one main-exe
 * r-xp mapping, so no path/readlink is needed. Returns 0 on success; -1 (fail
 * closed) unless exactly one executable libc segment and a text span are found.
 */
static void patina_sud_sigsys(int sig, siginfo_t *info, void *ucontext);

static int patina_sud_discover_regions(void) {
    /* 1 MiB comfortably covers /proc/self/maps for a statically-shim-linked
     * program; a larger map fails closed rather than parse a truncated view. */
    size_t capacity = 1u << 20;
    char *buffer = (char *)malloc(capacity);
    if (buffer == NULL) return -1;
    size_t length = 0;
    if (patina_sud_read_maps(buffer, capacity, &length) != 0) {
        free(buffer);
        return -1;
    }
    uintptr_t marker = (uintptr_t)(void *)&patina_sud_sigsys;
    int libc_exec_segments = 0;
    int text_found = 0;
    size_t index = 0;
    while (index < length) {
        char *line = buffer + index;
        /* NUL-terminate this line so string ops stay within it. */
        char *newline = memchr(line, '\n', length - index);
        size_t line_len = newline ? (size_t)(newline - line) : (length - index);
        line[line_len] = '\0';
        index += line_len + 1;

        const char *cursor = line;
        uintptr_t start = patina_parse_hex(&cursor);
        if (*cursor != '-') continue;
        cursor++;
        uintptr_t end = patina_parse_hex(&cursor);
        if (*cursor != ' ') continue;
        cursor++;
        /* perms are exactly 4 chars: e.g. "r-xp". */
        if (cursor[0] == '\0' || cursor[1] == '\0' || cursor[2] == '\0') continue;
        int executable = cursor[2] == 'x';
        if (!executable) continue;

        /* Main-executable text: the executable segment containing our own code. */
        if (marker >= start && marker < end) {
            patina_sud_text_lo = start;
            patina_sud_text_hi = end;
            text_found = 1;
        }

        /* libc: match the mapped pathname's basename. */
        const char *path = strchr(line, '/');
        if (path != NULL) {
            const char *slash = strrchr(path, '/');
            const char *base = slash ? slash + 1 : path;
            if (strncmp(base, "libc.so.6", 9) == 0 ||
                strncmp(base, "libc-", 5) == 0) {
                libc_exec_segments++;
                patina_sud_libc_off = (unsigned long)start;
                patina_sud_libc_len = (unsigned long)(end - start);
            }
        }
    }
    free(buffer);
    if (libc_exec_segments != 1 || !text_found) return -1;
    return 0;
}

/* Close the vDSO escape (SUD-DESIGN.md §6): rewrite the initial-stack auxv
 * entry AT_SYSINFO_EHDR to AT_IGNORE. glibc's getauxval walks this same array
 * (only AT_HWCAP is cached), so rustix's `getauxval(AT_SYSINFO_EHDR)` then
 * returns 0, its vDSO pointer is null, and it falls back to raw `clock_gettime`
 * — which SUD traps. glibc consumed the auxv before this scrub (host aliases
 * keep working). */
static void patina_sud_scrub_auxv(int argc, char **argv) {
    char **envp = argv + argc + 1;
    char **walk = envp;
    while (*walk != NULL) walk++;
    walk++; /* step over envp's NULL terminator to the auxv array */
    ElfW(auxv_t) *aux = (ElfW(auxv_t) *)walk;
    for (; aux->a_type != AT_NULL; aux++) {
        if (aux->a_type == AT_SYSINFO_EHDR) aux->a_type = AT_IGNORE;
    }
}

/* The SIGSYS dispatch handler. A syscall-user-dispatch SIGSYS is SYNCHRONOUS —
 * delivered on the faulting thread at the exact IP of the guest's own syscall
 * instruction (the kernel already rolled it back), semantically identical to the
 * guest having called an interposed effect. So re-entering the deterministic
 * runtime (which the Rust dispatch does) is sound; see SUD-DESIGN.md §4.2. This
 * handler decodes the number and six argument registers per arch, validates the
 * provenance, and hands off to the arch-agnostic Rust dispatcher, then writes the
 * raw return value back into the syscall's return register. */
static void patina_sud_sigsys(int sig, siginfo_t *info, void *ucontext) {
    (void)sig;
    long nr = info->si_syscall;
    uintptr_t call_addr = (uintptr_t)info->si_call_addr;
    /* Provenance: only a genuine syscall-user-dispatch SIGSYS is ours. A seccomp
     * or `kill -SYS` SIGSYS is a determinism escape and aborts loudly. */
    if (info->si_code != SYS_USER_DISPATCH) {
        patina_sud_report_fatal_addr(
            "SUD: SIGSYS with unexpected si_code (not syscall-user-dispatch)", nr,
            call_addr);
    }
#if defined(__x86_64__)
    if (info->si_arch != AUDIT_ARCH_X86_64) {
        patina_sud_report_fatal_addr("SUD: SIGSYS with unexpected si_arch", nr,
                                     call_addr);
    }
#elif defined(__aarch64__)
    if (info->si_arch != AUDIT_ARCH_AARCH64) {
        patina_sud_report_fatal_addr("SUD: SIGSYS with unexpected si_arch", nr,
                                     call_addr);
    }
#endif
    /* The faulting IP must lie in the main executable's text. Anything else — a
     * syscall from ld.so or another DSO — is unmodeled and aborts by name (§2.3),
     * rather than being emulated as if it were guest code. */
    if (call_addr < patina_sud_text_lo || call_addr >= patina_sud_text_hi) {
        patina_sud_report_fatal_addr(
            "SUD: trapped a syscall outside the main executable text (ld.so / DSO / "
            "vDSO); this path is not modeled",
            nr, call_addr);
    }

    ucontext_t *uc = (ucontext_t *)ucontext;
    int saved_errno = errno;
    unsigned long a0, a1, a2, a3, a4, a5;
#if defined(__x86_64__)
    greg_t *r = uc->uc_mcontext.gregs;
    a0 = (unsigned long)r[REG_RDI];
    a1 = (unsigned long)r[REG_RSI];
    a2 = (unsigned long)r[REG_RDX];
    a3 = (unsigned long)r[REG_R10];
    a4 = (unsigned long)r[REG_R8];
    a5 = (unsigned long)r[REG_R9];
#elif defined(__aarch64__)
    a0 = (unsigned long)uc->uc_mcontext.regs[0];
    a1 = (unsigned long)uc->uc_mcontext.regs[1];
    a2 = (unsigned long)uc->uc_mcontext.regs[2];
    a3 = (unsigned long)uc->uc_mcontext.regs[3];
    a4 = (unsigned long)uc->uc_mcontext.regs[4];
    a5 = (unsigned long)uc->uc_mcontext.regs[5];
#else
#error "SUD SIGSYS handler: unsupported architecture"
#endif
    long ret = patina_sud_dispatch(nr, a0, a1, a2, a3, a4, a5, call_addr);
#if defined(__x86_64__)
    uc->uc_mcontext.gregs[REG_RAX] = (greg_t)ret;
#elif defined(__aarch64__)
    uc->uc_mcontext.regs[0] = (unsigned long long)ret;
#endif
    /* Raw-syscall callers read the return register, not errno, but outer guest
     * frames may have a live errno the dispatch path clobbered — restore it. */
    errno = saved_errno;
}

/* Arm SUD on the calling thread from the cached region. Called on the main
 * thread at startup and on every managed thread from the Rust trampoline (the
 * config does not survive clone, so each thread arms once). A no-op when SUD was
 * not armed for this run (non-SUD kernel or standalone binary). */
void patina_sud_arm_thread(void) {
    if (!patina_sud_armed) return;
    if (patina_host_prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON,
                          patina_sud_libc_off, patina_sud_libc_len, NULL) != 0) {
        patina_sud_report_fatal(
            "SUD: failed to arm syscall-user-dispatch on a managed thread");
    }
}

/* Main-thread SUD setup, called from the `__libc_start_main` interposer BEFORE
 * guest constructors run. Arms only a managed run on a SUD-capable kernel; every
 * other case is a deliberate no-op (a binary that actually needs SUD was already
 * refused by the pre-run gate, and one that does not runs fine unarmed). */
static void patina_sud_init(int argc, char **argv) {
    /* A standalone run (no PATINA_MODE) is left unarmed: its first interposed
     * boundary already fails closed via ensure_runtime, and an unarmed raw
     * syscall there is no worse than today. environ is still intact here (the
     * ctor's scrub runs later), so read it directly. */
    if (!patina_env_has("PATINA_MODE", argv, argc)) return;

    patina_host_prctl = (patina_prctl_fn)__real_dlsym(RTLD_NEXT, "prctl");
    patina_host_open = (patina_host_open_fn)__real_dlsym(RTLD_NEXT, "open");
    patina_host_read_real = (patina_host_read_fn)__real_dlsym(RTLD_NEXT, "read");
    patina_host_close_real = (patina_host_close_fn)__real_dlsym(RTLD_NEXT, "close");
    (void)patina_real_sigaction();
    if (patina_host_prctl == NULL || patina_host_open == NULL ||
        patina_host_read_real == NULL || patina_host_close_real == NULL ||
        patina_host_sigaction == NULL) {
        /* Defensive: these are core glibc symbols. Leave unarmed rather than arm
         * with a missing vehicle. */
        return;
    }

    /* Kernel support probe: PR_SYS_DISPATCH_OFF with all-zero args returns 0 on a
     * SUD kernel and -EINVAL where the feature is absent (arm64 <= 6.18, pre-5.11
     * x86). Same process, same kernel as the guest. */
    if (patina_host_prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0,
                          NULL) != 0) {
        return; /* no kernel SUD: do not arm (pre-run gate handles refusal) */
    }

    if (patina_sud_discover_regions() != 0) {
        patina_sud_report_fatal(
            "SUD: could not determine glibc's single executable segment and the "
            "main-executable text from /proc/self/maps; refusing to arm on a "
            "guessed region");
    }

    patina_sud_scrub_auxv(argc, argv);

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = patina_sud_sigsys;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (patina_host_sigaction(SIGSYS, &action, NULL) != 0) {
        patina_sud_report_fatal("SUD: failed to install the SIGSYS dispatch handler");
    }

    patina_sud_armed = 1;
    patina_sud_arm_thread(); /* arm the main thread */
}

/*
 * SIGSYS-registration hardening (SUD-DESIGN.md §7.5, slice 1). Under SUD the
 * SIGSYS handler IS the deterministic containment; a guest `sigaction(SIGSYS,…)`
 * would replace it. Interpose `sigaction`/`signal` with strong defs that forward
 * every other signal to the real glibc registration (preserving std's
 * SIGSEGV/SIGBUS stack-overflow guard exactly) and fail closed for SIGSYS. The
 * raw door (a trapped `rt_sigaction(SIGSYS)`) is closed by the dispatch table.
 * The shim's own handler install above uses the resolved real sigaction, never
 * this interposer, so it is not self-blocked.
 */
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    if (signum == SIGSYS) {
        patina_posix_deny(
            "patina: sigaction(SIGSYS) refused: a guest may not register the "
            "syscall-dispatch signal (it would disable deterministic containment)\n");
        errno = EPERM;
        return -1;
    }
    return patina_real_sigaction()(signum, act, oldact);
}

void (*signal(int signum, void (*handler)(int)))(int) {
    if (signum == SIGSYS) {
        patina_posix_deny(
            "patina: signal(SIGSYS) refused: a guest may not register the "
            "syscall-dispatch signal (it would disable deterministic containment)\n");
        errno = EPERM;
        return SIG_ERR;
    }
    /* Emulate signal() over the real sigaction to avoid a second host-alias:
     * install the handler with the classic (restarting) semantics and return the
     * previous handler. */
    struct sigaction action;
    struct sigaction previous;
    memset(&action, 0, sizeof action);
    action.sa_handler = handler;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    if (patina_real_sigaction()(signum, &action, &previous) != 0) {
        return SIG_ERR;
    }
    return previous.sa_handler;
}

#endif /* __linux__ SUD */

#ifdef __linux__
/*
 * `__libc_start_main` interposer (Linux only). The `exit` interposer above
 * catches only EXPLICIT `exit(3)` calls from guest/executable code: on the
 * natural `main`-return path glibc's `__libc_start_main` calls `exit()` through a
 * hidden internal alias (bound at libc build time, not via the PLT), so ELF
 * interposition never sees it and the root task's post-`main` --yield-points
 * teardown yields would still be recorded nondeterministically. crt1.o in the
 * EXECUTABLE references `__libc_start_main`, and the executable's own strong
 * definition wins at static link (no --wrap), so this runs BEFORE glibc gets
 * control — immune to the internal binding. We stash the guest's real `main` and
 * hand glibc a wrapper that runs it and then sets the teardown flag BEFORE
 * returning the code into glibc's exit path (which then runs the thread-local
 * destructors, now silenced in the shim's sched_point). The real
 * `__libc_start_main` is resolved locally via `__real_dlsym(RTLD_NEXT, ...)`:
 * this runs before patina_native_start's constructor, so the shim host-alias
 * table is not yet built and must not be used; `__real_dlsym` is the
 * `-Wl,--wrap=dlsym` alias (guest/std `dlsym` binds to the neutering
 * `__wrap_dlsym`, so plain `dlsym` cannot reach the real resolver). Darwin uses a
 * different C runtime entry and is untouched (the `exit` interposer above already
 * covers its explicit-exit path; Darwin teardown is already deterministic).
 */
typedef int (*patina_main_fn)(int, char **, char **);
typedef int (*patina_libc_start_main_fn)(patina_main_fn, int, char **, void *,
                                         void *, void *, void *);

extern void *__real_dlsym(void *handle, const char *symbol);

static patina_main_fn patina_real_main;

static int patina_main_wrapper(int argc, char **argv, char **envp) {
    int code = patina_real_main(argc, argv, envp);
    /*
     * The guest's `main` has returned. Mark teardown NOW — before the code
     * re-enters glibc's `exit()`, which drives `__call_tls_dtors` — so the root
     * task's instrumented thread-local destructors take no scheduling point.
     */
    patina_note_main_returned();
    return code;
}

int __libc_start_main(patina_main_fn main_fn, int argc, char **argv, void *init,
                      void *fini, void *rtld_fini, void *stack_end) {
    patina_real_main = main_fn;
    /* Arm syscall-user-dispatch (managed run on a SUD kernel) BEFORE the real
     * __libc_start_main runs the guest constructors: parse the libc region,
     * scrub AT_SYSINFO_EHDR from the auxv, install the SIGSYS handler, and arm
     * the main thread. environ is still intact here (the ctor scrub runs later),
     * so PATINA_MODE is readable. A no-op on a non-SUD kernel or standalone run. */
    patina_sud_init(argc, argv);
    patina_libc_start_main_fn real =
        (patina_libc_start_main_fn)__real_dlsym(RTLD_NEXT, "__libc_start_main");
    if (real == NULL) {
        /*
         * Defensive and effectively unreachable: glibc always exports
         * __libc_start_main, and this file is only ever linked with
         * -Wl,--wrap=dlsym, so __real_dlsym is the genuine resolver. Fail closed
         * LOUDLY (SIGABRT) rather than run the guest unwrapped — which would
         * silently reintroduce the nondeterministic teardown yields this
         * interposer exists to remove. `abort()` is the real libc abort (the shim
         * does not interpose it), so it works before the runtime is installed and
         * without touching the interposed `syscall`/`write` layer.
         */
        abort();
    }
    return real(patina_main_wrapper, argc, argv, init, fini, rtld_fini, stack_end);
}
#endif

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
 * pthread synchronization Patina does not model deterministically is denied
 * (fail-closed) rather than allowed to fall through to the host, where it would
 * block a real thread outside the scheduler. (pthread_barrier_* and
 * pthread_spin_* do not exist on Darwin and are left to a future Linux layer.)
 */
int pthread_cancel(pthread_t thread) {
    (void)thread;
    return ENOSYS;
}

/*
 * pthread_rwlock_* routes reader/writer contention through the deterministic
 * scheduler (writer-preferring; FIFO among writers; blocked readers batch-woken
 * when a writer releases with no writer waiting). Rust std::sync::RwLock uses
 * the queue-based parking RwLock on the supported toolchains and does not reach
 * these symbols, so this is for C guests (and any std that lowers to pthread).
 * rwlockattr is ignored: the deterministic rwlock has one policy.
 */
int pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attr) {
    return patina_rwlock_init((void *)lock, (const void *)attr);
}

int pthread_rwlock_destroy(pthread_rwlock_t *lock) {
    return patina_rwlock_destroy((void *)lock);
}

int pthread_rwlock_rdlock(pthread_rwlock_t *lock) {
    return patina_rwlock_rdlock((void *)lock);
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *lock) {
    return patina_rwlock_tryrdlock((void *)lock);
}

int pthread_rwlock_wrlock(pthread_rwlock_t *lock) {
    return patina_rwlock_wrlock((void *)lock);
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *lock) {
    return patina_rwlock_trywrlock((void *)lock);
}

int pthread_rwlock_unlock(pthread_rwlock_t *lock) {
    return patina_rwlock_unlock((void *)lock);
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

/* A socketpair endpoint is a connected AF_UNIX stream, so the message-based
 * socket I/O (send/recv/sendto/recvfrom) is the same in-process byte channel as
 * write/read — tokio's UnixStream reaches the fd through send/recv, not
 * write/read. An addressed sendto/recvfrom on a connected pair is EISCONN. */
ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *addr, socklen_t alen) {
    if (fd >= PATINA_SOCKET_FD_BASE && patina_pipe_is_endpoint(fd)) {
        if (addr != NULL) {
            errno = EISCONN;
            return -1;
        }
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_pipe_write(fd, buf, len));
    }
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
    if (fd >= PATINA_SOCKET_FD_BASE && patina_pipe_is_endpoint(fd)) {
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_pipe_write(fd, buf, len));
    }
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
    if (fd >= PATINA_SOCKET_FD_BASE && patina_pipe_is_endpoint(fd)) {
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        (void)addr;
        (void)alen;
        return fail_size(patina_pipe_read(fd, buf, len));
    }
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
    if (fd >= PATINA_SOCKET_FD_BASE && patina_pipe_is_endpoint(fd)) {
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_pipe_read(fd, buf, len));
    }
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
                /* Deterministic receive timeout: store the timeval (in virtual
                 * nanoseconds) on the socket so a blocking recv is bounded by the
                 * virtual clock. A zero timeval is POSIX "no timeout" and clears
                 * it. */
                if (value != NULL && len >= (socklen_t)sizeof(struct timeval)) {
                    const struct timeval *rcv = (const struct timeval *)value;
                    uint64_t nanos = (uint64_t)rcv->tv_sec * 1000000000ull +
                                     (uint64_t)rcv->tv_usec * 1000ull;
                    if (patina_net_set_read_timeout(fd, nanos) != 0) {
                        errno = patina_errno();
                        return -1;
                    }
                    return 0;
                }
                break;
            case SO_SNDTIMEO:
                /* Send timeouts are moot: virtual datagram/stream sends never
                 * block, so only the no-op zero timeval is accepted. */
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
 * In-process pipe / socketpair (class g, in-process slice). Both endpoints stay
 * inside this one guest process — the common case is an async runtime's own
 * IO-driver / signal self-pipe wakeup — so there is NO cross-address-space
 * escape: they are modeled as deterministic in-memory byte channels wired to the
 * scheduler's wakeup path (see the "in-process pipe / socketpair" section in the
 * Rust shim). Descriptors come from the shared virtual-fd space above, so the
 * interposed read/write/close/fcntl route them to the pipe class via
 * patina_pipe_is_endpoint. eventfd (Linux) is likewise in-process — a single
 * 64-bit counter inside this guest, mio's Waker vehicle — and is interposed as
 * a deterministic counter (see the eventfd section in the Rust shim and the
 * Linux reactor block below). The truly cross-process class-g members
 * (shm_open, the mach_msg / mach_port / mq families) stay refused.
 */
int pipe(int fildes[2]) {
    if (fildes == NULL) {
        errno = EFAULT;
        return -1;
    }
    return fail_int(patina_pipe(&fildes[0], &fildes[1], 0));
}

int socketpair(int domain, int type, int protocol, int sv[2]) {
    if (sv == NULL) {
        errno = EFAULT;
        return -1;
    }
    /* AF_LOCAL is the same constant as AF_UNIX; only a Unix-domain STREAM pair is
     * a deterministic in-process duplex. Anything else fails closed. */
    if (domain != AF_UNIX) {
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
    base &= ~SOCK_CLOEXEC; /* no exec under the runtime: accept and ignore */
#endif
    if (base != SOCK_STREAM) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (protocol != 0) {
        errno = EPROTONOSUPPORT;
        return -1;
    }
    {
        int rc = patina_socketpair(&sv[0], &sv[1], nonblocking);
        return fail_int(rc);
    }
}

#ifdef __APPLE__
/*
 * kqueue / kevent / kevent64 (macOS readiness reactor). The Rust reactor owns
 * the knote registry, readiness, deterministic ordering, and the multi-fd
 * fan-in park (see the "kqueue / kevent readiness reactor" section in the Rust
 * shim); these interposers only marshal the platform struct kevent/kevent64_s
 * changelists and eventlists to and from the platform-neutral patina_kevent and
 * decode the timeout into the reactor's blocking mode. Being strong defs, the
 * guest's kqueue/kevent/kevent64 bind here and the libc symbols drop off the
 * import table, so the pre-run wait-multiplex gate clears with no allowance.
 *
 * `struct patina_kevent` is laid out to match `struct kevent` field for field,
 * so a kevent eventlist is marshalled by a direct reinterpret. kevent64_s carries
 * an `ext[2]` tail struct kevent lacks, so its eventlist is widened field by field.
 */
_Static_assert(sizeof(struct patina_kevent) == sizeof(struct kevent),
               "patina_kevent must match struct kevent size");
_Static_assert(offsetof(struct patina_kevent, ident) == offsetof(struct kevent, ident),
               "patina_kevent.ident offset");
_Static_assert(offsetof(struct patina_kevent, filter) == offsetof(struct kevent, filter),
               "patina_kevent.filter offset");
_Static_assert(offsetof(struct patina_kevent, flags) == offsetof(struct kevent, flags),
               "patina_kevent.flags offset");
_Static_assert(offsetof(struct patina_kevent, fflags) == offsetof(struct kevent, fflags),
               "patina_kevent.fflags offset");
_Static_assert(offsetof(struct patina_kevent, data) == offsetof(struct kevent, data),
               "patina_kevent.data offset");
_Static_assert(offsetof(struct patina_kevent, udata) == offsetof(struct kevent, udata),
               "patina_kevent.udata offset");


int kqueue(void) {
    int fd = patina_kqueue();
    if (fd < 0) errno = patina_errno();
    return fd;
}

/*
 * Decode the kevent timeout into the reactor's (mode, nanos): NULL blocks until
 * ready, a zero timespec is a non-blocking poll, and a positive one is a
 * relative virtual-clock deadline.
 */
static int patina_kevent_mode(const struct timespec *timeout, uint64_t *nanos) {
    *nanos = 0;
    if (timeout == NULL) return 1;
    if (timeout->tv_sec == 0 && timeout->tv_nsec == 0) return 0;
    *nanos = (uint64_t)timeout->tv_sec * UINT64_C(1000000000) + (uint64_t)timeout->tv_nsec;
    return 2;
}

int kevent(int kq, const struct kevent *changelist, int nchanges, struct kevent *eventlist,
           int nevents, const struct timespec *timeout) {
    if (patina_kqueue_is_kq(kq) == 0) {
        errno = EBADF;
        return -1;
    }
    if ((nchanges > 0 && changelist == NULL) ||
        (timeout != NULL && (timeout->tv_sec < 0 || timeout->tv_nsec < 0))) {
        errno = EINVAL;
        return -1;
    }
    /* Apply the changelist. A change carrying EV_RECEIPT (mio sets it on every
     * register), or one that fails, yields an EV_ERROR receipt whose data is the
     * errno (0 on success) — the standard bulk-change protocol mio reads back. */
    int nout = 0;
    for (int index = 0; index < nchanges; ++index) {
        const struct kevent *change = &changelist[index];
        int rc = patina_kqueue_apply(kq, (uint64_t)change->ident, change->filter, change->flags,
                                     change->fflags, (int64_t)change->data,
                                     (uintptr_t)change->udata);
        if ((change->flags & EV_RECEIPT) || rc != 0) {
            if (eventlist != NULL && nout < nevents) {
                /* eventlist may alias changelist (mio reuses the buffer); copy
                 * the change's identity out before overwriting the slot. */
                uintptr_t ident = change->ident;
                int16_t filter = change->filter;
                void *udata = change->udata;
                struct kevent *event = &eventlist[nout++];
                event->ident = ident;
                event->filter = filter;
                event->flags = EV_ERROR;
                event->fflags = 0;
                event->data = rc;
                event->udata = udata;
            } else if (rc != 0) {
                errno = rc;
                return -1;
            }
        }
    }
    if (nout > 0) return nout;
    uint64_t nanos;
    int mode = patina_kevent_mode(timeout, &nanos);
    int count = patina_kevent_gather(kq, (struct patina_kevent *)eventlist,
                                     nevents < 0 ? 0 : nevents, mode, nanos);
    if (count < 0) {
        errno = patina_errno();
        return -1;
    }
    return count;
}

int kevent64(int kq, const struct kevent64_s *changelist, int nchanges,
             struct kevent64_s *eventlist, int nevents, unsigned int flags,
             const struct timespec *timeout) {
    (void)flags; /* KEVENT_FLAG_* immediacy is governed by `timeout` here. */
    if (patina_kqueue_is_kq(kq) == 0) {
        errno = EBADF;
        return -1;
    }
    if ((nchanges > 0 && changelist == NULL) ||
        (timeout != NULL && (timeout->tv_sec < 0 || timeout->tv_nsec < 0))) {
        errno = EINVAL;
        return -1;
    }
    int nout = 0;
    for (int index = 0; index < nchanges; ++index) {
        const struct kevent64_s *change = &changelist[index];
        int rc = patina_kqueue_apply(kq, change->ident, change->filter, change->flags,
                                     change->fflags, (int64_t)change->data,
                                     (uintptr_t)change->udata);
        if ((change->flags & EV_RECEIPT) || rc != 0) {
            if (eventlist != NULL && nout < nevents) {
                uint64_t ident = change->ident;
                uint64_t udata = change->udata;
                int16_t filter = change->filter;
                struct kevent64_s *event = &eventlist[nout++];
                event->ident = ident;
                event->filter = filter;
                event->flags = EV_ERROR;
                event->fflags = 0;
                event->data = rc;
                event->udata = udata;
                event->ext[0] = 0;
                event->ext[1] = 0;
            } else if (rc != 0) {
                errno = rc;
                return -1;
            }
        }
    }
    if (nout > 0) return nout;
    uint64_t nanos;
    int mode = patina_kevent_mode(timeout, &nanos);
    int capacity = nevents < 0 ? 0 : nevents;
    struct patina_kevent *scratch = NULL;
    if (capacity > 0) {
        scratch = calloc((size_t)capacity, sizeof *scratch);
        if (scratch == NULL) {
            errno = ENOMEM;
            return -1;
        }
    }
    int count = patina_kevent_gather(kq, scratch, capacity, mode, nanos);
    if (count < 0) {
        free(scratch);
        errno = patina_errno();
        return -1;
    }
    for (int index = 0; index < count; ++index) {
        struct kevent64_s *event = &eventlist[index];
        event->ident = scratch[index].ident;
        event->filter = scratch[index].filter;
        event->flags = scratch[index].flags;
        event->fflags = scratch[index].fflags;
        event->data = scratch[index].data;
        event->udata = (uint64_t)(uintptr_t)scratch[index].udata;
        event->ext[0] = 0;
        event->ext[1] = 0;
    }
    free(scratch);
    return count;
}
#endif

#ifdef __linux__
/*
 * epoll / eventfd readiness reactor (Linux) — the mirror of the kqueue block
 * above. The Rust reactor owns the interest registry, readiness, deterministic
 * ordering, and the multi-fd fan-in park (see the "epoll readiness reactor"
 * section in the Rust shim); these interposers are deliberately thin because
 * patina_epoll_create1 / patina_epoll_ctl / patina_epoll_wait / patina_eventfd
 * are already syscall-shaped for the future syscall-user-dispatch SIGSYS
 * dispatcher. Being strong defs, the guest's epoll and eventfd references bind
 * here and the libc symbols drop off the import table, so the pre-run
 * wait-multiplex / shared-memory-ipc gates clear with no allowance.
 *
 * The Rust side reads and writes `struct epoll_event` with the kernel ABI
 * layout (packed on x86_64, natural alignment elsewhere); pin the platform
 * struct against that expectation.
 */
_Static_assert(offsetof(struct epoll_event, events) == 0, "epoll_event.events offset");
#ifdef __x86_64__
_Static_assert(sizeof(struct epoll_event) == 12, "epoll_event packed size");
_Static_assert(offsetof(struct epoll_event, data) == 4, "epoll_event.data offset");
#else
_Static_assert(sizeof(struct epoll_event) == 16, "epoll_event natural size");
_Static_assert(offsetof(struct epoll_event, data) == 8, "epoll_event.data offset");
#endif

int epoll_create1(int flags) {
    return fail_int(patina_epoll_create1(flags));
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    return fail_int(patina_epoll_ctl(epfd, op, fd, event));
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    return fail_int(patina_epoll_wait(epfd, events, maxevents, timeout));
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout,
                const sigset_t *sigmask) {
    /* Patina delivers no ambient signals, so a NULL mask is the plain wait. A
     * real mask swap has no deterministic meaning; fail closed loudly. */
    if (sigmask != NULL)
        return patina_posix_deny("patina: epoll_pwait with a signal mask is not modeled; failing closed\n");
    return fail_int(patina_epoll_wait(epfd, events, maxevents, timeout));
}

int eventfd(unsigned int initval, int flags) {
    return fail_int(patina_eventfd(initval, flags));
}
#endif

/*
 * Deterministic process-state values (getuid/geteuid/... below). The process
 * class itself — spawning, exec, reaping, credential and session changes — is a
 * deterministic-runtime non-goal, handled by the deny-traps just below.
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
 * Process-class deny-traps. The fork/exec/spawn/reap/credential/session surface
 * is a deterministic-runtime non-goal: a managed guest never legitimately enters
 * it and the runtime models none of it. Real guests still LINK this
 * surface (std::process and dormant subprocess helper paths that a plain
 * run never triggers), and a reachability audit cannot clear it — the spawn
 * path is statically wired into the main loop by direct calls and only a
 * runtime flag keeps it dormant (see crates/patina-target/ESCAPE-CLASSES.md).
 *
 * So interpose the whole family with strong definitions that ABORT
 * deterministically if ever reached. Two wins over leaving them as imports: the
 * symbols drop off the import table (the pre-run gate needs no allowance), AND a
 * guest that genuinely spawns fails LOUD and reproducibly instead of escaping
 * the runtime silently. A trap fires only if CALLED, so merely linking the
 * surface is inert and a plain search is unaffected.
 */
__attribute__((noreturn)) static void patina_process_trap(const char *symbol) {
    static const char prefix[] = "patina: process spawn reached under patina: ";
    write(2, prefix, sizeof prefix - 1);
    write(2, symbol, strlen(symbol));
    static const char suffix[] =
        "; the process class is a deterministic-runtime non-goal; failing closed\n";
    write(2, suffix, sizeof suffix - 1);
    /* abort() skips the atexit shutdown flush, so push the captured guest output
     * and this diagnostic to the real descriptors before terminating. */
    patina_flush_captured_stdio();
    abort();
}

pid_t fork(void) { patina_process_trap("fork"); }
int execvp(const char *file, char *const argv[]) {
    (void)file;
    (void)argv;
    patina_process_trap("execvp");
}
pid_t waitpid(pid_t pid, int *status, int options) {
    (void)pid;
    (void)status;
    (void)options;
    patina_process_trap("waitpid");
}
pid_t setsid(void) { patina_process_trap("setsid"); }
int setgid(gid_t gid) {
    (void)gid;
    patina_process_trap("setgid");
}
int setuid(uid_t uid) {
    (void)uid;
    patina_process_trap("setuid");
}
int setpgid(pid_t pid, pid_t pgid) {
    (void)pid;
    (void)pgid;
    patina_process_trap("setpgid");
}
#ifdef __APPLE__
int setgroups(int count, const gid_t *groups) {
#else
int setgroups(size_t count, const gid_t *groups) {
#endif
    (void)count;
    (void)groups;
    patina_process_trap("setgroups");
}
int chdir(const char *path) {
    (void)path;
    patina_process_trap("chdir");
}
int chroot(const char *path) {
    (void)path;
    patina_process_trap("chroot");
}
int posix_spawnp(pid_t *restrict pid, const char *restrict file,
                 const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *restrict attrp, char *const argv[restrict],
                 char *const envp[restrict]) {
    (void)pid;
    (void)file;
    (void)file_actions;
    (void)attrp;
    (void)argv;
    (void)envp;
    patina_process_trap("posix_spawnp");
}
int posix_spawn_file_actions_init(posix_spawn_file_actions_t *acts) {
    (void)acts;
    patina_process_trap("posix_spawn_file_actions_init");
}
int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *acts, int fd, int newfd) {
    (void)acts;
    (void)fd;
    (void)newfd;
    patina_process_trap("posix_spawn_file_actions_adddup2");
}
int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *acts) {
    (void)acts;
    patina_process_trap("posix_spawn_file_actions_destroy");
}
int posix_spawnattr_init(posix_spawnattr_t *attr) {
    (void)attr;
    patina_process_trap("posix_spawnattr_init");
}
int posix_spawnattr_destroy(posix_spawnattr_t *attr) {
    (void)attr;
    patina_process_trap("posix_spawnattr_destroy");
}
int posix_spawnattr_setflags(posix_spawnattr_t *attr, short flags) {
    (void)attr;
    (void)flags;
    patina_process_trap("posix_spawnattr_setflags");
}
int posix_spawnattr_setpgroup(posix_spawnattr_t *attr, pid_t pgroup) {
    (void)attr;
    (void)pgroup;
    patina_process_trap("posix_spawnattr_setpgroup");
}
int posix_spawnattr_setsigdefault(posix_spawnattr_t *restrict attr,
                                  const sigset_t *restrict sigdefault) {
    (void)attr;
    (void)sigdefault;
    patina_process_trap("posix_spawnattr_setsigdefault");
}

#ifdef __linux__
/*
 * Linux-only spawn/IPC/effect surface that newer glibc's std pulls in and macOS
 * does not (so it only shows up in the Linux import audit). These follow the
 * fork/posix_spawnp deny-trap doctrine above: a strong def drops the symbol off
 * the guest import table (the pre-run gate needs no allowance) and fails LOUD and
 * reproducibly if the guest ever genuinely reaches it. A plain search never
 * calls them, so linking the surface is inert. The `_GNU_SOURCE` prototypes are
 * visible here, so each definition matches glibc's exact signature.
 */
pid_t pidfd_getpid(int pidfd) {
    (void)pidfd;
    patina_process_trap("pidfd_getpid");
}
int pidfd_spawnp(int *restrict pidfd, const char *restrict file,
                 const posix_spawn_file_actions_t *restrict file_actions,
                 const posix_spawnattr_t *restrict attrp, char *const argv[restrict],
                 char *const envp[restrict]) {
    (void)pidfd;
    (void)file;
    (void)file_actions;
    (void)attrp;
    (void)argv;
    (void)envp;
    patina_process_trap("pidfd_spawnp");
}
int posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t *acts,
                                         const char *path) {
    (void)acts;
    (void)path;
    patina_process_trap("posix_spawn_file_actions_addchdir_np");
}
int posix_spawn_file_actions_addchdir(posix_spawn_file_actions_t *acts, const char *path) {
    (void)acts;
    (void)path;
    patina_process_trap("posix_spawn_file_actions_addchdir");
}
int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
    (void)idtype;
    (void)id;
    (void)infop;
    (void)options;
    patina_process_trap("waitid");
}

/*
 * pipe2 is the Linux flag-taking pipe (macOS has no such symbol). Same
 * deterministic in-process channel as pipe() above, honoring O_NONBLOCK at
 * creation; O_CLOEXEC is accepted-and-ignored (no exec under the runtime),
 * O_DIRECT (packet-mode pipes) is not modeled and fails ENOSYS, and any other
 * flag fails EINVAL.
 */
int pipe2(int pipefd[2], int flags) {
    if (pipefd == NULL) {
        errno = EFAULT;
        return -1;
    }
    int nonblocking = (flags & O_NONBLOCK) ? 1 : 0;
    int remaining = flags & ~O_NONBLOCK;
#ifdef O_CLOEXEC
    remaining &= ~O_CLOEXEC;
#endif
#ifdef O_DIRECT
    if (remaining & O_DIRECT) {
        errno = ENOSYS;
        return -1;
    }
    remaining &= ~O_DIRECT;
#endif
    if (remaining != 0) {
        errno = EINVAL;
        return -1;
    }
    return fail_int(patina_pipe(&pipefd[0], &pipefd[1], nonblocking));
}

/*
 * recvmsg/sendmsg are the ancillary/scatter-gather message variants; std links
 * them but Patina's deterministic net layer models only sendto/recvfrom (routed
 * through patina_net_*). No supported guest uses the msg variants, so fail closed
 * softly with ENOSYS rather than aborting: the symbols leave the import table and
 * a caller cannot send or receive undeterministically.
 */
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
    (void)sockfd;
    (void)msg;
    (void)flags;
    errno = ENOSYS;
    return -1;
}
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    (void)sockfd;
    (void)msg;
    (void)flags;
    errno = ENOSYS;
    return -1;
}

/*
 * std::thread::available_parallelism reads the CPU affinity mask. Return a fixed
 * single-CPU set so the guest sees a deterministic core count regardless of the
 * host; the deterministic scheduler runs one baton at a time anyway, and every
 * testbed forces stable output ordering, so the value never
 * perturbs results. This is interposed (not trapped) because it IS reached at
 * startup, unlike the inert spawn surface above.
 */
int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
    (void)pid;
    if (mask == NULL || cpusetsize == 0) {
        errno = EINVAL;
        return -1;
    }
    memset(mask, 0, cpusetsize);
    /* CPU 0 present, all others absent: a deterministic one-core affinity. */
    ((unsigned char *)mask)[0] = 1;
    return 0;
}
#endif

/*
 * Host-state queries → fixed deterministic values (isatty/confstr precedent).
 * These read real host identity/paths; a fully interposed guest must see a
 * constant instead so its output cannot depend on where, or as whom, it ran.
 * Being strong definitions, the guest references bind here and the libc symbols
 * drop off the import table.
 */
int gethostname(char *name, size_t len) {
    static const char host[] = "patina";
    /* `name` is declared nonnull by glibc (comparing it to NULL is a
     * -Werror=nonnull-compare error under gcc, and passing NULL is caller UB),
     * so only the buffer length is validated here — the readdir/dirent
     * nonnull-parameter precedent above. */
    if (len == 0) {
        errno = EINVAL;
        return -1;
    }
    size_t copied = sizeof host - 1; /* length without the NUL */
    if (copied >= len) copied = len - 1;
    memcpy(name, host, copied);
    name[copied] = '\0';
    return 0;
}
int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen,
               struct passwd **result) {
    (void)uid;
    (void)pwd;
    (void)buf;
    (void)buflen;
    /* Deterministic "no such user": the guest environment is emptied, so std's
     * home-directory lookup cleanly Nones and no host user identity leaks.
     * `result` is declared nonnull by glibc (a NULL compare is a
     * -Werror=nonnull-compare error under gcc), so the contract is trusted. */
    *result = NULL;
    return 0;
}
#ifdef __linux__
/*
 * glibc's RT-signal-range probe (libc::SIGRTMAX() reads it; tokio's signal
 * machinery links it). A pure host-configuration query with no boundary
 * effect: return glibc's own upper bound (64 — NPTL reserves 32/33 below
 * SIGRTMIN, which does not move the max) as a fixed deterministic value, the
 * gethostname doctrine above. tokio does not import __libc_current_sigrtmin,
 * so only the max probe is defined.
 */
int __libc_current_sigrtmax(void) { return 64; }
#endif
#ifdef __APPLE__
/*
 * _NSGetExecutablePath hands back the host executable's real path (std's
 * current_exe() reads it). Fail so current_exe() is a deterministic Err rather
 * than leaking the host path. A future guest that needs current_exe() -> Ok
 * should get a FIXED VIRTUAL path written here, never the host's real one.
 * (One leading underscore in source: the asm symbol is `__NSGetExecutablePath`,
 * matching the guest import — two underscores here would define the wrong name.)
 */
int _NSGetExecutablePath(char *buf, uint32_t *bufsize) {
    (void)buf;
    (void)bufsize;
    return -1;
}
#endif

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
#ifdef __linux__
    /*
     * Interposer-engagement canary. This atexit hook runs AFTER the thread-local
     * destructors on every exit-chain path that reaches it, so on Linux the
     * teardown flag MUST already be set (natural return via the __libc_start_main
     * wrapper, explicit exit via the `exit` interposer). If it is not, the
     * teardown interposer did not engage on this platform/toolchain and the root
     * task's --yield-points teardown yields were not silenced: fail LOUDLY here
     * (before finalizing the trace) rather than let the miss surface later as an
     * op-count divergence. `_exit`/`_Exit`/`abort` skip atexit, so a genuinely
     * abrupt exit never reaches this check.
     */
    patina_assert_teardown_engaged();
#endif
    patina_shutdown();
}

__attribute__((constructor)) static void patina_native_start(void) {
    atexit(patina_finalize_atexit);
    patina_capture_control_plane();
    /* Deferred harness init (PATINA_DEFER_INIT=1, set by `cargo patina run
     * --harness`): still capture the control plane, still register finalization,
     * still scrub the environment — but leave the runtime UNINSTALLED so
     * patina-dst-harness can apply its configuration overlay and install
     * explicitly. An interposed effect before that install fails closed in the
     * Rust ensure_runtime (never auto-inits under defer). */
    const char *defer = patina_control_getenv("PATINA_DEFER_INIT");
    int deferred = defer != NULL && strcmp(defer, "1") == 0;
    if (patina_control_getenv("PATINA_MODE") != NULL && !deferred) {
        patina_init_from_env();
    }
    patina_scrub_environ();
}
