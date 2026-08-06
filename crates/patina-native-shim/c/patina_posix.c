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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
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
 * issetugid(): "was this process started setuid/setgid?" Interposed to a fixed
 * deterministic 0 (never running as a set-id binary under Patina), so guest code
 * that gates on it (allocators reading environment/config — tikv-jemallocator's
 * malloc-conf lookup calls it) behaves identically regardless of the host's real
 * id state. A pure boolean of fixed process identity, no boundary effect; being
 * a strong def it also drops off the guest import table.
 */
int issetugid(void) {
    return 0;
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
    patina_note_boundary_symbol("clock_gettime");
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
    patina_note_boundary_symbol("gettimeofday");
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
 * environment is scrubbed. Public getenv/secure_getenv read only Patina's
 * deterministic guest map after startup (NULL before startup and when unset);
 * shim-internal startup reads use patina_control_getenv. */
static char **patina_control_plane = NULL;
/* Capture runs exactly once. After the deterministic array is published,
 * patina_environ_base() no longer sees the ambient host entries, so a second
 * capture would snapshot the guest's own PATINA_-prefixed values instead. */
static int patina_control_plane_captured = 0;
/* The AMBIENT host array, remembered at capture time. Everything after startup
 * must scrub through this rather than through patina_environ_base(): publishing
 * repoints the environ global at the deterministic array, and `main`'s third
 * `envp` parameter keeps pointing at the original. */
static char **patina_host_environ = NULL;

static char **patina_environ_base(void) {
#ifdef __APPLE__
    return *_NSGetEnviron();
#else
    return environ;
#endif
}

static void patina_capture_control_plane(void) {
    if (patina_control_plane_captured) return;
    patina_control_plane_captured = 1;
    char **base = patina_environ_base();
    patina_host_environ = base;
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

/* Empty the AMBIENT host array in place, so nothing holding a pointer to it can
 * still read the host environment — notably `main`'s third `envp` parameter,
 * which keeps pointing at the original array after publishing repoints environ.
 * This must go through patina_host_environ, NOT patina_environ_base(): by the
 * time this runs, a supervised startup has already installed the runtime and
 * published the deterministic array, so environ_base() would return that one and
 * this would wipe the guest's own environment while leaving the host's intact.
 * The entry strings stay alive; the control-plane snapshot borrows them. */
static void patina_scrub_environ(void) {
    if (patina_host_environ == NULL) return;
    patina_host_environ[0] = NULL;
}

/* Publish a deterministic environ array built by the Rust layer from the guest
 * env map. Direct environ readers — the Linux `environ` global, Darwin
 * `_NSGetEnviron`, std::env::vars — then see exactly what the getenv interposer
 * answers, before and after any guest setenv/unsetenv. Storage is owned (and
 * deliberately leaked) by the Rust side; this only repoints the global, which is
 * what a libc setenv does when it grows the array. */
static void patina_environ_install(char **next) {
#ifdef __APPLE__
    *_NSGetEnviron() = next;
#else
    environ = next;
#endif
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
    patina_note_boundary_symbol("getenv");
    return patina_getenv(name);
}

/* Guest-driven mutation is deterministic, so it is modeled rather than refused:
 * these update the runtime's guest env map and republish environ, keeping the
 * getenv interposer and direct environ walkers in agreement. Host libc is never
 * reached, so the scrubbed ambient environment stays scrubbed. */
int setenv(const char *name, const char *value, int overwrite) {
    patina_note_boundary_symbol("setenv");
    return fail_int(patina_setenv(name, value, overwrite));
}

int unsetenv(const char *name) {
    patina_note_boundary_symbol("unsetenv");
    return fail_int(patina_unsetenv(name));
}

#ifndef __APPLE__
/* glibc/musl only; Darwin libc has no clearenv. Interposed for the same reason
 * as unsetenv: left alone it would empty the published array behind the map's
 * back, so getenv and environ would disagree for the rest of the run. */
int clearenv(void) {
    patina_note_boundary_symbol("clearenv");
    return fail_int(patina_clearenv());
}
#endif

/* putenv is the one env mutator that stays fail-closed. Its entry remains
 * ALIASED to caller-owned memory: POSIX lets a later write through the caller's
 * buffer change the environment, and forbids the implementation from copying or
 * freeing the string. Patina's environment is an owned deterministic map, so
 * honoring that aliasing would mean tracking guest memory the runtime does not
 * own — an unmodeled effect whose divergence would surface as a silently stale
 * value rather than an error. Refuse loudly and name the modeled path. */
int putenv(char *string) {
    (void)string;
    return patina_posix_deny("patina: putenv is not modeled because its entry stays aliased to caller-owned memory; use setenv (modeled and deterministic); failing closed\n");
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
    char resolved[PATH_MAX];
    intptr_t length = patina_canonicalize(path, resolved, sizeof resolved);
    if (length < 0) {
        errno = patina_errno();
        return NULL;
    }
    if ((size_t)length >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    // `resolved` now holds the NUL-terminated canonical path. When the caller
    // provides no buffer, malloc the result with the guest allocator so the
    // guest's own free(3) reclaims it (the opendir/closedir ownership model).
    if (destination == NULL) {
        char *owned = malloc((size_t)length + 1);
        if (owned == NULL) {
            errno = ENOMEM;
            return NULL;
        }
        memcpy(owned, resolved, (size_t)length + 1);
        return owned;
    }
    memcpy(destination, resolved, (size_t)length + 1);
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
         * the same deterministic entropy source; otherwise older getrandom paths
         * may fall back to opening /dev/urandom (also modeled by the shim as a
         * deterministic entropy device). GRND_* flags are irrelevant:
         * deterministic entropy never blocks and has one source. */
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
    /* fdopendir transfers a virtual directory descriptor into the DIR, which
     * closedir then releases; -1 for an opendir DIR that owns no descriptor. */
    int owned_fd;
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
    directory->owned_fd = -1;
    return (DIR *)(void *)directory;
}

/*
 * fdopendir: build the same DIR opendir builds, but from the directory a virtual
 * dir fd is bound to, and TRANSFER the fd's ownership into the DIR (POSIX: the
 * descriptor is closed by closedir, not the caller). std's remove_dir_all opens
 * each directory with openat(..., O_DIRECTORY) and hands the fd here, then reads
 * entries and removes children through unlinkat(dirfd, ...). The entry snapshot
 * is taken now, exactly like opendir, so iteration is stable across the removals.
 */
DIR *fdopendir(int fd) {
    char path[PATH_MAX];
    intptr_t length = patina_dirpath(fd, path, sizeof path);
    if (length < 0) {
        errno = patina_errno();
        return NULL;
    }
    if ((size_t)length >= sizeof path) {
        errno = ENAMETOOLONG;
        return NULL;
    }
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
    size_t path_size = (size_t)length + 1;
    directory->path = malloc(path_size);
    if (directory->path == NULL) {
        free(directory);
        patina_read_dir_free(state);
        errno = ENOMEM;
        return NULL;
    }
    memcpy(directory->path, path, path_size);
    directory->state = state;
    directory->owned_fd = fd;
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
    /* Release the transferred descriptor for an fdopendir DIR (POSIX: closedir
     * closes the fd fdopendir took ownership of). An opendir DIR owns none. */
    if (directory->owned_fd >= 0) patina_dirclose(directory->owned_fd);
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
    struct patina_dir *directory = (struct patina_dir *)(void *)dirp;
    /* An fdopendir DIR exposes the descriptor it took ownership of; an opendir
     * DIR owns no descriptor, so it stays fail-closed as before. */
    if (directory->owned_fd >= 0) return directory->owned_fd;
    errno = ENOTSUP;
    return -1;
}

int symlink(const char *target, const char *link_path) {
    return fail_int(patina_symlink(target, link_path));
}

int link(const char *from, const char *to) {
    return fail_int(patina_link(from, to));
}

ssize_t readlink(const char *restrict path, char *restrict destination, size_t length) {
    return fail_size(patina_read_link(path, destination, length));
}

static int patina_open_directory(const char *path, int flags);

static int patina_posix_open(const char *path, int flags) {
    patina_note_boundary_symbol("open");
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
#ifdef O_DIRECTORY
    supported |= O_DIRECTORY;
#endif
    if ((flags & ~supported) != 0) {
        errno = ENOSYS;
        return -1;
    }
#ifdef O_DIRECTORY
    if (flags & O_DIRECTORY) return patina_open_directory(path, flags);
#endif
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
 * Resolve `path` for the *at family against a directory descriptor. Called only
 * when `dirfd != AT_FDCWD`. The descriptor must be a virtual directory descriptor
 * (issued by openat(..., O_DIRECTORY)); a real/unknown kernel descriptor the
 * deterministic filesystem never issued fails closed with ENOSYS (matching the
 * rest of the *at family) rather than silently escaping to the host -- even for
 * an absolute path, so an arbitrary bogus fd is never honored. Given a valid
 * descriptor, an absolute `path` ignores it (POSIX) and a relative `path` is
 * joined onto its bound directory path.
 */
static int patina_resolve_at(int dirfd, const char *path, char *out, size_t out_len) {
    if (!patina_dir_is_dirfd(dirfd)) {
        errno = ENOSYS;
        return -1;
    }
    if (path[0] == '/') {
        size_t path_len = strlen(path);
        if (path_len + 1 > out_len) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(out, path, path_len + 1);
        return 0;
    }
    char base[PATH_MAX];
    intptr_t base_len = patina_dirpath(dirfd, base, sizeof base);
    if (base_len < 0) {
        errno = patina_errno();
        return -1;
    }
    if ((size_t)base_len >= sizeof base) {
        errno = ENAMETOOLONG;
        return -1;
    }
    size_t path_len = strlen(path);
    int separator = ((size_t)base_len > 0 && base[base_len - 1] == '/') ? 0 : 1;
    if ((size_t)base_len + (size_t)separator + path_len + 1 > out_len) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, base, (size_t)base_len);
    size_t offset = (size_t)base_len;
    if (separator) out[offset++] = '/';
    memcpy(out + offset, path, path_len + 1);
    return 0;
}

/*
 * open/openat(..., O_DIRECTORY): validate that `path` names a directory, open a
 * read-only deterministic filesystem descriptor for it, and register the fd as a
 * directory handle for fdopendir/openat/unlinkat resolution. patina_metadata
 * reports the entry's own kind (no trailing-symlink follow, like lstat), so
 * O_NOFOLLOW on a symlink fails with ELOOP -- exactly what std's remove_dir_all
 * treats as "not a directory, unlink it". Without O_NOFOLLOW a trailing symlink
 * is resolved through realpath and re-checked, so a symlink-to-directory opens
 * honestly. A non-directory is ENOTDIR. The fd is a real deterministic-FS fd, so
 * fstat reports a directory and fsync is the parent-directory durability barrier.
 */
static int patina_open_directory(const char *path, int flags) {
    (void)flags;
    uint32_t kind = 0;
    uint64_t length = 0;
    if (patina_metadata(path, &kind, &length) != 0) {
        errno = patina_errno();
        return -1;
    }
    if (kind == PATINA_ENTRY_SYMLINK) {
#ifdef O_NOFOLLOW
        if (flags & O_NOFOLLOW) {
            errno = ELOOP;
            return -1;
        }
#endif
        char resolved[PATH_MAX];
        intptr_t resolved_len = patina_canonicalize(path, resolved, sizeof resolved);
        if (resolved_len < 0) {
            errno = patina_errno();
            return -1;
        }
        if ((size_t)resolved_len >= sizeof resolved) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (patina_metadata(resolved, &kind, &length) != 0) {
            errno = patina_errno();
            return -1;
        }
        if (kind != PATINA_ENTRY_DIRECTORY) {
            errno = ENOTDIR;
            return -1;
        }
        if ((flags & O_ACCMODE) != O_RDONLY ||
            (flags & (O_CREAT | O_TRUNC | O_APPEND | O_EXCL)) != 0) {
            errno = EISDIR;
            return -1;
        }
        return fail_int(patina_diropen(resolved));
    }
    if (kind != PATINA_ENTRY_DIRECTORY) {
        errno = ENOTDIR;
        return -1;
    }
    if ((flags & O_ACCMODE) != O_RDONLY ||
        (flags & (O_CREAT | O_TRUNC | O_APPEND | O_EXCL)) != 0) {
        errno = EISDIR;
        return -1;
    }
    return fail_int(patina_diropen(path));
}

/*
 * openat over the path-based deterministic filesystem. AT_FDCWD is a plain path;
 * a virtual directory descriptor (from a prior openat(..., O_DIRECTORY)) joins
 * its bound path with a relative `path` -- the resolution std's remove_dir_all
 * needs to recurse and remove children. O_DIRECTORY yields a virtual directory
 * descriptor; everything else routes to the ordinary file open. A real kernel
 * dirfd the deterministic filesystem never issued still fails closed (ENOSYS,
 * matching the rest of the *at family).
 * The variadic mode is dropped just as `open` drops it. rustix's libc backend
 * lowers its `fs` calls onto these on both platforms, so they are strong defs in
 * the common section rather than Apple-only.
 */
static int patina_openat_impl(int dirfd, const char *path, int flags) {
    char resolved[PATH_MAX];
    const char *effective = path;
    if (dirfd != AT_FDCWD) {
        if (patina_resolve_at(dirfd, path, resolved, sizeof resolved) != 0) return -1;
        effective = resolved;
    }
#ifdef O_DIRECTORY
    if (flags & O_DIRECTORY) {
        return patina_open_directory(effective, flags);
    }
#endif
    return patina_posix_open(effective, flags);
}

int openat(int dirfd, const char *path, int flags, ...) {
    return patina_openat_impl(dirfd, path, flags);
}

/*
 * `creat(path, mode)` is exactly `open(path, O_WRONLY|O_CREAT|O_TRUNC, mode)`, so
 * route it through the deterministic filesystem like `open`. The mode is dropped
 * (the deterministic FS is path-based with no permission bits), matching `open`.
 * A raw host `creat` would write the real filesystem; interposing keeps it in the
 * deterministic FS. Being a strong def it also drops off the guest import table.
 */
int creat(const char *path, mode_t mode) {
    (void)mode;
    return patina_posix_open(path, O_WRONLY | O_CREAT | O_TRUNC);
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
 * the *64 names on 64-bit Linux). Shares openat's directory-descriptor handling. */
int openat64(int dirfd, const char *path, int flags, ...) {
    return patina_openat_impl(dirfd, path, flags);
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
    /* A virtual directory descriptor is released here as well as by closedir, so
     * a guest that close()s the raw fd (rather than the DIR) still frees it.
     * Directory fds are ordinary deterministic-FS fds now (small numbers), so
     * check the directory table before the socket-space dispatch. */
    if (patina_dir_is_dirfd(fd)) return fail_int(patina_dirclose(fd));
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
 * *at removal/rename over the path-based deterministic filesystem. AT_FDCWD is a
 * plain path; a virtual directory descriptor joins its bound path with a relative
 * `path` (std's remove_dir_all removes children with unlinkat(dirfd, name, ...)).
 * unlinkat routes to rmdir when AT_REMOVEDIR is set, otherwise unlink; unknown
 * flags fail closed. renameat still requires both dirfds be AT_FDCWD (no ecosystem
 * path exercises a dir-fd-relative rename; adding it would be speculative surface).
 */
int unlinkat(int dirfd, const char *path, int flags) {
    if ((flags & ~AT_REMOVEDIR) != 0) {
        errno = ENOSYS;
        return -1;
    }
    char resolved[PATH_MAX];
    const char *effective = path;
    if (dirfd != AT_FDCWD) {
        if (patina_resolve_at(dirfd, path, resolved, sizeof resolved) != 0) return -1;
        effective = resolved;
    }
    if (flags & AT_REMOVEDIR) return fail_int(patina_rmdir(effective));
    return fail_int(patina_unlink(effective));
}

/*
 * link/linkat: create a hard link. std::fs::hard_link lowers to
 * linkat(AT_FDCWD, original, AT_FDCWD, link, 0) on Linux and macOS. AT_FDCWD and
 * absolute paths pass straight through; a virtual directory descriptor resolves
 * its bound path for symmetry with the openat/unlinkat family. AT_SYMLINK_FOLLOW
 * is the only defined flag: when set, `from` is canonicalized (its trailing
 * symlink resolved) before linking, so the link targets the resolved file rather
 * than duplicating the symlink -- the driver's link duplicates a symlink entry
 * as-is, which is precisely the no-AT_SYMLINK_FOLLOW behavior. Any other flag bit
 * is EINVAL rather than silently ignored.
 */
int linkat(int fromfd, const char *from, int tofd, const char *to, int flags) {
    if ((flags & ~AT_SYMLINK_FOLLOW) != 0) {
        errno = EINVAL;
        return -1;
    }
    char from_resolved[PATH_MAX];
    char to_resolved[PATH_MAX];
    const char *from_effective = from;
    const char *to_effective = to;
    if (fromfd != AT_FDCWD) {
        if (patina_resolve_at(fromfd, from, from_resolved, sizeof from_resolved) != 0) return -1;
        from_effective = from_resolved;
    }
    if (tofd != AT_FDCWD) {
        if (patina_resolve_at(tofd, to, to_resolved, sizeof to_resolved) != 0) return -1;
        to_effective = to_resolved;
    }
    if (flags & AT_SYMLINK_FOLLOW) {
        char canonical[PATH_MAX];
        intptr_t canonical_len = patina_canonicalize(from_effective, canonical, sizeof canonical);
        if (canonical_len < 0) {
            errno = patina_errno();
            return -1;
        }
        if ((size_t)canonical_len >= sizeof canonical) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return fail_int(patina_link(canonical, to_effective));
    }
    return fail_int(patina_link(from_effective, to_effective));
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
/* The arming flag is OWNED by the Rust lib (an exported AtomicU8 in a writable
 * section); the C arming path stores into it so `sud_armed_metadata` can read it
 * without the C→Rust link direction that left the lib's own test binary with an
 * undefined symbol. C is only ever linked where the Rust lib is present. */
extern unsigned char PATINA_SUD_ARMED;
/* The scrubbed auxv region (base pointer + byte length through AT_NULL,
 * inclusive), captured during the init scrub below and OWNED by the Rust lib
 * (exported AtomicUsize, same C→Rust direction and rationale as
 * PATINA_SUD_ARMED). The Rust PR_GET_AUXV dispatch row copies from here so a raw
 * prctl(PR_GET_AUXV) serves the shim's determinized auxv, never the kernel's
 * pristine saved_auxv. */
extern uintptr_t PATINA_SUD_AUXV_BASE;
extern uintptr_t PATINA_SUD_AUXV_LEN;

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
    ElfW(auxv_t) *base = aux;
    for (; aux->a_type != AT_NULL; aux++) {
        if (aux->a_type == AT_SYSINFO_EHDR) aux->a_type = AT_IGNORE;
    }
    /* `aux` now points at the terminating AT_NULL entry. Publish the scrubbed
     * auxv region — base and length through AT_NULL inclusive — to the Rust-owned
     * cells so the PR_GET_AUXV dispatch row copies THIS determinized array (this
     * runs after AT_RANDOM determinization and the AT_SYSINFO_EHDR rename, both
     * before SUD is armed, so no trap can observe an un-scrubbed region). */
    PATINA_SUD_AUXV_BASE = (uintptr_t)base;
    PATINA_SUD_AUXV_LEN = (uintptr_t)((char *)(aux + 1) - (char *)base);
}

/* AT_RANDOM determinization (SUD-DESIGN.md §9 slice 3). The kernel seeds the
 * auxv AT_RANDOM entry with 16 real-random bytes that glibc consumes at startup
 * for the stack canary and pointer guard AND that a guest can read directly via
 * getauxval(AT_RANDOM) — a nondeterminism/entropy leak. Unlike AT_SYSINFO_EHDR
 * (scrubbed to AT_IGNORE), AT_RANDOM must be REPLACED in place: glibc
 * dereferences the pointer during startup, so AT_IGNORE-ing it (a null return)
 * would crash the canary setup. Overwrite the 16 bytes with seed-derived
 * deterministic bytes. Kernel-INDEPENDENT: this runs on every managed run,
 * before guest ctors, whether or not SUD is armed. */
#ifndef AT_RANDOM
#define AT_RANDOM 25
#endif

static uint64_t patina_sud_splitmix64(uint64_t *state) {
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Read the PATINA_SEED value from the still-intact environ (the ctor scrub runs
 * later), or 0 if absent/unset. */
static uint64_t patina_sud_env_seed(int argc, char **argv) {
    char **envp = argv + argc + 1;
    static const char prefix[] = "PATINA_SEED=";
    size_t plen = sizeof prefix - 1;
    for (char **e = envp; *e != NULL; e++) {
        if (strncmp(*e, prefix, plen) == 0) {
            const char *v = *e + plen;
            uint64_t seed = 0;
            while (*v >= '0' && *v <= '9') {
                seed = seed * 10 + (uint64_t)(*v - '0');
                v++;
            }
            return seed;
        }
    }
    return 0;
}

static void patina_sud_determinize_at_random(int argc, char **argv) {
    /* Domain-separate the AT_RANDOM stream from every other seeded draw. */
    uint64_t state = patina_sud_env_seed(argc, argv) ^ 0x52414E444F4D0001ULL;
    char **envp = argv + argc + 1;
    char **walk = envp;
    while (*walk != NULL) walk++;
    walk++; /* step over envp's NULL terminator to the auxv array */
    ElfW(auxv_t) *aux = (ElfW(auxv_t) *)walk;
    for (; aux->a_type != AT_NULL; aux++) {
        if (aux->a_type == AT_RANDOM) {
            unsigned char *bytes = (unsigned char *)(uintptr_t)aux->a_un.a_val;
            if (bytes != NULL) {
                uint64_t lo = patina_sud_splitmix64(&state);
                uint64_t hi = patina_sud_splitmix64(&state);
                memcpy(bytes, &lo, sizeof lo);
                memcpy(bytes + sizeof lo, &hi, sizeof hi);
            }
        }
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

    /* AT_RANDOM determinization is kernel-independent: close the entropy leak on
     * EVERY managed run (SUD kernel or not), before the SUD kernel probe gate
     * below can early-return. */
    patina_sud_determinize_at_random(argc, argv);

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
    /* Publish the armed state to the Rust-owned flag (writable section) so the
     * config path records the `sud` trace-metadata field. */
    PATINA_SUD_ARMED = 1;
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

/*
 * glibc init-reachable helpers a custom global allocator (tikv-jemallocator)
 * links on Linux, made deterministic so the guest audits clean and runs
 * reproducibly. Each is a strong def, so it also drops off the guest import table.
 */

/* Live CPU id → a fixed 0. `sched_getcpu` is host-scheduling nondeterminism
 * (which core happens to run this thread); pinning it to a constant makes an
 * allocator's per-CPU arena selection deterministic, like the pid/uname
 * constants. Distinct from `__sched_cpucount` (the pure `CPU_COUNT` popcount over
 * caller memory), which is allowlisted rather than interposed. */
int sched_getcpu(void) {
    return 0;
}

/* CPU affinity is inert under the single-baton scheduler — exactly one managed
 * thread runs at a time regardless — so setting it is a deterministic no-op
 * success rather than a real host scheduling effect. */
int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask) {
    (void)pid;
    (void)cpusetsize;
    (void)mask;
    return 0;
}

/* `secure_getenv`, like the interposed `getenv`, reads only the deterministic
 * guest environment map. */
char *secure_getenv(const char *name) {
    patina_note_boundary_symbol("secure_getenv");
    return patina_getenv(name);
}

/* A thread's name is host/kernel state (`/proc/self/task/<tid>/comm`); return a
 * fixed empty name so a guest cannot observe where, or as what, it ran — the same
 * stance as `gethostname` → "patina". */
int pthread_getname_np(pthread_t thread, char *name, size_t len) {
    (void)thread;
    /* glibc declares `name` nonnull (a NULL comparison is a -Werror on gcc);
     * only guard the zero-length buffer. */
    if (len > 0) {
        name[0] = '\0';
    }
    return 0;
}

/* Signal masking is inert under Patina (no ambient signals are ever delivered),
 * so forward to the real glibc mask op for faithful `oldset` semantics — but NEVER
 * let the guest block SIGSYS: under syscall-user-dispatch a blocked synchronous
 * SIGSYS would kill the process and disable deterministic containment. Strip SIGSYS
 * from any block/setmask set, mirroring the `sigaction(SIGSYS)` hardening above.
 * The shim uses no `pthread_sigmask` internally, so this never self-blocks. */
typedef int (*patina_host_pthread_sigmask_fn)(int, const sigset_t *, sigset_t *);
static patina_host_pthread_sigmask_fn patina_host_pthread_sigmask_ptr;
static patina_host_pthread_sigmask_fn patina_real_pthread_sigmask(void) {
    if (patina_host_pthread_sigmask_ptr == NULL) {
        patina_host_pthread_sigmask_ptr =
            (patina_host_pthread_sigmask_fn)__real_dlsym(RTLD_NEXT, "pthread_sigmask");
    }
    return patina_host_pthread_sigmask_ptr;
}
int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset) {
    if (set != NULL && (how == SIG_BLOCK || how == SIG_SETMASK)) {
        sigset_t adjusted = *set;
        sigdelset(&adjusted, SIGSYS);
        return patina_real_pthread_sigmask()(how, &adjusted, oldset);
    }
    return patina_real_pthread_sigmask()(how, set, oldset);
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
 * ==========================================================================
 * Deterministic time / host-query / stdio surface.
 *
 * Real crates (mimalloc, the `time`/`chrono` crates, sysinfo, aws-lc-rs, zstd)
 * link a libc surface that reads host wall-clock timezone data, host
 * CPU/memory/hardware inventory, and libc `FILE*` stdio. Left as host imports
 * these taint the run's determinism claim and the pre-run gate refuses them.
 * Each is interposed with a strong definition that returns a value that is a
 * pure function of the virtual clock / a fixed world-model constant, so the
 * guest audits clean, the symbol drops off the import table, and the same seed
 * yields the same bytes regardless of the host. The world-model constants match
 * the ones the shim already exposes elsewhere (one CPU — sched_getcpu/
 * sched_getaffinity/sysconf(_SC_NPROCESSORS_*); a 4096-byte page —
 * sysconf(_SC_PAGESIZE)).
 * ==========================================================================
 */

/* Fixed physical-memory world-model constant (8 GiB). mimalloc's arena sizing
 * and sysinfo's total-memory probe read it; neither value is guest-observable
 * output, but a fixed nonzero constant keeps their heuristics deterministic
 * regardless of the host's real RAM. */
#define PATINA_PHYSICAL_MEMORY_BYTES (UINT64_C(8) * 1024 * 1024 * 1024)

/* The single fixed timezone the runtime models. A mutable static (not a string
 * literal) so it binds to `struct tm::tm_zone` whether the platform types that
 * field as `char *` (Darwin/BSD) or `const char *` (glibc) without a cast. */
static char patina_tm_zone_utc[] = "UTC";

/*
 * Broken-down UTC from a time_t, as a PURE function of the input seconds — no
 * host timezone database, /etc/localtime, or environment. The runtime models a
 * single fixed timezone (UTC): tm_gmtoff is 0 and tm_zone is "UTC" (the BSD/GNU
 * `struct tm` extension fields, visible here under _DARWIN_C_SOURCE/_GNU_SOURCE),
 * so a local-offset probe observes a zero offset and `now_local()` collapses
 * onto `now_utc()`. The civil-from-days decomposition is Howard Hinnant's
 * algorithm (proleptic Gregorian, whole time_t range), so identical seconds
 * always yield identical fields regardless of host locale or clock.
 */
static void patina_utc_from_time(time_t seconds, struct tm *out) {
    int64_t secs = (int64_t)seconds;
    int64_t days = secs / 86400;
    int64_t rem = secs % 86400;
    if (rem < 0) {
        rem += 86400;
        days -= 1;
    }
    int sec_of_day = (int)rem;
    out->tm_hour = sec_of_day / 3600;
    out->tm_min = (sec_of_day % 3600) / 60;
    out->tm_sec = sec_of_day % 60;
    /* 1970-01-01 was a Thursday (=4). Floor-mod into 0..6 with Sunday=0. */
    int wday = (int)(((days % 7) + 4) % 7);
    if (wday < 0) {
        wday += 7;
    }
    out->tm_wday = wday;
    /* days-from-civil inverse (epoch shifted to 0000-03-01 so leap days fall at
     * the end of the 400-year era). */
    int64_t z = days + 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);                          /* [0, 146096] */
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; /* [0, 399]   */
    int64_t y = (int64_t)yoe + era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100); /* [0, 365] */
    unsigned mp = (5 * doy + 2) / 153;                      /* [0, 11]  */
    unsigned d = doy - (153 * mp + 2) / 5 + 1;              /* [1, 31]  */
    unsigned m = mp < 10 ? mp + 3 : mp - 9;                 /* [1, 12]  */
    if (m <= 2) {
        y += 1;
    }
    out->tm_mday = (int)d;
    out->tm_mon = (int)m - 1;
    out->tm_year = (int)(y - 1900);
    static const int cumulative[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
    int leap = ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) ? 1 : 0;
    out->tm_yday = cumulative[out->tm_mon] + (int)d - 1 + (out->tm_mon > 1 ? leap : 0);
    out->tm_isdst = 0;
    out->tm_gmtoff = 0;
    out->tm_zone = patina_tm_zone_utc;
}

struct tm *localtime_r(const time_t *timep, struct tm *result) {
    if (timep == NULL || result == NULL) {
        errno = EFAULT;
        return NULL;
    }
    memset(result, 0, sizeof *result);
    patina_utc_from_time(*timep, result);
    return result;
}

/*
 * sleep(): the second-granularity blocking sleep (mimalloc's `mi_atomic_yield`
 * fallback issues `sleep(0)`). Route it through the virtual clock exactly like
 * nanosleep/usleep so it never blocks a real host thread. Always returns 0: under
 * virtual time the full interval elapses, so no seconds remain.
 */
unsigned int sleep(unsigned int seconds) {
    uint64_t now = 0;
    if (patina_clock_now(PATINA_CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    uint64_t delta = (uint64_t)seconds * UINT64_C(1000000000);
    if (delta <= UINT64_MAX - now) {
        (void)patina_sleep_until(PATINA_CLOCK_MONOTONIC, now + delta);
    }
    return 0;
}

/* Split a nanosecond count into a `struct timeval`. The CPU-time model attributes
 * ALL modeled time to user time (ru_utime); system time (ru_stime) stays 0 by
 * convention — the runtime does not partition guest work into user/kernel phases. */
static void patina_timeval_from_nanos(uint64_t nanos, struct timeval *out) {
    out->tv_sec = (time_t)(nanos / UINT64_C(1000000000));
    out->tv_usec = (suseconds_t)((nanos % UINT64_C(1000000000)) / 1000);
}

/*
 * getrusage(): per-process resource accounting is host state (real CPU time,
 * peak RSS, page faults) that varies run to run. Report a value that is a pure
 * function of the deterministic virtual clock instead: ru_utime is the modeled
 * CPU time (elapsed virtual monotonic time via patina_cpu_time_nanos — see its
 * ABI note for why the monotonic clock is the process's summed run-slice total),
 * all attributed to user time (ru_stime = 0, by the split convention above). A
 * guest that branches on its own CPU usage (mimalloc's process-info probe reads
 * ru_utime/ru_stime) then sees a deterministic, monotonically advancing counter
 * instead of live host counters, identical across same-seed runs. Both platforms.
 *
 * Only RUSAGE_SELF carries the modeled CPU time. RUSAGE_CHILDREN stays zeroed
 * (the runtime models no child processes), and on Linux RUSAGE_THREAD stays
 * zeroed too: per-thread run-slices are not separately accumulated (the model is
 * a single process-wide CPU timeline), so a truthful deterministic zero is
 * reported rather than mislabeling the whole-process timeline as one thread's.
 *
 * ru_maxrss stays 0: the shim models no deterministic memory high-water. Guest
 * allocations reach the host allocator / an anonymous-mmap passthrough (Linux
 * SUD; macOS has no mmap interposer at all), so any peak-RSS figure would reflect
 * host allocator/version/platform state — not simulation state — and could not be
 * made a pure function of the seed. A deterministic 0 (mimalloc reads it as
 * peak_rss) is preferable to a non-reproducible number.
 *
 * The first-argument type follows the platform's own prototype: glibc types it as
 * `__rusage_who_t` (an enum under _GNU_SOURCE), Darwin as plain `int`.
 */
#ifdef __linux__
int getrusage(__rusage_who_t who, struct rusage *usage) {
#else
int getrusage(int who, struct rusage *usage) {
#endif
    if (usage == NULL) {
        errno = EFAULT;
        return -1;
    }
    memset(usage, 0, sizeof *usage);
    if (who == RUSAGE_SELF) {
        uint64_t nanos = 0;
        if (patina_cpu_time_nanos(&nanos) == 0) {
            patina_timeval_from_nanos(nanos, &usage->ru_utime);
        }
    }
    return 0;
}

/*
 * libc `FILE*` stdio, deterministic sink edition. mimalloc and aws-lc write
 * warnings/errors through `fputs`/`fprintf`/`fwrite` to `stdout`/`stderr`
 * (`__stdoutp`/`__stderrp` on Darwin). Define the two stream globals as
 * shim-owned SENTINELS pointing at opaque static storage, and interpose the
 * three FILE* writers to route a sentinel stream to the deterministic captured
 * stdio (fd 1 / fd 2) via patina_stdio_write. The guest never dereferences the
 * sentinel: pointer identity alone selects the descriptor. A NON-sentinel FILE*
 * reaching an interposer means an un-interposed `fopen` leaked a real host
 * stream through, so it fails closed LOUDLY (flush + abort naming the symbol),
 * the patina_process_trap shape. Being strong defs, the guest's references bind
 * here and the libc stdio symbols drop off the import table.
 */
static FILE patina_sentinel_stdout_storage;
static FILE patina_sentinel_stderr_storage;
#ifdef __APPLE__
FILE *__stdoutp = &patina_sentinel_stdout_storage;
FILE *__stderrp = &patina_sentinel_stderr_storage;
#else
FILE *stdout = &patina_sentinel_stdout_storage;
FILE *stderr = &patina_sentinel_stderr_storage;
#endif

/* Map a stream to its captured descriptor: 1 for the stdout sentinel, 2 for the
 * stderr sentinel, -1 for any other (a leaked host FILE*). */
static int patina_sentinel_fd(FILE *stream) {
    if (stream == &patina_sentinel_stdout_storage) {
        return 1;
    }
    if (stream == &patina_sentinel_stderr_storage) {
        return 2;
    }
    return -1;
}

__attribute__((noreturn)) static void patina_stdio_trap(const char *symbol) {
    static const char prefix[] = "patina: stdio call on a non-sentinel FILE* reached under patina: ";
    write(2, prefix, sizeof prefix - 1);
    write(2, symbol, strlen(symbol));
    static const char suffix[] =
        "; a host FILE* means an un-interposed fopen leaked through; failing closed\n";
    write(2, suffix, sizeof suffix - 1);
    patina_flush_captured_stdio();
    abort();
}

int fputs(const char *string, FILE *stream) {
    int fd = patina_sentinel_fd(stream);
    if (fd < 0) {
        patina_stdio_trap("fputs");
    }
    /* `string` is declared nonnull by libc (a NULL compare is -Werror under
     * gcc), so the contract is trusted, the gethostname/getpwuid_r precedent. */
    if (patina_stdio_write(fd, string, strlen(string)) < 0) {
        return EOF;
    }
    return 0;
}

size_t fwrite(const void *pointer, size_t size, size_t count, FILE *stream) {
    int fd = patina_sentinel_fd(stream);
    if (fd < 0) {
        patina_stdio_trap("fwrite");
    }
    if (size == 0 || count == 0) {
        return 0;
    }
    intptr_t written = patina_stdio_write(fd, pointer, size * count);
    if (written < 0) {
        return 0;
    }
    return (size_t)written / size;
}

/* Shared printf-family engine: format once into a stack buffer (heap fallback
 * for the rare long message, sized from the vsnprintf length probe), then write
 * once to the captured descriptor. */
static int patina_stream_vprintf(int fd, const char *format, va_list arguments) {
    char stack[512];
    va_list second;
    va_copy(second, arguments);
    int needed = vsnprintf(stack, sizeof stack, format, arguments);
    if (needed < 0) {
        va_end(second);
        return needed;
    }
    if ((size_t)needed < sizeof stack) {
        va_end(second);
        (void)patina_stdio_write(fd, stack, (size_t)needed);
        return needed;
    }
    char *heap = malloc((size_t)needed + 1);
    if (heap == NULL) {
        va_end(second);
        errno = ENOMEM;
        return -1;
    }
    int written = vsnprintf(heap, (size_t)needed + 1, format, second);
    va_end(second);
    if (written > 0) {
        (void)patina_stdio_write(fd, heap, (size_t)written);
    }
    free(heap);
    return written;
}

int vfprintf(FILE *stream, const char *format, va_list arguments) {
    int fd = patina_sentinel_fd(stream);
    if (fd < 0) {
        patina_stdio_trap("vfprintf");
    }
    return patina_stream_vprintf(fd, format, arguments);
}

int fprintf(FILE *stream, const char *format, ...) {
    int fd = patina_sentinel_fd(stream);
    if (fd < 0) {
        patina_stdio_trap("fprintf");
    }
    va_list arguments;
    va_start(arguments, format);
    int written = patina_stream_vprintf(fd, format, arguments);
    va_end(arguments);
    return written;
}

/* `printf`/`puts`/`putchar` bind implicitly to the stdout sentinel, so no
 * sentinel check is needed: they can never see a leaked host FILE*. On ELF this
 * family is also what keeps glibc's own printf away from the sentinel globals —
 * a probe or guest calling printf must reach the shim, never glibc's stdio
 * (whose vtable hardening aborts on a foreign FILE). */
int printf(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    int written = patina_stream_vprintf(1, format, arguments);
    va_end(arguments);
    return written;
}

int puts(const char *string) {
    if (patina_stdio_write(1, string, strlen(string)) < 0) {
        return EOF;
    }
    static const char newline = '\n';
    if (patina_stdio_write(1, &newline, 1) < 0) {
        return EOF;
    }
    return 0;
}

int putchar(int character) {
    unsigned char byte = (unsigned char)character;
    if (patina_stdio_write(1, &byte, 1) < 0) {
        return EOF;
    }
    return byte;
}

int fputc(int character, FILE *stream) {
    int fd = patina_sentinel_fd(stream);
    if (fd < 0) {
        patina_stdio_trap("fputc");
    }
    unsigned char byte = (unsigned char)character;
    if (patina_stdio_write(fd, &byte, 1) < 0) {
        return EOF;
    }
    return byte;
}

/* The sentinel streams are unbuffered (every write goes straight to the
 * captured descriptor), so a flush is always trivially satisfied. NULL means
 * "flush everything" and is equally a no-op. */
int fflush(FILE *stream) {
    if (stream != NULL && patina_sentinel_fd(stream) < 0) {
        patina_stdio_trap("fflush");
    }
    return 0;
}

/*
 * pthread_once: run `init_routine` exactly once across all managed threads,
 * concurrent callers blocking until the first completes (aws-lc's lazy library
 * init reaches it). The pthread_once_t storage layout is not portable (glibc's
 * is a bare zeroed int; Darwin's carries a nonzero signature word), so state is
 * tracked in a shim-side registry keyed on the control-block ADDRESS — the
 * os_unfair_lock lazy-registration convention — guarded by a deterministic
 * mutex + condvar that route through the scheduler (the interposed pthread_mutex
 * and pthread_cond families above). This is deadlock-free and deterministic under the cooperative
 * scheduler: exactly one thread transitions the entry to "running", runs the
 * init with the guard released, then wakes any waiters. A strong def, so the
 * symbol drops off the import table.
 */
struct patina_once_entry {
    pthread_once_t *key;
    int state; /* 0 = fresh, 1 = running, 2 = done */
    struct patina_once_entry *next;
};
static struct patina_once_entry *patina_once_registry;
static pthread_mutex_t patina_once_guard = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t patina_once_cond = PTHREAD_COND_INITIALIZER;

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) {
    /* Both parameters are declared nonnull by libc (a NULL compare is -Werror
     * under gcc), so the contract is trusted — the gethostname precedent. */
    pthread_mutex_lock(&patina_once_guard);
    struct patina_once_entry *entry = patina_once_registry;
    while (entry != NULL && entry->key != once_control) {
        entry = entry->next;
    }
    if (entry == NULL) {
        entry = malloc(sizeof *entry);
        if (entry == NULL) {
            pthread_mutex_unlock(&patina_once_guard);
            return ENOMEM;
        }
        entry->key = once_control;
        entry->state = 0;
        entry->next = patina_once_registry;
        patina_once_registry = entry;
    }
    while (entry->state == 1) {
        pthread_cond_wait(&patina_once_cond, &patina_once_guard);
    }
    if (entry->state == 2) {
        pthread_mutex_unlock(&patina_once_guard);
        return 0;
    }
    entry->state = 1;
    pthread_mutex_unlock(&patina_once_guard);
    init_routine();
    pthread_mutex_lock(&patina_once_guard);
    entry->state = 2;
    pthread_cond_broadcast(&patina_once_cond);
    pthread_mutex_unlock(&patina_once_guard);
    return 0;
}

#ifdef __APPLE__
/*
 * __assert_rtn (Darwin `assert` failure hook, reached by aws-lc). It only fires
 * when an assertion has already failed, so aborting is the correct deterministic
 * outcome; route the diagnostic to the captured stderr sink first (flush + abort
 * like patina_process_trap) so it reaches the operator. NOT allowlisted — a
 * genuine assertion failure must be a loud, reproducible abort, not a host
 * passthrough.
 */
__attribute__((noreturn)) void __assert_rtn(const char *function, const char *file, int line,
                                            const char *expression) {
    char message[512];
    int needed = snprintf(message, sizeof message,
                          "patina: assertion failed: (%s), function %s, file %s, line %d.\n",
                          expression ? expression : "", function ? function : "",
                          file ? file : "", line);
    if (needed > 0) {
        size_t length = (size_t)needed < sizeof message ? (size_t)needed : sizeof message - 1;
        (void)patina_stdio_write(2, message, length);
    }
    patina_flush_captured_stdio();
    abort();
}

/* Deterministic sysctl emit: copy a fixed value into the caller's oldp per the
 * BSD length protocol (report the size when oldp is NULL; ENOMEM on a short
 * buffer). Shared by the mib `sysctl` and the name-keyed `sysctlbyname`. */
static int patina_sysctl_emit(const void *value, size_t value_len, void *oldp, size_t *oldlenp) {
    if (oldp != NULL) {
        if (oldlenp == NULL) {
            errno = EINVAL;
            return -1;
        }
        if (*oldlenp < value_len) {
            errno = ENOMEM;
            return -1;
        }
        memcpy(oldp, value, value_len);
        *oldlenp = value_len;
    } else if (oldlenp != NULL) {
        *oldlenp = value_len;
    }
    return 0;
}

static int patina_sysctl_emit_int(int value, void *oldp, size_t *oldlenp) {
    return patina_sysctl_emit(&value, sizeof value, oldp, oldlenp);
}

static int patina_sysctl_emit_int64(int64_t value, void *oldp, size_t *oldlenp) {
    return patina_sysctl_emit(&value, sizeof value, oldp, oldlenp);
}

/*
 * sysctl (mib form) / sysctlbyname (name form): host hardware/kernel state reads
 * (mimalloc's physical-memory probe, sysinfo's totals, aws-lc's CPU-feature
 * detection). Serve the small set of keys real crates query as fixed
 * world-model constants: physical memory = 8 GiB, CPU count = 1, page size =
 * 4096 (matching sysconf), and EVERY optional CPU feature (`hw.optional.*`)
 * reported ABSENT (0) so crypto libraries fall back to portable, deterministic
 * code paths. Writes (newp) are refused (EPERM — a guest may not mutate kernel
 * state), and any unmodeled key fails ENOENT per the sysctl convention, so an
 * unhandled query is a deterministic miss rather than a host read.
 */
int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (newp != NULL || newlen != 0) {
        errno = EPERM;
        return -1;
    }
    if (name == NULL || namelen < 2) {
        errno = ENOENT;
        return -1;
    }
    if (name[0] == CTL_HW) {
        switch (name[1]) {
#ifdef HW_MEMSIZE
        case HW_MEMSIZE:
            return patina_sysctl_emit_int64((int64_t)PATINA_PHYSICAL_MEMORY_BYTES, oldp, oldlenp);
#endif
#ifdef HW_PHYSMEM64
        case HW_PHYSMEM64:
            return patina_sysctl_emit_int64((int64_t)PATINA_PHYSICAL_MEMORY_BYTES, oldp, oldlenp);
#endif
#ifdef HW_NCPU
        case HW_NCPU:
            return patina_sysctl_emit_int(1, oldp, oldlenp);
#endif
#ifdef HW_AVAILCPU
        case HW_AVAILCPU:
            return patina_sysctl_emit_int(1, oldp, oldlenp);
#endif
#ifdef HW_PAGESIZE
        case HW_PAGESIZE:
            return patina_sysctl_emit_int(4096, oldp, oldlenp);
#endif
        default:
            break;
        }
    }
    errno = ENOENT;
    return -1;
}

int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (newp != NULL || newlen != 0) {
        errno = EPERM;
        return -1;
    }
    if (name == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (strcmp(name, "hw.memsize") == 0) {
        return patina_sysctl_emit_int64((int64_t)PATINA_PHYSICAL_MEMORY_BYTES, oldp, oldlenp);
    }
    if (strcmp(name, "hw.pagesize") == 0) {
        return patina_sysctl_emit_int(4096, oldp, oldlenp);
    }
    if (strcmp(name, "hw.ncpu") == 0 || strcmp(name, "hw.logicalcpu") == 0 ||
        strcmp(name, "hw.logicalcpu_max") == 0 || strcmp(name, "hw.physicalcpu") == 0 ||
        strcmp(name, "hw.physicalcpu_max") == 0 || strcmp(name, "hw.activecpu") == 0) {
        return patina_sysctl_emit_int(1, oldp, oldlenp);
    }
    /* Optional CPU-feature flags → absent (0): safe and deterministic, crypto
     * libraries take the portable path. */
    if (strncmp(name, "hw.optional.", 12) == 0) {
        return patina_sysctl_emit_int(0, oldp, oldlenp);
    }
    errno = ENOENT;
    return -1;
}

/* Split a nanosecond count into a Mach `time_value_t` (seconds + microseconds),
 * the CPU-time carrier in the task_info flavors. Same all-as-user convention as
 * getrusage: the caller fills user_time from this and leaves system_time zeroed. */
static void patina_time_value_from_nanos(uint64_t nanos, time_value_t *out) {
    out->seconds = (integer_t)(nanos / UINT64_C(1000000000));
    out->microseconds = (integer_t)((nanos % UINT64_C(1000000000)) / 1000);
}

/*
 * task_info: Mach per-task introspection. Real consumers (verified against
 * mimalloc's `_mi_prim_process_info`) read `resident_size` from MACH_TASK_BASIC_INFO
 * (falling back to TASK_BASIC_INFO) for current RSS. Memory sizes stay 0 for the
 * same reason getrusage's ru_maxrss does — no deterministic memory high-water is
 * modeled (see getrusage) — but the CPU-time fields the basic flavors carry are
 * filled from the SAME deterministic model as getrusage's ru_utime
 * (patina_cpu_time_nanos), all as user_time, so a guest branching on task-level
 * CPU time sees the same monotonically advancing, seed-stable counter. Every other
 * word stays zeroed and the call reports KERN_SUCCESS. The task port argument
 * (mach_task_self) is ignored. */
kern_return_t task_info(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out,
                        mach_msg_type_number_t *task_info_count) {
    (void)target_task;
    if (task_info_out == NULL || task_info_count == NULL) {
        return KERN_SUCCESS;
    }
    mach_msg_type_number_t count = *task_info_count;
    memset(task_info_out, 0, (size_t)count * sizeof(natural_t));
    uint64_t nanos = 0;
    (void)patina_cpu_time_nanos(&nanos);
    switch (flavor) {
#ifdef MACH_TASK_BASIC_INFO
    case MACH_TASK_BASIC_INFO:
        if (count >= MACH_TASK_BASIC_INFO_COUNT) {
            patina_time_value_from_nanos(
                nanos, &((mach_task_basic_info_t)task_info_out)->user_time);
        }
        break;
#endif
#ifdef TASK_BASIC_INFO_64
    case TASK_BASIC_INFO_64:
        if (count >= TASK_BASIC_INFO_64_COUNT) {
            patina_time_value_from_nanos(
                nanos, &((task_basic_info_64_t)task_info_out)->user_time);
        }
        break;
#endif
#ifdef TASK_BASIC_INFO_32
    case TASK_BASIC_INFO_32:
        if (count >= TASK_BASIC_INFO_32_COUNT) {
            patina_time_value_from_nanos(
                nanos, &((task_basic_info_32_t)task_info_out)->user_time);
        }
        break;
#endif
#ifdef TASK_THREAD_TIMES_INFO
    case TASK_THREAD_TIMES_INFO:
        if (count >= TASK_THREAD_TIMES_INFO_COUNT) {
            patina_time_value_from_nanos(
                nanos, &((task_thread_times_info_t)task_info_out)->user_time);
        }
        break;
#endif
    default:
        break;
    }
    return KERN_SUCCESS;
}
#endif /* __APPLE__ */

#ifdef __linux__
/*
 * sysinfo(2): Linux host memory/uptime/load summary (mimalloc's physical-memory
 * probe on Linux). Report a fixed deterministic struct — uptime from the virtual
 * monotonic clock, total memory = the 8 GiB world-model constant with a 1-byte
 * mem_unit, one process — so a guest reading it sees the same values regardless
 * of the host. freeram stays a fixed half of totalram rather than
 * `totalram - high-water`: the shim models no deterministic memory high-water
 * (see getrusage's ru_maxrss), so there is no seed-stable figure to subtract, and
 * a fixed fraction keeps the value a pure function of the world model.
 */
int sysinfo(struct sysinfo *info) {
    if (info == NULL) {
        errno = EFAULT;
        return -1;
    }
    memset(info, 0, sizeof *info);
    uint64_t nanos = 0;
    if (patina_clock_now(PATINA_CLOCK_MONOTONIC, &nanos) == 0) {
        info->uptime = (long)(nanos / UINT64_C(1000000000));
    }
    info->mem_unit = 1;
    info->totalram = (unsigned long)PATINA_PHYSICAL_MEMORY_BYTES;
    info->freeram = (unsigned long)(PATINA_PHYSICAL_MEMORY_BYTES / 2);
    info->procs = 1;
    return 0;
}

/*
 * prctl: mimalloc issues three process-local memory-attribute ops on Linux —
 * PR_SET_VMA (name an anonymous mapping), PR_SET_THP_DISABLE, and the
 * PR_GET_THP_DISABLE probe. None is a guest-observable effect under Patina (the
 * runtime does not model transparent-hugepage state or VMA names), so the two
 * setters are deterministic no-op successes and the getter reports a fixed
 * "THP disabled" (1). Every other option fails closed with ENOSYS, the `uname`
 * doctrine — a guest reaching an unmodeled prctl op is a deterministic miss, not
 * a host passthrough. Variadic like glibc's declaration; the extra arguments are
 * inert for the handled ops.
 */
int prctl(int option, ...) {
    switch (option) {
#ifdef PR_SET_VMA
    case PR_SET_VMA:
#endif
#ifdef PR_SET_THP_DISABLE
    case PR_SET_THP_DISABLE:
#endif
        return 0;
#ifdef PR_GET_THP_DISABLE
    case PR_GET_THP_DISABLE:
        return 1;
#endif
    default:
        errno = ENOSYS;
        return -1;
    }
}

/*
 * getrlimit/setrlimit (the sysinfo crate reads limits). getrlimit reports a
 * fixed generous limit — RLIM_INFINITY, except RLIMIT_NOFILE which reports 1024
 * to match sysconf(_SC_OPEN_MAX) so fd-counting code stays sane — as a
 * deterministic constant independent of the host's real ulimits. setrlimit
 * refuses with EPERM: a truthful "cannot mutate host resource limits" rather
 * than a lying success (a guest cannot change limits the runtime does not model).
 */
int getrlimit(__rlimit_resource_t resource, struct rlimit *rlim) {
    /* `rlim` is declared nonnull by glibc (a NULL compare is -Werror under gcc). */
    rlim_t value = RLIM_INFINITY;
#ifdef RLIMIT_NOFILE
    if (resource == RLIMIT_NOFILE) {
        value = 1024;
    }
#endif
    rlim->rlim_cur = value;
    rlim->rlim_max = value;
    return 0;
}

int setrlimit(__rlimit_resource_t resource, const struct rlimit *rlim) {
    (void)resource;
    (void)rlim;
    errno = EPERM;
    return -1;
}

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
#endif /* __linux__ */

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
 * Dormant-path deny-traps: the helpers of the native-trust-root
 * (rustls-native-certs) and host-inventory (sysinfo / chrono-timezone) surfaces
 * that the honest deterministic models below leave unreachable by construction.
 *
 * These generalize the process-spawn deny-trap doctrine above (ESCAPE-CLASSES.md
 * row e, "Why symbol-reachability, not static call-graph"). A large native
 * binary commonly LINKS an optional TLS-trust-root loader or a host-inventory
 * crate whose call sites are statically wired but runtime-flag dormant — the
 * scenario never reaches them — yet a reachability audit cannot clear a
 * statically-wired path, so the pre-run gate would refuse the whole binary. A
 * strong shim definition binds the guest reference at link (the symbol drops off
 * the import table, so the gate passes when the path is dormant) and fails LOUD +
 * reproducibly at FIRST CALL, naming the symbol, if a scenario genuinely reaches
 * it. Merely linking the surface is inert; only a real call trips the trap.
 *
 * Scope is exactly the enumerated dormant surface. The LIVE-path members these
 * families also expose — `sysctl`/`sysctlbyname`/`getrusage`/`task_info`, the
 * stdio surface, `localtime_r` — are deliberately NOT trapped here (a tier-3
 * interposer change owns those): a strong def would silently swallow a path a
 * normal startup actually reaches, so they stay refused pre-run.
 */
/* Apple-only: every remaining caller is a PATINA_FRAMEWORK_TRAP /
 * PATINA_INTROSPECTION_TRAP macro in the __APPLE__ region below — the
 * cross-platform members (`kill`, `if_nametoindex`) are deterministic models now,
 * and an unguarded unused static is -Werror=unused-function on Linux. */
#ifdef __APPLE__
__attribute__((noreturn)) static void patina_native_trap(const char *klass,
                                                         const char *symbol) {
    static const char prefix[] = "patina: ";
    write(2, prefix, sizeof prefix - 1);
    write(2, klass, strlen(klass));
    static const char mid[] = " reached under patina: ";
    write(2, mid, sizeof mid - 1);
    write(2, symbol, strlen(symbol));
    static const char suffix[] =
        "; not interposed by the deterministic runtime; failing closed\n";
    write(2, suffix, sizeof suffix - 1);
    /* abort() skips the atexit shutdown flush (patina_process_trap precedent), so
     * push the captured guest output and this diagnostic to the real descriptors
     * before terminating. */
    patina_flush_captured_stdio();
    abort();
}
#endif

/*
 * Cross-platform members converted from deny-traps to honest deterministic
 * results: a runtime abort is not "support"; where the API admits an honest
 * answer, return it so a guest that reaches the path runs deterministically.
 *
 * `kill` in the single-process deterministic world: the guest is pid 1
 * (getpid()==1, getppid()==0) and no other process exists. A signal-0 probe
 * (an existence/permission check that delivers nothing) reports the guest alive
 * and every other pid absent (ESRCH) — this is the shape sysinfo's
 * `check_if_pid_is_alive` and libc liveness probes rely on. A real signal to
 * ANOTHER pid is ESRCH (no such process). A real signal to SELF is not modeled:
 * the runtime delivers no asynchronous signals beyond its own SIGSYS
 * containment, so rather than silently claim delivery (a lie) or abort (not
 * support) it fails closed with a loud line and a recoverable ENOSYS.
 */
int kill(pid_t pid, int sig) {
    if (pid != 1) {
        errno = ESRCH;
        return -1;
    }
    if (sig == 0) {
        return 0; /* the guest (pid 1) exists; signal 0 delivers nothing */
    }
    return patina_posix_deny("patina: kill(self, signal) delivery is not modeled "
                             "by the deterministic runtime; failing closed\n");
}
/*
 * `if_nametoindex`: the interface-index lookup a host networking utility stack
 * (hyper-util) links dormant. No network interfaces are modeled, so every name
 * is "no such interface": return 0 (never a valid index) with errno ENXIO.
 * hyper-util reads the 0 as an absent scope id and proceeds.
 */
unsigned int if_nametoindex(const char *ifname) {
    (void)ifname;
    errno = ENXIO;
    return 0;
}

#ifdef __APPLE__
/*
 * macOS CoreFoundation / Security framework and Mach/BSD/IOKit host-introspection
 * surface. A runtime abort is not "support": wherever the API contract admits an
 * honest deterministic result, the entry point below returns it, so a program
 * that EXERCISES the path (rustls-native-certs' trust-root loader, sysinfo's
 * host/CPU/process inventory, iana-time-zone/chrono's local timezone) runs
 * deterministically — like a locked-down host with an empty inventory — instead
 * of aborting. Once each ENTRY point returns honest emptiness, a set of helpers
 * becomes unreachable by construction; those stay deny-traps, each annotated
 * with why the honest entry points can never reach it. Every def here (honest or
 * trap) binds its guest reference by NAME and shadows the framework/Mach symbol
 * at link (the symbol drops off the import table); the traps additionally keep
 * the arity-free `void name(void)` shape, safe because they are never called.
 */

/* Synthetic CoreFoundation tokens handed back by the honest entry points so a
 * consumer runs against a valid non-NULL object without any real CF object
 * existing. Each is a distinct address (so an identity compare, though none is
 * performed today, still distinguishes them); their bytes are never read. */
static const char patina_cf_empty_array = 0;
static const char patina_cf_system_timezone = 0;
static const char patina_cf_timezone_name = 0;
static const char patina_cf_utc_name[] = "UTC";
/* The guest's fixed virtual executable path (proc_pidpath for pid 1). */
static const char patina_proc_pid1_path[] = "/patina/guest";

/* --- rustls-native-certs / security-framework trust-root surface ---
 *
 * Verified against rustls-native-certs 0.8.4 + security-framework 3.7.0 +
 * core-foundation 0.10.1. TrustSettings::iter() calls
 * SecTrustSettingsCopyCertificates and maps errSecNoTrustSettings to an EMPTY
 * certificate iterator (via CFArray::from_CFTypes(&[])), so load_native_certs()
 * returns zero certs and zero errors deterministically for every domain — a host
 * with no per-domain trust settings. Return that status for all domains; the out
 * parameter is left untouched (security-framework ignores it on this status).
 */
int SecTrustSettingsCopyCertificates(unsigned int domain, void **out) {
    (void)domain;
    (void)out;
    return -25263; /* errSecNoTrustSettings */
}

/* --- CoreFoundation helpers the honest entry points make reachable ---
 *
 * The empty trust-root path builds an empty CFArray (from_CFTypes(&[]) ->
 * CFArrayCreate/CFArrayGetCount/CFRelease), and the UTC timezone path below
 * releases its synthetic timezone. Exactly those helpers are honest; the rest
 * stay traps. `wrap_under_create_rule` asserts non-NULL, so CFArrayCreate and
 * CFTimeZoneCopySystem must return non-NULL synthetic tokens (defined with the
 * data symbols below). No real CF object is ever created: their bytes are never
 * read, so CFArrayGetCount reports 0 and CFRelease is a no-op (also for NULL).
 */
const void *CFArrayCreate(const void *allocator, const void *const *values,
                          long num_values, const void *callbacks) {
    (void)allocator;
    (void)values;
    (void)num_values;
    (void)callbacks;
    return &patina_cf_empty_array;
}
long CFArrayGetCount(const void *array) {
    (void)array;
    return 0;
}
void CFRelease(const void *cf) { (void)cf; }

/* --- iana-time-zone 0.1.65 / chrono::Local timezone surface ---
 *
 * The runtime models a single fixed timezone, UTC (see localtime_r above:
 * tm_gmtoff 0, tm_zone "UTC"), so report UTC here for a consistent world.
 * tz_darwin.rs flow: CFTimeZoneResetSystem() (cache invalidate; a no-op here) ->
 * a non-NULL CFTimeZoneCopySystem() -> CFTimeZoneGetName() -> as_utf8()
 * (CFStringGetCStringPtr, UTF-8) yields "UTC". Returning the C string directly
 * keeps the fallback conversion (CFStringGetLength/CFStringGetBytes) unreachable.
 * get_timezone() therefore returns Ok("UTC"); chrono::Local resolves the same
 * fixed UTC offset it gets from the localtime_r interposer, deterministically.
 */
void CFTimeZoneResetSystem(void) {}
const void *CFTimeZoneCopySystem(void) { return &patina_cf_system_timezone; }
const void *CFTimeZoneGetName(const void *tz) {
    (void)tz;
    return &patina_cf_timezone_name;
}
const char *CFStringGetCStringPtr(const void *string, unsigned int encoding) {
    (void)string;
    (void)encoding;
    return patina_cf_utc_name;
}

/* --- IOKit CPU-frequency surface (sysinfo get_cpu_frequency, macos/cpu.rs) ---
 *
 * Return NULL from IOServiceMatching: sysinfo reads a NULL matching dictionary as
 * "AppleARMIODevice not found" and reports CPU frequency 0 (unknown) — honest,
 * since the deterministic world does not model CPU frequency. This keeps the
 * whole IOServiceGetMatchingServices / IOIteratorNext / IOObjectRelease /
 * IORegistryEntry* / CFData chain unreachable (they stay traps below).
 */
void *IOServiceMatching(const char *name) {
    (void)name;
    return NULL;
}

/* --- deny-traps unreachable once the entry points above return honest emptiness.
 * `void name(void)` is safe because none is ever called (justification each). */
#define PATINA_FRAMEWORK_TRAP(name)                                            \
    void name(void) { patina_native_trap("macos-framework", #name); }
#define PATINA_INTROSPECTION_TRAP(name)                                        \
    void name(void) { patina_native_trap("host-introspection", #name); }

/* Trust-root empty path: the cert iterator is empty, so no certificate is ever
 * indexed, DER-encoded, or trust-queried, and no os_error is formatted. */
PATINA_FRAMEWORK_TRAP(CFArrayGetValueAtIndex)     /* empty array: never indexed */
PATINA_FRAMEWORK_TRAP(SecCertificateCopyData)     /* no cert to DER-encode */
PATINA_FRAMEWORK_TRAP(SecTrustSettingsCopyTrustSettings) /* no cert to query */
PATINA_FRAMEWORK_TRAP(SecCopyErrorMessageString)  /* errSecNoTrustSettings != error path */
/* Per-cert trust-settings inspection (CFDictionary/CFNumber/CFString compares)
 * only runs once a cert is yielded — never on the empty path. */
PATINA_FRAMEWORK_TRAP(CFDictionaryGetValueIfPresent)
PATINA_FRAMEWORK_TRAP(CFEqual)
PATINA_FRAMEWORK_TRAP(CFNumberGetValue)
PATINA_FRAMEWORK_TRAP(CFGetTypeID)
/* CFString builders and the get-rule retain: security-framework's cert/policy
 * name construction and iana's to_utf8 fallback are all downstream of a yielded
 * cert or a NULL CFStringGetCStringPtr — neither occurs. */
PATINA_FRAMEWORK_TRAP(CFRetain)
PATINA_FRAMEWORK_TRAP(CFStringCreateWithBytesNoCopy)
PATINA_FRAMEWORK_TRAP(CFStringCreateWithCStringNoCopy)
PATINA_FRAMEWORK_TRAP(CFStringGetBytes)
PATINA_FRAMEWORK_TRAP(CFStringGetLength)
/* CFData accessors belong to the IOKit CPU-frequency property read, dead once
 * IOServiceMatching returns NULL. */
PATINA_FRAMEWORK_TRAP(CFDataGetBytePtr)
PATINA_FRAMEWORK_TRAP(CFDataGetLength)
PATINA_FRAMEWORK_TRAP(CFDataGetBytes)
PATINA_FRAMEWORK_TRAP(CFDataGetTypeID)

/* The IOKit registry walk is entered only with a non-NULL matching dictionary;
 * IOServiceMatching returns NULL, so none of these is reached. */
PATINA_INTROSPECTION_TRAP(IOIteratorNext)
PATINA_INTROSPECTION_TRAP(IOObjectRelease)
PATINA_INTROSPECTION_TRAP(IORegistryEntryCreateCFProperty)
PATINA_INTROSPECTION_TRAP(IORegistryEntryGetName)
PATINA_INTROSPECTION_TRAP(IOServiceGetMatchingServices)

#undef PATINA_FRAMEWORK_TRAP
#undef PATINA_INTROSPECTION_TRAP

/* --- BSD per-process introspection (sysinfo process refresh) ---
 *
 * The deterministic world is a single process — the guest, pid 1 (getpid()==1,
 * getppid()==0). proc_listallpids honestly enumerates that one pid: the sizing
 * call (buffer==NULL) reports one pid; the fill call writes pid 1. (sysinfo's
 * get_proc_list treats a fill that exactly reaches the reported capacity as "the
 * list grew, retry" and drops it, so under sysinfo the *detailed* list ends up
 * empty and proc_pidpath/proc_pidinfo/proc_pid_rusage are not reached via
 * new_all — that is sysinfo's own capacity heuristic, not a fabricated count
 * here; the honest pid count is 1.) The three per-pid queries are still
 * converted to honest deterministic results so any DIRECT caller runs
 * deterministically rather than aborting. */
int proc_listallpids(void *buffer, int buffersize) {
    if (buffer == NULL || buffersize <= 0) {
        return 1; /* one pid exists: the guest, pid 1 */
    }
    if ((size_t)buffersize < sizeof(int)) {
        return 0;
    }
    *(int *)buffer = 1;
    return 1;
}
/* proc_pidpath: the guest's virtual executable path (a fixed deterministic
 * identity, never the host's real path — the gethostname/_NSGetExecutablePath
 * doctrine). Other pids: no such process. */
int proc_pidpath(int pid, void *buffer, uint32_t buffersize) {
    if (pid != 1) {
        errno = ESRCH;
        return -1;
    }
    if (buffer == NULL) {
        errno = EFAULT;
        return -1;
    }
    size_t len = sizeof(patina_proc_pid1_path) - 1;
    if ((size_t)buffersize < len + 1) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(buffer, patina_proc_pid1_path, len + 1);
    return (int)len; /* real proc_pidpath returns the length, excluding the NUL */
}
/* proc_pidinfo: pid 1 exists, but its kernel-internal BSD/task/vnode info is not
 * modeled — report zero bytes filled. A caller (sysinfo's get_bsd_info /
 * get_cwd_root) reads that as "no info for this flavor" and degrades gracefully
 * (falls back to the proc_pidpath name) rather than aborting. Other pids: ESRCH. */
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    (void)flavor;
    (void)arg;
    (void)buffer;
    (void)buffersize;
    if (pid != 1) {
        errno = ESRCH;
        return -1;
    }
    return 0;
}
/* proc_pid_rusage: pid 1 has no modeled per-process resource accounting, so
 * report an all-zero rusage for the one flavor real consumers request
 * (RUSAGE_INFO_V2, sysinfo's disk-io read); zeroing only that known-size struct
 * keeps the write in bounds. Other flavors/pids: deterministic error. */
int proc_pid_rusage(int pid, int flavor, rusage_info_t *buffer) {
    if (pid != 1) {
        errno = ESRCH;
        return -1;
    }
    if (buffer == NULL) {
        errno = EFAULT;
        return -1;
    }
    if (flavor == RUSAGE_INFO_V2) {
        memset(buffer, 0, sizeof(struct rusage_info_v2));
        return 0;
    }
    errno = EINVAL;
    return -1;
}

/* --- Mach host / VM introspection (sysinfo memory + CPU refresh) ---
 * Prototyped by the mach headers (included for the task_info interposer above),
 * so these spell the real signatures. */

/* mach_host_self: a fixed synthetic host port. Its only consumers are the
 * deterministic host_statistics64 / host_processor_info below, which ignore the
 * port, so a real Mach host port is never needed. */
mach_port_t mach_host_self(void) { return (mach_port_t)0x484f5354u; /* 'HOST' */ }

/* host_statistics64(HOST_VM_INFO64): fixed VM page statistics consistent with the
 * shim's 8 GiB world (PATINA_PHYSICAL_MEMORY_BYTES) at 4 KiB pages = 2,097,152
 * pages, split into a stable, self-consistent free/active/inactive/wired layout.
 * Only the HOST_VM_INFO64 flavor is modeled (the one sysinfo requests). */
kern_return_t host_statistics64(host_t host_priv, host_flavor_t flavor,
                                host_info64_t host_info64_out,
                                mach_msg_type_number_t *host_info64_outCnt) {
    (void)host_priv;
    if (flavor != HOST_VM_INFO64 || host_info64_out == NULL ||
        host_info64_outCnt == NULL || *host_info64_outCnt < HOST_VM_INFO64_COUNT) {
        return KERN_INVALID_ARGUMENT;
    }
    struct vm_statistics64 stat;
    memset(&stat, 0, sizeof stat);
    stat.free_count = 524288;     /* 2 GiB free */
    stat.active_count = 786432;   /* 3 GiB active */
    stat.inactive_count = 524288; /* 2 GiB inactive */
    stat.wire_count = 262144;     /* 1 GiB wired */
    memcpy(host_info64_out, &stat, sizeof stat);
    *host_info64_outCnt = HOST_VM_INFO64_COUNT;
    return KERN_SUCCESS;
}

/* host_processor_info(PROCESSOR_CPU_LOAD_INFO): fixed single-CPU load ticks,
 * consistent with the cpu-count=1 world model (sysctl HW_NCPU=1). sysinfo pushes
 * one Cpu from this, so System::cpus().len() == 1. The buffer is a real one-page
 * mmap because sysinfo frees it two ways: macos/system.rs via munmap(ptr,
 * vm_page_size) — a real munmap of this real mapping (munmap is NOT interposed,
 * so a static buffer would unmap program data) — and apple/cpu.rs via
 * vm_deallocate, which the shim no-ops (that path leaks one page per CPU refresh,
 * bounded and negligible). */
kern_return_t host_processor_info(host_t host, processor_flavor_t flavor,
                                  natural_t *out_processor_count,
                                  processor_info_array_t *out_processor_info,
                                  mach_msg_type_number_t *out_processor_infoCnt) {
    (void)host;
    if (flavor != PROCESSOR_CPU_LOAD_INFO || out_processor_count == NULL ||
        out_processor_info == NULL || out_processor_infoCnt == NULL) {
        return KERN_INVALID_ARGUMENT;
    }
    int *buffer = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_PRIVATE, -1, 0);
    if (buffer == MAP_FAILED) {
        return KERN_RESOURCE_SHORTAGE;
    }
    buffer[CPU_STATE_USER] = 0;
    buffer[CPU_STATE_SYSTEM] = 0;
    buffer[CPU_STATE_IDLE] = 1000; /* wholly idle; a fixed nonzero total avoids NaN */
    buffer[CPU_STATE_NICE] = 0;
    *out_processor_count = 1;
    *out_processor_info = (processor_info_array_t)buffer;
    *out_processor_infoCnt = CPU_STATE_MAX;
    return KERN_SUCCESS;
}

/* vm_deallocate: a memory-safe no-op. Its one guest caller frees the
 * host_processor_info buffer above; unmapping a caller-chosen address here would
 * not be safe, and the companion munmap free path reclaims its own copies. */
kern_return_t vm_deallocate(vm_map_t target_task, vm_address_t address,
                            vm_size_t size) {
    (void)target_task;
    (void)address;
    (void)size;
    return KERN_SUCCESS;
}

/*
 * Data symbols cannot be trapped on read, so they get fixed deterministic
 * values. Each is only ever passed into a call that is either an honest entry
 * point above (which ignores or safely consumes the value) or an unreachable
 * trap; these bindings satisfy the data reference and drop the symbol off the
 * import table.
 */
void *const kCFAllocatorDefault = NULL; /* CF's own "default allocator" sentinel */
void *const kCFAllocatorNull = NULL;
/* CFArrayCallBacks {version, retain, release, copyDescription, equal}: a zeroed
 * "no custom management" struct, only ever handed to the honest CFArrayCreate
 * (which ignores it — the empty array has no elements to manage). */
const struct {
    long version;
    void *retain;
    void *release;
    void *copy_description;
    void *equal;
} kCFTypeArrayCallBacks = {0, NULL, NULL, NULL, NULL};
unsigned int kIOMasterPortDefault = 0; /* IOKit default master port; only reaches
                                        * the unreachable IOServiceGetMatchingServices */
/* mach_task_self_ is the task's send-right port name (a mach_port_t). A
 * synthetic, obviously-non-real value; its consumer (vm_deallocate) is a no-op,
 * so it is never used as a real port. */
unsigned int mach_task_self_ = 0x50415400u; /* 'PAT\0' */
/* vm_page_size (vm_size_t): the shim's single world-model page size, matching
 * sysconf(_SC_PAGESIZE) and sysctl(HW_PAGESIZE). Read by sysinfo's munmap free
 * path for the host_processor_info buffer (a real one-page mmap). */
unsigned long vm_page_size = 4096;
#endif /* __APPLE__ */

/*
 * Packaged startup. An ordinary program built with `cargo patina native-build`
 * must not need Patina-specific init calls: the boundary sits BELOW application
 * code. This constructor installs the deterministic runtime from the PATINA_*
 * protocol (idempotent) and registers finalization through atexit, so record
 * mode is finalized on any normal exit path (main return or exit()) without an
 * explicit patina_shutdown. A standalone run (no PATINA_MODE) is left
 * uninstalled; the first effect boundary then fails closed with a clear message
 * (see ensure_runtime in the Rust layer). The public interposed getenv reads only
 * the deterministic guest map after startup (NULL before startup and when unset);
 * startup reads the PATINA_* control plane through the private snapshot accessor
 * before scrubbing the ambient environ and publishing the deterministic one that
 * guest code sees.
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
    if (patina_shutdown() != 0) {
        /* patina_shutdown already emitted the runtime error; atexit return values
         * are ignored, so abort to make record/replay finalization failures loud. */
        abort();
    }
}

/* Priority 101 runs before default-priority constructors on toolchains that
 * honor constructor priorities, minimizing false early-init failures while still
 * letting deliberately earlier constructors (the e2e uses .init_array.00099 on
 * ELF) prove the fail-closed path. */
__attribute__((constructor(101))) static void patina_native_start(void) {
    atexit(patina_finalize_atexit);
    patina_capture_control_plane();
    /* Register before init: installing the runtime publishes environ from the
     * guest env map, and a deferred harness install happens after this
     * constructor returns. */
    patina_register_environ_installer(patina_environ_install);
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
    patina_publish_environ();
    patina_note_startup_constructor_finished();
}
