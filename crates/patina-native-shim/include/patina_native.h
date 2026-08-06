#ifndef PATINA_NATIVE_H
#define PATINA_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PATINA_CLOCK_REALTIME = 0,
    PATINA_CLOCK_MONOTONIC = 1,
};

enum {
    PATINA_O_READ = 1u << 0,
    PATINA_O_WRITE = 1u << 1,
    PATINA_O_CREATE = 1u << 2,
    PATINA_O_TRUNCATE = 1u << 3,
    PATINA_O_APPEND = 1u << 4,
    PATINA_O_EXCLUSIVE = 1u << 5,
};

enum {
    PATINA_SEEK_START = 0,
    PATINA_SEEK_CURRENT = 1,
    PATINA_SEEK_END = 2,
};

int32_t patina_init_seed(uint64_t seed);
int32_t patina_init_crash(uint64_t seed);
/*
 * Build the runtime from the documented PATINA_* environment protocol.
 * When PATINA_TRACE_FD names an inherited host descriptor, record mode
 * writes the finalized trace bundle to it and replay mode reads the bundle
 * from it, using non-interposed host descriptor I/O so fully interposed
 * processes never recurse into the deterministic filesystem.
 */
int32_t patina_init_from_env(void);
void patina_note_boundary_symbol(const char *symbol);
void patina_note_startup_constructor_finished(void);
void patina_control_set_entry(const char *entry);
char *patina_getenv(const char *name);
/*
 * Deterministic guest environment mutation. These update the runtime's guest
 * env map — the single source of truth the getenv interposer reads — and then
 * republish the process environ array through the registered installer, so a
 * direct environ walk can never disagree with a getenv lookup. Mutation is
 * guest-driven and unrecorded; only the startup map lives in trace metadata.
 * `patina_publish_environ` republishes without mutating, for the startup path.
 */
int32_t patina_setenv(const char *name, const char *value, int32_t overwrite);
int32_t patina_unsetenv(const char *name);
int32_t patina_clearenv(void);
void patina_register_environ_installer(void (*installer)(char **));
void patina_publish_environ(void);
int32_t patina_shutdown(void);
/*
 * The runtime side of the packaged `exit` interposer. Marks the process as
 * having entered post-`main` teardown (so the root task's --yield-points hooks
 * take no scheduling point) and then terminates through the real libc `exit`
 * resolved via the shim host-alias table, so the atexit chain (trace
 * finalization) and the thread-local destructors still run. Does not return.
 */
_Noreturn void patina_exit(int32_t status);
/*
 * Mark the process as having entered post-`main` teardown without terminating.
 * Called by the Linux `__libc_start_main` interposer from its wrapper `main`, the
 * instant the guest's real `main` returns and before the exit code re-enters
 * glibc's `exit()` path — so the root task's --yield-points thread-local
 * destructor yields are silenced on the natural-return path that a plain `exit`
 * interposer cannot see (glibc calls `exit` through a hidden internal alias).
 */
void patina_note_main_returned(void);
#ifdef __linux__
/*
 * Syscall-user-dispatch (SUD) boundary (Linux only). `patina_sud_dispatch` is
 * the arch-agnostic dispatcher the C SIGSYS handler calls with a trapped
 * syscall's number, its six argument registers, and the faulting instruction
 * address; it returns the raw value written back into the return register (a
 * negative value is `-errno`). Its *defined* presence in a binary's symbol table
 * is also the audit's SUD marker (a dispatch-capable shim is linked).
 * `patina_sud_arm_thread` re-arms SUD on a managed thread (the config does not
 * survive clone(2)); it is a no-op unless the run armed SUD.
 */
long patina_sud_dispatch(long nr, unsigned long a0, unsigned long a1,
                         unsigned long a2, unsigned long a3, unsigned long a4,
                         unsigned long a5, uintptr_t call_addr);
void patina_sud_arm_thread(void);
/*
 * Linux interposer-engagement canary, called from the atexit finalizer. Aborts
 * loudly if the post-`main` teardown flag was never set by the time atexit runs
 * (i.e. neither the __libc_start_main wrapper nor the `exit` interposer engaged),
 * so an interposition miss is a one-line fatal instead of a later op divergence.
 */
void patina_assert_teardown_engaged(void);
#endif
/*
 * Flush captured stdout/stderr to the real host descriptors WITHOUT finalizing
 * the run (unlike patina_shutdown). The process-class deny-traps call this
 * before abort() so the guest's output and the deny diagnostic reach the
 * operator even though abort() skips the atexit-driven shutdown flush.
 */
int32_t patina_flush_captured_stdio(void);
int32_t patina_errno(void);
int32_t patina_entropy(void *destination, size_t length);
int32_t patina_clock_now(uint32_t clock, uint64_t *nanos);
int32_t patina_sleep_until(uint32_t clock, uint64_t deadline_nanos);
/*
 * Deterministic per-process CPU-time proxy in nanoseconds, for the resource
 * accounting interposers (`getrusage`/`task_info`/Linux `sysinfo`). Reports the
 * current virtual monotonic time UNRECORDED (like the kqueue reactor's deadline
 * scans) — under the single-runnable-task world model the process's summed
 * per-thread run-slices equal the monotonic delta, so elapsed virtual time is
 * the deterministic CPU-time model. Always succeeds writing a value: 0 before a
 * runtime is installed (allocator bootstrap / run outside the supervisor) so an
 * accounting read never forces init or aborts. Pure function of simulation
 * state: identical across same-seed runs, monotonic within a run.
 */
int32_t patina_cpu_time_nanos(uint64_t *nanos);
int32_t patina_open(const char *path, uint32_t flags);
intptr_t patina_read(int32_t fd, void *destination, size_t length);
intptr_t patina_write(int32_t fd, const void *source, size_t length);
intptr_t patina_pread(int32_t fd, void *destination, size_t length, int64_t offset);
intptr_t patina_pwrite(int32_t fd, const void *source, size_t length, int64_t offset);
int32_t patina_close(int32_t fd);
int32_t patina_dup(int32_t fd);
int64_t patina_seek(int32_t fd, int64_t offset, uint32_t whence);
int32_t patina_fsync(int32_t fd);
int32_t patina_set_len(int32_t fd, uint64_t length);
/*
 * Advisory whole-file lock (flock(2)). `operation` is LOCK_SH/LOCK_EX/LOCK_UN
 * optionally OR'd with LOCK_NB. Keyed on the descriptor's deterministic-fs
 * inode: a lone opener always acquires, while an incompatible lock held on a
 * different descriptor of the same file yields EWOULDBLOCK (LOCK_NB) so a guest
 * that opens the same file twice contends as it would on a real kernel. The
 * lock clears on LOCK_UN and on close.
 */
int32_t patina_flock(int32_t fd, int32_t operation);
enum {
    PATINA_ENTRY_FILE = 1,
    PATINA_ENTRY_DIRECTORY = 2,
    PATINA_ENTRY_SYMLINK = 3,
};

int32_t patina_metadata(const char *path, uint32_t *kind, uint64_t *length);
int32_t patina_fd_metadata(int32_t fd, uint32_t *kind, uint64_t *length);
int32_t patina_metadata_full(const char *path, uint32_t *kind, uint64_t *length,
                             uint64_t *ino, uint32_t *nlink,
                             uint64_t *atime_nanos, uint64_t *mtime_nanos);
int32_t patina_fd_metadata_full(int32_t fd, uint32_t *kind, uint64_t *length,
                                uint64_t *ino, uint32_t *nlink,
                                uint64_t *atime_nanos, uint64_t *mtime_nanos);
int32_t patina_read_dir(const char *path, void **state);
/*
 * Return 1 after writing the next entry, 0 at end-of-directory, or -1 with
 * patina_errno set. name_buf receives a NUL-terminated entry name.
 */
int32_t patina_read_dir_next(void *state, char *name_buf, size_t buf_len, uint32_t *kind);
void patina_read_dir_free(void *state);
int32_t patina_symlink(const char *target, const char *link_path);
/*
 * Create a hard link. Mirrors patina_symlink: the driver shares one inode
 * between `from` and `to`, or duplicates the symlink entry when `from` is itself
 * a symlink (linkat's no-AT_SYMLINK_FOLLOW behavior). The C linkat interposer
 * canonicalizes `from` before calling this when AT_SYMLINK_FOLLOW is set.
 */
int32_t patina_link(const char *from, const char *to);
/*
 * Directory descriptors backing the openat/fdopendir/unlinkat family.
 * patina_diropen opens a read-only deterministic filesystem fd, records its
 * fd->path handle (the caller validates that `path` names a directory and
 * resolves any trailing symlink first), and returns that fd; patina_dirpath
 * recovers the bound path (buf gets a NUL-terminated copy when it fits; returns
 * the length, or -1/EBADF for an unknown fd); patina_dir_is_dirfd tells a dir fd
 * apart from other virtual fds; patina_dirclose releases the mapping and closes
 * the filesystem fd (closedir/close). fdopendir transfers fd ownership into the
 * DIR, so closedir is what calls patina_dirclose.
 */
int32_t patina_diropen(const char *path);
intptr_t patina_dirpath(int32_t fd, char *buf, size_t len);
int32_t patina_dir_is_dirfd(int32_t fd);
int32_t patina_dirclose(int32_t fd);
intptr_t patina_read_link(const char *path, char *buf, size_t len);
/*
 * Canonicalize a guest path to its deterministic absolute form (realpath). On
 * success writes the NUL-terminated canonical path into buf when it fits and
 * returns its length in bytes (excluding the terminator); a negative return sets
 * patina_errno. Resolution is driven entirely by the deterministic filesystem,
 * so both realpath calling conventions receive byte-identical results.
 */
intptr_t patina_canonicalize(const char *path, char *buf, size_t len);
int32_t patina_thread_id(void);
int32_t patina_sched_yield(void);
/*
 * --yield-points guard hook (patina_yield.c): a deterministic scheduling point
 * carrying the instrumented guest site for divergence diagnostics.
 */
void patina_yield_point(const void *site);
int32_t patina_mkdir(const char *path);
int32_t patina_unlink(const char *path);
int32_t patina_rmdir(const char *path);
int32_t patina_rename(const char *from, const char *to);
int32_t patina_crash(void);
/*
 * Capture deterministic stdout (fd 1) or stderr (fd 2) bytes. Captured bytes
 * are flushed to the real host descriptors at patina_shutdown.
 */
intptr_t patina_stdio_write(int32_t fd, const void *source, size_t length);

/*
 * Cooperative-SUT (buggify) surface. Labels and call-site identities are
 * (pointer, length) UTF-8 slices. A fatal always-violation or a duplicate label
 * flushes captured output, emits a distinct marker line, and aborts.
 */
int32_t patina_is_simulated(void);
/* prob_permille < 0 uses the run default. Returns 1 when the site fires. */
int32_t patina_buggify(const uint8_t *label, size_t label_len,
                       const uint8_t *site, size_t site_len, int32_t prob_permille);
int32_t patina_buggify_delay(const uint8_t *label, size_t label_len,
                             const uint8_t *site, size_t site_len);
int64_t patina_buggify_knob(const uint8_t *label, size_t label_len,
                            const uint8_t *site, size_t site_len,
                            int64_t default_value, int64_t lo, int64_t hi);
int32_t patina_always(int32_t condition, const uint8_t *label, size_t label_len,
                      const uint8_t *site, size_t site_len);
int32_t patina_sometimes(int32_t condition, const uint8_t *label, size_t label_len,
                         const uint8_t *site, size_t site_len);
int32_t patina_reachable(const uint8_t *label, size_t label_len,
                         const uint8_t *site, size_t site_len);
uint64_t patina_rng(void);
int32_t patina_lifecycle_setup_complete(void);
int32_t patina_lifecycle_event(const uint8_t *label, size_t label_len);

/*
 * Managed threads and pthread synchronization under the deterministic
 * scheduler. The opt-in POSIX layer routes pthread_create/join/detach/exit,
 * pthread_mutex_*, and pthread_cond_* through these entry points so real host
 * threads execute one at a time under seeded, recorded, and replayed schedule
 * decisions. Handles are the real pthread_t written by patina_thread_create.
 */
int32_t patina_thread_create(void **thread, const void *attr,
                             void *(*start)(void *), void *arg);
int32_t patina_thread_join(void *thread, void **retval);
int32_t patina_thread_detach(void *thread);
void patina_thread_exit(void *retval);
int32_t patina_mutex_init(void *mutex, const void *attr);
int32_t patina_mutex_lock(void *mutex);
int32_t patina_mutex_trylock(void *mutex);
int32_t patina_mutex_unlock(void *mutex);
int32_t patina_mutex_destroy(void *mutex);
int32_t patina_cond_init(void *cond, const void *attr);
int32_t patina_cond_wait(void *cond, void *mutex);
int32_t patina_cond_timedwait(void *cond, void *mutex, const void *abstime);
int32_t patina_cond_signal(void *cond);
int32_t patina_cond_broadcast(void *cond);
int32_t patina_cond_destroy(void *cond);

/*
 * Deterministic pthread_rwlock_* under the scheduler: writer-preferring, FIFO
 * among writers, blocked readers batch-woken when a writer releases with no
 * writer waiting. Handles are identified by the pthread_rwlock_t storage
 * address.
 */
int32_t patina_rwlock_init(void *lock, const void *attr);
int32_t patina_rwlock_rdlock(void *lock);
int32_t patina_rwlock_wrlock(void *lock);
int32_t patina_rwlock_tryrdlock(void *lock);
int32_t patina_rwlock_trywrlock(void *lock);
int32_t patina_rwlock_unlock(void *lock);
int32_t patina_rwlock_destroy(void *lock);

/*
 * Virtual AF_INET sockets over the runtime's SimNet. Descriptors are numbered
 * from PATINA_SOCKET_FD_BASE so the interposed close can route them here;
 * addresses are passed as host-order IPv4 + port. Blocking calls park the
 * calling managed task through the scheduler baton.
 */
#define PATINA_SOCKET_FD_BASE 0x40000000
int32_t patina_net_socket(int32_t stream, int32_t nonblocking);
int32_t patina_net_bind(int32_t fd, uint32_t ip, uint16_t port);
int32_t patina_net_connect(int32_t fd, uint32_t ip, uint16_t port);
int32_t patina_net_listen(int32_t fd, int32_t backlog);
int32_t patina_net_accept(int32_t fd, uint32_t *ip, uint16_t *port);
int32_t patina_net_tcp_connect(int32_t fd, uint32_t ip, uint16_t port);
intptr_t patina_net_sendto(int32_t fd, const void *buf, size_t len, uint32_t ip, uint16_t port);
intptr_t patina_net_send(int32_t fd, const void *buf, size_t len);
intptr_t patina_net_stream_send(int32_t fd, const void *buf, size_t len);
intptr_t patina_net_recvfrom(int32_t fd, void *buf, size_t len, uint32_t *ip, uint16_t *port);
intptr_t patina_net_recv(int32_t fd, void *buf, size_t len);
intptr_t patina_net_stream_recv(int32_t fd, void *buf, size_t len);
int32_t patina_net_shutdown(int32_t fd, int32_t how);
int32_t patina_net_getsockname(int32_t fd, uint32_t *ip, uint16_t *port);
int32_t patina_net_getpeername(int32_t fd, uint32_t *ip, uint16_t *port);
int32_t patina_net_kind(int32_t fd); /* -1 unknown, 0 datagram, 1 unbound stream, 2 listener, 3 stream */
int32_t patina_net_set_nonblocking(int32_t fd, int32_t nonblocking);
/* Set SO_RCVTIMEO in virtual nanoseconds; 0 clears (no timeout). */
int32_t patina_net_set_read_timeout(int32_t fd, uint64_t nanos);
int32_t patina_net_is_nonblocking(int32_t fd);
int32_t patina_net_close(int32_t fd);

/*
 * In-process pipe / socketpair. Both endpoints live inside this one guest
 * process (an async runtime's IO-driver / signal self-pipe), so they are modeled
 * as deterministic in-memory byte channels sharing the virtual-fd space above
 * (numbered from PATINA_SOCKET_FD_BASE) and the same baton/waiter machinery. The
 * interposed read/write/close/dup/fcntl route these fds via
 * patina_pipe_is_endpoint. patina_pipe_dup aliases an endpoint (dup /
 * F_DUPFD[_CLOEXEC]): a channel side reports EOF/EPIPE only once its LAST
 * aliasing fd has closed.
 */
int32_t patina_pipe(int32_t *read_fd_out, int32_t *write_fd_out, int32_t nonblocking);
int32_t patina_socketpair(int32_t *fd0_out, int32_t *fd1_out, int32_t nonblocking);
int32_t patina_pipe_is_endpoint(int32_t fd);
intptr_t patina_pipe_read(int32_t fd, void *buf, size_t len);
intptr_t patina_pipe_write(int32_t fd, const void *buf, size_t len);
int32_t patina_pipe_dup(int32_t fd);
int32_t patina_pipe_close(int32_t fd);
int32_t patina_pipe_is_nonblocking(int32_t fd);
int32_t patina_pipe_set_nonblocking(int32_t fd, int32_t nonblocking);

/*
 * Linux SYS_futex routing. Rust std on Linux implements Mutex/Condvar/thread
 * parking with raw futexes reached through libc's syscall() wrapper; the
 * interposed syscall() delegates FUTEX_WAIT/WAKE here so they run under the
 * deterministic scheduler keyed on the futex word's address.
 */
int32_t patina_futex_wait(uintptr_t addr, uint32_t expected);
/*
 * Timed FUTEX_WAIT/FUTEX_WAIT_BITSET. `clock` is PATINA_CLOCK_MONOTONIC unless
 * FUTEX_CLOCK_REALTIME was set; `absolute` is 0 for a relative FUTEX_WAIT
 * timeout and nonzero for an absolute FUTEX_WAIT_BITSET deadline. Returns 0 when
 * woken by FUTEX_WAKE, or -1 with patina_errno ETIMEDOUT at the deadline or
 * EWOULDBLOCK if the word no longer holds `expected`.
 */
int32_t patina_futex_wait_timed(uintptr_t addr, uint32_t expected, uint32_t clock,
                                int32_t absolute, uint64_t timeout_nanos);
int32_t patina_futex_wake(uintptr_t addr, int32_t count);

/*
 * epoll / eventfd readiness reactor (Linux). The Linux mirror of the macOS
 * kqueue reactor below, over the same shared readiness core. A virtual epoll or
 * eventfd descriptor is drawn from the shared virtual-fd space (numbered from
 * PATINA_SOCKET_FD_BASE); the interposed read/write/close/dup/fcntl route them
 * via patina_epoll_is_epoll / patina_eventfd_is. patina_epoll_create1,
 * patina_epoll_ctl, patina_epoll_wait, and patina_eventfd are SYSCALL-SHAPED —
 * they take the raw epoll_create1/epoll_ctl/epoll_wait/eventfd2 argument forms —
 * so a future syscall-user-dispatch SIGSYS dispatcher can call them with
 * register arguments directly; the C interposers are thin marshaling over them.
 * epoll_ctl/epoll_wait take the platform `struct epoll_event` pointers
 * directly: the Rust side reads/writes the kernel ABI layout (packed on x86_64,
 * natural elsewhere), pinned by _Static_asserts in the C layer.
 */
#ifdef __linux__
int32_t patina_epoll_create1(int32_t flags);
int32_t patina_epoll_is_epoll(int32_t fd);
int32_t patina_epoll_dup(int32_t fd);
int32_t patina_epoll_close(int32_t fd);
int32_t patina_epoll_ctl(int32_t epfd, int32_t op, int32_t fd, const void *event);
/* timeout_ms: -1 blocks until ready, 0 polls, > 0 is a relative virtual-clock
 * deadline in milliseconds. */
int32_t patina_epoll_wait(int32_t epfd, void *events, int32_t maxevents, int32_t timeout_ms);
/*
 * Deterministic in-process eventfd counter (mio's Waker vehicle; the
 * EVFILT_USER analogue). Readable iff the counter is nonzero; always writable —
 * a write that would overflow the kernel's u64-2 bound fails closed loudly
 * instead of modeling a blocked-writer queue.
 */
int32_t patina_eventfd(uint32_t initval, int32_t flags);
int32_t patina_eventfd_is(int32_t fd);
intptr_t patina_eventfd_read(int32_t fd, void *buf, size_t len);
intptr_t patina_eventfd_write(int32_t fd, const void *buf, size_t len);
int32_t patina_eventfd_close(int32_t fd);
#endif

/*
 * libdispatch semaphore routing (macOS). Rust std's Darwin thread Parker blocks
 * on a libdispatch semaphore; the interposed dispatch_time /
 * dispatch_semaphore_create/wait/signal / dispatch_release forward here so
 * std::thread parking (and the mpsc/mpmc/Once paths built on it) run under the
 * deterministic scheduler and virtual clock. dispatch_time returns the relative
 * monotonic token consumed by patina_dispatch_semaphore_wait.
 */
#ifdef __APPLE__
uint64_t patina_dispatch_time(uint64_t when, int64_t delta);
void *patina_dispatch_semaphore_create(intptr_t value);
intptr_t patina_dispatch_semaphore_wait(void *sem, uint64_t timeout);
intptr_t patina_dispatch_semaphore_signal(void *sem);
void patina_dispatch_release(void *object);

/*
 * os_unfair_lock routing (macOS). parking_lot_core's Darwin word lock is a bare
 * u32 with no init call; the deterministic mutex table lazily registers it on
 * first use. Non-recursive: a recursive lock by the owner or an unlock by a
 * non-owner aborts loudly. trylock returns 1 on acquisition, 0 when the lock is
 * already held.
 */
void patina_os_unfair_lock_lock(void *lock);
int32_t patina_os_unfair_lock_trylock(void *lock);
void patina_os_unfair_lock_unlock(void *lock);

/*
 * kqueue / kevent readiness reactor (macOS). A virtual kqueue descriptor is
 * drawn from the shared virtual-fd space (numbered from PATINA_SOCKET_FD_BASE),
 * so the interposed close routes it here via patina_kqueue_is_kq. The C kevent
 * interposers marshal the platform struct kevent/kevent64_s changelists and
 * eventlists to and from this platform-neutral projection; the Rust reactor owns
 * the knote registry, readiness, deterministic event ordering, and the multi-fd
 * fan-in park. `struct patina_kevent` is laid out to match the macOS `struct
 * kevent` field for field (asserted in the C layer), so a kevent eventlist is
 * marshalled by a direct reinterpret and a kevent64_s eventlist field by field.
 */
struct patina_kevent {
    uint64_t ident;
    int16_t filter;
    uint16_t flags;
    uint32_t fflags;
    int64_t data;
    void *udata;
};

int32_t patina_kqueue(void);
int32_t patina_kqueue_is_kq(int32_t fd);
/*
 * Duplicate a kqueue fd: the new fd aliases the SAME registry (tokio's IO driver
 * clones its selector through F_DUPFD_CLOEXEC), which drops only when the last
 * aliasing fd closes.
 */
int32_t patina_kqueue_dup(int32_t fd);
int32_t patina_kqueue_close(int32_t fd);
/*
 * Apply one changelist entry. Returns 0 on success or a POSIX errno the caller
 * places in an EV_ERROR receipt. An EVFILT_USER NOTE_TRIGGER wakes the kq's
 * parked kevent callers. Unmodeled filters fail closed loudly (SIGABRT).
 */
int32_t patina_kqueue_apply(int32_t kq, uint64_t ident, int16_t filter, uint16_t flags,
                            uint32_t fflags, int64_t data, uintptr_t udata);
/*
 * Gather up to `nevents` ready events into `out`, blocking per `mode`:
 * 0 = non-blocking poll, 1 = block until ready, 2 = block until `timeout_nanos`
 * of virtual time elapse. Returns the event count (>= 0) or -1 with patina_errno.
 */
int32_t patina_kevent_gather(int32_t kq, struct patina_kevent *out, int32_t nevents,
                             int32_t mode, uint64_t timeout_nanos);
#endif

#ifdef __cplusplus
}
#endif

#endif
