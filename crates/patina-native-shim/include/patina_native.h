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
void patina_control_set_entry(const char *entry);
int32_t patina_shutdown(void);
int32_t patina_errno(void);
int32_t patina_entropy(void *destination, size_t length);
int32_t patina_clock_now(uint32_t clock, uint64_t *nanos);
int32_t patina_sleep_until(uint32_t clock, uint64_t deadline_nanos);
int32_t patina_open(const char *path, uint32_t flags);
intptr_t patina_read(int32_t fd, void *destination, size_t length);
intptr_t patina_write(int32_t fd, const void *source, size_t length);
int32_t patina_close(int32_t fd);
int32_t patina_dup(int32_t fd);
int64_t patina_seek(int32_t fd, int64_t offset, uint32_t whence);
int32_t patina_fsync(int32_t fd);
int32_t patina_set_len(int32_t fd, uint64_t length);
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
intptr_t patina_read_link(const char *path, char *buf, size_t len);
int32_t patina_thread_id(void);
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
int32_t patina_net_is_nonblocking(int32_t fd);
int32_t patina_net_close(int32_t fd);

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

#ifdef __cplusplus
}
#endif

#endif
