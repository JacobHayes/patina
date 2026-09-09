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
    /* O_NOFOLLOW: when the final component turns out to be a symlink, refuse
     * with ELOOP instead of resolving it and opening the target. */
    PATINA_O_NOFOLLOW = 1u << 6,
    /* O_NONBLOCK: a no-op on every kind but a FIFO, where it decides whether the
     * open waits for the opposite end (blocking) or answers at once — success
     * for a reader, ENXIO for a writer with no reader. */
    PATINA_O_NONBLOCK = 1u << 7,
    /* O_PATH: name a LOCATION without opening the file behind it. The kernel
     * ignores the access mode under it, so it never travels with
     * PATINA_O_READ/PATINA_O_WRITE, and it charges nothing on the entry itself
     * (only the search walk of the path prefix) where a plain read-only open of
     * a directory charges `r`. The descriptor resolves *at paths, answers fstat
     * and readlinkat, dups and closes -- and refuses every read, write, seek,
     * fsync, fchmod and directory listing. */
    PATINA_O_PATH = 1u << 8,
    /* O_CLOEXEC: FD_CLOEXEC on the NUMBER the open mints. Neither a driver flag
     * nor a status flag: it lives on the descriptor-table slot, so a dup of the
     * descriptor does not carry it and F_GETFD/F_SETFD read and write it. */
    PATINA_O_CLOEXEC = 1u << 9,
    /* Reported by patina_fd_getfl, never accepted by patina_open: the description
     * was minted by open(2). A 64-bit Linux kernel forces O_LARGEFILE into such a
     * description's F_GETFL (and into no pipe's, socket's or O_PATH handle's), so
     * the C and SUD F_GETFL translate this bit to O_LARGEFILE there. */
    PATINA_O_OPENED = 1u << 10,
};

/*
 * What a guest descriptor NAMES: the answer of patina_fd_kind, the one oracle
 * the C interposers and the SUD rows consult when a call's meaning depends on
 * the kind of object behind a number (a socket op on a file is ENOTSOCK, a *at
 * dirfd must be PATINA_FD_DIR, mmap of a pipe is ENODEV). Every other question
 * about a descriptor -- its FD_CLOEXEC bit, its status flags, duplication,
 * closing, reading, writing -- is answered by the universal patina_* entries
 * below, which resolve the number themselves. The shim owns ONE table for all
 * of these: guest numbers are allocated lowest-free with holes, as a kernel
 * allocates them, refcount an open file description, and are never recorded.
 */
enum {
    PATINA_FD_STDIN = 0,   /* the guest's standard input: EOF, not a terminal */
    PATINA_FD_STDOUT = 1,  /* captured standard output */
    PATINA_FD_STDERR = 2,  /* captured standard error */
    PATINA_FD_FILE = 3,    /* a deterministic-filesystem file */
    PATINA_FD_DIR = 4,     /* a directory descriptor (O_DIRECTORY, with or without O_PATH) */
    PATINA_FD_OPATH = 5,   /* an O_PATH descriptor on a non-directory */
    PATINA_FD_URANDOM = 6, /* the /dev/urandom device */
    PATINA_FD_SOCKET = 7,  /* a virtual AF_INET socket */
    PATINA_FD_PIPE = 8,    /* a pipe / socketpair / FIFO endpoint */
    PATINA_FD_EVENTFD = 9, /* an eventfd counter (Linux) */
    PATINA_FD_EPOLL = 10,  /* an epoll instance (Linux) */
    PATINA_FD_KQUEUE = 11, /* a kqueue (Darwin) */
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
 * Record the guest's OWN exit status, before patina's atexit finalization can
 * replace it (a finalization failure aborts, and SIGABRT would be all that
 * survives). Called from the __libc_start_main wrapper when the guest's `main`
 * returns and from patina_exit for an explicit exit(3). First call wins.
 */
void patina_note_guest_exit_status(int32_t status);
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
/*
 * Open a path in the deterministic filesystem, returning a fresh guest
 * descriptor number. A FIFO answers with a PATINA_FD_PIPE descriptor, because a
 * named pipe's bytes are not filesystem state; /dev/urandom with a
 * PATINA_FD_URANDOM one. PATINA_O_CLOEXEC sets FD_CLOEXEC on the number.
 */
/*
 * `mode` is POSIX open(2)'s third argument: the creation mode, read only when
 * the flags can create the entry. A caller without PATINA_O_CREATE passes 0, so
 * the recorded operation carries no argument the kernel would not have read.
 */
int32_t patina_open(const char *path, uint32_t flags, uint32_t mode);
/*
 * The universal descriptor operations: each resolves the guest number once and
 * dispatches on what it names, answering what the kernel answers for a kind
 * that has no such operation (ESPIPE for a positional op or lseek on a pipe,
 * EINVAL for fsync/ftruncate on one, EBADF for an empty slot). The C read/
 * write/close/... interposers and the SUD rows call these and nothing else, so
 * the two doors share one decode.
 */
intptr_t patina_read(int32_t fd, void *destination, size_t length);
intptr_t patina_write(int32_t fd, const void *source, size_t length);
intptr_t patina_pread(int32_t fd, void *destination, size_t length, int64_t offset);
intptr_t patina_pwrite(int32_t fd, const void *source, size_t length, int64_t offset);
int32_t patina_close(int32_t fd);
int64_t patina_seek(int32_t fd, int64_t offset, uint32_t whence);
int32_t patina_fsync(int32_t fd);
int32_t patina_set_len(int32_t fd, uint64_t length);
/*
 * Advisory whole-file lock (flock(2)). `operation` is LOCK_SH/LOCK_EX/LOCK_UN
 * optionally OR'd with LOCK_NB. The lock belongs to the open file DESCRIPTION
 * (a dup of the holder shares and can release it) and is keyed on the
 * deterministic-fs inode: a lone opener always acquires, while an incompatible
 * lock held on a different description of the same file yields EWOULDBLOCK
 * (LOCK_NB) so a guest that opens the same file twice contends as it would on
 * a real kernel. The lock clears on LOCK_UN and with the description.
 */
int32_t patina_flock(int32_t fd, int32_t operation);
/*
 * The descriptor table itself. patina_fd_kind answers PATINA_FD_* or -1/EBADF.
 * patina_fd_limit is RLIMIT_NOFILE as the table enforces it (EMFILE at and
 * above it), the number getrlimit and sysconf(_SC_OPEN_MAX) must report.
 * F_GETFD/F_SETFD read and write the number's FD_CLOEXEC bit; F_GETFL/F_SETFL
 * read and write the description's status flags in the PATINA_O_* vocabulary
 * (access mode, PATINA_O_APPEND, PATINA_O_NONBLOCK, PATINA_O_PATH; only the
 * first two are settable, as the kernel ignores the rest of an F_SETFL
 * argument); patina_fd_set_nonblocking flips PATINA_O_NONBLOCK alone (FIONBIO,
 * SOCK_NONBLOCK on accept).
 */
int32_t patina_fd_kind(int32_t fd);
int32_t patina_fd_limit(void);
int32_t patina_fd_getfd(int32_t fd);
int32_t patina_fd_setfd(int32_t fd, int32_t cloexec);
int32_t patina_fd_getfl(int32_t fd);
int32_t patina_fd_setfl(int32_t fd, uint32_t flags);
int32_t patina_fd_set_nonblocking(int32_t fd, int32_t nonblocking);
/*
 * Duplication and closing, kernel semantics: dup binds the lowest free number;
 * F_DUPFD[_CLOEXEC] the lowest free at or above `minimum` (EINVAL outside the
 * table, EMFILE when none is free); dup2/dup3 bind a CHOSEN number, closing
 * what it named (dup2 of equal numbers validates and returns it, dup3 of equal
 * numbers is EINVAL; a target outside the table is EBADF). close frees the
 * number and, with its last number, the description; close_range covers
 * [first, last] (clamped to the table), or with CLOSE_RANGE_CLOEXEC marks the
 * range close-on-exec instead.
 */
int32_t patina_dup(int32_t fd);
int32_t patina_dupfd(int32_t fd, int32_t minimum, int32_t cloexec);
int32_t patina_dup2(int32_t oldfd, int32_t newfd);
int32_t patina_dup3(int32_t oldfd, int32_t newfd, int32_t cloexec);
int32_t patina_close_range(uint32_t first, uint32_t last, uint32_t flags);
/*
 * A hidden reference on a descriptor's description -- what a file-backed
 * mapping holds so its writeback survives the guest closing the number, as the
 * kernel's mapping holds the struct file. patina_fd_retain returns the
 * description id (or -1/EBADF); patina_desc_pwrite is pwrite through it;
 * patina_desc_release drops it, freeing the description with its last
 * reference exactly as the last close would.
 */
int64_t patina_fd_retain(int32_t fd);
intptr_t patina_desc_pwrite(int64_t desc, const void *source, size_t length, int64_t offset);
int32_t patina_desc_release(int64_t desc);
enum {
    PATINA_ENTRY_FILE = 1,
    PATINA_ENTRY_DIRECTORY = 2,
    PATINA_ENTRY_SYMLINK = 3,
    /* A named pipe. The ENTRY is filesystem state (it stats, renames, unlinks
     * like any other name); the bytes flowing through it are not, so one always
     * reports length 0. */
    PATINA_ENTRY_FIFO = 4,
};

int32_t patina_metadata(const char *path, uint32_t *kind, uint64_t *length);
int32_t patina_fd_metadata(int32_t fd, uint32_t *kind, uint64_t *length);
/*
 * `mode` receives the POSIX permission bits (0o7777) WITHOUT the file-type bits,
 * which `kind` already carries: a caller assembling a struct stat ORs the two.
 */
int32_t patina_metadata_full(const char *path, uint32_t *kind, uint64_t *length,
                             uint64_t *ino, uint32_t *nlink,
                             uint64_t *atime_nanos, uint64_t *mtime_nanos,
                             uint32_t *mode);
int32_t patina_fd_metadata_full(int32_t fd, uint32_t *kind, uint64_t *length,
                                uint64_t *ino, uint32_t *nlink,
                                uint64_t *atime_nanos, uint64_t *mtime_nanos,
                                uint32_t *mode);
/*
 * Change an entry's permission bits (chmod/fchmod/fchmodat). `follow` selects
 * the trailing-symlink behavior exactly as patina_diropen's does: follow != 0
 * resolves a trailing symlink and changes its TARGET (chmod, fchmodat with no
 * flags), follow == 0 names the link itself and is EOPNOTSUPP on one, because
 * Linux has no way to change a symlink's mode. Only the permission bits of
 * `mode` are stored.
 */
int32_t patina_chmod(const char *path, uint32_t mode, int32_t follow);
int32_t patina_fchmod(int32_t fd, uint32_t mode);
/*
 * Snapshot a directory for readdir/getdents iteration. Takes the open directory
 * DESCRIPTOR, not a name: the `r` it costs was charged when the descriptor was
 * opened, so a later chmod cannot break a walk already under way, a rename
 * cannot redirect it, and an O_PATH descriptor (which opened nothing) cannot
 * iterate at all.
 */
int32_t patina_read_dir(int32_t fd, void **state);
/*
 * Return 1 after writing the next entry, 0 at end-of-directory, or -1 with
 * patina_errno set. name_buf receives a NUL-terminated entry name.
 */
int32_t patina_read_dir_next(void *state, char *name_buf, size_t buf_len, uint32_t *kind);
void patina_read_dir_free(void *state);
/*
 * Create a named pipe (mkfifo/mkfifoat, and mknod/mknodat with S_IFIFO). Only
 * the NAME is created: the pipe behind it comes into existence when the first
 * descriptor opens the FIFO and is released with the last. `mode` is the
 * caller's requested mode and the deterministic filesystem applies its modeled
 * umask, exactly as the kernel applies the process umask.
 */
int32_t patina_mkfifo(const char *path, uint32_t mode);
int32_t patina_symlink(const char *target, const char *link_path);
/*
 * Create a hard link. Mirrors patina_symlink: the driver shares one inode
 * between `from` and `to`, or duplicates the symlink entry when `from` is itself
 * a symlink (linkat's no-AT_SYMLINK_FOLLOW behavior). The C linkat interposer
 * canonicalizes `from` before calling this when AT_SYMLINK_FOLLOW is set.
 */
int32_t patina_link(const char *from, const char *to);
/*
 * Directory descriptors backing the openat/fdopendir/unlinkat/getdents64 family.
 * patina_diropen VALIDATES that `path` names a directory, opens a read-only
 * deterministic filesystem handle, binds it to a fresh guest number of kind
 * PATINA_FD_DIR and returns the number (`cloexec` sets FD_CLOEXEC on it).
 * `follow` selects the trailing-symlink behavior (0 == O_NOFOLLOW): a symlink
 * with follow==0 is ELOOP, with follow!=0 it is resolved through the virtual
 * realpath and re-checked; a non-directory is ENOTDIR. Validation lives here so
 * the C interposers and the SUD dispatcher cannot drift.
 * patina_dirpath answers where the descriptor's NODE is NOW: it asks the
 * deterministic filesystem, which moves an open description with its inode
 * through every rename, rather than replaying the name the descriptor was
 * opened under (buf gets a NUL-terminated copy when it fits; returns the
 * length, or -1/EBADF for an unknown fd). It is the dirfd->path half of *at
 * resolution on both the libc and raw-syscall paths, so a renamed directory
 * keeps serving the descriptor and a symlink planted at the vacated name is
 * never followed;
 * `path_only` is O_PATH: the descriptor names the location and never opens the
 * directory, so it costs nothing on the entry and cannot be iterated, where a
 * plain (path_only == 0) directory open costs `r` and can (the description's
 * PATINA_O_PATH status bit tells the two apart). A directory descriptor dups
 * and closes through the universal entries like any other; every DIR owns a
 * number, so closedir is a patina_close.
 */
int32_t patina_diropen(const char *path, int32_t follow, int32_t path_only, int32_t cloexec);
intptr_t patina_dirpath(int32_t fd, char *buf, size_t len);
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
/* `mode` is mkdir(2)'s creation mode; the driver applies the modeled umask. */
int32_t patina_mkdir(const char *path, uint32_t mode);
int32_t patina_unlink(const char *path);
int32_t patina_rmdir(const char *path);
int32_t patina_rename(const char *from, const char *to);
int32_t patina_crash(void);
/*
 * Append to the captured stdout (`sink` 1) or stderr (`sink` 2) STREAM -- the
 * runtime's own diagnostics use this directly so a guest's dup2 over number 1
 * or 2 never redirects them. A guest write to number 1 or 2 goes through
 * patina_write, which reaches the same sink while the number still names it.
 * Captured bytes are flushed to the real host descriptors at patina_shutdown.
 */
intptr_t patina_stdio_write(int32_t sink, const void *source, size_t length);

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
 * Verdict ABI: one verb, kinds as data. A guest reports what it concluded about
 * its own run; the runtime records the call in the trace and emits a
 * PATINA_VERDICT line. `label` aggregates verdicts (it shares the SDK site label
 * namespace); `detail` is optional UTF-8, JSON by convention, recorded verbatim.
 * An unrecognized `kind` is refused with EINVAL rather than defaulted.
 * Kinds are pinned by patina_dst_abi::VerdictKind::as_abi.
 */
#define PATINA_VERDICT_VIOLATION 1u
#define PATINA_VERDICT_PASS 2u
#define PATINA_VERDICT_ABORT_INTENT 3u
int32_t patina_verdict(uint32_t kind, const uint8_t *label, size_t label_len,
                       const uint8_t *detail, size_t detail_len);

/*
 * Custom-operation ABI: three verbs, one per phase of a single operation. A
 * custom op is a guest-declared effect Patina does not model; the guest wraps it
 * at a boundary it controls so Patina can record the result and reproduce it on
 * replay. `label` names the op class (it shares the SDK site-label namespace,
 * registers no site, and may name many calls in a run); `key` is the operation's
 * logical input, recorded so replay can assert the guest asked the same
 * question. Both are opaque bytes here: the SDK owns the encoding, the ABI does
 * not.
 *
 *   1. patina_custom_op_begin(...)
 *        -> PATINA_CUSTOM_OP_RECORD: run the real effect, then call
 *           patina_custom_op_record with its result bytes.
 *        -> PATINA_CUSTOM_OP_REPLAY: the answer is recorded; do NOT run the real
 *           effect. *out_len is its length; fetch it with
 *           patina_custom_op_replay_result.
 *        -> -1 (errno EINVAL) for a malformed argument.
 *   2a. patina_custom_op_record returns 0, or -1 for a malformed argument.
 *   2b. patina_custom_op_replay_result returns the number of bytes written, or
 *       -1 (errno EINVAL) when out_cap is smaller than the reported length —
 *       nothing is copied and the operation stays open, so a retry with a large
 *       enough buffer still succeeds.
 *
 * Every runtime-level refusal (a replay divergence on the label or key, a nested
 * or unclosed operation, a modeled effect performed between the two halves) is
 * fatal: the shim emits PATINA_CUSTOM_OP_REFUSED and aborts, because there is no
 * answer the guest could safely be handed.
 */
#define PATINA_CUSTOM_OP_RECORD 0
#define PATINA_CUSTOM_OP_REPLAY 1
int32_t patina_custom_op_begin(const uint8_t *label, size_t label_len,
                               const uint8_t *key, size_t key_len,
                               size_t *out_len);
intptr_t patina_custom_op_replay_result(uint8_t *out, size_t out_cap);
int32_t patina_custom_op_record(const uint8_t *result, size_t result_len);

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
 * Virtual AF_INET sockets over the runtime's SimNet. Every entry takes a guest
 * descriptor number and answers ENOTSOCK for one that is not PATINA_FD_SOCKET;
 * addresses are passed as host-order IPv4 + port. Blocking calls park the
 * calling managed task through the scheduler baton. patina_net_accept's
 * `nonblocking`/`cloexec` are accept4's SOCK_NONBLOCK/SOCK_CLOEXEC for the NEW
 * descriptor.
 */
int32_t patina_net_socket(int32_t stream, int32_t nonblocking, int32_t cloexec);
int32_t patina_net_bind(int32_t fd, uint32_t ip, uint16_t port);
int32_t patina_net_connect(int32_t fd, uint32_t ip, uint16_t port);
int32_t patina_net_listen(int32_t fd, int32_t backlog);
int32_t patina_net_accept(int32_t fd, uint32_t *ip, uint16_t *port, int32_t nonblocking,
                          int32_t cloexec);
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
int32_t patina_net_kind(int32_t fd); /* -1 not a socket, 0 datagram, 1 unbound stream, 2 listener, 3 stream */
/* Set SO_RCVTIMEO in virtual nanoseconds; 0 clears (no timeout). */
int32_t patina_net_set_read_timeout(int32_t fd, uint64_t nanos);
/*
 * Resolve a host name to a virtual IPv4 address (host byte order) through the
 * run's deterministic DNS host table. Returns 0 and writes *ip on success; on
 * failure returns -1 and sets errno (ENOENT for a name that does not resolve,
 * EINTR for an injected resolver timeout). Backs getaddrinfo; gethostbyname and
 * getnameinfo stay refused.
 */
int32_t patina_dns_resolve(const char *name, uint32_t *ip);

/*
 * In-process pipe / socketpair. Both endpoints live inside this one guest
 * process (an async runtime's IO-driver / signal self-pipe), so they are modeled
 * as deterministic in-memory byte channels, PATINA_FD_PIPE descriptions on the
 * same baton/waiter machinery the sockets use. The two numbers are allocated
 * atomically (one free slot is EMFILE and creates nothing). A dup of an endpoint
 * shares its description: a channel side reports EOF/EPIPE only once its LAST
 * number has closed. patina_pipe_read/write are the recv/send face of a
 * socketpair end (read/write reach the same transfer through patina_read/
 * patina_write); patina_pipe_size / patina_pipe_set_size are F_GETPIPE_SZ /
 * F_SETPIPE_SZ (page-rounded to a power of two, 64 KiB by default, EBUSY below
 * the bytes buffered, EPERM above the unprivileged maximum).
 */
int32_t patina_pipe(int32_t *read_fd_out, int32_t *write_fd_out, int32_t nonblocking,
                    int32_t cloexec);
int32_t patina_socketpair(int32_t *fd0_out, int32_t *fd1_out, int32_t nonblocking,
                          int32_t cloexec);
intptr_t patina_pipe_read(int32_t fd, void *buf, size_t len);
intptr_t patina_pipe_write(int32_t fd, const void *buf, size_t len);
int32_t patina_pipe_size(int32_t fd);
int32_t patina_pipe_set_size(int32_t fd, int32_t size);

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
 * kqueue reactor below, over the same shared readiness core. An epoll instance
 * is a PATINA_FD_EPOLL description, an eventfd a PATINA_FD_EVENTFD one; read/
 * write/close/dup/fcntl reach them through the universal entries.
 * patina_epoll_create1, patina_epoll_ctl, patina_epoll_wait, and patina_eventfd
 * are SYSCALL-SHAPED — they take the raw epoll_create1/epoll_ctl/epoll_wait/
 * eventfd2 argument forms — so the syscall-user-dispatch rows call them with
 * register arguments directly; the C interposers are thin marshaling over them.
 * epoll_ctl answers the kernel's errnos (EBADF/EINVAL/EPERM/EEXIST/ENOENT) and
 * models EPOLLET and EPOLLONESHOT. epoll_ctl/epoll_wait take the platform
 * `struct epoll_event` pointers directly: the Rust side reads/writes the kernel
 * ABI layout (packed on x86_64, natural elsewhere), pinned by _Static_asserts
 * in the C layer.
 */
#ifdef __linux__
int32_t patina_epoll_create1(int32_t flags);
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
 * kqueue / kevent readiness reactor (macOS). A kqueue is a PATINA_FD_KQUEUE
 * description (close-on-exec from birth, as xnu makes it); close/dup/fcntl
 * reach it through the universal entries. The C kevent interposers marshal the platform struct kevent/kevent64_s changelists and
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

/*
 * Timestamp-counter trap (x86-64 Linux). The shim arms
 * prctl(PR_SET_TSC, PR_TSC_SIGSEGV) so `rdtsc`/`rdtscp` raise a synchronous
 * SIGSEGV, and the handler answers them from the run's virtual clock. These are
 * the dispatch outcomes shared by the C handler and src/tsc.rs: the faulting
 * instruction is not a counter read (the fault is genuine and must be taken),
 * `rdtsc`, or `rdtscp` (which also reports IA32_TSC_AUX in ECX).
 */
#define PATINA_TSC_NONE 0
#define PATINA_TSC_RDTSC 1
#define PATINA_TSC_RDTSCP 2

#ifdef __cplusplus
}
#endif

#endif
