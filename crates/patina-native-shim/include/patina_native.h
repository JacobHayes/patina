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
    /* Reported by patina_fd_getfl, never accepted by patina_openat: the description
     * was minted by open(2). A 64-bit Linux kernel forces O_LARGEFILE into such a
     * description's F_GETFL (and into no pipe's, socket's or O_PATH handle's), so
     * the C and SUD F_GETFL translate this bit to O_LARGEFILE there. */
    PATINA_O_OPENED = 1u << 10,
    /* The entry must be a directory (ENOTDIR otherwise). Not a driver flag: the
     * resolver already knows the entry's kind, and a directory is opened as a
     * directory descriptor whether or not the caller asked. */
    PATINA_O_DIRECTORY = 1u << 11,
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
    PATINA_FD_SIGNALFD = 12, /* a virtual signal queue reader (Linux) */
    PATINA_FD_MQUEUE = 13,   /* a POSIX message queue (Linux) */
    PATINA_FD_TIMERFD = 14,  /* a timer descriptor (Linux) */
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
/* POSIX-link startup only: installs panic containment, not a Context. */
void patina_init_panic_policy(void);
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
 * before patina_host_abort() so the guest's output and the deny diagnostic reach the
 * operator even though the private fatal vehicle skips the atexit-driven shutdown flush.
 */
int32_t patina_flush_captured_stdio(void);
int32_t patina_errno(void);
int32_t patina_entropy(void *destination, size_t length);
/* getrandom(2) over the seeded stream: the byte count, or -1/EINVAL for a flag
 * word the Linux kernel refuses (GRND_* outside NONBLOCK|RANDOM|INSECURE, or
 * INSECURE with RANDOM). */
intptr_t patina_getrandom(void *destination, size_t length, uint32_t flags);
int32_t patina_clock_now(uint32_t clock, uint64_t *nanos);
int32_t patina_sleep_until(uint32_t clock, uint64_t deadline_nanos);
int patina_sleep_until_remaining(uint32_t clock_id, uint64_t deadline_nanos, int64_t *remaining);
/*
 * The process's virtual CPU time in nanoseconds, for the Darwin resource
 * accounting interposers (`getrusage`/`task_info`): the modeled startup cost
 * plus what the runtime's advance-on-spin rescues charged, read UNRECORDED. Always succeeds writing a value: 0 before a
 * runtime is installed (allocator bootstrap / run outside the supervisor) so
 * an accounting read never forces init or aborts. Pure function of simulation
 * state: identical across same-seed runs, monotonic within a run.
 */
int32_t patina_cpu_time_nanos(uint64_t *nanos);
#ifdef __linux__
/*
 * The clocks (Linux): every clock id decoded once, in Rust (`src/clocks.rs`),
 * for both doors. Each answers 0 or -errno; a NULL `time` is EFAULT to
 * clock_gettime, a NULL `rem` is not written. `patina_clock_nanosleep` takes
 * the kernel's flags (TIMER_ABSTIME) and writes the time left of an
 * interrupted relative sleep.
 */
struct timespec;
int64_t patina_clock_gettime(int clock, struct timespec *time);
int64_t patina_clock_nanosleep(int clock, int flags, const struct timespec *request,
                               struct timespec *remain);
#endif
/*
 * Path resolution. Every entry below that takes a (dirfd, path) pair resolves
 * it through ONE resolver in the runtime: the working directory for
 * PATINA_AT_FDCWD (the Linux AT_FDCWD value; the C layer maps its platform's
 * spelling onto it), a directory descriptor's NODE for any other dirfd (EBADF
 * for a number that names nothing, ENOTDIR for a non-directory), `.`/`..`
 * applied to the resolved directory after symlink expansion, symlinks walked
 * to the kernel's 40-hop ELOOP limit, ENAMETOOLONG past PATH_MAX/NAME_MAX,
 * ENOTDIR for a component resolved through a non-directory, and the
 * trailing-slash rule. PATINA_RESOLVE_NOFOLLOW names a trailing symlink
 * itself; PATINA_RESOLVE_EMPTY_PATH lets an empty path name the base (the
 * AT_EMPTY_PATH form), where it is otherwise ENOENT. The restrictions only
 * patina_openat2 takes (openat2's RESOLVE_*): BENEATH refuses leaving the base
 * (a `..` out of it, an absolute path or symlink: EXDEV); IN_ROOT makes the
 * base the root; NO_SYMLINKS refuses any symlink (ELOOP); NO_XDEV refuses
 * leaving the volume (/dev/urandom: EXDEV); CACHED refuses a creating or
 * truncating open (EAGAIN).
 */
#define PATINA_AT_FDCWD (-100)
enum {
    PATINA_RESOLVE_NOFOLLOW = 1u << 0,
    PATINA_RESOLVE_EMPTY_PATH = 1u << 1,
    PATINA_RESOLVE_BENEATH = 1u << 2,
    PATINA_RESOLVE_IN_ROOT = 1u << 3,
    PATINA_RESOLVE_NO_SYMLINKS = 1u << 4,
    PATINA_RESOLVE_NO_XDEV = 1u << 5,
    PATINA_RESOLVE_CACHED = 1u << 6,
};
/*
 * The resolver itself, for the callers that want the canonical NAME
 * (realpath). Writes the NUL-terminated canonical path into buf when it fits
 * and returns its length (excluding the terminator; ERANGE when len is nonzero
 * and too small); *kind receives the final entry's PATINA_ENTRY_* kind, or 0
 * when the final component does not exist.
 */
intptr_t patina_resolve_path(int32_t dirfd, const char *path, uint32_t flags, char *buf,
                             size_t len, uint32_t *kind);
/*
 * The working directory and the umask: process state the shim keeps, like the
 * environment map. patina_getcwd copies the directory's CURRENT name (it is a
 * node, so a rename of an ancestor moves it) NUL-terminated into buf when it
 * fits and returns the length (ERANGE otherwise; len == 0 reports the length
 * alone; ENOENT once the directory is unlinked). patina_chdir resolves
 * (dirfd, path) with symlinks followed (ENOENT/ENOTDIR/EACCES as chdir(2));
 * patina_fchdir takes a directory descriptor (EBADF/ENOTDIR). patina_umask
 * installs a new mask and returns the previous one; every creating entry
 * applies it before the driver call, so the driver stores what the kernel
 * would store.
 */
intptr_t patina_getcwd(char *buf, size_t len);
int32_t patina_chdir(int32_t dirfd, const char *path);
int32_t patina_fchdir(int32_t fd);
uint32_t patina_umask(uint32_t mask);
/*
 * openat(2): open what (dirfd, path) resolves to, returning a fresh guest
 * descriptor number. The entry's KIND decides the description: a regular file,
 * a directory (with or without PATINA_O_DIRECTORY, and PATINA_FD_DIR either
 * way), an O_PATH location, /dev/urandom (PATINA_FD_URANDOM), or a FIFO's pipe
 * endpoint (PATINA_FD_PIPE, because a named pipe's bytes are not filesystem
 * state). PATINA_O_NOFOLLOW leaves a trailing symlink unresolved, which is
 * ELOOP (PATINA_O_PATH|PATINA_O_NOFOLLOW on one is a named deny: no descriptor
 * names a link entry). PATINA_O_CLOEXEC sets FD_CLOEXEC on the number.
 * `mode` is POSIX open(2)'s third argument: the creation mode, read only when
 * the flags can create the entry and applied under the process umask. A caller
 * without PATINA_O_CREATE passes 0, so the recorded operation carries no
 * argument the kernel would not have read.
 */
int32_t patina_openat(int32_t dirfd, const char *path, uint32_t flags, uint32_t mode);
/*
 * openat2(2) past its struct open_how checks: patina_openat with the
 * resolution restricted by `resolve` (PATINA_RESOLVE_BENEATH, _IN_ROOT,
 * _NO_SYMLINKS, _NO_XDEV, _CACHED; any other bit is EINVAL).
 */
#ifdef __linux__
int32_t patina_openat2(int32_t dirfd, const char *path, uint32_t flags, uint32_t mode,
                       uint32_t resolve);
#endif
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
/*
 * Vectored I/O over a `struct iovec` array of `count` segments: readv/writev at
 * the cursor, preadv/pwritev at `offset` (which never moves the cursor). The
 * vector is judged as the kernel's lib/iov_iter.c judges it (a count past
 * UIO_MAXIOV or negative, and a segment length negative as an ssize_t, are
 * EINVAL; a NULL vector with a count is EFAULT) after the descriptor and its
 * access mode. `flags` are the Linux RWF_* bits of preadv2/pwritev2 (0 for the
 * plain rows): an unknown bit is EOPNOTSUPP, RWF_NOWAIT never waits,
 * RWF_APPEND writes at the end, RWF_DSYNC/RWF_SYNC make the bytes durable.
 */
intptr_t patina_readv(int32_t fd, const void *vector, int64_t count, int32_t flags);
intptr_t patina_writev(int32_t fd, const void *vector, int64_t count, int32_t flags);
intptr_t patina_preadv(int32_t fd, const void *vector, int64_t count, int64_t offset,
                       int32_t flags);
intptr_t patina_pwritev(int32_t fd, const void *vector, int64_t count, int64_t offset,
                        int32_t flags);
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
 * ioctl(2)'s generic descriptor requests, `request` in the platform's own
 * numbering: FIOCLEX/FIONCLEX set/clear FD_CLOEXEC, FIONBIO reads an int
 * through `arg` (EFAULT for NULL) into the description's O_NONBLOCK, FIONREAD
 * writes an int (a regular file's size minus its position, a pipe's queued
 * bytes; EFAULT for NULL). An O_PATH descriptor is EBADF; any other request,
 * and FIONREAD on a descriptor with no such answer, is ENOTTY.
 */
int32_t patina_ioctl(int32_t fd, uint64_t request, void *arg);
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
#ifdef __linux__
/* The kernel's O_LARGEFILE bit for the target architecture (the uapi value the
 * SUD dispatcher reports), which F_GETFL carries for a PATINA_O_OPENED
 * description. glibc defines its O_LARGEFILE macro as 0 on 64-bit targets. */
extern const int32_t PATINA_KERNEL_O_LARGEFILE;
#endif
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
 * Memory mappings (src/mem.rs), the one model the C mmap/mmap64/munmap/mremap/
 * msync interposers and the SUD rows share. Each answers in the raw syscall
 * ABI: the address (or 0) on success, -errno on failure. An anonymous mapping
 * is host address space; a mapping of a deterministic-filesystem file is a
 * view of that file's page cache, coherent with read/write through every
 * descriptor on the file.
 */
int64_t patina_mmap(uintptr_t addr, size_t length, int32_t prot, int32_t flags, int32_t fd,
                    int64_t offset);
int64_t patina_munmap(uintptr_t addr, size_t length);
int64_t patina_mremap(uintptr_t old_addr, size_t old_length, size_t new_length, uintptr_t flags,
                      uintptr_t new_addr);
int64_t patina_msync(uintptr_t addr, size_t length, int32_t flags);
int64_t patina_mprotect(uintptr_t addr, size_t length, int32_t prot);
/*
 * Memory locks against the virtual RLIMIT_MEMLOCK (never the host's): mlock
 * and mlock2 (flags: MLOCK_ONFAULT), munlock, mlockall, munlockall.
 */
int64_t patina_mlock(uintptr_t addr, size_t length, uint32_t flags);
int64_t patina_munlock(uintptr_t addr, size_t length);
int64_t patina_mlockall(int32_t flags);
int64_t patina_munlockall(void);
/*
 * prlimit64 of the virtual process (pid 0 or 1): the old limits into `old`
 * when non-NULL, then `new` when non-NULL. 0 or -errno.
 */
struct patina_rlimit {
    uint64_t cur;
    uint64_t max;
};
int64_t patina_prlimit(int32_t pid, uint32_t resource, const struct patina_rlimit *new_limit,
                       struct patina_rlimit *old_limit);
/*
 * Anonymous files (src/mem.rs): memfd_create over the deterministic
 * filesystem, and the fcntl seal commands (F_GET_SEALS answers the seals,
 * F_ADD_SEALS adds them). Each returns -1 with patina_errno() on failure.
 */
int32_t patina_memfd_create(const char *name, uint32_t flags);
int32_t patina_get_seals(int32_t fd);
int32_t patina_add_seals(int32_t fd, uint32_t seals);
enum {
    PATINA_ENTRY_FILE = 1,
    PATINA_ENTRY_DIRECTORY = 2,
    PATINA_ENTRY_SYMLINK = 3,
    /* A named pipe. The ENTRY is filesystem state (it stats, renames, unlinks
     * like any other name); the bytes flowing through it are not, so one always
     * reports length 0. */
    PATINA_ENTRY_FIFO = 4,
    /* A socket node: mknod(S_IFSOCK), or a socketpair end's sockfs inode. */
    PATINA_ENTRY_SOCKET = 5,
    /* A character device: the whiteout (0:0) mknod(S_IFCHR, 0) and
     * renameat2(RENAME_WHITEOUT) leave. */
    PATINA_ENTRY_CHAR = 6,
};

/*
 * The filesystem a node is on (`fs` of struct patina_metadata), which decides
 * the device st_dev/stx_dev_* report: the deterministic volume (an ext4-like
 * filesystem on block device 8:1) holds every entry a path can name; an
 * anonymous pipe's node is on pipefs and a socketpair end's on sockfs, each an
 * anonymous device of its own, as on Linux.
 */
enum {
    PATINA_FS_VOLUME = 0,
    PATINA_FS_PIPEFS = 1,
    PATINA_FS_SOCKFS = 2,
};
enum {
    PATINA_VOLUME_DEV_MAJOR = 8,
    PATINA_VOLUME_DEV_MINOR = 1,
    PATINA_PIPEFS_DEV_MINOR = 14,
    PATINA_SOCKFS_DEV_MINOR = 8,
};

/*
 * One metadata record: what the stat family on both doors fills a struct
 * stat/statx from. `kind` is a PATINA_ENTRY_* value and `mode` the POSIX
 * permission bits (0o7777) WITHOUT the file-type bits: a caller assembling
 * st_mode ORs the two. The four timestamps are nanoseconds on the virtual
 * clock, stamped by the kernel's rules (creation sets all four, a data change
 * mtime+ctime, a metadata change ctime, a read atime under relatime). The
 * owner is not a field: every entry belongs to the one modeled identity,
 * read through patina_uid/patina_gid.
 */
struct patina_metadata {
    uint32_t kind;
    uint32_t mode;
    uint32_t nlink;
    uint32_t fs; /* PATINA_FS_* */
    uint64_t length;
    uint64_t ino;
    uint64_t atime_nanos;
    uint64_t mtime_nanos;
    uint64_t ctime_nanos;
    uint64_t btime_nanos;
};
/*
 * The metadata of what (dirfd, path) resolves to — the one entry behind the
 * stat family, access and statfs on both doors (`flags` are PATINA_RESOLVE_*;
 * a missing entry is ENOENT) — and of an open descriptor.
 */
int32_t patina_metadata_at(int32_t dirfd, const char *path, uint32_t flags,
                           struct patina_metadata *out);
int32_t patina_fd_metadata_full(int32_t fd, struct patina_metadata *out);
#ifdef __linux__
/*
 * Linux statfs(2)/fstatfs(2)/ustat(2): the filesystem a path (a trailing
 * symlink followed) or a descriptor (O_PATH included) is on, written into the
 * kernel's 64-bit `struct statfs` (glibc's layout too) or x86_64 `struct
 * ustat`. The deterministic volume is one constant ext4-like description;
 * a pipe, a socket, an eventfd/signalfd/epoll descriptor answer their
 * pseudo-filesystem's (PIPEFS_MAGIC, SOCKFS_MAGIC, ANON_INODE_FS_MAGIC).
 * f_flags carries ST_VALID. A NULL buffer is EFAULT once everything else was
 * judged; ustat of a device no filesystem is on is EINVAL before the buffer.
 */
int32_t patina_statfs(const char *path, void *out);
int32_t patina_fstatfs(int32_t fd, void *out);
int32_t patina_ustat(uint32_t dev, void *out);
/*
 * Linux extended attributes. A non-NULL `path` names the entry (`follow`
 * nonzero follows a final symlink, zero is the l* rows), a NULL one the
 * descriptor `fd` (O_PATH is EBADF). setxattr judges flags (XATTR_CREATE/
 * XATTR_REPLACE, EINVAL otherwise), the name (1..=255 bytes, ERANGE) and the
 * value (XATTR_SIZE_MAX, E2BIG) before the path; getxattr/removexattr after
 * it. get/list answer the size protocol: a zero size asks for the length, a
 * short buffer is ERANGE.
 */
intptr_t patina_getxattr(int32_t fd, const char *path, int32_t follow, const char *name,
                         void *value, size_t size);
intptr_t patina_listxattr(int32_t fd, const char *path, int32_t follow, void *list, size_t size);
int32_t patina_setxattr(int32_t fd, const char *path, int32_t follow, const char *name,
                        const void *value, size_t size, int32_t flags);
int32_t patina_removexattr(int32_t fd, const char *path, int32_t follow, const char *name);
/*
 * Linux in-kernel copies, each with its syscall's contract and refusal order:
 * copy_file_range between two regular files (offsets read and advanced
 * through the pointers, or the cursors when NULL), sendfile from a regular
 * file into anything writable, splice/tee between pipes and files, and
 * vmsplice of a `struct iovec` vector into or out of a pipe.
 */
intptr_t patina_copy_file_range(int32_t fd_in, int64_t *off_in, int32_t fd_out, int64_t *off_out,
                                size_t len, uint32_t flags);
intptr_t patina_sendfile(int32_t out_fd, int32_t in_fd, int64_t *offset, size_t count);
intptr_t patina_splice(int32_t fd_in, int64_t *off_in, int32_t fd_out, int64_t *off_out,
                       size_t len, uint32_t flags);
intptr_t patina_tee(int32_t fd_in, int32_t fd_out, size_t len, uint32_t flags);
intptr_t patina_vmsplice(int32_t fd, const void *vector, int64_t count, uint32_t flags);
/*
 * Linux page-cache advice and writeback, validated as the kernel validates
 * them over a filesystem with no page cache: posix_fadvise/readahead/
 * sync_file_range are no-ops past their refusals; sync makes the volume
 * durable and never fails; syncfs makes the descriptor's filesystem durable.
 */
int32_t patina_fadvise(int32_t fd, int64_t offset, int64_t length, int32_t advice);
int32_t patina_readahead(int32_t fd, int64_t offset, size_t count);
int32_t patina_sync_file_range(int32_t fd, int64_t offset, int64_t length, uint32_t flags);
int32_t patina_sync(void);
int32_t patina_syncfs(int32_t fd);
#endif
/*
 * The one modeled identity (uid/gid 1000): the ONE accessor getuid/geteuid,
 * getgid/getegid, every st_uid/st_gid, and the chown comparison read.
 */
/* The guest's pid and its parent's (the pid namespace's init). */
int32_t patina_pid(void);
int32_t patina_ppid(void);
uint32_t patina_uid(void);
uint32_t patina_gid(void);
#ifdef __APPLE__
/*
 * uname(3) on Darwin: the virtual Darwin kernel (`Darwin`, the run's node
 * name, the modeled release and version, the machine) into `name`, a Darwin
 * struct utsname. 0, or -1 with patina_errno(); before the runtime is
 * installed it installs it or refuses by name, as every boundary does.
 */
int32_t patina_uname(void *name);
#endif
/*
 * utimensat(2) on a (dirfd, path) (`flags` are PATINA_RESOLVE_*; NOFOLLOW
 * sets a symlink's own times; EMPTY_PATH reaches the descriptor's inode,
 * including O_PATH) and futimens(3) on a descriptor. Each time is a
 * (kind, nanos) pair: PATINA_TIME_OMIT leaves it alone, PATINA_TIME_NOW sets
 * the virtual clock's now AFTER modeled latency, PATINA_TIME_SET sets `nanos`. Both OMIT is the
 * kernel's early success (nothing crosses the boundary). ctime moves whenever
 * either time does. A futimens O_PATH descriptor is EBADF. FIFO endpoints
 * reach retained inode state; kinds without a modeled inode refuse loudly.
 */
enum {
    PATINA_TIME_OMIT = 0,
    PATINA_TIME_NOW = 1,
    PATINA_TIME_SET = 2,
};
int32_t patina_utimensat(int32_t dirfd, const char *path, uint32_t flags, uint32_t atime_kind,
                         uint64_t atime_nanos, uint32_t mtime_kind, uint64_t mtime_nanos);
int32_t patina_futimens(int32_t fd, uint32_t atime_kind, uint64_t atime_nanos,
                        uint32_t mtime_kind, uint64_t mtime_nanos);
/*
 * chown/lchown/fchownat on a (dirfd, path) (`flags` are PATINA_RESOLVE_*) and
 * fchown on a descriptor. `uid`/`gid` are the kernel's uid_t/gid_t: UINT32_MAX
 * is "unchanged". An id that is the modeled identity's or unchanged succeeds
 * (killing the setuid bit, and the setgid bit of a group-executable file, on
 * a non-directory, and moving ctime); any other id is the EPERM an
 * unprivileged process gets. An O_PATH descriptor is EBADF.
 */
int32_t patina_chown(int32_t dirfd, const char *path, uint32_t flags, uint32_t uid, uint32_t gid);
int32_t patina_fchown(int32_t fd, uint32_t uid, uint32_t gid);
/*
 * truncate(2): a regular file's length by name (a trailing symlink is
 * followed): negative is EINVAL, a directory EISDIR, any other kind EINVAL,
 * a file without `w` EACCES. fallocate(2) with the kernel's mode vocabulary
 * (FALLOC_FL_*) and order of refusals; the range-shifting modes are
 * EOPNOTSUPP.
 */
int32_t patina_truncate(int32_t dirfd, const char *path, int64_t length);
int32_t patina_fallocate(int32_t fd, uint32_t mode, int64_t offset, int64_t length);
/*
 * Change an entry's permission bits (chmod/fchmod/fchmodat). Without
 * PATINA_RESOLVE_NOFOLLOW a trailing symlink resolves and its TARGET changes
 * (chmod, fchmodat with no flags); with it the link itself is named, which is
 * EOPNOTSUPP because Linux has no way to change a symlink's mode. Only the
 * permission bits of `mode` are stored.
 */
int32_t patina_chmod(int32_t dirfd, const char *path, uint32_t mode, uint32_t flags);
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
 * The namespace operations, each on a resolved (dirfd, path). A trailing
 * symlink is never followed by these: the kernel creates, removes and renames
 * link ENTRIES as entries. Creating calls take the caller's mode and apply the
 * process umask, exactly as the kernel does. patina_mkfifo (mkfifo/mkfifoat,
 * mknod/mknodat with S_IFIFO) creates only the NAME: the pipe behind it comes
 * into existence when the first descriptor opens the FIFO and is released with
 * the last. patina_symlink stores `target` verbatim (an empty one is ENOENT).
 * patina_link shares one inode between `from` and `to`, or duplicates the
 * symlink entry when `from` is itself a symlink (linkat's no-AT_SYMLINK_FOLLOW
 * behavior); `follow` != 0 resolves `from`'s trailing symlink first.
 * patina_read_link copies a link's target bytes (no trailing NUL) and returns
 * the count; an empty path names the descriptor itself, a non-symlink is
 * EINVAL, a zero-length buffer is EINVAL.
 */
int32_t patina_mkdir(int32_t dirfd, const char *path, uint32_t mode);
int32_t patina_mkfifo(int32_t dirfd, const char *path, uint32_t mode);
/*
 * mknod(2)/mknodat(2) in the kernel's order: the type (S_IFDIR EPERM, an
 * unknown type EINVAL) before the path, then the name (ENOENT, EEXIST), the
 * parent's write access (EACCES), and the privilege a real device needs
 * (EPERM; the 0:0 whiteout needs none). A zero type or S_IFREG makes a regular
 * file, S_IFIFO a FIFO, S_IFSOCK a socket node, S_IFCHR 0:0 a whiteout. `dev`
 * is the kernel's 32-bit device word; the mode is applied under the umask.
 * Darwin: a FIFO is mkfifo, every other type EPERM.
 */
int32_t patina_mknod(int32_t dirfd, const char *path, uint32_t mode, uint32_t dev);
int32_t patina_unlink(int32_t dirfd, const char *path);
int32_t patina_rmdir(int32_t dirfd, const char *path);
/*
 * rename/renameat (flags 0) and renameat2(2): RENAME_NOREPLACE, RENAME_EXCHANGE
 * (an atomic swap of any two kinds) or RENAME_WHITEOUT (a 0:0 whiteout left at
 * the old name, in the same change); an unknown bit, or EXCHANGE with either
 * other flag, is EINVAL before the paths.
 */
int32_t patina_renameat2(int32_t fromfd, const char *from, int32_t tofd, const char *to,
                         uint32_t flags);
int32_t patina_symlink(const char *target, int32_t dirfd, const char *link_path);
int32_t patina_link(int32_t fromfd, const char *from, int32_t tofd, const char *to,
                    int32_t follow);
intptr_t patina_read_link(int32_t dirfd, const char *path, char *buf, size_t len);
int32_t patina_thread_id(void);

#ifdef __linux__
struct patina_signal_action {
    uintptr_t handler;
    uint64_t flags;
    uintptr_t restorer;
    uint64_t mask;
};
int64_t patina_signal_action(int32_t sig, const struct patina_signal_action *act,
                            struct patina_signal_action *old, size_t size);
int64_t patina_signal_mask(int32_t how, const uint64_t *set, uint64_t *old, size_t size);
int64_t patina_signal_pending(uint8_t *set, size_t size);
int64_t patina_signal_altstack(const void *stack, void *old);
enum patina_signal_wait_mode {
    PATINA_SIGNAL_DEQUEUE = 0,
    PATINA_SIGNAL_SUSPEND = 1,
    PATINA_SIGNAL_PAUSE = 2,
};
int64_t patina_signal_wait(const uint64_t *set, void *info, const void *timeout,
                          size_t size, enum patina_signal_wait_mode mode);
int patina_pthread_kill(uintptr_t thread, int sig);
int64_t patina_set_tid_address(int32_t *address);
_Noreturn void patina_raw_exit(int status);
_Noreturn void patina_raw_exit_group(int status);
void patina_signal_deliver(void);
void patina_signal_restorer(uintptr_t restorer);
int64_t patina_signal_action_libc(int sig, const struct patina_signal_action *action,
                                struct patina_signal_action *old);
void patina_signal_frame(uint64_t *mask, void *stack);
#endif
/* Private internal-fatal vehicle: never finalize the guest trace. */
_Noreturn void patina_host_abort(void);
#ifdef __linux__
_Noreturn void patina_abort(void);
#endif
int32_t patina_sched_yield(void);
/*
 * --yield-points guard hook (patina_yield.c): a deterministic scheduling point
 * carrying the instrumented guest site for divergence diagnostics.
 */
void patina_yield_point(const void *site);
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
                               int32_t fault_eligible, size_t *out_len);
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
intptr_t patina_net_stream_send(int32_t fd, const void *buf, size_t len, int flags);
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
intptr_t patina_pipe_write(int32_t fd, const void *buf, size_t len, int flags);
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

#ifdef __linux__
int64_t patina_signalfd(int fd, const uint64_t *mask, size_t size, int flags);
#endif

#ifdef __linux__
int64_t patina_poll(void *fds, size_t count, int64_t timeout, const uint64_t *mask, uint64_t *remaining);
int64_t patina_epoll_wait_masked(int ep, void *events, int capacity, int timeout, const uint64_t *mask);
int64_t patina_select(int nfds, uint64_t *read, uint64_t *write, uint64_t *except, int64_t timeout, const uint64_t *mask, uint64_t *remaining);
#endif

#ifdef __cplusplus
}
#endif

#endif

