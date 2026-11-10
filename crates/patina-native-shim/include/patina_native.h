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
     * directory descriptor whether or not the caller asked. The description
     * keeps it as a status flag, which Linux's F_GETFL reports. */
    PATINA_O_DIRECTORY = 1u << 11,
    /* The opened terminal must not become the caller's controlling terminal:
     * read only by a pseudoterminal slave's open (Linux), never status. */
    PATINA_O_NOCTTY = 1u << 12,
    /* O_DSYNC: every write through the description makes its data durable
     * before it returns, as an fdatasync after it would. Status: F_GETFL
     * reports it. */
    PATINA_O_DSYNC = 1u << 13,
    /* The other half of O_SYNC (the kernel's __O_SYNC, which O_SYNC sets with
     * O_DSYNC): the metadata too, as an fsync would. Status. */
    PATINA_O_SYNC = 1u << 14,
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
    PATINA_FD_STDIN = 0,   /* standard input: an empty pipe's read end, its writer gone */
    PATINA_FD_STDOUT = 1,  /* captured standard output: a drained pipe's write end */
    PATINA_FD_STDERR = 2,  /* captured standard error: a drained pipe's write end */
    PATINA_FD_FILE = 3,    /* a deterministic-filesystem file */
    PATINA_FD_DIR = 4,     /* a directory descriptor (O_DIRECTORY, with or without O_PATH) */
    PATINA_FD_OPATH = 5,   /* an O_PATH descriptor on a non-directory */
    PATINA_FD_URANDOM = 6, /* the /dev/urandom device */
    PATINA_FD_SOCKET = 7,  /* a virtual socket (any family; a socketpair end) */
    PATINA_FD_PIPE = 8,    /* a pipe / FIFO endpoint */
    PATINA_FD_EVENTFD = 9, /* an eventfd counter (Linux) */
    PATINA_FD_EPOLL = 10,  /* an epoll instance (Linux) */
    PATINA_FD_KQUEUE = 11, /* a kqueue (Darwin) */
    PATINA_FD_SIGNALFD = 12, /* a virtual signal queue reader (Linux) */
    PATINA_FD_TIMERFD = 14,  /* a timer descriptor (Linux) */
    PATINA_FD_PIDFD = 15,    /* a process descriptor (Linux) */
    PATINA_FD_NAMESPACE = 18,   /* a namespace file, /proc/self/ns/<type> (Linux) */
    PATINA_FD_NAMESPACE_PATH = 19, /* a namespace file opened O_PATH (Linux) */
    PATINA_FD_INOTIFY = 20,  /* an inotify instance (Linux) */
    PATINA_FD_PROC = 23,        /* a procfs file, /proc/uptime, /proc/<pid>/stat, ... (Linux) */
    PATINA_FD_PROC_DIR = 24,    /* a procfs directory, /proc or /proc/<pid> (Linux) */
};

enum {
    PATINA_SEEK_START = 0,
    PATINA_SEEK_CURRENT = 1,
    PATINA_SEEK_END = 2,
    /* The next data at or after the offset, and the next hole (Linux's
     * numbering, which the SUD lseek row passes through unchanged). */
    PATINA_SEEK_DATA = 3,
    PATINA_SEEK_HOLE = 4,
};

int32_t patina_init_seed(uint64_t seed);
int32_t patina_init_crash(uint64_t seed);
/*
 * Build the runtime from the documented PATINA_* environment protocol.
 * PATINA_RT_TRACE_FD names an inherited host descriptor: record mode
 * writes the finalized trace bundle to it and replay mode reads the bundle
 * from it, using non-interposed host descriptor I/O so fully interposed
 * processes never recurse into the deterministic filesystem.
 */
int32_t patina_init_from_env(void);
void patina_note_boundary_symbol(const char *symbol);
/*
 * The POSIX layer's stdio flush and stdout salvage, registered at startup.
 * patina_shutdown calls the flush first, so the exit paths (the atexit
 * finalizer) write what the streams buffered, as glibc's
 * exit does; the runtime's abort, fatal-signal and raw exit_group paths
 * finalize without it. The salvage hands over (and empties) stdout's buffer
 * without writing it: every path on which patina itself ends the run (a
 * refusal, a fatal, a verdict) writes those bytes after the captured ones.
 */
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
 * having entered post-`main` teardown (so the root task's --yield-stride hooks
 * take no scheduling point) and then terminates through the real libc `exit`
 * resolved via the shim host-alias table, so the atexit chain (trace
 * finalization) and the thread-local destructors still run. Does not return.
 */
_Noreturn void patina_exit(int32_t status);
/*
 * Mark the process as having entered post-`main` teardown without terminating.
 * Called by the Linux `__libc_start_main` interposer from its wrapper `main`, the
 * instant the guest's real `main` returns and before the exit code re-enters
 * glibc's `exit()` path — so the root task's --yield-stride thread-local
 * destructor yields are silenced on the natural-return path that a plain `exit`
 * interposer cannot see (glibc calls `exit` through a hidden internal alias).
 */
void patina_note_main_returned(void);
/*
 * 1 once the process is in post-`main` teardown (only the root task runs), 0
 * before: the POSIX layer's internal locks are not taken then.
 */
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
#endif
/*
 * Flush captured stdout/stderr to the real host descriptors WITHOUT finalizing
 * the run (unlike patina_shutdown), with what stdout's buffer holds after the
 * captured stdout. The process-class deny-traps call this before the
 * private fatal vehicle so the guest's output and the deny diagnostic reach the
 * operator even though that vehicle skips the atexit-driven shutdown flush.
 */
int32_t patina_flush_captured_stdio(void);
int32_t patina_errno(void);
int32_t patina_entropy(void *destination, size_t length);
/* Entry `index` of the virtual machine's passwd database as its /etc/passwd
 * line (registry PASSWD, file order), or NULL past the last. */
int32_t patina_clock_now(uint32_t clock, uint64_t *nanos);
int32_t patina_sleep_until(uint32_t clock, uint64_t deadline_nanos);
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
 * clock_gettime, a NULL `rem` is not written. `patina_clock_in_vdso` answers
 * whether glibc's reads of the clock are the vDSO's, which store their answer
 * in user space (the C door then stores it itself). `patina_clock_nanosleep`
 * takes the kernel's flags (TIMER_ABSTIME) and writes the time left of an
 * interrupted relative sleep.
 */
struct timespec;
int64_t patina_clock_gettime(int clock, struct timespec *time);
int64_t patina_clock_getres(int clock, struct timespec *res);
int patina_clock_in_vdso(int clock);
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
 * truncating open (EAGAIN); NO_MAGICLINKS refuses a magic link, a
 * /proc/self/ns entry (ELOOP).
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
    PATINA_RESOLVE_NO_MAGICLINKS = 1u << 7,
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
/*
 * openat(2): open what (dirfd, path) resolves to, returning a fresh guest
 * descriptor number. The entry's KIND decides the description: a regular file,
 * a directory (with or without PATINA_O_DIRECTORY, and PATINA_FD_DIR either
 * way), an O_PATH location, /dev/urandom (PATINA_FD_URANDOM), or a FIFO's pipe
 * endpoint (PATINA_FD_PIPE, because a named pipe's bytes are not filesystem
 * state). PATINA_O_NOFOLLOW leaves a trailing symlink unresolved, which is
 * ELOOP, except under PATINA_O_PATH, which opens an O_PATH location on the
 * link itself. PATINA_O_CLOEXEC sets FD_CLOEXEC on the number.
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
int32_t patina_close(int32_t fd);
int64_t patina_seek(int32_t fd, int64_t offset, uint32_t whence);
int32_t patina_fsync(int32_t fd);
/*
 * Memory mappings share one model across the libc and SUD doors. Each answer
 * follows the raw syscall ABI: the address (or 0) on success, -errno on
 * failure. An anonymous mapping is host address space; a mapping of a
 * deterministic-filesystem file is a view of that file's page cache,
 * coherent with read/write through every descriptor on the file.
 */
int64_t patina_mremap(uintptr_t old_addr, size_t old_length, size_t new_length, uintptr_t flags,
                      uintptr_t new_addr);
/*
 * Memory locks against the virtual RLIMIT_MEMLOCK (never the host's): mlock
 * and mlock2 (flags: MLOCK_ONFAULT), munlock, mlockall, munlockall.
 */
int64_t patina_mlock(uintptr_t addr, size_t length, uint32_t flags);
int64_t patina_munlock(uintptr_t addr, size_t length);
int64_t patina_mlockall(int32_t flags);
/* fcntl F_SETOWN/F_SETOWN_EX/F_SETSIG: EBADF for a closed or O_PATH
 * descriptor, otherwise a named fatal (SIGIO and SIGURG are not modeled). */
int32_t patina_fcntl_owner(int32_t fd);
/* fcntl F_GETOWN/F_GETSIG (ex 0) and F_GETOWN_EX (ex 1, owner the struct
 * f_owner_ex): EBADF for a closed or O_PATH descriptor, EFAULT for an
 * owner that cannot be written, otherwise 0 (nothing sets an owner). */
int32_t patina_fcntl_owner_get(int32_t fd, int32_t ex, void *owner);
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
    /* The anonymous inode (Linux, alloc_anon_inode): permission bits and no
     * file-type bits. */
    PATINA_ENTRY_ANON = 7,
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
    PATINA_FS_NSFS = 3, /* a namespace file (Linux): root's, on its own device */
    PATINA_FS_DEVTMPFS = 4, /* the entropy device (Linux): root's, on devtmpfs */
    /* 6.8's one anonymous inode (Linux), which every eventfd, timerfd, signalfd,
     * epoll, inotify and pidfd descriptor is a file on: root's,
     * on anon_inodefs */
    PATINA_FS_ANON_INODE = 7,
    /* A procfs node root owns (Linux): procfs's root, /proc/self, the
     * machine-wide files, init's directory and files */
    PATINA_FS_PROC = 9,
    /* A guest process's procfs directory and files (Linux): the caller's */
    PATINA_FS_PROC_OWN = 10,
};
enum {
    PATINA_VOLUME_DEV_MAJOR = 8,
    PATINA_VOLUME_DEV_MINOR = 1,
    PATINA_PIPEFS_DEV_MINOR = 14,
    PATINA_SOCKFS_DEV_MINOR = 8,
    PATINA_NSFS_DEV_MINOR = 4,
    PATINA_DEVTMPFS_DEV_MINOR = 5,
    PATINA_DEVPTS_DEV_MINOR = 24,
    PATINA_ANON_INODEFS_DEV_MINOR = 15,
    PATINA_PROC_DEV_MINOR = 25,
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
/*
 * A timestamp as the kernel's timespec64 holds it: signed seconds since the
 * epoch (a time before it is negative) and nanoseconds in [0, 999999999].
 */
struct patina_timestamp {
    int64_t sec;
    int64_t nsec;
};
/*
 * access/faccessat's answer for the node `values` describes: 0 or the errno
 * (the owner triad of a volume entry, the other triad of a root-owned node,
 * EPERM for write access to an immutable one).
 */
#ifdef __linux__
/*
 * Linux page-cache advice, validated as the kernel validates it over a
 * filesystem with no page cache: posix_fadvise/readahead are no-ops past
 * their refusals.
 */
#endif
/*
 * The one modeled identity (uid/gid 1000): the ONE accessor getuid/geteuid,
 * getgid/getegid, every st_uid/st_gid, and the chown comparison read.
 */
/* The owner stat reports for a node on the PATINA_FS_* filesystem `fs`: the
 * caller's, but for the nodes the virtual kernel's boot or devpts makes
 * (namespace files, the entropy device, /dev/ptmx, a pseudoterminal's slave). */
#ifdef __linux__
/* The name /proc/self/fd reads for a pseudoterminal descriptor (/dev/ptmx for
 * a master, /dev/pts/<index> for a slave): its length, written with its
 * terminator when `len` has room; -1 with patina_errno() (ENOTTY for any
 * other descriptor, EBADF for none). */
#endif
#ifdef __APPLE__
/*
 * uname(3) on Darwin: the virtual Darwin kernel (`Darwin`, the run's node
 * name, the modeled release and version, the machine) into `name`, a Darwin
 * struct utsname. 0, or -1 with patina_errno(); before the runtime is
 * installed it installs it or refuses by name, as every boundary does.
 */
#endif
/*
 * utimensat(2) on a (dirfd, path) (`flags` are PATINA_RESOLVE_*; NOFOLLOW
 * sets a symlink's own times; EMPTY_PATH reaches the descriptor's inode,
 * including O_PATH) and futimens(3) on a descriptor. Each time is a
 * (kind, timestamp) pair: PATINA_TIME_OMIT leaves it alone, PATINA_TIME_NOW
 * sets the virtual clock's now AFTER modeled latency, PATINA_TIME_SET sets the
 * timestamp, any second, truncated to the target filesystem's range as the
 * kernel's timestamp_truncate does (the volume is ext4's 1901-12-13 to
 * 2446-05-10, a memfd tmpfs's every 64-bit second). Both OMIT is the
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
                         struct patina_timestamp atime, uint32_t mtime_kind,
                         struct patina_timestamp mtime);
int32_t patina_futimens(int32_t fd, uint32_t atime_kind, struct patina_timestamp atime,
                        uint32_t mtime_kind, struct patina_timestamp mtime);
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
/*
 * mknod(2)/mknodat(2) in the kernel's order: the type (S_IFDIR EPERM, an
 * unknown type EINVAL) before the path, then the name (ENOENT, EEXIST), the
 * parent's write access (EACCES), and the privilege a real device needs
 * (EPERM; the 0:0 whiteout needs none). A zero type or S_IFREG makes a regular
 * file, S_IFIFO a FIFO, S_IFSOCK a socket node, S_IFCHR 0:0 a whiteout. `dev`
 * is the kernel's 32-bit device word; the mode is applied under the umask.
 * Darwin: a FIFO is mkfifo, every other type EPERM.
 */
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
intptr_t patina_read_link(int32_t dirfd, const char *path, char *buf, size_t len);
int32_t patina_thread_id(void);
#ifdef __APPLE__
/* Synchronous self-signal generation through the Darwin signal model. */
#endif

#ifdef __linux__
struct patina_signal_action {
    uintptr_t handler;
    uint64_t flags;
    uintptr_t restorer;
    uint64_t mask;
};
int64_t patina_signal_action(int32_t sig, const struct patina_signal_action *act,
                            struct patina_signal_action *old, size_t size);
/* Nonzero for glibc's reserved signals, SIGCANCEL (32) and SIGSETXID (33),
 * which its libc face refuses (EINVAL) to act on. */
_Noreturn void patina_raw_exit_group(int status);
void patina_signal_frame(uint64_t *mask, void *stack);
/* A guest restorer's rt_sigreturn: keep the containment signals out of the
 * frame's saved mask at `mask`, and name the host vehicle (glibc's real
 * syscall(2)) that issues the kernel's rt_sigreturn. */
uintptr_t patina_signal_return(uintptr_t mask);
/* Take over the main thread's host kernel registrations (the robust-futex
 * list head) as the main task's; a managed run's startup calls it once. */
void patina_thread_registrations_adopt_main(void);
#endif
#ifdef __linux__
_Noreturn void patina_abort(void);
#endif
int32_t patina_sched_yield(void);
/*
 * edge hook (patina_sancov.c, every --yield-stride-th edge): a deterministic scheduling point
 * carrying the instrumented guest site for divergence diagnostics.
 */
void patina_yield_point(const void *site);
/*
 * A compute meter's batch (patina_go_meter.c): charge `units` of metered
 * computation as virtual CPU time, then take a scheduling point.
 */
void patina_compute_point(uint64_t units);
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
/* Declare a site at run time, as the patina_sites table does before the guest
 * runs, for SDKs that cannot emit that table. `kind` is a static-site kind
 * (1 fault, 2 delay, 3 knob, 4 always, 5 sometimes, 6 reachable). */
int32_t patina_declare_site(uint8_t kind, const uint8_t *label, size_t label_len,
                            const uint8_t *site, size_t site_len);
uint64_t patina_rng(void);
/* The run parameter `key`'s byte length, copied into `out` when it fits in
 * `out_cap`; -1 when the run has no such parameter. */
intptr_t patina_param(const uint8_t *key, size_t key_len, uint8_t *out, size_t out_cap);
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
#ifdef __linux__
/*
 * The Linux thread lifecycle's C halves (c/posix/thread_sync.c): the host start
 * routine calls the guest routine between the prelude (which answers it and
 * its argument) and the epilogue, and pthread_exit records its value, then
 * calls the glibc pthread_exit the model answers. Each returns before glibc's
 * forced unwind starts, so the unwind crosses no Rust frame.
 */
typedef void *(*patina_start_routine)(void *);
patina_start_routine patina_thread_prelude(void *start, void **arg);
void patina_thread_returned(void *value);
typedef void (*patina_host_pthread_exit_fn)(void *) __attribute__((noreturn));
patina_host_pthread_exit_fn patina_thread_exiting(void *value);
/* The main thread's pthread_exit, from the __libc_start_main wrapper's cleanup
 * record once the guest's cleanup handlers ran. */
void patina_main_thread_exited(void);
/*
 * Cancellation (src/thread/cancel.rs). A negative answer tells the C wrapper
 * to act on the cancellation now, once the Rust call has returned:
 * pthread_exit(PTHREAD_CANCELED). patina_cancel_enter/leave bracket a
 * cancellation point the model acts at; leave takes what enter answered.
 */
int32_t patina_thread_cancel(uintptr_t thread);
int32_t patina_cancel_setstate(int32_t state, int32_t *old);
int32_t patina_cancel_settype(int32_t type, int32_t *old);
int32_t patina_cancel_test(void);
int32_t patina_cancel_enter(void);
int32_t patina_cancel_leave(int32_t outer);
/* The entry of every other glibc cancellation point the shim defines: a
 * thread with a cancel to act on stops the run by name. */
void patina_cancel_point(const char *name);
#endif
int32_t patina_cond_init(void *cond, const void *attr);
int32_t patina_cond_wait(void *cond, void *mutex);
int32_t patina_cond_timedwait(void *cond, void *mutex, const void *abstime);
int32_t patina_cond_signal(void *cond);
int32_t patina_cond_broadcast(void *cond);

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
 * epoll / eventfd readiness reactor (Linux). The Linux mirror of the macOS
 * kqueue reactor below, over the same shared readiness core. An epoll instance
 * is a PATINA_FD_EPOLL description, an eventfd a PATINA_FD_EVENTFD one; read/
 * write/close/dup/fcntl reach them through the universal entries.
 * The syscall-user-dispatch rows and libc doors share the readiness models;
 * eventfd is a virtual counter in the same descriptor table.
 * epoll_ctl answers the kernel's errnos (EBADF/EINVAL/EPERM/EEXIST/ENOENT) and
 * models EPOLLET and EPOLLONESHOT. epoll_ctl/epoll_wait take the platform
 * `struct epoll_event` pointers directly: the Rust side reads/writes the kernel
 * ABI layout (packed on x86_64, natural elsewhere), pinned by _Static_asserts
 * in the C layer.
 */
#ifdef __linux__
/* timeout_ms: -1 blocks until ready, 0 polls, > 0 is a relative virtual-clock
 * deadline in milliseconds. */
int32_t patina_epoll_wait(int32_t epfd, void *events, int32_t maxevents, int32_t timeout_ms);
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
 * Apply one changelist entry. Returns 0 on success or a POSIX errno the caller
 * places in an EV_ERROR receipt. An EVFILT_USER NOTE_TRIGGER wakes the kq's
 * parked kevent callers. Unmodeled filters fail closed loudly (SIGABRT).
 */
int32_t patina_kqueue_apply(int32_t kq, uint64_t ident, int16_t filter, uint16_t flags,
                            uint32_t fflags, int64_t data, uintptr_t udata);
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
