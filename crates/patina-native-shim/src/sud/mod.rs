//! Syscall-user-dispatch (SUD) dispatch table — Linux only.
//!
//! The C layer (`patina_posix.c`) arms SUD (`prctl(PR_SET_SYSCALL_USER_DISPATCH,
//! …)` with allowed region = glibc's executable segment, NULL selector) and
//! installs a `SIGSYS` handler. When guest code executes a raw `syscall`/`svc`
//! instruction outside glibc's text, the kernel rolls the instruction back and
//! delivers a synchronous, thread-directed `SIGSYS` at the exact faulting IP.
//! The C handler decodes the syscall number and its six argument registers from
//! the `ucontext`, then calls [`patina_sud_dispatch`], which routes the call
//! into the *same* `patina_*` entry points the C interposers use and returns the
//! value the handler writes back into the syscall's return register (raw ABI:
//! a negative value is `-errno`, there is no libc `errno` step).
//!
//! Soundness: the trap is synchronous — it *is* the guest's own effect boundary,
//! semantically identical to the guest having called an interposed `read()` — so
//! re-entering the deterministic runtime (taking `lock_state`, parking on the
//! baton) is exactly what every C interposer already does. See `SUD-DESIGN.md`
//! §4.2. The one invariant that must hold is that shim/runtime code never itself
//! traps while servicing a dispatch; [`with_dispatch_guard`] is the standalone
//! RED detector for a violation of it.
//!
//! Dispatch is GENERATED from the syscall registry (`crate::registry`): every
//! number the vendored kernel table lists has a row with a disposition, the
//! routed rows bind a handler in [`BINDINGS`], and [`build_dispatch`] turns the
//! rows for this arch into the number → row index at compile time. A number
//! the table does not list is a distinct diagnostic from a row whose
//! disposition is a trap. This module is `x86_64`-first (the only arch with
//! kernel SUD today); the arm64 rows carry their own numbers so the dispatcher
//! lights up unchanged when generic-entry arm64 kernels ship, and the libc
//! `syscall(2)` interposer already forwards into it on every Linux arch.

use crate::thread::signals::{
    Action, GenerationInfo, GenerationTarget, Info, Stack, WaitMode, deliver, generate_signal,
    patina_signal_action, patina_signal_altstack, patina_signal_mask, patina_signal_pending,
    patina_signal_wait,
};
use std::cell::Cell;

use crate::PatinaMetadata;
use crate::registry::{Arch, Disposition, SYSCALLS, SyscallRow};

mod fd_io;
mod fs;
mod mem;
mod net;
mod readiness;
mod sched_identity;
mod signal_process;
mod time;
use fd_io::*;
use fs::*;
use mem::*;
use net::*;
use readiness::*;
use sched_identity::*;
use signal_process::*;
use time::*;

// The one row-side entry the descriptor close path in `lib.rs` calls directly.
pub(crate) use fs::release_dir_iteration;

use std::ffi::{c_char, c_int, c_long, c_void};

// The `patina_*` runtime entry points the C interposers call. Declaring them as
// externs (rather than reaching for module paths) routes SUD through the exact
// same symbols — there is no second implementation of any effect. Every one is a
// `#[no_mangle] extern "C"` definition elsewhere in this crate.
unsafe extern "C" {
    fn patina_errno() -> c_int;
    fn patina_clock_now(clock: u32, nanos: *mut u64) -> c_int;
    fn patina_sleep_until_remaining(
        clock_id: u32,
        deadline_nanos: u64,
        remaining: *mut i64,
    ) -> c_int;
    // The one open entry (`openat(2)` shape): resolves `(dirfd, path)` through
    // the runtime's resolver and decides the descriptor's kind from the entry's.
    fn patina_openat(dirfd: c_int, path: *const c_char, flags: u32, mode: u32) -> c_int;
    fn patina_read(fd: c_int, destination: *mut c_void, length: usize) -> isize;
    fn patina_write(fd: c_int, source: *const c_void, length: usize) -> isize;
    fn patina_pread(fd: c_int, destination: *mut c_void, length: usize, offset: i64) -> isize;
    fn patina_pwrite(fd: c_int, source: *const c_void, length: usize, offset: i64) -> isize;
    fn patina_close(fd: c_int) -> c_int;
    fn patina_seek(fd: c_int, offset: i64, whence: u32) -> i64;
    fn patina_fsync(fd: c_int) -> c_int;
    fn patina_set_len(fd: c_int, length: u64) -> c_int;
    fn patina_flock(fd: c_int, operation: c_int) -> c_int;
    fn patina_dup(fd: c_int) -> c_int;
    fn patina_entropy(destination: *mut c_void, length: usize) -> c_int;
    fn patina_sched_yield() -> c_int;
    fn patina_thread_id() -> c_int;
    fn patina_raw_exit(status: c_int) -> !;
    fn patina_raw_exit_group(status: c_int) -> !;
    fn patina_set_tid_address(address: *mut i32) -> i64;
    fn patina_stdio_write(fd: c_int, source: *const c_void, length: usize) -> isize;
    fn patina_futex_wait(addr: usize, expected: u32) -> c_int;
    fn patina_futex_wait_timed(
        addr: usize,
        expected: u32,
        clock: u32,
        absolute: c_int,
        timeout_nanos: u64,
    ) -> c_int;
    fn patina_futex_wake(addr: usize, count: c_int) -> c_int;

    // Filesystem metadata / directory iteration (the same records the C
    // stat/statx/getdents interposers normalize).
    fn patina_metadata_at(
        dirfd: c_int,
        path: *const c_char,
        flags: u32,
        out: *mut PatinaMetadata,
    ) -> c_int;
    fn patina_fd_metadata_full(fd: c_int, out: *mut PatinaMetadata) -> c_int;
    // The one modeled identity, for st_uid/st_gid.
    fn patina_uid() -> u32;
    fn patina_gid() -> u32;
    // Timestamps, ownership and sizes: the same entries the C utimensat/chown/
    // truncate/fallocate families call.
    fn patina_utimensat(
        dirfd: c_int,
        path: *const c_char,
        flags: u32,
        atime_kind: u32,
        atime_nanos: u64,
        mtime_kind: u32,
        mtime_nanos: u64,
    ) -> c_int;
    fn patina_futimens(
        fd: c_int,
        atime_kind: u32,
        atime_nanos: u64,
        mtime_kind: u32,
        mtime_nanos: u64,
    ) -> c_int;
    fn patina_chown(dirfd: c_int, path: *const c_char, flags: u32, uid: u32, gid: u32) -> c_int;
    fn patina_fchown(fd: c_int, uid: u32, gid: u32) -> c_int;
    fn patina_truncate(dirfd: c_int, path: *const c_char, length: i64) -> c_int;
    fn patina_fallocate(fd: c_int, mode: u32, offset: i64, length: i64) -> c_int;
    // Permission bits: the same entries the C chmod/fchmod/fchmodat interposers
    // call, so a raw-syscall guest and a libc guest change one mode model.
    fn patina_chmod(dirfd: c_int, path: *const c_char, mode: u32, flags: u32) -> c_int;
    fn patina_fchmod(fd: c_int, mode: u32) -> c_int;
    fn patina_read_dir(fd: c_int, state_out: *mut *mut c_void) -> c_int;
    // The descriptor table's face: the kind oracle and the per-number /
    // per-description state (`include/patina_native.h`).
    fn patina_fd_kind(fd: c_int) -> c_int;
    fn patina_fd_getfd(fd: c_int) -> c_int;
    fn patina_fd_setfd(fd: c_int, cloexec: c_int) -> c_int;
    fn patina_fd_getfl(fd: c_int) -> c_int;
    fn patina_fd_setfl(fd: c_int, flags: u32) -> c_int;
    fn patina_fd_set_nonblocking(fd: c_int, nonblocking: c_int) -> c_int;
    fn patina_dupfd(fd: c_int, minimum: c_int, cloexec: c_int) -> c_int;
    fn patina_dup2(oldfd: c_int, newfd: c_int) -> c_int;
    fn patina_dup3(oldfd: c_int, newfd: c_int, cloexec: c_int) -> c_int;
    fn patina_close_range(first: u32, last: u32, flags: u32) -> c_int;
    fn patina_pipe_size(fd: c_int) -> c_int;
    fn patina_pipe_set_size(fd: c_int, size: c_int) -> c_int;
    fn patina_read_dir_next(
        state: *mut c_void,
        name_buf: *mut c_char,
        buf_len: usize,
        kind: *mut u32,
    ) -> c_int;
    fn patina_read_dir_free(state: *mut c_void);
    // The namespace operations, each on a `(dirfd, path)` the runtime resolves
    // — the same entries the C interposers of the same names call.
    fn patina_mkdir(dirfd: c_int, path: *const c_char, mode: u32) -> c_int;
    fn patina_mkfifo(dirfd: c_int, path: *const c_char, mode: u32) -> c_int;
    fn patina_unlink(dirfd: c_int, path: *const c_char) -> c_int;
    fn patina_rmdir(dirfd: c_int, path: *const c_char) -> c_int;
    fn patina_rename(fromfd: c_int, from: *const c_char, tofd: c_int, to: *const c_char) -> c_int;
    fn patina_symlink(target: *const c_char, dirfd: c_int, link_path: *const c_char) -> c_int;
    fn patina_link(
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
        follow: c_int,
    ) -> c_int;
    fn patina_read_link(
        dirfd: c_int,
        path: *const c_char,
        buf: *mut c_char,
        buf_len: usize,
    ) -> isize;
    // The working directory and the umask: the process state the C
    // getcwd/chdir/fchdir/umask interposers read and write.
    fn patina_getcwd(buf: *mut c_char, len: usize) -> isize;
    fn patina_chdir(dirfd: c_int, path: *const c_char) -> c_int;
    fn patina_fchdir(fd: c_int) -> c_int;
    fn patina_umask(mask: u32) -> u32;
    fn patina_pipe(
        read_fd_out: *mut c_int,
        write_fd_out: *mut c_int,
        nonblocking: c_int,
        cloexec: c_int,
    ) -> c_int;

    // Network (SimNet) — the exact entries the C socket interposers call.
    fn patina_net_socket(stream: c_int, nonblocking: c_int, cloexec: c_int) -> c_int;
    fn patina_net_kind(fd: c_int) -> c_int;
    fn patina_net_bind(fd: c_int, ip: u32, port: u16) -> c_int;
    fn patina_net_connect(fd: c_int, ip: u32, port: u16) -> c_int;
    fn patina_net_tcp_connect(fd: c_int, ip: u32, port: u16) -> c_int;
    fn patina_net_listen(fd: c_int, backlog: c_int) -> c_int;
    fn patina_net_accept(
        fd: c_int,
        ip_out: *mut u32,
        port_out: *mut u16,
        nonblocking: c_int,
        cloexec: c_int,
    ) -> c_int;
    fn patina_net_sendto(fd: c_int, buf: *const c_void, len: usize, ip: u32, port: u16) -> isize;
    fn patina_net_send(fd: c_int, buf: *const c_void, len: usize) -> isize;
    fn patina_net_stream_send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
    fn patina_net_recvfrom(
        fd: c_int,
        buf: *mut c_void,
        len: usize,
        ip_out: *mut u32,
        port_out: *mut u16,
    ) -> isize;
    fn patina_net_stream_recv(fd: c_int, buf: *mut c_void, len: usize) -> isize;
    fn patina_net_shutdown(fd: c_int, how: c_int) -> c_int;
    fn patina_net_getsockname(fd: c_int, ip_out: *mut u32, port_out: *mut u16) -> c_int;
    fn patina_net_getpeername(fd: c_int, ip_out: *mut u32, port_out: *mut u16) -> c_int;
    fn patina_net_set_read_timeout(fd: c_int, nanos: u64) -> c_int;
    fn patina_socketpair(
        fd0_out: *mut c_int,
        fd1_out: *mut c_int,
        nonblocking: c_int,
        cloexec: c_int,
    ) -> c_int;

    // In-process pipe / socketpair endpoints (the send/recv face of a
    // socketpair end) and eventfds.
    fn patina_pipe_read(fd: c_int, buf: *mut c_void, len: usize) -> isize;
    fn patina_pipe_write(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
    fn patina_eventfd(initval: u32, flags: c_int) -> c_int;

    // Readiness reactor (Linux epoll frontend over the OS-agnostic core). The SUD
    // rows are a SECOND caller of these exact entries, never a second reactor.
    fn patina_epoll_create1(flags: c_int) -> c_int;
    fn patina_epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *const c_void) -> c_int;
    fn patina_epoll_wait(
        epfd: c_int,
        events: *mut c_void,
        maxevents: c_int,
        timeout_ms: c_int,
    ) -> c_int;
}

// Linux errno values used to shape raw-syscall returns (`-errno`). Fixed across
// the Linux ABIs Patina targets.
const EPERM: i64 = 1;

const ERANGE: i64 = 34;

const EBADF: i64 = 9;

const EACCES: i64 = 13;

const EFAULT: i64 = 14;

const ECHILD: i64 = 10;

const ESRCH: i64 = 3;

const ENOTDIR: i64 = 20;

const EINVAL: i64 = 22;

const ENOTTY: i64 = 25;

const ESPIPE: i64 = 29;

const ENOSYS: i64 = 38;

const ENOTSOCK: i64 = 88;

const EOPNOTSUPP: i64 = 95;

const EAFNOSUPPORT: i64 = 97;

const ENOPROTOOPT: i64 = 92;

const EISCONN: i64 = 106;

const EPROTONOSUPPORT: i64 = 93;

const EPROTOTYPE: i64 = 91;

const EIO: i64 = 5;

// The descriptor kinds `patina_fd_kind` answers (`PATINA_FD_*` in
// `patina_native.h`): the one oracle a row consults when its meaning depends
// on what a number names. Everything else about a descriptor is answered by
// the universal `patina_*` entries, which resolve the number themselves.
const PATINA_FD_DIR: c_int = 4;

const PATINA_FD_SOCKET: c_int = 7;

const PATINA_FD_PIPE: c_int = 8;

// Patina clock ids (see `patina_native.h`).
const PATINA_CLOCK_REALTIME: u32 = 0;

const PATINA_CLOCK_MONOTONIC: u32 = 1;

// Patina open flags (see `patina_native.h`).
const PATINA_O_READ: u32 = 1 << 0;

const PATINA_O_WRITE: u32 = 1 << 1;

const PATINA_O_CREATE: u32 = 1 << 2;

const PATINA_O_TRUNCATE: u32 = 1 << 3;

const PATINA_O_APPEND: u32 = 1 << 4;

const PATINA_O_EXCLUSIVE: u32 = 1 << 5;

const PATINA_O_NOFOLLOW: u32 = 1 << 6;

const PATINA_O_NONBLOCK: u32 = 1 << 7;

const PATINA_O_PATH: u32 = 1 << 8;

const PATINA_O_CLOEXEC: u32 = 1 << 9;

const PATINA_O_OPENED: u32 = 1 << 10;

const PATINA_O_DIRECTORY: u32 = 1 << 11;

// Patina path-resolution flags (see `patina_native.h`).
const PATINA_RESOLVE_NOFOLLOW: u32 = 1 << 0;

const PATINA_RESOLVE_EMPTY_PATH: u32 = 1 << 1;

// Kernel `open(2)` flag bits (octal), identical on x86_64 and aarch64 Linux.
const O_ACCMODE: u64 = 0o3;

const O_WRONLY: u64 = 0o1;

const O_RDWR: u64 = 0o2;

const O_CREAT: u64 = 0o100;

const O_EXCL: u64 = 0o200;

const O_TRUNC: u64 = 0o1000;

const O_APPEND: u64 = 0o2000;

const O_DIRECTORY: u64 = 0o200000;

const O_NOFOLLOW: u64 = 0o400000;

const O_CLOEXEC: u64 = 0o2000000;

const O_LARGEFILE: u64 = 0o100000;

/// `O_PATH`: a descriptor that resolves paths and answers metadata but cannot
/// read or write. `cap-primitives` walks a path one component at a time with
/// `openat(dirfd, name, O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`, so this bit is
/// on the hot path of every capability-based filesystem guest.
const O_PATH: u64 = 0o10000000;

const AT_FDCWD: i64 = -100;

// `mmap(2)` / memory-management constants.
const MAP_ANONYMOUS: u64 = 0x20;

// `clock_nanosleep(2)` absolute-deadline flag.
const TIMER_ABSTIME: u64 = 1;

// `futex(2)` op decode (mirrors the libc `syscall()` interposer in
// patina_posix.c so the raw and wrapped paths route identically).
const FUTEX_WAIT: u64 = 0;

const FUTEX_WAKE: u64 = 1;

const FUTEX_WAIT_BITSET: u64 = 9;

const FUTEX_WAKE_BITSET: u64 = 10;

const FUTEX_PRIVATE_FLAG: u64 = 128;

const FUTEX_CLOCK_REALTIME: u64 = 256;

const NANOS_PER_SEC: u64 = 1_000_000_000;

// Patina FS entry kinds returned by the metadata / read-dir entries.
const PATINA_ENTRY_DIRECTORY: u32 = 2;

const PATINA_ENTRY_SYMLINK: u32 = 3;

const PATINA_ENTRY_FIFO: u32 = 4;

// getdents64 `d_type` values (linux_dirent64).
const DT_FIFO: u8 = 1;

const DT_DIR: u8 = 4;

const DT_REG: u8 = 8;

const DT_LNK: u8 = 10;

// File-mode bits for the kernel `struct stat`/`struct statx` (mirrors the C
// `patina_mode_for_kind`).
const S_IFIFO: u32 = 0o010000;

const S_IFDIR: u32 = 0o040000;

const S_IFREG: u32 = 0o100000;

const S_IFLNK: u32 = 0o120000;

/// `S_IFMT`: the file-type field of a `mode_t`, which `mknodat` carries.
const S_IFMT: u64 = 0o170000;

const S_IFCHR: u64 = 0o020000;

const S_IFBLK: u64 = 0o060000;

// `*at` flag bits.
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;

const AT_REMOVEDIR: u64 = 0x200;

const AT_SYMLINK_FOLLOW: u64 = 0x400;

const AT_EMPTY_PATH: u64 = 0x1000;

const AT_EACCESS: u64 = 0x200;

const AT_NO_AUTOMOUNT: u64 = 0x800;

// `statx(2)` sync-mode bits. They only choose how fresh a network filesystem's
// answer must be; a virtual filesystem is always exact, so they are accepted and
// ignored rather than failing closed (mirrors the C `statx` interposer).
const AT_STATX_SYNC_AS_STAT: u64 = 0x0000;

const AT_STATX_FORCE_SYNC: u64 = 0x2000;

const AT_STATX_DONT_SYNC: u64 = 0x4000;

// `access(2)` mode bits.
const X_OK: u64 = 1;

const W_OK: u64 = 2;

const R_OK: u64 = 4;

/// `utimensat(2)` `tv_nsec` sentinels.
const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

// `fcntl(2)` commands (identical on x86_64 and aarch64 Linux).
const F_DUPFD: u64 = 0;

const F_GETFD: u64 = 1;

const F_SETFD: u64 = 2;

const F_GETFL: u64 = 3;

const F_SETFL: u64 = 4;

const F_DUPFD_CLOEXEC: u64 = 1030;

const F_SETPIPE_SZ: u64 = 1031;

const F_GETPIPE_SZ: u64 = 1032;

const F_GETLK: u64 = 5;

const F_SETLK: u64 = 6;

const F_SETLKW: u64 = 7;

const F_OFD_GETLK: u64 = 36;

const F_OFD_SETLK: u64 = 37;

const F_OFD_SETLKW: u64 = 38;

const F_RDLCK: i16 = 0;

const F_WRLCK: i16 = 1;

const F_UNLCK: i16 = 2;

const LOCK_SH: c_int = 1;

const LOCK_EX: c_int = 2;

const LOCK_NB: c_int = 4;

const LOCK_UN: c_int = 8;

/// Kernel `struct flock` as the x86_64 / aarch64 Linux ABI lays it out (the
/// only two SUD platforms): what rustix's `fcntl_lock` hands `fcntl(2)`.
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelFlock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

const FD_CLOEXEC: i64 = 1;

const O_NONBLOCK: u64 = 0o4000;

/// `O_DIRECT` on a pipe asks for packet mode, which is not modeled.
const O_DIRECT: u64 = 0o40000;

// `ioctl(2)` request numbers used by nonblocking-flag toggling on virtual fds.
// (No FIONREAD row: the C ioctl models none, so a raw FIONREAD must fall to the
// same `-ENOTTY` an interposed one gets, not a fabricated 0.)
const FIONBIO: u64 = 0x5421;

const FIOCLEX: u64 = 0x5451;

const FIONCLEX: u64 = 0x5450;

// `socket(2)` domain / type / protocol constants (Linux, arch-independent).
const AF_INET: u16 = 2;

// AF_UNIX / AF_LOCAL (the only domain a deterministic socketpair models).
const AF_UNIX: i64 = 1;

const SOCK_STREAM: u64 = 1;

const SOCK_DGRAM: u64 = 2;

const SOCK_NONBLOCK: u64 = 0o4000;

const SOCK_CLOEXEC: u64 = 0o2000000;

const IPPROTO_TCP: u64 = 6;

const IPPROTO_UDP: u64 = 17;

// `shutdown(2)` how values.
const SHUT_RD: u64 = 0;

const SHUT_WR: u64 = 1;

const SHUT_RDWR: u64 = 2;

// setsockopt levels / options accepted as deterministic no-ops (mirrors the C
// setsockopt interposer's accepted subset).
const SOL_SOCKET: u64 = 1;

const SO_REUSEADDR: u64 = 2;

const SO_KEEPALIVE: u64 = 9;

const SO_BROADCAST: u64 = 6;

const SO_LINGER: u64 = 13;

const SO_REUSEPORT: u64 = 15;

const SO_RCVTIMEO: u64 = 20;

const SO_SNDTIMEO: u64 = 21;

const TCP_NODELAY: u64 = 1;

// `MSG_*` send/recv flags the virtual sockets tolerate (only MSG_NOSIGNAL is a
// no-op; anything else is unmodeled and fails closed, mirroring the C
// send/recv `patina_stream_flags_supported`).
const MSG_NOSIGNAL: u64 = 0x4000;

/// Kernel `struct sockaddr_in` on Linux (`sin_family`, `sin_port` (network
/// order), `sin_addr` (network order), padding). Read from / written to guest
/// memory during the socket-address rows.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

/// Kernel `struct timespec` on 64-bit Linux (`time_t` and `long` are both 8
/// bytes). Read from and written to guest memory during dispatch.
#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// Kernel `struct timeval` on 64-bit Linux.
#[repr(C)]
#[derive(Clone, Copy)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

thread_local! {
    /// Set while this thread is inside [`patina_sud_dispatch`]. A nested SIGSYS
    /// (i.e. a trap taken *while servicing a trap*) can only mean shim/runtime
    /// code executed a raw syscall — the one thing the audit instruction scan
    /// proves it never does. If the invariant were ever violated this flag turns
    /// the recursion into a loud, named abort instead of an unbounded SIGSYS
    /// storm. This is the standalone RED detector for the §4.2 soundness
    /// invariant ("shim never traps").
    static IN_DISPATCH: Cell<bool> = const { Cell::new(false) };
}

/// Only the kernel-frame release may re-enter dispatch as guest code.
pub(crate) fn with_signal_delivery(body: impl FnOnce()) {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            IN_DISPATCH.with(|cell| cell.set(self.0));
        }
    }
    let _restore = Restore(IN_DISPATCH.with(|cell| cell.replace(false)));
    body();
}

/// Run `body` with the reentry guard held. Re-entrant dispatch aborts loudly.
fn with_dispatch_guard<F: FnOnce() -> i64>(nr: i64, body: F) -> i64 {
    if IN_DISPATCH.with(Cell::get) {
        crate::trap_fatal(&format!(
            "SUD re-entered dispatch while servicing syscall {nr}: shim/runtime code executed a raw \
             syscall inside the SIGSYS handler (the instruction scan proves this cannot happen — a \
             reentry means the containment invariant is broken)"
        ));
    }
    IN_DISPATCH.with(|cell| cell.set(true));
    let result = body();
    IN_DISPATCH.with(|cell| cell.set(false));
    result
}

use std::collections::BTreeMap;

use std::sync::Mutex;

use std::sync::atomic::{AtomicUsize, Ordering};

/// Shape a raw-syscall return from a `patina_*` `int` result: on error the raw
/// caller reads `-errno` from the return register (there is no libc `errno`
/// step), on success the value itself.
fn ret_i32(result: c_int) -> i64 {
    if result < 0 {
        // SAFETY: `patina_errno` is a plain thread-local read.
        -(unsafe { patina_errno() } as i64)
    } else {
        result as i64
    }
}

/// As [`ret_i32`] for an `intptr_t`-returning entry point (`read`/`write`).
fn ret_isize(result: isize) -> i64 {
    if result < 0 {
        // SAFETY: as above.
        -(unsafe { patina_errno() } as i64)
    } else {
        result as i64
    }
}

/// A soft, DIAGNOSTIC deny — the SUD counterpart of the C `patina_posix_deny`.
/// It writes the byte-identical line to the CAPTURED stderr (fd 2, the recorded
/// stream) through the same `patina_stdio_write` entry the fd-2 write row uses,
/// then returns `-ENOSYS`. This is what gives a raw-backend guest and a
/// libc-backend guest the SAME recorded stderr when they hit the same refusal,
/// so trace / fingerprint comparison across the two backends does not diverge.
/// (Distinct from [`crate::trap_fatal`], which aborts and writes to the REAL host
/// stderr; a deny is a recoverable soft error the guest observes as `-ENOSYS`.)
/// `message` must be byte-for-byte identical to the C interposer's deny string,
/// including the `patina: ` prefix and trailing newline.
fn sud_deny(message: &str) -> i64 {
    // SAFETY: writing a byte slice to the captured-stderr runtime entry; when no
    // runtime is installed (unit tests) `patina_stdio_write` still appends to the
    // global capture buffer and returns, so this is side-effect-safe there too.
    unsafe {
        let _ = patina_stdio_write(2, message.as_ptr() as *const c_void, message.len());
    }
    -ENOSYS
}

/// The SIGSYS dispatch entry point. The C handler passes the decoded syscall
/// number, its six argument registers, and the faulting instruction address
/// (already validated by the C handler to lie within the main executable's
/// text). The returned value is written verbatim into the syscall's return
/// register — raw ABI, so a negative value is `-errno`.
///
/// The exported name doubles as the audit's SUD marker: a binary whose symbol
/// table *defines* `patina_sud_dispatch` carries a dispatch-capable shim, which
/// is condition (a) of the `direct-syscall` audit downgrade (see
/// `patina-target`). It is `#[used]`/`#[no_mangle]` and referenced by the C
/// handler, so it is never dead-stripped.
///
/// # Safety
/// Called only from the C `SIGSYS` handler on the faulting managed thread, with
/// argument registers that are the guest's own — pointers are valid guest
/// addresses for the lifetime of the (synchronous) dispatch.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_sud_dispatch(
    nr: c_long,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    call_addr: usize,
) -> c_long {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let _ = call_addr;
    // `c_long` is `i64` on the LP64 Linux targets this module compiles for, so it
    // matches the `i64` syscall-number table and dispatch signature directly.
    //
    // Thread-provenance invariant (SUD-DESIGN.md §4.2 invariant 1, restated): the
    // trapping thread is a managed task OR the pre-activation main thread —
    // identical thread-semantics to the interposer entries. The main thread gets
    // its managed TaskId lazily (`ensure_active`, on first thread-subsystem use),
    // so a raw syscall before any spawn runs with no CURRENT_TASK, exactly like an
    // interposed call would — the `patina_*` entries handle that today (the
    // UNMANAGED_TASK root fallback), and dispatch must not be stricter than the
    // boundary it mirrors (a hard managed-task assert here aborted every guest
    // whose first raw syscall preceded its first spawn). No dispatch-side check is
    // needed to hold the invariant: arming strictly follows `set_current_task` in
    // the trampoline, so an armed non-main thread always has a task; a foreign
    // host thread never executes the guest's inline syscall instructions (the C
    // handler already proved `call_addr` is in main-executable text); and shim/std
    // text contains zero raw syscalls (audit-proven), backstopped by the reentry
    // guard below.
    let args = [a0, a1, a2, a3, a4, a5];
    let result = with_dispatch_guard(nr, || {
        crate::thread::signals::refresh_handler_mask();
        dispatch(nr, args)
    });
    deliver();
    result
}

/// Interpret a syscall-argument register as a 32-bit `int` fd/dirfd — exactly as
/// the kernel does. The kernel reads fd/dirfd arguments as `int` (the low 32
/// bits), so a caller may fill the upper 32 register bits either way:
/// hand-written asm sign-extends a negative `AT_FDCWD` (-100 → `..FFFF_FF9C`),
/// but rustix's `linux_raw` backend ZERO-extends it (`raw_fd` does
/// `fd as c_uint as usize` → `0x0000_0000_FFFF_FF9C`). Reading the full 64-bit
/// register as `i64` would then see `AT_FDCWD` as a large positive number and
/// reject it (this exact gap made a rustix-default `openat(CWD, …)` return
/// EINVAL). Truncating to `i32` first recovers the kernel's view regardless of
/// how the upper bits were filled, and leaves every ordinary (small, positive)
/// fd unchanged.
#[inline]
fn arg_fd(reg: u64) -> i64 {
    reg as i32 as i64
}

/// A routed row's handler: the syscall number and its six argument registers
/// in, the raw return value out (`-errno` on failure). The number is passed so
/// the memory pass-through can hand the host kernel the exact number it trapped.
type Handler = fn(i64, [u64; 6]) -> i64;

/// The handler bound to each routed registry row, by row name. Dispatch is
/// GENERATED from `registry::SYSCALLS` (the [`DISPATCH`] index below is built
/// from the rows for this arch at compile time), so there is no second list of
/// numbers here — only the adapter from registers to the `sys_*` signature.
/// [`build_dispatch`] refuses to compile a `Modeled`/`Passthrough` row without
/// exactly one binding, a `Trap`/`Absent` row with one, or a binding that names
/// no row; `tests::bindings_match_the_registry_rows` reports the same
/// conditions by name.
///
/// fd/dirfd registers go through [`arg_fd`]; `AT_FDCWD` and any negative fd are
/// 32-bit `int`s the kernel reads from the low register bits.
const BINDINGS: &[(&str, Handler)] = &[
    ("select", |_, a| {
        sys_select(a[0], a[1], a[2], a[3], a[4], None)
    }),
    ("pselect6", |_, a| {
        sys_select(a[0], a[1], a[2], a[3], a[4], Some(a[5]))
    }),
    ("signalfd", |_, a| unsafe {
        crate::thread::signals::fd::patina_signalfd(
            a[0] as i32,
            a[1] as *const u64,
            a[2] as usize,
            0,
        )
    }),
    ("signalfd4", |_, a| unsafe {
        crate::thread::signals::fd::patina_signalfd(
            a[0] as i32,
            a[1] as *const u64,
            a[2] as usize,
            a[3] as i32,
        )
    }),
    // ---- time ----
    ("clock_gettime", |_, a| {
        sys_clock_gettime(a[0], a[1] as *mut Timespec)
    }),
    ("clock_getres", |_, a| {
        sys_clock_getres(a[0], a[1] as *mut Timespec)
    }),
    ("gettimeofday", |_, a| {
        sys_gettimeofday(a[0] as *mut Timeval)
    }),
    ("nanosleep", |_, a| {
        sys_nanosleep(a[0] as *const Timespec, a[1] as *mut Timespec)
    }),
    ("clock_nanosleep", |_, a| {
        sys_clock_nanosleep(a[0], a[1], a[2] as *const Timespec, a[3] as *mut Timespec)
    }),
    // ---- sync / sched / identity / entropy ----
    ("futex", |_, a| sys_futex(a)),
    ("getrandom", |_, a| sys_getrandom(a[0], a[1], a[2])),
    // SAFETY: plain runtime entry, no pointers.
    ("sched_yield", |_, _| {
        ret_i32(unsafe { patina_sched_yield() })
    }),
    // SAFETY: as above.
    ("gettid", |_, _| unsafe { patina_thread_id() as i64 }),
    ("set_tid_address", |_, a| unsafe {
        patina_set_tid_address(a[0] as *mut i32)
    }),
    ("exit", |_, a| unsafe { patina_raw_exit(a[0] as c_int) }),
    ("exit_group", |_, a| unsafe {
        patina_raw_exit_group(a[0] as c_int)
    }),
    // ---- memory: process-local, passed through to the host kernel via the
    // glibc `syscall(2)` HOST ALIAS (never the interposed `syscall`). Anonymous
    // only — an fd-backed mapping would bypass the deterministic FS.
    ("mmap", sys_mmap),
    ("munmap", mem_passthrough),
    ("mprotect", mem_passthrough),
    ("madvise", mem_passthrough),
    ("mremap", mem_passthrough),
    ("brk", mem_passthrough),
    // ---- signals / process rows owned by the signals conformance family ----
    // `rt_sigaction` for SIGSYS would replace the dispatch handler: fatal.
    ("rt_sigaction", |_, a| unsafe {
        patina_signal_action(
            a[0] as i32,
            a[1] as *const Action,
            a[2] as *mut Action,
            a[3] as usize,
        )
    }),
    ("rt_sigprocmask", |_, a| unsafe {
        patina_signal_mask(
            a[0] as i32,
            a[1] as *const u64,
            a[2] as *mut u64,
            a[3] as usize,
        )
    }),
    ("rt_sigpending", |_, a| unsafe {
        patina_signal_pending(a[0] as *mut u8, a[1] as usize)
    }),
    ("sigaltstack", |_, a| unsafe {
        patina_signal_altstack(a[0] as *const Stack, a[1] as *mut Stack)
    }),
    ("tkill", |_, a| unsafe {
        generate_signal(
            GenerationTarget::Thread {
                tgid: None,
                tid: a[0] as i32,
            },
            a[1] as i32,
            GenerationInfo::Thread,
        )
    }),
    ("rt_sigqueueinfo", |_, a| unsafe {
        generate_signal(
            GenerationTarget::Process { pid: a[0] as i32 },
            a[1] as i32,
            GenerationInfo::Queued(a[2] as *const Info),
        )
    }),
    ("rt_tgsigqueueinfo", |_, a| unsafe {
        generate_signal(
            GenerationTarget::Thread {
                tgid: Some(a[0] as i32),
                tid: a[1] as i32,
            },
            a[2] as i32,
            GenerationInfo::Queued(a[3] as *const Info),
        )
    }),
    ("pause", |_, _| unsafe {
        patina_signal_wait(
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            8,
            WaitMode::Pause,
        )
    }),
    ("rt_sigsuspend", |_, a| unsafe {
        patina_signal_wait(
            a[0] as *const u64,
            std::ptr::null_mut(),
            std::ptr::null(),
            a[1] as usize,
            WaitMode::Suspend,
        )
    }),
    ("rt_sigtimedwait", |_, a| unsafe {
        patina_signal_wait(
            a[0] as *const u64,
            a[1] as *mut Info,
            a[2] as *const crate::thread::signals::Timespec,
            a[3] as usize,
            WaitMode::Dequeue,
        )
    }),
    ("kill", |_, a| sys_kill(a[0] as i64, a[1] as i64)),
    ("tgkill", |_, a| {
        sys_tgkill(a[0] as i64, a[1] as i64, a[2] as i64)
    }),
    ("wait4", |_, _| sys_wait4()),
    ("waitid", |_, a| sys_waitid(a[3])),
    ("getpgid", |_, a| sys_getpgid(a[0] as i64)),
    ("getsid", |_, a| sys_getsid(a[0] as i64)),
    // ---- fd I/O ----
    ("read", |_, a| sys_read(arg_fd(a[0]), a[1], a[2])),
    ("write", |_, a| sys_write(arg_fd(a[0]), a[1], a[2])),
    ("close", |_, a| sys_close(arg_fd(a[0]))),
    ("lseek", |_, a| sys_lseek(arg_fd(a[0]), a[1] as i64, a[2])),
    ("pread64", |_, a| {
        sys_pread(arg_fd(a[0]), a[1], a[2], a[3] as i64)
    }),
    ("pwrite64", |_, a| {
        sys_pwrite(arg_fd(a[0]), a[1], a[2], a[3] as i64)
    }),
    ("readv", |_, a| sys_readv(arg_fd(a[0]), a[1], a[2] as i64)),
    ("writev", |_, a| sys_writev(arg_fd(a[0]), a[1], a[2] as i64)),
    ("fsync", |_, a| sys_fsync(arg_fd(a[0]))),
    ("fdatasync", |_, a| sys_fsync(arg_fd(a[0]))),
    ("ftruncate", |_, a| sys_ftruncate(arg_fd(a[0]), a[1] as i64)),
    ("fallocate", |_, a| {
        sys_fallocate(arg_fd(a[0]), a[1], a[2] as i64, a[3] as i64)
    }),
    ("flock", |_, a| sys_flock(arg_fd(a[0]), a[1] as i64)),
    ("dup", |_, a| sys_dup(arg_fd(a[0]))),
    ("dup3", |_, a| sys_dup3(arg_fd(a[0]), arg_fd(a[1]), a[2])),
    ("close_range", |_, a| sys_close_range(a[0], a[1], a[2])),
    ("fcntl", |_, a| sys_fcntl(arg_fd(a[0]), a[1], a[2])),
    ("ioctl", |_, a| sys_ioctl(arg_fd(a[0]), a[1], a[2])),
    ("pipe2", |_, a| sys_pipe2(a[0], a[1])),
    // ---- filesystem ----
    ("openat", |_, a| sys_openat(arg_fd(a[0]), a[1], a[2], a[3])),
    ("fstat", |_, a| sys_fstat(arg_fd(a[0]), a[1])),
    ("newfstatat", |_, a| {
        sys_newfstatat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    ("statx", |_, a| {
        sys_statx(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    ("getdents64", |_, a| {
        sys_getdents64(arg_fd(a[0]), a[1], a[2])
    }),
    ("mkdirat", |_, a| sys_mkdirat(arg_fd(a[0]), a[1], a[2])),
    ("mknodat", |_, a| {
        sys_mknodat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    ("unlinkat", |_, a| sys_unlinkat(arg_fd(a[0]), a[1], a[2])),
    ("symlinkat", |_, a| sys_symlinkat(a[0], arg_fd(a[1]), a[2])),
    ("readlinkat", |_, a| {
        sys_readlinkat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    ("linkat", |_, a| {
        sys_linkat(arg_fd(a[0]), a[1], arg_fd(a[2]), a[3], a[4])
    }),
    ("renameat", |_, a| {
        sys_renameat(arg_fd(a[0]), a[1], arg_fd(a[2]), a[3], 0)
    }),
    ("renameat2", |_, a| {
        sys_renameat(arg_fd(a[0]), a[1], arg_fd(a[2]), a[3], a[4])
    }),
    // `faccessat` carries no flags in the kernel ABI; `faccessat2` adds them.
    // rustix tries `faccessat2` first and falls back to `faccessat` on ENOSYS,
    // so BOTH are routed — a soft deny on `faccessat2` would print its
    // diagnostic on every `..` component a capability-based guest walks.
    ("faccessat", |_, a| {
        sys_faccessat(arg_fd(a[0]), a[1], a[2], 0)
    }),
    ("faccessat2", |_, a| {
        sys_faccessat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    // The working directory and the umask: process state the shim keeps, the
    // same state the C getcwd/chdir/fchdir/umask interposers use.
    ("getcwd", |_, a| sys_getcwd(a[0], a[1])),
    ("chdir", |_, a| sys_chdir(a[0])),
    ("fchdir", |_, a| sys_fchdir(arg_fd(a[0]))),
    ("umask", |_, a| sys_umask(a[0])),
    // Same shape for `fchmodat`/`fchmodat2`.
    ("fchmod", |_, a| sys_fchmod(arg_fd(a[0]), a[1])),
    ("fchmodat", |_, a| sys_fchmodat(arg_fd(a[0]), a[1], a[2], 0)),
    ("fchmodat2", |_, a| {
        sys_fchmodat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    // Timestamps, ownership and sizes: the same `patina_*` entries the C
    // utimensat/chown/truncate families call.
    ("utimensat", |_, a| {
        sys_utimensat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    ("fchownat", |_, a| {
        sys_fchownat(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    ("fchown", |_, a| sys_fchown(arg_fd(a[0]), a[1], a[2])),
    ("truncate", |_, a| sys_truncate(a[0], a[1] as i64)),
    // `openat2` is the RESOLVE_BENEATH open: a NAMED soft deny whose ENOSYS is
    // exactly what its callers probe for before falling back to `openat`.
    ("openat2", |_, _| sud_deny(DENY_OPENAT2)),
    // ---- network ----
    ("socket", |_, a| sys_socket(a[0], a[1], a[2])),
    ("bind", |_, a| sys_bind(arg_fd(a[0]), a[1], a[2] as u32)),
    ("listen", |_, a| sys_listen(arg_fd(a[0]), a[1] as i64)),
    ("connect", |_, a| {
        sys_connect(arg_fd(a[0]), a[1], a[2] as u32)
    }),
    ("accept", |_, a| sys_accept(arg_fd(a[0]), a[1], a[2], 0)),
    ("accept4", |_, a| sys_accept(arg_fd(a[0]), a[1], a[2], a[3])),
    ("sendto", |_, a| {
        sys_sendto(arg_fd(a[0]), a[1], a[2], a[3], a[4], a[5] as u32)
    }),
    ("recvfrom", |_, a| {
        sys_recvfrom(arg_fd(a[0]), a[1], a[2], a[3], a[4], a[5])
    }),
    ("sendmsg", |_, a| sys_sendmsg(arg_fd(a[0]), a[1], a[2])),
    ("recvmsg", |_, a| sys_recvmsg(arg_fd(a[0]), a[1], a[2])),
    ("shutdown", |_, a| sys_shutdown(arg_fd(a[0]), a[1])),
    ("getsockname", |_, a| {
        sys_getsockname(arg_fd(a[0]), a[1], a[2])
    }),
    ("getpeername", |_, a| {
        sys_getpeername(arg_fd(a[0]), a[1], a[2])
    }),
    ("setsockopt", |_, a| {
        sys_setsockopt(arg_fd(a[0]), a[1], a[2], a[3], a[4] as u32)
    }),
    ("getsockopt", |_, a| {
        sys_getsockopt(arg_fd(a[0]), a[3], a[4])
    }),
    ("socketpair", |_, a| sys_socketpair(a[0], a[1], a[2], a[3])),
    // ---- readiness ----
    ("epoll_create1", |_, a| sys_epoll_create1(a[0])),
    ("epoll_ctl", |_, a| {
        sys_epoll_ctl(arg_fd(a[0]), a[1] as i64, arg_fd(a[2]), a[3])
    }),
    ("epoll_wait", |_, a| {
        sys_epoll_wait(arg_fd(a[0]), a[1], a[2] as i64, a[3] as i64)
    }),
    ("epoll_pwait", |_, a| {
        sys_epoll_pwait(arg_fd(a[0]), a[1], a[2] as i64, a[3] as i64, a[4], a[5])
    }),
    ("epoll_pwait2", |_, a| {
        sys_epoll_pwait2(arg_fd(a[0]), a[1], a[2] as i64, a[3], a[4], a[5])
    }),
    ("eventfd2", |_, a| sys_eventfd2(a[0], a[1] as i64)),
    ("ppoll", |_, a| sys_ppoll(a[0], a[1], a[2], a[3], a[4])),
    // ---- process: the ONLY prctl option routed is PR_GET_AUXV ----
    ("prctl", |_, a| sys_prctl(a[0], a[1], a[2], a[3], a[4])),
    // ---- x86_64 legacy aliases (route to the SAME modern handler) ----
    // rustix's linux_raw backend and hand-written asm reach for the legacy
    // non-`*at` forms on x86_64; each is exactly its modern form with dirfd =
    // AT_FDCWD (and, for `creat`, synthesized flags). The registry gives these
    // rows no arm64 number, so the bindings are inert there.
    ("open", |_, a| sys_openat(AT_FDCWD, a[0], a[1], a[2])),
    // `creat(path, mode)` is `open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)`: the
    // mode is the SECOND argument here, not the third.
    ("creat", |_, a| {
        sys_openat(AT_FDCWD, a[0], O_CREAT | O_WRONLY | O_TRUNC, a[1])
    }),
    ("stat", |_, a| sys_newfstatat(AT_FDCWD, a[0], a[1], 0)),
    ("lstat", |_, a| {
        sys_newfstatat(AT_FDCWD, a[0], a[1], AT_SYMLINK_NOFOLLOW)
    }),
    ("unlink", |_, a| sys_unlinkat(AT_FDCWD, a[0], 0)),
    ("rmdir", |_, a| sys_unlinkat(AT_FDCWD, a[0], AT_REMOVEDIR)),
    ("mkdir", |_, a| sys_mkdirat(AT_FDCWD, a[0], a[1])),
    ("mknod", |_, a| sys_mknodat(AT_FDCWD, a[0], a[1], a[2])),
    ("rename", |_, a| {
        sys_renameat(AT_FDCWD, a[0], AT_FDCWD, a[1], 0)
    }),
    ("link", |_, a| sys_linkat(AT_FDCWD, a[0], AT_FDCWD, a[1], 0)),
    ("symlink", |_, a| sys_symlinkat(a[0], AT_FDCWD, a[1])),
    ("readlink", |_, a| {
        sys_readlinkat(AT_FDCWD, a[0], a[1], a[2])
    }),
    ("access", |_, a| sys_faccessat(AT_FDCWD, a[0], a[1], 0)),
    ("chmod", |_, a| sys_fchmodat(AT_FDCWD, a[0], a[1], 0)),
    ("chown", |_, a| sys_fchownat(AT_FDCWD, a[0], a[1], a[2], 0)),
    ("lchown", |_, a| {
        sys_fchownat(AT_FDCWD, a[0], a[1], a[2], AT_SYMLINK_NOFOLLOW)
    }),
    // The pre-utimensat time rows: whole seconds (`utime`), microseconds
    // (`utimes`, `futimesat`), each decoded onto the one set-times entry.
    ("utime", |_, a| sys_utime(a[0], a[1])),
    ("utimes", |_, a| sys_futimesat(AT_FDCWD, a[0], a[1])),
    ("futimesat", |_, a| sys_futimesat(arg_fd(a[0]), a[1], a[2])),
    ("dup2", |_, a| sys_dup2(arg_fd(a[0]), arg_fd(a[1]))),
    ("pipe", |_, a| sys_pipe2(a[0], 0)),
    ("eventfd", |_, a| sys_eventfd2(a[0], 0)),
    ("epoll_create", |_, a| sys_epoll_create(a[0])),
    ("poll", |_, a| sys_poll(a[0], a[1], a[2] as i32 as i64)),
];

/// "No row" / "no binding" sentinel in the dispatch index.
const NONE: u16 = u16::MAX;
/// The dispatch index covers numbers below this bound; the vendored tables top
/// out well under it (x86_64 at 472), and a number at or above it is answered
/// as "not in the vendored table" without consulting the index.
const INDEX_LEN: usize = 1024;

/// The compile-time dispatch index for this arch: number → row, row → binding.
struct Dispatch {
    row_for_nr: [u16; INDEX_LEN],
    binding_for_row: [u16; SYSCALLS.len()],
}

const DISPATCH: Dispatch = build_dispatch();

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Build [`DISPATCH`] from the registry rows for the host arch. Every check
/// here is a compile error, which is what makes the registry the single source
/// of dispatch: a row cannot claim `Modeled` without a handler, a `Trap` row
/// cannot carry one, and a binding cannot name a row that does not exist.
const fn build_dispatch() -> Dispatch {
    let arch = Arch::host();
    let mut row_for_nr = [NONE; INDEX_LEN];
    let mut binding_for_row = [NONE; SYSCALLS.len()];
    let mut i = 0;
    while i < SYSCALLS.len() {
        let row = &SYSCALLS[i];
        let mut bound = NONE;
        let mut j = 0;
        while j < BINDINGS.len() {
            if str_eq(BINDINGS[j].0, row.name) {
                if bound != NONE {
                    panic!("a registry row has two handler bindings in sud::BINDINGS");
                }
                bound = j as u16;
            }
            j += 1;
        }
        if row.disposition.is_routed() && bound == NONE {
            panic!("a Modeled/Passthrough registry row has no handler binding in sud::BINDINGS");
        }
        if !row.disposition.may_bind() && bound != NONE {
            panic!("a Trap/Absent registry row has a handler binding in sud::BINDINGS");
        }
        binding_for_row[i] = bound;
        if let Some(nr) = row.nr.for_arch(arch) {
            let nr = nr as usize;
            if nr >= INDEX_LEN {
                panic!("a registry row's syscall number exceeds sud::INDEX_LEN");
            }
            if row_for_nr[nr] != NONE {
                panic!("two registry rows share a syscall number on this arch");
            }
            row_for_nr[nr] = i as u16;
        }
        i += 1;
    }
    let mut j = 0;
    while j < BINDINGS.len() {
        let mut found = false;
        let mut i = 0;
        while i < SYSCALLS.len() {
            if str_eq(SYSCALLS[i].name, BINDINGS[j].0) {
                found = true;
            }
            i += 1;
        }
        if !found {
            panic!("a sud::BINDINGS entry names a syscall that has no registry row");
        }
        j += 1;
    }
    Dispatch {
        row_for_nr,
        binding_for_row,
    }
}

/// The registry row a number resolves to on this arch, if the vendored table
/// lists it.
fn row_for(nr: i64) -> Option<(usize, &'static SyscallRow)> {
    let index = usize::try_from(nr).ok().filter(|nr| *nr < INDEX_LEN)?;
    let row = DISPATCH.row_for_nr[index];
    (row != NONE).then(|| (row as usize, &SYSCALLS[row as usize]))
}

fn dispatch(nr: i64, args: [u64; 6]) -> i64 {
    let Some((index, row)) = row_for(nr) else {
        return not_in_table(nr, args);
    };
    let binding = DISPATCH.binding_for_row[index];
    let bound = (binding != NONE).then(|| BINDINGS[binding as usize].1);
    match (row.disposition, bound) {
        (Disposition::Modeled | Disposition::Passthrough, Some(handler)) => handler(nr, args),
        // A routed row always has a binding: `build_dispatch` refused to compile
        // otherwise. Unreachable by construction, and still a loud abort rather
        // than a silent answer if that ever stopped being true.
        (Disposition::Modeled | Disposition::Passthrough, None) => {
            crate::trap_fatal("SUD dispatch: a routed registry row has no handler binding")
        }
        // A bound handler answers a constant/soft-deny row (it may print the
        // shared deny diagnostic first); an unbound one is answered from the row.
        (Disposition::Constant(_) | Disposition::SoftDeny(_), Some(handler)) => handler(nr, args),
        (Disposition::Constant(value), None) => value,
        (Disposition::SoftDeny(errno), None) => -(errno as i64),
        (Disposition::Trap(class), _) => trap_row(row, class, nr, args),
        (Disposition::Absent, _) => -ENOSYS,
    }
}

/// A number the registry dispositions as a named, deterministic abort. The
/// diagnostic carries the row's name, class, and reasoning, so the guest's
/// stderr says exactly why the number is excluded and what closes it.
fn trap_row(row: &SyscallRow, class: &str, nr: i64, args: [u64; 6]) -> i64 {
    let closes = match row.closes_in {
        Some(arc) => format!(" Closes in the {arc} arc."),
        None => String::new(),
    };
    crate::trap_fatal(&format!(
        "SUD trapped unsupported syscall {} (nr {nr}, class {class}; args {:#x} {:#x} {:#x} {:#x} \
         {:#x} {:#x}): {}{closes} Guest raw syscalls must map to a deterministic route; `cargo \
         patina syscalls` lists every row",
        row.name, args[0], args[1], args[2], args[3], args[4], args[5], row.reasoning
    ));
}

/// A number the vendored table for this arch does not list at all: either
/// newer than the vendored snapshot (refresh the tables and add its row) or
/// garbage in the syscall register. Distinct from a trapped row, which is a
/// deliberate disposition.
fn not_in_table(nr: i64, args: [u64; 6]) -> i64 {
    crate::trap_fatal(&format!(
        "SUD trapped syscall number {nr}, which is not in the vendored Linux {} syscall table \
         (args {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}); run scripts/refresh-syscall-tables.sh and \
         add a registry row if the kernel has grown a number, or treat this as a corrupt raw \
         syscall",
        Arch::host().name(),
        args[0],
        args[1],
        args[2],
        args[3],
        args[4],
        args[5]
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The by-name twin of the compile-time checks in `build_dispatch`: the same
    /// three conditions, reported with the offending row/binding named. RED:
    /// plant a `("nonesuch", …)` binding, remove the `read` binding, or bind
    /// `fork`, and the message says which.
    #[test]
    fn bindings_match_the_registry_rows() {
        let mut problems = Vec::new();
        for row in SYSCALLS {
            let bound = BINDINGS
                .iter()
                .filter(|(name, _)| *name == row.name)
                .count();
            if row.disposition.is_routed() && bound == 0 {
                problems.push(format!(
                    "{}: routed row without a handler binding",
                    row.name
                ));
            }
            if !row.disposition.may_bind() && bound > 0 {
                problems.push(format!(
                    "{}: trap/absent row with a handler binding",
                    row.name
                ));
            }
            if bound > 1 {
                problems.push(format!("{}: bound {bound} times", row.name));
            }
        }
        for (name, _) in BINDINGS {
            if !SYSCALLS.iter().any(|row| row.name == *name) {
                problems.push(format!("{name}: binding names no registry row"));
            }
        }
        assert!(
            problems.is_empty(),
            "sud::BINDINGS and registry::SYSCALLS disagree:\n  {}",
            problems.join("\n  ")
        );
        // Every number the vendored table lists for this arch resolves to its row.
        for entry in crate::registry::table::linux_table(Arch::host()) {
            let (_, row) = row_for(entry.nr as i64).unwrap_or_else(|| {
                panic!("{} ({}) has no dispatch index entry", entry.name, entry.nr)
            });
            assert_eq!(row.name, entry.name);
        }
        assert!(row_for(INDEX_LEN as i64).is_none());
        assert!(row_for(-1).is_none());
    }

    #[test]
    fn arg_fd_reads_int_fds_the_way_the_kernel_does() {
        // The kernel reads fd/dirfd as a 32-bit `int` (low register bits). A
        // caller may sign-extend a negative fd (hand asm) OR zero-extend it
        // (rustix's linux_raw `raw_fd` does `fd as c_uint as usize`): both leave
        // the same low 32 bits, and `arg_fd` must recover the same `int`.
        // RED: reading the raw register as `i64` (the pre-fix behavior) makes the
        // zero-extended cases below large positive numbers, so `AT_FDCWD`
        // miscompares and a rustix `openat(CWD, …)` returns EINVAL.
        assert_eq!(arg_fd(0x0000_0000_FFFF_FF9C), AT_FDCWD); // rustix zero-extended AT_FDCWD
        assert_eq!(arg_fd(0xFFFF_FFFF_FFFF_FF9C), AT_FDCWD); // hand-asm sign-extended AT_FDCWD
        assert_eq!(arg_fd(0x0000_0000_FFFF_FFFF), -1); // zero-extended -1
        assert_eq!(arg_fd(0), 0);
        assert_eq!(arg_fd(5), 5);
        assert_eq!(arg_fd(0x4000_0005), 0x4000_0005);
    }

    /// The deny strings SUD and the C interposers emit for the same refusal must
    /// be byte-identical, or a raw-syscall guest and a libc guest record
    /// different stderr for the same event and their traces diverge on the
    /// refusal alone. `sud_deny`'s doc comment states the rule; this makes it a
    /// gate. RED: change either spelling and the assertion names both.
    #[test]
    fn every_shared_deny_matches_the_c_interposer_byte_for_byte() {
        // (The O_PATH|O_NOFOLLOW-on-a-symlink deny has no row: it is emitted
        // by the one Rust open entry both doors call, so there is no second
        // spelling to keep in step.) Adding a deny that BOTH doors can reach
        // means adding an assertion here.
        assert_eq!(
            c_deny_macro("PATINA_DENY_MKNOD_TYPE"),
            DENY_MKNOD_TYPE,
            "the SUD and C deny strings for a mknod of a special file that is not a FIFO \
             differ; a raw-syscall guest and a libc guest would record different stderr"
        );
    }

    /// Expand a `#define`d C deny string from the shim's C (the shared deny
    /// strings live in `c/posix/core.c`), concatenating its continuation lines'
    /// string literals exactly as the preprocessor does.
    fn c_deny_macro(macro_name: &str) -> String {
        const C_SOURCE: &str = include_str!("../../c/posix/core.c");
        let define = format!("#define {macro_name}");
        let start = C_SOURCE
            .find(&define)
            .unwrap_or_else(|| panic!("{macro_name} is not defined in c/posix/core.c"));
        let mut message = String::new();
        for line in C_SOURCE[start..].lines() {
            let mut rest = line;
            while let Some(open) = rest.find('"') {
                let tail = &rest[open + 1..];
                let close = tail.find('"').expect("unterminated C string literal");
                message.push_str(&tail[..close]);
                rest = &tail[close + 1..];
            }
            if !line.trim_end().ends_with('\\') {
                break;
            }
        }
        // The only escape either spelling uses is the trailing newline.
        message.replace("\\n", "\n")
    }

    #[test]
    fn sendmsg_recvmsg_mirror_the_interposer_enosys_never_fragment() {
        // The C sendmsg/recvmsg interposers fail closed with ENOSYS; the SUD
        // rows must return the identical refusal, NOT a per-iovec sendto/recvfrom
        // loop. RED: a fragmenting implementation would route the (fd, msg, flags)
        // through the net rows and return a byte count (or -EFAULT / other),
        // never exactly -ENOSYS — so this assertion catches the silently-wrong
        // datagram-fragmentation regression. Pure (no runtime entry is called),
        // so the argument values are irrelevant to the refusal.
        assert_eq!(sys_sendmsg(0, 0, 0), -ENOSYS);
        assert_eq!(sys_sendmsg(0x4000_0000, 0xdead_beef, 0x4000), -ENOSYS);
        assert_eq!(sys_recvmsg(0, 0, 0), -ENOSYS);
        assert_eq!(sys_recvmsg(0x4000_0000, 0xdead_beef, 0x4000), -ENOSYS);
    }

    #[test]
    fn prctl_option_narrows_to_unsigned_int_like_the_kernel() {
        // The kernel reads `option = (unsigned int) arg`, so only the low 32 bits
        // decide the route. rustix passes a clean 32-bit PR_GET_AUXV; hand asm may
        // sign-/zero-extend. RED: comparing the full 64-bit register would make a
        // sign-extended PR_GET_AUXV (or a high-bit-dirty PR_SET_NAME) miscompare —
        // either wrongly denying the auxv route or wrongly accepting an escape.
        assert_eq!(prctl_option(0x4155_5856), PR_GET_AUXV); // exact
        assert_eq!(prctl_option(0xFFFF_FFFF_4155_5856), PR_GET_AUXV); // dirty high bits ignored
        assert_ne!(prctl_option(15), PR_GET_AUXV); // PR_SET_NAME is denied
        assert_eq!(prctl_option(0x1_0000_000F), 15); // truncation: still PR_SET_NAME (denied)
    }

    #[test]
    fn pr_get_auxv_copy_mirrors_the_kernel_semantics() {
        // A stand-in scrubbed auxv (bytes are irrelevant to the copy math; the
        // real region runs through the AT_NULL pair inclusively).
        let saved: Vec<u8> = (0..48u8).collect();

        // Full copy: user buffer >= auxv. Returns the FULL length, copies it all.
        let mut user = vec![0xAAu8; 512];
        assert_eq!(
            pr_get_auxv_copy(&saved, user.as_mut_ptr(), user.len(), 0, 0),
            48
        );
        assert_eq!(&user[..48], &saved[..]);
        assert!(user[48..].iter().all(|&b| b == 0xAA)); // nothing past the auxv touched

        // Truncated copy: a small user buffer gets a prefix, but the return value
        // is STILL the full auxv length (what rustix uses to size its retry). RED:
        // returning the copied count would break rustix's `assert_eq!(len, buf)`.
        let mut small = vec![0u8; 16];
        assert_eq!(
            pr_get_auxv_copy(&saved, small.as_mut_ptr(), small.len(), 0, 0),
            48
        );
        assert_eq!(&small[..], &saved[..16]);

        // Nonzero arg4 or arg5 ⇒ -EINVAL, and NO bytes are copied.
        let mut untouched = vec![0x5Au8; 64];
        assert_eq!(
            pr_get_auxv_copy(&saved, untouched.as_mut_ptr(), untouched.len(), 1, 0),
            -EINVAL
        );
        assert_eq!(
            pr_get_auxv_copy(&saved, untouched.as_mut_ptr(), untouched.len(), 0, 1),
            -EINVAL
        );
        assert!(untouched.iter().all(|&b| b == 0x5A));

        // A zero-length user request copies nothing but still reports the length.
        assert_eq!(pr_get_auxv_copy(&saved, std::ptr::null_mut(), 0, 0, 0), 48);
        // A nonzero request with a null buffer faults (mirrors copy_to_user).
        assert_eq!(
            pr_get_auxv_copy(&saved, std::ptr::null_mut(), 8, 0, 0),
            -EFAULT
        );
    }

    #[test]
    fn creat_synthesizes_create_write_truncate_flags() {
        // The legacy `creat(path, mode)` alias routes to openat with a SYNTHESIZED
        // flag word `O_CREAT | O_WRONLY | O_TRUNC` (creat has no flags argument).
        // That must decode to a writable, creating, truncating open — never a
        // read-only one (which would drop the file's contents differently and
        // fail to create). RED: synthesizing the wrong flags (e.g. O_RDONLY=0)
        // would decode to PATINA_O_READ with no create/truncate bit.
        let flags = openat_patina_flags(O_CREAT | O_WRONLY | O_TRUNC);
        assert_eq!(
            flags,
            PATINA_O_WRITE | PATINA_O_CREATE | PATINA_O_TRUNCATE,
            "creat must be write+create+truncate"
        );
        // And it must NOT be classified read-only (that gates the directory-fd
        // fallback path in sys_openat).
        let read_only = flags & (PATINA_O_WRITE | PATINA_O_CREATE | PATINA_O_TRUNCATE) == 0;
        assert!(!read_only, "creat is never a read-only open");

        // A bare `open(path, O_RDONLY)` (the read alias) decodes read-only — this
        // pins the contrast the alias relies on.
        assert_eq!(openat_patina_flags(0), PATINA_O_READ);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn dup2_diverges_from_dup3_only_on_equal_fds() {
        // The kernel-exact divergence: dup2(fd, fd) is a validating no-op that
        // returns fd, whereas dup3(fd, fd, 0) is -EINVAL. RED: routing legacy
        // `dup2` straight through the dup3 handler (or vice versa) would turn a
        // valid stdio dup2(1,1) into -EINVAL, breaking any raw dup2-based fd
        // shuffle. The descriptor table alone answers these (no runtime is
        // installed here): the three standard numbers exist from birth.
        assert_eq!(sys_dup2(0, 0), 0);
        assert_eq!(sys_dup2(1, 1), 1);
        assert_eq!(sys_dup2(2, 2), 2);
        assert_eq!(sys_dup3(0, 0, 0), -EINVAL);
        assert_eq!(sys_dup3(1, 1, 0), -EINVAL);
        // An out-of-range equal fd is EBADF (a bad descriptor), NOT EINVAL.
        assert_eq!(sys_dup2(-1, -1), -EBADF);
        // A source that names nothing is EBADF before the target is looked at.
        assert_eq!(sys_dup2(900, 901), -EBADF);
        assert_eq!(sys_dup3(900, 901, 0), -EBADF);
        // dup3 refuses a flag other than O_CLOEXEC before touching the table.
        assert_eq!(sys_dup3(0, 901, 0o4000), -EINVAL);
        // A chosen number well above the table is EBADF.
        assert_eq!(sys_dup3(0, 1 << 20, 0), -EBADF);
    }

    #[test]
    fn socketpair_validates_args_in_c_order() {
        // A non-null dummy sv pointer that is never dereferenced on the failure
        // paths (each check below returns before touching it).
        let sv: u64 = 0x1000;
        // Null sv is EFAULT, checked FIRST — even with otherwise-valid args.
        assert_eq!(sys_socketpair(AF_UNIX as u64, SOCK_STREAM, 0, 0), -EFAULT);
        // Wrong domain → EAFNOSUPPORT (only AF_UNIX is a deterministic duplex).
        assert_eq!(
            sys_socketpair(AF_INET as u64, SOCK_STREAM, 0, sv),
            -EAFNOSUPPORT
        );
        // Non-STREAM base type → EOPNOTSUPP, and SOCK_NONBLOCK is stripped BEFORE
        // that compare (a DGRAM|NONBLOCK stays DGRAM, not mistaken for STREAM).
        assert_eq!(
            sys_socketpair(AF_UNIX as u64, SOCK_DGRAM, 0, sv),
            -EOPNOTSUPP
        );
        assert_eq!(
            sys_socketpair(AF_UNIX as u64, SOCK_DGRAM | SOCK_NONBLOCK, 0, sv),
            -EOPNOTSUPP
        );
        // A STREAM pair with a non-zero protocol → EPROTONOSUPPORT (the NONBLOCK
        // and CLOEXEC bits are stripped, so the base is a clean STREAM here).
        assert_eq!(
            sys_socketpair(
                AF_UNIX as u64,
                SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                6,
                sv
            ),
            -EPROTONOSUPPORT
        );
    }

    #[test]
    fn poll_validates_buffers_and_descriptor_limit_before_waiting() {
        assert_eq!(poll_core(0, 1, None), -EFAULT);
        assert_eq!(poll_core(0, 1025, Some(0)), -EINVAL);
        assert_eq!(sys_ppoll(0, 0, 0, 1, 4), -EINVAL);
    }

    #[test]
    fn fcntl_and_ioctl_answer_from_the_descriptor_table() {
        // No runtime is installed here: the descriptor table alone answers, and
        // it holds exactly the three standard numbers. A number that names
        // nothing is EBADF for every command (the kernel checks the number
        // before the command), an unknown command on an open number is EINVAL,
        // and FD_CLOEXEC is per number while F_GETFL/F_SETFL are per
        // description (C parity through the SAME entries).
        assert_eq!(sys_fcntl(5, F_GETFD, 0), -EBADF);
        assert_eq!(sys_fcntl(5, F_SETFD, 0), -EBADF);
        assert_eq!(sys_fcntl(5, F_GETFL, 0), -EBADF);
        assert_eq!(sys_fcntl(5, F_SETFL, 0), -EBADF);
        assert_eq!(sys_fcntl(5, 0x9999, 0), -EBADF);
        assert_eq!(sys_fcntl(2, 0x9999, 0), -EINVAL);
        assert_eq!(sys_fcntl(0, F_GETFL, 0), 0); // O_RDONLY
        assert_eq!(sys_fcntl(2, F_GETFL, 0), O_WRONLY as i64);
        assert_eq!(sys_fcntl(2, F_GETFD, 0), 0);
        assert_eq!(sys_fcntl(2, F_SETFD, FD_CLOEXEC as u64), 0);
        assert_eq!(sys_fcntl(2, F_GETFD, 0), FD_CLOEXEC);
        assert_eq!(sys_fcntl(2, F_SETFD, 0), 0);
        assert_eq!(sys_fcntl(2, F_GETFD, 0), 0);
        // F_SETFL changes O_APPEND/O_NONBLOCK and nothing else.
        assert_eq!(sys_fcntl(2, F_SETFL, O_NONBLOCK | O_RDWR), 0);
        assert_eq!(sys_fcntl(2, F_GETFL, 0), (O_WRONLY | O_NONBLOCK) as i64);
        assert_eq!(sys_fcntl(2, F_SETFL, 0), 0);
        assert_eq!(sys_fcntl(2, F_GETFL, 0), O_WRONLY as i64);
        // ioctl: FIOCLEX/FIONCLEX are the FD_CLOEXEC bit; an unknown request is
        // a soft -ENOTTY on an open number (never fatal, never a fake
        // FIONREAD=0) and -EBADF on a closed one.
        assert_eq!(sys_ioctl(2, FIOCLEX, 0), 0);
        assert_eq!(sys_fcntl(2, F_GETFD, 0), FD_CLOEXEC);
        assert_eq!(sys_ioctl(2, FIONCLEX, 0), 0);
        assert_eq!(sys_fcntl(2, F_GETFD, 0), 0);
        assert_eq!(sys_ioctl(2, 0x1234, 0), -ENOTTY);
        assert_eq!(sys_ioctl(5, 0x1234, 0), -EBADF);
        assert_eq!(sys_ioctl(5, FIOCLEX, 0), -EBADF);
    }

    #[test]
    fn openat_flag_decode_ignores_largefile_directory_cloexec_bits() {
        // rustix ORs O_LARGEFILE (0x8000) into every open, and a directory open
        // adds O_DIRECTORY|O_CLOEXEC. The legacy `open`/`creat` aliases and the
        // direct `openat` share ONE decode (`openat_patina_flags`), so they are
        // bit-for-bit identical — the round-6 EBADF was NOT a flag defect (it was
        // the dir-fd fcntl/openat gap). This pins that: the noise bits never
        // perturb the decode. RED: folding O_LARGEFILE into the access-mode
        // compare, or reacting to O_DIRECTORY, would diverge open from openat.
        // O_CLOEXEC is NOT noise: it is the new number's FD_CLOEXEC bit.
        let noise = O_LARGEFILE | O_DIRECTORY;
        assert_eq!(
            openat_patina_flags(O_RDWR | O_CLOEXEC),
            PATINA_O_READ | PATINA_O_WRITE | PATINA_O_CLOEXEC
        );
        // The EXACT round-5 flag word (O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE).
        assert_eq!(
            openat_patina_flags(0x8241),
            PATINA_O_WRITE | PATINA_O_CREATE | PATINA_O_TRUNCATE
        );
        // A directory open decodes read-only plus the directory requirement;
        // the ONE open entry decides the descriptor's kind from the entry's,
        // so the bit travels rather than routing here.
        assert_eq!(
            openat_patina_flags(O_DIRECTORY | O_LARGEFILE),
            PATINA_O_READ | PATINA_O_DIRECTORY
        );
        // `O_PATH` opens nothing: the access mode and every creating bit are
        // dropped under it, exactly as the kernel ignores them.
        assert_eq!(
            openat_patina_flags(O_PATH | O_RDWR | O_CREAT | O_CLOEXEC),
            PATINA_O_PATH | PATINA_O_CLOEXEC
        );
        // The noise bits are inert atop any base access/creation flag word.
        for base in [
            0,
            O_WRONLY,
            O_RDWR,
            O_CREAT | O_WRONLY | O_TRUNC,
            O_APPEND | O_WRONLY,
        ] {
            assert_eq!(
                openat_patina_flags(base) | PATINA_O_DIRECTORY,
                openat_patina_flags(base | noise)
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn epoll_create_rejects_nonpositive_size_like_the_kernel() {
        // Legacy `epoll_create(size)` ignores `size` since 2.6.8 but still rejects
        // `size <= 0` with -EINVAL before creating. RED: dropping the guard would
        // let epoll_create(0) fall through to epoll_create1 and succeed, diverging
        // from the kernel. (size > 0 delegates to the runtime and is covered
        // end-to-end by the epoll validate leg.)
        assert_eq!(sys_epoll_create(0), -EINVAL);
        assert_eq!(sys_epoll_create(0xFFFF_FFFF), -EINVAL); // reads as int -1
    }
}
