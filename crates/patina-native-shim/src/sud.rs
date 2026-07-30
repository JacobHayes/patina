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
//! This module is `x86_64`-first (the only arch with kernel SUD today); the
//! `aarch64` number table compiles so the dispatcher lights up unchanged when
//! generic-entry arm64 kernels ship, but it is dead at runtime there (the kernel
//! probe fails and the run is refused before exec — see the audit gate).

use std::cell::Cell;
use std::ffi::{c_char, c_int, c_long, c_void};

// The `patina_*` runtime entry points the C interposers call. Declaring them as
// externs (rather than reaching for module paths) routes SUD through the exact
// same symbols — there is no second implementation of any effect. Every one is a
// `#[no_mangle] extern "C"` definition elsewhere in this crate.
unsafe extern "C" {
    fn patina_errno() -> c_int;
    fn patina_clock_now(clock: u32, nanos: *mut u64) -> c_int;
    fn patina_sleep_until(clock: u32, deadline_nanos: u64) -> c_int;
    fn patina_open(path: *const c_char, flags: u32) -> c_int;
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
    fn patina_exit(status: c_int) -> !;
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
    fn patina_metadata_full(
        path: *const c_char,
        kind: *mut u32,
        length: *mut u64,
        ino: *mut u64,
        nlink: *mut u32,
        atime_nanos: *mut u64,
        mtime_nanos: *mut u64,
    ) -> c_int;
    fn patina_fd_metadata_full(
        fd: c_int,
        kind: *mut u32,
        length: *mut u64,
        ino: *mut u64,
        nlink: *mut u32,
        atime_nanos: *mut u64,
        mtime_nanos: *mut u64,
    ) -> c_int;
    fn patina_read_dir(path: *const c_char, state_out: *mut *mut c_void) -> c_int;
    fn patina_read_dir_next(
        state: *mut c_void,
        name_buf: *mut c_char,
        buf_len: usize,
        kind: *mut u32,
    ) -> c_int;
    fn patina_read_dir_free(state: *mut c_void);
    fn patina_mkdir(path: *const c_char) -> c_int;
    fn patina_unlink(path: *const c_char) -> c_int;
    fn patina_rmdir(path: *const c_char) -> c_int;
    fn patina_rename(from: *const c_char, to: *const c_char) -> c_int;
    fn patina_symlink(target: *const c_char, link_path: *const c_char) -> c_int;
    fn patina_read_link(path: *const c_char, buf: *mut c_char, buf_len: usize) -> isize;
    fn patina_pipe(read_fd_out: *mut c_int, write_fd_out: *mut c_int, nonblocking: c_int) -> c_int;

    // Network (SimNet) — the exact entries the C socket interposers call.
    fn patina_net_socket(stream: c_int, nonblocking: c_int) -> c_int;
    fn patina_net_kind(fd: c_int) -> c_int;
    fn patina_net_bind(fd: c_int, ip: u32, port: u16) -> c_int;
    fn patina_net_connect(fd: c_int, ip: u32, port: u16) -> c_int;
    fn patina_net_tcp_connect(fd: c_int, ip: u32, port: u16) -> c_int;
    fn patina_net_listen(fd: c_int, backlog: c_int) -> c_int;
    fn patina_net_accept(fd: c_int, ip_out: *mut u32, port_out: *mut u16) -> c_int;
    fn patina_net_sendto(fd: c_int, buf: *const c_void, len: usize, ip: u32, port: u16) -> isize;
    fn patina_net_send(fd: c_int, buf: *const c_void, len: usize) -> isize;
    fn patina_net_stream_send(fd: c_int, buf: *const c_void, len: usize) -> isize;
    fn patina_net_recvfrom(
        fd: c_int,
        buf: *mut c_void,
        len: usize,
        ip_out: *mut u32,
        port_out: *mut u16,
    ) -> isize;
    fn patina_net_recv(fd: c_int, buf: *mut c_void, len: usize) -> isize;
    fn patina_net_stream_recv(fd: c_int, buf: *mut c_void, len: usize) -> isize;
    fn patina_net_shutdown(fd: c_int, how: c_int) -> c_int;
    fn patina_net_getsockname(fd: c_int, ip_out: *mut u32, port_out: *mut u16) -> c_int;
    fn patina_net_getpeername(fd: c_int, ip_out: *mut u32, port_out: *mut u16) -> c_int;
    fn patina_net_set_nonblocking(fd: c_int, nonblocking: c_int) -> c_int;
    fn patina_net_set_read_timeout(fd: c_int, nanos: u64) -> c_int;
    fn patina_net_is_nonblocking(fd: c_int) -> c_int;
    fn patina_net_close(fd: c_int) -> c_int;
    fn patina_socketpair(fd0_out: *mut c_int, fd1_out: *mut c_int, nonblocking: c_int) -> c_int;

    // In-process pipe / socketpair endpoints and eventfds.
    fn patina_pipe_is_endpoint(fd: c_int) -> c_int;
    fn patina_pipe_read(fd: c_int, buf: *mut c_void, len: usize) -> isize;
    fn patina_pipe_write(fd: c_int, buf: *const c_void, len: usize) -> isize;
    fn patina_pipe_dup(fd: c_int) -> c_int;
    fn patina_pipe_close(fd: c_int) -> c_int;
    fn patina_pipe_is_nonblocking(fd: c_int) -> c_int;
    fn patina_pipe_set_nonblocking(fd: c_int, nonblocking: c_int) -> c_int;
    fn patina_eventfd(initval: u32, flags: c_int) -> c_int;
    fn patina_eventfd_is(fd: c_int) -> c_int;
    fn patina_eventfd_read(fd: c_int, buf: *mut c_void, len: usize) -> isize;
    fn patina_eventfd_write(fd: c_int, buf: *const c_void, len: usize) -> isize;
    fn patina_eventfd_close(fd: c_int) -> c_int;

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
    fn patina_epoll_is_epoll(fd: c_int) -> c_int;
    fn patina_epoll_dup(fd: c_int) -> c_int;
    fn patina_epoll_close(fd: c_int) -> c_int;
}

// Linux errno values used to shape raw-syscall returns (`-errno`). Fixed across
// the Linux ABIs Patina targets.
const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const ENOTDIR: i64 = 20;
const EISDIR: i64 = 21;
const EINVAL: i64 = 22;
const ENOTTY: i64 = 25;
const ESPIPE: i64 = 29;
const ENOSYS: i64 = 38;
const ENOTSOCK: i64 = 88;
const EOPNOTSUPP: i64 = 95;
const EAFNOSUPPORT: i64 = 97;
const ENOPROTOOPT: i64 = 92;
const EISCONN: i64 = 106;
const ENOTCONN: i64 = 107;
const EPROTONOSUPPORT: i64 = 93;
const EPROTOTYPE: i64 = 91;
const ELOOP: i64 = 40;
const ENAMETOOLONG: i64 = 36;
const EIO: i64 = 5;

/// The virtual-descriptor base: any fd at or above this is a Patina socket /
/// pipe / eventfd / epoll descriptor (mirrors `PATINA_SOCKET_FD_BASE` in
/// `patina_native.h`). A raw read/write/close on such an fd must route through
/// the same fd-class dispatch the C `read`/`write`/`close` interposers use.
const PATINA_SOCKET_FD_BASE: i64 = 0x4000_0000;

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

// Kernel `open(2)` flag bits (octal), identical on x86_64 and aarch64 Linux.
const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;

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

// getdents64 `d_type` values (linux_dirent64).
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;

// File-mode bits for the kernel `struct stat`/`struct statx` (mirrors the C
// `patina_mode_for_kind`).
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

// `*at` flag bits.
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EMPTY_PATH: u64 = 0x1000;

// `fcntl(2)` commands (identical on x86_64 and aarch64 Linux).
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_DUPFD_CLOEXEC: u64 = 1030;
const FD_CLOEXEC: i64 = 1;
const O_NONBLOCK: u64 = 0o4000;

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

/// Run `body` with the reentry guard held. A re-entrant dispatch aborts loudly.
fn with_dispatch_guard<F: FnOnce() -> i64>(nr: i64, body: F) -> i64 {
    if IN_DISPATCH.with(Cell::get) {
        crate::sud_fatal(&format!(
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

// ===========================================================================
// SUD directory-fd model (getdents64).
//
// The deterministic filesystem refuses to hand out a descriptor for a directory
// (`fs_open` returns EISDIR): the interposed path models directory iteration
// through the *path-based* `opendir`/`readdir` strong defs, which call
// `patina_read_dir`. A raw caller (rustix's `Dir`, hand-rolled getdents) instead
// does `openat(dir, O_DIRECTORY) → getdents64(fd)` — it needs a real directory
// fd. So the SUD layer models one: when a read-only `openat` lands on a
// directory (EISDIR), it snapshots the directory through the SAME
// `patina_read_dir` entry the interposed `opendir` uses and hands back a
// SUD-private descriptor; `getdents64` then walks that snapshot into
// `linux_dirent64` records, `lseek(…,0,SEEK_SET)` rewinds it (re-snapshot), and
// `close`/`fstat` recognize it. Entries come from the one runtime entry — this
// is a second *caller*, never a second directory model.
// ===========================================================================

use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

/// SUD-private directory descriptors are drawn from a high, distinct range so
/// they never collide with the runtime's regular fds (small, from 3) or the
/// virtual socket/pipe/eventfd/epoll space (`>= PATINA_SOCKET_FD_BASE`,
/// 0x4000_0000). The counter is bumped once per directory open; the schedule is
/// deterministic, so the fd numbers are a deterministic function of it.
const PATINA_SUD_DIR_FD_BASE: i32 = 0x6000_0000;
static NEXT_DIR_FD: AtomicI32 = AtomicI32::new(PATINA_SUD_DIR_FD_BASE);

/// A directory-iteration snapshot behind a SUD directory fd. The snapshot
/// pointer is a `Box<ReadDirState>` owned by `patina_read_dir`; it is only ever
/// touched under [`DIR_FDS`]'s lock, so passing it across threads is sound (the
/// raw pointer is stored as `usize` to keep the map `Send`).
struct DirFd {
    path: CString,
    snapshot: usize,
    /// An entry read from the snapshot that did not fit the previous
    /// `getdents64` buffer, held so the next call emits it first (the kernel
    /// never drops an entry it could not return). `patina_read_dir_next` only
    /// advances, so there is no peek — this is the one-slot push-back.
    pending: Option<(Vec<u8>, u32)>,
}

static DIR_FDS: Mutex<BTreeMap<i32, DirFd>> = Mutex::new(BTreeMap::new());

fn is_sud_dir_fd(fd: i64) -> bool {
    fd >= PATINA_SUD_DIR_FD_BASE as i64 && DIR_FDS.lock().unwrap().contains_key(&(fd as i32))
}

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
/// (Distinct from [`crate::sud_fatal`], which aborts and writes to the REAL host
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

/// The one `prctl(2)` option the dispatch table routes: `PR_GET_AUXV` (Linux
/// 6.4 and later). rustix's `linux_raw` backend calls `prctl(PR_GET_AUXV, buf,
/// size, 0, 0)` to read the aux vector during init. Read as an `unsigned int`
/// exactly as the kernel does (`option = (unsigned int) arg`); see
/// [`prctl_option`].
const PR_GET_AUXV: u32 = 0x4155_5856;

/// The shim's own **scrubbed** auxv region, captured once at init by the C
/// arming path (`patina_sud_scrub_auxv`): the base pointer of the initial-stack
/// aux array and its byte length through the terminating `AT_NULL` pair
/// (inclusive). OWNED by Rust and written by C — the same C→Rust ownership
/// direction as [`crate::PATINA_SUD_ARMED`], so the lib's own test binary (which
/// links no C) still defines the symbols. The `PR_GET_AUXV` dispatch row copies
/// from here so a raw `prctl(PR_GET_AUXV)` serves the SAME determinized auxv the
/// shim already produced in memory — `AT_RANDOM` replaced with seed-derived
/// bytes and `AT_SYSINFO_EHDR` renamed to `AT_IGNORE` — instead of the kernel's
/// pristine `saved_auxv`, which would reintroduce the entropy / vDSO escape
/// (SUD-DESIGN.md §6, §9). `0` until C captures it; a trap seeing `0` fails
/// closed rather than serve garbage (see [`sys_prctl`]).
#[unsafe(no_mangle)]
pub static PATINA_SUD_AUXV_BASE: AtomicUsize = AtomicUsize::new(0);
#[unsafe(no_mangle)]
pub static PATINA_SUD_AUXV_LEN: AtomicUsize = AtomicUsize::new(0);

/// The syscall numbers slice 1 routes, selected per target arch at compile time.
/// x86_64 is the shipping arch; the aarch64 set compiles so the dispatcher is
/// arch-complete for when generic-entry arm64 kernels ship, and is inert at
/// runtime there (no kernel SUD ⇒ the run is refused before it can trap).
#[cfg(target_arch = "x86_64")]
mod nr {
    pub const READ: i64 = 0;
    pub const WRITE: i64 = 1;
    pub const CLOSE: i64 = 3;
    pub const LSEEK: i64 = 8;
    pub const MMAP: i64 = 9;
    pub const MPROTECT: i64 = 10;
    pub const MUNMAP: i64 = 11;
    pub const BRK: i64 = 12;
    pub const RT_SIGACTION: i64 = 13;
    pub const RT_SIGPROCMASK: i64 = 14;
    pub const MADVISE: i64 = 28;
    pub const NANOSLEEP: i64 = 35;
    pub const SCHED_YIELD: i64 = 24;
    pub const MREMAP: i64 = 25;
    pub const EXIT: i64 = 60;
    pub const GETTIMEOFDAY: i64 = 96;
    pub const SIGALTSTACK: i64 = 131;
    pub const GETTID: i64 = 186;
    pub const FUTEX: i64 = 202;
    pub const SET_ROBUST_LIST: i64 = 273;
    pub const CLOCK_GETTIME: i64 = 228;
    pub const CLOCK_GETRES: i64 = 229;
    pub const CLOCK_NANOSLEEP: i64 = 230;
    pub const EXIT_GROUP: i64 = 231;
    pub const OPENAT: i64 = 257;
    pub const GETRANDOM: i64 = 318;
    pub const MEMBARRIER: i64 = 324;
    pub const RSEQ: i64 = 334;

    // Slice 2 — filesystem.
    pub const FSTAT: i64 = 5;
    pub const IOCTL: i64 = 16;
    pub const PREAD64: i64 = 17;
    pub const PWRITE64: i64 = 18;
    pub const READV: i64 = 19;
    pub const WRITEV: i64 = 20;
    pub const DUP: i64 = 32;
    pub const FCNTL: i64 = 72;
    pub const FLOCK: i64 = 73;
    pub const FSYNC: i64 = 74;
    pub const FDATASYNC: i64 = 75;
    pub const FTRUNCATE: i64 = 77;
    pub const GETDENTS64: i64 = 217;
    pub const MKDIRAT: i64 = 258;
    pub const NEWFSTATAT: i64 = 262;
    pub const UNLINKAT: i64 = 263;
    pub const RENAMEAT: i64 = 264;
    pub const SYMLINKAT: i64 = 266;
    pub const READLINKAT: i64 = 267;
    pub const DUP3: i64 = 292;
    pub const PIPE2: i64 = 293;
    pub const RENAMEAT2: i64 = 316;
    pub const STATX: i64 = 332;

    // Slice 2 — network.
    pub const SOCKET: i64 = 41;
    pub const CONNECT: i64 = 42;
    pub const ACCEPT: i64 = 43;
    pub const SENDTO: i64 = 44;
    pub const RECVFROM: i64 = 45;
    pub const SENDMSG: i64 = 46;
    pub const RECVMSG: i64 = 47;
    pub const SHUTDOWN: i64 = 48;
    pub const BIND: i64 = 49;
    pub const LISTEN: i64 = 50;
    pub const GETSOCKNAME: i64 = 51;
    pub const GETPEERNAME: i64 = 52;
    pub const SETSOCKOPT: i64 = 54;
    pub const GETSOCKOPT: i64 = 55;
    pub const ACCEPT4: i64 = 288;
    pub const SOCKETPAIR: i64 = 53;

    // Slice 2 — readiness (epoll frontend) + eventfd + ppoll.
    pub const EPOLL_WAIT: i64 = 232;
    pub const EPOLL_CTL: i64 = 233;
    pub const EPOLL_PWAIT: i64 = 281;
    pub const EVENTFD2: i64 = 290;
    pub const EPOLL_CREATE1: i64 = 291;
    pub const EPOLL_PWAIT2: i64 = 441;
    pub const PPOLL: i64 = 271;

    // Slice 2 — deterministic process-state constants.
    pub const GETPID: i64 = 39;
    pub const GETUID: i64 = 102;
    pub const GETGID: i64 = 104;
    pub const GETEUID: i64 = 107;
    pub const GETEGID: i64 = 108;
    pub const GETPPID: i64 = 110;
    pub const UNAME: i64 = 63;

    // Slice 2 — the ONLY prctl option routed is PR_GET_AUXV (below); every other
    // option is the process/escape class and fails closed in the dispatch arm.
    pub const PRCTL: i64 = 157;

    // Slice 2 — x86_64 LEGACY aliases. These non-`*at` / non-`p*` numbers exist
    // ONLY on x86_64 (aarch64 is `*at`-only), so they live in this module alone
    // and their dispatch arms are `#[cfg(target_arch = "x86_64")]`. Each aliases
    // an already-routed modern form with the same semantics (dirfd injected as
    // AT_FDCWD, flags synthesized) — NO new effect, one source of truth. rustix's
    // linux_raw backend emits several of these directly on x86_64 (e.g. `open` →
    // `__NR_open`), which is what a raw-syscall guest traps on.
    pub const OPEN: i64 = 2;
    pub const STAT: i64 = 4;
    pub const LSTAT: i64 = 6;
    pub const PIPE: i64 = 22;
    pub const DUP2: i64 = 33;
    pub const RENAME: i64 = 82;
    pub const MKDIR: i64 = 83;
    pub const RMDIR: i64 = 84;
    pub const CREAT: i64 = 85;
    pub const UNLINK: i64 = 87;
    pub const SYMLINK: i64 = 88;
    pub const READLINK: i64 = 89;
    pub const EPOLL_CREATE: i64 = 213;
    pub const EVENTFD: i64 = 284;
    pub const POLL: i64 = 7;
}

#[cfg(target_arch = "aarch64")]
mod nr {
    pub const READ: i64 = 63;
    pub const WRITE: i64 = 64;
    pub const CLOSE: i64 = 57;
    pub const LSEEK: i64 = 62;
    pub const MMAP: i64 = 222;
    pub const MPROTECT: i64 = 226;
    pub const MUNMAP: i64 = 215;
    pub const BRK: i64 = 214;
    pub const RT_SIGACTION: i64 = 134;
    pub const RT_SIGPROCMASK: i64 = 135;
    pub const MADVISE: i64 = 233;
    pub const NANOSLEEP: i64 = 101;
    pub const SCHED_YIELD: i64 = 124;
    pub const MREMAP: i64 = 216;
    pub const EXIT: i64 = 93;
    pub const GETTIMEOFDAY: i64 = 169;
    pub const SIGALTSTACK: i64 = 132;
    pub const GETTID: i64 = 178;
    pub const FUTEX: i64 = 98;
    pub const SET_ROBUST_LIST: i64 = 99;
    pub const CLOCK_GETTIME: i64 = 113;
    pub const CLOCK_GETRES: i64 = 114;
    pub const CLOCK_NANOSLEEP: i64 = 115;
    pub const EXIT_GROUP: i64 = 94;
    pub const OPENAT: i64 = 56;
    pub const GETRANDOM: i64 = 278;
    pub const MEMBARRIER: i64 = 283;
    pub const RSEQ: i64 = 293;

    // Slice 2 — filesystem.
    pub const FSTAT: i64 = 80;
    pub const IOCTL: i64 = 29;
    pub const PREAD64: i64 = 67;
    pub const PWRITE64: i64 = 68;
    pub const READV: i64 = 65;
    pub const WRITEV: i64 = 66;
    pub const DUP: i64 = 23;
    pub const FCNTL: i64 = 25;
    pub const FLOCK: i64 = 32;
    pub const FSYNC: i64 = 82;
    pub const FDATASYNC: i64 = 83;
    pub const FTRUNCATE: i64 = 46;
    pub const GETDENTS64: i64 = 61;
    pub const MKDIRAT: i64 = 34;
    pub const NEWFSTATAT: i64 = 79;
    pub const UNLINKAT: i64 = 35;
    pub const RENAMEAT: i64 = 38;
    pub const SYMLINKAT: i64 = 36;
    pub const READLINKAT: i64 = 78;
    pub const DUP3: i64 = 24;
    pub const PIPE2: i64 = 59;
    pub const RENAMEAT2: i64 = 276;
    pub const STATX: i64 = 291;

    // Slice 2 — network.
    pub const SOCKET: i64 = 198;
    pub const CONNECT: i64 = 203;
    pub const ACCEPT: i64 = 202;
    pub const SENDTO: i64 = 206;
    pub const RECVFROM: i64 = 207;
    pub const SENDMSG: i64 = 211;
    pub const RECVMSG: i64 = 212;
    pub const SHUTDOWN: i64 = 210;
    pub const BIND: i64 = 200;
    pub const LISTEN: i64 = 201;
    pub const GETSOCKNAME: i64 = 204;
    pub const GETPEERNAME: i64 = 205;
    pub const SETSOCKOPT: i64 = 208;
    pub const GETSOCKOPT: i64 = 209;
    pub const ACCEPT4: i64 = 242;
    pub const SOCKETPAIR: i64 = 199;

    // Slice 2 — readiness (epoll frontend) + eventfd. arm64 has no `epoll_wait`
    // (only `epoll_pwait`); the constant is defined negative so the shared
    // dispatch arm is inert here (the number can never be a real syscall nr).
    pub const EPOLL_WAIT: i64 = -1;
    pub const EPOLL_CTL: i64 = 21;
    pub const EPOLL_PWAIT: i64 = 22;
    pub const EVENTFD2: i64 = 19;
    pub const EPOLL_CREATE1: i64 = 20;
    pub const EPOLL_PWAIT2: i64 = 441;
    pub const PPOLL: i64 = 73;

    // Slice 2 — deterministic process-state constants.
    pub const GETPID: i64 = 172;
    pub const GETUID: i64 = 174;
    pub const GETGID: i64 = 176;
    pub const GETEUID: i64 = 175;
    pub const GETEGID: i64 = 177;
    pub const GETPPID: i64 = 173;
    pub const UNAME: i64 = 160;

    // Slice 2 — the ONLY prctl option routed is PR_GET_AUXV (below); every other
    // option is the process/escape class and fails closed in the dispatch arm.
    pub const PRCTL: i64 = 167;
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
    with_dispatch_guard(nr, || dispatch(nr, args))
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

fn dispatch(nr: i64, args: [u64; 6]) -> i64 {
    match nr {
        nr::CLOCK_GETTIME => sys_clock_gettime(args[0], args[1] as *mut Timespec),
        nr::CLOCK_GETRES => sys_clock_getres(args[0], args[1] as *mut Timespec),
        nr::GETTIMEOFDAY => sys_gettimeofday(args[0] as *mut Timeval),
        nr::NANOSLEEP => sys_nanosleep(args[0] as *const Timespec),
        nr::CLOCK_NANOSLEEP => sys_clock_nanosleep(args[0], args[1], args[2] as *const Timespec),
        nr::FUTEX => sys_futex(args),
        nr::READ => sys_read(arg_fd(args[0]), args[1], args[2]),
        nr::WRITE => sys_write(arg_fd(args[0]), args[1], args[2]),
        nr::OPENAT => sys_openat(arg_fd(args[0]), args[1], args[2]),
        nr::CLOSE => sys_close(arg_fd(args[0])),
        nr::LSEEK => sys_lseek(arg_fd(args[0]), args[1] as i64, args[2]),
        nr::GETRANDOM => sys_getrandom(args[0], args[1], args[2]),
        nr::SCHED_YIELD => {
            // SAFETY: plain runtime entry, no pointers.
            ret_i32(unsafe { patina_sched_yield() })
        }
        nr::GETTID => {
            // SAFETY: as above.
            unsafe { patina_thread_id() as i64 }
        }
        // A raw `exit`/`exit_group` ends the run deterministically. Slice 1 folds
        // a lone-thread raw `exit(2)` onto whole-process exit (no managed guest
        // raw-exits a single thread — std threads return from the trampoline);
        // true per-thread raw exit is slice 2.
        nr::EXIT | nr::EXIT_GROUP => {
            // SAFETY: `patina_exit` terminates the process and never returns.
            unsafe { patina_exit((args[0] & 0xff) as c_int) }
        }
        // Process-local memory management: pass through to the host kernel via the
        // glibc `syscall(2)` vehicle (its kernel entry sits in glibc text, the
        // allowed region). Anonymous only — an fd-backed mapping would bypass the
        // deterministic FS and is refused loudly.
        nr::MMAP => sys_mmap(nr, args),
        nr::MUNMAP | nr::MPROTECT | nr::MADVISE | nr::MREMAP | nr::BRK => mem_passthrough(nr, args),
        // A kernel without these is a real configuration every libc/runtime
        // handles; passing them through would leak host-kernel-version behavior.
        nr::SET_ROBUST_LIST | nr::RSEQ | nr::MEMBARRIER => -ENOSYS,
        // No ambient signals exist in the simulation, so signal-mask/altstack ops
        // are deterministic success no-ops — EXCEPT `rt_sigaction` for SIGSYS,
        // which would replace the dispatch handler: that is fatal (§7.5 raw door).
        nr::RT_SIGPROCMASK | nr::SIGALTSTACK => 0,
        nr::RT_SIGACTION => sys_rt_sigaction(args[0] as i64),

        // ---- Slice 2: filesystem ----
        // (fd/dirfd args go through `arg_fd`; `AT_FDCWD` and any negative fd are
        // 32-bit `int`s the kernel reads from the low register bits.)
        nr::PREAD64 => sys_pread(arg_fd(args[0]), args[1], args[2], args[3] as i64),
        nr::PWRITE64 => sys_pwrite(arg_fd(args[0]), args[1], args[2], args[3] as i64),
        nr::READV => sys_readv(arg_fd(args[0]), args[1], args[2] as i64),
        nr::WRITEV => sys_writev(arg_fd(args[0]), args[1], args[2] as i64),
        nr::FSYNC | nr::FDATASYNC => sys_fsync(arg_fd(args[0])),
        nr::FTRUNCATE => sys_ftruncate(arg_fd(args[0]), args[1] as i64),
        nr::FLOCK => sys_flock(arg_fd(args[0]), args[1] as i64),
        nr::DUP => sys_dup(arg_fd(args[0])),
        nr::DUP3 => sys_dup3(arg_fd(args[0]), arg_fd(args[1]), args[2] as i64),
        nr::FCNTL => sys_fcntl(arg_fd(args[0]), args[1], args[2]),
        nr::IOCTL => sys_ioctl(arg_fd(args[0]), args[1], args[2]),
        nr::PIPE2 => sys_pipe2(args[0], args[1]),
        nr::FSTAT => sys_fstat(arg_fd(args[0]), args[1]),
        nr::NEWFSTATAT => sys_newfstatat(arg_fd(args[0]), args[1], args[2], args[3]),
        nr::STATX => sys_statx(arg_fd(args[0]), args[1], args[2], args[4]),
        nr::GETDENTS64 => sys_getdents64(arg_fd(args[0]), args[1], args[2]),
        nr::MKDIRAT => sys_mkdirat(arg_fd(args[0]), args[1]),
        nr::UNLINKAT => sys_unlinkat(arg_fd(args[0]), args[1], args[2]),
        nr::SYMLINKAT => sys_symlinkat(args[0], arg_fd(args[1]), args[2]),
        nr::READLINKAT => sys_readlinkat(arg_fd(args[0]), args[1], args[2], args[3]),
        nr::RENAMEAT => sys_renameat(arg_fd(args[0]), args[1], arg_fd(args[2]), args[3], 0),
        nr::RENAMEAT2 => sys_renameat(arg_fd(args[0]), args[1], arg_fd(args[2]), args[3], args[4]),

        // ---- Slice 2: network ----
        nr::SOCKET => sys_socket(args[0], args[1], args[2]),
        nr::BIND => sys_bind(arg_fd(args[0]), args[1], args[2] as u32),
        nr::LISTEN => sys_listen(arg_fd(args[0]), args[1] as i64),
        nr::CONNECT => sys_connect(arg_fd(args[0]), args[1], args[2] as u32),
        nr::ACCEPT => sys_accept(arg_fd(args[0]), args[1], args[2], 0),
        nr::ACCEPT4 => sys_accept(arg_fd(args[0]), args[1], args[2], args[3]),
        nr::SENDTO => sys_sendto(
            arg_fd(args[0]),
            args[1],
            args[2],
            args[3],
            args[4],
            args[5] as u32,
        ),
        nr::RECVFROM => sys_recvfrom(arg_fd(args[0]), args[1], args[2], args[3], args[4], args[5]),
        nr::SENDMSG => sys_sendmsg(arg_fd(args[0]), args[1], args[2]),
        nr::RECVMSG => sys_recvmsg(arg_fd(args[0]), args[1], args[2]),
        nr::SHUTDOWN => sys_shutdown(arg_fd(args[0]), args[1]),
        nr::GETSOCKNAME => sys_getsockname(arg_fd(args[0]), args[1], args[2]),
        nr::GETPEERNAME => sys_getpeername(arg_fd(args[0]), args[1], args[2]),
        nr::SETSOCKOPT => {
            sys_setsockopt(arg_fd(args[0]), args[1], args[2], args[3], args[4] as u32)
        }
        nr::GETSOCKOPT => sys_getsockopt(arg_fd(args[0]), args[3], args[4]),
        nr::SOCKETPAIR => sys_socketpair(args[0], args[1], args[2], args[3]),

        // ---- Slice 2: readiness reactor + eventfd ----
        nr::EPOLL_CREATE1 => sys_epoll_create1(args[0]),
        nr::EPOLL_CTL => sys_epoll_ctl(arg_fd(args[0]), args[1] as i64, arg_fd(args[2]), args[3]),
        nr::EPOLL_WAIT => sys_epoll_wait(arg_fd(args[0]), args[1], args[2] as i64, args[3] as i64),
        nr::EPOLL_PWAIT => sys_epoll_pwait(
            arg_fd(args[0]),
            args[1],
            args[2] as i64,
            args[3] as i64,
            args[4],
        ),
        nr::EPOLL_PWAIT2 => {
            sys_epoll_pwait2(arg_fd(args[0]), args[1], args[2] as i64, args[3], args[4])
        }
        nr::EVENTFD2 => sys_eventfd2(args[0], args[1] as i64),
        nr::PPOLL => sys_ppoll(args[0], args[1], args[2], args[3], args[4]),

        // ---- Slice 2: deterministic process-state constants ----
        // The same values the C interposers return (getpid=1, getppid=0, all
        // uids/gids=1000, uname=ENOSYS, gettid=managed thread id).
        nr::GETPID => 1,
        nr::GETPPID => 0,
        nr::GETUID | nr::GETEUID | nr::GETGID | nr::GETEGID => 1000,
        // The C `uname` interposer returns ENOSYS (the runtime models no host
        // uname); the raw row matches it byte-for-byte.
        nr::UNAME => -ENOSYS,

        // `prctl` is the process/escape class — but rustix's linux_raw init reads
        // the aux vector with a raw `prctl(PR_GET_AUXV, …)`. Route ONLY that
        // option (serving the shim's scrubbed auxv, never the kernel's pristine
        // one); every other option fails closed with a named prctl abort.
        nr::PRCTL => sys_prctl(args[0], args[1], args[2], args[3], args[4]),

        // ---- Slice 2: x86_64 legacy aliases (route to the SAME modern handler) ----
        // rustix's linux_raw backend and hand-written asm reach for the legacy
        // non-`*at` forms on x86_64; each is exactly its modern form with dirfd =
        // AT_FDCWD (and, for `creat`, synthesized flags). aarch64 lacks these
        // numbers entirely, so the arms are `#[cfg(target_arch = "x86_64")]`.
        #[cfg(target_arch = "x86_64")]
        nr::OPEN => sys_openat(AT_FDCWD, args[0], args[1]),
        #[cfg(target_arch = "x86_64")]
        nr::CREAT => sys_openat(AT_FDCWD, args[0], O_CREAT | O_WRONLY | O_TRUNC),
        #[cfg(target_arch = "x86_64")]
        nr::STAT => sys_newfstatat(AT_FDCWD, args[0], args[1], 0),
        #[cfg(target_arch = "x86_64")]
        nr::LSTAT => sys_newfstatat(AT_FDCWD, args[0], args[1], AT_SYMLINK_NOFOLLOW),
        #[cfg(target_arch = "x86_64")]
        nr::UNLINK => sys_unlinkat(AT_FDCWD, args[0], 0),
        #[cfg(target_arch = "x86_64")]
        nr::RMDIR => sys_unlinkat(AT_FDCWD, args[0], AT_REMOVEDIR),
        #[cfg(target_arch = "x86_64")]
        nr::MKDIR => sys_mkdirat(AT_FDCWD, args[0]),
        #[cfg(target_arch = "x86_64")]
        nr::RENAME => sys_renameat(AT_FDCWD, args[0], AT_FDCWD, args[1], 0),
        #[cfg(target_arch = "x86_64")]
        nr::SYMLINK => sys_symlinkat(args[0], AT_FDCWD, args[1]),
        #[cfg(target_arch = "x86_64")]
        nr::READLINK => sys_readlinkat(AT_FDCWD, args[0], args[1], args[2]),
        #[cfg(target_arch = "x86_64")]
        nr::DUP2 => sys_dup2(arg_fd(args[0]), arg_fd(args[1])),
        #[cfg(target_arch = "x86_64")]
        nr::PIPE => sys_pipe2(args[0], 0),
        #[cfg(target_arch = "x86_64")]
        nr::EVENTFD => sys_eventfd2(args[0], 0),
        #[cfg(target_arch = "x86_64")]
        nr::EPOLL_CREATE => sys_epoll_create(args[0]),
        #[cfg(target_arch = "x86_64")]
        nr::POLL => sys_poll(args[0], args[1], args[2] as i32 as i64),

        // Everything else — the process/escape class (clone/execve/ptrace/prctl/
        // seccomp/io_uring/…) and any un-tabled number — is fatal by default.
        _ => unmapped(nr, args),
    }
}

fn clock_from_raw(raw: u64) -> Option<u32> {
    // Mirror the C `clock_gettime` interposer: only REALTIME/MONOTONIC route.
    match raw {
        0 => Some(PATINA_CLOCK_REALTIME),
        1 => Some(PATINA_CLOCK_MONOTONIC),
        _ => None,
    }
}

fn sys_clock_gettime(clock_raw: u64, out: *mut Timespec) -> i64 {
    let Some(clock) = clock_from_raw(clock_raw) else {
        return -EINVAL;
    };
    if out.is_null() {
        return -EINVAL;
    }
    let mut nanos: u64 = 0;
    // SAFETY: `nanos` is local, writable storage.
    let rc = unsafe { patina_clock_now(clock, &mut nanos) };
    if rc != 0 {
        return ret_i32(rc);
    }
    // SAFETY: `out` is a guest pointer to `struct timespec` storage.
    unsafe {
        out.write(Timespec {
            tv_sec: (nanos / NANOS_PER_SEC) as i64,
            tv_nsec: (nanos % NANOS_PER_SEC) as i64,
        });
    }
    0
}

fn sys_clock_getres(clock_raw: u64, out: *mut Timespec) -> i64 {
    // Resolution of the virtual clock is 1ns; report it deterministically.
    if clock_from_raw(clock_raw).is_none() {
        return -EINVAL;
    }
    if !out.is_null() {
        // SAFETY: `out` is a guest `struct timespec` pointer.
        unsafe {
            out.write(Timespec {
                tv_sec: 0,
                tv_nsec: 1,
            });
        }
    }
    0
}

fn sys_gettimeofday(out: *mut Timeval) -> i64 {
    if out.is_null() {
        return 0;
    }
    let mut nanos: u64 = 0;
    // SAFETY: local storage.
    let rc = unsafe { patina_clock_now(PATINA_CLOCK_REALTIME, &mut nanos) };
    if rc != 0 {
        return ret_i32(rc);
    }
    // SAFETY: `out` is a guest `struct timeval` pointer.
    unsafe {
        out.write(Timeval {
            tv_sec: (nanos / NANOS_PER_SEC) as i64,
            tv_usec: ((nanos % NANOS_PER_SEC) / 1000) as i64,
        });
    }
    0
}

/// Read a `struct timespec` from guest memory and validate it, returning its
/// value in nanoseconds or an `-errno`.
fn read_timespec_nanos(ptr: *const Timespec) -> Result<u64, i64> {
    if ptr.is_null() {
        return Err(-EINVAL);
    }
    // SAFETY: `ptr` is a guest `struct timespec` pointer.
    let ts = unsafe { ptr.read() };
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= NANOS_PER_SEC as i64 {
        return Err(-EINVAL);
    }
    let seconds = ts.tv_sec as u64;
    if seconds > u64::MAX / NANOS_PER_SEC {
        return Err(-EINVAL);
    }
    Ok(seconds * NANOS_PER_SEC + ts.tv_nsec as u64)
}

fn sys_nanosleep(req: *const Timespec) -> i64 {
    // Relative CLOCK_MONOTONIC sleep. Convert to an absolute virtual deadline.
    let rel = match read_timespec_nanos(req) {
        Ok(nanos) => nanos,
        Err(errno) => return errno,
    };
    let mut now: u64 = 0;
    // SAFETY: local storage.
    let rc = unsafe { patina_clock_now(PATINA_CLOCK_MONOTONIC, &mut now) };
    if rc != 0 {
        return ret_i32(rc);
    }
    let deadline = now.saturating_add(rel);
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_sleep_until(PATINA_CLOCK_MONOTONIC, deadline) })
}

fn sys_clock_nanosleep(clock_raw: u64, flags: u64, req: *const Timespec) -> i64 {
    let Some(clock) = clock_from_raw(clock_raw) else {
        return -EINVAL;
    };
    let requested = match read_timespec_nanos(req) {
        Ok(nanos) => nanos,
        Err(errno) => return errno,
    };
    let deadline = if flags & TIMER_ABSTIME != 0 {
        requested
    } else {
        let mut now: u64 = 0;
        // SAFETY: local storage.
        let rc = unsafe { patina_clock_now(clock, &mut now) };
        if rc != 0 {
            return ret_i32(rc);
        }
        now.saturating_add(requested)
    };
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_sleep_until(clock, deadline) })
}

fn sys_futex(args: [u64; 6]) -> i64 {
    let uaddr = args[0] as usize;
    let futex_op = args[1];
    let val = args[2] as u32;
    let timeout = args[3] as *const Timespec;
    let op = futex_op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    if op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET {
        if timeout.is_null() {
            // SAFETY: no dereference of `uaddr` here; the runtime treats it as a key.
            return ret_i32(unsafe { patina_futex_wait(uaddr, val) });
        }
        // FUTEX_WAIT: relative CLOCK_MONOTONIC. FUTEX_WAIT_BITSET: absolute,
        // CLOCK_REALTIME iff FUTEX_CLOCK_REALTIME — mirrors the C `syscall()` path.
        let absolute = op == FUTEX_WAIT_BITSET;
        let clock = if absolute && futex_op & FUTEX_CLOCK_REALTIME != 0 {
            PATINA_CLOCK_REALTIME
        } else {
            PATINA_CLOCK_MONOTONIC
        };
        let timeout_nanos = match read_timespec_nanos(timeout) {
            Ok(nanos) => nanos,
            Err(errno) => return errno,
        };
        // SAFETY: `uaddr` is treated as a key by the runtime.
        return ret_i32(unsafe {
            patina_futex_wait_timed(uaddr, val, clock, absolute as c_int, timeout_nanos)
        });
    }
    if op == FUTEX_WAKE || op == FUTEX_WAKE_BITSET {
        // SAFETY: `uaddr` is a key; `val` is the wake count.
        return ret_i32(unsafe { patina_futex_wake(uaddr, val as c_int) });
    }
    -ENOSYS
}

/// Route a raw `read(2)` by fd class, exactly as the C `read` interposer does: a
/// virtual socket/pipe/eventfd descriptor (fd >= [`PATINA_SOCKET_FD_BASE`]) goes
/// to the network/pipe/eventfd entries, everything else to the deterministic
/// filesystem. Keeping this decode identical to the C path is what makes a raw
/// `read` on a rustix-default socket record the same op-stream as an interposed
/// one.
fn sys_read(fd: i64, buf: u64, count: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    let cfd = fd as c_int;
    let dst = buf as *mut c_void;
    let len = count as usize;
    if fd >= PATINA_SOCKET_FD_BASE {
        // SAFETY: `buf`/`count` describe a guest buffer per the read(2) contract.
        return unsafe {
            let kind = patina_net_kind(cfd);
            if kind == 3 {
                ret_isize(patina_net_stream_recv(cfd, dst, len))
            } else if kind == 0 {
                ret_isize(patina_net_recv(cfd, dst, len))
            } else if patina_pipe_is_endpoint(cfd) != 0 {
                ret_isize(patina_pipe_read(cfd, dst, len))
            } else if patina_eventfd_is(cfd) != 0 {
                ret_isize(patina_eventfd_read(cfd, dst, len))
            } else if kind < 0 {
                -EBADF
            } else {
                -ENOTCONN
            }
        };
    }
    // SAFETY: `buf`/`count` describe a guest buffer per the read(2) contract.
    ret_isize(unsafe { patina_read(cfd, dst, len) })
}

/// Route a raw `write(2)` by fd class, mirroring the C `write` interposer:
/// captured stdout/stderr (fd 1/2), then virtual socket/pipe/eventfd classes,
/// then the deterministic filesystem.
fn sys_write(fd: i64, buf: u64, count: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    let cfd = fd as c_int;
    let src = buf as *const c_void;
    let len = count as usize;
    if fd == 1 || fd == 2 {
        // SAFETY: `buf`/`count` describe a guest buffer per the write(2) contract.
        return ret_isize(unsafe { patina_stdio_write(cfd, src, len) });
    }
    if fd >= PATINA_SOCKET_FD_BASE {
        // SAFETY: as above.
        return unsafe {
            let kind = patina_net_kind(cfd);
            if kind == 3 {
                ret_isize(patina_net_stream_send(cfd, src, len))
            } else if kind == 0 {
                ret_isize(patina_net_send(cfd, src, len))
            } else if patina_pipe_is_endpoint(cfd) != 0 {
                ret_isize(patina_pipe_write(cfd, src, len))
            } else if patina_eventfd_is(cfd) != 0 {
                ret_isize(patina_eventfd_write(cfd, src, len))
            } else if kind < 0 {
                -EBADF
            } else {
                -ENOTCONN
            }
        };
    }
    // SAFETY: as above.
    ret_isize(unsafe { patina_write(cfd, src, len) })
}

/// Route a raw `close(2)` by fd class, mirroring the C `close` interposer.
fn sys_close(fd: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    let cfd = fd as c_int;
    // A SUD directory fd: free its snapshot and drop the registration.
    if fd >= PATINA_SUD_DIR_FD_BASE as i64 {
        if let Some(dir) = DIR_FDS.lock().unwrap().remove(&cfd) {
            // SAFETY: `snapshot` is the live `patina_read_dir` box for this fd.
            unsafe { patina_read_dir_free(dir.snapshot as *mut c_void) };
            return 0;
        }
    }
    if fd >= PATINA_SOCKET_FD_BASE {
        // SAFETY: no dereferenced pointers.
        return unsafe {
            if patina_epoll_is_epoll(cfd) != 0 {
                ret_i32(patina_epoll_close(cfd))
            } else if patina_eventfd_is(cfd) != 0 {
                ret_i32(patina_eventfd_close(cfd))
            } else if patina_pipe_is_endpoint(cfd) != 0 {
                ret_i32(patina_pipe_close(cfd))
            } else {
                ret_i32(patina_net_close(cfd))
            }
        };
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_close(cfd) })
}

// `lseek(2)` whence values.
const SEEK_SET: u64 = 0;

fn sys_lseek(fd: i64, offset: i64, whence: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // A SUD directory fd: `lseek(fd, 0, SEEK_SET)` is rustix `Dir::rewind` — drop
    // the current snapshot and re-snapshot from the start. Any other seek on a
    // directory fd is meaningless (ESPIPE, matching a directory stream).
    if fd >= PATINA_SUD_DIR_FD_BASE as i64 && is_sud_dir_fd(fd) {
        if whence == SEEK_SET && offset == 0 {
            return rewind_dir_fd(fd as c_int);
        }
        return -ESPIPE;
    }
    // patina_seek returns the new offset or -1; shape it to the raw convention.
    // SAFETY: no pointers.
    let result = unsafe { patina_seek(fd as c_int, offset, whence as u32) };
    if result < 0 {
        // SAFETY: plain thread-local read.
        -(unsafe { patina_errno() } as i64)
    } else {
        result
    }
}

/// Guard the fd against the negative/oversized values that cannot be Patina
/// virtual descriptors, so the cast into `c_int` never wraps.
fn fd_out_of_range(fd: i64) -> Option<i64> {
    if fd < 0 || fd > c_int::MAX as i64 {
        Some(-EINVAL)
    } else {
        None
    }
}

/// Translate kernel `open(2)` flag bits into Patina open flags. Pure so both the
/// `openat` row and the legacy `open`/`creat` aliases (whose only difference is
/// the dirfd injection and, for `creat`, the synthesized `O_CREAT|O_WRONLY|
/// O_TRUNC`) share one decode and one source of truth.
fn openat_patina_flags(flags: u64) -> u32 {
    let mut patina_flags = match flags & O_ACCMODE {
        O_WRONLY => PATINA_O_WRITE,
        O_RDWR => PATINA_O_READ | PATINA_O_WRITE,
        // O_RDONLY == 0
        _ => PATINA_O_READ,
    };
    if flags & O_CREAT != 0 {
        patina_flags |= PATINA_O_CREATE;
    }
    if flags & O_TRUNC != 0 {
        patina_flags |= PATINA_O_TRUNCATE;
    }
    if flags & O_APPEND != 0 {
        patina_flags |= PATINA_O_APPEND;
    }
    if flags & O_EXCL != 0 {
        patina_flags |= PATINA_O_EXCLUSIVE;
    }
    patina_flags
}

fn sys_openat(dirfd: i64, path: u64, flags: u64) -> i64 {
    // A dirfd-relative open where `dirfd` is a SUD directory fd. rustix's
    // `Dir::read_from` derives its iteration handle with `openat(dir_fd, ".", …)`,
    // so this path IS reached for every raw directory listing (not slice 2 general
    // resolution). Re-snapshot the same directory into a fresh SUD dir fd; only
    // "." (the directory itself) is modeled.
    if is_sud_dir_fd(dirfd) {
        return openat_sud_dir(dirfd, path);
    }
    // Otherwise: AT_FDCWD only. A real (non-SUD) dirfd is slice 2.
    if dirfd != AT_FDCWD {
        return -EINVAL;
    }
    if path == 0 {
        return -EINVAL;
    }
    let patina_flags = openat_patina_flags(flags);
    let read_only = patina_flags & (PATINA_O_WRITE | PATINA_O_CREATE | PATINA_O_TRUNCATE) == 0;
    // SAFETY: `path` is a guest NUL-terminated string pointer.
    let fd = unsafe { patina_open(path as *const c_char, patina_flags) };
    if fd >= 0 {
        return fd as i64;
    }
    // SAFETY: plain thread-local read.
    let errno = unsafe { patina_errno() } as i64;
    // A read-only open of a directory: the deterministic FS refuses to open a
    // directory as an ordinary fd (EISDIR), but a raw caller (rustix `Dir`)
    // legitimately wants a directory fd to `getdents64`. Model it in the SUD
    // layer, snapshotting through the same `patina_read_dir` the interposed
    // `opendir` uses.
    if errno == EISDIR && read_only {
        return open_dir_fd(path as *const c_char);
    }
    -errno
}

/// Snapshot the directory at `path` via `patina_read_dir` and register a
/// SUD-private directory fd over it. Returns the fd or `-errno`.
fn open_dir_fd(path: *const c_char) -> i64 {
    // Copy the path into an owned CString for re-snapshot on rewind.
    // SAFETY: `path` is the guest's NUL-terminated string pointer.
    let owned = match copy_c_path(path) {
        Some(owned) => owned,
        None => return -EINVAL,
    };
    let mut snapshot: *mut c_void = std::ptr::null_mut();
    // SAFETY: `path` is a valid guest C string; `snapshot` is writable local.
    let rc = unsafe { patina_read_dir(path, &mut snapshot) };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    let fd = NEXT_DIR_FD.fetch_add(1, Ordering::Relaxed);
    DIR_FDS.lock().unwrap().insert(
        fd,
        DirFd {
            path: owned,
            snapshot: snapshot as usize,
            pending: None,
        },
    );
    fd as i64
}

/// `openat(dir_fd, path, …)` where `dir_fd` is a SUD directory fd. rustix's
/// `Dir::_read_from` opens `"."` relative to a directory fd to obtain a fresh
/// iteration handle (`backend/linux_raw/fs/dir.rs`), so a raw `getdents64`
/// listing always lands here. Model it by re-snapshotting the SAME directory
/// (by its stored path) into a new SUD dir fd. Only `"."` — the directory
/// itself — is modeled; a sub-name would be general dirfd-relative resolution,
/// which the deterministic FS does not do, so it fails closed with `-EINVAL`.
fn openat_sud_dir(dir_fd: i64, path: u64) -> i64 {
    if path == 0 {
        return -EINVAL;
    }
    // SAFETY: `path` is the guest's NUL-terminated string pointer.
    let bytes = unsafe { std::ffi::CStr::from_ptr(path as *const c_char) }.to_bytes();
    if bytes != b"." {
        return -EINVAL;
    }
    reopen_sud_dir(dir_fd)
}

/// Re-snapshot the directory behind an existing SUD dir fd into a NEW SUD dir fd
/// (shared by `openat(dir_fd, ".")` and `fcntl(dir_fd, F_DUPFD)`). Clones the
/// stored path out from under the lock, then reopens it (open_dir_fd re-locks to
/// register the fresh fd).
fn reopen_sud_dir(dir_fd: i64) -> i64 {
    let stored = {
        let map = DIR_FDS.lock().unwrap();
        match map.get(&(dir_fd as c_int)) {
            Some(dir) => dir.path.clone(),
            None => return -EBADF,
        }
    };
    open_dir_fd(stored.as_ptr())
}

/// Copy a guest NUL-terminated C string into an owned [`CString`], or `None` on
/// a null pointer / embedded issue.
fn copy_c_path(path: *const c_char) -> Option<CString> {
    if path.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a valid NUL-terminated guest string.
    let bytes = unsafe { std::ffi::CStr::from_ptr(path) }.to_bytes();
    CString::new(bytes).ok()
}

fn sys_getrandom(buf: u64, len: u64, _flags: u64) -> i64 {
    // Deterministic entropy never blocks and has one source, so GRND_* flags are
    // irrelevant (mirrors the C getrandom/SYS_getrandom routes).
    // SAFETY: `buf`/`len` describe a guest buffer.
    let rc = unsafe { patina_entropy(buf as *mut c_void, len as usize) };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        -(unsafe { patina_errno() } as i64)
    } else {
        len as i64
    }
}

fn sys_rt_sigaction(signum: i64) -> i64 {
    // SIGSYS registration by the guest would replace the dispatch handler:
    // containment over. Fatal (the raw door of the §7.5 SIGSYS hardening; the
    // symbol door is the interposed sigaction/signal in patina_posix.c).
    const SIGSYS: i64 = 31;
    if signum == SIGSYS {
        crate::sud_fatal(
            "SUD trapped rt_sigaction(SIGSYS): a guest may not re-register the syscall-dispatch \
             handler — doing so would disable deterministic containment",
        );
    }
    // No ambient signals exist, so registering any other handler is a
    // deterministic success no-op that records nothing (mirrors the allowlist
    // stance for bare sigaction/signal).
    0
}

fn sys_mmap(nr: i64, args: [u64; 6]) -> i64 {
    let flags = args[3];
    let fd = args[4] as i64;
    if flags & MAP_ANONYMOUS == 0 || fd != -1 {
        crate::sud_fatal(
            "SUD trapped a file-backed mmap: mapping a descriptor into memory bypasses the \
             deterministic filesystem. Only MAP_ANONYMOUS mappings (fd == -1) are process-local \
             and passed through",
        );
    }
    mem_passthrough(nr, args)
}

/// Pass a process-local memory syscall through to the host kernel via the glibc
/// `syscall(2)` vehicle. The wrapper returns `-1` and sets `errno` on failure;
/// reshape that into the raw `-errno` the syscall return register carries.
fn mem_passthrough(nr: i64, args: [u64; 6]) -> i64 {
    // SAFETY: process-local memory management; the arguments are the guest's own
    // and the vehicle is glibc's `syscall` wrapper resolved as a host alias.
    let result = unsafe {
        crate::sud_host_syscall(
            nr as c_long,
            args[0] as c_long,
            args[1] as c_long,
            args[2] as c_long,
            args[3] as c_long,
            args[4] as c_long,
            args[5] as c_long,
        )
    };
    if result == -1 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .map(|e| e as i64)
            .unwrap_or(EIO);
        -errno
    } else {
        result as i64
    }
}

/// Re-snapshot a SUD directory fd from its start (rustix `Dir::rewind`).
fn rewind_dir_fd(fd: c_int) -> i64 {
    let mut map = DIR_FDS.lock().unwrap();
    let Some(dir) = map.get_mut(&fd) else {
        return -EBADF;
    };
    let mut fresh: *mut c_void = std::ptr::null_mut();
    // SAFETY: `dir.path` is an owned, valid C string; `fresh` is writable local.
    let rc = unsafe { patina_read_dir(dir.path.as_ptr(), &mut fresh) };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    // SAFETY: the old snapshot is the live box for this fd; replace it.
    unsafe { patina_read_dir_free(dir.snapshot as *mut c_void) };
    dir.snapshot = fresh as usize;
    dir.pending = None;
    0
}

// ---- Positional & vectored I/O ----

fn sys_pread(fd: i64, buf: u64, count: u64, offset: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // Virtual sockets have no offset addressing (ESPIPE), mirroring the C pread.
    if fd >= PATINA_SOCKET_FD_BASE {
        return -ESPIPE;
    }
    // SAFETY: `buf`/`count` describe a guest buffer per the pread(2) contract.
    ret_isize(unsafe { patina_pread(fd as c_int, buf as *mut c_void, count as usize, offset) })
}

fn sys_pwrite(fd: i64, buf: u64, count: u64, offset: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    if fd == 1 || fd == 2 || fd >= PATINA_SOCKET_FD_BASE {
        return -ESPIPE;
    }
    // SAFETY: `buf`/`count` describe a guest buffer per the pwrite(2) contract.
    ret_isize(unsafe { patina_pwrite(fd as c_int, buf as *const c_void, count as usize, offset) })
}

/// Kernel `struct iovec` on 64-bit Linux.
#[repr(C)]
#[derive(Clone, Copy)]
struct Iovec {
    iov_base: u64,
    iov_len: usize,
}

/// Iterate the guest iovec array, applying `op` to each (base, len). Mirrors the
/// C `writev`/`readv`: stop at the first short/failed transfer, returning the
/// running total (or `-errno` if the very first transfer failed).
fn iovec_loop(iov: u64, count: i64, mut op: impl FnMut(u64, u64) -> i64) -> i64 {
    if count < 0 || (count > 0 && iov == 0) {
        return -EINVAL;
    }
    let mut total: i64 = 0;
    for index in 0..count as usize {
        // SAFETY: `iov` is the guest's iovec array of `count` entries.
        let vector = unsafe { (iov as *const Iovec).add(index).read() };
        let moved = op(vector.iov_base, vector.iov_len as u64);
        if moved < 0 {
            return if total > 0 { total } else { moved };
        }
        total += moved;
        if (moved as u64) < vector.iov_len as u64 {
            break;
        }
    }
    total
}

fn sys_readv(fd: i64, iov: u64, count: i64) -> i64 {
    iovec_loop(iov, count, |base, len| sys_read(fd, base, len))
}

fn sys_writev(fd: i64, iov: u64, count: i64) -> i64 {
    iovec_loop(iov, count, |base, len| sys_write(fd, base, len))
}

fn sys_fsync(fd: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_fsync(fd as c_int) })
}

fn sys_ftruncate(fd: i64, length: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    if length < 0 {
        return -EINVAL;
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_set_len(fd as c_int, length as u64) })
}

fn sys_flock(fd: i64, operation: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // Advisory locks on virtual sockets are not modeled (C denies them, with a
    // recorded diagnostic).
    if fd >= PATINA_SOCKET_FD_BASE {
        return sud_deny(
            "patina: advisory locks on virtual sockets are not modeled; failing closed\n",
        );
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_flock(fd as c_int, operation as c_int) })
}

fn sys_dup(fd: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // Mirror the C `dup` interposer class-by-class, including the byte-identical
    // deny diagnostics: captured stdio and virtual eventfd/socket dups fail closed
    // with their own messages; epoll and pipe endpoints alias into a shared handle.
    if (0..=2).contains(&fd) {
        return sud_deny(
            "patina: duplicating a captured stdio descriptor is not modeled; failing closed\n",
        );
    }
    // A SUD directory fd is SUD-only (no C counterpart): re-snapshot it, matching
    // the fcntl(F_DUPFD) handling for the same fd.
    if is_sud_dir_fd(fd) {
        return reopen_sud_dir(fd);
    }
    let cfd = fd as c_int;
    if fd >= PATINA_SOCKET_FD_BASE {
        // SAFETY: no dereferenced pointers.
        return unsafe {
            if patina_epoll_is_epoll(cfd) != 0 {
                ret_i32(patina_epoll_dup(cfd))
            } else if patina_eventfd_is(cfd) != 0 {
                sud_deny(
                    "patina: duplicating a virtual eventfd descriptor is not modeled; failing closed\n",
                )
            } else if patina_pipe_is_endpoint(cfd) != 0 {
                ret_i32(patina_pipe_dup(cfd))
            } else {
                sud_deny(
                    "patina: duplicating a virtual socket descriptor is not modeled; failing closed\n",
                )
            }
        };
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_dup(cfd) })
}

fn sys_dup3(oldfd: i64, newfd: i64, _flags: i64) -> i64 {
    // dup3 to a chosen descriptor number is not modeled; equal fds are EINVAL
    // (POSIX dup3), everything else fails closed — mirrors the C dup3 interposer,
    // including the byte-identical deny diagnostic.
    if oldfd == newfd {
        return -EINVAL;
    }
    sud_deny("patina: dup3 to a chosen descriptor number is not modeled; failing closed\n")
}

/// Legacy `dup2(2)` (x86_64-only syscall). It differs from `dup3` in EXACTLY the
/// equal-fd case: `dup2(fd, fd)` validates `fd` and returns it unchanged (no
/// close, no CLOEXEC), whereas `dup3(fd, fd, …)` is `-EINVAL`. A distinct-target
/// `dup2` is `dup3(old, new, 0)` — dup-to-a-chosen-number, which this model does
/// not support, so it fails closed identically. Mirrors the C `dup2` interposer's
/// validity checks so the raw and wrapped paths route identically.
#[cfg(target_arch = "x86_64")]
fn sys_dup2(oldfd: i64, newfd: i64) -> i64 {
    if oldfd != newfd {
        // Not the no-op case: a chosen-number dup is unmodeled. Emit the dup2
        // (NOT dup3) deny line so a raw dup2 records the same bytes a libc dup2
        // does — the two messages differ only by the "2"/"3", so delegating to
        // sys_dup3 here would print the wrong one.
        return sud_deny(
            "patina: dup2 to a chosen descriptor number is not modeled; failing closed\n",
        );
    }
    // Equal fds: return `fd` iff it is a currently-valid descriptor, else EBADF.
    if fd_out_of_range(oldfd).is_some() {
        return -EBADF;
    }
    if (0..=2).contains(&oldfd) {
        return newfd; // captured stdio is always valid
    }
    if is_sud_dir_fd(oldfd) {
        return newfd; // a live SUD directory fd (SUD-only; no C counterpart)
    }
    let cfd = oldfd as c_int;
    if oldfd >= PATINA_SOCKET_FD_BASE {
        // Mirror the C dup2 validity EXACTLY (patina_posix.c:1110): a virtual fd is
        // valid iff it is a net socket (net_is_nonblocking >= 0) OR a pipe/socketpair
        // endpoint. epoll and eventfd fds are NOT accepted — C reports EBADF for
        // them, so this must too.
        // SAFETY: no dereferenced pointers.
        let valid =
            unsafe { patina_net_is_nonblocking(cfd) >= 0 || patina_pipe_is_endpoint(cfd) != 0 };
        return if valid { newfd } else { -EBADF };
    }
    // A regular fd: validate through the SAME metadata entry the C dup2 uses.
    let (mut kind, mut length, mut ino, mut atime, mut mtime) = (0u32, 0u64, 0u64, 0u64, 0u64);
    let mut nlink = 0u32;
    // SAFETY: every out-param is local writable storage.
    let rc = unsafe {
        patina_fd_metadata_full(
            cfd,
            &mut kind,
            &mut length,
            &mut ino,
            &mut nlink,
            &mut atime,
            &mut mtime,
        )
    };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    newfd
}

fn sys_fcntl(fd: i64, command: u64, arg: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    let cfd = fd as c_int;
    // A SUD directory fd (>= PATINA_SUD_DIR_FD_BASE, which is itself above
    // PATINA_SOCKET_FD_BASE) must be recognized BEFORE the virtual-socket branch,
    // or `patina_net_is_nonblocking` on it returns EBADF — which is exactly what
    // broke rustix `Dir::read_from`'s `fcntl(dir_fd, F_GETFL)`. The directory was
    // opened read-only; F_GETFL reports O_RDONLY (O_DIRECTORY/O_CLOEXEC are not
    // file-status flags), the CLOEXEC/flag setters are no-ops, and F_DUPFD yields
    // a fresh handle to the same directory.
    if is_sud_dir_fd(fd) {
        return match command {
            F_GETFL => 0, // O_RDONLY
            F_GETFD => FD_CLOEXEC,
            F_SETFD | F_SETFL => 0,
            F_DUPFD | F_DUPFD_CLOEXEC => reopen_sud_dir(fd),
            _ => -EINVAL,
        };
    }
    if fd >= PATINA_SOCKET_FD_BASE {
        // Virtual epoll descriptors.
        // SAFETY: no dereferenced pointers below unless noted.
        unsafe {
            if patina_epoll_is_epoll(cfd) != 0 {
                return match command {
                    F_DUPFD | F_DUPFD_CLOEXEC => ret_i32(patina_epoll_dup(cfd)),
                    F_GETFD => FD_CLOEXEC,
                    F_SETFD | F_SETFL | F_GETFL => 0,
                    _ => -EINVAL,
                };
            }
            if patina_pipe_is_endpoint(cfd) != 0 {
                return match command {
                    F_GETFL => {
                        let nb = patina_pipe_is_nonblocking(cfd);
                        if nb < 0 {
                            -EBADF
                        } else if nb != 0 {
                            O_NONBLOCK as i64
                        } else {
                            0
                        }
                    }
                    F_SETFL => ret_i32(patina_pipe_set_nonblocking(
                        cfd,
                        ((arg & O_NONBLOCK) != 0) as c_int,
                    )),
                    F_GETFD => FD_CLOEXEC,
                    F_SETFD => 0,
                    F_DUPFD | F_DUPFD_CLOEXEC => ret_i32(patina_pipe_dup(cfd)),
                    _ => -EINVAL,
                };
            }
            // Virtual sockets: report/adjust the blocking flag; cloexec is a no-op.
            return match command {
                F_GETFL => {
                    let nb = patina_net_is_nonblocking(cfd);
                    if nb < 0 {
                        -EBADF
                    } else if nb != 0 {
                        O_NONBLOCK as i64
                    } else {
                        0
                    }
                }
                F_SETFL => ret_i32(patina_net_set_nonblocking(
                    cfd,
                    ((arg & O_NONBLOCK) != 0) as c_int,
                )),
                F_GETFD => FD_CLOEXEC,
                F_SETFD => 0,
                // Duplicating a virtual socket descriptor is not modeled.
                F_DUPFD | F_DUPFD_CLOEXEC => sud_deny(
                    "patina: duplicating a virtual socket descriptor is not modeled; failing closed\n",
                ),
                _ => -EINVAL,
            };
        }
    }
    // Regular fds (and captured stdio): mirror the C fcntl regular-fd tail EXACTLY
    // (patina_posix.c). Only F_GETFD/F_SETFD/F_DUPFD are modeled; F_GETFL, F_SETFL,
    // and every unknown command fall through to a SOFT -ENOSYS (NOT 0, NOT fatal),
    // just as C's final `errno = ENOSYS; return -1` does.
    match command {
        F_GETFD => FD_CLOEXEC,
        F_SETFD => 0,
        F_DUPFD | F_DUPFD_CLOEXEC => {
            if (0..=2).contains(&fd) {
                return sud_deny(
                    "patina: duplicating a captured stdio descriptor is not modeled; failing closed\n",
                );
            }
            // SAFETY: no pointers.
            let dup = unsafe { patina_dup(cfd) };
            if dup < 0 {
                // SAFETY: plain thread-local read.
                return -(unsafe { patina_errno() } as i64);
            }
            // The deterministic counter is monotonic; a requested minimum above
            // it cannot be honored without modeling sparse placement.
            if (dup as u64) < arg {
                // SAFETY: no pointers.
                unsafe { patina_close(dup) };
                return sud_deny(
                    "patina: F_DUPFD minimum above the deterministic descriptor counter is not modeled; failing closed\n",
                );
            }
            dup as i64
        }
        // F_GETFL / F_SETFL / any unknown command: soft ENOSYS (C parity).
        _ => -ENOSYS,
    }
}

fn sys_ioctl(fd: i64, request: u64, arg: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    let cfd = fd as c_int;
    // Mirror the C ioctl interposer EXACTLY: FIONBIO toggles nonblocking on a
    // VIRTUAL socket only; FIOCLEX/FIONCLEX are no-ops; everything else — an
    // unknown request, or FIONBIO on a non-virtual fd — is a SOFT -ENOTTY (NOT
    // fatal, NOT a fabricated FIONREAD=0, which C does not model).
    match request {
        FIONBIO if fd >= PATINA_SOCKET_FD_BASE => {
            // SAFETY: `arg` points to an `int` on/off flag when non-null.
            let on = if arg != 0 {
                (unsafe { (arg as *const c_int).read() }) != 0
            } else {
                false
            };
            ret_i32(unsafe { patina_net_set_nonblocking(cfd, on as c_int) })
        }
        FIOCLEX | FIONCLEX => 0,
        _ => -ENOTTY,
    }
}

fn sys_pipe2(fds_out: u64, flags: u64) -> i64 {
    if fds_out == 0 {
        return -EFAULT;
    }
    let nonblocking = (flags & O_NONBLOCK != 0) as c_int;
    let mut read_fd: c_int = 0;
    let mut write_fd: c_int = 0;
    // SAFETY: local writable storage for the pair.
    let rc = unsafe { patina_pipe(&mut read_fd, &mut write_fd, nonblocking) };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    // SAFETY: `fds_out` is the guest's `int[2]`.
    unsafe {
        let out = fds_out as *mut c_int;
        out.write(read_fd);
        out.add(1).write(write_fd);
    }
    0
}

// ---- Metadata (fstat / newfstatat / statx) ----

struct StatValues {
    kind: u32,
    length: u64,
    ino: u64,
    nlink: u32,
    atime_nanos: u64,
    mtime_nanos: u64,
}

fn mode_for_kind(kind: u32) -> u32 {
    match kind {
        PATINA_ENTRY_DIRECTORY => S_IFDIR | 0o700,
        PATINA_ENTRY_SYMLINK => S_IFLNK | 0o777,
        _ => S_IFREG | 0o700,
    }
}

/// The kernel `struct stat` for the `fstat`/`newfstatat` syscalls. The layout is
/// arch-specific (x86_64 vs the arm64 generic layout); only the fields the C
/// `fill_stat` sets are populated, the rest stay zero.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Default)]
struct KernelStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    __pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    __unused: [i64; 3],
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Default)]
struct KernelStat {
    st_dev: u64,
    st_ino: u64,
    st_mode: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64,
    __pad1: u64,
    st_size: i64,
    st_blksize: i32,
    __pad2: i32,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: u64,
    st_mtime: i64,
    st_mtime_nsec: u64,
    st_ctime: i64,
    st_ctime_nsec: u64,
    __unused: [u32; 2],
}

impl KernelStat {
    fn from_values(values: &StatValues) -> Self {
        let mut stat = Self::default();
        stat.st_mode = mode_for_kind(values.kind);
        stat.st_nlink = values.nlink as _;
        stat.st_ino = values.ino;
        stat.st_size = values.length as i64;
        stat.st_atime = (values.atime_nanos / NANOS_PER_SEC) as i64;
        stat.st_atime_nsec = (values.atime_nanos % NANOS_PER_SEC) as _;
        stat.st_mtime = (values.mtime_nanos / NANOS_PER_SEC) as i64;
        stat.st_mtime_nsec = (values.mtime_nanos % NANOS_PER_SEC) as _;
        stat.st_ctime = stat.st_mtime;
        stat.st_ctime_nsec = stat.st_mtime_nsec;
        stat
    }
}

fn fd_stat_values(fd: c_int) -> Result<StatValues, i64> {
    let mut v = StatValues {
        kind: 0,
        length: 0,
        ino: 0,
        nlink: 0,
        atime_nanos: 0,
        mtime_nanos: 0,
    };
    // SAFETY: all out-pointers are writable local storage.
    let rc = unsafe {
        patina_fd_metadata_full(
            fd,
            &mut v.kind,
            &mut v.length,
            &mut v.ino,
            &mut v.nlink,
            &mut v.atime_nanos,
            &mut v.mtime_nanos,
        )
    };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        return Err(-(unsafe { patina_errno() } as i64));
    }
    Ok(v)
}

fn path_stat_values(path: *const c_char) -> Result<StatValues, i64> {
    let mut v = StatValues {
        kind: 0,
        length: 0,
        ino: 0,
        nlink: 0,
        atime_nanos: 0,
        mtime_nanos: 0,
    };
    // SAFETY: `path` is a valid guest C string; out-pointers are local storage.
    let rc = unsafe {
        patina_metadata_full(
            path,
            &mut v.kind,
            &mut v.length,
            &mut v.ino,
            &mut v.nlink,
            &mut v.atime_nanos,
            &mut v.mtime_nanos,
        )
    };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        return Err(-(unsafe { patina_errno() } as i64));
    }
    Ok(v)
}

/// Resolve one hop of terminal-symlink following, mirroring the C
/// `patina_stat_metadata`: metadata at `path`, and if a symlink is followed,
/// `readlink` + resolve-relative + re-stat once (a second symlink is ELOOP).
fn stat_metadata(path: *const c_char, follow: bool) -> Result<StatValues, i64> {
    let values = path_stat_values(path)?;
    if !follow || values.kind != PATINA_ENTRY_SYMLINK {
        return Ok(values);
    }
    // Read the link target.
    let mut target = [0u8; 4096];
    // SAFETY: `path` valid; `target` is writable for its length.
    let len = unsafe { patina_read_link(path, target.as_mut_ptr() as *mut c_char, target.len()) };
    if len < 0 {
        // SAFETY: plain thread-local read.
        return Err(-(unsafe { patina_errno() } as i64));
    }
    let target = &target[..len as usize];
    let link = match copy_c_path(path) {
        Some(link) => link,
        None => return Err(-EINVAL),
    };
    let resolved = match resolve_symlink_target(link.to_bytes(), target) {
        Some(resolved) => resolved,
        None => return Err(-ENAMETOOLONG),
    };
    let values = path_stat_values(resolved.as_ptr())?;
    if values.kind == PATINA_ENTRY_SYMLINK {
        return Err(-ELOOP);
    }
    Ok(values)
}

/// Resolve `target` relative to `link_path`, mirroring the C
/// `patina_resolve_symlink_target` (absolute target wins; otherwise splice onto
/// the link's parent directory). Returns a NUL-terminated resolved path.
fn resolve_symlink_target(link_path: &[u8], target: &[u8]) -> Option<CString> {
    if target.first() == Some(&b'/') {
        return CString::new(target).ok();
    }
    let parent = match link_path.iter().rposition(|&b| b == b'/') {
        Some(0) => &link_path[..1], // parent is "/"
        Some(slash) => &link_path[..slash],
        None => &link_path[..0],
    };
    let mut resolved = Vec::with_capacity(parent.len() + 1 + target.len());
    if parent.is_empty() {
        resolved.extend_from_slice(target);
    } else {
        resolved.extend_from_slice(parent);
        if !(parent.len() == 1 && parent[0] == b'/') {
            resolved.push(b'/');
        }
        resolved.extend_from_slice(target);
    }
    CString::new(resolved).ok()
}

fn write_kernel_stat(values: &StatValues, out: u64) -> i64 {
    if out == 0 {
        return -EINVAL;
    }
    // SAFETY: `out` is the guest's `struct stat` storage.
    unsafe { (out as *mut KernelStat).write(KernelStat::from_values(values)) };
    0
}

fn sys_fstat(fd: i64, statbuf: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // A SUD directory fd reports as a directory (rustix `Dir` fstat-checks it).
    if fd >= PATINA_SUD_DIR_FD_BASE as i64 {
        let dir_values = {
            let map = DIR_FDS.lock().unwrap();
            map.get(&(fd as c_int)).map(|dir| dir.path.clone())
        };
        if let Some(path) = dir_values {
            return match stat_metadata(path.as_ptr(), true) {
                Ok(values) => write_kernel_stat(&values, statbuf),
                Err(errno) => errno,
            };
        }
    }
    match fd_stat_values(fd as c_int) {
        Ok(values) => write_kernel_stat(&values, statbuf),
        Err(errno) => errno,
    }
}

fn sys_newfstatat(dirfd: i64, path: u64, statbuf: u64, flags: u64) -> i64 {
    // AT_EMPTY_PATH with an empty path is an fstat on the dirfd; otherwise only
    // AT_FDCWD-relative resolution is modeled (mirrors the C fstatat contract).
    if flags & AT_EMPTY_PATH != 0 && (path == 0 || unsafe { (path as *const u8).read() } == 0) {
        return sys_fstat(dirfd, statbuf);
    }
    if dirfd != AT_FDCWD {
        return -ENOSYS;
    }
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -ENOSYS;
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    match stat_metadata(path as *const c_char, follow) {
        Ok(values) => write_kernel_stat(&values, statbuf),
        Err(errno) => errno,
    }
}

/// Kernel `struct statx_timestamp`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct StatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    __reserved: i32,
}

/// Kernel `struct statx` (arch-independent).
#[repr(C)]
#[derive(Default)]
struct Statx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    stx_dio_mem_align: u32,
    stx_dio_offset_align: u32,
    __spare3: [u64; 12],
}

fn sys_statx(dirfd: i64, path: u64, flags: u64, statxbuf: u64) -> i64 {
    if dirfd != AT_FDCWD {
        return -ENOSYS;
    }
    if statxbuf == 0 {
        return -EFAULT;
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let values = match stat_metadata(path as *const c_char, follow) {
        Ok(values) => values,
        Err(errno) => return errno,
    };
    // STATX_{TYPE|MODE|NLINK|INO|SIZE|ATIME|MTIME|CTIME} — the exact mask the C
    // statx interposer reports.
    const STATX_MASK: u32 = 0x0001 | 0x0002 | 0x0004 | 0x0100 | 0x0200 | 0x0020 | 0x0040 | 0x0080;
    let mut stx = Statx::default();
    stx.stx_mask = STATX_MASK;
    stx.stx_mode = mode_for_kind(values.kind) as u16;
    stx.stx_nlink = values.nlink;
    stx.stx_ino = values.ino;
    stx.stx_size = values.length;
    stx.stx_atime = StatxTimestamp {
        tv_sec: (values.atime_nanos / NANOS_PER_SEC) as i64,
        tv_nsec: (values.atime_nanos % NANOS_PER_SEC) as u32,
        __reserved: 0,
    };
    stx.stx_mtime = StatxTimestamp {
        tv_sec: (values.mtime_nanos / NANOS_PER_SEC) as i64,
        tv_nsec: (values.mtime_nanos % NANOS_PER_SEC) as u32,
        __reserved: 0,
    };
    stx.stx_ctime = stx.stx_mtime;
    // SAFETY: `statxbuf` is the guest's `struct statx` storage.
    unsafe { (statxbuf as *mut Statx).write(stx) };
    0
}

// ---- getdents64 ----

fn dt_for_kind(kind: u32) -> u8 {
    match kind {
        PATINA_ENTRY_DIRECTORY => DT_DIR,
        PATINA_ENTRY_SYMLINK => DT_LNK,
        _ => DT_REG,
    }
}

/// Fill the guest buffer with `linux_dirent64` records from the fd's snapshot,
/// advancing `patina_read_dir_next` past every entry that fits. Returns the
/// number of bytes written (0 at end-of-directory) or `-errno`.
fn sys_getdents64(fd: i64, dirp: u64, count: u64) -> i64 {
    if !is_sud_dir_fd(fd) {
        // A getdents64 on anything but a SUD directory fd: the deterministic FS
        // hands out no other directory descriptors.
        return -ENOTDIR;
    }
    if dirp == 0 {
        return -EFAULT;
    }
    let cap = count as usize;
    let mut map = DIR_FDS.lock().unwrap();
    let Some(dir) = map.get_mut(&(fd as c_int)) else {
        return -EBADF;
    };
    let snapshot = dir.snapshot as *mut c_void;
    let mut written = 0usize;
    // linux_dirent64 header: d_ino(8) d_off(8) d_reclen(2) d_type(1) then name.
    const HEADER: usize = 19;
    loop {
        // Next entry: the pushed-back one first, else consume from the snapshot.
        // `patina_read_dir_next` only advances (no peek), so an entry that does
        // not fit is stashed in `dir.pending` and never dropped.
        let (name, kind) = if let Some(entry) = dir.pending.take() {
            entry
        } else {
            let mut buf = [0u8; 256];
            let mut k: u32 = 0;
            // SAFETY: `snapshot` is the live box; `buf` is writable for its length.
            let rc = unsafe {
                patina_read_dir_next(snapshot, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut k)
            };
            match rc {
                1 => {
                    // SAFETY: `buf` now holds a NUL-terminated name.
                    let len = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const c_char) }
                        .to_bytes()
                        .len();
                    (buf[..len].to_vec(), k)
                }
                0 => break, // end of directory
                _ => {
                    if written > 0 {
                        break;
                    }
                    // SAFETY: plain thread-local read.
                    return -(unsafe { patina_errno() } as i64);
                }
            }
        };
        let reclen = (HEADER + name.len() + 1 + 7) & !7; // 8-byte aligned
        if written + reclen > cap {
            // No room: push the entry back for the next call and stop. If nothing
            // fit at all, the caller's buffer is too small for even one entry.
            let empty = written == 0;
            dir.pending = Some((name, kind));
            if empty {
                return -EINVAL;
            }
            break;
        }
        // Commit: write the linux_dirent64 record into the guest buffer.
        // SAFETY: `dirp+written` has `reclen` bytes of room (checked above).
        unsafe {
            let rec = (dirp as *mut u8).add(written);
            // d_ino: the snapshot exposes no inode; a stable nonzero value keeps
            // callers that reject d_ino==0 happy.
            (rec as *mut u64).write((written as u64) + 1);
            (rec.add(8) as *mut i64).write((written + reclen) as i64); // d_off cookie
            (rec.add(16) as *mut u16).write(reclen as u16); // d_reclen
            rec.add(18).write(dt_for_kind(kind)); // d_type
            let dst = rec.add(HEADER);
            std::ptr::copy_nonoverlapping(name.as_ptr(), dst, name.len());
            dst.add(name.len()).write(0); // NUL
        }
        written += reclen;
    }
    written as i64
}

// ---- Directory namespace ops ----

fn sys_mkdirat(dirfd: i64, path: u64) -> i64 {
    if dirfd != AT_FDCWD {
        return -ENOSYS;
    }
    // SAFETY: `path` is a guest C string.
    ret_i32(unsafe { patina_mkdir(path as *const c_char) })
}

fn sys_unlinkat(dirfd: i64, path: u64, flags: u64) -> i64 {
    if dirfd != AT_FDCWD {
        return -ENOSYS;
    }
    // AT_REMOVEDIR selects rmdir; no flag selects unlink; unknown flags fail.
    if flags & !AT_REMOVEDIR != 0 {
        return -EINVAL;
    }
    // SAFETY: `path` is a guest C string.
    if flags & AT_REMOVEDIR != 0 {
        ret_i32(unsafe { patina_rmdir(path as *const c_char) })
    } else {
        ret_i32(unsafe { patina_unlink(path as *const c_char) })
    }
}

fn sys_symlinkat(target: u64, newdirfd: i64, linkpath: u64) -> i64 {
    if newdirfd != AT_FDCWD {
        return -ENOSYS;
    }
    // SAFETY: both are guest C strings.
    ret_i32(unsafe { patina_symlink(target as *const c_char, linkpath as *const c_char) })
}

fn sys_readlinkat(dirfd: i64, path: u64, buf: u64, bufsize: u64) -> i64 {
    if dirfd != AT_FDCWD {
        return -ENOSYS;
    }
    // SAFETY: `path` is a guest C string; `buf` is writable for `bufsize`.
    ret_isize(unsafe {
        patina_read_link(path as *const c_char, buf as *mut c_char, bufsize as usize)
    })
}

fn sys_renameat(olddirfd: i64, oldpath: u64, newdirfd: i64, newpath: u64, flags: u64) -> i64 {
    if olddirfd != AT_FDCWD || newdirfd != AT_FDCWD {
        return -ENOSYS;
    }
    // The deterministic rename models no flags (RENAME_NOREPLACE/EXCHANGE/…);
    // a nonzero renameat2 flag fails closed, mirroring the C interposer.
    if flags != 0 {
        return -EINVAL;
    }
    // SAFETY: both are guest C strings.
    ret_i32(unsafe { patina_rename(oldpath as *const c_char, newpath as *const c_char) })
}

// ---- Network (SimNet) ----

/// Parse a guest `struct sockaddr_in` (AF_INET only). Returns `(ip, port)` in
/// host byte order, mirroring the C `patina_parse_sockaddr`.
fn parse_sockaddr(addr: u64, len: u32) -> Option<(u32, u16)> {
    if addr == 0 || (len as usize) < core::mem::size_of::<SockaddrIn>() {
        return None;
    }
    // SAFETY: `addr` points to at least `sizeof(sockaddr_in)` guest bytes.
    let sa = unsafe { (addr as *const SockaddrIn).read_unaligned() };
    if sa.sin_family != AF_INET {
        return None;
    }
    Some((u32::from_be(sa.sin_addr), u16::from_be(sa.sin_port)))
}

/// Fill a guest `struct sockaddr_in` and update its length in/out pointer,
/// mirroring the C `patina_fill_sockaddr`.
fn fill_sockaddr(addr: u64, len_ptr: u64, ip: u32, port: u16) {
    if addr == 0 || len_ptr == 0 {
        return;
    }
    let sa = SockaddrIn {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: ip.to_be(),
        sin_zero: [0; 8],
    };
    // SAFETY: `len_ptr` is a writable socklen_t; `addr` is writable for `copy`.
    unsafe {
        let provided = (len_ptr as *const u32).read();
        let full = core::mem::size_of::<SockaddrIn>() as u32;
        let copy = provided.min(full) as usize;
        std::ptr::copy_nonoverlapping(
            (&sa as *const SockaddrIn).cast::<u8>(),
            addr as *mut u8,
            copy,
        );
        (len_ptr as *mut u32).write(full);
    }
}

fn sys_socket(domain: u64, ty: u64, protocol: u64) -> i64 {
    if domain as u16 != AF_INET {
        return -EAFNOSUPPORT;
    }
    let mut base = ty;
    let mut nonblocking = 0;
    if base & SOCK_NONBLOCK != 0 {
        nonblocking = 1;
        base &= !SOCK_NONBLOCK;
    }
    base &= !SOCK_CLOEXEC;
    let stream = if base == SOCK_DGRAM {
        if protocol != 0 && protocol != IPPROTO_UDP {
            return -EPROTONOSUPPORT;
        }
        0
    } else if base == SOCK_STREAM {
        if protocol != 0 && protocol != IPPROTO_TCP {
            return -EPROTONOSUPPORT;
        }
        1
    } else {
        return -EPROTOTYPE;
    };
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_net_socket(stream, nonblocking) })
}

fn sys_bind(fd: i64, addr: u64, len: u32) -> i64 {
    let Some((ip, port)) = parse_sockaddr(addr, len) else {
        return -EAFNOSUPPORT;
    };
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_net_bind(fd as c_int, ip, port) })
}

fn sys_listen(fd: i64, backlog: i64) -> i64 {
    if fd < PATINA_SOCKET_FD_BASE {
        return -ENOTSOCK;
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_net_listen(fd as c_int, backlog as c_int) })
}

fn sys_connect(fd: i64, addr: u64, len: u32) -> i64 {
    let Some((ip, port)) = parse_sockaddr(addr, len) else {
        return -EAFNOSUPPORT;
    };
    let cfd = fd as c_int;
    if fd >= PATINA_SOCKET_FD_BASE {
        // SAFETY: no pointers.
        return unsafe {
            match patina_net_kind(cfd) {
                3 => -EISCONN,
                1 => ret_i32(patina_net_tcp_connect(cfd, ip, port)),
                0 => ret_i32(patina_net_connect(cfd, ip, port)),
                2 => -EOPNOTSUPP,
                _ => -EBADF,
            }
        };
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_net_connect(cfd, ip, port) })
}

fn sys_accept(fd: i64, addr: u64, len_ptr: u64, flags: u64) -> i64 {
    if fd < PATINA_SOCKET_FD_BASE {
        return -ENOTSOCK;
    }
    // accept4 flags: only SOCK_CLOEXEC / SOCK_NONBLOCK are meaningful.
    if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
        return -EINVAL;
    }
    let mut ip: u32 = 0;
    let mut port: u16 = 0;
    // SAFETY: writable local storage.
    let accepted = unsafe { patina_net_accept(fd as c_int, &mut ip, &mut port) };
    if accepted < 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    fill_sockaddr(addr, len_ptr, ip, port);
    if flags & SOCK_NONBLOCK != 0 {
        // SAFETY: no pointers.
        let rc = unsafe { patina_net_set_nonblocking(accepted, 1) };
        if rc != 0 {
            // SAFETY: plain thread-local read.
            return -(unsafe { patina_errno() } as i64);
        }
    }
    accepted as i64
}

/// Whether the send/recv flags are all no-ops on a virtual socket (only
/// MSG_NOSIGNAL is tolerated), mirroring the C `patina_stream_flags_supported`.
fn stream_flags_supported(flags: u64) -> bool {
    flags & !MSG_NOSIGNAL == 0
}

fn sys_sendto(fd: i64, buf: u64, len: u64, flags: u64, addr: u64, alen: u32) -> i64 {
    let cfd = fd as c_int;
    let src = buf as *const c_void;
    let n = len as usize;
    if fd >= PATINA_SOCKET_FD_BASE && unsafe { patina_pipe_is_endpoint(cfd) } != 0 {
        if addr != 0 {
            return -EISCONN;
        }
        if !stream_flags_supported(flags) {
            return -EOPNOTSUPP;
        }
        // SAFETY: `buf`/`len` describe a guest buffer.
        return ret_isize(unsafe { patina_pipe_write(cfd, src, n) });
    }
    let kind = if fd >= PATINA_SOCKET_FD_BASE {
        unsafe { patina_net_kind(cfd) }
    } else {
        -1
    };
    if kind == 3 {
        if addr != 0 {
            return -EISCONN;
        }
        if !stream_flags_supported(flags) {
            return -EOPNOTSUPP;
        }
        // SAFETY: as above.
        return ret_isize(unsafe { patina_net_stream_send(cfd, src, n) });
    }
    if addr != 0 {
        let Some((ip, port)) = parse_sockaddr(addr, alen) else {
            return -EAFNOSUPPORT;
        };
        // SAFETY: as above.
        return ret_isize(unsafe { patina_net_sendto(cfd, src, n, ip, port) });
    }
    // SAFETY: as above.
    ret_isize(unsafe { patina_net_send(cfd, src, n) })
}

fn sys_recvfrom(fd: i64, buf: u64, len: u64, flags: u64, addr: u64, alen: u64) -> i64 {
    let cfd = fd as c_int;
    let dst = buf as *mut c_void;
    let n = len as usize;
    if fd >= PATINA_SOCKET_FD_BASE && unsafe { patina_pipe_is_endpoint(cfd) } != 0 {
        if !stream_flags_supported(flags) {
            return -EOPNOTSUPP;
        }
        // SAFETY: `buf`/`len` describe a guest buffer.
        return ret_isize(unsafe { patina_pipe_read(cfd, dst, n) });
    }
    let kind = if fd >= PATINA_SOCKET_FD_BASE {
        unsafe { patina_net_kind(cfd) }
    } else {
        -1
    };
    if kind == 3 {
        if addr != 0 {
            return -EISCONN;
        }
        if !stream_flags_supported(flags) {
            return -EOPNOTSUPP;
        }
        // SAFETY: as above.
        return ret_isize(unsafe { patina_net_stream_recv(cfd, dst, n) });
    }
    let mut ip: u32 = 0;
    let mut port: u16 = 0;
    // SAFETY: `buf`/`len` describe a guest buffer; ip/port are local storage.
    let result = ret_isize(unsafe { patina_net_recvfrom(cfd, dst, n, &mut ip, &mut port) });
    if result >= 0 && addr != 0 {
        fill_sockaddr(addr, alen, ip, port);
    }
    result
}

/// `sendmsg`/`recvmsg` mirror the C interposers EXACTLY: the deterministic net
/// layer models only `sendto`/`recvfrom` (routed through `patina_net_*`), and
/// the C `sendmsg`/`recvmsg` strong defs fail closed with `ENOSYS` — no
/// supported guest uses the scatter-gather/ancillary variants. So the SUD rows
/// refuse them identically. This is deliberately NOT a per-iovec `sendto` loop:
/// a datagram socket coalesces the iovec array into ONE datagram, so per-iovec
/// sends would fragment one message into N — a *silently-wrong* semantics that
/// house doctrine forbids (fail-closed beats silently-wrong). Refusing with the
/// same `ENOSYS` the interposer returns keeps the two vehicles byte-identical
/// and closes the fragmentation hole.
fn sys_sendmsg(_fd: i64, _msg: u64, _flags: u64) -> i64 {
    -ENOSYS
}

fn sys_recvmsg(_fd: i64, _msg: u64, _flags: u64) -> i64 {
    -ENOSYS
}

fn sys_shutdown(fd: i64, how: u64) -> i64 {
    if fd < PATINA_SOCKET_FD_BASE {
        return -ENOTSOCK;
    }
    let patina_how = match how {
        SHUT_RD => 0,
        SHUT_WR => 1,
        SHUT_RDWR => 2,
        _ => return -EINVAL,
    };
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_net_shutdown(fd as c_int, patina_how) })
}

fn sys_getsockname(fd: i64, addr: u64, len_ptr: u64) -> i64 {
    let mut ip: u32 = 0;
    let mut port: u16 = 0;
    // SAFETY: local storage.
    if unsafe { patina_net_getsockname(fd as c_int, &mut ip, &mut port) } != 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    fill_sockaddr(addr, len_ptr, ip, port);
    0
}

fn sys_getpeername(fd: i64, addr: u64, len_ptr: u64) -> i64 {
    let mut ip: u32 = 0;
    let mut port: u16 = 0;
    // SAFETY: local storage.
    if unsafe { patina_net_getpeername(fd as c_int, &mut ip, &mut port) } != 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    fill_sockaddr(addr, len_ptr, ip, port);
    0
}

/// Whether `optval` points to a zero `struct timeval` (POSIX "no timeout"),
/// mirroring the C `patina_zero_timeval`. A null/short buffer is not zero.
fn timeval_is_zero(value: u64, len: u32) -> bool {
    if value == 0 || (len as usize) < core::mem::size_of::<[i64; 2]>() {
        return false;
    }
    // SAFETY: `value` points to a `struct timeval { tv_sec: i64, tv_usec: i64 }`.
    unsafe {
        let p = value as *const i64;
        p.read() == 0 && p.add(1).read() == 0
    }
}

fn sys_setsockopt(fd: i64, level: u64, optname: u64, value: u64, len: u32) -> i64 {
    if fd < PATINA_SOCKET_FD_BASE {
        return -ENOTSOCK;
    }
    if level == SOL_SOCKET {
        match optname {
            SO_REUSEADDR | SO_REUSEPORT | SO_KEEPALIVE | SO_BROADCAST => return 0,
            SO_LINGER => {
                // Accept only linger-off (l_onoff == 0), like the C interposer.
                if value != 0 && (len as usize) >= 4 {
                    // SAFETY: `value` points to `struct linger`; l_onoff is its first int.
                    if unsafe { (value as *const i32).read() } == 0 {
                        return 0;
                    }
                }
            }
            SO_RCVTIMEO => {
                // struct timeval { tv_sec: i64, tv_usec: i64 } on 64-bit Linux.
                if value != 0 && (len as usize) >= 16 {
                    // SAFETY: `value` points to a `struct timeval`.
                    let (sec, usec) = unsafe {
                        let p = value as *const i64;
                        (p.read(), p.add(1).read())
                    };
                    let nanos = sec as u64 * NANOS_PER_SEC + usec as u64 * 1000;
                    // SAFETY: no pointers.
                    return ret_i32(unsafe { patina_net_set_read_timeout(fd as c_int, nanos) });
                }
            }
            // Only the no-op zero timeval is accepted (sends never block); a
            // non-zero send timeout falls through to ENOPROTOOPT below.
            SO_SNDTIMEO if timeval_is_zero(value, len) => return 0,
            _ => {}
        }
    }
    if level == IPPROTO_TCP && optname == TCP_NODELAY {
        return 0;
    }
    -ENOPROTOOPT
}

fn sys_getsockopt(fd: i64, value: u64, len_ptr: u64) -> i64 {
    if fd < PATINA_SOCKET_FD_BASE {
        return -ENOTSOCK;
    }
    // Mirror the C getsockopt: zero the caller's buffer, report success.
    if value != 0 && len_ptr != 0 {
        // SAFETY: `len_ptr` is a socklen_t; `value` is writable for that many bytes.
        unsafe {
            let n = (len_ptr as *const u32).read() as usize;
            std::ptr::write_bytes(value as *mut u8, 0, n);
        }
    }
    0
}

// ---- Readiness reactor (epoll) + eventfd ----

fn sys_epoll_create1(flags: u64) -> i64 {
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_epoll_create1(flags as c_int) })
}

/// Legacy `epoll_create(size)` (x86_64-only syscall). The `size` hint has been
/// ignored since Linux 2.6.8, but the kernel still rejects `size <= 0` with
/// `-EINVAL` before creating the instance with no flags. Everything else is
/// `epoll_create1(0)`.
#[cfg(target_arch = "x86_64")]
fn sys_epoll_create(size: u64) -> i64 {
    if size as i32 <= 0 {
        return -EINVAL;
    }
    sys_epoll_create1(0)
}

fn sys_epoll_ctl(epfd: i64, op: i64, fd: i64, event: u64) -> i64 {
    // SAFETY: `event` is a guest `struct epoll_event` for ADD/MOD (NULL for DEL,
    // which the entry tolerates).
    ret_i32(unsafe {
        patina_epoll_ctl(
            epfd as c_int,
            op as c_int,
            fd as c_int,
            event as *const c_void,
        )
    })
}

fn sys_epoll_wait(epfd: i64, events: u64, maxevents: i64, timeout_ms: i64) -> i64 {
    // SAFETY: `events` is the guest event buffer for `maxevents` entries.
    ret_i32(unsafe {
        patina_epoll_wait(
            epfd as c_int,
            events as *mut c_void,
            maxevents as c_int,
            timeout_ms as c_int,
        )
    })
}

fn sys_epoll_pwait(epfd: i64, events: u64, maxevents: i64, timeout_ms: i64, sigmask: u64) -> i64 {
    // Patina delivers no ambient signals, so a NULL mask is the plain wait; a
    // real mask swap has no deterministic meaning. Mirror the C epoll_pwait
    // interposer's deny EXACTLY — the same recorded diagnostic and -ENOSYS.
    if sigmask != 0 {
        return sud_deny("patina: epoll_pwait with a signal mask is not modeled; failing closed\n");
    }
    sys_epoll_wait(epfd, events, maxevents, timeout_ms)
}

fn sys_epoll_pwait2(epfd: i64, events: u64, maxevents: i64, timeout: u64, sigmask: u64) -> i64 {
    if sigmask != 0 {
        return -EINVAL;
    }
    // epoll_pwait2 takes an absolute `struct timespec *timeout` (NULL == block
    // forever). Convert to the millisecond timeout the reactor entry takes.
    let timeout_ms: i64 = if timeout == 0 {
        -1
    } else {
        // SAFETY: `timeout` is a guest `struct timespec`.
        let ts = unsafe { (timeout as *const Timespec).read() };
        if ts.tv_sec < 0 || ts.tv_nsec < 0 {
            return -EINVAL;
        }
        let ms = ts.tv_sec.saturating_mul(1000) + ts.tv_nsec / 1_000_000;
        ms.min(c_int::MAX as i64)
    };
    sys_epoll_wait(epfd, events, maxevents, timeout_ms)
}

fn sys_eventfd2(initval: u64, flags: i64) -> i64 {
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_eventfd(initval as u32, flags as c_int) })
}

/// `socketpair(2)`. Mirrors the C `socketpair` interposer (patina_posix.c) field
/// for field: only an `AF_UNIX` `SOCK_STREAM` pair (protocol 0) is a
/// deterministic in-process duplex; `SOCK_NONBLOCK`/`SOCK_CLOEXEC` are stripped
/// before the base-type check. The two descriptors are written into the guest's
/// `int sv[2]` on success.
fn sys_socketpair(domain: u64, sock_type: u64, protocol: u64, sv: u64) -> i64 {
    if sv == 0 {
        return -EFAULT;
    }
    if domain as i32 as i64 != AF_UNIX {
        return -EAFNOSUPPORT;
    }
    let type_bits = sock_type as i32 as i64;
    let nonblocking = (type_bits & SOCK_NONBLOCK as i64 != 0) as c_int;
    let base = type_bits & !((SOCK_NONBLOCK | SOCK_CLOEXEC) as i64);
    if base != SOCK_STREAM as i64 {
        return -EOPNOTSUPP;
    }
    if protocol as i32 != 0 {
        return -EPROTONOSUPPORT;
    }
    let mut fd0: c_int = 0;
    let mut fd1: c_int = 0;
    // SAFETY: local writable storage for the pair.
    let rc = unsafe { patina_socketpair(&mut fd0, &mut fd1, nonblocking) };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    // SAFETY: `sv` is the guest's `int[2]`.
    unsafe {
        let out = sv as *mut c_int;
        out.write(fd0);
        out.add(1).write(fd1);
    }
    0
}

/// The size of a Linux `struct pollfd` (`int fd; short events; short revents;`).
const POLLFD_SIZE: usize = 8;

/// The shared `poll`/`ppoll` core, mirroring the C `poll` interposer
/// (patina_posix.c). `timeout` is normalized to nanoseconds: `Some(0)` = return
/// immediately, `Some(n>0)` = wait `n` ns of VIRTUAL time, `None` = the "infinite"
/// timeout (poll's `-1` / ppoll's NULL). The C model:
///  - with descriptors (`nfds != 0`): a non-zero timeout is an unmodeled real
///    wait → `-ENOSYS`; a zero timeout requires every `events` to be empty (a
///    non-empty event set is an unmodeled real readiness query → `-ENOSYS`),
///    clearing each `revents` and returning 0.
///  - with no descriptors (`nfds == 0`): sleep for a strictly-positive timeout
///    (advancing virtual time), then return 0. An infinite/zero timeout returns 0
///    immediately (no event can ever arrive on an empty set, so a real kernel's
///    forever-block is deterministically an instant no-op here).
fn poll_core(fds: u64, nfds: u64, timeout: Option<u64>) -> i64 {
    let zero_timeout = timeout == Some(0);
    if nfds != 0 {
        if !zero_timeout {
            // A real wait on descriptors has no deterministic model.
            return -ENOSYS;
        }
        if fds == 0 {
            return -EFAULT;
        }
        for i in 0..nfds as usize {
            let entry = (fds as *mut u8).wrapping_add(i * POLLFD_SIZE);
            // events/revents are `short` at offsets 4 and 6 of the pollfd.
            // SAFETY: `fds` is the guest's array of `nfds` pollfd entries.
            let events = unsafe { (entry.add(4) as *const u16).read_unaligned() };
            if events != 0 {
                // A real readiness query is unmodeled.
                return -ENOSYS;
            }
            // SAFETY: as above; clear the result field.
            unsafe { (entry.add(6) as *mut u16).write_unaligned(0) };
        }
        return 0;
    }
    // No descriptors: a strictly-positive timeout advances virtual time; an
    // infinite or zero timeout returns 0 immediately.
    match timeout {
        Some(nanos) if nanos > 0 => {
            let mut now: u64 = 0;
            // SAFETY: local storage.
            let rc = unsafe { patina_clock_now(PATINA_CLOCK_MONOTONIC, &mut now) };
            if rc != 0 {
                return ret_i32(rc);
            }
            let deadline = now.saturating_add(nanos);
            // SAFETY: no pointers.
            ret_i32(unsafe { patina_sleep_until(PATINA_CLOCK_MONOTONIC, deadline) })
        }
        _ => 0,
    }
}

/// Legacy `poll(2)` (x86_64-only syscall). `timeout` is an `int` of milliseconds:
/// negative is the infinite timeout, otherwise it scales to nanoseconds for
/// [`poll_core`].
#[cfg(target_arch = "x86_64")]
fn sys_poll(fds: u64, nfds: u64, timeout_ms: i64) -> i64 {
    let timeout = if timeout_ms < 0 {
        None
    } else {
        Some((timeout_ms as u64).saturating_mul(1_000_000))
    };
    poll_core(fds, nfds, timeout)
}

/// `ppoll(2)`. The `int`-milliseconds timeout of `poll` becomes a relative
/// `struct timespec *` (NULL = infinite); a signal mask is inert in a signal-free
/// deterministic world (no ambient signals exist to block), so it is ignored and
/// the call routes through the same [`poll_core`]. `ppoll_time64` (x86_64 414) is
/// deliberately NOT routed — 64-bit callers never use it — so it stays fail-closed.
fn sys_ppoll(fds: u64, nfds: u64, timeout: u64, _sigmask: u64, _sigsetsize: u64) -> i64 {
    let timeout = if timeout == 0 {
        None
    } else {
        // SAFETY: `timeout` is a guest `struct timespec`.
        let ts = unsafe { (timeout as *const Timespec).read() };
        if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= NANOS_PER_SEC as i64 {
            return -EINVAL;
        }
        Some(
            (ts.tv_sec as u64)
                .saturating_mul(NANOS_PER_SEC)
                .saturating_add(ts.tv_nsec as u64),
        )
    };
    poll_core(fds, nfds, timeout)
}

/// Read a `prctl` option register as the kernel does. The kernel's prctl entry
/// is `SYSCALL_DEFINE5(prctl, int, option, …)` and immediately narrows it to an
/// `unsigned int` for its option dispatch (`option = (unsigned int) arg`), so a
/// caller's upper 32 register bits — sign-extended by hand asm or zero-extended
/// by rustix — never affect the comparison. Truncating to `u32` recovers that
/// exact view (mirrors [`arg_fd`]'s treatment of `int` fd args).
#[inline]
fn prctl_option(reg: u64) -> u32 {
    reg as u32
}

/// Serve `PR_GET_AUXV` from the shim's captured, already-scrubbed auxv `saved`,
/// mirroring the kernel's `prctl_get_auxv` (kernel/sys.c) byte-for-byte EXCEPT
/// the source is our determinized auxv rather than the kernel's pristine
/// `saved_auxv`:
///  - `arg4`/`arg5` nonzero ⇒ `-EINVAL` (the kernel rejects a non-zero tail).
///  - copy `min(user_size, saved.len())` bytes into the user buffer.
///  - return the FULL auxv byte length (`saved.len()`, NOT the copied count) —
///    the value rustix uses to size a second, exact-fit buffer (its dynamic path
///    asserts the re-query returns that same length) and, in the static path,
///    the slice length it then walks until `AT_NULL`. Because `saved` runs
///    through the terminating `AT_NULL` pair inclusively, a full copy always
///    contains the terminator rustix's unbounded `AuxPointer` walk stops on.
fn pr_get_auxv_copy(
    saved: &[u8],
    user_buf: *mut u8,
    user_size: usize,
    arg4: u64,
    arg5: u64,
) -> i64 {
    if arg4 != 0 || arg5 != 0 {
        return -EINVAL;
    }
    let copy = user_size.min(saved.len());
    if copy > 0 {
        if user_buf.is_null() {
            // The kernel's copy_to_user would fault on a bad/absent buffer.
            return -EFAULT;
        }
        // SAFETY: `user_buf` is the guest's buffer, valid for at least
        // `user_size >= copy` bytes; `saved` is the shim-owned scrubbed auxv,
        // valid for its whole length. The regions never overlap (distinct
        // allocations: guest buffer vs. the initial-stack auxv).
        unsafe {
            std::ptr::copy_nonoverlapping(saved.as_ptr(), user_buf, copy);
        }
    }
    saved.len() as i64
}

/// `prctl(2)`: the ONLY routed option is `PR_GET_AUXV`. Every other option is
/// the process/escape class (`PR_SET_SECCOMP`, `PR_SET_SYSCALL_USER_DISPATCH`,
/// `PR_SET_NAME`, …) and must never reach the host — it fails closed with a
/// named, diagnosable abort exactly like an unmapped syscall.
fn sys_prctl(option_reg: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i64 {
    let option = prctl_option(option_reg);
    if option != PR_GET_AUXV {
        crate::sud_fatal(&format!(
            "SUD trapped prctl(option={option:#x}): only PR_GET_AUXV is a deterministic route. Every \
             other prctl option is the process/escape class (PR_SET_SECCOMP, \
             PR_SET_SYSCALL_USER_DISPATCH, PR_SET_NAME, …) and fails closed — routing it would let a \
             guest reconfigure the process behind the deterministic runtime"
        ));
    }
    let base = PATINA_SUD_AUXV_BASE.load(Ordering::Relaxed);
    let len = PATINA_SUD_AUXV_LEN.load(Ordering::Relaxed);
    if base == 0 || len == 0 {
        // Init never captured the auxv: refuse rather than serve the kernel's
        // pristine (un-scrubbed, vDSO/AT_RANDOM-leaking) auxv or return 0/garbage.
        crate::sud_fatal(
            "SUD trapped prctl(PR_GET_AUXV) but the shim never captured the scrubbed auxv at init: \
             refusing to serve auxv bytes (serving the kernel's pristine saved_auxv would reintroduce \
             the AT_RANDOM entropy and AT_SYSINFO_EHDR vDSO escapes)",
        );
    }
    // SAFETY: `base`/`len` describe the shim's own scrubbed auxv region on the
    // initial stack, captured once during init and never mutated thereafter, so
    // the slice is valid for the whole (synchronous) dispatch.
    let saved = unsafe { std::slice::from_raw_parts(base as *const u8, len) };
    pr_get_auxv_copy(saved, arg2 as *mut u8, arg3 as usize, arg4, arg5)
}

fn unmapped(nr: i64, args: [u64; 6]) -> i64 {
    crate::sud_fatal(&format!(
        "SUD trapped unsupported syscall {nr} (args {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}); guest raw \
         syscalls must map to a deterministic route. This is the process/escape class (clone, \
         execve, ptrace, prctl, seccomp, io_uring, …) or a number slice 1 does not yet route — see \
         `cargo patina audit`",
        args[0], args[1], args[2], args[3], args[4], args[5]
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            arg_fd(PATINA_SOCKET_FD_BASE as u64 + 5),
            PATINA_SOCKET_FD_BASE + 5
        );
        assert_eq!(
            arg_fd(PATINA_SUD_DIR_FD_BASE as u64),
            PATINA_SUD_DIR_FD_BASE as i64
        );
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
        // shuffle.
        assert_eq!(sys_dup2(0, 0), 0);
        assert_eq!(sys_dup2(1, 1), 1);
        assert_eq!(sys_dup2(2, 2), 2);
        assert_eq!(sys_dup3(0, 0, 0), -EINVAL);
        assert_eq!(sys_dup3(1, 1, 0), -EINVAL);
        // An out-of-range equal fd is EBADF (a bad descriptor), NOT EINVAL.
        assert_eq!(sys_dup2(-1, -1), -EBADF);
        // A distinct-target dup2/dup3 both fail closed with -ENOSYS (chosen-number
        // dup unmodeled). They emit DIFFERENT deny diagnostics ("dup2" vs "dup3"),
        // but the errno the guest observes is identical.
        assert_eq!(sys_dup2(3, 7), -ENOSYS);
        assert_eq!(sys_dup3(3, 7, 0), -ENOSYS);
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
    fn poll_core_mirrors_the_c_poll_classification() {
        // With descriptors, a non-zero timeout is an unmodeled real wait (-ENOSYS),
        // whether infinite or positive — no guest memory is read on this path.
        assert_eq!(poll_core(0x1000, 3, None), -ENOSYS);
        assert_eq!(poll_core(0x1000, 3, Some(5_000_000)), -ENOSYS);
        // With descriptors and a zero timeout: a real (non-empty) event set is
        // unmodeled (-ENOSYS); an all-empty set clears revents and returns 0.
        let mut one = [0u8; POLLFD_SIZE]; // fd=0, events=0, revents=0xBEEF
        one[6] = 0xEF;
        one[7] = 0xBE;
        let ptr = one.as_mut_ptr() as u64;
        assert_eq!(poll_core(ptr, 1, Some(0)), 0);
        assert_eq!(&one[6..8], &[0, 0], "revents must be cleared");
        // A pollfd requesting POLLIN (events != 0) → -ENOSYS.
        let mut want = [0u8; POLLFD_SIZE];
        want[4] = 0x01; // POLLIN in the low byte of the `short events`
        assert_eq!(poll_core(want.as_mut_ptr() as u64, 1, Some(0)), -ENOSYS);
        // Empty set (nfds == 0): infinite/zero timeout returns 0 immediately (no
        // event can ever arrive), with no guest-memory access.
        assert_eq!(poll_core(0, 0, None), 0);
        assert_eq!(poll_core(0, 0, Some(0)), 0);
    }

    #[test]
    fn fcntl_regular_tail_and_ioctl_mirror_c_soft_errors() {
        // Regular-fd fcntl tail: only F_GETFD/F_SETFD are modeled; F_GETFL, F_SETFL,
        // and any unknown command are a SOFT -ENOSYS (C parity), never 0/fatal.
        assert_eq!(sys_fcntl(5, F_GETFD, 0), FD_CLOEXEC);
        assert_eq!(sys_fcntl(5, F_SETFD, 0), 0);
        assert_eq!(sys_fcntl(5, F_GETFL, 0), -ENOSYS);
        assert_eq!(sys_fcntl(5, F_SETFL, 0), -ENOSYS);
        assert_eq!(sys_fcntl(5, 0x9999, 0), -ENOSYS);
        // ioctl: FIOCLEX/FIONCLEX are no-ops; an unknown request and FIONBIO on a
        // NON-virtual fd are both a soft -ENOTTY (never fatal, never a fake
        // FIONREAD=0).
        assert_eq!(sys_ioctl(5, FIOCLEX, 0), 0);
        assert_eq!(sys_ioctl(5, FIONCLEX, 0), 0);
        assert_eq!(sys_ioctl(5, 0x1234, 0), -ENOTTY);
        assert_eq!(sys_ioctl(5, FIONBIO, 0), -ENOTTY); // non-virtual fd
    }

    #[test]
    fn openat_flag_decode_ignores_largefile_directory_cloexec_bits() {
        // rustix ORs O_LARGEFILE (0x8000) into every open, and a directory open
        // adds O_DIRECTORY|O_CLOEXEC. The legacy `open`/`creat` aliases and the
        // direct `openat` share ONE decode (`openat_patina_flags`), so they are
        // bit-for-bit identical — the round-6 EBADF was NOT a flag defect (it was
        // the SUD dir-fd fcntl/openat gap). This pins that: the noise bits never
        // perturb the decode. RED: folding O_LARGEFILE into the access-mode
        // compare, or reacting to O_DIRECTORY, would diverge open from openat.
        const O_LARGEFILE: u64 = 0o100000; // 0x8000 (rustix's signature bit)
        const O_DIRECTORY: u64 = 0o200000; // x86_64 value
        const O_CLOEXEC: u64 = 0o2000000;
        let noise = O_LARGEFILE | O_DIRECTORY | O_CLOEXEC;
        // The EXACT round-5 flag word (O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE).
        assert_eq!(
            openat_patina_flags(0x8241),
            PATINA_O_WRITE | PATINA_O_CREATE | PATINA_O_TRUNCATE
        );
        // A directory open decodes read-only (→ EISDIR → SUD dir-fd fallback).
        assert_eq!(
            openat_patina_flags(O_DIRECTORY | O_LARGEFILE),
            PATINA_O_READ
        );
        // The noise bits are inert atop any base access/creation flag word.
        for base in [
            0,
            O_WRONLY,
            O_RDWR,
            O_CREAT | O_WRONLY | O_TRUNC,
            O_APPEND | O_WRONLY,
        ] {
            assert_eq!(openat_patina_flags(base), openat_patina_flags(base | noise));
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
