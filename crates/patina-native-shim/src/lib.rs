//! Explicit native C ABI entry points for Patina.
//!
//! Internal crate: the native interposition layer that `cargo patina build`
//! links below a guest binary. The Rust side here exposes prefixed
//! `patina_*` C ABI entry points over the deterministic runtime; the bundled C
//! interposer (`c/patina_posix.c` and its per-family slices under `c/posix/`,
//! exported as [`POSIX_C_SOURCE`] and [`POSIX_C_FAMILY_SOURCES`]) provides the
//! libc-compatible symbols (file, socket, clock, thread, entropy) that route a
//! guest's ordinary `std` calls into it. The prefixed Rust surface
//! deliberately does not export ambient `open`/`read`/pthread symbols, so
//! linking this crate alone cannot silently alter unrelated host operations.
//! Adopters never depend on this crate; see [ARCHITECTURE.md] for the shim
//! design and its fail-closed doctrine.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

/// The POSIX interposer C translation unit, exposed as text so out-of-tree
/// tooling (`cargo patina build`) can reproduce the native link recipe from the
/// installed crate without the workspace source tree. It lives here — the crate
/// that owns `c/patina_posix.c` — so the shim's C and any embedded copy can
/// never drift, and so both this crate and `cargo-patina` package cleanly for
/// publish (each is self-contained; neither reaches across crate boundaries).
///
/// The unit is an umbrella: it `#include`s the per-family slices in
/// [`POSIX_C_FAMILY_SOURCES`], which must be staged beside it (at their
/// relative paths) before it is compiled.
pub const POSIX_C_SOURCE: &str = include_str!("../c/patina_posix.c");
/// The per-family slices `c/patina_posix.c` includes, as `(path relative to the
/// umbrella, source)`. One entry per file under `c/posix/`; the umbrella names
/// each by that relative path, so a slice added there must be added here (the
/// `posix_umbrella_includes_every_family_slice` test pins the two together).
pub const POSIX_C_FAMILY_SOURCES: &[(&str, &str)] = &[
    ("posix/core.c", include_str!("../c/posix/core.c")),
    ("posix/env.c", include_str!("../c/posix/env.c")),
    ("posix/init.c", include_str!("../c/posix/init.c")),
    ("posix/time.c", include_str!("../c/posix/time.c")),
    (
        "posix/sched_identity.c",
        include_str!("../c/posix/sched_identity.c"),
    ),
    ("posix/entropy.c", include_str!("../c/posix/entropy.c")),
    ("posix/fs.c", include_str!("../c/posix/fs.c")),
    ("posix/fd_io.c", include_str!("../c/posix/fd_io.c")),
    ("posix/mem.c", include_str!("../c/posix/mem.c")),
    (
        "posix/thread_sync.c",
        include_str!("../c/posix/thread_sync.c"),
    ),
    (
        "posix/signal_process.c",
        include_str!("../c/posix/signal_process.c"),
    ),
    (
        "posix/privileged.c",
        include_str!("../c/posix/privileged.c"),
    ),
    ("posix/net.c", include_str!("../c/posix/net.c")),
    ("posix/readiness.c", include_str!("../c/posix/readiness.c")),
    ("posix/stdio.c", include_str!("../c/posix/stdio.c")),
    ("posix/darwin.c", include_str!("../c/posix/darwin.c")),
    ("posix/dlsym.c", include_str!("../c/posix/dlsym.c")),
];
/// The companion C header for [`POSIX_C_SOURCE`] (`include/patina_native.h`).
pub const NATIVE_HEADER: &str = include_str!("../include/patina_native.h");

// The syscall registry: every kernel number with its disposition, the symbol
// layer mapped onto it, and the vendored-table gates. Platform-independent
// data; `cargo patina syscalls` reads it and the Linux SUD dispatcher is
// generated from it. See `registry/mod.rs`.
pub mod registry;

// Syscall-user-dispatch (SUD) dispatch table — Linux only. The C layer arms SUD
// and installs the SIGSYS handler; this module owns the per-arch decode and the
// routing of trapped raw syscalls into the same `patina_*` entry points the C
// interposers use. See `sud.rs` and `SUD-DESIGN.md`.
#[cfg(target_os = "linux")]
mod sud;

// Timestamp-counter trap (`rdtsc`/`rdtscp`) — armed by the C layer via
// `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)` on x86-64 Linux. This module owns the
// instruction decode and the virtual-clock derivation the SIGSEGV handler writes
// back into the guest's registers. See `tsc.rs`.
//
// Built on every Linux target (the decode is pure byte matching, and the audit's
// second condition is a live `PR_SET_TSC` probe, so an arm64 build carrying the
// dispatcher still never downgrades), and under `cfg(test)` everywhere so the
// decode's fail-closed behaviour is covered on a macOS host too.
#[cfg(any(target_os = "linux", test))]
mod tsc;

// The guest descriptor table: guest fd numbers → open file descriptions, for
// every class the shim models. The single global instance and every entry that
// consults it live below (`fd_table`, `patina_fd_kind`, the universal
// `patina_read`/`patina_close`/`patina_dup*` entries); the data structure and
// its allocation/refcount rules are the module's own. See `fdtable.rs`.
mod fdtable;
// `ioctl(2)`'s generic descriptor requests (`FIOCLEX`/`FIONCLEX`/`FIONBIO`/
// `FIONREAD`), one entry both doors call. See `ioctl.rs`.
mod ioctl;
// Vectored I/O (`readv`/`writev`/`preadv`/`pwritev` and the `*v2` flags): the
// iovec import the kernel's `lib/iov_iter.c` does, over the single-buffer
// transfers below. See `iov.rs`.
mod iov;
// Page-cache advice and writeback (`readahead`, `fadvise64`,
// `sync_file_range`, `sync`, `syncfs`). See `advice.rs`.
#[cfg(target_os = "linux")]
mod advice;
#[cfg(target_os = "linux")]
mod clocks;
#[cfg(target_os = "linux")]
mod identity;
// The virtual Darwin kernel's self-description (`uname` on macOS). Built
// under `cfg(test)` everywhere so its field model is covered on a Linux host
// too. See `darwin_identity.rs`.
#[cfg(any(target_os = "macos", test))]
mod darwin_identity;
// `localtime_r`'s time zone: glibc's TZ rules over the virtual machine. See
// `localtime.rs`.
#[cfg(target_os = "linux")]
mod limits;
mod localtime;
#[cfg(target_os = "linux")]
mod mem;
#[cfg(target_os = "linux")]
mod numa;
mod panic_boundary;
mod paths;
// Guest memory copied the way the kernel's `copy_from_user`/`copy_to_user` do:
// whole or `EFAULT`, never a fault in shim code. See `uaccess.rs`.
mod uaccess;
// What `statfs`/`fstatfs`/`ustat` report: the one deterministic volume and the
// kernel's pseudo-filesystems. See `volume.rs`.
// In-kernel copies (`copy_file_range`, `sendfile`, `splice`, `tee`,
// `vmsplice`) over the positional file I/O and the pipe channels. See
// `transfer.rs`.
#[cfg(target_os = "linux")]
mod transfer;
#[cfg(target_os = "linux")]
mod volume;
// Extended attributes: the `fs/xattr.c` syscall half over the filesystem's
// attribute store. See `xattr.rs`.
#[cfg(target_os = "linux")]
mod xattr;

use std::cell::{Cell, UnsafeCell};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io;
use std::ops::{Deref, DerefMut};
use std::slice;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use fdtable::{DescId, FdKind, GuestFdTable, Release, Resolved};

use patina_dst_abi::{
    ClockKind, EffectError, ErrorCode, Fd, FsDirectoryEntry, FsEntryKind, FsNode, OpenFlags,
    SeekWhence, TaskId,
};

use patina_dst_fs_crash::CrashFs;
use patina_dst_fs_mem::{FsImage, FsSnapshot, MemFs};
use patina_dst_runtime::{
    BuggifyKind, Context, CustomOpMode, MAX_TRACE_BYTES, RuntimeBuilder, RuntimeConfig,
    RuntimeError, SiteOutcome, TraceTransport, VerdictKind,
};
use patina_dst_trace::{
    HandoffSealKey, IncarnationHandoff, TraceError, abandoned_trace_marker,
    resource_limit_infra_line,
};
pub use thread::{
    patina_cond_broadcast, patina_cond_destroy, patina_cond_init, patina_cond_signal,
    patina_cond_timedwait, patina_cond_wait, patina_futex_wait, patina_futex_wait_timed,
    patina_futex_wake, patina_mutex_destroy, patina_mutex_init, patina_mutex_lock,
    patina_mutex_trylock, patina_mutex_unlock, patina_rwlock_destroy, patina_rwlock_init,
    patina_rwlock_rdlock, patina_rwlock_tryrdlock, patina_rwlock_trywrlock, patina_rwlock_unlock,
    patina_rwlock_wrlock, patina_thread_create, patina_thread_detach, patina_thread_exit,
    patina_thread_join,
};
#[cfg(target_os = "macos")]
pub use thread::{
    patina_dispatch_release, patina_dispatch_semaphore_create, patina_dispatch_semaphore_signal,
    patina_dispatch_semaphore_wait, patina_dispatch_time,
};

// POSIX errno values. The low-numbered codes below are identical on macOS and
// Linux, but several higher codes diverge (Darwin's BSD numbering vs Linux's
// asm-generic table). Those MUST be target-conditional: returning the macOS
// value on Linux hands the guest a *different* error — e.g. the macOS
// `EWOULDBLOCK` value 35 is Linux's `EDEADLK` ("Resource deadlock avoided"), so
// std's futex `EAGAIN` retry path (every contended mutex) was seen as a fatal
// deadlock. `EWOULDBLOCK == EAGAIN` on Linux (11).
const EACCES: c_int = 13;
#[cfg(target_os = "macos")]
const EALREADY: c_int = 37;
#[cfg(not(target_os = "macos"))]
const EALREADY: c_int = 114;
const EBADF: c_int = 9;
const EBUSY: c_int = 16;
#[cfg(target_os = "macos")]
const EDEADLK: c_int = 11;
#[cfg(not(target_os = "macos"))]
const EDEADLK: c_int = 35;
const EEXIST: c_int = 17;
const EINTR: c_int = 4;
const EINVAL: c_int = 22;
const EFAULT: c_int = 14;
const EIO: c_int = 5;
#[cfg(target_os = "linux")]
const ENOMEM: c_int = 12;
const EISDIR: c_int = 21;
const ENOENT: c_int = 2;
const ENOSPC: c_int = 28;
#[cfg(target_os = "macos")]
const ENOSYS: c_int = 78;
#[cfg(not(target_os = "macos"))]
const ENOSYS: c_int = 38;
const ENOTDIR: c_int = 20;
#[cfg(target_os = "macos")]
const ELOOP: c_int = 62;
#[cfg(not(target_os = "macos"))]
const ELOOP: c_int = 40;
#[cfg(target_os = "macos")]
const ENOTEMPTY: c_int = 66;
#[cfg(not(target_os = "macos"))]
const ENOTEMPTY: c_int = 39;
#[cfg(target_os = "macos")]
const EOVERFLOW: c_int = 84;
#[cfg(not(target_os = "macos"))]
const EOVERFLOW: c_int = 75;
const EPERM: c_int = 1;
const ESRCH: c_int = 3;
#[cfg(target_os = "macos")]
const EWOULDBLOCK: c_int = 35;
#[cfg(not(target_os = "macos"))]
const EWOULDBLOCK: c_int = 11;
#[cfg(target_os = "macos")]
const ENOTCONN: c_int = 57;
#[cfg(not(target_os = "macos"))]
const ENOTCONN: c_int = 107;
const EPIPE: c_int = 32;
/// `ENXIO` — the answer a non-blocking `open(fifo, O_WRONLY)` gets with no
/// reader. Same value on macOS and Linux.
const ENXIO: c_int = 6;
#[cfg(target_os = "macos")]
const ECONNRESET: c_int = 54;
#[cfg(not(target_os = "macos"))]
const ECONNRESET: c_int = 104;
#[cfg(target_os = "macos")]
const EISCONN: c_int = 56;
#[cfg(not(target_os = "macos"))]
const EISCONN: c_int = 106;
#[cfg(target_os = "macos")]
const ECONNREFUSED: c_int = 61;
#[cfg(not(target_os = "macos"))]
const ECONNREFUSED: c_int = 111;
#[cfg(target_os = "macos")]
const EOPNOTSUPP: c_int = 102;
#[cfg(not(target_os = "macos"))]
const EOPNOTSUPP: c_int = 95;
#[cfg(target_os = "macos")]
const ETIMEDOUT: c_int = 60;
#[cfg(target_os = "linux")]
const ETIMEDOUT: c_int = 110;

#[cfg(target_os = "macos")]
const ENOTSOCK: c_int = 38;
#[cfg(target_os = "linux")]
const ENOTSOCK: c_int = 88;
const EFBIG: c_int = 27;
/// `fallocate` on a descriptor that is neither a regular file nor a block
/// device (a socket, an eventfd, a character device); 19 on Linux and Darwin.
const ENODEV: c_int = 19;
const ERANGE: c_int = 34;
const E2BIG: c_int = 7;
const EXDEV: c_int = 18;

/// The modeled page size: what `sysconf(_SC_PAGESIZE)` answers (the C layer
/// pins it), so what every page-granular kernel rule reads.
#[cfg(target_os = "linux")]
pub(crate) const PAGE_SIZE: usize = 4096;
#[cfg(target_os = "macos")]
const ENAMETOOLONG: c_int = 63;
#[cfg(not(target_os = "macos"))]
const ENAMETOOLONG: c_int = 36;
#[cfg(target_os = "macos")]
const ENODATA: c_int = 96;
#[cfg(not(target_os = "macos"))]
const ENODATA: c_int = 61;
const ESPIPE: c_int = 29;
const MAX_CAPTURED_STDIO_BYTES: usize = 64 * 1024 * 1024;
const HOST_IO_CHUNK: usize = 64 * 1024;

const O_READ: u32 = 1 << 0;
const O_WRITE: u32 = 1 << 1;
const O_CREATE: u32 = 1 << 2;
const O_TRUNCATE: u32 = 1 << 3;
const O_APPEND: u32 = 1 << 4;
const O_EXCLUSIVE: u32 = 1 << 5;
/// `O_NOFOLLOW`: refuse a trailing symlink instead of resolving it. Not a driver
/// flag — the deterministic filesystem never opens a symlink entry — but the
/// choice [`patina_openat`] makes when the path turns out to name one: `ELOOP`
/// with this bit, resolve-and-retry without it.
const O_NOFOLLOW: u32 = 1 << 6;
/// `O_NONBLOCK`: on a regular file or a directory this changes nothing (it is a
/// no-op on every Unix), so it is not a driver flag either. It matters for
/// exactly one modeled entry kind — a FIFO — where it turns the open's
/// rendezvous with the opposite end into an immediate answer.
const O_NONBLOCK: u32 = 1 << 7;
/// `O_PATH`: name a LOCATION without opening the file behind it. This one IS a
/// driver flag: it changes what the open costs (the path prefix's `x` walk and
/// nothing on the entry, where a plain read-only open of a directory pays `r`)
/// and what the descriptor can then do (`*at` resolution, `fstat`, `readlinkat`,
/// `dup`, `close` — never a read, a write, or a directory listing). The kernel
/// ignores the access mode under it, so it never travels with `O_READ`/`O_WRITE`.
const O_PATH: u32 = 1 << 8;
/// `O_CLOEXEC`: not a driver flag and not a status flag either — it is the
/// per-NUMBER `FD_CLOEXEC` bit of the descriptor the open mints, so it lives on
/// the table slot, never on the description.
const O_CLOEXEC: u32 = 1 << 9;
/// `O_DIRECTORY`: the entry must be a directory (`ENOTDIR` otherwise). Not a
/// driver flag — the resolver already knows the entry's kind, and a directory
/// is opened as one whether or not the caller asked.
const O_DIRECTORY: u32 = 1 << 11;
/// A status bit the table sets on every description `open(2)` mints (a file, a
/// directory opened for reading, the entropy device, a FIFO endpoint) and on
/// nothing else: a 64-bit Linux kernel forces `O_LARGEFILE` into those
/// descriptions' `F_GETFL`, and a pipe, socket or `O_PATH` handle never carries
/// it. Never accepted from a caller (`O_ALL` excludes it).
const O_OPENED: u32 = 1 << 10;
const O_ALL: u32 = O_READ
    | O_WRITE
    | O_CREATE
    | O_TRUNCATE
    | O_APPEND
    | O_EXCLUSIVE
    | O_NOFOLLOW
    | O_NONBLOCK
    | O_PATH
    | O_CLOEXEC
    | O_DIRECTORY;
/// The status bits `F_SETFL` may change (the kernel ignores every other bit in
/// the argument, including the access mode).
const O_SETFL_MASK: u32 = O_APPEND | O_NONBLOCK;

/// A minimal spinlock the shim uses instead of `std::sync::Mutex`.
///
/// The shim interposes `pthread_mutex_*`, so its own `std::sync::Mutex` would
/// recurse straight back into the deterministic layer. A spinlock built on
/// atomics never touches pthread, and every critical section here is short and
/// almost always uncontended: only the managed thread that currently holds the
/// execution baton runs shim code, so contention is limited to brief handoffs.
struct SpinMutex<T> {
    /// The lock word: the holding thread's [`thread_token`], 0 while free.
    /// Taking the lock and naming its holder are one compare-exchange, so
    /// there is no instant at which the lock is held by nobody in particular.
    /// A contended acquire whose holder is the acquiring thread itself can
    /// never succeed:
    /// the only way one thread reaches a shim lock it already holds is a
    /// signal handler running over shim code (a fault in the shim, the guest's
    /// handler calling back into an interposer), and spinning there hangs the
    /// process where the kernel would have answered. [`SpinMutex::lock`] turns
    /// it into a named fatal instead.
    owner: AtomicUsize,
    value: UnsafeCell<T>,
}

/// A shim lock re-acquired by the thread that holds it (see [`SpinMutex`]).
#[derive(Debug, PartialEq, Eq)]
struct SelfDeadlock;

/// This thread's identity for [`SpinMutex::owner`]: the address of one of its
/// thread-locals, never 0 and unique among LIVE threads (a thread that exits
/// can hand its address to a later one; a holder cannot exit while holding a
/// shim lock without the process aborting first).
fn thread_token() -> usize {
    thread_local! {
        static TOKEN: u8 = const { 0 };
    }
    TOKEN.with(|token| token as *const u8 as usize)
}

// SAFETY: the spinlock serializes all access to the interior value, so it is
// safe to share across threads whenever the value may be sent across them.
unsafe impl<T: Send> Sync for SpinMutex<T> {}
// SAFETY: as above; ownership can move across threads.
unsafe impl<T: Send> Send for SpinMutex<T> {}

impl<T> SpinMutex<T> {
    const fn new(value: T) -> Self {
        Self {
            owner: AtomicUsize::new(0),
            value: UnsafeCell::new(value),
        }
    }

    fn lock(&self) -> SpinGuard<'_, T> {
        self.acquire().unwrap_or_else(|SelfDeadlock| {
            // Nothing that takes a shim lock may run here — the lock this
            // thread re-entered may be any of them, the captured-stdio one
            // included — so the diagnostic goes straight to the host.
            let _ = host_write_all(
                2,
                b"patina native shim fatal: a shim lock was re-entered by the thread that \
                  holds it (a signal handler ran over shim code); failing closed\n",
            );
            host_abort()
        })
    }

    /// Take the lock, or report that this thread already holds it.
    fn acquire(&self) -> Result<SpinGuard<'_, T>, SelfDeadlock> {
        let me = thread_token();
        while let Err(holder) =
            self.owner
                .compare_exchange_weak(0, me, Ordering::Acquire, Ordering::Relaxed)
        {
            // The lock word names its holder from the instant it is taken, so
            // this thread reads its own token exactly while it holds the lock.
            if holder == me {
                return Err(SelfDeadlock);
            }
            while self.owner.load(Ordering::Relaxed) != 0 {
                std::hint::spin_loop();
            }
        }
        // Mark that this thread now holds a shim spinlock, so a reentrant lock
        // interposer (reached only via an allocator-internal allocation on the
        // scheduler path) forwards to the real host primitive instead of
        // deadlocking on this very lock. See `SPIN_DEPTH`.
        spin_depth_inc();
        Ok(SpinGuard { mutex: self })
    }
}

struct SpinGuard<'a, T> {
    mutex: &'a SpinMutex<T>,
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: holding the guard guarantees exclusive access.
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: holding the guard guarantees exclusive access.
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.owner.store(0, Ordering::Release);
        spin_depth_dec();
    }
}

#[cfg(test)]
mod spin_mutex_tests {
    use super::{SelfDeadlock, SpinMutex};

    #[test]
    fn a_lock_its_own_holder_takes_again_is_a_self_deadlock_not_a_spin() {
        let mutex = SpinMutex::new(0u8);
        let held = mutex.acquire().expect("a free lock is taken");
        assert_eq!(mutex.acquire().err(), Some(SelfDeadlock));
        drop(held);
        assert!(mutex.acquire().is_ok(), "released, it is free again");
    }

    #[test]
    fn a_lock_another_thread_released_is_no_self_deadlock() {
        let mutex = std::sync::Arc::new(SpinMutex::new(0u8));
        let other = std::sync::Arc::clone(&mutex);
        std::thread::spawn(move || drop(other.acquire().expect("taken elsewhere")))
            .join()
            .unwrap();
        let held = mutex.acquire().expect("free after the other thread");
        assert_eq!(mutex.acquire().err(), Some(SelfDeadlock));
        drop(held);
    }
}

static CONTEXT: OnceLock<SpinMutex<Option<Context>>> = OnceLock::new();
static STDIO: OnceLock<SpinMutex<StdioCapture>> = OnceLock::new();
static FD_TABLE: OnceLock<SpinMutex<GuestFdTable>> = OnceLock::new();

/// The guest descriptor table (see `fdtable.rs`). Lock order: the thread
/// runtime's state lock first, this lock second — `fd_readiness` and the
/// waiter registration resolve descriptors while holding the runtime state —
/// and this lock is never held across a runtime call or a scheduling point.
fn fd_table() -> &'static SpinMutex<GuestFdTable> {
    FD_TABLE.get_or_init(|| {
        SpinMutex::new(GuestFdTable::new(
            fdtable::RLIMIT_NOFILE,
            O_READ,
            O_WRITE,
            O_WRITE,
        ))
    })
}

/// What a guest number names right now, or `EBADF` — the kernel's
/// `fdget_raw`, which an `O_PATH` descriptor passes (`fstat`, `fstatfs`,
/// `fcntl`, the base of a `*at` path).
pub(crate) fn resolve_fd(raw_fd: c_int) -> Result<Resolved, c_int> {
    fd_table().lock().resolve(raw_fd).ok_or(EBADF)
}

/// What a guest number names for an operation on an OPENED file — the kernel's
/// `fdget`, which refuses an `O_PATH` descriptor with `EBADF` exactly as it
/// refuses an empty slot (`read`, `ioctl`, `fsync`, the `f*xattr` rows, ...).
pub(crate) fn fdget(raw_fd: c_int) -> Result<Resolved, c_int> {
    match resolve_fd(raw_fd)? {
        resolved if resolved.kind == FdKind::OPath => Err(EBADF),
        resolved => Ok(resolved),
    }
}

/// The driver handle behind a deterministic-filesystem descriptor. Any other
/// kind — and an empty slot — is `EBADF`, which is what every filesystem-only
/// entry (`fstat`, `fchmod`, `getdents`, the record locks) answers for a
/// descriptor that is not a file.
fn fs_handle(raw_fd: c_int) -> Result<Fd, c_int> {
    let resolved = resolve_fd(raw_fd)?;
    if resolved.kind.is_fs() {
        Ok(Fd(resolved.handle))
    } else {
        Err(EBADF)
    }
}

/// Bind a fresh description to the lowest free guest number, or `EMFILE`.
fn install_fd(kind: FdKind, handle: u64, status: u32, cloexec: bool) -> Result<c_int, c_int> {
    fd_table().lock().install(kind, handle, status, cloexec)
}

/// Free the class object a description named, once its last reference is
/// gone. Runs OUTSIDE the table lock: a driver close is a recorded boundary
/// operation, a pipe close wakes parked peers, and a readiness registry drop
/// wakes parked waiters.
pub(crate) fn release_description(release: Release) -> Result<(), c_int> {
    flock_release(release.desc);
    // An epoll interest is on the FILE (the kernel's `(fd, struct file)` key
    // drops with the file's last reference), whatever kind it was.
    #[cfg(target_os = "linux")]
    thread::forget_description(release.desc);
    match release.kind {
        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr | FdKind::Urandom => Ok(()),
        FdKind::File | FdKind::Dir | FdKind::OPath => {
            #[cfg(target_os = "linux")]
            mem::released(release.handle);
            with_context(|context| context.fs_close(Fd(release.handle)))
        }
        FdKind::Socket => thread::net::socket_close(release.handle),
        FdKind::Pipe => thread::pipe_close(release.handle),
        #[cfg(target_os = "linux")]
        FdKind::SignalFd => {
            thread::signals::fd::close(release.handle);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        FdKind::EventFd => {
            thread::eventfd_close(release.handle);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        FdKind::TimerFd => {
            thread::timers::timerfd_close(release.handle);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        FdKind::Epoll => {
            thread::epoll_close(release.handle);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue => {
            thread::ipc::mq_close(release.handle);
            Ok(())
        }
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => {
            thread::kqueue_close(release.handle);
            Ok(())
        }
    }
}

/// True from process start until the shim constructor finishes installing the
/// deterministic runtime ([`patina_init_from_env`] clears it at the end). This is
/// the window in which a custom global allocator's OWN eager, constructor-driven
/// initialization runs (tikv-jemallocator installs a `__attribute__((constructor))`
/// that calls `malloc_init_hard` before `main`). During it the shim runs the
/// allocator's init-reachable interposers NATIVELY rather than through the
/// deterministic model: the allocator's init locks/reads are allocator-internal,
/// single-threaded, and — crucially — must not allocate through the shim (a shim
/// allocation re-enters the half-initialized guest allocator and deadlocks or trips
/// its non-recursive init lock). Started `true` (before ANY constructor runs, so it
/// covers the allocator's constructor whichever order it is scheduled in) and
/// cleared exactly once, before `main`; a single-threaded guest's later, legitimate
/// deterministic calls (e.g. `readlink` in `main`) are therefore unaffected.
///
/// Cleared only by a SUCCESSFUL install, so a failed one leaves it set for the
/// rest of the process — which is why the window is entered exclusively through
/// [`in_shim_bootstrap`], where a stored init error turns every answer below it
/// into a named abort.
static SHIM_BOOTSTRAP: AtomicBool = AtomicBool::new(true);

#[repr(C)]
struct StaticSiteDescriptor {
    label_ptr: *const u8,
    label_len: usize,
    site_ptr: *const u8,
    site_len: usize,
    kind: u8,
    _reserved: [u8; 7],
}

// SAFETY: descriptors point at immutable linker-section data and are never
// mutated by the shim.
unsafe impl Sync for StaticSiteDescriptor {}

impl StaticSiteDescriptor {
    const fn sentinel() -> Self {
        Self {
            label_ptr: core::ptr::null(),
            label_len: 0,
            site_ptr: core::ptr::null(),
            site_len: 0,
            kind: 0,
            _reserved: [0; 7],
        }
    }

    fn is_sentinel(&self) -> bool {
        self.kind == 0 && self.label_len == 0 && self.site_len == 0
    }
}

#[used]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__DATA,__patina_sites"))]
#[cfg_attr(not(target_os = "macos"), unsafe(link_section = "patina_sites"))]
static PATINA_STATIC_SITE_SENTINEL: StaticSiteDescriptor = StaticSiteDescriptor::sentinel();

#[cfg(target_os = "macos")]
unsafe extern "C" {
    #[link_name = "\u{1}section$start$__DATA$__patina_sites"]
    static PATINA_STATIC_SITES_START: StaticSiteDescriptor;
    #[link_name = "\u{1}section$end$__DATA$__patina_sites"]
    static PATINA_STATIC_SITES_END: StaticSiteDescriptor;
}

#[cfg(not(target_os = "macos"))]
unsafe extern "C" {
    #[link_name = "__start_patina_sites"]
    static PATINA_STATIC_SITES_START: StaticSiteDescriptor;
    #[link_name = "__stop_patina_sites"]
    static PATINA_STATIC_SITES_END: StaticSiteDescriptor;
}

fn declare_link_time_sites(context: &mut Context) -> Result<(), RuntimeError> {
    let start = core::ptr::addr_of!(PATINA_STATIC_SITES_START).cast::<StaticSiteDescriptor>();
    let end = core::ptr::addr_of!(PATINA_STATIC_SITES_END).cast::<StaticSiteDescriptor>();
    let start_addr = start as usize;
    let end_addr = end as usize;
    let byte_len = end_addr.checked_sub(start_addr).ok_or_else(|| {
        RuntimeError::Config("Patina static site linker section has invalid bounds".to_string())
    })?;
    let record_size = core::mem::size_of::<StaticSiteDescriptor>();
    if record_size == 0 || byte_len % record_size != 0 {
        return Err(RuntimeError::Config(format!(
            "Patina static site linker section size {byte_len} is not a multiple of {record_size}"
        )));
    }
    // SAFETY: the start/end symbols delimit the linker section populated with
    // `StaticSiteDescriptor` records by the SDK macros plus the sentinel above.
    let descriptors = unsafe { slice::from_raw_parts(start, byte_len / record_size) };
    for descriptor in descriptors {
        if descriptor.is_sentinel() {
            continue;
        }
        let kind = BuggifyKind::from_static_site_kind(descriptor.kind).ok_or_else(|| {
            RuntimeError::Config(format!(
                "Patina static site declaration has unknown kind {}",
                descriptor.kind
            ))
        })?;
        let label = descriptor_text("label", descriptor.label_ptr, descriptor.label_len)?;
        let site = descriptor_text("site", descriptor.site_ptr, descriptor.site_len)?;
        if context.declare_static_site(label, site, kind)? == SiteOutcome::DuplicateLabel {
            abort_with_buggify_marker("PATINA_BUGGIFY_DUPLICATE_LABEL", label);
        }
    }
    Ok(())
}

fn descriptor_text(
    field: &str,
    pointer: *const u8,
    length: usize,
) -> Result<&'static str, RuntimeError> {
    if length == 0 {
        return Err(RuntimeError::Config(format!(
            "Patina static site {field} must not be empty"
        )));
    }
    if pointer.is_null() {
        return Err(RuntimeError::Config(format!(
            "Patina static site {field} pointer is null"
        )));
    }
    // SAFETY: descriptor pointers come from SDK string literals retained in the
    // same linked image as the descriptor and therefore live for the process.
    let bytes = unsafe { slice::from_raw_parts(pointer, length) };
    std::str::from_utf8(bytes).map_err(|error| {
        RuntimeError::Config(format!(
            "Patina static site {field} is not valid UTF-8: {error}"
        ))
    })
}

/// Whether the process is still in the shim-bootstrap window (see
/// [`SHIM_BOOTSTRAP`]). Read lock-free so the interposers can branch on it on
/// entry, before touching any shim lock or the guest allocator.
///
/// This is the ONE door into the window, and it fails closed on a failed init:
/// [`SHIM_BOOTSTRAP`] is cleared only by a SUCCESSFUL [`install`], so an
/// initialization that failed closed (a `--fingerprint` mismatch, a bad
/// `--mount` corpus, ...) leaves the window open for the rest of the process.
/// Every answer behind it — a zero clock, a zero CPU time, `ENOENT` for a
/// `read_link`, a natively-run lock — is produced WITHOUT reaching
/// [`ensure_runtime`], so without the check below the guest never learns the run
/// was refused. That is not hypothetical: a replay of a guest whose only
/// boundary operations are clock reads used to spin at 100% CPU on a fabricated
/// frozen clock instead of aborting on the fingerprint mismatch. Consulting the
/// stored init error HERE, rather than at each answer, covers the paths that
/// exist and the ones not yet written; `bootstrap_window_lints` keeps it the
/// only reader of the flag.
#[inline]
fn in_shim_bootstrap() -> bool {
    if !SHIM_BOOTSTRAP.load(Ordering::Acquire) {
        return false;
    }
    abort_if_init_failed();
    true
}

thread_local! {
    /// How many shim [`SpinMutex`]es this thread currently holds. Incremented when
    /// a guard is acquired and decremented on drop, so `> 0` means the thread is
    /// executing shim-internal code with a spinlock held.
    ///
    /// This is what makes a custom global allocator (jemalloc) work AFTER the
    /// bootstrap window too: the shim holds its `thread_runtime` spinlock while
    /// calling the scheduler (in `patina-dst-runtime`), whose ordinary Rust
    /// allocations go through the guest allocator. A reentrant `os_unfair_lock` the
    /// allocator takes from inside that allocation would re-acquire the held
    /// spinlock and deadlock — so when a spinlock is held, the lock interposers
    /// forward the (allocator-internal) lock to the real host primitive instead.
    /// The guest never runs guest code with a spinlock held (`switch_and_park`
    /// drops the guard before the baton handoff), so a held spinlock uniquely marks
    /// allocator-internal reentrancy. With the DEFAULT allocator this never fires:
    /// libc malloc's own locks are bound inside libc, not interposed.
    static SPIN_DEPTH: Cell<usize> = const { Cell::new(0) };
}

#[inline]
fn spin_depth_inc() {
    SPIN_DEPTH.with(|depth| depth.set(depth.get() + 1));
}

#[inline]
fn spin_depth_dec() {
    SPIN_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
}

/// Whether this thread currently holds any shim spinlock — i.e. a lock-interposer
/// call now would be allocator-internal reentrancy that must run natively rather
/// than re-acquire the held spinlock. See [`SPIN_DEPTH`].
#[inline]
fn in_shim_critical() -> bool {
    SPIN_DEPTH.with(Cell::get) > 0
}

#[derive(Default)]
struct StdioCapture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

// Host-alias doctrine (see ARCHITECTURE.md, "Host-alias doctrine").
//
// Shim-internal code must never name a public, interposable host symbol as an
// undefined external. Such a name would appear in the *guest binary's* import
// table (the shim is statically linked into the guest), forcing `native-audit`
// to `--allow` it — a name-based allowance guest code can ride past the gate.
// That is exactly the class of the worst escape found: the execution baton used
// the public `dispatch_semaphore_*` symbols, so allowing them for the shim also
// allowed std's `Parker` to reach the real host semaphore off-scheduler.
//
// Instead every host vehicle the shim needs — the trace-fd descriptor I/O here,
// the execution-baton semaphore, and the managed host-thread creation vehicle —
// is resolved once, by string, through `dlsym(RTLD_NEXT, ...)` at first use and
// cached in [`hostapi::HostApi`]. `RTLD_NEXT` reaches the *real* libSystem/libc
// definition even for a name the shim itself interposes (verified: from the main
// executable image, `dlsym(RTLD_NEXT, "dispatch_semaphore_wait")` returns
// libdispatch's implementation, not the shim's strong def), so the shim's own
// host use is invisible to the symbol namespace while a guest naming the same
// public symbol still binds to the interposer (its own image) or is denied by
// the audit. The only escape-surface symbol the shim objects still name is
// `dlsym` itself; the `cargo-patina/tests/shim_host_alias.rs` scan
// enforces that by scanning the shim's own objects (red→green: it fails on the
// pre-doctrine shim that named `semaphore_wait`, `pthread_create_suspended_np`,
// `read$NOCANCEL`, ... and passes once they route through here).
//
// Both platforms are swept onto this table (see the two `hostapi` modules
// below). macOS resolves through `dlsym(RTLD_NEXT, ...)` directly. Linux has one
// wrinkle: the shim interposes `dlsym` itself (so guest and std dynamic lookups
// get a deterministic answer instead of a host symbol), and glibc's flat
// namespace means the shim's own strong `read`/
// `write`/`sem_*` defs would satisfy any reference the shim made to those names —
// so a plain `dlsym`-based table would hit the shim's own interposer. The Linux
// primitive is instead `__real_dlsym`, the real glibc resolver reached through
// `-Wl,--wrap=dlsym`; guest
// `dlsym` binds to `__wrap_dlsym`, and `dlsym(RTLD_NEXT, "read")`
// reaches genuine glibc, skipping the shim's strong def. So `__read`/`__write`/
// `sem_*`/`pthread_create` leave the guest import table on Linux too (each
// interposed by a strong def, its real vehicle resolved through the table), and
// its `shim_control_plane` residue is the single `dlsym` primitive, as on macOS.
#[cfg(target_os = "macos")]
mod hostapi {
    use std::ffi::{CStr, c_char, c_int, c_void};
    use std::sync::OnceLock;

    // The single sanctioned host-alias resolution primitive. `dlsym` is not
    // interposed on macOS, so this reaches the real dyld resolver. This is the
    // one escape-surface symbol the shim objects legitimately name.
    unsafe extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }

    // `<dlfcn.h>`: `RTLD_NEXT == (void *)-1`. Resolve against the images that
    // follow the caller's, i.e. the real host definition even when the shim
    // interposes the public name in its own (the main executable's) image.
    const RTLD_NEXT: *mut c_void = usize::MAX as *mut c_void;

    type MachPort = u32;

    // libdispatch semaphore vehicle for the execution baton. `dispatch_semaphore_t`
    // is an opaque object pointer; `dispatch_semaphore_wait`'s timeout is a
    // `dispatch_time_t` (u64), and the baton always passes `DISPATCH_TIME_FOREVER`.
    pub type DispatchSemaphoreCreate = unsafe extern "C" fn(isize) -> *mut c_void;
    pub type DispatchSemaphoreWait = unsafe extern "C" fn(*mut c_void, u64) -> isize;
    pub type DispatchSemaphoreSignal = unsafe extern "C" fn(*mut c_void) -> isize;
    pub type DispatchRelease = unsafe extern "C" fn(*mut c_void);
    pub type StartRoutine = extern "C" fn(*mut c_void) -> *mut c_void;
    pub type PthreadCreateSuspended =
        unsafe extern "C" fn(*mut *mut c_void, *const c_void, StartRoutine, *mut c_void) -> c_int;
    pub type PthreadJoin = unsafe extern "C" fn(*mut c_void, *mut *mut c_void) -> c_int;
    pub type PthreadMachThread = unsafe extern "C" fn(*mut c_void) -> MachPort;
    pub type ThreadResume = unsafe extern "C" fn(MachPort) -> c_int;
    pub type HostRead = unsafe extern "C" fn(c_int, *mut c_void, usize) -> isize;
    pub type HostWrite = unsafe extern "C" fn(c_int, *const c_void, usize) -> isize;
    // The real libSystem `exit`, reached so the shim's public `exit` interposer
    // (which marks post-`main` teardown) can terminate the process without
    // recursing into itself. `exit` does not return.
    pub type HostExit = unsafe extern "C" fn(c_int) -> !;
    // The real `os_unfair_lock` primitive. The lock interposers forward here — run
    // the lock natively instead of routing through the scheduler — for an
    // allocator-INTERNAL `os_unfair_lock` (tikv-jemallocator's `malloc_mutex`): in
    // the bootstrap window while the allocator's own eager init runs
    // (`SHIM_BOOTSTRAP`), and reentrantly while the shim already holds a spinlock
    // (`SPIN_DEPTH`, the scheduler-path allocation re-entering the initialized
    // allocator). Both are single-owner, allocator-internal locks that must not
    // route through the deterministic model — doing so would trip the
    // non-recursive-lock guard on the allocator's init reentrancy or deadlock on the
    // held spinlock. An `os_unfair_lock` is a bare zero-initialized `u32` with no
    // init call, so forwarding needs no paired init. `trylock` returns a C `bool`.
    pub type OsUnfairLockOp = unsafe extern "C" fn(*mut c_void);
    pub type OsUnfairLockTry = unsafe extern "C" fn(*mut c_void) -> bool;
    // `<mach/mach_vm.h>`: copy between this task's own address ranges through
    // the kernel, which answers `KERN_INVALID_ADDRESS` (`uaccess` takes
    // `KERN_PROTECTION_FAILURE` too) for a range a user access could not touch
    // instead of faulting — the
    // guest-memory copy vehicle (`uaccess`). `mach_vm_write`'s count is a
    // `mach_msg_type_number_t`.
    pub type MachVmReadOverwrite = unsafe extern "C" fn(u32, u64, u64, u64, *mut u64) -> c_int;
    pub type MachVmWrite = unsafe extern "C" fn(u32, u64, usize, u32) -> c_int;

    /// Real host vehicles resolved once through `dlsym(RTLD_NEXT, ...)`. None of
    /// these names appears as an undefined external in the shim objects.
    pub struct HostApi {
        /// The execution-baton vehicle: the real libdispatch semaphore — the same
        /// primitive Rust std's Darwin `Parker` uses, which the doctrine now makes
        /// safe to share (the shim resolves the *real* libdispatch entry via
        /// `dlsym(RTLD_NEXT, ...)` while its public strong-def interposers capture
        /// guest calls). Using the canonical primitive also exercises that
        /// caller-discrimination on every context switch, so a doctrine regression
        /// deadlocks immediately instead of lying dormant.
        pub dispatch_semaphore_create: DispatchSemaphoreCreate,
        pub dispatch_semaphore_wait: DispatchSemaphoreWait,
        pub dispatch_semaphore_signal: DispatchSemaphoreSignal,
        pub dispatch_release: DispatchRelease,
        pub pthread_create_suspended_np: PthreadCreateSuspended,
        /// The real host `pthread_join`, used by `patina_thread_join` to reap
        /// the worker's host thread so its teardown makes the joiner's
        /// deterministic last reference (see `patina_thread_join`).
        pub host_pthread_join: PthreadJoin,
        pub host_abort: unsafe extern "C" fn() -> !,
        pub host_pthread_detach: unsafe extern "C" fn(*mut c_void) -> c_int,
        pub pthread_mach_thread_np: PthreadMachThread,
        pub thread_resume: ThreadResume,
        /// The non-cancel-point host `read`/`write` for the trace control plane
        /// and captured-stdio flush; resolving `read$NOCANCEL`/`write$NOCANCEL`
        /// reaches libSystem's real descriptor I/O (never the interposed `read`/
        /// `write`), so trace finalization can never recurse into the FS.
        pub host_read: HostRead,
        pub host_write: HostWrite,
        /// The real libSystem `exit`, called by the `exit` interposer after it
        /// marks post-`main` teardown; resolving it here keeps the interposer from
        /// naming (and recursing into) the public `exit` it defines.
        pub host_exit: HostExit,
        /// The real `os_unfair_lock` primitive, used to run an allocator's
        /// pre-activation init locks natively. See [`OsUnfairLockOp`].
        pub host_os_unfair_lock_lock: OsUnfairLockOp,
        pub host_os_unfair_lock_trylock: OsUnfairLockTry,
        pub host_os_unfair_lock_unlock: OsUnfairLockOp,
        /// This task's own port (`mach_task_self()`, the `mach_task_self_`
        /// variable) and the kernel copies `uaccess` makes against it.
        pub task_self: MachPort,
        pub mach_vm_read_overwrite: MachVmReadOverwrite,
        pub mach_vm_write: MachVmWrite,
    }

    // SAFETY: the fields are all function pointers into libSystem/libdispatch;
    // sharing them across threads is sound.
    unsafe impl Send for HostApi {}
    // SAFETY: as above.
    unsafe impl Sync for HostApi {}

    fn resolve(name: &CStr) -> *mut c_void {
        // SAFETY: `dlsym` with a valid NUL-terminated symbol name and the
        // `RTLD_NEXT` pseudo-handle.
        let ptr = unsafe { dlsym(RTLD_NEXT, name.as_ptr()) };
        if ptr.is_null() {
            // A core libSystem symbol failed to resolve: the process image is
            // unusable, so fail closed rather than continue with a null vehicle.
            eprintln!(
                "patina native shim fatal: could not resolve host symbol {name:?} via dlsym(RTLD_NEXT)"
            );
            unsafe {
                let abort = dlsym(RTLD_NEXT, c"abort".as_ptr());
                if !abort.is_null() {
                    std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> !>(abort)();
                }
                let exit = dlsym(RTLD_NEXT, c"_exit".as_ptr());
                std::mem::transmute::<*mut c_void, unsafe extern "C" fn(i32) -> !>(exit)(127);
            }
        }
        ptr
    }

    fn build() -> HostApi {
        // SAFETY: each resolved pointer is transmuted to the real C ABI
        // signature of the libSystem/libdispatch symbol it names. Resolving the
        // `dispatch_semaphore_*` names through `RTLD_NEXT` reaches libdispatch's
        // real implementation, not the shim's own strong-def interposers (which
        // route guest calls through the scheduler), so the baton never recurses.
        unsafe {
            HostApi {
                dispatch_semaphore_create: std::mem::transmute::<
                    *mut c_void,
                    DispatchSemaphoreCreate,
                >(resolve(c"dispatch_semaphore_create")),
                dispatch_semaphore_wait: std::mem::transmute::<*mut c_void, DispatchSemaphoreWait>(
                    resolve(c"dispatch_semaphore_wait"),
                ),
                dispatch_semaphore_signal: std::mem::transmute::<
                    *mut c_void,
                    DispatchSemaphoreSignal,
                >(resolve(c"dispatch_semaphore_signal")),
                dispatch_release: std::mem::transmute::<*mut c_void, DispatchRelease>(resolve(
                    c"dispatch_release",
                )),
                pthread_create_suspended_np: std::mem::transmute::<
                    *mut c_void,
                    PthreadCreateSuspended,
                >(resolve(
                    c"pthread_create_suspended_np",
                )),
                host_abort: std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> !>(
                    resolve(c"abort"),
                ),
                host_pthread_detach: std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn(*mut c_void) -> c_int,
                >(resolve(c"pthread_detach")),
                host_pthread_join: std::mem::transmute::<*mut c_void, PthreadJoin>(resolve(
                    c"pthread_join",
                )),
                pthread_mach_thread_np: std::mem::transmute::<*mut c_void, PthreadMachThread>(
                    resolve(c"pthread_mach_thread_np"),
                ),
                thread_resume: std::mem::transmute::<*mut c_void, ThreadResume>(resolve(
                    c"thread_resume",
                )),
                host_read: std::mem::transmute::<*mut c_void, HostRead>(resolve(c"read$NOCANCEL")),
                host_write: std::mem::transmute::<*mut c_void, HostWrite>(resolve(
                    c"write$NOCANCEL",
                )),
                host_exit: std::mem::transmute::<*mut c_void, HostExit>(resolve(c"exit")),
                host_os_unfair_lock_lock: std::mem::transmute::<*mut c_void, OsUnfairLockOp>(
                    resolve(c"os_unfair_lock_lock"),
                ),
                host_os_unfair_lock_trylock: std::mem::transmute::<*mut c_void, OsUnfairLockTry>(
                    resolve(c"os_unfair_lock_trylock"),
                ),
                host_os_unfair_lock_unlock: std::mem::transmute::<*mut c_void, OsUnfairLockOp>(
                    resolve(c"os_unfair_lock_unlock"),
                ),
                task_self: *resolve(c"mach_task_self_").cast::<MachPort>(),
                mach_vm_read_overwrite: std::mem::transmute::<*mut c_void, MachVmReadOverwrite>(
                    resolve(c"mach_vm_read_overwrite"),
                ),
                mach_vm_write: std::mem::transmute::<*mut c_void, MachVmWrite>(resolve(
                    c"mach_vm_write",
                )),
            }
        }
    }

    /// The process-wide host-alias table, resolved on first use. Every entry
    /// point that reaches it (the baton, thread creation, trace-fd I/O) runs
    /// well after the loader has mapped libSystem, so lazy resolution is safe;
    /// the `OnceLock` makes the one-time resolution race-free.
    pub fn get() -> &'static HostApi {
        static API: OnceLock<HostApi> = OnceLock::new();
        API.get_or_init(build)
    }
}

// Linux half of the host-alias doctrine. glibc's flat namespace means the shim's
// own strong `read`/`write`/`sem_*` definitions would satisfy any reference the
// shim made to those names, and the shim also interposes `dlsym` itself (so
// dynamic lookup answers deterministically instead of returning host symbols) —
// so neither a named import nor a plain
// `dlsym` can reach the real host vehicles. The resolution primitive is instead
// `__real_dlsym`, the real glibc resolver reached through `-Wl,--wrap=dlsym`
// (added by `cargo patina native-build`).
// `dlsym(RTLD_NEXT, "read")` then returns glibc's `read`, not the shim's strong
// def (RTLD_NEXT searches images *after* the main executable), so the trace-fd
// I/O, the baton semaphore, and the managed host-thread creator (`pthread_create`)
// reach the genuine host functions while their public names never appear as
// undefined externals in the shim objects. The one escape-surface residue is
// `dlsym`, matching macOS: `read`/`write`/`sem_*`/`pthread_create` all leave the
// guest import table because the shim interposes them with strong defs and
// reaches the real host vehicles through the single `RTLD_NEXT` resolution.
#[cfg(target_os = "linux")]
mod hostapi {
    use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
    use std::sync::OnceLock;

    // The real glibc resolver, reached through the `-Wl,--wrap=dlsym` alias
    // `__real_dlsym`. Guest and std `dlsym` references bind to the shim's
    // `__wrap_dlsym` (c/posix/dlsym.c), which answers only from its routing
    // table of shim definitions; only this shim-internal path
    // reaches the real resolver. Any consumer of the shim staticlib that drives a
    // host vehicle (managed threads / trace-fd I/O / baton) must link
    // `-Wl,--wrap=dlsym`, the single wrap the shim needs (thread creation is a
    // strong-def interposer whose real vehicle this same table resolves, so it
    // needs no wrap of its own); `cargo patina native-build` always links it, and
    // the direct-`cc` native_abi probes pass it explicitly.
    unsafe extern "C" {
        fn __real_dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }
    // Weak in the staticlib, where only the wrap resolves it. The unit-test
    // binary defines it strongly (thread/signals/tests.rs), and a weak
    // directive in the same object as that definition is an assembler error.
    #[cfg(not(test))]
    core::arch::global_asm!(".weak __real_dlsym");

    // `__real_dlsym`'s address as data: 0 when the weak reference went
    // unresolved (a link without `-Wl,--wrap=dlsym`, the prefixed C ABI
    // alone). A data word, because the compiler takes a function's address
    // as never null.
    core::arch::global_asm!(
        ".pushsection .data.rel.ro.patina_real_dlsym,\"aw\"",
        ".balign 8",
        ".globl patina_real_dlsym_address",
        ".hidden patina_real_dlsym_address",
        "patina_real_dlsym_address:",
        ".quad __real_dlsym",
        ".popsection",
    );
    unsafe extern "C" {
        static patina_real_dlsym_address: usize;
    }

    /// Whether the host-alias table can be had: the link supplied
    /// `__real_dlsym` (`-Wl,--wrap=dlsym`). An embedding that links the
    /// prefixed C ABI alone has no host vehicle to reach.
    pub fn available() -> bool {
        // SAFETY: a plain data word the link filled in.
        unsafe { std::ptr::read_volatile(&raw const patina_real_dlsym_address) != 0 }
    }

    // `<dlfcn.h>`: `RTLD_NEXT == (void *)-1`. Resolve against the images that
    // follow the main executable, i.e. the real glibc definition even for a name
    // the shim itself defines as a strong symbol (`read`/`write`/`sem_*`).
    // Verified empirically on glibc 2.39/aarch64: from the main executable image,
    // `dlsym(RTLD_NEXT, "read")` returns glibc's `read`, not the shim's strong def.
    const RTLD_NEXT: *mut c_void = usize::MAX as *mut c_void;

    pub type HostRead = unsafe extern "C" fn(c_int, *mut c_void, usize) -> isize;
    pub type HostWrite = unsafe extern "C" fn(c_int, *const c_void, usize) -> isize;
    // The real glibc `exit`, reached so the shim's public `exit` interposer (which
    // marks post-`main` teardown) can terminate without recursing into itself.
    pub type HostExit = unsafe extern "C" fn(c_int) -> !;
    pub type SemInit = unsafe extern "C" fn(*mut c_void, c_int, c_uint) -> c_int;
    pub type SemOp = unsafe extern "C" fn(*mut c_void) -> c_int;
    pub type StartRoutine = extern "C" fn(*mut c_void) -> *mut c_void;
    pub type HostPthreadCreate =
        unsafe extern "C" fn(*mut *mut c_void, *const c_void, StartRoutine, *mut c_void) -> c_int;
    // The real glibc `pthread_join`, used to reap a completed worker's host thread
    // at the managed-join point so the worker's std `Arc<thread::Inner>` reference
    // is dropped BEFORE the joiner returns — making the joiner's own drop the
    // deterministic last reference (see `patina_thread_join`).
    pub type HostPthreadJoin = unsafe extern "C" fn(*mut c_void, *mut *mut c_void) -> c_int;
    // The real glibc `syscall(2)` wrapper, the pass-through vehicle for the SUD
    // dispatcher's process-local memory rows (mmap-anon/munmap/mprotect/…). Its
    // kernel entry sits in glibc text — the SUD-allowed region — so a syscall it
    // issues never re-traps. Declared with the six integer argument registers the
    // Linux syscall ABI uses; the glibc entry is variadic but every argument is an
    // integer passed in registers, so a fixed-arity call is ABI-compatible.
    pub type HostThreadAtexit =
        unsafe extern "C" fn(unsafe extern "C" fn(*mut c_void), *mut c_void, *mut c_void) -> c_int;
    pub type HostSyscall =
        unsafe extern "C" fn(c_long, c_long, c_long, c_long, c_long, c_long, c_long) -> c_long;

    /// Real host vehicles resolved once through `__real_dlsym(RTLD_NEXT, ...)`.
    /// None of these names appears as an undefined external in the shim objects.
    pub struct HostApi {
        /// The non-cancel-point-free host `read`/`write` for the trace control
        /// plane and captured-stdio flush; resolving them through `RTLD_NEXT`
        /// reaches glibc's descriptor I/O, never the shim's interposed `read`/
        /// `write`, so trace finalization can never recurse into the FS.
        pub host_read: HostRead,
        pub host_write: HostWrite,
        /// The real glibc `exit`, called by the `exit` interposer after it marks
        /// post-`main` teardown; resolving it here keeps the interposer from
        /// naming (and recursing into) the public `exit` it defines.
        pub host_exit: HostExit,
        pub host_abort: unsafe extern "C" fn() -> !,
        pub host_pthread_self: unsafe extern "C" fn() -> usize,
        /// The execution-baton POSIX semaphore vehicle.
        pub sem_init: SemInit,
        pub sem_wait: SemOp,
        pub sem_post: SemOp,
        /// The managed host-thread creation vehicle: the real glibc
        /// `pthread_create`. The shim interposes `pthread_create` with a strong
        /// def (patina_posix.c) that routes guest/std threads through the
        /// scheduler; resolving the genuine creator through `RTLD_NEXT` lets the
        /// shim spawn a real OS thread without recursing into its own interposer,
        /// and — like `read`/`write`/`sem_*` — keeps `pthread_create` off the
        /// guest import table entirely (no `--wrap`, no named residue).
        pub host_pthread_create: HostPthreadCreate,
        /// The real glibc `pthread_join` for reaping completed worker host
        /// threads deterministically at the managed-join point.
        pub host_pthread_join: HostPthreadJoin,
        pub host_pthread_detach: unsafe extern "C" fn(*mut c_void) -> c_int,
        /// The real glibc `syscall(2)` wrapper, the SUD dispatcher's pass-through
        /// vehicle for process-local memory-management rows.
        pub host_syscall: HostSyscall,
        /// glibc's `__cxa_thread_atexit_impl`: a managed thread's completion
        /// is its first-registered thread-local destructor, so it runs after
        /// every destructor the guest registers, where the kernel's exit
        /// (robust-list walk, clear-child-tid) follows them.
        pub host_cxa_thread_atexit_impl: HostThreadAtexit,
    }

    // SAFETY: the fields are function pointers into glibc; sharing them across
    // threads is sound.
    unsafe impl Send for HostApi {}
    // SAFETY: as above.
    unsafe impl Sync for HostApi {}

    fn resolve(name: &CStr) -> *mut c_void {
        // SAFETY: `__real_dlsym` (the wrap-provided real glibc `dlsym`) with a
        // valid NUL-terminated name and the `RTLD_NEXT` pseudo-handle.
        let ptr = unsafe { __real_dlsym(RTLD_NEXT, name.as_ptr()) };
        if ptr.is_null() {
            // A core glibc symbol failed to resolve: the process image is
            // unusable, so fail closed rather than continue with a null vehicle.
            eprintln!(
                "patina native shim fatal: could not resolve host symbol {name:?} via dlsym(RTLD_NEXT)"
            );
            // Resolve directly: the alias table is still being initialized.
            unsafe {
                let abort = __real_dlsym(RTLD_NEXT, c"abort".as_ptr());
                if !abort.is_null() {
                    std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> !>(abort)();
                }
                // A libc without abort is unusable; do not enter the public interposer.
                let exit = __real_dlsym(RTLD_NEXT, c"_exit".as_ptr());
                std::mem::transmute::<*mut c_void, unsafe extern "C" fn(i32) -> !>(exit)(127);
            }
        }
        ptr
    }

    /// A host symbol by name, from the images after the main executable (the
    /// loader's and glibc's data symbols too), or null where none defines it.
    pub fn symbol(name: &CStr) -> *mut c_void {
        // SAFETY: as in `resolve`.
        unsafe { __real_dlsym(RTLD_NEXT, name.as_ptr()) }
    }

    fn build() -> HostApi {
        // SAFETY: each resolved pointer is transmuted to the real C ABI signature
        // of the glibc symbol it names.
        unsafe {
            HostApi {
                host_read: std::mem::transmute::<*mut c_void, HostRead>(resolve(c"read")),
                host_write: std::mem::transmute::<*mut c_void, HostWrite>(resolve(c"write")),
                host_exit: std::mem::transmute::<*mut c_void, HostExit>(resolve(c"exit")),
                host_abort: std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> !>(
                    resolve(c"abort"),
                ),
                host_pthread_self: std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn() -> usize,
                >(resolve(c"pthread_self")),
                sem_init: std::mem::transmute::<*mut c_void, SemInit>(resolve(c"sem_init")),
                sem_wait: std::mem::transmute::<*mut c_void, SemOp>(resolve(c"sem_wait")),
                sem_post: std::mem::transmute::<*mut c_void, SemOp>(resolve(c"sem_post")),
                host_pthread_create: std::mem::transmute::<*mut c_void, HostPthreadCreate>(
                    resolve(c"pthread_create"),
                ),
                host_pthread_detach: std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn(*mut c_void) -> c_int,
                >(resolve(c"pthread_detach")),
                host_pthread_join: std::mem::transmute::<*mut c_void, HostPthreadJoin>(resolve(
                    c"pthread_join",
                )),
                host_syscall: std::mem::transmute::<*mut c_void, HostSyscall>(resolve(c"syscall")),
                host_cxa_thread_atexit_impl: std::mem::transmute::<*mut c_void, HostThreadAtexit>(
                    resolve(c"__cxa_thread_atexit_impl"),
                ),
            }
        }
    }

    /// The process-wide host-alias table, resolved on first use. Every entry
    /// point that reaches it (the baton, host-thread creation, trace-fd I/O) runs
    /// well after the loader has mapped glibc, so lazy resolution is safe; the
    /// `OnceLock` makes the one-time resolution race-free.
    pub fn get() -> &'static HostApi {
        static API: OnceLock<HostApi> = OnceLock::new();
        API.get_or_init(build)
    }
}

// Host-libc-backed containers for the shim's interposer-reachable synchronization
// tables. These MUST NOT allocate through the guest's global allocator: the
// lock/sync interposers (`os_unfair_lock`/`pthread_mutex`/`cond`/`rwlock`) register
// each lock lazily on first touch WHILE HOLDING the shim spinlock, and a custom
// `#[global_allocator]` (e.g. tikv-jemallocator) whose OWN initialization takes an
// interposed lock would re-enter the guest allocator from inside that
// registration and deadlock/double-init before `main` (the tikv-jemallocator
// blocker: `malloc_init_hard` -> `os_unfair_lock` -> shim interposer ->
// `entry().or_default()` -> guest `__rust_alloc` -> `malloc_init_hard` again).
// Backing them with the real libc `malloc`/`free`/`realloc` keeps them entirely
// off the guest allocator: a Rust `#[global_allocator]` replaces `__rust_alloc`,
// never the C `malloc` symbol, so these bind to libSystem/glibc's allocator, whose
// internal locks are bound inside libc and are not interposed — exactly why the
// DEFAULT-allocator shim never deadlocked here. The allocator is bound DIRECTLY as
// an `extern "C"` symbol (below), NOT resolved through the host-alias `dlsym`
// table: that table's Linux resolver reaches the real glibc `dlsym` through
// `__real_dlsym` (the `-Wl,--wrap=dlsym` alias), which only a `cargo patina build`
// binary links — the plain Rust lib-test binary links neither `patina_posix.c` nor
// the wrap, so `__real_dlsym` is an UNRESOLVED WEAK NULL and calling it SIGSEGVs.
// A direct `extern "C"` reference makes `hostcoll` self-sufficient in ANY link
// context (interposing guest, default guest, unit-test lib) with no `cfg(test)`
// divergence. Minimal by design (unsorted linear probing over a host-`realloc`'d
// array; the number of live locks is tiny) and never touched by the fingerprint
// (map order is never iterated). No `allocator_api` (stable-only).
mod hostcoll {
    use std::ffi::c_void;
    use std::marker::PhantomData;
    use std::mem;
    use std::ptr;
    use std::slice;

    // The real host libc allocator. A Rust `#[global_allocator]` (jemalloc) only
    // replaces `__rust_alloc`, so the C `malloc`/`free`/`realloc` symbols still
    // resolve to libSystem/glibc in every link context — including the lib-test
    // binary, where they are the ordinary (non-interposed) host allocator.
    unsafe extern "C" {
        fn malloc(size: usize) -> *mut c_void;
        fn free(ptr: *mut c_void);
        fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
    }

    unsafe fn host_grow(ptr: *mut u8, size: usize) -> *mut u8 {
        // SAFETY: `ptr` is either null (fresh allocation via `malloc`) or a live
        // host block from this module (grown via `realloc`); `size` is a valid
        // nonzero byte count.
        let grown = unsafe {
            if ptr.is_null() {
                malloc(size)
            } else {
                realloc(ptr.cast(), size)
            }
        };
        assert!(
            !grown.is_null(),
            "patina shim: host allocation failed for an interposer table"
        );
        grown.cast()
    }

    unsafe fn host_free(ptr: *mut u8) {
        if !ptr.is_null() {
            // SAFETY: `ptr` is a live host-`malloc` block from this module.
            unsafe { free(ptr.cast::<c_void>()) };
        }
    }

    /// A growable array whose storage is the real libc allocator, never the guest
    /// global allocator. Elements are dropped in place on removal and on `Drop`.
    pub struct HostVec<T> {
        ptr: *mut T,
        len: usize,
        cap: usize,
        _marker: PhantomData<T>,
    }

    // SAFETY: the raw pointer uniquely OWNS a host-`malloc` block; there is no
    // aliasing. A `HostVec` (and the `HostMap`/`HostDeque` built on it) only ever
    // lives inside a `SpinMutex`-guarded `ThreadRuntime`, so all access is
    // serialized — mirroring `SpinMutex`'s own `Send`/`Sync` reasoning. Sending or
    // sharing is therefore sound whenever the elements are.
    unsafe impl<T: Send> Send for HostVec<T> {}
    // SAFETY: as above; access is always exclusive under the shim spinlock.
    unsafe impl<T: Send> Sync for HostVec<T> {}

    impl<T> HostVec<T> {
        pub const fn new() -> Self {
            Self {
                ptr: ptr::null_mut(),
                len: 0,
                cap: 0,
                _marker: PhantomData,
            }
        }

        fn grow(&mut self) {
            let new_cap = if self.cap == 0 { 4 } else { self.cap * 2 };
            let bytes = new_cap
                .checked_mul(mem::size_of::<T>())
                .expect("patina shim: HostVec capacity overflow");
            // SAFETY: growing our own (possibly null) host block to `bytes`.
            let new_ptr = unsafe { host_grow(self.ptr.cast::<u8>(), bytes) };
            self.ptr = new_ptr.cast::<T>();
            self.cap = new_cap;
        }

        pub fn push(&mut self, value: T) {
            if self.len == self.cap {
                self.grow();
            }
            // SAFETY: `self.len < self.cap` after `grow`, so the slot is in bounds.
            unsafe { ptr::write(self.ptr.add(self.len), value) };
            self.len += 1;
        }

        pub fn len(&self) -> usize {
            self.len
        }

        pub fn is_empty(&self) -> bool {
            self.len == 0
        }

        pub fn get(&self, index: usize) -> &T {
            debug_assert!(index < self.len);
            // SAFETY: index is in bounds per the caller's contract / debug assert.
            unsafe { &*self.ptr.add(index) }
        }

        pub fn get_mut(&mut self, index: usize) -> &mut T {
            debug_assert!(index < self.len);
            // SAFETY: as above; `&mut self` guarantees exclusive access.
            unsafe { &mut *self.ptr.add(index) }
        }

        pub fn as_slice(&self) -> &[T] {
            if self.ptr.is_null() {
                &[]
            } else {
                // SAFETY: `ptr..ptr+len` is an initialized, live run of `T`.
                unsafe { slice::from_raw_parts(self.ptr, self.len) }
            }
        }

        #[cfg(target_os = "macos")]
        pub fn as_mut_slice(&mut self) -> &mut [T] {
            if self.ptr.is_null() {
                &mut []
            } else {
                // SAFETY: as above; `&mut self` guarantees exclusive access.
                unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
            }
        }

        /// Remove the element at `index`, moving the last element into its place
        /// (order not preserved). Used where iteration order is irrelevant.
        pub fn swap_remove(&mut self, index: usize) -> T {
            debug_assert!(index < self.len);
            let last = self.len - 1;
            // SAFETY: both indices are in bounds; `read` moves the value out and
            // the length shrinks so no slot is double-owned.
            unsafe {
                let removed = ptr::read(self.ptr.add(index));
                if index != last {
                    let tail = ptr::read(self.ptr.add(last));
                    ptr::write(self.ptr.add(index), tail);
                }
                self.len = last;
                removed
            }
        }

        /// Remove the element at `index`, shifting the tail down (order
        /// preserved). Used by the FIFO waiter queues, whose order is
        /// determinism-relevant.
        pub fn remove(&mut self, index: usize) -> T {
            debug_assert!(index < self.len);
            // SAFETY: `index` in bounds; the tail shift keeps every live slot
            // initialized and the length shrinks by one.
            unsafe {
                let removed = ptr::read(self.ptr.add(index));
                let tail = self.len - index - 1;
                if tail > 0 {
                    ptr::copy(self.ptr.add(index + 1), self.ptr.add(index), tail);
                }
                self.len -= 1;
                removed
            }
        }
    }

    impl<T> Drop for HostVec<T> {
        fn drop(&mut self) {
            // SAFETY: drop the live prefix in place, then free the host block.
            unsafe {
                for index in 0..self.len {
                    ptr::drop_in_place(self.ptr.add(index));
                }
                host_free(self.ptr.cast::<u8>());
            }
        }
    }

    impl<T> Default for HostVec<T> {
        fn default() -> Self {
            Self::new()
        }
    }

    /// A FIFO queue over [`HostVec`] (push at the back, pop from the front). Order
    /// is preserved because waiter wake order is a determinism input.
    pub struct HostDeque<T> {
        inner: HostVec<T>,
    }

    impl<T> HostDeque<T> {
        pub const fn new() -> Self {
            Self {
                inner: HostVec::new(),
            }
        }

        pub fn push_back(&mut self, value: T) {
            self.inner.push(value);
        }

        pub fn pop_front(&mut self) -> Option<T> {
            if self.inner.is_empty() {
                None
            } else {
                Some(self.inner.remove(0))
            }
        }

        /// Remove the element at `index`, preserving FIFO order of the rest.
        pub fn remove(&mut self, index: usize) -> T {
            self.inner.remove(index)
        }

        pub fn iter(&self) -> slice::Iter<'_, T> {
            self.inner.as_slice().iter()
        }

        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        pub fn len(&self) -> usize {
            self.inner.len()
        }
    }

    impl<T> Default for HostDeque<T> {
        fn default() -> Self {
            Self::new()
        }
    }

    /// A tiny map over [`HostVec`] of `(key, value)` pairs with linear lookup. The
    /// synchronization tables are keyed by a lock/task address and never iterated
    /// in order, so linear probing over host storage is both sufficient and
    /// order-independent (no fingerprint impact).
    pub struct HostMap<K, V> {
        entries: HostVec<(K, V)>,
    }

    impl<K: Copy + PartialEq, V> HostMap<K, V> {
        pub const fn new() -> Self {
            Self {
                entries: HostVec::new(),
            }
        }

        fn index_of(&self, key: &K) -> Option<usize> {
            (0..self.entries.len()).find(|&index| self.entries.get(index).0 == *key)
        }

        pub fn get(&self, key: &K) -> Option<&V> {
            self.index_of(key).map(|index| &self.entries.get(index).1)
        }

        pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
            match self.index_of(key) {
                Some(index) => Some(&mut self.entries.get_mut(index).1),
                None => None,
            }
        }

        pub fn insert(&mut self, key: K, value: V) {
            match self.index_of(&key) {
                // Assignment drops the previous value (freeing its host storage).
                Some(index) => self.entries.get_mut(index).1 = value,
                None => self.entries.push((key, value)),
            }
        }

        pub fn remove(&mut self, key: &K) -> Option<V> {
            self.index_of(key)
                .map(|index| self.entries.swap_remove(index).1)
        }

        #[cfg(all(test, target_os = "linux"))]
        pub fn values(&self) -> impl Iterator<Item = &V> {
            self.entries.as_slice().iter().map(|(_, value)| value)
        }

        #[cfg(target_os = "macos")]
        pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
            self.entries
                .as_mut_slice()
                .iter_mut()
                .map(|(_, value)| value)
        }
    }

    impl<K: Copy + PartialEq, V> HostMap<K, V> {
        /// Return a mutable reference to the value for `key`, inserting
        /// `make()` first if absent.
        pub fn entry_or_insert_with(&mut self, key: K, make: impl FnOnce() -> V) -> &mut V {
            let index = match self.index_of(&key) {
                Some(index) => index,
                None => {
                    self.entries.push((key, make()));
                    self.entries.len() - 1
                }
            };
            &mut self.entries.get_mut(index).1
        }
    }

    impl<K: Copy + PartialEq, V: Default> HostMap<K, V> {
        /// Return a mutable reference to the value for `key`, inserting a default
        /// value first if absent — the [`std::collections::btree_map::Entry`]
        /// `or_default` the sync tables relied on.
        pub fn entry_or_default(&mut self, key: K) -> &mut V {
            self.entry_or_insert_with(key, V::default)
        }
    }

    impl<K: Copy + PartialEq, V> Default for HostMap<K, V> {
        fn default() -> Self {
            Self::new()
        }
    }

    // `BTreeMap`-style panicking key indexing, so shim unit tests that assert on a
    // table entry (`table.mutexes[&key]`) read unchanged.
    impl<K: Copy + PartialEq, V> std::ops::Index<&K> for HostMap<K, V> {
        type Output = V;
        fn index(&self, key: &K) -> &V {
            self.get(key).expect("no entry found for key")
        }
    }

    impl<K: Copy + PartialEq, V> std::ops::IndexMut<&K> for HostMap<K, V> {
        fn index_mut(&mut self, key: &K) -> &mut V {
            self.get_mut(key).expect("no entry found for key")
        }
    }
}

// Non-interposed host descriptor I/O for Patina's trace control plane and
// captured-stdio flushing. Both platforms route through the resolved host-alias
// table: macOS through `dlsym(RTLD_NEXT, "read$NOCANCEL")`, Linux through
// `__real_dlsym(RTLD_NEXT, "read")` (see the two `hostapi` modules above).
#[cfg(target_os = "macos")]
unsafe fn host_read(fd: c_int, destination: *mut c_void, length: usize) -> isize {
    // SAFETY: forwarded from the caller's contract to the resolved host `read`.
    unsafe { (hostapi::get().host_read)(fd, destination, length) }
}

#[cfg(target_os = "macos")]
unsafe fn host_write(fd: c_int, source: *const c_void, length: usize) -> isize {
    // SAFETY: forwarded from the caller's contract to the resolved host `write`.
    unsafe { (hostapi::get().host_write)(fd, source, length) }
}

#[cfg(target_os = "linux")]
unsafe fn host_read(fd: c_int, destination: *mut c_void, length: usize) -> isize {
    // SAFETY: forwarded from the caller's contract to the resolved host `read`.
    unsafe { (hostapi::get().host_read)(fd, destination, length) }
}

#[cfg(target_os = "linux")]
unsafe fn host_write(fd: c_int, source: *const c_void, length: usize) -> isize {
    // SAFETY: forwarded from the caller's contract to the resolved host `write`.
    unsafe { (hostapi::get().host_write)(fd, source, length) }
}

fn host_write_all(fd: c_int, bytes: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        // SAFETY: The pointer and length describe a live slice.
        let written = unsafe { host_write(fd, remaining.as_ptr().cast(), remaining.len()) };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "host descriptor accepted no bytes",
            ));
        }
        offset += written as usize;
    }
    Ok(())
}

/// Run-facts channel over a supervisor-provided host descriptor
/// (`PATINA_FACTS_FD`). The guest's filesystem is fully interposed, so the
/// structured facts document must leave through the private host aliases exactly
/// like the trace bundle and the coverage map do.
struct FdFactsSink {
    fd: c_int,
}

impl patina_dst_runtime::FactsSink for FdFactsSink {
    fn write_facts(&mut self, bytes: &[u8]) -> io::Result<()> {
        host_write_all(self.fd, bytes)
    }
}

/// Trace channel over a supervisor-provided host descriptor (`PATINA_TRACE_FD`).
struct FdTraceTransport {
    fd: c_int,
}

impl TraceTransport for FdTraceTransport {
    fn read_bundle(&mut self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut chunk = vec![0_u8; HOST_IO_CHUNK];
        loop {
            // SAFETY: The pointer and length describe a live buffer.
            let count = unsafe { host_read(self.fd, chunk.as_mut_ptr().cast(), chunk.len()) };
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if count == 0 {
                return Ok(bytes);
            }
            bytes.extend_from_slice(&chunk[..count as usize]);
            if bytes.len() as u64 > MAX_TRACE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "trace descriptor read is {} bytes; limit is {MAX_TRACE_BYTES}; reduce recorded event count or payload volume, or split the run",
                        bytes.len()
                    ),
                ));
            }
        }
    }

    fn write_bundle(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() as u64 > MAX_TRACE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "trace descriptor write is {} bytes; limit is {MAX_TRACE_BYTES}; reduce recorded event count or payload volume, or split the run",
                    bytes.len()
                ),
            ));
        }
        host_write_all(self.fd, bytes)
    }
}

const COVERAGE_MAGIC: &[u8; 16] = b"patina.covmap/v1";
const COVERAGE_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CoverageRange {
    start: usize,
    len: usize,
}

#[derive(Default)]
struct CoverageState {
    guard_ranges: Vec<CoverageRange>,
    pc_ranges: Vec<CoverageRange>,
}

#[derive(Debug, PartialEq, Eq)]
struct CoverageSummary {
    edges_total: u64,
    edges_covered: u64,
    covered_permille: u64,
    hits_total: u64,
    hits_max: u32,
    saturated: u64,
}

#[derive(Debug)]
struct PreparedCoverage {
    summary: CoverageSummary,
    map: Option<Vec<u8>>,
}

static COVERAGE_STATE: OnceLock<SpinMutex<CoverageState>> = OnceLock::new();

fn coverage_state() -> &'static SpinMutex<CoverageState> {
    COVERAGE_STATE.get_or_init(|| SpinMutex::new(CoverageState::default()))
}

fn coverage_len<T>(start: *const T, stop: *const T) -> usize {
    if start.is_null() || stop.is_null() {
        return 0;
    }
    let start = start as usize;
    let stop = stop as usize;
    if stop <= start {
        return 0;
    }
    (stop - start) / std::mem::size_of::<T>()
}

fn register_coverage_range(ranges: &mut Vec<CoverageRange>, start: usize, len: usize) {
    if len == 0 {
        return;
    }
    if ranges
        .iter()
        .any(|range| range.start == start && range.len == len)
    {
        return;
    }
    ranges.push(CoverageRange { start, len });
}

/// Register one SanitizerCoverage guard-counter range. Called by the C hook's
/// `__sanitizer_cov_trace_pc_guard_init` once per codegen unit. The guard words
/// are the counters themselves, so registration records only the live range.
#[unsafe(no_mangle)]
pub extern "C" fn patina_coverage_register(start: *mut u32, stop: *mut u32) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let len = coverage_len(start.cast_const(), stop.cast_const());
    let mut state = coverage_state().lock();
    register_coverage_range(&mut state.guard_ranges, start as usize, len);
}

/// Register one SanitizerCoverage pc-table range. LLVM gives a flat uintptr_t
/// array of `(pc, flags)` pairs; the coverage map persists one anchor-relative
/// pc delta per guard. The flags are intentionally not serialized in wave A's
/// `patina.covmap/v1` format (12 bytes per edge: u32 count + i64 delta).
#[unsafe(no_mangle)]
pub extern "C" fn patina_coverage_register_pcs(start: *const usize, stop: *const usize) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let words = coverage_len(start, stop);
    let entries = words / 2;
    let mut state = coverage_state().lock();
    register_coverage_range(&mut state.pc_ranges, start as usize, entries);
}

fn coverage_snapshot() -> (Vec<CoverageRange>, Vec<CoverageRange>) {
    let state = coverage_state().lock();
    (state.guard_ranges.clone(), state.pc_ranges.clone())
}

fn coverage_count(ranges: &[CoverageRange]) -> Result<usize, String> {
    ranges.iter().try_fold(0usize, |total, range| {
        total.checked_add(range.len).ok_or_else(|| {
            "registered coverage ranges exceed this platform's addressable size".to_string()
        })
    })
}

fn validate_coverage_ranges(
    guard_ranges: &[CoverageRange],
    pc_ranges: &[CoverageRange],
) -> Result<usize, String> {
    let guard_count = coverage_count(guard_ranges)?;
    let pc_count = coverage_count(pc_ranges)?;
    if guard_count != pc_count {
        return Err(format!(
            "guard/pc-table count mismatch: guards={guard_count} pcs={pc_count}"
        ));
    }
    if guard_ranges.len() != pc_ranges.len() {
        return Err(format!(
            "guard/pc-table range count mismatch: guard_ranges={} pc_ranges={} guards={} pcs={}",
            guard_ranges.len(),
            pc_ranges.len(),
            guard_count,
            pc_count,
        ));
    }
    for (index, (guards, pcs)) in guard_ranges.iter().zip(pc_ranges).enumerate() {
        if guards.len != pcs.len {
            return Err(format!(
                "guard/pc-table range {index} count mismatch: guards={} pcs={} total_guards={} total_pcs={}",
                guards.len, pcs.len, guard_count, pc_count,
            ));
        }
    }
    Ok(guard_count)
}

fn coverage_summary(guard_ranges: &[CoverageRange]) -> CoverageSummary {
    let mut edges_total = 0u64;
    let mut edges_covered = 0u64;
    let mut hits_total = 0u64;
    let mut hits_max = 0u32;
    let mut saturated = 0u64;
    for range in guard_ranges {
        // SAFETY: SanitizerCoverage guard arrays are process-lifetime static
        // storage. Registration only records the compiler-provided `[start, stop)`
        // subranges, and finalization runs after managed execution is stopped.
        let counters = unsafe { slice::from_raw_parts(range.start as *const u32, range.len) };
        edges_total += counters.len() as u64;
        for &hits in counters {
            if hits != 0 {
                edges_covered += 1;
            }
            hits_total = hits_total.saturating_add(hits as u64);
            hits_max = hits_max.max(hits);
            if hits == u32::MAX {
                saturated += 1;
            }
        }
    }
    let covered_permille = if edges_total == 0 {
        0
    } else {
        ((edges_covered as u128 * 1000) / edges_total as u128) as u64
    };
    CoverageSummary {
        edges_total,
        edges_covered,
        covered_permille,
        hits_total,
        hits_max,
        saturated,
    }
}

fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_i64_le(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn build_coverage_map(
    guard_ranges: &[CoverageRange],
    pc_ranges: &[CoverageRange],
) -> Result<Vec<u8>, String> {
    let guard_count = validate_coverage_ranges(guard_ranges, pc_ranges)?;
    let range_count = guard_ranges.len();
    let mut bytes = Vec::with_capacity(
        COVERAGE_MAGIC.len()
            + 4
            + 8
            + 8
            + range_count.saturating_mul(32)
            + guard_count.saturating_mul(12),
    );
    bytes.extend_from_slice(COVERAGE_MAGIC);
    push_u32_le(&mut bytes, COVERAGE_VERSION);
    push_u64_le(&mut bytes, guard_count as u64);
    push_u64_le(&mut bytes, range_count as u64);

    let mut guard_offset = 0u64;
    let mut pc_offset = 0u64;
    for (guards, pcs) in guard_ranges.iter().zip(pc_ranges) {
        push_u64_le(&mut bytes, guard_offset);
        push_u64_le(&mut bytes, guards.len as u64);
        push_u64_le(&mut bytes, pc_offset);
        push_u64_le(&mut bytes, pcs.len as u64);
        guard_offset += guards.len as u64;
        pc_offset += pcs.len as u64;
    }

    let mut counters_flat = Vec::with_capacity(guard_count);
    for range in guard_ranges {
        // SAFETY: see `coverage_summary`.
        let counters = unsafe { slice::from_raw_parts(range.start as *const u32, range.len) };
        for &counter in counters {
            counters_flat.push(counter);
            push_u32_le(&mut bytes, counter);
        }
    }

    let anchor = patina_yield_point as *const () as i128;
    let mut guard_index = 0usize;
    for range in pc_ranges {
        // SAFETY: pc-table arrays are process-lifetime static storage. `len` is
        // the number of `(pc, flags)` pairs, so the raw word slice is `len * 2`.
        let words = unsafe { slice::from_raw_parts(range.start as *const usize, range.len * 2) };
        for pair in words.chunks_exact(2) {
            let raw_pc = pair[0];
            let delta = if raw_pc <= 1 {
                // On current Darwin/LLVM builds a handful of unexecuted guard
                // slots can carry a null/function-entry sentinel (`0`/`1`) in
                // the pc-table rather than a load-addressed code pointer. The
                // literal sentinel is already stable; subtracting the ASLR-slid
                // anchor would manufacture nondeterministic bytes. Keep unhit
                // sentinels as the stable zero delta, but fail closed if such a
                // guard ever reports coverage — a covered edge without a real PC
                // cannot be symbolized honestly.
                if counters_flat[guard_index] != 0 {
                    return Err(format!(
                        "coverage pc-table entry {guard_index} has sentinel pc={raw_pc} for a covered guard"
                    ));
                }
                0
            } else {
                let pc = raw_pc as i128;
                let delta = pc - anchor;
                i64::try_from(delta).map_err(|_| {
                    format!(
                        "coverage pc delta {delta} does not fit in patina.covmap/v1 i64 encoding"
                    )
                })?
            };
            push_i64_le(&mut bytes, delta);
            guard_index += 1;
        }
    }
    Ok(bytes)
}

fn control_coverage_fd() -> Result<Option<c_int>, RuntimeError> {
    control_env(patina_dst_runtime::ENV_COVERAGE_FD)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{} must be a non-negative descriptor number",
                    patina_dst_runtime::ENV_COVERAGE_FD
                ))
            })
        })
        .transpose()
}

/// The run's end-of-run report-suppression preferences, parsed ONCE from the
/// constructor's pre-scrub control-plane snapshot and cached.
///
/// Cached because both consumers need the same answer at different times: the
/// runtime config takes it at install, and coverage finalization takes it at
/// shutdown — after the context has left the slot, where a `std::env` read would
/// route through the interposed `getenv` and come back empty. The control plane
/// is the only view of the operator's environment that outlives the scrub, so it
/// is the only one either consumer may use.
fn control_reports() -> patina_dst_runtime::ReportConfig {
    *REPORTS.get_or_init(|| patina_dst_runtime::ReportConfig::default().applied(control_env))
}

static REPORTS: OnceLock<patina_dst_runtime::ReportConfig> = OnceLock::new();

fn prepare_coverage_output(
    requested: bool,
    guard_ranges: &[CoverageRange],
    pc_ranges: &[CoverageRange],
) -> Result<Option<PreparedCoverage>, String> {
    let guard_count = coverage_count(guard_ranges)?;
    if requested && guard_count == 0 {
        return Err(
            "requested coverage is unavailable: the binary registered zero SanitizerCoverage guard ranges; rebuild with `cargo patina build --yield-points`"
                .to_string(),
        );
    }
    if guard_count == 0 {
        return Ok(None);
    }
    // Validate before reading counters or emitting a report so the fail-closed
    // guard/pc-table invariant always wins over any derived observation.
    validate_coverage_ranges(guard_ranges, pc_ranges)?;
    let summary = coverage_summary(guard_ranges);
    if requested && summary.edges_covered == 0 {
        return Err(format!(
            "requested coverage is empty: edges_total={} edges_covered=0; the yield-point hook did not count any executed guard",
            summary.edges_total,
        ));
    }
    let map = requested
        .then(|| build_coverage_map(guard_ranges, pc_ranges))
        .transpose()?;
    Ok(Some(PreparedCoverage { summary, map }))
}

fn finalize_coverage() -> Result<(), String> {
    let coverage_fd = control_coverage_fd().map_err(|error| error.to_string())?;
    let requested = coverage_fd.is_some();
    let (guard_ranges, pc_ranges) = coverage_snapshot();
    let Some(prepared) = prepare_coverage_output(requested, &guard_ranges, &pc_ranges)? else {
        return Ok(());
    };
    if control_reports().enabled(patina_dst_runtime::Report::Coverage) {
        capture_stderr_line(&format!(
            "PATINA_COVERAGE_REPORT edges_total={} edges_covered={} covered_permille={} hits_total={} hits_max={} saturated={}",
            prepared.summary.edges_total,
            prepared.summary.edges_covered,
            prepared.summary.covered_permille,
            prepared.summary.hits_total,
            prepared.summary.hits_max,
            prepared.summary.saturated,
        ));
    }
    if let (Some(fd), Some(map)) = (coverage_fd, prepared.map) {
        host_write_all(fd, &map).map_err(|error| {
            format!(
                "failed to write {} coverage map to descriptor {fd}: {error}",
                patina_dst_runtime::ENV_COVERAGE_FD,
            )
        })?;
    }
    Ok(())
}

thread_local! {
    static LAST_ERRNO: Cell<c_int> = const { Cell::new(0) };
}

fn slot() -> &'static SpinMutex<Option<Context>> {
    CONTEXT.get_or_init(|| SpinMutex::new(None))
}

static CONTROL_PLANE: OnceLock<SpinMutex<BTreeMap<String, String>>> = OnceLock::new();

fn control_plane() -> &'static SpinMutex<BTreeMap<String, String>> {
    CONTROL_PLANE.get_or_init(|| SpinMutex::new(BTreeMap::new()))
}

/// The runtime's own diagnostic from the most recent failed `init_from_env`,
/// captured so the fail-closed abort path can surface *why* initialization
/// failed (fingerprint mismatch, bad `--mount` corpus, replay-fault conflict, …)
/// instead of the generic "no runtime installed" line. `install` collapses the
/// [`RuntimeError`] to an errno, discarding the message; this preserves it.
static INIT_ERROR: OnceLock<SpinMutex<Option<String>>> = OnceLock::new();

fn init_error() -> &'static SpinMutex<Option<String>> {
    INIT_ERROR.get_or_init(|| SpinMutex::new(None))
}

/// Lock-free mirror of "[`INIT_ERROR`] holds a message", for the readers that
/// must decide without taking a lock or allocating — chiefly
/// [`in_shim_bootstrap`], which runs on the allocator's own init path and is hit
/// by every clock read of a healthy run.
static INIT_FAILED: AtomicBool = AtomicBool::new(false);

/// Set once [`abort_if_init_failed`] has begun writing the diagnostic, so a
/// re-entrant call from inside that write cannot take [`INIT_ERROR`] twice. The
/// write flushes captured stdio, whose buffers deallocate through the guest
/// global allocator; with a custom allocator (jemalloc) that deallocation takes
/// an interposed lock, which re-enters [`in_shim_bootstrap`] while this thread
/// already holds the non-recursive spinlock.
static INIT_ERROR_ABORTING: AtomicBool = AtomicBool::new(false);

/// Record the runtime's own init-failure diagnostic. The single writer of
/// [`INIT_ERROR`], so [`INIT_FAILED`] can never drift from it; the flag is
/// published after the message, so a reader that sees the flag sees the message.
fn record_init_error(message: String) {
    *init_error().lock() = Some(message);
    INIT_FAILED.store(true, Ordering::Release);
}

/// Abort with the stored init diagnostic if initialization has already failed
/// closed, else return and let the caller proceed.
///
/// For the paths that would otherwise answer WITHOUT reaching [`ensure_runtime`]
/// — the shim-bootstrap window. Allocation-free and takes only shim spinlocks,
/// which is what makes it safe on the allocator-init path that window exists
/// for; the re-entrancy latch covers the one call the diagnostic write can make
/// back into it.
fn abort_if_init_failed() {
    if !INIT_FAILED.load(Ordering::Acquire) {
        return;
    }
    if INIT_ERROR_ABORTING.swap(true, Ordering::AcqRel) {
        // Already aborting on this path: this call came back out of the
        // diagnostic write itself. Returning lets it finish; the abort follows.
        return;
    }
    let guard = init_error().lock();
    if let Some(message) = guard.as_deref() {
        abort_with_init_error(message);
    }
}

/// The mode a description holds an advisory `flock` in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FlockMode {
    Shared,
    Exclusive,
}

/// What an advisory lock is taken ON: the kernel keys `flock` by inode, so two
/// descriptions open on one deterministic-fs inode contend, while every other
/// kind of description is its own inode (a socket, an eventfd) — modeled as the
/// description itself. (The two ends of one anonymous pipe share an inode on
/// Linux and do not here; no supported guest locks a pipe.)
#[derive(Clone, Copy, PartialEq, Eq)]
enum LockIdentity {
    Inode(u64),
    Description(DescId),
}

/// Advisory `flock` state, keyed by the open file DESCRIPTION that holds the
/// lock (so a `dup` of the holder can release it, and closing one number of a
/// dup'd pair keeps it) and recording the identity the lock is on. Conflicts are
/// resolved against that identity, so two independent opens of the same path
/// contend exactly as a real per-file `flock` would (a single-opener database's
/// "already open" error), while a lone opener always acquires. Cleared on
/// `LOCK_UN` and when the description's last reference goes. This is shim-side
/// state, never a trace record: the inode it keys on is read through the
/// recorded metadata path, so the table rebuilds identically under replay from
/// the same deterministic open sequence.
static FLOCK_TABLE: OnceLock<SpinMutex<BTreeMap<DescId, (LockIdentity, FlockMode)>>> =
    OnceLock::new();

fn flock_table() -> &'static SpinMutex<BTreeMap<DescId, (LockIdentity, FlockMode)>> {
    FLOCK_TABLE.get_or_init(|| SpinMutex::new(BTreeMap::new()))
}

/// Release any advisory lock a description holds. Called by `LOCK_UN` and when
/// the description is freed; a description holding no lock is a no-op.
fn flock_release(desc: DescId) {
    flock_table().lock().remove(&desc);
}

fn set_errno(errno: c_int) {
    LAST_ERRNO.with(|value| value.set(errno));
}

/// A raw-ABI error return: `-errno`.
#[cfg(target_os = "linux")]
pub(crate) fn neg_errno(errno: c_int) -> i64 {
    -i64::from(errno)
}

fn fail(errno: c_int) -> c_int {
    set_errno(errno);
    -1
}

/// Loud fail-closed for the trap dispatchers: one deterministic diagnostic line
/// on the real host stderr, then abort. Mirrors the thread module's `fatal` but
/// is reachable from the crate-level `sud` and `tsc` modules. Used for the
/// unmapped-syscall abort, the timestamp-counter trap's refusals, and the
/// containment-invariant violations of both (§4.4, §7.4).
pub(crate) fn trap_fatal(message: &str) -> ! {
    // `host_abort()` skips the atexit-driven shutdown flush, so the guest's captured
    // output would be lost with the diagnostic: flush it first, exactly as the
    // C layer's process-class traps do, so a probe that dies here still leaves
    // its event stream behind for the conformance differ.
    let _ = flush_before_refusal();
    let text = format!("patina: {message}\n");
    let _ = host_write_all(2, text.as_bytes());
    crate::host_abort();
}

/// C-callable loud fail-closed for the SUD C layer (arming failures, region
/// discovery). The C side formats no message text of its own (it references no
/// non-allowlisted stdio), so the diagnostic is emitted here through the glibc
/// host-write alias before aborting.
///
/// # Safety
/// `message` must be a valid NUL-terminated C string.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_sud_report_fatal(message: *const c_char) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller passes a valid NUL-terminated C string.
    let text = unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned();
    trap_fatal(&text);
}

/// As [`patina_sud_report_fatal`] with the trapped syscall number and faulting
/// instruction address appended — used by the SIGSYS handler's provenance and
/// out-of-text aborts (§4.4).
///
/// # Safety
/// `message` must be a valid NUL-terminated C string.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_sud_report_fatal_addr(
    message: *const c_char,
    nr: std::ffi::c_long,
    addr: usize,
) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller passes a valid NUL-terminated C string.
    let text = unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned();
    trap_fatal(&format!("{text} (syscall {nr} at {addr:#x})"));
}

/// Pass a process-local memory syscall through to the host kernel via glibc's
/// `syscall(2)` wrapper, resolved as a host alias (its kernel entry sits in
/// glibc text, the SUD-allowed region). See [`sud`] `mem_passthrough`.
///
/// # Safety
/// The arguments are the guest's own for a process-local memory-management
/// syscall (mmap-anon/munmap/mprotect/madvise/mremap/brk); no other numbers are
/// routed here.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn sud_host_syscall(
    nr: std::ffi::c_long,
    a0: std::ffi::c_long,
    a1: std::ffi::c_long,
    a2: std::ffi::c_long,
    a3: std::ffi::c_long,
    a4: std::ffi::c_long,
    a5: std::ffi::c_long,
) -> std::ffi::c_long {
    // SAFETY: `host_syscall` is glibc's real `syscall` wrapper resolved through
    // `dlsym(RTLD_NEXT, "syscall")`, never this shim's interposed `syscall`.
    unsafe { (hostapi::get().host_syscall)(nr, a0, a1, a2, a3, a4, a5) }
}

fn runtime_errno(error: &RuntimeError) -> c_int {
    match error {
        RuntimeError::Effect(error) => effect_errno(error),
        // An exhausted step budget is a supervisor-imposed stop, not a
        // recoverable I/O error: handing the guest an errno lets it swallow the
        // bound and keep going (every subsequent boundary op failing the same
        // way), so the budget would not actually bound anything. Name it and
        // abort, the way a liveness violation does.
        RuntimeError::StepBudgetExceeded { budget } => {
            eprintln!(
                "patina: step budget of {budget} boundary operations was exhausted; \
                 the run is stopped"
            );
            abort_after_flushing_output()
        }
        // A liveness-watchdog violation is fatal and fail-closed: the run has
        // wedged into a virtual-time no-progress churn. Returning an errno the
        // guest could ignore would let it keep spinning, so abort loudly instead —
        // the runtime has already emitted the classifiable PATINA_LIVENESS marker
        // to the captured stderr.
        RuntimeError::Liveness { .. } => abort_after_flushing_output(),
        // A refused custom operation has no answer the guest could safely be
        // handed: the recording disagrees with what it asked, or its `perform`
        // did something replay could never reproduce. Returning an errno would
        // let the guest swallow that and carry on against a trace that no longer
        // describes the run, so name it and abort — the same treatment liveness
        // and the step budget get.
        RuntimeError::CustomOp { label, detail } => {
            eprintln!("PATINA_CUSTOM_OP_REFUSED label={label}\npatina: {detail}");
            abort_after_flushing_output()
        }
        // Frozen-clock churn is the same fail-closed shape: the guest is in a
        // loop that ignores the clock it reads, so advance-on-spin cannot free
        // it and an errno it could swallow would just resume the spin. The
        // runtime has already emitted the classifiable marker and flushed the
        // truncated trace.
        RuntimeError::FrozenClockChurn { .. } => abort_after_flushing_output(),
        RuntimeError::InjectedFsCrash(_) => abort_after_flushing_output(),
        RuntimeError::CrashSelectorUnreached { .. } => EIO,
        RuntimeError::Config(_)
        | RuntimeError::Io { .. }
        | RuntimeError::Trace(_)
        | RuntimeError::InvalidOutcome { .. }
        | RuntimeError::RunAndFinalize { .. }
        | RuntimeError::ScheduleDivergence { .. } => EIO,
    }
}

/// Flush the captured guest output — which already carries the marker line
/// explaining why (`PATINA_LIVENESS`, an exhausted step budget) — and abort the
/// run. `host_abort()` skips the atexit-driven shutdown flush, so the explicit flush
/// here is what preserves that marker; mirrors [`abort_with_init_error`] /
/// [`abort_with_buggify_marker`].
fn abort_after_flushing_output() -> ! {
    let _ = flush_before_refusal();
    crate::host_abort();
}

fn effect_errno(error: &EffectError) -> c_int {
    match error.code {
        ErrorCode::Denied => EACCES,
        ErrorCode::InvalidInput => EINVAL,
        ErrorCode::InvalidHandle => EBADF,
        ErrorCode::MissingDriver => ENOSYS,
        ErrorCode::NotFound => ENOENT,
        ErrorCode::NotReadable | ErrorCode::NotWritable => EBADF,
        ErrorCode::AlreadyExists | ErrorCode::AlreadyBound => EEXIST,
        ErrorCode::IsDirectory => EISDIR,
        ErrorCode::NotDirectory => ENOTDIR,
        ErrorCode::DirectoryNotEmpty => ENOTEMPTY,
        ErrorCode::Io => EIO,
        ErrorCode::NoSpace => ENOSPC,
        ErrorCode::Interrupted => EINTR,
        ErrorCode::Deadlock | ErrorCode::NoRoute | ErrorCode::InvalidState => EIO,
        ErrorCode::ConnectionRefused => ECONNREFUSED,
        ErrorCode::ConnectionReset => ECONNRESET,
        ErrorCode::BrokenPipe => EPIPE,
        ErrorCode::NotConnected => ENOTCONN,
        ErrorCode::NotPermitted => EPERM,
        ErrorCode::NoData => ENODATA,
        ErrorCode::Range => ERANGE,
        ErrorCode::TooBig => E2BIG,
        ErrorCode::Unsupported => EOPNOTSUPP,
        ErrorCode::Busy => EBUSY,
        ErrorCode::IllegalSeek => ESPIPE,
        ErrorCode::CrossDevice => EXDEV,
    }
}

/// Set once `patina_shutdown` has finalized, so a later boundary call fails
/// with `ENOSYS` instead of re-initializing a torn-down runtime.
static SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set once any deterministic boundary effect has run against the installed
/// context (in [`with_context`]/[`with_context_raw`]). The shim-backed harness
/// (`patina-dst-harness`, USAGE-MODES.md Option B) consults this in
/// [`patina_harness_install`]: a boundary observed BEFORE the harness installs
/// means the run already produced events, so reconfiguring the context would
/// make replay semantics ambiguous — the install fails closed. The harness's own
/// `install` does not route through those functions, so it never self-trips this.
static BOUNDARY_SEEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set once [`patina_harness_install`] has installed the runtime. Monotonic: it
/// stays set for the rest of the process, including the teardown window after
/// `patina_shutdown` has taken the context back out of the slot.
///
/// Under deferred init the shim answers an absent context by aborting with the
/// "harness has not installed the runtime yet" diagnostic. That is only the right
/// answer *before* the install — after it, an absent context means the run was
/// already finalized, which is an ordinary teardown state the non-deferred path
/// handles by returning nothing. Keying the diagnostic on the install itself
/// rather than on the context's presence keeps the two apart with no window
/// between `patina_shutdown` taking the context and marking the run shut down.
static HARNESS_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Set by the packaged C startup constructor after it has captured the control
/// plane, optionally installed the runtime, and scrubbed the live environment.
/// If an interposed boundary arrives before this flag, a guest/static constructor
/// beat Patina's constructor in the loader order and the runtime cannot be
/// installed soundly from the still-unsnapshotted control plane.
static STARTUP_CONSTRUCTOR_FINISHED: AtomicBool = AtomicBool::new(false);

/// Best-effort name of the public interposed symbol currently entering the Rust
/// boundary. C interposers store string-literal pointers here before calling the
/// prefixed `patina_*` ABI; early-init diagnostics read it without allocation.
static LAST_BOUNDARY_SYMBOL: AtomicPtr<c_char> = AtomicPtr::new(std::ptr::null_mut());

/// Guarantee a deterministic runtime is installed before a boundary call, or
/// fail closed. Ordinary programs built with `cargo patina native-build` do not
/// call `patina_init_from_env` themselves: the packaged startup path installs
/// the runtime from the supervisor protocol. This is the belt-and-suspenders
/// path — if the constructor has not run yet (static-init ordering) but the
/// protocol is present, it initializes now; if the protocol is absent the
/// binary is being run outside `cargo patina native-run`, which is a hard,
/// clearly reported error rather than a silent seeded-zero run.
fn ensure_runtime() -> Result<(), c_int> {
    if slot().lock().is_some() {
        return Ok(());
    }
    if SHUTDOWN.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(ENOSYS);
    }
    // A prior init attempt (the startup constructor, or an earlier boundary) has
    // already failed closed: surface ITS diagnostic and abort. Never retry — the
    // failed attempt may have drained the inherited trace descriptor to EOF, so a
    // re-init would mask the real cause (fingerprint/corpus/fault mismatch) behind
    // a degraded "empty trace" parse error.
    if let Some(message) = init_error().lock().clone() {
        abort_with_init_error(&message);
    }
    if !STARTUP_CONSTRUCTOR_FINISHED.load(Ordering::Acquire) {
        abort_preinit_interposed_call();
    }
    // Deferred harness init (PATINA_DEFER_INIT=1, `cargo patina run --harness`):
    // the harness owns installation, so an effect that arrives with no context
    // installed and no install yet performed ran BEFORE `patina_harness_install`.
    // Do NOT auto-init from the env — that would race the harness's overlay and
    // silently run against a config the harness never got to apply. Fail closed,
    // loudly and named, so the boundary is attributed to the missing install.
    if missing_context_is_pre_harness_install() {
        abort_harness_before_install();
    }
    if control_env(patina_dst_runtime::ENV_MODE).is_some() {
        let _ = init_from_env();
        if slot().lock().is_some() {
            return Ok(());
        }
        // The protocol was present but initialization failed closed — a
        // fingerprint mismatch (including plain-vs-`--yield-points` cross-replay),
        // a `--mount` corpus that does not match the recorded image hash, a
        // replay-fault-config conflict, and so on. Surface the runtime's specific
        // diagnostic instead of the generic "no runtime installed" line.
        if let Some(message) = init_error().lock().clone() {
            abort_with_init_error(&message);
        }
    }
    let message: &[u8] = b"patina: this binary was built with `cargo patina build` and must \
run under `cargo patina run` (or with the PATINA_MODE protocol set); no deterministic runtime is installed\n";
    let _ = host_write_all(2, message);
    crate::host_abort();
}

/// Emit the runtime's own init-failure diagnostic and abort the process. The
/// `message` is the runtime's error text — a fingerprint mismatch (incl.
/// plain-vs-`--yield-points` cross-replay), a `--mount` corpus whose hash does
/// not match the recording, a replay-fault-config conflict, and so on. The write
/// goes through the host-alias descriptor I/O (never the interposed `write`);
/// captured guest stdio is flushed first so the diagnostic lands after any
/// buffered output, mirroring the process-class deny-trap path.
fn abort_with_init_error(message: &str) -> ! {
    let _ = flush_before_refusal();
    // Written in pieces rather than through one `format!`: this is reachable
    // from the shim-bootstrap window, where a custom global allocator may still
    // be initializing and an allocation here would re-enter it. Same bytes.
    let _ = host_write_all(
        2,
        b"patina: the deterministic runtime failed to initialize: ",
    );
    let _ = host_write_all(2, message.as_bytes());
    let _ = host_write_all(2, b"\n");
    crate::host_abort();
}

fn last_boundary_symbol_bytes() -> Option<&'static [u8]> {
    let pointer = LAST_BOUNDARY_SYMBOL.load(Ordering::Relaxed);
    if pointer.is_null() {
        return None;
    }
    // SAFETY: C only stores string-literal pointers for diagnostics. This is a
    // best-effort field and is never trusted for control flow.
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    if bytes.is_empty() { None } else { Some(bytes) }
}

/// Whether an absent deterministic context means the harness has not installed
/// the runtime *yet* — the fail-closed pre-install case — as opposed to the run
/// having already been installed and finalized.
///
/// `patina_shutdown` takes the context out of the slot before `Context::finish`
/// emits the end-of-run diagnostics, and the multithreaded schedule report reads
/// its own suppression knob through `std::env`, which links to the interposed
/// `getenv` inside a shim-linked guest. So every harness run whose guest spawned
/// a thread reached the interposers with no context installed, during teardown of
/// a runtime the harness had plainly installed. Without this discriminator that
/// landed on the pre-install abort and killed the process before the trace was
/// written.
fn missing_context_is_pre_harness_install() -> bool {
    if HARNESS_INSTALLED.load(Ordering::Acquire) {
        return false;
    }
    control_plane()
        .lock()
        .contains_key(patina_dst_runtime::ENV_DEFER_INIT)
}

fn abort_harness_before_install() -> ! {
    let _ = flush_before_refusal();
    let message: &[u8] = b"patina: harness has not installed the runtime yet; an interposed \
effect reached the deterministic boundary before patina_dst_harness::run/run_with installed the \
runtime. Do all configuration and application effects inside the harness closure.\n";
    let _ = host_write_all(2, message);
    crate::host_abort();
}

fn abort_preinit_interposed_call() -> ! {
    let _ = host_write_all(
        2,
        b"patina: interposed call before deterministic runtime initialization",
    );
    if let Some(symbol) = last_boundary_symbol_bytes() {
        let _ = host_write_all(2, b"; calling symbol: ");
        let _ = host_write_all(2, symbol);
    }
    let _ = host_write_all(
        2,
        b". This most likely came from a static constructor/ctor that ran before Patina's startup constructor. Patina fails closed here because the control plane is not installed yet; cfg-gate that constructor out of DST builds (for example with `#[cfg(not(patina))]` / `#[cfg(not(dst))]`) and move any setup that reads environment, files, clocks, threads, or other interposed APIs into `main` or the Patina harness closure.\n",
    );
    crate::host_abort();
}

/// Run a closure against the installed [`Context`] without first taking a
/// deterministic scheduling point. The managed-thread runtime uses this to
/// perform scheduler transitions from inside the baton critical section, where
/// re-entering [`sched_point`] would recurse on the thread-runtime lock.
fn with_context_raw<T>(
    invoke: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, c_int> {
    BOUNDARY_SEEN.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut guard = slot().lock();
    let context = guard.as_mut().ok_or(ENOSYS)?;
    match invoke(context) {
        Ok(value) => Ok(value),
        Err(error @ RuntimeError::InjectedFsCrash(_)) => terminate_for_injected_fs_crash(error),
        Err(error) => Err(runtime_errno(&error)),
    }
}

fn handoff_key_from_control() -> Result<HandoffSealKey, String> {
    let value = control_env(patina_dst_runtime::ENV_HANDOFF_KEY)
        .ok_or_else(|| format!("{} is required", patina_dst_runtime::ENV_HANDOFF_KEY))?;
    let value = value.trim();
    if value.len() != 64 {
        return Err(format!(
            "{} must be 64 lowercase hex characters",
            patina_dst_runtime::ENV_HANDOFF_KEY
        ));
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| {
            format!(
                "{} must be 64 lowercase hex characters",
                patina_dst_runtime::ENV_HANDOFF_KEY
            )
        })?;
        bytes[index] = u8::from_str_radix(text, 16).map_err(|_| {
            format!(
                "{} must be 64 lowercase hex characters",
                patina_dst_runtime::ENV_HANDOFF_KEY
            )
        })?;
    }
    Ok(HandoffSealKey::from_bytes(bytes))
}

fn terminate_for_injected_fs_crash(error: RuntimeError) -> ! {
    let RuntimeError::InjectedFsCrash(control) = error else {
        unreachable!("caller passes only InjectedFsCrash")
    };
    let patina_dst_runtime::InjectedFsCrash {
        compatibility_fingerprint,
        from_incarnation,
        to_incarnation,
        selector,
        consumed,
        snapshot,
    } = *control;
    let result = (|| -> Result<(), String> {
        let fd = control_handoff_fd()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("{} is required", patina_dst_runtime::ENV_HANDOFF_FD))?;
        let key = handoff_key_from_control()?;
        let handoff = IncarnationHandoff {
            compatibility_fingerprint,
            from_incarnation,
            to_incarnation,
            selector,
            consumed,
            snapshot,
        };
        let bytes = handoff
            .seal(&key)
            .map_err(|error| format!("failed to seal crash-restart handoff: {error}"))?;
        host_write_all(fd, &bytes)
            .map_err(|error| format!("failed to write crash-restart handoff: {error}"))?;
        Ok(())
    })();
    if let Err(message) = result {
        let _ = flush_captured_stdio();
        let line = format!("PATINA_FS_CRASH_HANDOFF_ERROR {message}\n");
        let _ = host_write_all(2, line.as_bytes());
        crate::host_abort();
    }
    let _ = flush_captured_stdio();
    // SAFETY: `_exit` is the host process termination primitive. It skips guest
    // atexit handlers and Patina's normal finalization, which is exactly the
    // modeled power-loss boundary: no code after the triggering call runs in this
    // incarnation.
    unsafe { libc_exit_immediately(NATIVE_FS_CRASH_RESTART_EXIT) }
}

/// Run a scheduler closure against the installed [`Context`], preserving the
/// runtime error message. The managed-thread runtime uses this so a genuine
/// scheduler deadlock surfaces the scheduler's explicit diagnostic instead of
/// a bare errno.
fn with_context_msg<T>(
    invoke: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, String> {
    // Detection-before-fixes. `with_context_msg` is the sole chokepoint for every
    // recorded/replayed managed *scheduler* operation (task spawn/yield/park/wake/
    // complete/next). Once `main` has returned the process is in its post-`main`
    // teardown window, where the only permitted managed activity is the root
    // task's yield hooks — and those are silenced in `sched_point` before they
    // ever reach here. So ANY scheduler operation arriving past the flag is an
    // unmanaged-window leak (a boundary that bypassed the silence): fail LOUDLY
    // and named rather than record/consume a trace op that would otherwise resurface
    // as an unexplained record/replay op-count divergence at some far-away index.
    if thread::main_returned() {
        let _ = flush_before_refusal();
        let _ = host_write_all(
            2,
            b"patina native shim fatal: a managed scheduling operation reached the trace after \
`main` returned; the post-main teardown window must take no recorded scheduling points\n",
        );
        crate::host_abort();
    }
    ensure_runtime().map_err(|_| "Patina context is not installed".to_string())?;
    let mut guard = slot().lock();
    let context = guard
        .as_mut()
        .ok_or_else(|| "Patina context is not installed".to_string())?;
    invoke(context).map_err(|error| match &error {
        // A classified yield divergence gains the one fact only the shim knows:
        // the instrumented guest site of the in-flight guard hit (if any).
        RuntimeError::ScheduleDivergence { .. } => {
            format!("{error}{}", thread::yield_site_context())
        }
        _ => error.to_string(),
    })
}

/// Run a closure against the installed [`Context`] behind a deterministic
/// scheduling point. Every interposed boundary call routes through here, so
/// the seeded scheduler can transfer the execution baton between managed
/// threads at each boundary; when no managed threads exist the scheduling
/// point is a cheap no-op and the behavior is identical to a single thread.
fn with_context<T>(
    invoke: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, c_int> {
    BOUNDARY_SEEN.store(true, std::sync::atomic::Ordering::Relaxed);
    ensure_runtime()?;
    thread::sched_point()?;
    with_context_raw(invoke)
}

/// The instant the deterministic filesystem would stamp an entry with now, for
/// a node the shim keeps itself (a pipe's pipefs inode); 0 with no runtime
/// installed. A clock read, not a boundary effect: it neither marks a boundary
/// nor records anything.
fn fs_time_unrecorded() -> u64 {
    slot()
        .lock()
        .as_mut()
        .and_then(|context| context.fs_time_unrecorded().ok())
        .unwrap_or(0)
}

fn control_env(name: &str) -> Option<String> {
    if let Some(value) = control_plane().lock().get(name).cloned() {
        return Some(value);
    }
    if STARTUP_CONSTRUCTOR_FINISHED.load(Ordering::Acquire) {
        return None;
    }
    // Direct C-ABI users that link only the Rust static library have no POSIX
    // constructor to snapshot/scrub environ, so patina_init_from_env keeps the
    // documented PATINA_* protocol working by reading the host environment here.
    // Once the packaged POSIX constructor has finished, the live environment is
    // scrubbed and public getenv reads the published environ; do not recurse
    // through std::env in that post-startup path.
    std::env::var(name).ok()
}

fn parse_control_u64(name: &str) -> Result<Option<u64>, RuntimeError> {
    control_env(name)
        .map(|value| {
            value.parse().map_err(|_| {
                RuntimeError::Config(format!("{name} must be an unsigned 64-bit integer"))
            })
        })
        .transpose()
}

fn required_control_string(name: &str) -> Result<String, RuntimeError> {
    control_env(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RuntimeError::Config(format!("{name} is required")))
}

/// Parse `PATINA_FACTS_FD` from the control plane, mirroring `control_trace_fd`.
/// Present only when the supervisor asked for the structured run-facts document.
fn control_facts_fd() -> Result<Option<i32>, RuntimeError> {
    control_env(patina_dst_runtime::ENV_FACTS_FD)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{} must be a non-negative descriptor number",
                    patina_dst_runtime::ENV_FACTS_FD
                ))
            })
        })
        .transpose()
}

fn control_handoff_fd() -> Result<Option<i32>, RuntimeError> {
    control_env(patina_dst_runtime::ENV_HANDOFF_FD)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{} must be a non-negative descriptor number",
                    patina_dst_runtime::ENV_HANDOFF_FD
                ))
            })
        })
        .transpose()
}

fn control_trace_fd() -> Result<Option<i32>, RuntimeError> {
    control_env(patina_dst_runtime::ENV_TRACE_FD)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{} must be a non-negative descriptor number",
                    patina_dst_runtime::ENV_TRACE_FD
                ))
            })
        })
        .transpose()
}

/// Parse `PATINA_FS_IMAGE_FD` from the control plane, mirroring `control_trace_fd`.
/// Present only when `native-run --mount` streamed a captured host directory.
fn control_restart_snapshot_fd() -> Result<Option<i32>, RuntimeError> {
    control_env(patina_dst_runtime::ENV_RESTART_SNAPSHOT_FD)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{} must be a non-negative descriptor number",
                    patina_dst_runtime::ENV_RESTART_SNAPSHOT_FD
                ))
            })
        })
        .transpose()
}

fn control_fs_image_fd() -> Result<Option<i32>, RuntimeError> {
    control_env(patina_dst_runtime::ENV_FS_IMAGE_FD)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{} must be a non-negative descriptor number",
                    patina_dst_runtime::ENV_FS_IMAGE_FD
                ))
            })
        })
        .transpose()
}

// Process-termination primitive for modeled power loss. This must be `_exit`,
// not libc `exit`, because crash termination skips guest atexit handlers and
// Patina's normal finalization.
unsafe extern "C" {
    #[link_name = "_exit"]
    fn libc_exit_immediately(status: c_int) -> !;
}

const NATIVE_FS_CRASH_RESTART_EXIT: c_int = 112;

fn read_host_fd_to_end(fd: c_int) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = vec![0_u8; HOST_IO_CHUNK];
    loop {
        // SAFETY: The pointer and length describe a live buffer.
        let count = unsafe { host_read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk[..count as usize]);
    }
}

/// Build the deterministic filesystem for a native run. When
/// `PATINA_FS_IMAGE_FD` is set (`native-run --mount`), rebuild the streamed
/// read-only corpus image and wrap it in the same crash-modeling `CrashFs` used
/// otherwise, so `--fs-crash-at` and friends compose identically with a mount.
/// Absent the knob, an empty `CrashFs`, exactly as before. `FsImage::decode`
/// fails closed on a corrupt or non-canonical image, so a bad stream errors here
/// rather than yielding a silently different filesystem.
/// The durable base image handed to `RuntimeBuilder::with_fs_image`: an empty
/// `MemFs`, or the decoded `--mount` corpus. The runtime — not the shim —
/// wraps this in the config-driven `CrashFs` at its single choke point, so a
/// parsed crash knob (`--fs-crash-at`, `--fs-torn-granularity`) can never be
/// dropped by a filesystem the shim pre-installed outside the fault config.
fn fs_image_base() -> Result<MemFs, RuntimeError> {
    let restart_fd = control_restart_snapshot_fd()?;
    let image_fd = control_fs_image_fd()?;
    match (restart_fd, image_fd) {
        (Some(_), Some(_)) => Err(RuntimeError::Config(format!(
            "{} and {} must not both be set",
            patina_dst_runtime::ENV_RESTART_SNAPSHOT_FD,
            patina_dst_runtime::ENV_FS_IMAGE_FD
        ))),
        (Some(fd), None) => {
            let bytes = read_host_fd_to_end(fd).map_err(|error| {
                RuntimeError::Config(format!(
                    "failed to read {}: {error}",
                    patina_dst_runtime::ENV_RESTART_SNAPSHOT_FD
                ))
            })?;
            FsSnapshot::decode(&bytes)
                .map_err(|error| RuntimeError::Config(format!("invalid restart snapshot: {error}")))
                .map(|snapshot| snapshot.into_memfs())
        }
        (None, Some(fd)) => {
            let bytes = read_host_fd_to_end(fd).map_err(|error| {
                RuntimeError::Config(format!(
                    "failed to read {}: {error}",
                    patina_dst_runtime::ENV_FS_IMAGE_FD
                ))
            })?;
            let image = FsImage::decode(&bytes).map_err(|error| {
                RuntimeError::Config(format!("invalid filesystem image: {error}"))
            })?;
            image
                .into_memfs()
                .and_then(with_identity_home)
                .map_err(|error| {
                    RuntimeError::Config(format!("failed to rebuild filesystem image: {error}"))
                })
        }
        (None, None) => with_identity_home(MemFs::new()).map_err(|error| {
            RuntimeError::Config(format!("failed to seed the filesystem image: {error}"))
        }),
    }
}

/// The identity's home directory in a fresh image, as the pinned system's
/// image has it: `/home` 0755, the home 0750, both the identity's (every
/// entry is). `getpwuid_r` answers that home, so a guest that asks for its
/// home finds a directory there. A `--mount` corpus that already holds either
/// keeps its own; a restart snapshot is the previous incarnation's
/// filesystem, and a home the guest removed stays removed.
fn with_identity_home(mut fs: MemFs) -> Result<MemFs, patina_dst_abi::EffectError> {
    use patina_dst_abi::FsClock;
    use patina_dst_driver_api::FsDriver;
    for (path, mode) in [("/home", 0o755), (registry::IDENTITY_HOME, 0o750)] {
        if fs.metadata(path).is_err() {
            fs.create_directory(FsClock::EPOCH, path, mode)?;
        }
    }
    Ok(fs)
}

#[cfg(test)]
mod identity_home_tests {
    use super::*;
    use patina_dst_driver_api::FsDriver;

    /// The home `getpwuid_r` answers for the identity is a directory in a
    /// fresh image, with the pinned system's modes.
    #[test]
    fn a_fresh_image_holds_the_identity_home() {
        let mut fs = with_identity_home(MemFs::new()).unwrap();
        for (path, mode) in [("/home", 0o755), (registry::IDENTITY_HOME, 0o750)] {
            let metadata = fs.metadata(path).unwrap();
            assert_eq!(
                (metadata.kind, metadata.mode & 0o7777),
                (patina_dst_abi::FsEntryKind::Directory, mode),
                "{path}"
            );
        }
    }
}

fn runtime_config_from_control_plane() -> Result<(RuntimeConfig, Option<i32>), RuntimeError> {
    let mode = control_env(patina_dst_runtime::ENV_MODE).unwrap_or_else(|| "seeded".into());
    let seed = parse_control_u64(patina_dst_runtime::ENV_SEED)?.unwrap_or(0);
    let trace_fd = control_trace_fd()?;
    if trace_fd.is_some()
        && control_env(patina_dst_runtime::ENV_TRACE).is_some_and(|value| !value.is_empty())
    {
        return Err(RuntimeError::Config(format!(
            "{} and {} must not both be set",
            patina_dst_runtime::ENV_TRACE,
            patina_dst_runtime::ENV_TRACE_FD
        )));
    }
    let mut config = match (mode.as_str(), trace_fd) {
        ("seeded", None) => RuntimeConfig::seeded(seed),
        ("seeded", Some(_)) => {
            return Err(RuntimeError::Config(format!(
                "{} is only meaningful in record or replay mode",
                patina_dst_runtime::ENV_TRACE_FD
            )));
        }
        ("record", None) => RuntimeConfig::record(
            seed,
            required_control_string(patina_dst_runtime::ENV_TRACE)?,
            required_control_string(patina_dst_runtime::ENV_FINGERPRINT)?,
        ),
        ("record", Some(_)) => RuntimeConfig::record_transport(
            seed,
            required_control_string(patina_dst_runtime::ENV_FINGERPRINT)?,
        ),
        ("replay", None) => RuntimeConfig::replay_timeline(
            required_control_string(patina_dst_runtime::ENV_TRACE)?,
            control_env(patina_dst_runtime::ENV_TIMELINE).unwrap_or_else(|| "main".into()),
            required_control_string(patina_dst_runtime::ENV_FINGERPRINT)?,
        ),
        ("replay", Some(_)) => RuntimeConfig::replay_transport_timeline(
            control_env(patina_dst_runtime::ENV_TIMELINE).unwrap_or_else(|| "main".into()),
            required_control_string(patina_dst_runtime::ENV_FINGERPRINT)?,
        ),
        ("branch", None) => RuntimeConfig::branch(
            required_control_string(patina_dst_runtime::ENV_TRACE)?,
            control_env(patina_dst_runtime::ENV_PARENT_TIMELINE).unwrap_or_else(|| "main".into()),
            parse_control_u64(patina_dst_runtime::ENV_BRANCH_FROM)?.ok_or_else(|| {
                RuntimeError::Config(format!(
                    "{} is required",
                    patina_dst_runtime::ENV_BRANCH_FROM
                ))
            })?,
            required_control_string(patina_dst_runtime::ENV_BRANCH_ID)?,
            parse_control_u64(patina_dst_runtime::ENV_BRANCH_SEED)?.ok_or_else(|| {
                RuntimeError::Config(format!(
                    "{} is required",
                    patina_dst_runtime::ENV_BRANCH_SEED
                ))
            })?,
            required_control_string(patina_dst_runtime::ENV_FINGERPRINT)?,
        ),
        ("branch", Some(_)) => {
            return Err(RuntimeError::Config(format!(
                "branch mode requires a {} path; {} is unsupported",
                patina_dst_runtime::ENV_TRACE,
                patina_dst_runtime::ENV_TRACE_FD
            )));
        }
        (value, _) => {
            return Err(RuntimeError::Config(format!(
                "{} must be seeded, record, replay, or branch; got {value:?}",
                patina_dst_runtime::ENV_MODE
            )));
        }
    };
    if let Some(budget) = parse_control_u64(patina_dst_runtime::ENV_STEP_BUDGET)? {
        config = config.with_step_budget(budget);
    }
    if let Some(incarnation) = parse_control_u64(patina_dst_runtime::ENV_INCARNATION)? {
        config = config.with_incarnation(incarnation);
    }
    if control_handoff_fd()?.is_some() {
        config = config.require_crash_selector_reached();
    }
    if let Some(value) = control_env(patina_dst_runtime::ENV_PARAMS_JSON) {
        let params: BTreeMap<String, String> = serde_json::from_str(&value).map_err(|error| {
            RuntimeError::Config(format!(
                "{} is invalid: {error}",
                patina_dst_runtime::ENV_PARAMS_JSON
            ))
        })?;
        for (key, value) in params {
            config = config.with_param(key, value)?;
        }
    }
    if let Some(latency) = parse_control_u64(patina_dst_runtime::ENV_NET_LATENCY)? {
        config = config.with_net_latency_nanos(latency);
    }
    // Seed-driven fault knobs (crash point, sleep/net jitter, drop) are read from
    // the scrubbed constructor-time control plane by the same parser the process
    // environment path uses, so both entry points accept the identical protocol
    // and fail closed on any malformed value.
    config = config.apply_fault_env(control_env)?;
    // The DNS host table rides the same scrubbed control plane as the fault
    // knobs, through the same parser, so both entry points accept one protocol.
    config = config.apply_dns_env(control_env)?;
    // Cooperative-SUT (buggify) knobs come from the same control plane through
    // the shared parser, so the shim and the process-environment path agree.
    config = config.apply_buggify_env(control_env)?;
    if matches!(
        config.mode(),
        &patina_dst_runtime::ExecutionMode::Record { .. }
            | &patina_dst_runtime::ExecutionMode::RecordTransport
    ) && fingerprint_declares_component(config.fingerprint(), "buggify")
        && !config.buggify().enabled
    {
        return Err(RuntimeError::Config(
            "fingerprint declares +buggify but buggify is not enabled; refusing vacuous SDK buggify coverage"
                .into(),
        ));
    }
    // Exploration scheduling-policy (PCT / starvation) and swarm fault-class
    // selection knobs travel the same control plane through the shared parsers,
    // so the shim and the process-environment path agree on the protocol.
    config = config.apply_schedule_env(control_env)?;
    config = config.apply_swarm_env(control_env)?;
    // Liveness-watchdog knobs travel the same control plane through the shared
    // parser, so the shim and the process-environment path agree on the protocol.
    config = config.apply_liveness_env(control_env)?;
    // Guest argv (recorded into the trace metadata) travels the same control
    // plane, so record mode captures the arguments the supervisor forwarded.
    config = config.apply_guest_argv_env(control_env)?;
    // Deterministic guest environment values travel the same control plane and
    // are recorded into trace metadata so replay restores them flag-free.
    config = config.apply_guest_env_env(control_env)?;
    // The guest's initial working directory travels the same control plane and
    // is recorded the same way; `install` opens it before the run starts.
    config = config.apply_guest_cwd_env(control_env)?;
    config = config.apply_realtime_epoch_env(control_env)?;
    config = config.apply_hostname_env(control_env)?;
    // End-of-run report suppression comes from the SAME pre-scrub snapshot, once,
    // and is carried in the config: by finalization the context is out of the slot
    // and the interposed `getenv` returns NULL for everything, so a knob read then
    // would silently report "not set" and every suppression request would be inert.
    config = config.with_reports(control_reports());
    // The run-facts path travels the same control plane. On this family the
    // supervisor uses the descriptor channel instead, so a path AND a descriptor
    // together are refused by `RuntimeBuilder::build` — never silently dropped.
    config = config.apply_facts_env(control_env);
    // Record whether syscall-user-dispatch was armed for this run (the C layer's
    // arming state), so a cross-kernel replay is refused up front rather than
    // diverging mid-run (SUD-DESIGN.md §7.3). `None` on every non-SUD run.
    config = config.with_sud(sud_armed_metadata());
    // Same reconciliation contract for the timestamp-counter trap: a trace
    // recorded with rdtsc/rdtscp answered from the virtual clock cannot be
    // replayed on a run that leaves the counter readable, so record the arming
    // and let the runtime refuse the mismatch up front. `None` on every run that
    // did not arm.
    config = config.with_tsc(tsc_armed_metadata());
    Ok((config, trace_fd))
}

/// The syscall-user-dispatch arming flag, OWNED by Rust and exported so the C
/// arming path (`patina_sud_init`) writes it (`PATINA_SUD_ARMED = 1`) when it
/// arms SUD. The dependency points C→Rust deliberately: C is only ever linked
/// where this Rust lib is present, but the Rust lib's own test binary links NO C
/// objects — so a Rust→C reference (the previous `patina_sud_is_armed()`) left
/// the lib-test binary with an undefined symbol. As an `AtomicU8` it lives in a
/// writable section (unlike a plain `static`, which C could not store into).
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub static PATINA_SUD_ARMED: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Whether SUD was armed for this run, shaped for [`RunMetadata::sud`]:
/// `Some(true)` iff the C layer armed syscall-user-dispatch, else `None`
/// (macOS, a non-SUD kernel, a standalone binary). Never records `Some(false)`,
/// so old and non-SUD traces stay byte-identical.
#[cfg(target_os = "linux")]
fn sud_armed_metadata() -> Option<bool> {
    if PATINA_SUD_ARMED.load(core::sync::atomic::Ordering::Relaxed) != 0 {
        Some(true)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn sud_armed_metadata() -> Option<bool> {
    None
}

/// The timestamp-counter trap arming flag, OWNED by Rust and exported so the C
/// arming path (`patina_tsc_init`) writes it (`PATINA_TSC_ARMED = 1`) when it
/// arms `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)`. Same C→Rust ownership direction and
/// rationale as [`PATINA_SUD_ARMED`].
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub static PATINA_TSC_ARMED: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Whether the timestamp-counter trap was armed for this run, shaped for
/// `RunMetadata::tsc`: `Some(true)` iff the C layer armed it, else `None`
/// (macOS, arm64, a kernel without `PR_SET_TSC`, a standalone binary). Never
/// records `Some(false)`, so old and untrapped traces stay byte-identical.
#[cfg(target_os = "linux")]
fn tsc_armed_metadata() -> Option<bool> {
    if PATINA_TSC_ARMED.load(core::sync::atomic::Ordering::Relaxed) != 0 {
        Some(true)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn tsc_armed_metadata() -> Option<bool> {
    None
}

fn fingerprint_declares_component(fingerprint: &str, component: &str) -> bool {
    fingerprint.split('+').skip(1).any(|part| part == component)
}

fn install(context: Result<Context, RuntimeError>) -> c_int {
    let mut context = match context {
        Ok(context) => context,
        Err(error) => return fail(runtime_errno(&error)),
    };
    if let Err(error) = declare_link_time_sites(&mut context) {
        record_init_error(error.to_string());
        return fail(runtime_errno(&error));
    }
    // A configured `--cwd` is opened now, on the context directly: a path that
    // is not a directory refuses the run by name here rather than answering
    // ENOENT to every relative path later.
    if let Err(error) = paths::install_cwd(&mut context) {
        record_init_error(error.to_string());
        return fail(runtime_errno(&error));
    }
    // Guest memory is copied through `process_vm_readv`/`writev` on this
    // process (`uaccess`); a host that refuses them refuses the run by name.
    #[cfg(target_os = "linux")]
    if let Err(message) = uaccess::probe() {
        record_init_error(message);
        return fail(ENOSYS);
    }
    let mut guard = slot().lock();
    if guard.is_some() {
        return fail(EALREADY);
    }
    *guard = Some(context);
    // Publish `environ` from the freshly installed startup env map. The startup
    // constructor also publishes, but a deferred harness install (or a direct
    // C-ABI embedder) lands here first — and its `--env`/overlay values are the
    // environment the guest starts from.
    publish_environ(guard.as_ref().expect("just installed").guest_env());
    set_errno(0);
    // The deterministic runtime is now installed, so the bootstrap window is over.
    // Before ending it, force the guest global allocator to finish initializing
    // while the init-reachable interposers still run natively (see `SHIM_BOOTSTRAP`):
    // a custom `#[global_allocator]` (jemalloc) initializes lazily / via its own
    // constructor, and this guarantees that init has happened during bootstrap
    // regardless of the order its constructor is scheduled relative to this one, so
    // its init can never re-enter the shim after the window closes. `black_box`
    // keeps the probe allocation from being elided.
    let probe = Box::new(0u8);
    std::hint::black_box(probe.as_ref());
    drop(probe);
    SHIM_BOOTSTRAP.store(false, Ordering::Release);
    0
}

fn path_from_c(path: *const c_char) -> Result<String, c_int> {
    if path.is_null() {
        return Err(EINVAL);
    }
    // SAFETY: The C ABI contract requires a valid NUL-terminated string.
    unsafe { CStr::from_ptr(path) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| EINVAL)
}

fn clock(value: u32) -> Result<ClockKind, c_int> {
    match value {
        0 => Ok(ClockKind::Realtime),
        1 => Ok(ClockKind::Monotonic),
        _ => Err(EINVAL),
    }
}

/// Remember the public interposed symbol entering the Rust boundary so an
/// early-init abort can name the API that a constructor reached.
#[unsafe(no_mangle)]
pub extern "C" fn patina_note_boundary_symbol(symbol: *const c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    LAST_BOUNDARY_SYMBOL.store(symbol.cast_mut(), Ordering::Relaxed);
}

/// Install the POSIX interposer's internal-panic policy without installing a
/// runtime. Bare prefixed-C embedders have no guest abort interposer or required
/// host aliases and deliberately do not call this startup control-plane entry.
#[unsafe(no_mangle)]
pub extern "C" fn patina_init_panic_policy() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::panic_boundary::install();
}

/// Mark that the packaged C startup constructor finished capture/init/scrub.
#[unsafe(no_mangle)]
pub extern "C" fn patina_note_startup_constructor_finished() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // The loader runs the constructor on the main thread.
    thread::claim_main_thread();
    STARTUP_CONSTRUCTOR_FINISHED.store(true, Ordering::Release);
}

/// Capture one `PATINA_NAME=value` constructor-time control-plane entry for
/// later shim-internal configuration reads. Guest-visible getenv never serves
/// this map.
///
/// # Safety
/// `entry` must point to a valid NUL-terminated string for the duration of the
/// call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_control_set_entry(entry: *const c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if entry.is_null() {
        return;
    }
    // SAFETY: Guaranteed by this function's C ABI contract.
    let entry = unsafe { CStr::from_ptr(entry) }.to_string_lossy();
    let Some((name, value)) = entry.split_once('=') else {
        return;
    };
    if !name.starts_with("PATINA_") {
        return;
    }
    control_plane()
        .lock()
        .insert(name.to_owned(), value.to_owned());
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_init_seed(seed: u64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    install(Context::from_config(RuntimeConfig::seeded(seed)))
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_init_crash(seed: u64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // Explicit manual-crash filesystem for C-ABI embedders that drive
    // `context.fs_crash()` themselves. Seed the crash policy from the argument
    // (a default-constructed `CrashFs` would pin seed 0 and silently ignore it).
    let context = CrashFs::builder()
        .seed(seed)
        .build()
        .map_err(RuntimeError::Effect)
        .and_then(|filesystem| {
            RuntimeBuilder::new(RuntimeConfig::seeded(seed))
                .with_default_drivers()
                .with_filesystem(filesystem)
                .build()
        });
    install(context)
}

fn init_from_env() -> c_int {
    let context = runtime_config_from_control_plane().and_then(|(config, trace_fd)| {
        let mut builder = RuntimeBuilder::new(config)
            .with_default_drivers()
            .with_fs_image(fs_image_base()?);
        if let Some(fd) = trace_fd {
            builder = builder.with_trace_transport(FdTraceTransport { fd });
        }
        // The structured run-facts channel. A `PATINA_FACTS` path alongside it is
        // refused by `build` rather than silently losing one document.
        if let Some(fd) = control_facts_fd()? {
            builder = builder.with_facts_sink(FdFactsSink { fd });
        }
        builder.build()
    });
    if let Err(error) = &context {
        // Preserve the runtime's diagnostic before `install` collapses it to a
        // bare errno, so the fail-closed abort path can report *why*.
        record_init_error(error.to_string());
    }
    install(context)
}

/// Build the runtime from the `PATINA_*` protocol. Idempotent: the packaged
/// startup path (a constructor in the POSIX layer) calls this automatically, so
/// an explicit call from application code that also wants it is a no-op rather
/// than a double-init error.
#[unsafe(no_mangle)]
pub extern "C" fn patina_init_from_env() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if slot().lock().is_some() {
        set_errno(0);
        return 0;
    }
    init_from_env()
}

/// Install the deterministic runtime for a shim-backed harness (see
/// `patina-dst-harness`, USAGE-MODES.md startup Option B). Called by
/// `patina_dst_harness::run`/`run_with` under `cargo patina run --harness`
/// (`PATINA_DEFER_INIT=1`), after the harness has injected its configuration
/// overlay onto the captured control plane via [`patina_control_set_entry`]. The
/// runtime is then built from the (overlaid) control plane through the SAME
/// parsers the constructor path uses ([`init_from_env`]), so every fault/buggify/
/// schedule/liveness knob folds into the identical `RuntimeConfig` fields — the
/// existing fingerprint folds and `reconcile_replay_*` conflict checks apply with
/// no new fingerprint component.
///
/// Fails closed, returning a distinct [`patina_dst_runtime`] `HARNESS_ERR_*`
/// sentinel and printing a loud diagnostic, when: a boundary effect already ran
/// (`HARNESS_ERR_BOUNDARY_BEFORE_INSTALL`); the runtime is already installed
/// (`HARNESS_ERR_ALREADY_INSTALLED`); there is no `PATINA_MODE` in the control
/// plane, i.e. not under `cargo patina run` (`HARNESS_ERR_NOT_UNDER_PATINA`); or
/// the configuration failed to build/validate (`HARNESS_ERR_CONFIG`).
#[unsafe(no_mangle)]
pub extern "C" fn patina_harness_install() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // Ordering matters: report the most specific fail-closed reason first. A
    // boundary already seen is the sharpest diagnostic (the run produced events
    // before configuration), so it precedes the generic already-installed check.
    if BOUNDARY_SEEN.load(std::sync::atomic::Ordering::Relaxed) {
        let _ = flush_captured_stdio();
        let _ = host_write_all(
            2,
            b"patina: patina_dst_harness cannot install the runtime: a deterministic boundary \
effect already ran before the harness configured the context; do all configuration and application \
effects inside the harness closure so replay stays unambiguous\n",
        );
        return patina_dst_runtime::HARNESS_ERR_BOUNDARY_BEFORE_INSTALL;
    }
    if slot().lock().is_some() {
        let _ = flush_captured_stdio();
        let _ = host_write_all(
            2,
            b"patina: patina_dst_harness cannot install the runtime: a deterministic runtime is \
already installed. Run the harness binary with `cargo patina run --harness` so startup defers \
initialization to the harness (PATINA_DEFER_INIT), and call run/run_with exactly once\n",
        );
        return patina_dst_runtime::HARNESS_ERR_ALREADY_INSTALLED;
    }
    if control_env(patina_dst_runtime::ENV_MODE).is_none() {
        let _ = flush_captured_stdio();
        let _ = host_write_all(
            2,
            b"patina: patina_dst_harness cannot install the runtime: this binary is not running \
under `cargo patina run` (no PATINA_MODE control plane). A shim-backed harness must be built and \
run through Patina, e.g. `cargo patina run <manifest> --target native --harness`\n",
        );
        return patina_dst_runtime::HARNESS_ERR_NOT_UNDER_PATINA;
    }
    let _ = init_from_env();
    if slot().lock().is_some() {
        // Ordered against the interposers' `missing_context_is_pre_harness_install`
        // load: once this is visible, an absent context is teardown, not a
        // pre-install boundary.
        HARNESS_INSTALLED.store(true, Ordering::Release);
        set_errno(0);
        return patina_dst_runtime::HARNESS_OK;
    }
    // Configuration failed to build: surface the runtime's own diagnostic (bad
    // knob value, replay fingerprint/reconciliation conflict, bad `--mount`
    // corpus, ...) rather than a bare code.
    if let Some(message) = init_error().lock().clone() {
        let _ = flush_captured_stdio();
        let line = format!(
            "patina: patina_dst_harness could not build the runtime configuration: {message}\n"
        );
        let _ = host_write_all(2, line.as_bytes());
    }
    patina_dst_runtime::HARNESS_ERR_CONFIG
}

/// `void (*)(void)` the POSIX layer registers at startup: the flush of its
/// stdio buffers, or null when no C layer is linked (direct C-ABI embedders
/// and the Rust lib tests). Stored as a data pointer, as the environ installer
/// is.
static STREAM_FLUSHER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// `size_t (*)(const void **)` registered beside the flusher: hands over the
/// bytes stdout's buffer holds and empties it, writing nothing (see
/// [`salvage_buffered_stdout`]).
static STREAM_SALVAGE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

type StreamFlusher = unsafe extern "C" fn();
type StreamSalvage = unsafe extern "C" fn(*mut *const c_void) -> usize;

/// Register the POSIX layer's stdio flush, which [`patina_shutdown`] runs
/// first, and the salvage of its stdout buffer, which every refusal runs
/// ([`flush_before_refusal`]). Null pointers unregister.
///
/// # Safety
/// `flusher` must be a valid `void (*)(void)` and `salvage` a valid
/// `size_t (*)(const void **)` for the life of the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_register_stream_flusher(
    flusher: Option<StreamFlusher>,
    salvage: Option<StreamSalvage>,
) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let flusher = flusher.map_or(std::ptr::null_mut(), |flusher| flusher as *mut c_void);
    let salvage = salvage.map_or(std::ptr::null_mut(), |salvage| salvage as *mut c_void);
    STREAM_FLUSHER.store(flusher, Ordering::Release);
    STREAM_SALVAGE.store(salvage, Ordering::Release);
}

/// Finalize the runtime on an exit path, writing any recorded trace and
/// flushing captured stdio. The guest's stdio buffers are written first, as
/// glibc's `exit` flushes them after the atexit handlers (`_IO_cleanup`); the
/// runtime's own abort, fatal-signal and raw `exit_group` paths call
/// [`shutdown_run`] instead, since glibc flushes on none of them. Idempotent:
/// the packaged startup path registers this through `atexit` so record mode
/// finalizes on normal exit without an explicit call, and a second call (for
/// example an application that still calls it explicitly) is a no-op.
#[unsafe(no_mangle)]
pub extern "C" fn patina_shutdown() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let pointer = STREAM_FLUSHER.load(Ordering::Acquire);
    if !pointer.is_null() && slot().lock().is_some() {
        // SAFETY: non-null only after `patina_register_stream_flusher` stored a
        // valid `StreamFlusher`. The flush writes through the guest's own
        // descriptors, so it is guest code for the panic boundary.
        let flusher = unsafe { std::mem::transmute::<*mut c_void, StreamFlusher>(pointer) };
        let _guest = crate::panic_boundary::PanicScope::suspend();
        unsafe { flusher() };
    }
    shutdown_run()
}

/// Finalize the runtime without flushing the guest's stdio buffers (see
/// [`patina_shutdown`]).
pub(crate) fn shutdown_run() -> c_int {
    thread::deactivate();
    let context = {
        let mut guard = slot().lock();
        match guard.take() {
            Some(context) => context,
            None => {
                set_errno(0);
                return 0;
            }
        }
    };
    SHUTDOWN.store(true, std::sync::atomic::Ordering::Relaxed);
    // Detect a declared-but-never-reached setup gate before the context is
    // consumed. The trace is still finalized (the run is reproducible), then the
    // process fails loudly — a `--buggify-after-setup` run whose guest never
    // called `setup_complete()` is a harness bug, not a silent no-fault run.
    let setup_violation = context.buggify_setup_violation();
    let finished = context.finish();
    let coverage = finalize_coverage();
    let flushed = flush_captured_stdio();
    if setup_violation {
        let _ = host_write_all(
            2,
            b"PATINA_BUGGIFY_SETUP_NEVER_CALLED --buggify-after-setup was declared but the guest \
never called patina_dst::lifecycle::setup_complete()\n",
        );
        crate::host_abort();
    }
    if let Err(error) = coverage {
        let line = format!("patina: coverage finalization refused: {error}\n");
        let _ = host_write_all(2, line.as_bytes());
        crate::host_abort();
    }
    // Patina fails closed by default: a shutdown failure is reported and the
    // atexit hook aborts on it, so a recorder that misbehaved can never be
    // mistaken for a clean run. A recorder BUDGET overflow is the one
    // deliberate exception, and this is the record of what makes it safe: by
    // the time `finish` runs the guest has already returned from `main` (or
    // called `exit`), so the run's verdict is FINAL and known — nothing about
    // the outcome is in doubt, and the only thing lost is the replay artifact.
    // Aborting here would overwrite that settled verdict with SIGABRT, turning
    // every sufficiently long recorded run into a phantom failure and, worse,
    // masking the true exit status and diagnostics of a run that failed for a
    // real reason. Every OTHER finalization failure — an I/O error, an
    // unwritable path, a bundle that would not serialize or validate — still
    // aborts: those mean the recorder itself is broken rather than merely out
    // of budget, and for them the fail-closed default is exactly right.
    //
    // The budget refusal is raised before the recorder writes anything, so the
    // downgrade can never leave a half-written artifact behind: in path mode no
    // file is created at all, and on the descriptor channel the marker written
    // below is the only thing the supervisor ever sees.
    let finished = match finished {
        Err(RuntimeError::Trace(error)) if error.is_resource_limit() => {
            abandon_over_budget_trace(&error);
            Ok(())
        }
        other => other,
    };
    match (finished, flushed) {
        (Ok(()), Ok(())) => {
            set_errno(0);
            0
        }
        (Err(error), _) => {
            report_shutdown_error(&error.to_string());
            fail(runtime_errno(&error))
        }
        (Ok(()), Err(error)) => {
            report_shutdown_error(&format!("flush captured stdio: {error}"));
            fail(EIO)
        }
    }
}

/// Report a trace the recorder abandoned because the run outgrew its budget,
/// and — on the descriptor channel — tell the supervisor so in a form it can
/// tell apart from a crash-truncated trace.
///
/// Two lines reach stderr: the machine-greppable `PATINA_INFRA` marker a sweep
/// classifies on, and the human sentence that says the verdict stands. The
/// marker document goes to the trace descriptor because the supervisor's only
/// other evidence would be an empty file, which is exactly what a guest that
/// died mid-run leaves; without the marker it could not tell "this run outgrew
/// its budget" from "this run never finalized", and it must keep failing loudly
/// on the latter.
///
/// In `PATINA_TRACE` path mode there is no descriptor and no file — the budget
/// is enforced before the trace is created — so the stderr lines are the whole
/// report and a later `replay` simply finds nothing at the path.
fn abandon_over_budget_trace(error: &TraceError) {
    let _ = host_write_all(2, over_budget_diagnostic(error).as_bytes());
    if let Ok(Some(fd)) = control_trace_fd() {
        let _ = host_write_all(
            fd,
            &abandoned_trace_marker("resource-limit", &error.to_string()),
        );
    }
}

/// The two stderr lines for an over-budget trace: the machine-greppable marker
/// a sweep classifies on, carrying the figures when the budget is a byte one,
/// and the human sentence that says what it means for the run.
fn over_budget_diagnostic(error: &TraceError) -> String {
    let mut lines = resource_limit_infra_line(error);
    lines.push_str(&format!(
        "patina: the recorded trace outgrew its budget and was NOT written ({error}). This \
run's own verdict stands unchanged — the guest ran to completion and its exit status is its \
own — but the trace is unusable for replay; re-record a shorter run if you need one.\n"
    ));
    lines
}

/// Sentinel for "the guest's own exit status was never observed" — a platform
/// or exit path that reaches shutdown without passing through either recording
/// site (Darwin's natural `main` return keeps libSystem's own `exit`).
const GUEST_EXIT_UNKNOWN: i32 = i32::MIN;

/// The guest's OWN exit status, recorded the instant its `main` returned or it
/// called `exit(3)` — before patina's atexit finalization runs and, on a
/// finalization failure, before `host_abort()` replaces that status with SIGABRT.
///
/// Without this the guest's verdict is unrecoverable in exactly the case that
/// matters most: a long run that both failed for a real reason AND outgrew or
/// broke the recorder. The supervisor would see only the shim's SIGABRT, file
/// the generation as patina's own infrastructure failure, and the real finding
/// would disappear. See [`report_shutdown_error`].
static GUEST_EXIT_STATUS: std::sync::atomic::AtomicI32 =
    std::sync::atomic::AtomicI32::new(GUEST_EXIT_UNKNOWN);

/// Record the guest's own exit status. Called from the `__libc_start_main`
/// wrapper the moment the guest's `main` returns, and from [`patina_exit`] for
/// an explicit `exit(3)`/`std::process::exit`. The FIRST recording wins: `main`
/// returning is the guest's verdict, and glibc's own later `exit()` of that same
/// code must not be mistaken for a second, independent one.
#[unsafe(no_mangle)]
pub extern "C" fn patina_note_guest_exit_status(status: c_int) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let _ = GUEST_EXIT_STATUS.compare_exchange(
        GUEST_EXIT_UNKNOWN,
        status,
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
    );
}

fn guest_exit_status() -> Option<i32> {
    match GUEST_EXIT_STATUS.load(std::sync::atomic::Ordering::Relaxed) {
        GUEST_EXIT_UNKNOWN => None,
        status => Some(status),
    }
}

/// Report a finalization failure, naming the status the GUEST itself reached.
///
/// The atexit hook `host_abort()`s on this, so the process dies on SIGABRT and the
/// guest's own status is gone from everything downstream can see. Carrying it on
/// the refusal line is what lets a supervisor tell "patina's recorder broke on a
/// run that was otherwise clean" (infrastructure) from "patina's recorder broke
/// on a run the guest had ALREADY failed" — where the guest's failure is the
/// finding and the unusable trace is a footnote.
fn report_shutdown_error(message: &str) {
    let mut line = format!("patina: runtime shutdown failed: {message}");
    match guest_exit_status() {
        Some(status) => line.push_str(&format!(" guest_exit_code={status}")),
        None => line.push_str(" guest_exit_code=unknown"),
    }
    line.push('\n');
    let _ = host_write_all(2, line.as_bytes());
}

/// Flush captured stdout/stderr to the real host descriptors WITHOUT finalizing
/// the run (unlike [`patina_shutdown`], which also finishes the trace/record),
/// salvaging what the C streams buffered ([`flush_before_refusal`]). The
/// process-class deny-traps in `c/patina_posix.c` call this immediately
/// before `host_abort()`: `host_abort()` skips the atexit-driven shutdown flush, so
/// without it the guest's buffered output and the deny diagnostic would be lost.
#[unsafe(no_mangle)]
pub extern "C" fn patina_flush_captured_stdio() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match flush_before_refusal() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Write what the capture holds to the host, as the end of a run does. The
/// guest's own stdio buffers are not touched: [`shutdown_run`] and the
/// crash-restart `_exit` end the run the way glibc's abort, fatal signal and
/// `_exit` do, and those lose them.
fn flush_captured_stdio() -> io::Result<()> {
    flush_capture(false)
}

/// The flush every path on which PATINA ends the run makes before it aborts:
/// a refusal, an internal fatal, a liveness or step-budget stop, a verdict, a
/// failed initialization. The guest did not choose to end there, so the
/// output it buffered in C `stdout` (which glibc would have written at a later
/// flush) is handed to the capture too: the lines leading up to the refusal
/// are what a user debugs it from.
fn flush_before_refusal() -> io::Result<()> {
    flush_capture(true)
}

fn flush_capture(salvage: bool) -> io::Result<()> {
    let mut capture = stdio_slot().lock();
    let stdout = std::mem::take(&mut capture.stdout);
    let stderr = std::mem::take(&mut capture.stderr);
    drop(capture);
    host_write_all(1, &stdout)?;
    if salvage {
        salvage_buffered_stdout()?;
    }
    host_write_all(2, &stderr)
}

/// Write what C `stdout` has buffered straight to the host's stdout, after the
/// captured bytes: the POSIX layer's registered salvage empties the buffer and
/// hands it over. Only while descriptor 1 is still the capture: bytes bound
/// for a descriptor the guest redirected (`dup2` onto a file) would be a
/// filesystem effect, and are lost as glibc loses them. Allocates nothing and
/// takes no scheduling point (this runs on fatal paths, some from the
/// bootstrap window); a descriptor table this thread already holds is
/// undecidable, so the buffer is dropped rather than guessed at.
fn salvage_buffered_stdout() -> io::Result<()> {
    let pointer = STREAM_SALVAGE.load(Ordering::Acquire);
    if pointer.is_null() {
        return Ok(());
    }
    let to_capture = FD_TABLE.get().is_some_and(|table| {
        table
            .acquire()
            .is_ok_and(|table| table.kind(1) == Some(FdKind::Stdout))
    });
    // SAFETY: non-null only after `patina_register_stream_flusher` stored a
    // valid `StreamSalvage`.
    let salvage = unsafe { std::mem::transmute::<*mut c_void, StreamSalvage>(pointer) };
    let mut bytes: *const c_void = std::ptr::null();
    // SAFETY: the salvage writes one pointer through `bytes`.
    let length = unsafe { salvage(&mut bytes) };
    if !to_capture || length == 0 || bytes.is_null() {
        return Ok(());
    }
    // SAFETY: the salvage answers the stream's own buffer and the count of
    // bytes it holds; nothing writes to it again before the process aborts.
    let pending = unsafe { slice::from_raw_parts(bytes.cast::<u8>(), length) };
    host_write_all(1, pending)
}

fn stdio_slot() -> &'static SpinMutex<StdioCapture> {
    STDIO.get_or_init(|| SpinMutex::new(StdioCapture::default()))
}

/// Capture deterministic stdout (1) or stderr (2) bytes for flushing to the
/// host at `patina_shutdown`, mirroring the WASI host's captured stdio.
///
/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_stdio_write(
    fd: c_int,
    source: *const c_void,
    length: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if fd != 1 && fd != 2 {
        return fail(EBADF) as isize;
    }
    if length != 0 && source.is_null() {
        return fail(EINVAL) as isize;
    }
    // Capture accepts bytes with no context installed, so — like the
    // shim-bootstrap window — it never reaches `ensure_runtime` and would
    // swallow a fail-closed init error. The buffer is flushed at
    // `patina_shutdown`, which with no context returns quietly, so a guest whose
    // only boundary effect is a `println!` used to exit 0 with its output
    // dropped and the refusal unreported. Not `ensure_runtime`: that would also
    // fire for a binary run outside the supervisor, whose diagnostic is the
    // startup path's to give.
    abort_if_init_failed();
    // Runtime diagnostics can print with Context/ThreadRuntime locked. They use
    // the same captured sink, but must not schedule or re-enter either lock.
    // Guest writes still take their ordinary scheduling point.
    if !in_shim_critical() {
        if let Err(errno) = thread::sched_point() {
            return fail(errno) as isize;
        }
    }
    let bytes = if length == 0 {
        &[]
    } else {
        // SAFETY: Guaranteed by this function's C ABI contract.
        unsafe { slice::from_raw_parts(source.cast::<u8>(), length) }
    };
    let mut capture = stdio_slot().lock();
    let sink = if fd == 1 {
        &mut capture.stdout
    } else {
        &mut capture.stderr
    };
    if sink.len().saturating_add(bytes.len()) > MAX_CAPTURED_STDIO_BYTES {
        return fail(EFBIG) as isize;
    }
    sink.extend_from_slice(bytes);
    set_errno(0);
    isize::try_from(length).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_errno() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    LAST_ERRNO.with(Cell::get)
}

// ---- The guest environment ----------------------------------------------------
//
// The environment is the process's own `environ` array, as it is under glibc:
// the C layer (`c/posix/env.c`) runs glibc's getenv/setenv/unsetenv/putenv/
// clearenv over whatever array `environ` names, so a pointer `getenv` answers
// is the entry's own bytes, new names are appended, an array the program
// assigns is honoured and a `putenv` string stays aliased. The runtime's part
// is the array the run STARTS with — the startup `--env` map, the one piece
// the trace records, published once the ambient host environment is scrubbed
// (and again when a deferred harness installs the runtime) — and the gates
// below, which decide when the C layer may answer at all.
//
// Mutations are guest-driven and therefore deterministic: nothing is recorded
// per mutation, and replay reproduces them by re-executing the guest.

/// May the C `getenv` read `environ`? 1 to read it, 0 to answer NULL: before
/// the startup constructor finishes, `environ` is still the ambient host
/// environment, and Rust/libc startup code can probe it before Patina's
/// constructor runs, so those probes see the historical empty environment
/// rather than the host's. A stored init error aborts, as every entry that
/// answers without reaching `ensure_runtime` must; so does a lookup that beat
/// a deferred harness install.
#[unsafe(no_mangle)]
pub extern "C" fn patina_env_read_gate() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if let Some(message) = init_error().lock().clone() {
        abort_with_init_error(&message);
    }
    if !STARTUP_CONSTRUCTOR_FINISHED.load(Ordering::Acquire) {
        return 0;
    }
    let missing_context = slot().lock().is_none();
    if missing_context && missing_context_is_pre_harness_install() {
        abort_harness_before_install();
    }
    1
}

/// May the C layer mutate `environ`? 0 to go ahead, -1 (`ENOSYS`, with a
/// diagnostic) when no runtime is installed. Unlike a lookup, a pre-startup
/// WRITE would change the ambient host array the constructor is about to
/// scrub, and the guest and the run would then disagree about the
/// environment: a constructor beat Patina's, so name it and fail closed.
#[unsafe(no_mangle)]
pub extern "C" fn patina_env_write_gate() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if let Some(message) = init_error().lock().clone() {
        abort_with_init_error(&message);
    }
    if !STARTUP_CONSTRUCTOR_FINISHED.load(Ordering::Acquire) {
        abort_preinit_interposed_call();
    }
    let missing_context = slot().lock().is_none();
    if missing_context {
        if missing_context_is_pre_harness_install() {
            abort_harness_before_install();
        }
        // A standalone run (or one past `patina_shutdown`) has no deterministic
        // environment to mutate; refuse rather than pretend the write took.
        let _ = host_write_all(
            2,
            b"patina: environment mutation requires an installed deterministic runtime; failing closed\n",
        );
        return fail(ENOSYS);
    }
    set_errno(0);
    0
}

/// `void (*)(char **)` installed by the POSIX layer's constructor, or null when
/// no C layer is linked (direct C-ABI embedders and the Rust lib tests). Stored
/// as a data pointer because Rust has no atomic function-pointer type. The
/// dependency points C→Rust: the Rust lib's own test binary links no C
/// objects, so naming `environ`'s owner here would leave it undefined (the
/// same trap documented for `PATINA_SUD_ARMED`).
static ENVIRON_INSTALLER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

type EnvironInstaller = unsafe extern "C" fn(*mut *mut c_char);

/// Register the callback that publishes the startup `environ` array. Called
/// once from the POSIX constructor before the runtime is installed.
///
/// # Safety
/// `installer` must be a valid `void (*)(char **)` for the life of the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_register_environ_installer(installer: Option<EnvironInstaller>) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // A function pointer and a data pointer are the same width on every platform
    // Patina targets; the value is only ever transmuted back to the same type.
    let pointer = match installer {
        Some(installer) => installer as *mut c_void,
        None => std::ptr::null_mut(),
    };
    ENVIRON_INSTALLER.store(pointer, Ordering::Release);
}

fn environ_installer() -> Option<EnvironInstaller> {
    let pointer = ENVIRON_INSTALLER.load(Ordering::Acquire);
    if pointer.is_null() {
        return None;
    }
    // SAFETY: non-null only after `patina_register_environ_installer` stored a
    // valid `EnvironInstaller`.
    Some(unsafe { std::mem::transmute::<*mut c_void, EnvironInstaller>(pointer) })
}

/// Build the startup `environ` array from `env` (key order) and hand it to the
/// registered installer. The array and its strings are deliberately leaked: the
/// guest owns the environment from here on, and glibc's `setenv` copies an
/// array it did not allocate before growing it.
fn publish_environ(env: &BTreeMap<String, String>) {
    let Some(installer) = environ_installer() else {
        return;
    };
    let mut entries: Vec<*mut c_char> = Vec::with_capacity(env.len() + 1);
    for (key, value) in env {
        let Ok(entry) = CString::new(format!("{key}={value}")) else {
            // The guest-env validators reject NUL bytes on every path that can
            // reach the map; keep this fail-closed if an embedder bypasses them.
            let _ = host_write_all(
                2,
                b"patina: deterministic guest environment contained a NUL byte; failing closed\n",
            );
            crate::host_abort();
        };
        entries.push(entry.into_raw());
    }
    entries.push(std::ptr::null_mut());
    let array = Box::leak(entries.into_boxed_slice()).as_mut_ptr();
    // SAFETY: `array` is a live, NUL-terminated `char **` that outlives the
    // process, which is exactly what the installer stores into `environ`.
    unsafe { installer(array) };
}

/// Publish `environ` from the installed context's startup map, or an empty
/// array when no runtime is installed. Called by the POSIX constructor after
/// the ambient host environment is scrubbed, so `environ` holds the
/// deterministic startup environment (the `--env` set, or nothing) from the
/// guest's first instruction.
#[unsafe(no_mangle)]
pub extern "C" fn patina_publish_environ() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let guard = slot().lock();
    match guard.as_ref() {
        Some(context) => publish_environ(context.guest_env()),
        None => publish_environ(&BTreeMap::new()),
    }
}

/// Fill caller-owned memory with deterministic bytes: 0, or -1 with `EFAULT`
/// for a buffer the guest cannot write (the bytes are drawn either way,
/// except for a NULL buffer).
///
/// # Safety
/// `destination` is a guest address; it is written only through `uaccess`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_entropy(destination: *mut c_void, length: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if length != 0 && destination.is_null() {
        return fail(EFAULT);
    }
    let result = with_context(|context| context.entropy_bytes(length));
    match result {
        // Copied as the kernel's `copy_to_user` copies: a buffer the guest
        // cannot write is `EFAULT`, never a fault in shim code.
        Ok(bytes) => match uaccess::write_bytes(destination as usize, &bytes) {
            Ok(()) => {
                set_errno(0);
                0
            }
            Err(errno) => fail(errno),
        },
        Err(errno) => fail(errno),
    }
}

/// Does the kernel's `getrandom(2)` accept `flags`? Every bit outside
/// `GRND_NONBLOCK|GRND_RANDOM|GRND_INSECURE`, and `GRND_INSECURE` with
/// `GRND_RANDOM`, is `EINVAL` (`drivers/char/random.c`).
pub(crate) fn getrandom_flags_accepted(flags: u32) -> bool {
    use linux_raw_sys::general::{GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM};
    let insecure_random = GRND_INSECURE | GRND_RANDOM;
    flags & !(GRND_NONBLOCK | insecure_random) == 0 && flags & insecure_random != insecure_random
}

/// The most one read-like call transfers: `MAX_RW_COUNT`, `INT_MAX` rounded
/// down to the modeled 4096-byte page.
const MAX_RW_COUNT: usize = i32::MAX as usize & !4095;

/// `getrandom(2)` over the seeded stream: the byte count, -1/`EINVAL` for a
/// flag word the kernel refuses, or -1/`EFAULT` for a null buffer. The stream
/// never blocks and has one pool, so the accepted flags change nothing. One
/// draw is at most `MAX_RW_COUNT` bytes, as on the kernel. The C `getrandom`
/// and the SUD row both answer here.
///
/// # Safety
/// `destination` must be writable for `length` bytes when `length` is nonzero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_getrandom(
    destination: *mut c_void,
    length: usize,
    flags: u32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !getrandom_flags_accepted(flags) {
        return fail(EINVAL) as isize;
    }
    if length != 0 && destination.is_null() {
        return fail(EFAULT) as isize;
    }
    let length = length.min(MAX_RW_COUNT);
    // SAFETY: Guaranteed by this function's C ABI contract.
    match unsafe { patina_entropy(destination, length) } {
        0 => length as isize,
        _ => -1,
    }
}

/// Write a deterministic clock value to caller-owned memory.
///
/// # Safety
/// `nanos` must point to writable `uint64_t` storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_clock_now(clock_id: u32, nanos: *mut u64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if nanos.is_null() {
        return fail(EINVAL);
    }
    // Bootstrap window (see `SHIM_BOOTSTRAP`): a custom global allocator's own
    // constructor reads the clock for internal timing (tikv-jemallocator's
    // `arena_new` calls `nstime_update` -> `mach_absolute_time`) BEFORE the shim
    // has installed the runtime. That value is allocator-internal, never
    // guest-observable, so answer a fixed zero without touching the runtime —
    // for the realtime clock too, which then reads 1970 rather than the run's
    // epoch: an allocator timing itself there is not a clock bug — going
    // through `with_context`/`ensure_runtime` here would try to auto-install the
    // runtime in the middle of the allocator's own initialization and re-enter it.
    if in_shim_bootstrap() {
        // SAFETY: `nanos` was checked non-null and is writable per the C ABI.
        unsafe { nanos.write(0) };
        set_errno(0);
        return 0;
    }
    let clock = match clock(clock_id) {
        Ok(clock) => clock,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.now(clock)) {
        Ok(value) => {
            // SAFETY: The pointer was checked and is required to be writable.
            unsafe { nanos.write(value) };
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_sleep_until(clock_id: u32, deadline_nanos: u64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: null means no remaining-time output.
    unsafe { patina_sleep_until_remaining(clock_id, deadline_nanos, std::ptr::null_mut()) }
}

/// Sleep with an optional two-i64 kernel timespec remaining-time output.
/// Absolute sleeps pass null, so their caller's rem buffer is untouched.
/// # Safety
/// Non-null `remaining` must be writable for two i64 values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_sleep_until_remaining(
    clock_id: u32,
    deadline_nanos: u64,
    remaining: *mut i64,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let clock = match clock(clock_id) {
        Ok(clock) => clock,
        Err(errno) => return fail(errno),
    };
    if let Err(errno) = ensure_runtime() {
        return fail(errno);
    }
    // Apply any configured seeded sleep-latency jitter once here, at the single
    // guest-facing sleep entry, so both the managed-thread park and the
    // single-threaded clock jump below sleep to the same inflated deadline. The
    // draw is owned by the deterministic context (seeded, replayed), so the
    // jittered deadline reproduces exactly. `with_context_raw` avoids taking an
    // extra scheduling point, leaving unjittered runs byte-for-byte unchanged.
    let deadline_nanos =
        match with_context_raw(|context| Ok(context.apply_sleep_jitter(deadline_nanos))) {
            Ok(deadline) => deadline,
            Err(errno) => return fail(errno),
        };
    // With managed threads, a sleep parks on the virtual-clock timer queue so
    // other runnable tasks execute while it sleeps and the clock advances only
    // through the deadlock rescue. A single-threaded program (thread subsystem
    // never activated) keeps the direct clock jump, which is identical.
    // SAFETY: the caller supplies the optional remaining-time buffer.
    if let Some(result) = unsafe { thread::managed_sleep(clock, deadline_nanos, remaining) } {
        return if result == 0 {
            set_errno(0);
            0
        } else {
            fail(result)
        };
    }
    match with_context(|context| context.sleep_until(clock, deadline_nanos)) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// The process's virtual CPU time in nanoseconds, backing the Darwin resource
/// accounting interposers (`getrusage`/`task_info`): the modeled startup cost
/// plus what the advance-on-spin rescue charged its tasks
/// (`Context::cpu_time_nanos`; the Linux rows read it through `clocks`). Read UNRECORDED, so this read
/// emits no trace op and takes no scheduling point; the value is a pure
/// function of the recorded stream.
///
/// Always succeeds writing a value. Before the runtime is installed (a custom
/// allocator's bootstrap timing, or a binary run outside the supervisor) it
/// reports a deterministic 0 rather than auto-installing: a resource read must
/// never be the thing that forces runtime init, mirroring [`patina_clock_now`]'s
/// bootstrap leg. It does still abort when initialization has already FAILED —
/// answering 0 there would hand the guest a fabricated value for a run that was
/// refused (see [`in_shim_bootstrap`]).
///
/// # Safety
/// `nanos` must be non-null and writable for one `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_cpu_time_nanos(nanos: *mut u64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if nanos.is_null() {
        return fail(EINVAL);
    }
    // Bootstrap window / no runtime installed: a deterministic zero (see
    // `patina_clock_now`). Never routes through `ensure_runtime`, so an
    // accounting probe cannot trip an auto-install or abort.
    let value = if in_shim_bootstrap() {
        0
    } else {
        with_context_raw(|context| Ok(context.cpu_time_nanos())).unwrap_or(0)
    };
    // SAFETY: `nanos` was checked non-null and is writable per the C ABI.
    unsafe { nanos.write(value) };
    set_errno(0);
    0
}

/// Bind a driver handle the filesystem just opened to a guest number. A table
/// full (`EMFILE`) closes the handle again — through the recorded close, as the
/// kernel's `fd_install` failure path releases the file — so nothing leaks.
fn bind_fs_handle(fd: Fd, kind: FdKind, status: u32, cloexec: bool) -> c_int {
    match install_fd(kind, fd.0, status, cloexec) {
        Ok(number) => {
            set_errno(0);
            number
        }
        Err(errno) => {
            let _ = with_context(|context| context.fs_close(fd));
            fail(errno)
        }
    }
}

/// The deny an `O_PATH|O_NOFOLLOW` open of a SYMLINK gets — the one spelling
/// that names the link entry itself, which the deterministic filesystem has no
/// descriptor for. One string, emitted from the one open entry both doors call,
/// so a raw-syscall guest and a libc guest record the same captured stderr.
pub(crate) const DENY_O_PATH_SYMLINK: &str = "patina: O_PATH|O_NOFOLLOW on a symlink is not modeled (the deterministic \
     filesystem has no descriptor for a link entry); failing closed\n";

/// A soft, diagnostic deny: the line goes to the CAPTURED stderr (the recorded
/// stream) and the call answers `ENOSYS`, exactly as the C `patina_posix_deny`
/// and the SUD `sud_deny` do.
fn deny(message: &str) -> c_int {
    // SAFETY: a byte slice handed to the captured-stderr entry.
    let _ = unsafe { patina_stdio_write(2, message.as_ptr().cast(), message.len()) };
    fail(ENOSYS)
}

/// `openat(2)` over the deterministic filesystem: resolve `(dirfd, path)`
/// through the one resolver, then open what it names. Every success is a fresh
/// guest number from the descriptor table (lowest free, `EMFILE` past
/// `RLIMIT_NOFILE`), and the entry's KIND decides the description: a regular
/// file, a directory (whether or not `O_DIRECTORY` asked for one — the kernel
/// hands back a directory descriptor for `open(dir, O_RDONLY)` too, and it is
/// what `fchdir`, `*at` resolution and `getdents` key off), an `O_PATH`
/// location, the `/dev/urandom` device, or a FIFO's pipe endpoint.
///
/// `O_NOFOLLOW` leaves a trailing symlink unresolved, which is then `ELOOP`
/// (`cap-primitives` keys its manual symlink walk off it, and std's
/// `remove_dir_all` reads it as "not a directory"); the one exception is
/// `O_PATH|O_NOFOLLOW`, the spelling that names the link ENTRY, which has no
/// descriptor here and is a named deny. `O_DIRECTORY` on anything but a
/// directory is `ENOTDIR`; a write-mode open of a directory is `EISDIR`.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_openat(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    mode: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the caller.
    unsafe { open_at(dirfd, path, flags, mode, 0) }
}

/// `openat2(2)` past its `struct open_how` checks: [`patina_openat`] with the
/// resolution confined by `resolve`, `PATINA_RESOLVE_*` restriction bits
/// (`paths::RESOLVE_SCOPE_FLAGS`); any other bit is `EINVAL`.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_openat2(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    mode: u32,
    resolve: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if resolve & !paths::RESOLVE_SCOPE_FLAGS != 0 {
        return fail(EINVAL);
    }
    // SAFETY: forwarded from the caller.
    unsafe { open_at(dirfd, path, flags, mode, resolve) }
}

/// The one open behind [`patina_openat`] and `patina_openat2`.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
unsafe fn open_at(dirfd: c_int, path: *const c_char, flags: u32, mode: u32, scope: u32) -> c_int {
    if flags & !O_ALL != 0 {
        return fail(EINVAL);
    }
    // `O_CREAT|O_DIRECTORY` names no open (Linux `build_open_flags`, XNU
    // `open1`); under `O_PATH` the creating flag was never read.
    if flags & (O_CREATE | O_DIRECTORY | O_PATH) == O_CREATE | O_DIRECTORY {
        return fail(EINVAL);
    }
    if scope & paths::RESOLVE_CACHED != 0
        && flags & O_PATH == 0
        && flags & (O_CREATE | O_TRUNCATE) != 0
    {
        return fail(EWOULDBLOCK);
    }
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let nofollow = flags & O_NOFOLLOW != 0;
    let nonblocking = flags & O_NONBLOCK != 0;
    let path_only = flags & O_PATH != 0;
    let cloexec = flags & O_CLOEXEC != 0;
    let directory = flags & O_DIRECTORY != 0;
    let creating = flags & O_CREATE != 0 && !path_only;
    let resolved = match paths::resolve(
        dirfd,
        &path,
        scope | if nofollow { paths::RESOLVE_NOFOLLOW } else { 0 },
    ) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    // The description's status flags as `F_GETFL` reports them: the access
    // mode, `O_APPEND`, `O_NONBLOCK`; an `O_PATH` description carries only
    // `O_PATH` (the kernel reads no access mode under it).
    let status = if path_only {
        O_PATH
    } else {
        (flags & (O_READ | O_WRITE | O_APPEND | O_NONBLOCK)) | O_OPENED
    };
    let kind = if path_only {
        FdKind::OPath
    } else {
        FdKind::File
    };
    let open_flags = OpenFlags {
        // Under `O_PATH` the kernel reads no access mode and creates nothing,
        // so neither does this: a path-only open is exactly one thing.
        read: flags & O_READ != 0 && !path_only,
        write: flags & O_WRITE != 0 && !path_only,
        create: creating,
        truncate: flags & O_TRUNCATE != 0 && !path_only,
        append: flags & O_APPEND != 0 && !path_only,
        exclusive: flags & O_EXCLUSIVE != 0 && !path_only,
        path_only,
        // POSIX reads `open`'s third argument only when the call can create the
        // entry; recording anything else here would put an argument in the trace
        // the kernel never looked at. Callers pass 0 without `O_CREAT`. The
        // process umask is applied HERE, where a kernel applies it, so the
        // driver stores — and the trace records — the mode the kernel would.
        mode: if creating {
            (mode & 0o7777) & !paths::umask()
        } else {
            0
        },
    };
    if paths::is_urandom(&resolved.path) {
        if open_flags.read
            && !open_flags.write
            && !open_flags.create
            && !open_flags.truncate
            && !open_flags.append
            && !open_flags.exclusive
        {
            return match install_fd(FdKind::Urandom, 0, O_READ | O_OPENED, cloexec) {
                Ok(number) => {
                    set_errno(0);
                    number
                }
                Err(errno) => fail(errno),
            };
        }
        return fail(EACCES);
    }
    let writes = open_flags.write
        || open_flags.create
        || open_flags.truncate
        || open_flags.append
        || open_flags.exclusive;
    let entry = resolved.metadata.map(|metadata| metadata.kind);
    match entry {
        // Reachable only under `O_NOFOLLOW` (the resolver followed otherwise).
        Some(FsEntryKind::Symlink) => {
            if path_only {
                return deny(DENY_O_PATH_SYMLINK);
            }
            fail(ELOOP)
        }
        Some(FsEntryKind::Directory) => {
            // `O_PATH` opens nothing, so the kernel ignores the access mode
            // under it; a plain directory open must be read-only. The two cost
            // different things (nothing vs `r`), which is why they are two
            // driver opens.
            if !path_only && writes {
                return fail(EISDIR);
            }
            let (dir_flags, dir_status) = if path_only {
                (OpenFlags::path_only(), O_PATH)
            } else {
                (OpenFlags::read_only(), O_READ | O_OPENED)
            };
            match with_context(|context| context.fs_open(&resolved.path, dir_flags)) {
                Ok(fd) => bind_fs_handle(fd, FdKind::Dir, dir_status, cloexec),
                Err(errno) => fail(errno),
            }
        }
        Some(
            FsEntryKind::File | FsEntryKind::Fifo | FsEntryKind::Socket | FsEntryKind::CharDevice,
        ) if directory => fail(ENOTDIR),
        None if directory => fail(ENOENT),
        Some(FsEntryKind::Fifo) => {
            // A FIFO has no filesystem descriptor, because its bytes are not
            // filesystem state. The driver still judges existence, resolution
            // AND permissions — and then declines to hand back a descriptor
            // (`EINVAL`), which is the seam where the pipe rendezvous begins.
            // Only an `O_PATH` open of a FIFO is a filesystem descriptor.
            match with_context(|context| context.fs_open(&resolved.path, open_flags)) {
                Ok(fd) => bind_fs_handle(fd, kind, status, cloexec),
                Err(errno) if errno == EINVAL && !path_only => thread::fifo_open(
                    resolved.metadata.expect("a FIFO entry has metadata").ino,
                    open_flags.read,
                    open_flags.write,
                    nonblocking,
                    status,
                    cloexec,
                ),
                Err(errno) => fail(errno),
            }
        }
        // A socket node or a whiteout has nothing behind it: past the
        // driver's existence and permission answers, and short of an `O_PATH`
        // descriptor, the open is the `ENXIO` the kernel's does (a socket
        // inode's `sock_no_open`, a device number no driver serves).
        Some(FsEntryKind::Socket | FsEntryKind::CharDevice) => {
            match with_context(|context| context.fs_open(&resolved.path, open_flags)) {
                Ok(fd) => bind_fs_handle(fd, kind, status, cloexec),
                Err(errno) if errno == EINVAL && !path_only => fail(ENXIO),
                Err(errno) => fail(errno),
            }
        }
        Some(FsEntryKind::File) | None => {
            match with_context(|context| context.fs_open(&resolved.path, open_flags)) {
                Ok(fd) => {
                    // An `O_TRUNC` open of a mapped file empties its page cache.
                    #[cfg(target_os = "linux")]
                    if let (true, Some(metadata)) = (open_flags.truncate, resolved.metadata) {
                        mem::resized_ino(metadata.ino, 0);
                    }
                    bind_fs_handle(fd, kind, status, cloexec)
                }
                Err(errno) => fail(errno),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The descriptor table's C face. `patina_fd_kind` is the ONE kind oracle the C
// interposers and the SUD rows consult when an answer depends on what a number
// names (a socket op on a file is ENOTSOCK, a `*at` dirfd must be a directory,
// mmap of a pipe is ENODEV); everything else about a descriptor — its
// FD_CLOEXEC bit, its status flags, duplication, closing — is answered here so
// the two doors cannot drift.

/// The `PATINA_FD_*` kind of a guest descriptor, or -1 with `EBADF` for a
/// number that names nothing.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fd_kind(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match fd_table().lock().kind(raw_fd) {
        Some(kind) => {
            set_errno(0);
            kind.wire()
        }
        None => fail(EBADF),
    }
}

/// `RLIMIT_NOFILE` as the table enforces it — the one number `getrlimit`,
/// `sysconf(_SC_OPEN_MAX)` and the `EMFILE` bound must agree on.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fd_limit() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    c_int::try_from(fd_limit()).expect("the descriptor limit fits an int")
}

/// The descriptor table's bound now: the soft `RLIMIT_NOFILE`.
pub(crate) fn fd_limit() -> usize {
    fd_table().lock().limit()
}

/// A new soft `RLIMIT_NOFILE` (`src/limits.rs`), which the table enforces
/// from the next allocation on; descriptors above it stay open.
#[cfg(target_os = "linux")]
pub(crate) fn set_fd_limit(limit: u64) {
    fd_table()
        .lock()
        .set_limit(usize::try_from(limit).unwrap_or(usize::MAX));
}

/// `F_GETFD`: 1 when the number carries `FD_CLOEXEC`, 0 when not, -1/`EBADF`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fd_getfd(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match fd_table().lock().cloexec(raw_fd) {
        Ok(cloexec) => {
            set_errno(0);
            c_int::from(cloexec)
        }
        Err(errno) => fail(errno),
    }
}

/// `F_SETFD`: set (nonzero) or clear the number's `FD_CLOEXEC` bit.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fd_setfd(raw_fd: c_int, cloexec: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match fd_table().lock().set_cloexec(raw_fd, cloexec != 0) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `F_GETFL`: the description's status flags in the `PATINA_O_*` vocabulary
/// (access mode, `O_APPEND`, `O_NONBLOCK`, `O_PATH`), or -1/`EBADF`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fd_getfl(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match resolve_fd(raw_fd) {
        Ok(resolved) => {
            set_errno(0);
            c_int::try_from(resolved.status).unwrap_or_else(|_| fail(EOVERFLOW))
        }
        Err(errno) => fail(errno),
    }
}

/// `F_SETFL`: replace the description's `O_APPEND`/`O_NONBLOCK` with the bits
/// in `flags` (`PATINA_O_*`); every other bit is ignored, as the kernel ignores
/// the access mode and creation flags in an `F_SETFL` argument.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fd_setfl(raw_fd: c_int, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match fd_table().lock().set_status(raw_fd, O_SETFL_MASK, flags) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `ioctl(FIONBIO)` / `SOCK_NONBLOCK` on accept: set or clear `O_NONBLOCK`
/// alone, leaving the other status flags as they are.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fd_set_nonblocking(raw_fd: c_int, nonblocking: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let bits = if nonblocking != 0 { O_NONBLOCK } else { 0 };
    match fd_table().lock().set_status(raw_fd, O_NONBLOCK, bits) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `dup(2)`: the lowest free number, sharing `fd`'s description, without
/// `FD_CLOEXEC`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_dup(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    patina_dupfd(raw_fd, 0, 0)
}

/// `fcntl(F_DUPFD)` / `F_DUPFD_CLOEXEC`: the lowest free number at or above
/// `minimum`. `EINVAL` for a minimum outside the table, `EMFILE` when nothing
/// at or above it is free.
#[unsafe(no_mangle)]
pub extern "C" fn patina_dupfd(raw_fd: c_int, minimum: c_int, cloexec: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match fd_table().lock().dup(raw_fd, minimum, cloexec != 0) {
        Ok(number) => {
            set_errno(0);
            number
        }
        Err(errno) => fail(errno),
    }
}

/// `dup2(2)`: `dup3(old, new, 0)`, except that equal numbers validate `old`
/// and return it unchanged (where `dup3` is `EINVAL`).
#[unsafe(no_mangle)]
pub extern "C" fn patina_dup2(oldfd: c_int, newfd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if oldfd == newfd {
        return match resolve_fd(oldfd) {
            Ok(_) => {
                set_errno(0);
                newfd
            }
            Err(errno) => fail(errno),
        };
    }
    patina_dup3(oldfd, newfd, 0)
}

/// `dup3(2)`: bind `newfd` to `oldfd`'s description, closing whatever `newfd`
/// named first. Equal numbers are `EINVAL`; a target outside the table is
/// `EBADF`. An error from closing the old target is not reported, as the kernel
/// does not report it.
#[unsafe(no_mangle)]
pub extern "C" fn patina_dup3(oldfd: c_int, newfd: c_int, cloexec: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let released = match fd_table().lock().dup3(oldfd, newfd, cloexec != 0) {
        Ok(released) => released,
        Err(errno) => return fail(errno),
    };
    retire_number(newfd);
    if let Some(release) = released {
        let _ = release_description(release);
    }
    set_errno(0);
    newfd
}

/// Per-NUMBER teardown when a slot is vacated (close, dup2/dup3 over it,
/// close_range): the state the two doors key by guest number rather than by
/// description — the SUD `getdents64` snapshot on Linux, the kqueue knotes
/// (which BSD drops when the NUMBER closes, whatever the file's other
/// references) on macOS.
fn retire_number(raw_fd: c_int) {
    #[cfg(target_os = "linux")]
    crate::sud::release_dir_iteration(raw_fd);
    #[cfg(target_os = "macos")]
    thread::kqueue_forget_number(raw_fd);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = raw_fd;
}

/// `close(2)`: free the number; the description is freed with its last number.
/// `EBADF` for a number that names nothing.
#[unsafe(no_mangle)]
pub extern "C" fn patina_close(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let released = match fd_table().lock().close(raw_fd) {
        Ok(released) => released,
        Err(errno) => return fail(errno),
    };
    retire_number(raw_fd);
    let result = match released {
        Some(release) => release_description(release),
        None => Ok(()),
    };
    match result {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `close_range(2)`: close every number in `[first, last]`, or with
/// `CLOSE_RANGE_CLOEXEC` mark them close-on-exec instead. `first > last` or an
/// unknown flag is `EINVAL`; the range is clamped to the table.
#[unsafe(no_mangle)]
pub extern "C" fn patina_close_range(first: u32, last: u32, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let closed = match fd_table().lock().close_range(first, last, flags) {
        Ok(closed) => closed,
        Err(errno) => return fail(errno),
    };
    for (number, release) in closed {
        retire_number(number);
        if let Some(release) = release {
            let _ = release_description(release);
        }
    }
    set_errno(0);
    0
}

// ---------------------------------------------------------------------------
// The universal descriptor operations. Each resolves the guest number ONCE and
// dispatches on what it names; a kind that has no such operation answers what
// the kernel answers for it. These are the entries the C `read`/`write`/... and
// the SUD rows call, so the two doors share one decode.

fn fs_read(fd: Fd, destination: *mut c_void, length: usize) -> isize {
    #[cfg(target_os = "linux")]
    mem::reading(fd.0);
    match with_context(|context| context.fs_read(fd, length)) {
        Ok(bytes) => {
            if !bytes.is_empty() {
                // SAFETY: the caller's C ABI contract makes `destination`
                // writable for `length` bytes, and `bytes.len() <= length`.
                unsafe {
                    slice::from_raw_parts_mut(destination.cast::<u8>(), length)[..bytes.len()]
                        .copy_from_slice(&bytes);
                }
            }
            isize::try_from(bytes.len()).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        Err(errno) => fail(errno) as isize,
    }
}

/// The guest's standard input: EOF, deterministically. Still a boundary call
/// (a scheduling point), as a captured-stdio write is. A `--stdin` knob feeding
/// bytes here is a later slice; the registry row's reasoning names it.
fn stdin_read() -> isize {
    if let Err(errno) = thread::sched_point() {
        return fail(errno) as isize;
    }
    set_errno(0);
    0
}

/// Read bytes into caller-owned memory.
///
/// # Safety
/// `destination` must be writable for `length` bytes when nonzero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_read(
    raw_fd: c_int,
    destination: *mut c_void,
    length: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if length != 0 && destination.is_null() {
        return fail(EINVAL) as isize;
    }
    let resolved = match resolve_fd(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno) as isize,
    };
    let nonblocking = resolved.status & O_NONBLOCK != 0;
    // SAFETY: forwarded from this function's own contract.
    unsafe { read_resolved(resolved, destination, length, nonblocking) }
}

/// The transfer `read(2)` makes on what a number names, by kind. `nonblocking`
/// is the call's own answer to "may this wait": the description's `O_NONBLOCK`,
/// or a vectored read that already has bytes in hand.
///
/// # Safety
/// `destination` must be writable for `length` bytes when nonzero.
unsafe fn read_resolved(
    resolved: Resolved,
    destination: *mut c_void,
    length: usize,
    nonblocking: bool,
) -> isize {
    match resolved.kind {
        FdKind::Stdin => stdin_read(),
        // The captured streams are write-only, like the pipe a supervisor
        // hands a child.
        FdKind::Stdout | FdKind::Stderr => fail(EBADF) as isize,
        FdKind::File | FdKind::Dir | FdKind::OPath => {
            fs_read(Fd(resolved.handle), destination, length)
        }
        FdKind::Urandom => {
            // SAFETY: forwarded from this function's own contract.
            let result = unsafe { patina_entropy(destination, length) };
            if result == 0 {
                isize::try_from(length).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
            } else {
                fail(patina_errno()) as isize
            }
        }
        // SAFETY: forwarded from this function's own contract.
        FdKind::Socket => unsafe {
            thread::net::socket_read(resolved.handle, nonblocking, destination, length)
        },
        // SAFETY: as above.
        FdKind::Pipe => unsafe {
            thread::pipe_read(resolved.handle, nonblocking, destination, length)
        },
        // SAFETY: as above.
        #[cfg(target_os = "linux")]
        FdKind::SignalFd => unsafe {
            thread::signals::fd::read(resolved.handle, nonblocking, destination, length)
        },
        #[cfg(target_os = "linux")]
        FdKind::EventFd => unsafe {
            thread::eventfd_read(resolved.handle, nonblocking, destination, length)
        },
        #[cfg(target_os = "linux")]
        FdKind::TimerFd => {
            thread::timers::timerfd_read(resolved.handle, nonblocking, destination as usize, length)
        }
        #[cfg(target_os = "linux")]
        FdKind::Epoll => fail(EINVAL) as isize,
        // SAFETY: forwarded from this function's own contract.
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue if resolved.status & O_READ != 0 => unsafe {
            thread::ipc::mq_read(resolved.handle, destination, length, None)
        },
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue => fail(EBADF) as isize,
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => fail(EINVAL) as isize,
    }
}

fn fs_write(fd: Fd, source: *const c_void, length: usize) -> isize {
    let bytes = if length == 0 {
        &[]
    } else {
        // SAFETY: the caller's C ABI contract makes `source` readable for
        // `length` bytes.
        unsafe { slice::from_raw_parts(source.cast::<u8>(), length) }
    };
    match with_context(|context| context.fs_write(fd, bytes)) {
        Ok(written) => {
            #[cfg(target_os = "linux")]
            mem::written_at_cursor(fd.0, &bytes[..written.min(bytes.len())]);
            isize::try_from(written).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        Err(errno) => fail(errno) as isize,
    }
}

/// Write bytes from caller-owned memory.
///
/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_write(
    raw_fd: c_int,
    source: *const c_void,
    length: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if length != 0 && source.is_null() {
        return fail(EINVAL) as isize;
    }
    let resolved = match resolve_fd(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno) as isize,
    };
    let nonblocking = resolved.status & O_NONBLOCK != 0;
    // SAFETY: forwarded from this function's own contract.
    unsafe { write_resolved(resolved, source, length, nonblocking) }
}

/// The transfer `write(2)` makes on what a number names, by kind; see
/// [`read_resolved`] for `nonblocking`.
///
/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
unsafe fn write_resolved(
    resolved: Resolved,
    source: *const c_void,
    length: usize,
    nonblocking: bool,
) -> isize {
    match resolved.kind {
        FdKind::Stdin | FdKind::Urandom => fail(EBADF) as isize,
        // SAFETY: forwarded from this function's own contract.
        FdKind::Stdout | FdKind::Stderr => unsafe {
            patina_stdio_write(resolved.handle as c_int, source, length)
        },
        FdKind::File | FdKind::Dir | FdKind::OPath => fs_write(Fd(resolved.handle), source, length),
        // SAFETY: forwarded from this function's own contract.
        FdKind::Socket => unsafe {
            thread::net::socket_write(resolved.handle, nonblocking, source, length)
        },
        // SAFETY: as above.
        FdKind::Pipe => unsafe {
            thread::pipe_write(resolved.handle, nonblocking, source, length, false)
        },
        // SAFETY: as above.
        #[cfg(target_os = "linux")]
        FdKind::EventFd => unsafe { thread::eventfd_write(resolved.handle, source, length) },
        #[cfg(target_os = "linux")]
        FdKind::Epoll | FdKind::SignalFd | FdKind::TimerFd => fail(EINVAL) as isize,
        // A queue file has no write method: EBADF without write access, EINVAL
        // with it.
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue if resolved.status & O_WRITE == 0 => fail(EBADF) as isize,
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue => fail(EINVAL) as isize,
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => fail(EINVAL) as isize,
    }
}

/// What a positional transfer may address: the driver handle of a regular
/// file, in the kernel's order of refusals (`ksys_pread64`/`ksys_pwrite64`):
/// a negative position is `EINVAL` before the descriptor is looked at, an
/// empty slot or an `O_PATH` descriptor is `EBADF` (`fdget`), and a
/// description without offset addressing (a pipe, a socket, the captured
/// streams) is `ESPIPE`. A directory is addressable — its refusal is the read
/// itself (`EISDIR`), or the write mode it was never opened with (`EBADF`).
fn positional_target(raw_fd: c_int, offset: i64) -> Result<(Resolved, u64), c_int> {
    let Ok(offset) = u64::try_from(offset) else {
        return Err(EINVAL);
    };
    let resolved = fdget(raw_fd)?;
    match resolved.kind {
        // An mqueue file is positioned (it reads its status line).
        FdKind::File | FdKind::Dir => Ok((resolved, offset)),
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue => Ok((resolved, offset)),
        FdKind::OPath
        | FdKind::Stdin
        | FdKind::Stdout
        | FdKind::Stderr
        | FdKind::Urandom
        | FdKind::Socket
        | FdKind::Pipe => Err(ESPIPE),
        #[cfg(target_os = "linux")]
        FdKind::EventFd | FdKind::Epoll | FdKind::SignalFd | FdKind::TimerFd => Err(ESPIPE),
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => Err(ESPIPE),
    }
}

/// # Safety
/// `destination` must be writable for `length` bytes when nonzero.
unsafe fn fs_pread(
    resolved: Resolved,
    destination: *mut c_void,
    length: usize,
    offset: u64,
) -> isize {
    if resolved.status & O_READ == 0 {
        return fail(EBADF) as isize;
    }
    if resolved.kind == FdKind::Dir {
        return fail(EISDIR) as isize;
    }
    #[cfg(target_os = "linux")]
    if resolved.kind == FdKind::MessageQueue {
        // SAFETY: forwarded from this function's own contract.
        return unsafe { thread::ipc::mq_read(resolved.handle, destination, length, Some(offset)) };
    }
    #[cfg(target_os = "linux")]
    mem::reading(resolved.handle);
    match with_context(|context| context.fs_read_at(Fd(resolved.handle), offset, length)) {
        Ok(bytes) => {
            if !bytes.is_empty() {
                // SAFETY: Guaranteed by this function's contract.
                unsafe {
                    slice::from_raw_parts_mut(destination.cast::<u8>(), length)[..bytes.len()]
                        .copy_from_slice(&bytes);
                }
            }
            isize::try_from(bytes.len()).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        Err(errno) => fail(errno) as isize,
    }
}

/// Positional read (`pread`): read at `offset` without moving the file cursor;
/// see [`positional_target`] for the refusals.
///
/// # Safety
/// `destination` must be writable for `length` bytes when nonzero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_pread(
    raw_fd: c_int,
    destination: *mut c_void,
    length: usize,
    offset: i64,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (resolved, offset) = match positional_target(raw_fd, offset) {
        Ok(target) => target,
        Err(errno) => return fail(errno) as isize,
    };
    if length != 0 && destination.is_null() {
        return fail(EFAULT) as isize;
    }
    // SAFETY: forwarded from this function's own contract.
    unsafe { fs_pread(resolved, destination, length, offset) }
}

/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
unsafe fn fs_pwrite(handle: Fd, source: *const c_void, length: usize, offset: i64) -> isize {
    let offset = match u64::try_from(offset) {
        Ok(offset) => offset,
        Err(_) => return fail(EINVAL) as isize,
    };
    let bytes = if length == 0 {
        &[]
    } else {
        // SAFETY: Guaranteed by this function's contract.
        unsafe { slice::from_raw_parts(source.cast::<u8>(), length) }
    };
    match with_context(|context| context.fs_write_at(handle, offset, bytes)) {
        Ok(written) => {
            #[cfg(target_os = "linux")]
            mem::written(handle.0, offset, &bytes[..written.min(bytes.len())]);
            isize::try_from(written).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        Err(errno) => fail(errno) as isize,
    }
}

/// Where a positional write lands. On Linux a write through an `O_APPEND`
/// description goes to the end of the file whatever the position (pwrite(2)
/// BUGS: `generic_write_checks` sets the position to `i_size` under
/// `IOCB_APPEND`), and so does one carrying `RWF_APPEND`; the file's cursor
/// stays where it was either way. Darwin's `pwrite` writes at the position.
fn positional_write_offset(resolved: Resolved, offset: u64, append: bool) -> Result<u64, c_int> {
    let append = append || (cfg!(target_os = "linux") && resolved.status & O_APPEND != 0);
    if !append || resolved.kind != FdKind::File {
        return Ok(offset);
    }
    with_context(|context| context.fs_fd_metadata(Fd(resolved.handle))).map(|metadata| metadata.len)
}

/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
unsafe fn fs_pwrite_resolved(
    resolved: Resolved,
    source: *const c_void,
    length: usize,
    offset: u64,
    append: bool,
) -> isize {
    if resolved.status & O_WRITE == 0 {
        return fail(EBADF) as isize;
    }
    let offset = if length == 0 {
        offset
    } else {
        match positional_write_offset(resolved, offset, append) {
            Ok(offset) => offset,
            Err(errno) => return fail(errno) as isize,
        }
    };
    let Ok(offset) = i64::try_from(offset) else {
        return fail(EFBIG) as isize;
    };
    // SAFETY: forwarded from this function's own contract.
    unsafe { fs_pwrite(Fd(resolved.handle), source, length, offset) }
}

/// Positional write (`pwrite`): write at `offset` without moving the file
/// cursor; see [`positional_target`] for the refusals and
/// [`positional_write_offset`] for `O_APPEND`.
///
/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_pwrite(
    raw_fd: c_int,
    source: *const c_void,
    length: usize,
    offset: i64,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (resolved, offset) = match positional_target(raw_fd, offset) {
        Ok(target) => target,
        Err(errno) => return fail(errno) as isize,
    };
    if length != 0 && source.is_null() {
        return fail(EFAULT) as isize;
    }
    // SAFETY: forwarded from this function's own contract.
    unsafe { fs_pwrite_resolved(resolved, source, length, offset, false) }
}

/// `LOCK_SH`/`LOCK_EX`/`LOCK_NB`/`LOCK_UN` from `<sys/file.h>` — identical values
/// on Linux and Darwin.
const LOCK_SH: c_int = 1;
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const LOCK_UN: c_int = 8;

/// Advisory whole-file lock — the interposed `flock` in `c/patina_posix.c` and
/// the SUD `flock` row. A single-opener database (via std `File::try_lock`)
/// takes one `LOCK_EX | LOCK_NB` on open; a lone opener always acquires it.
///
/// The lock belongs to the open file DESCRIPTION and is keyed on the
/// deterministic-fs inode it is open on, so two independent opens of the *same*
/// path contend faithfully: a non-blocking request that would collide with an
/// incompatible lock held on another description reports `EWOULDBLOCK` (a
/// single-opener database surfaces this as an "already open" error), while a
/// `dup` of the holder shares the lock and can release it. `LOCK_SH` conflicts
/// only with a held `LOCK_EX`; `LOCK_EX` conflicts with any held lock.
/// Re-locking or upgrading on the *same* description is always allowed (it
/// replaces that description's entry and never self-conflicts). The lock clears
/// on `LOCK_UN` and when the description's last number closes.
///
/// A *blocking* request that would contend fails closed with `EDEADLK` rather
/// than parking a real thread — the single-baton scheduler does not model
/// advisory-lock waiting, and no supported guest blocks on a contended `flock`
/// (std's `File::try_lock*` is always `LOCK_NB`).
///
/// The refusals come in the kernel's order (`fs/locks.c`): on Linux a request
/// carrying `LOCK_MAND` answers 0 and is ignored before anything else is looked
/// at (Linux 5.19+), an unknown operation is `EINVAL` before the descriptor,
/// and an empty slot or an `O_PATH` descriptor is `EBADF` (`fdget`).
#[unsafe(no_mangle)]
pub extern "C" fn patina_flock(raw_fd: c_int, operation: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    if operation & linux_raw_sys::general::LOCK_MAND as c_int != 0 {
        set_errno(0);
        return 0;
    }
    let non_blocking = operation & LOCK_NB != 0;
    let mode = match operation & !LOCK_NB {
        LOCK_UN => None,
        LOCK_SH => Some(FlockMode::Shared),
        LOCK_EX => Some(FlockMode::Exclusive),
        _ => return fail(EINVAL),
    };
    let resolved = match fdget(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    let Some(mode) = mode else {
        flock_release(resolved.desc);
        set_errno(0);
        return 0;
    };
    // Resolve a file's inode through the recorded metadata path so the conflict
    // decision keys on the same file identity under record and replay.
    let identity = if resolved.kind.is_fs() {
        match with_context(|context| context.fs_fd_metadata(Fd(resolved.handle))) {
            Ok(metadata) => LockIdentity::Inode(metadata.ino),
            Err(errno) => return fail(errno),
        }
    } else {
        LockIdentity::Description(resolved.desc)
    };
    let mut table = flock_table().lock();
    let conflict = table.iter().any(|(&holder, &(held_identity, held_mode))| {
        holder != resolved.desc
            && held_identity == identity
            && (mode == FlockMode::Exclusive || held_mode == FlockMode::Exclusive)
    });
    if conflict {
        drop(table);
        return if non_blocking {
            fail(EWOULDBLOCK)
        } else {
            fail(EDEADLK)
        };
    }
    table.insert(resolved.desc, (identity, mode));
    set_errno(0);
    0
}

/// `lseek(2)`: a file's cursor; a description without offset addressing is
/// `ESPIPE`.
///
/// On Linux a directory's position is its `getdents64` iteration, which both
/// doors read and move (`crate::sud::seek_dir_iteration`).
#[unsafe(no_mangle)]
pub extern "C" fn patina_seek(raw_fd: c_int, offset: i64, whence: u32) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let handle = match resolve_fd(raw_fd) {
        #[cfg(target_os = "linux")]
        Ok(resolved) if resolved.kind == FdKind::Dir => {
            return match crate::sud::seek_dir_iteration(raw_fd, offset, whence) {
                Some(position) => {
                    set_errno(0);
                    position as i64
                }
                None => i64::from(fail(EINVAL)),
            };
        }
        #[cfg(target_os = "linux")]
        Ok(resolved) if resolved.kind == FdKind::MessageQueue => {
            return match thread::ipc::mq_seek(resolved.handle, offset, whence) {
                Ok(position) => {
                    set_errno(0);
                    position
                }
                Err(errno) => i64::from(fail(errno)),
            };
        }
        Ok(resolved) if resolved.kind.is_fs() => Fd(resolved.handle),
        Ok(_) => return i64::from(fail(ESPIPE)),
        Err(errno) => return i64::from(fail(errno)),
    };
    let whence = match whence {
        0 => SeekWhence::Start,
        1 => SeekWhence::Current,
        2 => SeekWhence::End,
        _ => return i64::from(fail(EINVAL)),
    };
    match with_context(|context| context.fs_seek(handle, offset, whence)) {
        Ok(position) => i64::try_from(position).unwrap_or_else(|_| i64::from(fail(EOVERFLOW))),
        Err(errno) => i64::from(fail(errno)),
    }
}

/// `fsync(2)`: durability for a file (or a directory: the crash model's
/// namespace barrier); every other kind is `EINVAL`, as the kernel answers for
/// a pipe or a socket.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fsync(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let handle = match resolve_fd(raw_fd) {
        Ok(resolved) if resolved.kind.is_fs() => Fd(resolved.handle),
        Ok(_) => return fail(EINVAL),
        Err(errno) => return fail(errno),
    };
    match fs_sync_handle(handle) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// `fsync` of a filesystem handle: what shared mappings of its file stored is
/// written back first, so it becomes durable with the rest of the file.
fn fs_sync_handle(handle: Fd) -> Result<(), c_int> {
    #[cfg(target_os = "linux")]
    mem::syncing(handle.0)?;
    with_context(|context| context.fs_sync(handle))
}

/// `sync`/`syncfs` of the volume: every mapped file's stores are written back
/// first.
#[cfg(target_os = "linux")]
fn fs_sync_volume() -> Result<(), c_int> {
    mem::syncing_all()?;
    with_context(|context| context.fs_sync_all())
}

/// `ftruncate(2)`: a file's length; every other kind is `EINVAL`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_set_len(raw_fd: c_int, length: u64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let handle = match resolve_fd(raw_fd) {
        Ok(resolved) if resolved.kind.is_fs() => Fd(resolved.handle),
        Ok(_) => return fail(EINVAL),
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_set_len(handle, length)) {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            mem::resized(handle.0, length);
            0
        }
        Err(errno) => fail(errno),
    }
}

struct ReadDirState {
    entries: Vec<FsDirectoryEntry>,
    position: usize,
}

impl ReadDirState {
    /// A directory's listing as the kernel's `getdents64` reports it: `.` and
    /// `..` first, then the driver's entries.
    fn listing(listed: Vec<FsDirectoryEntry>) -> Self {
        let dots = [".", ".."].map(|name| FsDirectoryEntry {
            name: name.into(),
            kind: FsEntryKind::Directory,
        });
        ReadDirState {
            entries: dots.into_iter().chain(listed).collect(),
            position: 0,
        }
    }
}

/// The `PATINA_ENTRY_*` wire values (`include/patina_native.h`). The C side ORs
/// the corresponding `S_IF*` bit onto the entry's permission bits.
const PATINA_ENTRY_FILE: u32 = 1;
const PATINA_ENTRY_DIRECTORY: u32 = 2;
const PATINA_ENTRY_SYMLINK: u32 = 3;
const PATINA_ENTRY_FIFO: u32 = 4;
const PATINA_ENTRY_SOCKET: u32 = 5;
const PATINA_ENTRY_CHAR: u32 = 6;

fn metadata_kind(kind: FsEntryKind) -> u32 {
    match kind {
        FsEntryKind::File => PATINA_ENTRY_FILE,
        FsEntryKind::Directory => PATINA_ENTRY_DIRECTORY,
        FsEntryKind::Symlink => PATINA_ENTRY_SYMLINK,
        FsEntryKind::Fifo => PATINA_ENTRY_FIFO,
        FsEntryKind::Socket => PATINA_ENTRY_SOCKET,
        FsEntryKind::CharDevice => PATINA_ENTRY_CHAR,
    }
}

/// The `PATINA_FS_*` wire values: which filesystem a node is on. The
/// deterministic volume holds every entry a path can name; an anonymous pipe's
/// node is on pipefs and a socket's on sockfs, as on Linux.
const PATINA_FS_VOLUME: u32 = 0;
const PATINA_FS_PIPEFS: u32 = 1;
const PATINA_FS_SOCKFS: u32 = 2;

/// The `(major, minor)` device a `PATINA_FS_*` filesystem reports through
/// `st_dev`/`stx_dev_*` (`PATINA_*_DEV_*` in `patina_native.h`): the volume is
/// an ext4-like filesystem on block device 8:1, pipefs and sockfs anonymous
/// devices of their own.
#[cfg(target_os = "linux")]
pub(crate) fn fs_device(fs: u32) -> (u32, u32) {
    match fs {
        PATINA_FS_PIPEFS => (0, 14),
        PATINA_FS_SOCKFS => (0, 8),
        _ => (8, 1),
    }
}

/// The C face of a metadata record (`struct patina_metadata` in
/// `include/patina_native.h`): what the stat family on both doors fills a
/// `struct stat`/`struct statx` from. Every field is a modeled fact; the owner
/// is not here because it is a property of the one identity the runtime
/// models, read through [`patina_uid`]/[`patina_gid`], never per entry.
#[repr(C)]
pub struct PatinaMetadata {
    /// A `PATINA_ENTRY_*` kind.
    pub kind: u32,
    /// The permission bits (`0o7777`) WITHOUT the file-type bits `kind` carries.
    pub mode: u32,
    pub nlink: u32,
    /// The `PATINA_FS_*` filesystem the node is on, which decides the device
    /// `st_dev` reports.
    pub fs: u32,
    pub length: u64,
    pub ino: u64,
    pub atime_nanos: u64,
    pub mtime_nanos: u64,
    pub ctime_nanos: u64,
    pub btime_nanos: u64,
}

fn write_metadata(metadata: patina_dst_abi::FsMetadata, out: *mut PatinaMetadata) -> c_int {
    if out.is_null() {
        return fail(EINVAL);
    }
    // SAFETY: the pointer was checked and is required to be writable by the C
    // ABI contract.
    unsafe {
        out.write(PatinaMetadata {
            kind: metadata_kind(metadata.kind),
            mode: metadata.mode,
            nlink: metadata.nlink,
            fs: PATINA_FS_VOLUME,
            length: metadata.len,
            ino: metadata.ino,
            atime_nanos: metadata.atime_nanos,
            mtime_nanos: metadata.mtime_nanos,
            ctime_nanos: metadata.ctime_nanos,
            btime_nanos: metadata.btime_nanos,
        });
    }
    0
}

/// The guest's pid (`registry::IDENTITY_PID`): the one value `getpid`
/// answers on both doors.
#[unsafe(no_mangle)]
pub extern "C" fn patina_pid() -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    registry::IDENTITY_PID as i32
}

/// The guest's parent, the pid namespace's init (`registry::INIT_PID`).
#[unsafe(no_mangle)]
pub extern "C" fn patina_ppid() -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    registry::INIT_PID as i32
}

/// Who the caller is, to the rows both OSes answer (the owner `stat`
/// reports, `chown`, `SO_PEERCRED`, a signal's sender): on Linux the virtual
/// credential's ids and supplementary groups (`identity::credential`). macOS
/// has no credential yet; there the caller is the registry's fixed identity
/// in its own group alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Caller {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) groups: &'static [u32],
}

impl Caller {
    /// `in_group_p`: whether `gid` is the caller's group or one of its
    /// supplementary groups.
    pub(crate) fn in_group(&self, gid: u32) -> bool {
        gid == self.gid || self.groups.contains(&gid)
    }
}

/// The caller; see [`Caller`].
pub(crate) const fn caller() -> Caller {
    #[cfg(target_os = "linux")]
    {
        let credential = identity::credential();
        Caller {
            uid: credential.uid,
            gid: credential.gid,
            groups: credential.groups,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Caller {
            uid: registry::IDENTITY_UID,
            gid: registry::IDENTITY_GID,
            groups: &[registry::IDENTITY_GID],
        }
    }
}

/// The caller's user id ([`caller`]) — what every `st_uid`, the C
/// `getuid`/`geteuid`, and the ownership comparisons read. A guest reading
/// an owner reads this, never a per-entry field: the deterministic
/// filesystem stores no owner because every entry is the caller's.
#[unsafe(no_mangle)]
pub extern "C" fn patina_uid() -> u32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    caller().uid
}

/// Entry `index` of the virtual machine's passwd database
/// (`registry::PASSWD`, file order) as its `/etc/passwd` line, or NULL past
/// the last: what the C passwd readers answer from.
#[unsafe(no_mangle)]
pub extern "C" fn patina_passwd_line(index: u32) -> *const c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    usize::try_from(index)
        .ok()
        .and_then(|index| registry::PASSWD.get(index))
        .map_or(std::ptr::null(), |line| line.as_ptr())
}

/// The caller's group id; see [`patina_uid`].
#[unsafe(no_mangle)]
pub extern "C" fn patina_gid() -> u32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    caller().gid
}

/// The virtual machine's node name (`--hostname`), a recorded run fact that
/// both platforms' `uname` report: read from the installed runtime, which a
/// call before installation installs or, from a static constructor that ran
/// before Patina's, refuses by name — never a default a constructor could
/// cache for the whole run.
fn node_name() -> Result<String, c_int> {
    ensure_runtime()?;
    with_context_raw(|context| Ok(context.hostname().to_owned()))
}

/// `uname(3)` on Darwin: the virtual Darwin kernel's self-description
/// (`darwin_identity`) into the caller's `struct utsname`. 0, or -1 with
/// [`patina_errno`] (`EFAULT` for NULL).
///
/// # Safety
/// `out` must be NULL or writable for a Darwin `struct utsname`.
#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_uname(out: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if out.is_null() {
        return fail(EFAULT);
    }
    let name = match node_name() {
        Ok(name) => darwin_identity::describe(&name),
        Err(errno) => return fail(errno),
    };
    // SAFETY: `out` was checked non-null and is writable per this function's
    // contract.
    unsafe { out.cast::<darwin_identity::Utsname>().write_unaligned(name) };
    set_errno(0);
    0
}

/// Read the metadata of the entry `(dirfd, path)` resolves to: the one entry
/// behind `stat`, `lstat`, `fstatat`, `statx`, `access`, `statfs` and every
/// other by-path metadata read on both doors. `flags` are `PATINA_RESOLVE_*`:
/// `NOFOLLOW` names a trailing symlink itself (`lstat`, `AT_SYMLINK_NOFOLLOW`),
/// `EMPTY_PATH` lets an empty path name the base (`AT_EMPTY_PATH` on
/// `AT_FDCWD` is the working directory). Symlinks are walked to the kernel's
/// 40-hop limit. A missing entry is `ENOENT`.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string and `out` to a
/// writable `struct patina_metadata`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_metadata_at(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    out: *mut PatinaMetadata,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !paths::RESOLVE_AT_FLAGS != 0 {
        return fail(EINVAL);
    }
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let resolved = match paths::resolve(dirfd, &path, flags) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    let Some(metadata) = resolved.metadata else {
        return fail(ENOENT);
    };
    write_metadata(metadata, out)
}

/// Read full metadata for a deterministic descriptor.
///
/// # Safety
/// `out` must point to a writable `struct patina_metadata`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_fd_metadata_full(raw_fd: c_int, out: *mut PatinaMetadata) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // A FIFO descriptor is a pipe endpoint, not a filesystem descriptor: the
    // filesystem knows the ENTRY but holds no handle to ask about. What the
    // descriptor holds is the NODE, so the filesystem is asked about the inode —
    // which is what makes a `chmod` of the FIFO after the open visible here,
    // exactly as it is through a regular file's descriptor, and what makes a
    // hard-linked FIFO report its real link count.
    //
    // Unlinking the last name does not change that: the endpoint HOLDS a
    // reference on the node, so the filesystem still speaks for it and reports
    // `nlink` 0 with the live mode — which is exactly what a kernel reports for
    // an unlinked-but-open entry. There is no open-time copy to fall back to,
    // because a copy is a stale cache one field over from the cached path.
    if let Some(node) = thread::fifo_ino(raw_fd) {
        return match with_context(|context| context.fs_inode_metadata(node)) {
            Ok(metadata) => write_metadata(metadata, out),
            Err(errno) => fail(errno),
        };
    }
    // An anonymous pipe end or a socket is on pipefs/sockfs: its node is the
    // shim's own, and answers without a trip to the filesystem.
    if let Some(metadata) = thread::pipe_inode_metadata(raw_fd) {
        if out.is_null() {
            return fail(EINVAL);
        }
        // SAFETY: `out` was checked and is writable per the C ABI contract.
        unsafe { out.write(metadata) };
        set_errno(0);
        return 0;
    }
    let fd = match fs_handle(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_fd_metadata(fd)) {
        Ok(metadata) => write_metadata(metadata, out),
        Err(errno) => fail(errno),
    }
}

/// Change the permission bits of the entry `(dirfd, path)` names (`chmod` /
/// `fchmodat`). `flags` are `PATINA_RESOLVE_*`: without `NOFOLLOW` a trailing
/// symlink resolves and its TARGET changes (the `chmod` and flagless `fchmodat`
/// spellings); with it the link itself is named, which is `EOPNOTSUPP`
/// because Linux gives a symlink no mode of its own to change.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_chmod(
    dirfd: c_int,
    path: *const c_char,
    mode: u32,
    flags: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !paths::RESOLVE_AT_FLAGS != 0 {
        return fail(EINVAL);
    }
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let resolved = match paths::resolve(dirfd, &path, flags) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    match resolved.metadata.map(|metadata| metadata.kind) {
        None => return fail(ENOENT),
        Some(FsEntryKind::Symlink) => return fail(EOPNOTSUPP),
        Some(
            FsEntryKind::File
            | FsEntryKind::Directory
            | FsEntryKind::Fifo
            | FsEntryKind::Socket
            | FsEntryKind::CharDevice,
        ) => {}
    }
    match with_context(|context| context.fs_set_mode(&resolved.path, mode)) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Change the permission bits of the entry an open descriptor names (`fchmod`).
/// A descriptor already names the node, so there is no symlink to resolve.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fchmod(raw_fd: c_int, mode: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // A FIFO endpoint is a pipe, not a filesystem descriptor — so the bits it
    // changes are named by NODE, exactly as its `fstat` reads them by node. That
    // is what keeps `fchmod` working on an entry whose last name is gone.
    if let Some(node) = thread::fifo_ino(raw_fd) {
        return match with_context(|context| context.fs_set_inode_mode(node, mode)) {
            Ok(()) => {
                set_errno(0);
                0
            }
            Err(errno) => fail(errno),
        };
    }
    if thread::pipe_inode_set_mode(raw_fd, mode).is_some() {
        set_errno(0);
        return 0;
    }
    let fd = match fs_handle(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_set_fd_mode(fd, mode)) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

// ---------------------------------------------------------------------------
// Timestamps, ownership and sizes: the entries behind the utimensat, chown,
// truncate and fallocate families on both doors.

/// A time argument as the `utimensat` family spells it: leave the time alone.
pub const TIME_OMIT: u32 = 0;
/// Set the time to the virtual clock's now.
pub const TIME_NOW: u32 = 1;
/// Set the time to the nanoseconds given beside the kind.
pub const TIME_SET: u32 = 2;

/// Decode requests without sampling NOW; the runtime resolves it after latency.
fn resolve_time_arguments(
    atime_kind: u32,
    atime_nanos: u64,
    mtime_kind: u32,
    mtime_nanos: u64,
) -> Result<(patina_dst_runtime::FsTime, patina_dst_runtime::FsTime), c_int> {
    use patina_dst_runtime::FsTime;
    let pick = |kind, nanos| match kind {
        TIME_OMIT => Ok(FsTime::Omit),
        TIME_NOW => Ok(FsTime::Now),
        TIME_SET => Ok(FsTime::Nanos(nanos)),
        _ => Err(EINVAL),
    };
    Ok((
        pick(atime_kind, atime_nanos)?,
        pick(mtime_kind, mtime_nanos)?,
    ))
}

/// `utimensat(2)` on a `(dirfd, path)`: set the entry's access and
/// modification times (each `PATINA_TIME_OMIT`, `PATINA_TIME_NOW`, or
/// `PATINA_TIME_SET` with its nanoseconds); `ctime` moves whenever either does.
/// `flags` are `PATINA_RESOLVE_*` (`NOFOLLOW` sets a symlink's own times, as
/// `lutimes`/`AT_SYMLINK_NOFOLLOW` do). Both `OMIT` is the kernel's early
/// success: nothing crosses the boundary and no time moves. The one modeled
/// identity owns every entry, so the kernel's owner-or-`w` rule always passes.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn patina_utimensat(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    atime_kind: u32,
    atime_nanos: u64,
    mtime_kind: u32,
    mtime_nanos: u64,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    abort_if_init_failed();
    if atime_kind == TIME_OMIT && mtime_kind == TIME_OMIT {
        set_errno(0);
        return 0;
    }
    if flags & !paths::RESOLVE_AT_FLAGS != 0 {
        return fail(EINVAL);
    }
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let (atime, mtime) =
        match resolve_time_arguments(atime_kind, atime_nanos, mtime_kind, mtime_nanos) {
            Ok(times) => times,
            Err(errno) => return fail(errno),
        };
    if path.is_empty() && flags & paths::RESOLVE_EMPTY_PATH != 0 && dirfd != paths::AT_FDCWD {
        let descriptor = match resolve_fd(dirfd) {
            Ok(descriptor) => descriptor,
            Err(errno) => return fail(errno),
        };
        let ino = if let Some(ino) = thread::fifo_ino(dirfd) {
            ino
        } else if descriptor.kind.is_fs() {
            match with_context(|context| context.fs_fd_metadata(Fd(descriptor.handle))) {
                Ok(metadata) => metadata.ino,
                Err(errno) => return fail(errno),
            }
        } else {
            return deny(
                "patina: utimensat on a descriptor without a modeled inode; failing closed\n",
            );
        };
        return match with_context(|context| context.fs_set_inode_times_spec(ino, atime, mtime)) {
            Ok(()) => {
                set_errno(0);
                0
            }
            Err(errno) => fail(errno),
        };
    }
    let resolved = match paths::resolve(dirfd, &path, flags) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    if resolved.metadata.is_none() {
        return fail(ENOENT);
    }
    match with_context(|context| context.fs_set_times_by_path_spec(&resolved.path, atime, mtime)) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `futimens(3)` / `utimensat(fd, NULL, …)`: the same change, on the node an
/// open descriptor holds. An `O_PATH` descriptor is `EBADF` (the kernel's
/// `fdget` never hands one out for this call). A descriptor on something the
/// filesystem holds no node for refuses loudly. Named FIFO endpoints reach
/// their retained inode, including after unlink.
#[unsafe(no_mangle)]
pub extern "C" fn patina_futimens(
    raw_fd: c_int,
    atime_kind: u32,
    atime_nanos: u64,
    mtime_kind: u32,
    mtime_nanos: u64,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    abort_if_init_failed();
    if atime_kind == TIME_OMIT && mtime_kind == TIME_OMIT {
        set_errno(0);
        return 0;
    }
    let resolved = match resolve_fd(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    if resolved.kind == FdKind::OPath {
        return fail(EBADF);
    }
    let (atime, mtime) =
        match resolve_time_arguments(atime_kind, atime_nanos, mtime_kind, mtime_nanos) {
            Ok(times) => times,
            Err(errno) => return fail(errno),
        };
    if let Some(ino) = thread::fifo_ino(raw_fd) {
        return match with_context(|context| context.fs_set_inode_times_spec(ino, atime, mtime)) {
            Ok(()) => {
                set_errno(0);
                0
            }
            Err(errno) => fail(errno),
        };
    }
    if !resolved.kind.is_fs() {
        return deny("patina: futimens on a descriptor without a modeled inode; failing closed\n");
    }
    let fd = Fd(resolved.handle);
    match with_context(|context| context.fs_set_times_spec(fd, atime, mtime)) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `uid_t`/`gid_t` `-1`: leave the id alone.
const ID_UNCHANGED: u32 = u32::MAX;
const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
const S_IXGRP: u32 = 0o010;

/// The `chown` decision (`chown_ok`/`chgrp_ok`) for `caller`, who owns every
/// entry: a uid that is `-1` or the owner's, and a gid that is `-1` or one
/// of the caller's groups, are what the kernel lets an owner without
/// `CAP_CHOWN` ask for; anything else is `EPERM`. `Ok` carries the mode the
/// kernel would store afterwards — on a non-directory `chown` kills the
/// setuid bit and, when the group may execute, the setgid bit — so the
/// caller writes that mode back through the one mode entry, which is also
/// what moves `ctime`.
fn chown_decision(
    caller: Caller,
    uid: u32,
    gid: u32,
    kind: FsEntryKind,
    mode: u32,
) -> Result<u32, c_int> {
    if (uid != ID_UNCHANGED && uid != caller.uid) || (gid != ID_UNCHANGED && !caller.in_group(gid))
    {
        return Err(EPERM);
    }
    if kind == FsEntryKind::Directory {
        return Ok(mode);
    }
    let mut mode = mode & !S_ISUID;
    if mode & (S_ISGID | S_IXGRP) == S_ISGID | S_IXGRP {
        mode &= !S_ISGID;
    }
    Ok(mode)
}

#[cfg(test)]
mod chown_tests {
    use super::*;

    /// A caller in a supplementary group may give its file to that group,
    /// as `in_group_p` lets it; no other group or owner.
    #[test]
    fn chown_accepts_the_callers_groups_only() {
        let caller = Caller {
            uid: 1000,
            gid: 1000,
            groups: &[1000, 27],
        };
        let decide = |uid, gid| chown_decision(caller, uid, gid, FsEntryKind::File, 0o644);
        assert_eq!(decide(ID_UNCHANGED, 27), Ok(0o644));
        assert_eq!(decide(1000, 1000), Ok(0o644));
        assert_eq!(decide(ID_UNCHANGED, 28), Err(EPERM));
        assert_eq!(decide(1001, ID_UNCHANGED), Err(EPERM));
    }
}

/// `chown`/`lchown`/`fchownat` on a `(dirfd, path)`; `flags` are
/// `PATINA_RESOLVE_*` (`NOFOLLOW` names a symlink itself, `EMPTY_PATH` lets
/// `AT_EMPTY_PATH` name the base). A symlink keeps its mode and data times,
/// but its own ctime moves.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_chown(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    uid: u32,
    gid: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !paths::RESOLVE_AT_FLAGS != 0 {
        return fail(EINVAL);
    }
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let resolved = match paths::resolve(dirfd, &path, flags) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    let Some(metadata) = resolved.metadata else {
        return fail(ENOENT);
    };
    let mode = match chown_decision(caller(), uid, gid, metadata.kind, metadata.mode) {
        Ok(mode) => mode,
        Err(errno) => return fail(errno),
    };
    let result = if metadata.kind == FsEntryKind::Symlink {
        with_context(|context| {
            context.fs_set_times_by_path(
                &resolved.path,
                Some(metadata.atime_nanos),
                Some(metadata.mtime_nanos),
            )
        })
    } else {
        with_context(|context| context.fs_set_mode(&resolved.path, mode))
    };
    match result {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `fchown`: the same decision on the node a descriptor holds. `O_PATH` is
/// `EBADF`; descriptors without a modeled inode refuse loudly.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fchown(raw_fd: c_int, uid: u32, gid: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let resolved = match resolve_fd(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    if resolved.kind == FdKind::OPath {
        return fail(EBADF);
    }
    if let Some(node) = thread::fifo_ino(raw_fd) {
        let metadata = match with_context(|context| context.fs_inode_metadata(node)) {
            Ok(metadata) => metadata,
            Err(errno) => return fail(errno),
        };
        let mode = match chown_decision(caller(), uid, gid, metadata.kind, metadata.mode) {
            Ok(mode) => mode,
            Err(errno) => return fail(errno),
        };
        return match with_context(|context| context.fs_set_inode_mode(node, mode)) {
            Ok(()) => {
                set_errno(0);
                0
            }
            Err(errno) => fail(errno),
        };
    }
    if !resolved.kind.is_fs() {
        return deny("patina: fchown on a descriptor without a modeled inode; failing closed\n");
    }
    let fd = Fd(resolved.handle);
    let metadata = match with_context(|context| context.fs_fd_metadata(fd)) {
        Ok(metadata) => metadata,
        Err(errno) => return fail(errno),
    };
    let mode = match chown_decision(caller(), uid, gid, metadata.kind, metadata.mode) {
        Ok(mode) => mode,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_set_fd_mode(fd, mode)) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `truncate(2)`: a regular file's length by name (a trailing symlink is
/// followed). A negative length is `EINVAL`, a directory `EISDIR`, any other
/// kind `EINVAL`; the driver charges `w` on the entry.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_truncate(dirfd: c_int, path: *const c_char, length: i64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let Ok(length) = u64::try_from(length) else {
        return fail(EINVAL);
    };
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let resolved = match paths::resolve(dirfd, &path, 0) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    let ino = match resolved.metadata {
        None => return fail(ENOENT),
        Some(metadata) => match metadata.kind {
            FsEntryKind::Directory => return fail(EISDIR),
            FsEntryKind::Fifo
            | FsEntryKind::Symlink
            | FsEntryKind::Socket
            | FsEntryKind::CharDevice => return fail(EINVAL),
            FsEntryKind::File => metadata.ino,
        },
    };
    match with_context(|context| context.fs_set_len_by_path(&resolved.path, length)) {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            mem::resized_ino(ino, length);
            #[cfg(not(target_os = "linux"))]
            let _ = ino;
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `fallocate(2)` mode bits.
pub const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
pub const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
pub const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x08;
pub const FALLOC_FL_ZERO_RANGE: u32 = 0x10;
pub const FALLOC_FL_INSERT_RANGE: u32 = 0x20;
pub const FALLOC_FL_UNSHARE_RANGE: u32 = 0x40;
/// The bits the kernel's `vfs_fallocate` recognizes at all; anything else is
/// `EOPNOTSUPP` before the descriptor is even looked at.
const FALLOC_FL_SUPPORTED: u32 = FALLOC_FL_KEEP_SIZE
    | FALLOC_FL_PUNCH_HOLE
    | FALLOC_FL_COLLAPSE_RANGE
    | FALLOC_FL_ZERO_RANGE
    | FALLOC_FL_INSERT_RANGE
    | FALLOC_FL_UNSHARE_RANGE;

/// The operation bits of a `fallocate` mode (everything but `KEEP_SIZE`); the
/// kernel accepts at most one of them per call.
const FALLOC_FL_OPERATIONS: u32 = FALLOC_FL_PUNCH_HOLE
    | FALLOC_FL_COLLAPSE_RANGE
    | FALLOC_FL_ZERO_RANGE
    | FALLOC_FL_INSERT_RANGE
    | FALLOC_FL_UNSHARE_RANGE;

/// `fallocate(2)`, in the kernel's order of refusals: a bad range is
/// `EINVAL`; an unknown bit, two operation bits at once, `PUNCH_HOLE` without
/// `KEEP_SIZE`, or a range-shifting mode with `KEEP_SIZE` is `EOPNOTSUPP`
/// (host-checked: Linux 6.8 answers `EOPNOTSUPP`, not `EINVAL`, for the
/// self-contradictory modes); a descriptor not open for writing (or `O_PATH`)
/// `EBADF`, a pipe `ESPIPE`, a directory `EISDIR`, any other non-file `ENODEV`,
/// a range past the file size limit `EFBIG`. Mode `0` and `KEEP_SIZE` reserve
/// (the file grows to `offset + len` unless `KEEP_SIZE`); `PUNCH_HOLE|KEEP_SIZE`
/// and `ZERO_RANGE` zero the range; the range-shifting modes (`COLLAPSE_RANGE`,
/// `INSERT_RANGE`) and `UNSHARE_RANGE` are `EOPNOTSUPP`, a real answer on
/// filesystems without them. One recorded operation whatever the range.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fallocate(raw_fd: c_int, mode: u32, offset: i64, length: i64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if offset < 0 || length <= 0 {
        return fail(EINVAL);
    }
    if mode & !FALLOC_FL_SUPPORTED != 0
        || (mode & FALLOC_FL_OPERATIONS).count_ones() > 1
        || (mode & FALLOC_FL_PUNCH_HOLE != 0 && mode & FALLOC_FL_KEEP_SIZE == 0)
        || (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE) != 0
            && mode & FALLOC_FL_KEEP_SIZE != 0)
    {
        return fail(EOPNOTSUPP);
    }
    let resolved = match resolve_fd(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    if resolved.kind == FdKind::OPath || resolved.status & O_WRITE == 0 {
        return fail(EBADF);
    }
    match resolved.kind {
        FdKind::File => {}
        FdKind::Pipe => return fail(ESPIPE),
        FdKind::Dir => return fail(EISDIR),
        FdKind::OPath
        | FdKind::Stdin
        | FdKind::Stdout
        | FdKind::Stderr
        | FdKind::Urandom
        | FdKind::Socket => return fail(ENODEV),
        #[cfg(target_os = "linux")]
        FdKind::EventFd | FdKind::Epoll | FdKind::SignalFd | FdKind::TimerFd => {
            return fail(ENODEV);
        }
        // A queue is a regular file (judged after the range, below).
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue => {}
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => return fail(ENODEV),
    }
    if mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE | FALLOC_FL_UNSHARE_RANGE) != 0 {
        return fail(EOPNOTSUPP);
    }
    let (offset, length) = (offset as u64, length as u64);
    if offset
        .checked_add(length)
        .is_none_or(|end| end > i64::MAX as u64)
    {
        return fail(EFBIG);
    }
    // The file's own `fallocate`: an mqueue file has none, and a memfd
    // (`shmem_fallocate`, `hugetlbfs_fallocate`) takes only `KEEP_SIZE` and
    // `PUNCH_HOLE`.
    #[cfg(target_os = "linux")]
    if resolved.kind == FdKind::MessageQueue
        || (mem::anonymous(resolved.handle).is_some()
            && mode & !(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE) != 0)
    {
        return fail(EOPNOTSUPP);
    }
    let zero = mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE) != 0;
    let keep_size = mode & FALLOC_FL_KEEP_SIZE != 0;
    let fd = Fd(resolved.handle);
    match with_context(|context| context.fs_allocate(fd, offset, length, zero, keep_size)) {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            mem::allocated(fd.0, offset, length, zero, keep_size);
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Capture a deterministic directory snapshot for POSIX readdir iteration.
///
/// Iteration is a read OF A DESCRIPTOR, not a fresh lookup of a name: the `r` it
/// costs was charged when the directory was opened, so a `chmod` afterwards
/// cannot break a walk already under way, a rename cannot redirect it, and a
/// descriptor opened `O_PATH` — which never opened the directory — cannot list
/// at all. Both doors reach it the same way: the libc `opendir` mints its own
/// descriptor first (which is also what makes `dirfd()` on one meaningful), and
/// `fdopendir` and the raw `getdents64` row already hold one.
///
/// The snapshot lists `.` and `..` first ([`ReadDirState::listing`]): every
/// directory has both, and the kernel's `getdents64` (so every `readdir`)
/// reports them.
///
/// # Safety
/// `state_out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_read_dir(raw_fd: c_int, state_out: *mut *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if state_out.is_null() {
        return fail(EINVAL);
    }
    let fd = match fs_handle(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_read_directory_fd(fd)) {
        Ok(listed) => {
            let state = Box::new(ReadDirState::listing(listed));
            // SAFETY: `state_out` was checked and is required to be writable.
            unsafe { state_out.write(Box::into_raw(state).cast()) };
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Copy the next directory-snapshot entry into caller-owned storage.
///
/// Returns 1 for an entry, 0 at end-of-directory, and -1 on error.
///
/// # Safety
/// `state` must be a pointer returned by [`patina_read_dir`], `name_buf` must
/// be writable for `buf_len` bytes, and `kind` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_read_dir_next(
    state: *mut c_void,
    name_buf: *mut c_char,
    buf_len: usize,
    kind: *mut u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if state.is_null() || kind.is_null() || (buf_len != 0 && name_buf.is_null()) {
        return fail(EINVAL);
    }
    // SAFETY: Guaranteed by this function's C ABI contract.
    let state = unsafe { &mut *state.cast::<ReadDirState>() };
    let Some(entry) = state.entries.get(state.position) else {
        set_errno(0);
        return 0;
    };
    let bytes = entry.name.as_bytes();
    if bytes
        .len()
        .checked_add(1)
        .is_none_or(|needed| needed > buf_len)
    {
        return fail(EINVAL);
    }
    // SAFETY: The destination buffer has room for the bytes plus a NUL.
    unsafe {
        let destination = slice::from_raw_parts_mut(name_buf.cast::<u8>(), buf_len);
        destination[..bytes.len()].copy_from_slice(bytes);
        destination[bytes.len()] = 0;
        kind.write(metadata_kind(entry.kind));
    }
    state.position += 1;
    set_errno(0);
    1
}

/// Free a directory snapshot returned by [`patina_read_dir`].
///
/// # Safety
/// `state` must be null or a pointer returned by [`patina_read_dir`] not yet
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_read_dir_free(state: *mut c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !state.is_null() {
        // SAFETY: Guaranteed by this function's C ABI contract.
        drop(unsafe { Box::from_raw(state.cast::<ReadDirState>()) });
    }
}

/// Resolve `(dirfd, path)` once and run `invoke` on the canonical path.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
unsafe fn path_unit(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    invoke: impl FnOnce(&mut Context, &str) -> Result<(), RuntimeError>,
) -> c_int {
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let resolved = match paths::resolve(dirfd, &path, flags) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| invoke(context, &resolved.path)) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Create a deterministic directory (`mkdir`/`mkdirat`) at the caller's
/// requested `mode` under the process umask, exactly as the kernel applies it
/// to `mkdir(2)`. A trailing symlink is not followed: the name must be free.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_mkdir(dirfd: c_int, path: *const c_char, mode: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // `vfs_mkdir` keeps the permission triads and the sticky bit of the
    // request and drops setuid/setgid: a directory never gets those from its
    // creation mode.
    let mode = (mode & 0o1777) & !paths::umask();
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe {
        path_unit(dirfd, path, paths::RESOLVE_NOFOLLOW, |context, path| {
            context.fs_create_directory(path, mode)
        })
    }
}

/// Create a named pipe (`mkfifo`/`mkfifoat`, and `mknod`/`mknodat` with
/// `S_IFIFO`) at the caller's requested `mode` under the process umask. Only
/// the NAME is filesystem state, so this is one recorded boundary operation
/// and nothing else: the pipe behind the name comes into existence when the
/// first descriptor opens it, and vanishes with the last.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_mkfifo(dirfd: c_int, path: *const c_char, mode: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mode = (mode & 0o7777) & !paths::umask();
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe {
        path_unit(dirfd, path, paths::RESOLVE_NOFOLLOW, |context, path| {
            context.fs_make_fifo(path, mode)
        })
    }
}

/// `S_IFMT` and the file types a `mknod` mode carries (identical on Linux and
/// Darwin).
const S_IFMT: u32 = 0o170000;
const S_IFIFO: u32 = 0o010000;
const S_IFCHR: u32 = 0o020000;
const S_IFDIR: u32 = 0o040000;
const S_IFBLK: u32 = 0o060000;
const S_IFREG: u32 = 0o100000;
const S_IFSOCK: u32 = 0o140000;

/// `mknod(2)`/`mknodat(2)`, in the kernel's order of refusals (Linux
/// `do_mknodat`): the type first (`may_mknod`: a directory is `EPERM`, an
/// unknown type `EINVAL`), then the name (`ENOENT` for a missing parent,
/// `EEXIST` for a taken name); the driver judges the rest (the parent's
/// `w`+`x`, then the `CAP_MKNOD` a device other than the whiteout needs). A
/// zero type or `S_IFREG` makes an empty regular file, `S_IFSOCK` a socket
/// node, `S_IFCHR` with device 0 a whiteout. `dev` is the kernel's 32-bit
/// device word. The mode's permission bits are applied under the process
/// umask. On Darwin (`mknod` in XNU) a FIFO is `mkfifo` and every other type
/// needs a privilege the one modeled identity lacks (`EPERM`, before the
/// path).
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_mknod(
    dirfd: c_int,
    path: *const c_char,
    mode: u32,
    dev: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let kind = mode & S_IFMT;
    if cfg!(target_os = "macos") && kind != S_IFIFO {
        return fail(EPERM);
    }
    let node = match kind {
        0 | S_IFREG => FsNode::File,
        S_IFIFO => FsNode::Fifo,
        S_IFSOCK => FsNode::Socket,
        S_IFCHR if dev == 0 => FsNode::Whiteout,
        S_IFCHR => FsNode::CharDevice { device: dev },
        S_IFBLK => FsNode::BlockDevice { device: dev },
        S_IFDIR => return fail(EPERM),
        _ => return fail(EINVAL),
    };
    let spelled = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let resolved = match paths::resolve(dirfd, &spelled, paths::RESOLVE_NOFOLLOW) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    if resolved.metadata.is_some() || paths::last_component(&spelled) != paths::Last::Name {
        return fail(EEXIST);
    }
    let mode = (mode & 0o7777) & !paths::umask();
    let result = if node == FsNode::Fifo {
        with_context(|context| context.fs_make_fifo(&resolved.path, mode))
    } else {
        with_context(|context| context.fs_make_node(&resolved.path, node, mode))
    };
    match result {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Remove a name (`unlink`/`unlinkat`). Never follows a trailing symlink: the
/// link entry itself is what goes. A final `.`, `..` or `/` names no entry to
/// unlink: `EISDIR` once the parent resolved (`do_unlinkat`).
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_unlink(dirfd: c_int, path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let spelled = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match paths::final_component(dirfd, &spelled) {
        Ok(paths::Last::Name) => {}
        Ok(paths::Last::Dot | paths::Last::DotDot | paths::Last::Root) => return fail(EISDIR),
        Err(errno) => return fail(errno),
    }
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe {
        path_unit(
            dirfd,
            path,
            paths::RESOLVE_NOFOLLOW,
            Context::fs_remove_file,
        )
    }
}

/// Remove an empty deterministic directory (`rmdir`/`unlinkat(AT_REMOVEDIR)`).
/// A final component that names no entry is refused once the parent resolved
/// (`do_rmdir`): `.` is `EINVAL`, `..` is `ENOTEMPTY` (the directory it names
/// holds at least the one it was reached through), the root `EBUSY`.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_rmdir(dirfd: c_int, path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let spelled = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match paths::final_component(dirfd, &spelled) {
        Ok(paths::Last::Name) => {}
        Ok(paths::Last::Dot) => return fail(EINVAL),
        Ok(paths::Last::DotDot) => return fail(ENOTEMPTY),
        Ok(paths::Last::Root) => return fail(EBUSY),
        Err(errno) => return fail(errno),
    }
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe {
        path_unit(
            dirfd,
            path,
            paths::RESOLVE_NOFOLLOW,
            Context::fs_remove_directory,
        )
    }
}

/// `renameat2(2)`'s flags (Linux values).
pub(crate) const RENAME_NOREPLACE: u32 = 1 << 0;
pub(crate) const RENAME_EXCHANGE: u32 = 1 << 1;
pub(crate) const RENAME_WHITEOUT: u32 = 1 << 2;

/// Judge a `renameat2` flag word as `do_renameat2` does before any path is
/// looked at: an unknown bit, or `RENAME_EXCHANGE` with either of the others,
/// is `EINVAL`.
pub(crate) fn rename_flags_valid(flags: u32) -> bool {
    flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) == 0
        && !(flags & RENAME_EXCHANGE != 0 && flags & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0)
}

#[cfg(test)]
mod open_flag_tests {
    use super::*;

    /// RED before: the shared open read `O_CREAT|O_DIRECTORY` as a directory
    /// open and went on to resolve the path (here `ENAMETOOLONG`).
    #[test]
    fn a_creating_directory_open_is_einval_before_the_path() {
        let long = std::ffi::CString::new("a".repeat(paths::PATH_MAX)).unwrap();
        let flags = O_READ | O_CREATE | O_DIRECTORY;
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(
            unsafe { patina_openat(-1, long.as_ptr(), flags, 0o644) },
            -1
        );
        assert_eq!(patina_errno(), EINVAL);
    }
}

#[cfg(test)]
mod rename_flag_tests {
    use super::*;

    #[test]
    fn renameat2_flags_are_judged_as_do_renameat2_judges_them() {
        for accepted in [
            0,
            RENAME_NOREPLACE,
            RENAME_EXCHANGE,
            RENAME_WHITEOUT,
            RENAME_NOREPLACE | RENAME_WHITEOUT,
        ] {
            assert!(
                rename_flags_valid(accepted),
                "{accepted:#x} is a kernel flag set"
            );
        }
        for refused in [
            RENAME_NOREPLACE | RENAME_EXCHANGE,
            RENAME_WHITEOUT | RENAME_EXCHANGE,
            1 << 3,
            RENAME_NOREPLACE | 1 << 31,
        ] {
            assert!(!rename_flags_valid(refused), "{refused:#x} is EINVAL");
        }
    }
}

/// Rename a deterministic filesystem entry (`rename`/`renameat`, which pass no
/// flags, and `renameat2`). Neither side follows a trailing symlink: the kernel
/// renames link entries as entries. The refusals come in `do_renameat2`'s
/// order: the flag word, both paths' parents, a final `.`/`..`/`/` on either
/// side (`EBUSY`; `EEXIST` on the destination under `RENAME_NOREPLACE`), a
/// missing source (`ENOENT`), then the flag's own rule — `RENAME_NOREPLACE`
/// refuses an existing destination (`EEXIST`), `RENAME_EXCHANGE` needs one
/// (`ENOENT`) and swaps the two entries atomically, `RENAME_WHITEOUT` leaves a
/// whiteout (a 0:0 character device) at the old name — and last the rename's
/// own (`EISDIR`, `ENOTDIR`, `ENOTEMPTY`, `EINVAL` into itself).
///
/// # Safety
/// `from` and `to` must point to valid NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_renameat2(
    fromfd: c_int,
    from: *const c_char,
    tofd: c_int,
    to: *const c_char,
    flags: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !rename_flags_valid(flags) {
        return fail(EINVAL);
    }
    let from = match path_from_c(from) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let to = match path_from_c(to) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let (from_last, to_last) = match (
        paths::final_component(fromfd, &from),
        paths::final_component(tofd, &to),
    ) {
        (Ok(from_last), Ok(to_last)) => (from_last, to_last),
        (Err(errno), _) | (_, Err(errno)) => return fail(errno),
    };
    if from_last != paths::Last::Name {
        return fail(EBUSY);
    }
    if to_last != paths::Last::Name {
        return fail(if flags & RENAME_NOREPLACE != 0 {
            EEXIST
        } else {
            EBUSY
        });
    }
    let from = match paths::resolve(fromfd, &from, paths::RESOLVE_NOFOLLOW) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    let to = match paths::resolve(tofd, &to, paths::RESOLVE_NOFOLLOW) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    if from.metadata.is_none() {
        return fail(ENOENT);
    }
    let result = if flags & RENAME_EXCHANGE != 0 {
        if to.metadata.is_none() {
            return fail(ENOENT);
        }
        with_context(|context| context.fs_exchange(&from.path, &to.path))
    } else if flags & RENAME_NOREPLACE != 0 && to.metadata.is_some() {
        Err(EEXIST)
    } else if flags & RENAME_WHITEOUT != 0 {
        with_context(|context| context.fs_rename_whiteout(&from.path, &to.path))
    } else {
        with_context(|context| context.fs_rename(&from.path, &to.path))
    };
    match result {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Create a deterministic symbolic link (`symlink`/`symlinkat`). Only the LINK
/// side resolves — `target` is the link's literal contents, stored verbatim —
/// and an empty target is `ENOENT`, as `symlink(2)` answers.
///
/// # Safety
/// `target` and `link_path` must point to valid NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_symlink(
    target: *const c_char,
    dirfd: c_int,
    link_path: *const c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let target = match path_from_c(target) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    if target.is_empty() {
        return fail(ENOENT);
    }
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe {
        path_unit(
            dirfd,
            link_path,
            paths::RESOLVE_NOFOLLOW,
            |context, link_path| context.fs_symlink(&target, link_path),
        )
    }
}

/// Create a deterministic hard link (`link`/`linkat`). The driver shares one
/// inode between `from` and `to`, or duplicates the symlink entry when `from`
/// is itself a symlink — the POSIX "hard link the symlink itself" behavior of
/// `linkat` without `AT_SYMLINK_FOLLOW`. With `follow` nonzero `from`'s
/// trailing symlink is resolved first, so the link targets the resolved file.
///
/// # Safety
/// `from` and `to` must point to valid NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_link(
    fromfd: c_int,
    from: *const c_char,
    tofd: c_int,
    to: *const c_char,
    follow: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let from = match path_from_c(from) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let to = match path_from_c(to) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let from_flags = if follow != 0 {
        0
    } else {
        paths::RESOLVE_NOFOLLOW
    };
    let from = match paths::resolve(fromfd, &from, from_flags) {
        Ok(resolved) => resolved.path,
        Err(errno) => return fail(errno),
    };
    let to = match paths::resolve(tofd, &to, paths::RESOLVE_NOFOLLOW) {
        Ok(resolved) => resolved.path,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_link(&from, &to)) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Read a deterministic symbolic link's target bytes (`readlink`/
/// `readlinkat`). An empty path names the descriptor itself, as the kernel's
/// `readlinkat` allows; a name that is not a symlink is `EINVAL`, a zero-length
/// buffer is `EINVAL`. Returns the byte count copied, with no trailing NUL.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string and `buf` must be
/// writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_read_link(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut c_char,
    len: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // Bootstrap window (see `SHIM_BOOTSTRAP`): this is an allocator's init-time
    // config probe — tikv-jemallocator's `obtain_malloc_conf` does
    // `readlink("/etc/malloc.conf")` while holding its init lock. The deterministic
    // FS carries no such file, and — crucially — this MUST NOT allocate (the
    // `String` path would re-enter the half-initialized guest allocator and trip its
    // non-recursive init lock / deadlock), so answer ENOENT without building a path
    // or touching the runtime. A guest's own deterministic `read_link` runs after
    // bootstrap and is unaffected.
    if in_shim_bootstrap() {
        return fail(ENOENT) as isize;
    }
    if len == 0 || buf.is_null() {
        return fail(EINVAL) as isize;
    }
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno) as isize,
    };
    let resolved = match paths::resolve(
        dirfd,
        &path,
        paths::RESOLVE_NOFOLLOW | paths::RESOLVE_EMPTY_PATH,
    ) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno) as isize,
    };
    match resolved.metadata.map(|metadata| metadata.kind) {
        None => return fail(ENOENT) as isize,
        Some(FsEntryKind::Symlink) => {}
        Some(
            FsEntryKind::File
            | FsEntryKind::Directory
            | FsEntryKind::Fifo
            | FsEntryKind::Socket
            | FsEntryKind::CharDevice,
        ) => {
            return fail(EINVAL) as isize;
        }
    }
    match with_context(|context| context.fs_read_link(&resolved.path)) {
        Ok(target) => {
            let bytes = target.as_bytes();
            let copied = bytes.len().min(len);
            // SAFETY: The destination buffer was checked and is required to be
            // writable for `len` bytes by this function's C ABI.
            unsafe {
                slice::from_raw_parts_mut(buf.cast::<u8>(), len)[..copied]
                    .copy_from_slice(&bytes[..copied]);
            }
            set_errno(0);
            isize::try_from(copied).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        Err(errno) => fail(errno) as isize,
    }
}

/// Copy a NUL-terminated `path` into `buf` when it fits, returning its length
/// in bytes (excluding the terminator); `ERANGE` when `len` is nonzero and too
/// small. With `len == 0` only the length is reported.
fn copy_path_out(path: &str, buf: *mut c_char, len: usize) -> isize {
    let bytes = path.as_bytes();
    if len != 0 {
        if buf.is_null() {
            return fail(EINVAL) as isize;
        }
        if bytes.len() >= len {
            return fail(ERANGE) as isize;
        }
        // SAFETY: The destination is writable for `len` bytes by the C ABI
        // contract, and `bytes.len() < len` leaves room for the terminator.
        unsafe {
            let destination = slice::from_raw_parts_mut(buf.cast::<u8>(), len);
            destination[..bytes.len()].copy_from_slice(bytes);
            destination[bytes.len()] = 0;
        }
    }
    set_errno(0);
    isize::try_from(bytes.len()).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
}

/// The one path resolver, exported for the caller that wants the canonical
/// NAME rather than an operation on it (`realpath`). Resolves `(dirfd, path)` — the
/// working directory for `PATINA_AT_FDCWD`, a directory descriptor's node
/// otherwise — applying `.`/`..` to the resolved directory, walking symlinks to
/// the kernel's 40-hop `ELOOP` limit, and answering `ENAMETOOLONG`, `ENOTDIR`
/// for a component through a non-directory, and the trailing-slash rule.
/// `flags` are `PATINA_RESOLVE_*`. Writes the NUL-terminated canonical path
/// into `buf` when it fits and returns its length; `*kind` receives the final
/// entry's `PATINA_ENTRY_*` kind, or 0 when the final component does not
/// exist.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string, `buf` must be
/// writable for `len` bytes when `len` is nonzero, and `kind` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_resolve_path(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    buf: *mut c_char,
    len: usize,
    kind: *mut u32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !paths::RESOLVE_AT_FLAGS != 0 || kind.is_null() {
        return fail(EINVAL) as isize;
    }
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno) as isize,
    };
    let resolved = match paths::resolve(dirfd, &path, flags) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno) as isize,
    };
    // SAFETY: `kind` was checked non-null and is writable per the C ABI.
    unsafe {
        kind.write(
            resolved
                .metadata
                .map_or(0, |metadata| metadata_kind(metadata.kind)),
        );
    }
    copy_path_out(&resolved.path, buf, len)
}

/// `getcwd(2)`: where the working directory's NODE is now, NUL-terminated in
/// `buf` when it fits (`ERANGE` otherwise; `len == 0` reports the length
/// alone), returning the length. `ENOENT` once the directory has been
/// unlinked, exactly as Linux answers.
///
/// # Safety
/// `buf` must be writable for `len` bytes when `len` is nonzero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_getcwd(buf: *mut c_char, len: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match paths::cwd_path() {
        Ok(path) => copy_path_out(&path, buf, len),
        Err(errno) => fail(errno) as isize,
    }
}

/// `chdir(2)`: resolve `(dirfd, path)` (symlinks followed) and make the
/// directory it names the working directory. `ENOENT` for a missing name,
/// `ENOTDIR` for anything but a directory, `EACCES` for one the modeled
/// identity cannot search.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_chdir(dirfd: c_int, path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match paths::chdir(dirfd, &path) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `fchdir(2)`: a directory descriptor — opened plainly or `O_PATH` — becomes
/// the working directory. `EBADF` for a number that names nothing, `ENOTDIR`
/// for any other kind.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fchdir(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match paths::fchdir(raw_fd) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `umask(2)`: install `mask` (its permission bits) as the process umask every
/// creating entry applies, and return the previous one. Never fails.
#[unsafe(no_mangle)]
pub extern "C" fn patina_umask(mask: u32) -> u32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    set_errno(0);
    paths::set_umask(mask)
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_thread_id() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    thread::deterministic_thread_id()
}

/// `sched_yield`/`thread::yield_now`: take a deterministic scheduling point
/// instead of yielding the host scheduler. std's `mpsc`/`mpmc` backoff spins
/// through `thread::yield_now` before parking, so an uninterposed `sched_yield`
/// would be a host scheduling call outside the runtime. A no-op until the
/// thread subsystem activates, so single-threaded programs are unaffected.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sched_yield() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let _ = thread::sched_point();
    0
}

/// The `--yield-points` guard hook: `patina_yield.c` forwards every
/// SanitizerCoverage guard hit here with the instrumented call site, so a
/// record/replay yield divergence can name the exact guest location that took
/// the extra scheduling point. Otherwise identical to [`patina_sched_yield`].
#[unsafe(no_mangle)]
pub extern "C" fn patina_yield_point(site: *const c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    thread::yield_point_from(site as usize);
}

/// The runtime side of the packaged `exit` interposer (patina_posix.c). It runs
/// at the process's main-return / `exit(3)` boundary — the one point that
/// executes on the exiting thread AFTER its managed body but BEFORE the C runtime
/// drives the guest's thread-local destructors. Marking teardown here makes the
/// root task's post-`main` yield hooks take no scheduling point (see
/// `thread::sched_point`), so a `--yield-points` guest's host-teardown-ordering-
/// dependent trailing yields can never diverge record from replay. `atexit`
/// cannot serve: glibc runs the TLS destructors BEFORE the atexit list, so the
/// packaged `patina_shutdown` atexit hook is too late. `_exit`/`_Exit` skip the
/// TLS destructors entirely and are deliberately not interposed. The real libc
/// `exit` is reached through the init-resolved `host_exit` alias (never the
/// public `exit`, which the C interposer defines), so there is no recursion —
/// glibc's `exit` still runs the atexit chain (finalizing the trace in record
/// mode) and the TLS destructors, now with the teardown flag set.
#[unsafe(no_mangle)]
pub extern "C" fn patina_exit(status: c_int) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    patina_note_guest_exit_status(status);
    thread::note_main_returned();
    // SAFETY: `host_exit` is the real libc `exit` resolved once via
    // `dlsym(RTLD_NEXT, "exit")`; it does not return.
    let _guest = crate::panic_boundary::PanicScope::suspend();
    unsafe { (hostapi::get().host_exit)(status) }
}

/// Private fatal vehicle: never finalize an invalid run through the guest abort interposer.
fn host_abort() -> ! {
    unsafe { (hostapi::get().host_abort)() }
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_host_abort() -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    host_abort()
}

/// A guest's `abort` is glibc's: SIGABRT through the virtual kernel, so an
/// installed handler runs, then the default action, which finalizes the trace
/// and ends the run by the signal ([`thread::signals::abort_through_kernel`]).
/// Without an installed runtime, or if the signal did not end the run, it
/// finalizes a healthy run and uses libc's real abort vehicle. Internal
/// lock-held fatal paths cannot recursively finalize the runtime.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn patina_abort() -> ! {
    // Inspect the caller before entering: a guest abort is not a shim panic.
    // This also covers panic=abort if the guest replaced our global hook.
    let internal_panic = crate::panic_boundary::in_shim() && std::thread::panicking();
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if internal_panic {
        let _ = host_write_all(2, b"patina native shim panic: aborting an owned boundary\n");
        host_abort();
    }
    if !in_shim_critical() {
        if slot().lock().is_some() {
            thread::signals::abort_through_kernel();
        }
        let _ = shutdown_run();
    }
    unsafe { (hostapi::get().host_abort)() }
}

/// Mark the process as having entered post-`main` teardown WITHOUT terminating.
/// The Linux `__libc_start_main` interposer (patina_posix.c) calls this from its
/// wrapper `main` the instant the guest's real `main` returns — before it hands
/// the exit code back into glibc's `exit()` path, which then drives the
/// thread-local destructors. That natural-return path never reaches
/// [`patina_exit`]: glibc's `__libc_start_main` calls `exit` through a hidden
/// internal alias (bound at libc build time, not via the PLT), so an `exit`
/// strong-def only catches EXPLICIT `exit(3)`/`std::process::exit`. Setting the
/// flag here silences the root task's `--yield-points` teardown yields on that
/// natural path (see `thread::sched_point`).
#[unsafe(no_mangle)]
pub extern "C" fn patina_note_main_returned() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    thread::note_main_returned();
}

/// Whether the process is in its post-`main` teardown (1) or not (0). After
/// `main` returns only the root task runs, so the POSIX layer's internal locks
/// (a stream's, the environment's) have nothing left to exclude, and waiting
/// on one a parked task holds would be a scheduling operation past the end of
/// the run — the refusal in `with_context_msg`. They are not taken then.
#[unsafe(no_mangle)]
pub extern "C" fn patina_in_teardown() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    c_int::from(thread::main_returned())
}

/// Linux interposer-engagement canary. `patina_finalize_atexit` (patina_posix.c)
/// calls this from the `atexit` hook, which glibc runs AFTER the thread-local
/// destructors on every exit-chain path that reaches it. On Linux the teardown
/// flag MUST already be set by then — the natural `main` return sets it through
/// the `__libc_start_main` wrapper, and an explicit `exit(3)`/`std::process::exit`
/// through the `exit` interposer. `_exit`/`_Exit`/`abort` skip `atexit` entirely,
/// so they never reach this. If the flag is UNSET here, the teardown interposer
/// did not engage on this platform/toolchain (e.g. an unversioned strong def
/// failing to interpose a versioned crt reference), which means the root task's
/// `--yield-points` teardown yields were NOT silenced and record/replay would
/// diverge. Fail LOUDLY and named rather than let that miss surface hours later as
/// an unexplained op-count divergence. Darwin is excluded by design: its natural
/// path keeps libSystem's own `exit` (two-level namespace), so the flag is not set
/// there and the root task's teardown yields stay recorded — deterministically,
/// now that `patina_thread_join`'s host reap fixes the one known load-dependent
/// branch (the joiner-vs-worker `Arc<thread::Inner>` teardown race).
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn patina_assert_teardown_engaged() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !thread::main_returned() {
        let _ = host_write_all(
            2,
            b"patina native shim fatal: teardown interposer did not engage -- main-return \
silencing is not active on this platform/toolchain (neither the __libc_start_main wrapper nor the \
exit interposer set the teardown flag before atexit); --yield-points teardown determinism is not \
guaranteed\n",
        );
        crate::host_abort();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_crash() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match with_context(Context::fs_crash) {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            mem::crashed();
            0
        }
        Err(errno) => fail(errno),
    }
}

// ---- Cooperative-SUT (buggify) C ABI -----------------------------------------
//
// The runtime side of the `patina` crate's `buggify!`, `always!`, `sometimes!`,
// `reachable!`, `buggify_knob!`, `buggify_delay!`, `rng`, and lifecycle macros.
// Labels and call-site identities arrive as `(ptr, len)` UTF-8 slices. Fatal
// signals (`always!` violation, duplicate label) flush captured output, emit a
// distinct marker line to the real stderr, and abort — never a silent escape.

/// Reborrow a `(ptr, len)` pair as a UTF-8 label. `None` (invalid UTF-8 or a null
/// non-empty pointer) is a fail-closed error at the call sites below.
///
/// # Safety
/// `ptr` must point to `len` readable bytes, or be null when `len == 0`.
unsafe fn buggify_label<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if len == 0 {
        return Some("");
    }
    if ptr.is_null() {
        return None;
    }
    // SAFETY: guaranteed by this function's documented contract.
    std::str::from_utf8(unsafe { slice::from_raw_parts(ptr, len) }).ok()
}

/// Flush captured guest output, emit `<marker> label=<label>` to the real
/// stderr through the non-interposed host alias, and abort. Mirrors
/// [`abort_with_init_error`] so the marker lands after buffered guest output.
///
/// Reserved for patina's own *refusals* — a duplicate buggify label and its
/// peers, whose marker is what `cargo patina`'s envelope attributes the refusal
/// from. A system-under-test finding does NOT come through here: it is reported
/// as a verdict ([`abort_after_verdict`]).
fn abort_with_buggify_marker(marker: &str, label: &str) -> ! {
    let _ = flush_before_refusal();
    let line = format!("{marker} label={label}\n");
    let _ = host_write_all(2, line.as_bytes());
    crate::host_abort();
}

/// Flush captured guest output and abort, printing nothing of the shim's own.
///
/// The run's finding has already been reported through the verdict ABI and
/// drained into the captured stderr as a `PATINA_VERDICT` line, so a second
/// hand-formatted marker would be a duplicate channel — and the classifier reads
/// the verdict, never a marker (`docs/arcs/outcome-channel.md`).
fn abort_after_verdict() -> ! {
    let _ = flush_before_refusal();
    crate::host_abort();
}

/// Move the runtime's queued diagnostic lines (today: `PATINA_VERDICT`) into the
/// captured stderr stream. The runtime performs no process I/O of its own mid-run,
/// so every shim entry point that can produce one drains it here — including on
/// the fatal paths, where [`abort_with_buggify_marker`] / [`abort_after_verdict`]
/// flush the capture before aborting and the lines therefore still reach the real
/// stderr.
fn drain_runtime_diagnostics() {
    let lines = with_context_raw(|context| Ok(context.take_pending_diagnostics()));
    for line in lines.unwrap_or_default() {
        capture_stderr_line(&line);
    }
}

/// Append a diagnostic line to the captured stderr buffer so it interleaves with
/// guest output and flushes at exit (lifecycle markers). Bounded like guest I/O.
fn capture_stderr_line(line: &str) {
    let mut capture = stdio_slot().lock();
    if capture.stderr.len().saturating_add(line.len() + 1) > MAX_CAPTURED_STDIO_BYTES {
        return;
    }
    capture.stderr.extend_from_slice(line.as_bytes());
    capture.stderr.push(b'\n');
}

/// Shared body for the site-evaluating buggify entry points: read the label and
/// call site, invoke the context method, map the outcome to `1`=fire / `0`=no,
/// and abort on a fatal always-violation or duplicate label.
fn buggify_site_call(
    label_ptr: *const u8,
    label_len: usize,
    site_ptr: *const u8,
    site_len: usize,
    invoke: impl FnOnce(&mut Context, &str, &str) -> Result<SiteOutcome, RuntimeError>,
) -> c_int {
    // SAFETY: the caller (the `patina` crate macro expansion) passes live slices.
    let label = match unsafe { buggify_label(label_ptr, label_len) } {
        Some(label) => label,
        None => return fail(EINVAL),
    };
    let site = match unsafe { buggify_label(site_ptr, site_len) } {
        Some(site) => site,
        None => return fail(EINVAL),
    };
    let outcome = with_context(|context| invoke(context, label, site));
    // Before acting on the outcome: an `always!` violation lowers to a verdict,
    // and the fatal arm below never returns. The drained `PATINA_VERDICT` line is
    // the violation's ONLY announcement — there is no second marker.
    drain_runtime_diagnostics();
    match outcome {
        Ok(SiteOutcome::Fire) => 1,
        Ok(SiteOutcome::Ok) => 0,
        Ok(SiteOutcome::AlwaysViolation) => abort_after_verdict(),
        Ok(SiteOutcome::DuplicateLabel) => {
            abort_with_buggify_marker("PATINA_BUGGIFY_DUPLICATE_LABEL", label)
        }
        Err(errno) => fail(errno),
    }
}

/// `patina_dst::is_simulated()`: 1 whenever the deterministic runtime is installed.
#[unsafe(no_mangle)]
pub extern "C" fn patina_is_simulated() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    c_int::from(ensure_runtime().is_ok())
}

/// `buggify!` / `buggify_with_prob!`: `prob_permille < 0` uses the run default.
/// Returns 1 when the site fires, 0 otherwise.
///
/// # Safety
/// Label and site pointers must describe live UTF-8 slices of the given lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_buggify(
    label: *const u8,
    label_len: usize,
    site: *const u8,
    site_len: usize,
    prob_permille: i32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    buggify_site_call(label, label_len, site, site_len, move |context, l, s| {
        let prob = (prob_permille >= 0).then(|| prob_permille.clamp(0, 1000) as u16);
        context.buggify_evaluate(l, s, prob)
    })
}

/// `buggify_delay!`: on firing, advance virtual time deterministically. Returns
/// 1 when it delayed.
///
/// # Safety
/// See [`patina_buggify`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_buggify_delay(
    label: *const u8,
    label_len: usize,
    site: *const u8,
    site_len: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    buggify_site_call(label, label_len, site, site_len, |context, l, s| {
        context.buggify_delay(l, s)
    })
}

/// `buggify_knob!`: a per-run perturbed value within `[lo, hi]` for an active
/// site, or `default` otherwise. A duplicate label aborts.
///
/// # Safety
/// See [`patina_buggify`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_buggify_knob(
    label: *const u8,
    label_len: usize,
    site: *const u8,
    site_len: usize,
    default: i64,
    lo: i64,
    hi: i64,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller passes live slices.
    let label = match unsafe { buggify_label(label, label_len) } {
        Some(label) => label,
        None => return default,
    };
    let site = match unsafe { buggify_label(site, site_len) } {
        Some(site) => site,
        None => return default,
    };
    match with_context(|context| context.buggify_knob(label, site, default, lo, hi)) {
        Ok(Ok(value)) => value,
        Ok(Err(())) => abort_with_buggify_marker("PATINA_BUGGIFY_DUPLICATE_LABEL", label),
        Err(_) => default,
    }
}

/// `always!`: a false `condition` is a fatal invariant violation under the
/// simulator (independent of buggify being enabled).
///
/// # Safety
/// See [`patina_buggify`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_always(
    condition: c_int,
    label: *const u8,
    label_len: usize,
    site: *const u8,
    site_len: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    buggify_site_call(label, label_len, site, site_len, move |context, l, s| {
        context.always_check(l, s, condition != 0)
    })
}

/// `sometimes!`: coverage oracle noting the site reached and satisfied-if-true.
///
/// # Safety
/// See [`patina_buggify`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_sometimes(
    condition: c_int,
    label: *const u8,
    label_len: usize,
    site: *const u8,
    site_len: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    buggify_site_call(label, label_len, site, site_len, move |context, l, s| {
        context.sometimes_check(l, s, condition != 0)
    })
}

/// `reachable!`: coverage oracle noting the site reached.
///
/// # Safety
/// See [`patina_buggify`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_reachable(
    label: *const u8,
    label_len: usize,
    site: *const u8,
    site_len: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    buggify_site_call(label, label_len, site, site_len, |context, l, s| {
        context.reachable_mark(l, s)
    })
}

/// `patina_dst::verdict(...)`: report one structured guest verdict.
///
/// The verdict ABI is a SINGLE verb — `kind` is data, not a symbol per kind — so
/// a new [`VerdictKind`] never grows the shim's export surface. An unknown `kind`
/// is refused with `EINVAL` rather than defaulted: a guest built against a newer
/// enum than the shim understands must fail closed, not have its verdict silently
/// reclassified. The call is recorded in the trace and its `PATINA_VERDICT` line
/// enters the captured stderr stream, so it survives a subsequent guest abort.
///
/// # Safety
/// Label and detail pointers must describe live UTF-8 slices of the given
/// lengths (or be null with a zero length).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_verdict(
    kind: u32,
    label: *const u8,
    label_len: usize,
    detail: *const u8,
    detail_len: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let Some(kind) = VerdictKind::from_abi(kind) else {
        return fail(EINVAL);
    };
    // SAFETY: the caller passes live slices.
    let Some(label) = (unsafe { buggify_label(label, label_len) }) else {
        return fail(EINVAL);
    };
    // SAFETY: the caller passes live slices.
    let Some(detail) = (unsafe { buggify_label(detail, detail_len) }) else {
        return fail(EINVAL);
    };
    let result = with_context(|context| context.verdict(kind, label, detail));
    drain_runtime_diagnostics();
    match result {
        Ok(_) => 0,
        Err(errno) => fail(errno),
    }
}

// The custom-op ABI: three verbs, one per phase of a single operation.
//
// Why three symbols rather than one verb with a phase argument (the shape the
// verdict ABI uses for its kinds): a verdict's kinds are values of ONE call, so
// carrying them as data keeps the call shape fixed. A custom op's phases are
// three different calls with three different argument shapes and three different
// directions of data flow — announce (in), fetch the recorded result (out),
// report a fresh result (in). Folding them into one signature would mean
// arguments that are meaningful on one phase and ignored on the others, and
// ignored arguments are exactly where a fail-closed check goes blind. The
// property the verdict doctrine protects — no new symbol per *op class* — is
// intact: the op class is the `label`, which is data.
//
// The protocol, which the SDK's `custom_op_bytes` drives:
//
//   1. `patina_custom_op_begin(label, key, fault_eligible, &out_len)`
//        -> 0: record pass. Run `perform`, then call `patina_custom_op_record`.
//        -> 1: replay pass. Do NOT run `perform`; `out_len` is the recorded
//              result's length, fetched with `patina_custom_op_replay_result`.
//        -> 2: a seeded fault fired (or the recording holds one). Do NOT run
//              `perform`; return the failure the call declared. The operation is
//              already closed — there is no phase-2 call.
//   2a. `patina_custom_op_record(result, result_len)` closes a record pass.
//   2b. `patina_custom_op_replay_result(out, out_cap)` closes a replay pass.
//
// `fault_eligible` (nonzero) is the guest's declaration that this call has a
// failure shape it handles, which is what `--custom-op-fail-permille` acts on.
// The declared failure itself never crosses the boundary: only the guest's own
// types know a value the call site can return, so the shim decides WHETHER the
// operation fails and the guest supplies WHAT that means.
//
// Every runtime-level refusal (a replay divergence on the label or key, a nested
// or unclosed operation, a modeled effect performed inside `perform`) is fatal:
// there is no answer the guest could safely be handed, so the shim aborts loudly
// rather than returning an errno the guest could swallow and continue past. Only
// malformed arguments — a non-UTF-8 label, a null pointer with a nonzero length —
// return `EINVAL`, because those are the guest's own call being wrong.

/// Announce a custom operation; returns 0 for "record pass, run `perform`", 1
/// for "replay pass, the answer is recorded", or 2 for "seeded fault, return the
/// declared failure". See the module comment above.
///
/// # Safety
/// `label`/`key` must describe live slices of the given lengths (or be null with
/// a zero length), and `out_len` must be a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_custom_op_begin(
    label: *const u8,
    label_len: usize,
    key: *const u8,
    key_len: usize,
    fault_eligible: c_int,
    out_len: *mut usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller passes live slices.
    let Some(label) = (unsafe { buggify_label(label, label_len) }) else {
        return fail(EINVAL);
    };
    // SAFETY: the caller passes live slices.
    let Some(key) = (unsafe { custom_op_bytes(key, key_len) }) else {
        return fail(EINVAL);
    };
    if out_len.is_null() {
        return fail(EINVAL);
    }
    match with_context(|context| context.custom_op_begin(label, key, fault_eligible != 0)) {
        Ok(CustomOpMode::Record) => {
            // SAFETY: checked non-null above; the caller guarantees writability.
            unsafe { out_len.write(0) };
            0
        }
        Ok(CustomOpMode::Replay { len }) => {
            // SAFETY: checked non-null above; the caller guarantees writability.
            unsafe { out_len.write(len) };
            1
        }
        Ok(CustomOpMode::Fault) => {
            // SAFETY: checked non-null above; the caller guarantees writability.
            unsafe { out_len.write(0) };
            2
        }
        Err(errno) => fail(errno),
    }
}

/// Copy the recorded result of the open custom operation into `out`, closing it.
/// Returns the number of bytes written, or -1 when `out_cap` is smaller than the
/// length `patina_custom_op_begin` reported (nothing is copied and the operation
/// stays open, so the caller can retry with a large enough buffer).
///
/// # Safety
/// `out` must be writable for `out_cap` bytes, or be null when `out_cap == 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_custom_op_replay_result(out: *mut u8, out_cap: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // `with_context_raw`, not `with_context`: one custom operation is ONE
    // boundary, and its scheduling point was already taken by
    // `patina_custom_op_begin`. Taking a second one here would let another
    // managed task record operations between the two halves, which is exactly
    // what `Context::custom_op_record`'s "no modeled effects inside `perform`"
    // check reads as a guest error.
    let taken = with_context_raw(|context| {
        // A short buffer must not consume the recorded result: report the
        // shortfall and leave the operation open so a retry can still succeed.
        if context
            .custom_op_pending_len()
            .is_some_and(|len| len > out_cap)
        {
            return Ok(None);
        }
        context.custom_op_replay_result().map(Some)
    });
    let bytes = match taken {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            set_errno(EINVAL);
            return -1;
        }
        Err(errno) => return fail(errno) as isize,
    };
    if !bytes.is_empty() {
        if out.is_null() {
            return fail(EINVAL) as isize;
        }
        // SAFETY: the caller guarantees `out` is writable for `out_cap >= len`.
        unsafe { slice::from_raw_parts_mut(out, out_cap)[..bytes.len()].copy_from_slice(&bytes) };
    }
    bytes.len() as isize
}

/// Report what the guest's `perform` produced, closing the open custom operation
/// and recording its trace event.
///
/// # Safety
/// `result` must describe a live slice of `result_len` bytes (or be null with a
/// zero length).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_custom_op_record(result: *const u8, result_len: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller passes a live slice.
    let Some(result) = (unsafe { custom_op_bytes(result, result_len) }) else {
        return fail(EINVAL);
    };
    // `with_context_raw` for the same reason as `patina_custom_op_replay_result`:
    // the operation's single scheduling point was taken at `begin`.
    match with_context_raw(|context| context.custom_op_record(result.to_vec())) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Reborrow a `(ptr, len)` pair as opaque custom-op bytes. Unlike
/// [`buggify_label`] there is no UTF-8 requirement — a custom-op key or result is
/// whatever the guest's encoding produced — but a null pointer with a nonzero
/// length is still a fail-closed error.
///
/// # Safety
/// `ptr` must point to `len` readable bytes, or be null when `len == 0`.
unsafe fn custom_op_bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    // SAFETY: guaranteed by this function's documented contract.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

/// `patina_dst::rng()`: a deterministic 64-bit draw bridged to the root seed.
#[unsafe(no_mangle)]
pub extern "C" fn patina_rng() -> u64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    with_context(|context| Ok(context.buggify_rng())).unwrap_or(0)
}

/// `patina_dst::lifecycle::setup_complete()`: mark the setup boundary and emit a marker.
#[unsafe(no_mangle)]
pub extern "C" fn patina_lifecycle_setup_complete() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let _ = with_context(|context| {
        context.lifecycle_setup_complete();
        Ok(())
    });
    capture_stderr_line("PATINA_LIFECYCLE setup_complete");
    0
}

/// `patina_dst::lifecycle::event!("label")`: emit a lifecycle marker.
///
/// # Safety
/// Label pointer must describe a live UTF-8 slice of `label_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_lifecycle_event(label: *const u8, label_len: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller passes a live slice.
    let Some(label) = (unsafe { buggify_label(label, label_len) }) else {
        return fail(EINVAL);
    };
    capture_stderr_line(&format!("PATINA_LIFECYCLE_EVENT label={label}"));
    0
}

/// Deterministic managed threads and pthread synchronization.
///
/// The guest's `pthread_create`/`join`, `pthread_mutex_*`, and
/// `pthread_cond_*` calls (and thereby Rust `std::thread`, `Mutex`, and
/// `Condvar`) execute under Patina's [`DetScheduler`](patina_dst_sched_det). Real
/// host OS threads back each managed task, but a single execution baton ensures
/// exactly one runs at a time; every handoff is a seeded scheduler decision
/// recorded and replayed like any other boundary operation.
///
/// # Staying out of its own interposition
///
/// The shim interposes the guest's pthread symbols, so it must never call them
/// to implement itself, or it would recurse. Two choices keep the shim off its
/// own interposers, reaching each host vehicle through the sanctioned host-alias
/// table instead:
///
/// * Shim-internal synchronization never uses `std::sync` (which lowers to the
///   interposed pthread symbols). The short state sections use an atomics
///   [`SpinMutex`], and the execution baton is a per-task host OS semaphore
///   (`dispatch_semaphore` on macOS, POSIX `sem_t` on Linux) — pure blocking
///   primitives that carry no scheduling decision. Neither touches the
///   interposed pthread layer.
/// * A real host OS thread is created through a *distinct*, non-interposed
///   path: `pthread_create_suspended_np` (plus a mach `thread_resume`) on
///   macOS. glibc has no such variant, so on Linux the shim resolves the genuine
///   glibc `pthread_create` through the host-alias table's `dlsym(RTLD_NEXT, ...)`
///   primitive (`RTLD_NEXT` skips the shim's own strong-def interposer), exactly
///   as it reaches the real `read`/`write`/`sem_*`.
///
/// Every scheduling decision — which task runs next at each boundary — is made
/// by [`DetScheduler`](patina_dst_sched_det) and recorded/replayed; the OS
/// primitives only provide the vehicle and the blocking.
mod thread {
    #[cfg(target_os = "linux")]
    pub(crate) mod ipc;
    pub(crate) mod net;
    #[cfg(target_os = "linux")]
    pub(crate) mod readiness;
    #[cfg(target_os = "linux")]
    pub(crate) mod registrations;
    #[cfg(target_os = "linux")]
    pub(crate) mod sched;
    #[cfg(target_os = "linux")]
    pub(crate) mod signals;
    #[cfg(target_os = "linux")]
    pub(crate) mod timers;
    use std::cell::Cell;
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::c_char;
    use std::ffi::{c_int, c_void};
    use std::sync::{Arc, OnceLock};

    use patina_dst_abi::ClockKind;

    use super::fdtable::{DescId, FdKind};
    use super::hostcoll::{HostDeque, HostMap};
    use super::{
        EBUSY, EDEADLK, EINVAL, EISCONN, ENOTCONN, EOPNOTSUPP, EOVERFLOW, EPERM, ESRCH, ETIMEDOUT,
        EWOULDBLOCK, O_NONBLOCK, O_READ, O_WRITE, SpinGuard, SpinMutex, TaskId, host_write_all,
        with_context_msg, with_context_raw,
    };

    /// Where a guest number lands in this module's class tables. Every extern
    /// entry below resolves its guest number ONCE through the descriptor table
    /// and works on the handle from then on; the class tables never see a guest
    /// number. `EBADF` for an empty slot.
    fn class_entry(guest_fd: c_int) -> Result<super::fdtable::Resolved, c_int> {
        super::resolve_fd(guest_fd)
    }

    /// A guest number's socket handle and its `O_NONBLOCK`: `ENOTSOCK` for any
    /// other kind of description.
    fn socket_entry(guest_fd: c_int) -> Result<(c_int, bool), c_int> {
        let resolved = class_entry(guest_fd)?;
        match resolved.kind {
            FdKind::Socket => Ok((resolved.handle as c_int, resolved.status & O_NONBLOCK != 0)),
            FdKind::Stdin
            | FdKind::Stdout
            | FdKind::Stderr
            | FdKind::File
            | FdKind::Dir
            | FdKind::OPath
            | FdKind::Urandom
            | FdKind::Pipe => Err(super::ENOTSOCK),
            #[cfg(target_os = "linux")]
            FdKind::EventFd
            | FdKind::Epoll
            | FdKind::SignalFd
            | FdKind::MessageQueue
            | FdKind::TimerFd => Err(super::ENOTSOCK),
            #[cfg(target_os = "macos")]
            FdKind::Kqueue => Err(super::ENOTSOCK),
        }
    }

    /// A guest number's pipe-endpoint handle and its `O_NONBLOCK`: `EBADF` for
    /// anything that is not a pipe/FIFO endpoint.
    fn pipe_entry(guest_fd: c_int) -> Result<(c_int, bool), c_int> {
        let resolved = class_entry(guest_fd)?;
        match resolved.kind {
            FdKind::Pipe => Ok((resolved.handle as c_int, resolved.status & O_NONBLOCK != 0)),
            FdKind::Stdin
            | FdKind::Stdout
            | FdKind::Stderr
            | FdKind::File
            | FdKind::Dir
            | FdKind::OPath
            | FdKind::Urandom
            | FdKind::Socket => Err(super::EBADF),
            #[cfg(target_os = "linux")]
            FdKind::EventFd
            | FdKind::Epoll
            | FdKind::SignalFd
            | FdKind::MessageQueue
            | FdKind::TimerFd => Err(super::EBADF),
            #[cfg(target_os = "macos")]
            FdKind::Kqueue => Err(super::EBADF),
        }
    }

    /// Mint the next class handle. Handles are internal identities (never a
    /// guest number) shared by every class table in this module, so a handle
    /// is a socket XOR a pipe end XOR an eventfd; the descriptor table's kind
    /// says which.
    fn next_handle(state: &mut ThreadRuntime) -> c_int {
        let handle = state.net.next_handle;
        state.net.next_handle = state.net.next_handle.wrapping_add(1);
        handle
    }

    /// A guest thread body: `void *start_routine(void *arg)`.
    type StartRoutine = extern "C" fn(*mut c_void) -> *mut c_void;

    // Host thread creation: the shim interposes `pthread_create` with a strong
    // def, so to spawn a real OS thread it reaches the host creator through a
    // *distinct*, non-interposed path. On macOS that is
    // `pthread_create_suspended_np` plus a mach `thread_resume` (the created
    // thread parks on the baton immediately, so the brief suspend/resume is only
    // used to avoid the interposed name). glibc has no suspended variant, so on
    // Linux the shim resolves the genuine glibc `pthread_create` through the
    // host-alias table's `dlsym(RTLD_NEXT, ...)` primitive — the same mechanism
    // that reaches the real `read`/`write`/`sem_*`. `RTLD_NEXT` returns the libc
    // definition after the main executable, so the resolved vehicle is never this
    // shim's own interposer and the call cannot recurse. No `--wrap` and no named
    // import: `pthread_create` stays off the guest import table like the rest.
    /// Create a real, non-interposed host OS thread running `start(arg)` and
    /// write its `pthread_t` into `handle`. The thread's trampoline parks on the
    /// baton before executing any guest code. The creation vehicle is reached
    /// through the resolved host-alias table, so `pthread_create_suspended_np`,
    /// `pthread_mach_thread_np`, and `thread_resume` never appear in the guest
    /// binary's import table (see the top-level host-alias doctrine).
    ///
    /// # Safety
    /// `handle` must be writable and `start`/`arg` a valid thread entry point.
    #[cfg(target_os = "macos")]
    unsafe fn spawn_host_thread(
        handle: *mut *mut c_void,
        attr: *const c_void,
        start: StartRoutine,
        arg: *mut c_void,
    ) -> c_int {
        let api = crate::hostapi::get();
        // SAFETY: forwarded from this function's contract to the resolved host
        // `pthread_create_suspended_np`. `StartRoutine` here and the table's
        // matching type share the `extern "C" fn(*mut c_void) -> *mut c_void`
        // ABI, so the resolved pointer is called with its true signature.
        let rc = unsafe { (api.pthread_create_suspended_np)(handle, attr, start, arg) };
        if rc != 0 {
            return rc;
        }
        // SAFETY: `*handle` is the freshly created (suspended) host thread.
        unsafe { (api.thread_resume)((api.pthread_mach_thread_np)(handle.read())) };
        0
    }

    /// # Safety
    /// `handle` must be writable and `start`/`arg` a valid thread entry point.
    #[cfg(target_os = "linux")]
    unsafe fn spawn_host_thread(
        handle: *mut *mut c_void,
        attr: *const c_void,
        start: StartRoutine,
        arg: *mut c_void,
    ) -> c_int {
        // SAFETY: the real glibc `pthread_create` resolved through
        // `dlsym(RTLD_NEXT, ...)` (never this shim's strong-def interposer);
        // forwarded from this function's contract.
        unsafe { (crate::hostapi::get().host_pthread_create)(handle, attr, start, arg) }
    }

    thread_local! {
        /// The managed task this host thread runs, if any.
        static CURRENT_TASK: Cell<Option<TaskId>> = const { Cell::new(None) };
        /// Set once this host thread's task has completed (`thread_finish`), so
        /// any instrumented teardown it runs afterward — pthread TLS destructors
        /// under `--yield-points` execute std generic code monomorphized into the
        /// guest crate, which carries the yield hook — takes no scheduling point
        /// instead of rescheduling a task the scheduler has already removed. This
        /// is deliberately a *distinct* state from "never registered": a foreign
        /// or pre-registration thread that reaches a scheduling point still fails
        /// loudly through the unchanged `reschedule` path, never silently proceeds
        /// unscheduled.
        static TASK_COMPLETED: Cell<bool> = const { Cell::new(false) };
        /// The guest pc of the in-flight `--yield-points` guard hit, captured by
        /// [`yield_point_from`] so a replay divergence can name the instrumented
        /// site that took the extra scheduling point; 0 outside a guard hit.
        static YIELD_SITE: Cell<usize> = const { Cell::new(0) };
    }

    fn set_current_task(task: TaskId) {
        CURRENT_TASK.with(|cell| cell.set(Some(task)));
    }

    /// Mark this host thread's task as completed. Idempotent.
    fn mark_task_completed() {
        TASK_COMPLETED.with(|cell| cell.set(true));
    }

    /// Whether this host thread has already finished its managed task and is now
    /// in post-completion teardown.
    fn task_completed() -> bool {
        TASK_COMPLETED.with(Cell::get)
    }

    /// Set once the guest's `main` has returned (or the guest called `exit`), so
    /// the process is unwinding through the `exit` interposer. Unlike
    /// [`task_completed`] (per host thread, set for a *worker* at `thread_finish`),
    /// this is process-wide and covers the ROOT (main) task, which never runs
    /// `thread_finish` and so has no completion sentinel of its own. glibc drives
    /// the guest's thread-local destructors from inside `exit()` — under
    /// `--yield-points` those are instrumented std code that hits the yield hook —
    /// BEFORE the atexit-registered `patina_shutdown` runs `deactivate()`. Those
    /// teardown yields sit outside the deterministic body, and whether a given
    /// yield-guard edge fires before or after the runtime detaches is governed by
    /// host teardown ordering (glibc TLS-dtor vs atexit ordering, plus a
    /// still-exiting worker host thread), not the seed — so recording them lets a
    /// record run and a replay run disagree on a trailing `TaskYield`. Setting
    /// this at the `exit` boundary (never via `atexit`, which glibc runs *after*
    /// the TLS destructors) lets `sched_point` silence them deterministically.
    static MAIN_RETURNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// Mark the process as having entered post-`main` teardown. Idempotent.
    /// Called only by the `exit` interposer at the main-return/`exit` boundary.
    pub(crate) fn note_main_returned() {
        MAIN_RETURNED.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether the process has entered post-`main` teardown.
    pub(crate) fn main_returned() -> bool {
        MAIN_RETURNED.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The task of a host thread the runtime does not run (a foreign thread,
    /// or the main thread of an embedding without the POSIX startup
    /// constructor); the scheduler never issues task id 0.
    const UNMANAGED_TASK: TaskId = TaskId(0);

    /// The main thread's task. The scheduler numbers tasks from 1 and
    /// [`ThreadRuntime::ensure_active`] spawns the main thread's first, so the
    /// startup constructor can claim this identity for the main thread before
    /// the thread runtime activates. Everything that records a thread's
    /// identity before activation — a mutex or write-lock owner, a waiter —
    /// then names the same task after it: activation (the first
    /// `pthread_create`, but also a pipe, an eventfd, a FIFO open, a futex
    /// wait or any signal-state call) never changes who the main thread is.
    const MAIN_TASK: TaskId = TaskId(1);

    /// Claim [`MAIN_TASK`] for the calling thread. Called once, by the POSIX
    /// startup constructor, which the loader runs on the main thread.
    pub(crate) fn claim_main_thread() {
        set_current_task(MAIN_TASK);
    }

    fn current_task() -> TaskId {
        CURRENT_TASK.with(Cell::get).unwrap_or(UNMANAGED_TASK)
    }

    /// How far thread ids sit above task ids: the main thread is
    /// [`MAIN_TASK`], and its id is the guest's pid.
    const TID_OFFSET: u64 = crate::registry::IDENTITY_PID as u64 - 1;

    /// The thread id of `task`: the guest's pid for the main thread (and for
    /// the unmanaged main thread before the thread subsystem activates).
    pub(crate) fn tid_of(task: TaskId) -> c_int {
        if task == UNMANAGED_TASK {
            crate::registry::IDENTITY_PID as c_int
        } else {
            c_int::try_from(task.0 + TID_OFFSET).unwrap_or(c_int::MAX)
        }
    }

    /// The task a thread id names, if it is one a task could have (the
    /// thread ids below the guest's pid belong to no thread of the guest).
    #[cfg(target_os = "linux")]
    pub(crate) fn task_of(tid: c_int) -> Option<TaskId> {
        u64::try_from(tid)
            .ok()
            .filter(|tid| *tid > TID_OFFSET)
            .map(|tid| TaskId(tid - TID_OFFSET))
    }

    pub(crate) fn deterministic_thread_id() -> c_int {
        tid_of(current_task())
    }

    /// The calling thread's tid (the main thread's is the pid).
    #[cfg(target_os = "linux")]
    pub(crate) fn current_tid() -> i32 {
        deterministic_thread_id()
    }

    /// Whether `tid` names a live thread of the guest: the main thread (whose
    /// tid is the pid) before the thread subsystem activates, any task the
    /// signal state holds after.
    #[cfg(target_os = "linux")]
    pub(crate) fn live_tid(tid: i32) -> bool {
        let state = lock_state();
        live_tid_locked(&state, tid)
    }

    /// [`live_tid`] under the runtime lock the caller holds.
    #[cfg(target_os = "linux")]
    fn live_tid_locked(state: &ThreadRuntime, tid: i32) -> bool {
        if state.signals.is_empty() {
            return tid == crate::registry::IDENTITY_PID as i32;
        }
        task_of(tid).is_some_and(|task| state.signals.has_task(task))
    }

    /// The live threads of the virtual process.
    #[cfg(target_os = "linux")]
    pub(crate) fn live_threads() -> usize {
        lock_state().signals.task_count().max(1)
    }

    /// Detach the thread subsystem from the runtime at shutdown. Later boundary
    /// calls (for example `Mutex`/`Condvar` destructors as the program unwinds)
    /// then take no scheduling point and never touch the removed context.
    pub(crate) fn deactivate() {
        let mut state = lock_state();
        state.active = false;
    }

    fn fatal(message: &str) -> ! {
        // Like `trap_fatal`: `host_abort()` skips the shutdown flush, so the guest's
        // captured output goes out first — a probe that dies here (a deadlock,
        // an unmodeled flag) still leaves its event stream for the conformance
        // differ, which is what lets the testbed declare the death at an exact
        // event instead of writing the whole probe off.
        let _ = super::flush_before_refusal();
        let text = format!("patina native shim fatal: {message}\n");
        let _ = host_write_all(2, text.as_bytes());
        crate::host_abort();
    }

    /// A recoverable POSIX error code or a fatal determinism violation.
    #[derive(Debug)]
    enum ThreadError {
        Posix(c_int),
        Fatal(String),
    }

    impl ThreadError {
        fn into_posix(self) -> c_int {
            match self {
                Self::Posix(code) => code,
                Self::Fatal(message) => fatal(&message),
            }
        }
    }

    impl From<String> for ThreadError {
        fn from(message: String) -> Self {
            Self::Fatal(message)
        }
    }

    /// The scheduler transitions the thread runtime needs. Implemented for the
    /// real runtime [`Context`](super::Context) and, in tests, for a bare
    /// [`DetScheduler`](patina_dst_sched_det).
    trait Scheduler {
        fn spawn(&mut self, label: &str) -> Result<TaskId, String>;
        fn yield_task(&mut self, task: TaskId) -> Result<(), String>;
        fn park(&mut self, task: TaskId, reason: &str) -> Result<(), String>;
        fn park_timed(
            &mut self,
            task: TaskId,
            reason: &str,
            clock: ClockKind,
            deadline: u64,
        ) -> Result<(), String>;
        fn wake(&mut self, task: TaskId) -> Result<(), String>;
        fn complete(&mut self, task: TaskId) -> Result<(), String>;
        fn next(&mut self) -> Result<Option<TaskId>, String>;
    }

    /// Routes scheduler transitions through the installed runtime context so
    /// they are recorded and replayed like every other boundary operation.
    struct RealScheduler;

    impl Scheduler for RealScheduler {
        fn spawn(&mut self, label: &str) -> Result<TaskId, String> {
            with_context_msg(|context| context.task_spawn(label))
        }

        fn yield_task(&mut self, task: TaskId) -> Result<(), String> {
            with_context_msg(|context| context.task_yield(task))
        }

        fn park(&mut self, task: TaskId, reason: &str) -> Result<(), String> {
            with_context_msg(|context| context.task_park(task, reason))
        }

        fn park_timed(
            &mut self,
            task: TaskId,
            reason: &str,
            clock: ClockKind,
            deadline: u64,
        ) -> Result<(), String> {
            with_context_msg(|context| context.task_park_timed(task, reason, clock, deadline))
        }

        fn wake(&mut self, task: TaskId) -> Result<(), String> {
            with_context_msg(|context| context.task_wake(task))
        }

        fn complete(&mut self, task: TaskId) -> Result<(), String> {
            with_context_msg(|context| context.task_complete(task))
        }

        fn next(&mut self) -> Result<Option<TaskId>, String> {
            with_context_msg(super::Context::scheduler_next)
        }
    }

    /// A mutex's type: what its owner's relock does.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    enum MutexKind {
        /// `PTHREAD_MUTEX_NORMAL` (glibc's default, and its adaptive type):
        /// the owner's relock deadlocks, as glibc's does — the owner parks
        /// behind itself, and the run ends as a deadlock unless the guest has
        /// other work. Its unlock checks no owner: whoever unlocks it frees
        /// it, and unlocking it unlocked is 0.
        #[default]
        Normal,
        /// A normal mutex that is robust or priority-inheriting: its relock
        /// deadlocks as [`Self::Normal`]'s does, but an unlock by a thread
        /// that does not hold it is `EPERM`, as glibc's full unlock path
        /// answers. Decoded from glibc's flags, so only on Linux.
        #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
        NormalOwned,
        /// `PTHREAD_MUTEX_ERRORCHECK`: the owner's relock is `EDEADLK`.
        ErrorCheck,
        /// `PTHREAD_MUTEX_RECURSIVE`: the owner relocks, and the mutex is
        /// free after as many unlocks as locks.
        Recursive,
    }

    impl MutexKind {
        /// The type in glibc's encoding, shared by a mutex attribute's
        /// `mutexkind` and a mutex's `__kind`: the low two bits, and the
        /// robust (16) and priority-inheritance (32) flags, under which a
        /// normal mutex's unlock checks its owner. The other flags
        /// (process-shared, priority protection, elision) change neither.
        #[cfg(target_os = "linux")]
        fn from_glibc(kind: c_int) -> Self {
            const ROBUST: c_int = 16;
            const PRIO_INHERIT: c_int = 32;
            match kind & 3 {
                1 => Self::Recursive,
                2 => Self::ErrorCheck,
                _ if kind & (ROBUST | PRIO_INHERIT) != 0 => Self::NormalOwned,
                _ => Self::Normal,
            }
        }

        /// The type a `pthread_mutex_init` attribute names; no attribute is
        /// the default type.
        ///
        /// # Safety
        /// Non-null `attr` must point to an initialized `pthread_mutexattr_t`.
        unsafe fn of_attr(attr: *const c_void) -> Self {
            #[cfg(target_os = "linux")]
            {
                if attr.is_null() {
                    return Self::Normal;
                }
                // SAFETY: glibc's `struct pthread_mutexattr` is one `int`,
                // `mutexkind`.
                Self::from_glibc(unsafe { attr.cast::<c_int>().read() })
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = attr;
                Self::ErrorCheck
            }
        }

        /// The type of a mutex first touched without `pthread_mutex_init`:
        /// the one its static initializer wrote (glibc's
        /// `PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP` and
        /// `PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP` set `__kind`).
        ///
        /// # Safety
        /// `mutex` must point to a `pthread_mutex_t`.
        unsafe fn of_static(mutex: *const c_void) -> Self {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: `__kind` is the fifth `int` of glibc's
                // `struct __pthread_mutex_s` on the 64-bit targets.
                Self::from_glibc(unsafe { mutex.cast::<c_int>().add(4).read() })
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = mutex;
                Self::ErrorCheck
            }
        }
    }

    #[derive(Default)]
    struct MutexEntry {
        owner: Option<TaskId>,
        /// How many times the owner holds it: 1, or more for a recursive
        /// mutex.
        count: u32,
        kind: MutexKind,
        waiters: HostDeque<TaskId>,
    }

    impl MutexEntry {
        fn of_kind(kind: MutexKind) -> Self {
            Self {
                kind,
                ..Self::default()
            }
        }

        /// Hand the mutex to `task`, held once.
        fn grant(&mut self, task: TaskId) {
            self.owner = Some(task);
            self.count = 1;
        }
    }

    struct CondEntry {
        waiters: HostDeque<(TaskId, usize)>,
        /// The clock its timed waits judge their deadline on: its attribute's
        /// (`pthread_condattr_setclock`), `CLOCK_REALTIME` by default.
        clock: ClockKind,
    }

    impl Default for CondEntry {
        fn default() -> Self {
            Self {
                waiters: HostDeque::default(),
                clock: ClockKind::Realtime,
            }
        }
    }

    impl CondEntry {
        /// The clock a `pthread_cond_init` attribute names; no attribute is
        /// `CLOCK_REALTIME`.
        ///
        /// # Safety
        /// Non-null `attr` must point to an initialized `pthread_condattr_t`.
        unsafe fn clock_of_attr(attr: *const c_void) -> ClockKind {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: glibc's `struct pthread_condattr` is one `int`,
                // `value`: bit 0 process-shared, bit 1 the clock
                // (`CLOCK_MONOTONIC` when set; `pthread_condattr_setclock`
                // accepts only it and `CLOCK_REALTIME`).
                if !attr.is_null() && (unsafe { attr.cast::<c_int>().read() } >> 1) & 1 == 1 {
                    return ClockKind::Monotonic;
                }
            }
            let _ = attr;
            ClockKind::Realtime
        }
    }

    /// Which side a reader/writer lock favours when both wait
    /// (`nptl/pthread_rwlock_common.c`).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    #[allow(clippy::enum_variant_names)] // glibc's own names for the kinds
    enum RwLockKind {
        /// glibc's default, `PTHREAD_RWLOCK_PREFER_READER_NP`: a new reader
        /// acquires the lock whenever no writer holds it, waiting writers or
        /// not, and a releasing writer hands the lock to the waiting readers
        /// first.
        #[default]
        PreferReader,
        /// `PTHREAD_RWLOCK_PREFER_WRITER_NP`: readers are admitted as by
        /// default, but a releasing writer hands the lock to the next
        /// waiting writer first (glibc's writer-to-writer hand-over, which
        /// every kind but the default takes). Decoded from glibc's
        /// encoding, so only on Linux.
        #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
        PreferWriter,
        /// `PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP`: a releasing writer
        /// hands over to the next writer, and a new reader also waits while
        /// a writer holds the lock or waits for it, so readers never starve a
        /// writer.
        PreferWriterNonrecursive,
    }

    impl RwLockKind {
        /// The kind in glibc's encoding, shared by an attribute's `lockkind`
        /// and a lock's `__flags`.
        #[cfg(target_os = "linux")]
        fn from_glibc(kind: c_int) -> Self {
            match kind {
                0 => Self::PreferReader,
                2 => Self::PreferWriterNonrecursive,
                // glibc tests the default by equality: any other value hands
                // over writer to writer and admits readers.
                _ => Self::PreferWriter,
            }
        }

        /// The kind a `pthread_rwlock_init` attribute names; no attribute is
        /// the default kind.
        ///
        /// # Safety
        /// Non-null `attr` must point to an initialized `pthread_rwlockattr_t`.
        unsafe fn of_attr(attr: *const c_void) -> Self {
            #[cfg(target_os = "linux")]
            {
                if attr.is_null() {
                    return Self::PreferReader;
                }
                // SAFETY: glibc's `struct pthread_rwlockattr` starts with the
                // `int lockkind`.
                Self::from_glibc(unsafe { attr.cast::<c_int>().read() })
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = attr;
                Self::PreferWriterNonrecursive
            }
        }

        /// The kind of a lock first touched without `pthread_rwlock_init`:
        /// the one its static initializer wrote (glibc's
        /// `PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP` sets
        /// `__flags`).
        ///
        /// # Safety
        /// `lock` must point to a `pthread_rwlock_t`.
        unsafe fn of_static(lock: *const c_void) -> Self {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: `__flags` is the `unsigned int` at byte 48 of glibc's
                // `struct __pthread_rwlock_arch_t` on the 64-bit targets.
                Self::from_glibc(unsafe { lock.cast::<u8>().add(48).cast::<c_int>().read() })
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = lock;
                Self::PreferWriterNonrecursive
            }
        }
    }

    /// A deterministic reader/writer lock of one [`RwLockKind`]. Writers are
    /// granted in strict FIFO order; blocked readers are granted together (a
    /// batch wake, like a condvar broadcast). Every wake is a recorded
    /// scheduler decision, so the wake order is reproducible.
    #[derive(Default)]
    struct RwLockEntry {
        kind: RwLockKind,
        /// Number of tasks currently holding the read lock.
        readers: usize,
        /// The task currently holding the write lock, if any.
        writer: Option<TaskId>,
        write_waiters: HostDeque<TaskId>,
        read_waiters: HostDeque<TaskId>,
    }

    impl RwLockEntry {
        fn of_kind(kind: RwLockKind) -> Self {
            Self {
                kind,
                ..Self::default()
            }
        }

        /// Whether a new reader acquires the lock now.
        fn admits_reader(&self) -> bool {
            self.writer.is_none()
                && (self.kind != RwLockKind::PreferWriterNonrecursive
                    || self.write_waiters.is_empty())
        }
    }

    struct ThreadEntry {
        finished: bool,
        retval: usize,
        joiner: Option<TaskId>,
        detached: bool,
        // Some(false): temporarily runnable for a signal, still semantically
        // waiting. Some(true): an ordinary grant/notification arrived meanwhile.
        #[cfg(target_os = "linux")]
        signal_resume: Option<bool>,
    }

    enum LockStep {
        Acquired,
        MustBlock,
    }

    enum JoinStep {
        Done(usize),
        MustBlock,
    }

    /// Pure state of every virtual mutex, condition variable, and managed
    /// thread. Ownership transfer and wake decisions live here so they are
    /// unit-testable against any [`Scheduler`] without spawning host threads.
    ///
    /// Contended mutexes wake waiters in strict FIFO order, and an unlock hands
    /// ownership directly to the next waiter so no thundering herd occurs.
    #[derive(Default)]
    struct ThreadTable {
        // The synchronization tables are host-libc-backed (see `hostcoll`): the
        // lock/sync interposers register each lock lazily on first touch while
        // holding the shim spinlock, so they must never allocate through the
        // guest global allocator (a custom `#[global_allocator]` whose init takes
        // an interposed lock would re-enter and deadlock before `main`).
        mutexes: HostMap<usize, MutexEntry>,
        conds: HostMap<usize, CondEntry>,
        rwlocks: HostMap<usize, RwLockEntry>,
        // Thread lifecycle only — grown by explicit `pthread_create`/join, never
        // reentrantly from an allocation, so it stays on the ordinary allocator.
        threads: BTreeMap<TaskId, ThreadEntry>,
    }

    fn refuse_nested_sync_wait(interrupted: bool) {
        if interrupted {
            fatal("signal handler blocked on a pthread wait while interrupting one: not modeled");
        }
    }

    impl ThreadTable {
        fn sync_interrupted(&self, task: TaskId) -> bool {
            #[cfg(target_os = "linux")]
            {
                self.threads
                    .get(&task)
                    .is_some_and(|entry| entry.signal_resume.is_some())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = task;
                false
            }
        }

        fn register(&mut self, task: TaskId) {
            self.threads.insert(
                task,
                ThreadEntry {
                    finished: false,
                    retval: 0,
                    joiner: None,
                    detached: false,
                    #[cfg(target_os = "linux")]
                    signal_resume: None,
                },
            );
        }

        #[cfg(target_os = "linux")]
        fn still_waiting(&self, task: TaskId, loc: WaiterLoc) -> bool {
            match loc {
                WaiterLoc::Mutex(key) => self
                    .mutexes
                    .get(&key)
                    .is_some_and(|entry| entry.waiters.iter().any(|waiter| *waiter == task)),
                WaiterLoc::RwRead(key) => self
                    .rwlocks
                    .get(&key)
                    .is_some_and(|entry| entry.read_waiters.iter().any(|waiter| *waiter == task)),
                WaiterLoc::RwWrite(key) => self
                    .rwlocks
                    .get(&key)
                    .is_some_and(|entry| entry.write_waiters.iter().any(|waiter| *waiter == task)),
                WaiterLoc::Cond(cond, mutex) => {
                    self.conds.get(&cond).is_some_and(|entry| {
                        entry.waiters.iter().any(|(waiter, _)| *waiter == task)
                    }) || self.still_waiting(task, WaiterLoc::Mutex(mutex))
                }
                WaiterLoc::Join(target) => self
                    .threads
                    .get(&target)
                    .is_some_and(|entry| !entry.finished && entry.joiner == Some(task)),
                _ => false,
            }
        }

        fn notify(
            &mut self,
            scheduler: &mut dyn Scheduler,
            task: TaskId,
        ) -> Result<(), ThreadError> {
            #[cfg(target_os = "linux")]
            if let Some(notified) = self
                .threads
                .get_mut(&task)
                .and_then(|entry| entry.signal_resume.as_mut())
            {
                *notified = true;
                return Ok(());
            }
            scheduler.wake(task)?;
            Ok(())
        }

        fn init_mutex(&mut self, key: usize, kind: MutexKind) {
            self.mutexes.insert(key, MutexEntry::of_kind(kind));
        }

        /// The mutex at `key`; one never initialized is registered as `kind`
        /// on first touch.
        fn mutex(&mut self, key: usize, kind: MutexKind) -> &mut MutexEntry {
            self.mutexes
                .entry_or_insert_with(key, || MutexEntry::of_kind(kind))
        }

        /// Lock the mutex at `key` (`kind` if first touched here).
        fn lock(
            &mut self,
            me: TaskId,
            key: usize,
            kind: MutexKind,
        ) -> Result<LockStep, ThreadError> {
            let interrupted = self.sync_interrupted(me);
            let entry = self.mutex(key, kind);
            match entry.owner {
                None => {
                    entry.grant(me);
                    Ok(LockStep::Acquired)
                }
                Some(owner) if owner == me && entry.kind == MutexKind::ErrorCheck => {
                    Err(ThreadError::Posix(EDEADLK))
                }
                Some(owner) if owner == me && entry.kind == MutexKind::Recursive => {
                    entry.count = entry
                        .count
                        .checked_add(1)
                        .ok_or(ThreadError::Posix(EWOULDBLOCK))?; // EAGAIN
                    Ok(LockStep::Acquired)
                }
                // Another owner, or a normal mutex's owner relocking: wait.
                Some(_) => {
                    refuse_nested_sync_wait(interrupted);
                    entry.waiters.push_back(me);
                    Ok(LockStep::MustBlock)
                }
            }
        }

        /// Try to lock the mutex at `key` (`kind` if first touched here):
        /// `EBUSY` when it is held, by the caller too unless it is recursive.
        fn trylock(&mut self, me: TaskId, key: usize, kind: MutexKind) -> c_int {
            let entry = self.mutex(key, kind);
            match entry.owner {
                None => {
                    entry.grant(me);
                    0
                }
                Some(owner) if owner == me && entry.kind == MutexKind::Recursive => {
                    match entry.count.checked_add(1) {
                        Some(count) => {
                            entry.count = count;
                            0
                        }
                        None => EWOULDBLOCK, // EAGAIN
                    }
                }
                Some(_) => EBUSY,
            }
        }

        fn unlock(
            &mut self,
            scheduler: &mut dyn Scheduler,
            me: TaskId,
            key: usize,
        ) -> Result<(), ThreadError> {
            let entry = self
                .mutexes
                .get_mut(&key)
                .ok_or(ThreadError::Posix(EINVAL))?;
            if entry.owner != Some(me) {
                if entry.kind != MutexKind::Normal {
                    return Err(ThreadError::Posix(EPERM));
                }
                // glibc's normal unlock checks no owner: it frees a mutex
                // another thread holds, and one already unlocked stays so.
                if entry.owner.is_none() {
                    return Ok(());
                }
                entry.count = 1;
            }
            entry.count -= 1;
            if entry.count > 0 {
                return Ok(());
            }
            if let Some(next) = entry.waiters.pop_front() {
                entry.grant(next);
                self.notify(scheduler, next)?;
            } else {
                entry.owner = None;
            }
            Ok(())
        }

        fn destroy_mutex(&mut self, key: usize) -> Result<(), ThreadError> {
            if let Some(entry) = self.mutexes.get(&key) {
                if entry.owner.is_some() || !entry.waiters.is_empty() {
                    return Err(ThreadError::Posix(EBUSY));
                }
                self.mutexes.remove(&key);
            }
            Ok(())
        }

        fn init_rwlock(&mut self, key: usize, kind: RwLockKind) {
            self.rwlocks.insert(key, RwLockEntry::of_kind(kind));
        }

        /// The lock at `key`; one never initialized is registered as `kind` on
        /// first touch.
        fn rwlock(&mut self, key: usize, kind: RwLockKind) -> &mut RwLockEntry {
            self.rwlocks
                .entry_or_insert_with(key, || RwLockEntry::of_kind(kind))
        }

        /// Acquire the read lock, blocking unless the lock admits a new reader
        /// ([`RwLockEntry::admits_reader`]). The writer's own call is
        /// `EDEADLK`.
        fn rwlock_rdlock(
            &mut self,
            me: TaskId,
            key: usize,
            kind: RwLockKind,
        ) -> Result<LockStep, ThreadError> {
            let interrupted = self.sync_interrupted(me);
            let entry = self.rwlock(key, kind);
            if entry.writer == Some(me) {
                return Err(ThreadError::Posix(EDEADLK));
            }
            if entry.admits_reader() {
                entry.readers += 1;
                Ok(LockStep::Acquired)
            } else {
                refuse_nested_sync_wait(interrupted);
                entry.read_waiters.push_back(me);
                Ok(LockStep::MustBlock)
            }
        }

        /// Acquire the write lock: exclusive, so block unless the lock is fully
        /// idle (no readers and no writer).
        fn rwlock_wrlock(
            &mut self,
            me: TaskId,
            key: usize,
            kind: RwLockKind,
        ) -> Result<LockStep, ThreadError> {
            let interrupted = self.sync_interrupted(me);
            let entry = self.rwlock(key, kind);
            if entry.writer == Some(me) {
                return Err(ThreadError::Posix(EDEADLK));
            }
            if entry.writer.is_none() && entry.readers == 0 {
                entry.writer = Some(me);
                Ok(LockStep::Acquired)
            } else {
                refuse_nested_sync_wait(interrupted);
                entry.write_waiters.push_back(me);
                Ok(LockStep::MustBlock)
            }
        }

        /// Try the read lock: `EBUSY` unless it admits a new reader, for the
        /// writer too (glibc's non-blocking calls do not check the writer).
        fn rwlock_tryrdlock(&mut self, key: usize, kind: RwLockKind) -> c_int {
            let entry = self.rwlock(key, kind);
            if entry.admits_reader() {
                entry.readers += 1;
                0
            } else {
                EBUSY
            }
        }

        /// Try the write lock: `EBUSY` unless the lock is idle.
        fn rwlock_trywrlock(&mut self, me: TaskId, key: usize, kind: RwLockKind) -> c_int {
            let entry = self.rwlock(key, kind);
            if entry.writer.is_none() && entry.readers == 0 {
                entry.writer = Some(me);
                0
            } else {
                EBUSY
            }
        }

        /// Release whichever mode `me` holds, then grant the idle lock to the
        /// next waiter(s) deterministically: the preferred side first — every
        /// blocked reader together, or the first waiting writer (FIFO) — and
        /// the other side only when none of the preferred one waits.
        fn rwlock_unlock(
            &mut self,
            scheduler: &mut dyn Scheduler,
            me: TaskId,
            key: usize,
        ) -> Result<(), ThreadError> {
            let entry = self
                .rwlocks
                .get_mut(&key)
                .ok_or(ThreadError::Posix(EINVAL))?;
            if entry.writer == Some(me) {
                entry.writer = None;
            } else if entry.readers > 0 {
                entry.readers -= 1;
                if entry.readers > 0 {
                    // Other readers still hold the lock; no grant yet.
                    return Ok(());
                }
            } else {
                return Err(ThreadError::Posix(EPERM));
            }
            // The lock is now idle (no writer, no readers). Grant it.
            // Every kind but the default hands a writer's release to the next
            // writer; a reader's last release finds only writers waiting.
            let readers_first = entry.kind == RwLockKind::PreferReader;
            let next_writer = if readers_first && !entry.read_waiters.is_empty() {
                None
            } else {
                entry.write_waiters.pop_front()
            };
            if let Some(next) = next_writer {
                entry.writer = Some(next);
                self.notify(scheduler, next)?;
            } else {
                // Batch-wake every blocked reader in FIFO order. Drained one at a
                // time (re-borrowing the entry each step) rather than collected
                // into a `Vec` — the collection would allocate through the guest
                // global allocator, which the sync path must never touch.
                entry.readers = entry.read_waiters.len();
                loop {
                    let reader = self
                        .rwlocks
                        .get_mut(&key)
                        .and_then(|entry| entry.read_waiters.pop_front());
                    match reader {
                        Some(reader) => self.notify(scheduler, reader)?,
                        None => break,
                    }
                }
            }
            Ok(())
        }

        fn destroy_rwlock(&mut self, key: usize) -> Result<(), ThreadError> {
            if let Some(entry) = self.rwlocks.get(&key) {
                if entry.writer.is_some()
                    || entry.readers > 0
                    || !entry.write_waiters.is_empty()
                    || !entry.read_waiters.is_empty()
                {
                    return Err(ThreadError::Posix(EBUSY));
                }
                self.rwlocks.remove(&key);
            }
            Ok(())
        }

        fn init_cond(&mut self, key: usize, clock: ClockKind) {
            self.conds.insert(
                key,
                CondEntry {
                    clock,
                    ..CondEntry::default()
                },
            );
        }

        /// The clock the condition variable at `key` judges deadlines on.
        fn cond_clock(&self, key: usize) -> ClockKind {
            self.conds
                .get(&key)
                .map_or(ClockKind::Realtime, |cond| cond.clock)
        }

        /// Release `mutex_key` (waking its next waiter) and enqueue `me` on the
        /// condition variable. The caller then parks `me`; a later signal or
        /// broadcast re-grants the mutex before `me` resumes, so there are no
        /// spurious wakeups.
        fn cond_wait(
            &mut self,
            scheduler: &mut dyn Scheduler,
            me: TaskId,
            cond_key: usize,
            mutex_key: usize,
        ) -> Result<(), ThreadError> {
            refuse_nested_sync_wait(self.sync_interrupted(me));
            self.unlock(scheduler, me, mutex_key)?;
            self.conds
                .entry_or_default(cond_key)
                .waiters
                .push_back((me, mutex_key));
            Ok(())
        }

        fn cond_signal(
            &mut self,
            scheduler: &mut dyn Scheduler,
            cond_key: usize,
        ) -> Result<(), ThreadError> {
            let woken = self
                .conds
                .get_mut(&cond_key)
                .and_then(|cond| cond.waiters.pop_front());
            if let Some((task, mutex_key)) = woken {
                let entry = self.mutexes.entry_or_default(mutex_key);
                match entry.owner {
                    None => {
                        entry.grant(task);
                        self.notify(scheduler, task)?;
                    }
                    // A recursive mutex held more than once stays the
                    // waiter's across the wait; glibc's re-lock counts it
                    // again (its recursive relock), and the waiter resumes.
                    Some(owner) if owner == task => {
                        entry.count += 1;
                        self.notify(scheduler, task)?;
                    }
                    Some(_) => entry.waiters.push_back(task),
                }
            }
            Ok(())
        }

        fn cond_broadcast(
            &mut self,
            scheduler: &mut dyn Scheduler,
            cond_key: usize,
        ) -> Result<(), ThreadError> {
            while self
                .conds
                .get(&cond_key)
                .is_some_and(|cond| !cond.waiters.is_empty())
            {
                self.cond_signal(scheduler, cond_key)?;
            }
            Ok(())
        }

        fn destroy_cond(&mut self, key: usize) -> Result<(), ThreadError> {
            if let Some(cond) = self.conds.get(&key) {
                if !cond.waiters.is_empty() {
                    return Err(ThreadError::Posix(EBUSY));
                }
                self.conds.remove(&key);
            }
            Ok(())
        }

        /// Join `target`: its value if it has finished, else wait. A detached
        /// target is `EINVAL`, and then a join that could never end — of the
        /// caller itself, or of a thread waiting to join the caller — is
        /// `EDEADLK`, in glibc's order.
        fn begin_join(&mut self, me: TaskId, target: TaskId) -> Result<JoinStep, ThreadError> {
            let interrupted = self.sync_interrupted(me);
            if self
                .threads
                .get(&target)
                .is_some_and(|entry| entry.detached)
            {
                return Err(ThreadError::Posix(EINVAL));
            }
            let joins_me = self
                .threads
                .get(&me)
                .is_some_and(|entry| !entry.finished && entry.joiner == Some(target));
            if target == me || joins_me {
                return Err(ThreadError::Posix(EDEADLK));
            }
            let entry = self
                .threads
                .get_mut(&target)
                .ok_or(ThreadError::Posix(ESRCH))?;
            if entry.detached {
                return Err(ThreadError::Posix(EINVAL));
            }
            if entry.finished {
                let retval = entry.retval;
                self.threads.remove(&target);
                return Ok(JoinStep::Done(retval));
            }
            if entry.joiner.is_some() {
                return Err(ThreadError::Posix(EINVAL));
            }
            refuse_nested_sync_wait(interrupted);
            entry.joiner = Some(me);
            Ok(JoinStep::MustBlock)
        }

        fn take_join_result(&mut self, target: TaskId) -> usize {
            self.threads.remove(&target).map_or(0, |entry| entry.retval)
        }

        fn detach(&mut self, target: TaskId) -> Result<(), ThreadError> {
            let entry = self
                .threads
                .get_mut(&target)
                .ok_or(ThreadError::Posix(ESRCH))?;
            if entry.detached || entry.joiner.is_some() {
                return Err(ThreadError::Posix(EINVAL));
            }
            entry.detached = true;
            if entry.finished {
                self.threads.remove(&target);
            }
            Ok(())
        }

        fn exit(
            &mut self,
            scheduler: &mut dyn Scheduler,
            me: TaskId,
            retval: usize,
        ) -> Result<(), ThreadError> {
            let entry = self.threads.get_mut(&me).ok_or(ThreadError::Posix(ESRCH))?;
            entry.finished = true;
            entry.retval = retval;
            let joiner = entry.joiner;
            let detached = entry.detached;
            if let Some(joiner) = joiner {
                self.notify(scheduler, joiner)?;
            }
            scheduler.complete(me)?;
            if detached && joiner.is_none() {
                self.threads.remove(&me);
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum BlockClass {
        Io,
        Futex,
        TimedFutex,
        Sleep,
        Readiness,
        Sync,
        #[cfg(target_os = "linux")]
        Pause,
        #[cfg(target_os = "linux")]
        SigSuspend,
        #[cfg(target_os = "linux")]
        SigWait,
        #[cfg(target_os = "linux")]
        SignalfdRead,
        /// A System V IPC wait: never restarted after a handler (`EINTR`).
        #[cfg(target_os = "linux")]
        Ipc,
    }

    #[derive(Clone)]
    struct Wait {
        class: BlockClass,
        locs: Vec<WaiterLoc>,
        #[cfg(target_os = "linux")]
        wanted: u64,
    }
    impl Wait {
        fn new(class: BlockClass, locs: Vec<WaiterLoc>) -> Self {
            Self {
                class,
                locs,
                #[cfg(target_os = "linux")]
                wanted: 0,
            }
        }
        #[cfg(target_os = "linux")]
        fn signals(mut self, wanted: u64) -> Self {
            self.wanted = wanted;
            self
        }
    }

    /// The scheduling result of a boundary or blocking operation.
    enum Step {
        /// Keep running on this thread.
        Continue,
        /// Transfer the baton to the given task and wait to be resumed.
        Switch(TaskId),
    }

    enum JoinResolve {
        Ready(usize),
        Blocked(Step),
    }

    /// Per-managed-thread blocking primitive. The execution baton is handed to a
    /// task by signaling its semaphore; a task parks by waiting on its own. The
    /// backing host OS semaphore (a libdispatch semaphore on macOS, a POSIX
    /// `sem_t` on Linux) is a pure blocking primitive that carries no
    /// deterministic decision — every scheduling choice is made by
    /// [`DetScheduler`](patina_dst_sched_det).
    ///
    /// On macOS the baton uses the *canonical* Darwin primitive — a libdispatch
    /// semaphore, the same one Rust std's thread [`Parker`] uses — rather than a
    /// distinct one chosen to dodge the symbol namespace. That is only safe
    /// because of the host-alias doctrine: the shim interposes
    /// `dispatch_semaphore_*` with public strong defs (so a *guest* `Parker`
    /// routes through the deterministic scheduler), while the baton reaches the
    /// *real* libdispatch entry points through the host-alias table
    /// (`dlsym(RTLD_NEXT, ...)`), so it never recurses into its own interposer.
    /// The vehicle names therefore never appear in the guest import table (only
    /// `dlsym` does), so no `--allow` is needed and a guest importing
    /// `dispatch_semaphore_wait` still fails the audit. Matching the native
    /// primitive is also a robustness win: the baton exercises this shim-vs-guest
    /// discrimination on every context switch, so a doctrine regression deadlocks
    /// immediately instead of lying dormant.
    #[cfg(target_os = "macos")]
    mod baton {
        use std::ffi::c_void;

        use crate::hostapi;

        // `<dispatch/time.h>`: `DISPATCH_TIME_FOREVER == ~0ull`. The baton never
        // times out — a park blocks until the baton is handed back by a signal.
        const DISPATCH_TIME_FOREVER: u64 = u64::MAX;

        /// The per-task execution baton: a real libdispatch counting semaphore
        /// (created with value 0, so the first wait blocks until the baton is
        /// first handed over). This is the *canonical* Darwin primitive — the
        /// same one Rust std's `Parker` uses — chosen deliberately to match the
        /// native implementation. The doctrine makes reusing it safe: the shim
        /// reaches the REAL libdispatch entry points through the host-alias table
        /// (`dlsym(RTLD_NEXT, ...)`), while the shim's own public
        /// `dispatch_semaphore_*` strong-def interposers capture *guest* parking
        /// and route it through the deterministic scheduler. Because the baton
        /// exercises that shim-vs-guest discrimination on every context switch, a
        /// doctrine regression (the baton accidentally binding the interposer)
        /// deadlocks immediately instead of lying dormant.
        pub(super) struct Semaphore(*mut c_void);

        // SAFETY: libdispatch semaphores are thread-safe objects.
        unsafe impl Send for Semaphore {}
        // SAFETY: as above.
        unsafe impl Sync for Semaphore {}

        impl Semaphore {
            pub(super) fn new() -> Self {
                // Initial value 0: the first wait blocks until the baton is handed
                // over, exactly matching the previous Mach-semaphore baton.
                let handle = unsafe { (hostapi::get().dispatch_semaphore_create)(0) };
                assert!(!handle.is_null(), "dispatch_semaphore_create failed");
                Self(handle)
            }

            pub(super) fn wait(&self) {
                // SAFETY: `self.0` is a live dispatch semaphore for this object's
                // lifetime. `DISPATCH_TIME_FOREVER` blocks until signalled and
                // never times out (libdispatch absorbs interrupts internally), so
                // the wait returns only when the baton is handed to this task —
                // the same "block until handed the baton" contract the Mach
                // `semaphore_wait` EINTR loop provided.
                unsafe { (hostapi::get().dispatch_semaphore_wait)(self.0, DISPATCH_TIME_FOREVER) };
            }

            pub(super) fn signal(&self) {
                // SAFETY: as above; hands the baton to the task waiting on `self`.
                unsafe { (hostapi::get().dispatch_semaphore_signal)(self.0) };
            }
        }

        impl Drop for Semaphore {
            fn drop(&mut self) {
                // A baton at rest has value 0 (its created value), so releasing is
                // sound (libdispatch traps a release below the created value). In
                // practice managed-task batons live for the process — the runtime's
                // `sems` map is never pruned — so this is defensive lifecycle
                // correctness mirroring a native libdispatch client, not a hot path.
                // SAFETY: `self.0` is a live dispatch object with no waiters.
                unsafe { (hostapi::get().dispatch_release)(self.0) };
            }
        }
    }

    #[cfg(target_os = "linux")]
    mod baton {
        use crate::hostapi;

        // `sem_t` is opaque; glibc's is 32 bytes. Over-allocate and align so the
        // backing storage is valid on any supported layout.
        #[repr(C, align(16))]
        struct SemStorage([u8; 64]);

        pub(super) struct Semaphore(*mut SemStorage);

        // SAFETY: POSIX semaphores are thread-safe; the storage is heap-pinned.
        unsafe impl Send for Semaphore {}
        // SAFETY: as above.
        unsafe impl Sync for Semaphore {}

        impl Semaphore {
            pub(super) fn new() -> Self {
                let storage = Box::into_raw(Box::new(SemStorage([0; 64])));
                // SAFETY: `storage` is a fresh, correctly aligned `sem_t` slot.
                // `sem_init` is reached through the resolved host-alias table, so
                // `sem_init`/`sem_wait`/`sem_post` never appear in the guest
                // binary's import table (see the top-level host-alias doctrine):
                // the shim's use is invisible to the symbol namespace, so even a
                // guest that itself uses POSIX semaphores could be interposed
                // without colliding with the baton.
                let rc = unsafe { (hostapi::get().sem_init)(storage.cast(), 0, 0) };
                assert!(rc == 0, "sem_init failed");
                Self(storage)
            }

            pub(super) fn wait(&self) {
                let wait = hostapi::get().sem_wait;
                // SAFETY: `self.0` is a live semaphore; retry on EINTR.
                while unsafe { wait(self.0.cast()) } != 0 {}
            }

            pub(super) fn signal(&self) {
                // SAFETY: as above.
                unsafe { (hostapi::get().sem_post)(self.0.cast()) };
            }
        }
        // Intentionally not `Drop`: managed-thread semaphores live for the
        // process, so the pinned storage is deliberately leaked.
    }

    /// Release the state lock, hand the baton to `picked` by signaling its
    /// semaphore, then park on `me`'s semaphore until it is handed back.
    fn handoff(state: SpinGuard<'_, ThreadRuntime>, picked: TaskId, me: TaskId) {
        let picked_sem = state.task_sem(picked);
        let my_sem = state.task_sem(me);
        drop(state);
        picked_sem.signal();
        my_sem.wait();
    }

    fn switch_and_park(state: SpinGuard<'_, ThreadRuntime>, picked: TaskId, me: TaskId) {
        handoff(state, picked, me);
        #[cfg(target_os = "linux")]
        {
            while let Some(blocked) = signals::take_sync_resume(me) {
                // Pthread waits retain their semantic registration while a
                // handler runs. Grants mark completion, not another wake.
                signals::deliver();
                let mut state = lock_state();
                let notified = state
                    .table
                    .threads
                    .get_mut(&me)
                    .unwrap()
                    .signal_resume
                    .take()
                    .unwrap_or_else(|| fatal("signal-woken pthread waiter lost resume state"));
                if notified {
                    state.remove_signal_wait(me);
                    return;
                }
                let wait = Wait::new(blocked.class, blocked.locs);
                let step = match blocked.deadline {
                    Some((clock, deadline)) => {
                        state.block_timed(me, blocked.reason, wait, clock, deadline)
                    }
                    None => state.block(me, blocked.reason, wait),
                };
                match step {
                    Ok(Step::Switch(next)) => handoff(state, next, me),
                    Ok(Step::Continue) => return,
                    Err(error) => fatal(&format!(
                        "resuming pthread wait failed: {}",
                        error.into_posix()
                    )),
                }
            }
            let mut resumed = lock_state();
            let sync = resumed
                .signals
                .blocked
                .get(&me)
                .is_some_and(|wait| wait.class == BlockClass::Sync);
            resumed.remove_signal_wait(me);
            drop(resumed);
            if sync {
                signals::deliver();
            }
        }
    }

    /// Baton-guarded state shared by every managed host thread. Only the current
    /// baton holder touches it, so the spinlock is essentially uncontended.
    struct ThreadRuntime {
        table: ThreadTable,
        #[cfg(target_os = "linux")]
        signals: signals::SignalRuntime,
        /// System V IPC objects and their waiters.
        #[cfg(target_os = "linux")]
        ipc: ipc::Ipc,
        /// Per-thread scheduling attributes and persona.
        #[cfg(target_os = "linux")]
        sched: sched::SchedRuntime,
        /// Per-thread kernel registrations (the robust-futex list head).
        #[cfg(target_os = "linux")]
        registrations: registrations::RegistrationRuntime,
        /// The interval timers, POSIX timers and timer descriptors.
        #[cfg(target_os = "linux")]
        timers: timers::Timers,
        /// Real host `pthread_t` bits mapped to the managed task they run.
        handles: BTreeMap<usize, TaskId>,
        /// Per-task baton semaphores.
        sems: BTreeMap<TaskId, Arc<baton::Semaphore>>,
        /// Virtual datagram sockets delegating to the runtime's `SimNet`.
        net: NetState,
        /// Tasks parked on a Linux futex word, keyed by the word's address.
        /// Rust std on Linux lowers `Mutex`/`Condvar`/thread parking to raw
        /// `SYS_futex` through libc's `syscall` wrapper rather than pthread, so
        /// the interposed `syscall` routes those waits/wakes here.
        futexes: BTreeMap<usize, VecDeque<TaskId>>,
        /// The tasks among [`Self::futexes`]' waiters that wait with
        /// `FUTEX_PRIVATE_FLAG`, set or cleared each time a task parks. Only a
        /// dead robust owner's wake tells them apart: the kernel wakes those
        /// futexes by their shared key, which a private waiter's does not
        /// match.
        private_futex_waits: std::collections::BTreeSet<TaskId>,
        /// Timed waiters (`cond_timedwait`, timed futex waits) whose deadline
        /// fired: the runtime's deadlock-rescue woke them, and this shim purged
        /// them from their primitive's waiter list. On resume they return
        /// `ETIMEDOUT` instead of the signalled `0`. Populated by
        /// [`ThreadRuntime::settle_rescued`] from the runtime's rescued set.
        timed_out: std::collections::BTreeSet<TaskId>,
        /// libdispatch semaphores modeled deterministically, keyed by the opaque
        /// handle the interposed `dispatch_semaphore_create` hands out. std's
        /// Darwin thread `Parker` (and everything built on it: `mpsc`/`mpmc`
        /// `recv`/`recv_timeout`, `Once`, ...) blocks here through the interposed
        /// `dispatch_semaphore_wait` so it stays on the scheduler + virtual clock.
        #[cfg(target_os = "macos")]
        dispatch: BTreeMap<usize, DispatchSem>,
        /// Monotonic allocator for dispatch-semaphore handles. Starts at one so
        /// the pointer std stores is never null (it asserts non-null).
        #[cfg(target_os = "macos")]
        next_dispatch_handle: usize,
        active: bool,
    }

    /// A libdispatch counting semaphore modeled for the deterministic scheduler.
    /// `count` follows dispatch semantics: `wait` decrements and blocks when the
    /// result is negative, `signal` increments and wakes one waiter when the
    /// result is not positive. A negative `count` equals the number of blocked
    /// waiters, so a timed-out waiter restores one to `count` when it leaves.
    #[cfg(target_os = "macos")]
    #[derive(Default)]
    struct DispatchSem {
        count: isize,
        waiters: VecDeque<TaskId>,
    }

    impl ThreadRuntime {
        /// Note whether `task`, parking on a futex word, waits privately.
        fn note_futex_wait(&mut self, task: TaskId, private: bool) {
            if private {
                self.private_futex_waits.insert(task);
            } else {
                self.private_futex_waits.remove(&task);
            }
        }

        fn task_sem(&self, task: TaskId) -> Arc<baton::Semaphore> {
            Arc::clone(
                self.sems
                    .get(&task)
                    .expect("every managed task has a baton semaphore"),
            )
        }

        /// Register the main thread as the first managed task, [`MAIN_TASK`],
        /// and give it the baton the first time the thread subsystem is used.
        fn ensure_active(&mut self) -> Result<(), ThreadError> {
            if self.active {
                return Ok(());
            }
            let mut scheduler = RealScheduler;
            let main = scheduler.spawn("main")?;
            if main != MAIN_TASK {
                return Err(ThreadError::Fatal(format!(
                    "the scheduler numbered the main task {main:?}, not {MAIN_TASK:?}"
                )));
            }
            let selected = scheduler.next()?;
            if selected != Some(main) {
                return Err(ThreadError::Fatal(format!(
                    "scheduler selected {selected:?} instead of the main task {main:?}"
                )));
            }
            self.table.register(main);
            #[cfg(target_os = "linux")]
            self.signals.spawn(main, None);
            #[cfg(target_os = "linux")]
            self.handles
                .insert(unsafe { (crate::hostapi::get().host_pthread_self)() }, main);
            self.sems.insert(main, Arc::new(baton::Semaphore::new()));
            self.active = true;
            set_current_task(main);
            Ok(())
        }

        /// Pick the next task. On Linux the process's timers come first: what
        /// virtual time reached fires, and while every task waits idle time
        /// advances to a timer ahead of every parked deadline, whose expiry may
        /// wake one (`timers`). The pick may run the deadlock rescue, which
        /// wakes the tasks whose own deadlines came due; they are settled
        /// (unlinked from every wait) before the timers that came due with
        /// them fire, so an expiry never wakes a task the rescue already woke.
        fn next_task(&mut self) -> Result<Option<TaskId>, ThreadError> {
            #[cfg(target_os = "linux")]
            for task in self.idle_timers()? {
                RealScheduler.wake(task)?;
            }
            let next = RealScheduler.next()?;
            self.settle_rescued()?;
            #[cfg(target_os = "linux")]
            for task in self.fire_timers().map_err(ThreadError::Posix)? {
                RealScheduler.wake(task)?;
            }
            Ok(next)
        }

        fn reschedule(&mut self, me: TaskId) -> Result<Option<TaskId>, ThreadError> {
            let mut scheduler = RealScheduler;
            scheduler.yield_task(me)?;
            Ok(scheduler.next()?)
        }

        fn begin_lock(
            &mut self,
            me: TaskId,
            key: usize,
            kind: MutexKind,
        ) -> Result<Step, ThreadError> {
            match self.table.lock(me, key, kind)? {
                LockStep::Acquired => Ok(Step::Continue),
                LockStep::MustBlock => self.block(
                    me,
                    "mutex-contended",
                    Wait::new(BlockClass::Sync, vec![WaiterLoc::Mutex(key)]),
                ),
            }
        }

        fn begin_rdlock(
            &mut self,
            me: TaskId,
            key: usize,
            kind: RwLockKind,
        ) -> Result<Step, ThreadError> {
            match self.table.rwlock_rdlock(me, key, kind)? {
                LockStep::Acquired => Ok(Step::Continue),
                LockStep::MustBlock => self.block(
                    me,
                    "rwlock-read-contended",
                    Wait::new(BlockClass::Sync, vec![WaiterLoc::RwRead(key)]),
                ),
            }
        }

        fn begin_wrlock(
            &mut self,
            me: TaskId,
            key: usize,
            kind: RwLockKind,
        ) -> Result<Step, ThreadError> {
            match self.table.rwlock_wrlock(me, key, kind)? {
                LockStep::Acquired => Ok(Step::Continue),
                LockStep::MustBlock => self.block(
                    me,
                    "rwlock-write-contended",
                    Wait::new(BlockClass::Sync, vec![WaiterLoc::RwWrite(key)]),
                ),
            }
        }

        fn begin_cond_wait(
            &mut self,
            me: TaskId,
            cond_key: usize,
            mutex_key: usize,
        ) -> Result<Step, ThreadError> {
            let mut scheduler = RealScheduler;
            self.table
                .cond_wait(&mut scheduler, me, cond_key, mutex_key)?;
            self.block(
                me,
                "cond-wait",
                Wait::new(BlockClass::Sync, vec![WaiterLoc::Cond(cond_key, mutex_key)]),
            )
        }

        fn begin_join(&mut self, me: TaskId, target: TaskId) -> Result<JoinResolve, ThreadError> {
            match self.table.begin_join(me, target)? {
                JoinStep::Done(retval) => Ok(JoinResolve::Ready(retval)),
                JoinStep::MustBlock => Ok(JoinResolve::Blocked(self.block(
                    me,
                    "join",
                    Wait::new(BlockClass::Sync, vec![WaiterLoc::Join(target)]),
                )?)),
            }
        }

        fn block(
            &mut self,
            me: TaskId,
            reason: &'static str,
            wait: Wait,
        ) -> Result<Step, ThreadError> {
            if wait.class == BlockClass::Sync {
                refuse_nested_sync_wait(self.table.sync_interrupted(me));
            }
            // A wait before the first thread (a normal mutex's owner relocking
            // it) parks the main task, so the scheduler must know it.
            self.ensure_active()?;
            #[cfg(target_os = "linux")]
            self.register_signal_wait(me, reason, wait, None);
            #[cfg(not(target_os = "linux"))]
            let _ = (wait.class, wait.locs);
            let mut scheduler = RealScheduler;
            scheduler.park(me, reason)?;
            let next = self.next_task()?;
            match next {
                Some(next) => Ok(Step::Switch(next)),
                None => Err(ThreadError::Fatal(
                    "scheduler returned no runnable task after parking".into(),
                )),
            }
        }

        /// Park `me` with a virtual-clock deadline, hand off the baton, and
        /// report whether another task took over. Unlike [`Self::block`] this can
        /// return [`Step::Continue`]: if `me`'s own timer is the earliest and no
        /// other task is runnable, the deadlock-rescue advances virtual time and
        /// re-selects `me` in the same `scheduler.next()`, so `me` keeps running.
        fn block_timed(
            &mut self,
            me: TaskId,
            reason: &'static str,
            wait: Wait,
            clock: ClockKind,
            deadline: u64,
        ) -> Result<Step, ThreadError> {
            if wait.class == BlockClass::Sync {
                refuse_nested_sync_wait(self.table.sync_interrupted(me));
            }
            // As in `block`: the main task may wait before the first thread.
            self.ensure_active()?;
            let mut scheduler = RealScheduler;
            #[cfg(target_os = "linux")]
            self.register_signal_wait(me, reason, wait, Some((clock, deadline)));
            #[cfg(not(target_os = "linux"))]
            let _ = (wait.class, wait.locs);
            scheduler.park_timed(me, reason, clock, deadline)?;
            let next = self.next_task()?;
            match next {
                Some(picked) if picked == me => Ok(Step::Continue),
                Some(picked) => Ok(Step::Switch(picked)),
                None => Err(ThreadError::Fatal(
                    "scheduler returned no runnable task after timed park".into(),
                )),
            }
        }

        /// After a `scheduler.next()` that may have run the runtime's deadlock
        /// rescue, unlink every rescued task from the primitive it was waiting on
        /// and flag cond/futex timeouts. Doing this before the baton is handed
        /// off keeps a later signal (`cond_broadcast`, `FUTEX_WAKE`) from trying
        /// to re-wake an already timer-woken task.
        fn settle_rescued(&mut self) -> Result<(), ThreadError> {
            let rescued = with_context_raw(|context| Ok(context.take_rescued_timeouts()))
                .map_err(ThreadError::Posix)?;
            for task in rescued {
                self.mark_timed_out(task);
            }
            Ok(())
        }

        /// Unlink `task` from whichever wait queue holds it. A cond or futex
        /// waiter also enters `timed_out` so its wait returns `ETIMEDOUT`; a
        /// socket waiter simply retries (the packet is now due, or its timeout
        /// has passed), and a bare timed sleep is on no queue at all.
        fn mark_timed_out(&mut self, task: TaskId) {
            #[cfg(target_os = "linux")]
            {
                if self.signals.blocked.get(&task).is_some_and(|blocked| {
                    blocked.class == BlockClass::TimedFutex
                        || blocked
                            .locs
                            .iter()
                            .any(|loc| matches!(loc, WaiterLoc::Cond(..) | WaiterLoc::Ipc(..)))
                }) {
                    self.timed_out.insert(task);
                }
                self.remove_signal_wait(task);
            }
            #[cfg(target_os = "macos")]
            {
                for cond in self.table.conds.values_mut() {
                    if let Some(index) = cond.waiters.iter().position(|(waiter, _)| *waiter == task)
                    {
                        cond.waiters.remove(index);
                        self.timed_out.insert(task);
                        return;
                    }
                }
                for waiters in self.futexes.values_mut() {
                    if let Some(index) = waiters.iter().position(|waiter| *waiter == task) {
                        waiters.remove(index);
                        self.timed_out.insert(task);
                        return;
                    }
                }
                #[cfg(target_os = "macos")]
                for sem in self.dispatch.values_mut() {
                    if let Some(index) = sem.waiters.iter().position(|waiter| *waiter == task) {
                        sem.waiters.remove(index);
                        // The waiter eagerly decremented on entry; restore it so a
                        // negative `count` keeps equaling the live waiter total.
                        sem.count += 1;
                        self.timed_out.insert(task);
                        return;
                    }
                }
                for socket in self.net.sockets.table.values_mut() {
                    for waiters in [&mut socket.recv_waiters, &mut socket.send_waiters] {
                        if let Some(index) = waiters.iter().position(|waiter| *waiter == task) {
                            waiters.remove(index);
                            return;
                        }
                    }
                }
            }
        }
    }

    fn thread_runtime() -> &'static SpinMutex<ThreadRuntime> {
        static RUNTIME: OnceLock<SpinMutex<ThreadRuntime>> = OnceLock::new();
        RUNTIME.get_or_init(|| {
            SpinMutex::new(ThreadRuntime {
                table: ThreadTable::default(),
                #[cfg(target_os = "linux")]
                signals: signals::SignalRuntime::default(),
                #[cfg(target_os = "linux")]
                ipc: ipc::Ipc::default(),
                #[cfg(target_os = "linux")]
                sched: sched::SchedRuntime::default(),
                #[cfg(target_os = "linux")]
                registrations: registrations::RegistrationRuntime::default(),
                #[cfg(target_os = "linux")]
                timers: timers::Timers::default(),
                handles: BTreeMap::new(),
                sems: BTreeMap::new(),
                net: NetState::new(),
                futexes: BTreeMap::new(),
                private_futex_waits: std::collections::BTreeSet::new(),
                timed_out: std::collections::BTreeSet::new(),
                #[cfg(target_os = "macos")]
                dispatch: BTreeMap::new(),
                #[cfg(target_os = "macos")]
                next_dispatch_handle: 1,
                active: false,
            })
        })
    }

    fn lock_state() -> SpinGuard<'static, ThreadRuntime> {
        thread_runtime().lock()
    }

    /// Take a guard-driven scheduling point, remembering the instrumented call
    /// site for the divergence diagnostic. On the failure path `sched_point`
    /// aborts with the site still set, which is exactly when
    /// [`yield_site_context`] reads it.
    pub(crate) fn yield_point_from(site: usize) {
        YIELD_SITE.with(|cell| cell.set(site));
        let _ = sched_point();
        YIELD_SITE.with(|cell| cell.set(0));
    }

    /// Divergence-diagnostic context: where the in-flight scheduling point came
    /// from. ASLR makes a raw pc unusable offline, so the site is also reported
    /// relative to the shim's own `patina_yield_point` in the same executable
    /// image — a delta that is stable across runs of one binary. Symbolize by
    /// adding the delta to `nm <binary> | grep patina_yield_point`.
    pub(crate) fn yield_site_context() -> String {
        let site = YIELD_SITE.with(Cell::get);
        if site == 0 {
            return "; the divergent scheduling point came from an interposed boundary call, not a \
--yield-points guard".into();
        }
        let anchor = crate::patina_yield_point as *const () as usize;
        let delta = site.wrapping_sub(anchor) as isize;
        let sign = if delta < 0 { '-' } else { '+' };
        format!(
            "; divergent yield point: guest pc {site:#x} = patina_yield_point{sign}{:#x}",
            delta.unsigned_abs()
        )
    }

    /// Take a deterministic scheduling point at a boundary call. A no-op until
    /// the thread subsystem activates, so single-threaded programs are
    /// unaffected.
    pub(crate) fn sched_point() -> Result<(), c_int> {
        // A thread whose task already completed is running teardown code only; it
        // must not take a scheduling point. Checked before locking and keyed on
        // the completed sentinel alone, so a never-registered thread falls through
        // to the unchanged (loud) reschedule path below rather than being silenced.
        //
        // `main_returned()` extends the identical treatment to the ROOT (main)
        // task once the process is unwinding through the `exit` interposer: the
        // main task never runs `thread_finish`, so without this its instrumented
        // thread-local destructors (under `--yield-points`) would record trailing,
        // host-teardown-ordering-dependent `TaskYield`s and diverge record from
        // replay. The deterministic contract: the root task records exactly ZERO
        // teardown yields on every platform. This is a silence (no op recorded or
        // consumed), never a replay-tolerance relaxation; a NON-yield scheduler op
        // arriving past the flag is still caught loudly (see `with_context_msg`).
        if task_completed() || main_returned() {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        signals::deliver();
        let mut state = lock_state();
        if !state.active {
            return Ok(());
        }
        let me = current_task();
        match state.reschedule(me) {
            Ok(Some(picked)) if picked == me => Ok(()),
            Ok(Some(picked)) => {
                switch_and_park(state, picked, me);
                #[cfg(target_os = "linux")]
                signals::deliver();
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(ThreadError::Posix(errno)) => Err(errno),
            Err(ThreadError::Fatal(message)) => fatal(&message),
        }
    }

    /// Sleep until an absolute virtual deadline through a timed park, so other
    /// managed tasks run while this one sleeps and the clock advances only via
    /// the rescue. Returns `None` when the thread subsystem is inactive (no
    /// managed threads yet), so the caller performs a plain clock jump identical
    /// to the historical single-threaded behavior; otherwise `Some(0)` once the
    /// deadline is reached (a timed sleep has no distinct timeout return).
    /// # Safety
    /// Non-null `remaining` must name a writable pair of i64 timespec fields.
    pub(crate) unsafe fn managed_sleep(
        clock: ClockKind,
        deadline: u64,
        remaining: *mut i64,
    ) -> Option<c_int> {
        let me = current_task();
        let mut state = lock_state();
        if !state.active {
            return None;
        }
        match state.block_timed(
            me,
            "sleep",
            Wait::new(BlockClass::Sleep, vec![]),
            clock,
            deadline,
        ) {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => return Some(error.into_posix()),
        }
        // A bare sleep is on no waiter list; clear a defensive timer flag anyway.
        lock_state().timed_out.remove(&me);
        #[cfg(target_os = "linux")]
        if signals::resume_with(|| {
            if !remaining.is_null() {
                // Snapshot at interruption, not after a handler that may itself
                // advance virtual time. A clock failure must never invent rem=0.
                let now = with_context_raw(|context| context.now(clock))
                    .unwrap_or_else(|_| fatal("reading interrupted sleep clock failed"));
                let rem = deadline.saturating_sub(now);
                unsafe {
                    remaining.write((rem / 1_000_000_000) as i64);
                    remaining.add(1).write((rem % 1_000_000_000) as i64);
                }
            }
        }) == signals::Resumed::Eintr
        {
            return Some(super::EINTR);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = remaining;
        Some(0)
    }

    struct ThreadStart {
        task: TaskId,
        routine: StartRoutine,
        arg: *mut c_void,
    }

    // Arm syscall-user-dispatch on the calling managed thread. The real
    // definition is in the C layer (patina_posix.c); it is a no-op unless SUD was
    // armed for this run. The Rust half of the shim also ships in probes that link
    // the staticlib WITHOUT the C layer (the C-ABI-only host-alias probe/test),
    // where this call would be an unresolved reference. Provide a WEAK no-op
    // definition so those links resolve; when the C layer is linked its STRONG
    // definition overrides this weak one and real arming happens. Mirrors the
    // `.weak __real_dlsym` idiom used for the wrap alias.
    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        fn patina_sud_arm_thread();
        fn patina_tsc_arm_thread();
    }
    #[cfg(target_os = "linux")]
    core::arch::global_asm!(
        ".text",
        ".weak patina_sud_arm_thread",
        ".p2align 2",
        "patina_sud_arm_thread:",
        "ret",
        ".weak patina_tsc_arm_thread",
        ".p2align 2",
        "patina_tsc_arm_thread:",
        "ret",
    );

    extern "C" fn thread_trampoline(raw: *mut c_void) -> *mut c_void {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        // SAFETY: `raw` is the `Box<ThreadStart>` leaked in patina_thread_create.
        let start = unsafe { Box::from_raw(raw.cast::<ThreadStart>()) };
        let ThreadStart { task, routine, arg } = *start;
        set_current_task(task);
        // Arm syscall-user-dispatch on this managed thread. The SUD config does
        // not survive clone(2), so every thread must re-arm; this is the second
        // (and only other) arming site besides the main thread in
        // `__libc_start_main`. A no-op when SUD was not armed for this run
        // (non-SUD kernel or standalone binary).
        #[cfg(target_os = "linux")]
        // SAFETY: the C symbol takes no arguments and is a no-op unless the main
        // thread armed SUD for this run.
        unsafe {
            patina_sud_arm_thread()
        };
        // The timestamp-counter setting is per-thread too, so it arms at the same
        // two sites. A no-op when the trap was not armed for this run.
        #[cfg(target_os = "linux")]
        // SAFETY: as above, for the TSC trap.
        unsafe {
            patina_tsc_arm_thread()
        };
        // glibc's start_thread registered this thread with the host kernel
        // before calling here: take the registrations over before the guest
        // runs on it, and register the task's completion as this thread's
        // first thread-local destructor. Then let the creator return: until
        // now it waits, so no guest code runs beside this off-baton setup and
        // a query of this thread's registrations answers the same every run.
        #[cfg(target_os = "linux")]
        let exit = {
            registrations::adopt(task);
            let exit = finish_after_destructors(task);
            creation_settled().signal();
            exit
        };
        // Park on this task's baton semaphore until it is first scheduled.
        let sem = lock_state().task_sem(task);
        sem.wait();
        #[cfg(target_os = "linux")]
        {
            let mask = lock_state().signals.mask(task);
            signals::install_mask(mask);
        }
        let ret = {
            let _guest = crate::panic_boundary::PanicScope::suspend();
            routine(arg)
        };
        // On Linux the task completes from glibc's thread-local destructor
        // pass (`finish_after_destructors`), once the guest's own destructors
        // ran on it.
        #[cfg(target_os = "linux")]
        // SAFETY: the record `finish_after_destructors` leaked; its
        // destructor, which frees it, has not run yet.
        unsafe {
            (*exit).retval = ret as usize;
        }
        #[cfg(not(target_os = "linux"))]
        thread_finish(task, ret as usize, 0);
        ret
    }

    /// Posted by a new thread once its host registrations are taken over and
    /// its completion is registered; `patina_thread_create` waits for it.
    /// Creations are serialized (only the baton holder creates, and it holds
    /// the baton while it waits), so one semaphore serves every creation.
    #[cfg(target_os = "linux")]
    fn creation_settled() -> &'static baton::Semaphore {
        static SETTLED: OnceLock<baton::Semaphore> = OnceLock::new();
        SETTLED.get_or_init(baton::Semaphore::new)
    }

    /// A managed thread's completion, waiting for its return value.
    #[cfg(target_os = "linux")]
    struct ThreadExit {
        task: TaskId,
        retval: usize,
    }

    /// Register `task`'s completion ([`thread_finish`]) as the calling
    /// thread's first thread-local destructor. glibc runs them last-registered
    /// first once the start routine returns, so the task completes after every
    /// destructor the guest registered (C++ `thread_local`, Rust's
    /// thread-locals), which therefore run on the live task, as natively they
    /// run before the kernel's exit: the robust-list walk and the
    /// clear-child-tid wake that a join waits for. Answers the record the
    /// trampoline fills in with the return value.
    #[cfg(target_os = "linux")]
    fn finish_after_destructors(task: TaskId) -> *mut ThreadExit {
        unsafe extern "C" fn complete(record: *mut c_void) {
            let _panic_scope = crate::panic_boundary::PanicScope::enter();
            // SAFETY: the record leaked below, consumed exactly once here.
            let ThreadExit { task, retval } =
                *unsafe { Box::from_raw(record.cast::<ThreadExit>()) };
            thread_finish(task, retval, 0);
        }
        unsafe extern "C" {
            static __dso_handle: u8;
        }
        let record = Box::into_raw(Box::new(ThreadExit { task, retval: 0 }));
        // SAFETY: glibc's real `__cxa_thread_atexit_impl` with a destructor
        // that takes the record, and this image's DSO handle.
        let rc = unsafe {
            (crate::hostapi::get().host_cxa_thread_atexit_impl)(
                complete,
                record.cast(),
                (&raw const __dso_handle).cast_mut().cast(),
            )
        };
        if rc != 0 {
            fatal("registering a managed thread's completion failed (__cxa_thread_atexit_impl)");
        }
        record
    }

    fn thread_finish(task: TaskId, retval: usize, exit_status: i32) {
        #[cfg(not(target_os = "linux"))]
        let _ = exit_status;
        // The kernel's exit order: the robust list, then clear-child-tid.
        #[cfg(target_os = "linux")]
        registrations::exit(task);
        #[cfg(target_os = "linux")]
        signals::clear_tid(task);
        let mut state = lock_state();
        let mut scheduler = RealScheduler;
        if let Err(ThreadError::Fatal(message)) = state.table.exit(&mut scheduler, task, retval) {
            fatal(&message);
        }
        #[cfg(target_os = "linux")]
        state.signals.finish(task);
        #[cfg(target_os = "linux")]
        state.sched.finish(task);
        // Detached handles remain targetable while live, then disappear with
        // their ThreadEntry; completed joinable handles remain until reaped.
        if !state.table.threads.contains_key(&task) {
            state.handles.retain(|_, owner| *owner != task);
        }
        // The task is gone from the scheduler; mark this host thread completed so
        // instrumented teardown (TLS destructors under `--yield-points`) takes no
        // scheduling point rather than rescheduling a task that no longer exists.
        mark_task_completed();
        let next = match state.next_task() {
            Ok(next) => next,
            Err(error) => fatal(&format!(
                "picking the next task after completion failed ({})",
                error.into_posix()
            )),
        };
        #[cfg(target_os = "linux")]
        if state.signals.is_empty() {
            drop(state);
            signals::patina_raw_exit_group(exit_status);
        }
        // The completed task never runs again; hand the baton to the next task
        // (if any) and let this host thread return out of the trampoline and
        // exit. When no task remains the program is ending.
        if let Some(next) = next {
            let next_sem = state.task_sem(next);
            drop(state);
            next_sem.signal();
        }
    }

    /// Create a managed thread. `pthread_create` semantics: register a task,
    /// spawn a real host thread that parks until it receives the baton, and hand
    /// the caller the real `pthread_t`.
    ///
    /// # Safety
    /// `thread_out` must be writable, and `start`/`arg` must form a valid
    /// thread entry point per the C ABI.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_thread_create(
        thread_out: *mut *mut c_void,
        attr: *const c_void,
        start: Option<StartRoutine>,
        arg: *mut c_void,
    ) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        let Some(start) = start else {
            return EINVAL;
        };
        if thread_out.is_null() {
            return EINVAL;
        }
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return error.into_posix();
        }
        let task = match RealScheduler.spawn("thread") {
            Ok(task) => task,
            Err(message) => fatal(&message),
        };
        state.table.register(task);
        #[cfg(target_os = "linux")]
        state.signals.spawn(task, Some(current_task()));
        #[cfg(target_os = "linux")]
        state.sched.spawn(task, current_task());
        // A new thread inherits its creator's memory policy.
        #[cfg(target_os = "linux")]
        crate::numa::spawned(deterministic_thread_id(), tid_of(task));
        // The semaphore must exist before the host thread parks on it.
        state.sems.insert(task, Arc::new(baton::Semaphore::new()));
        #[cfg(target_os = "linux")]
        creation_settled();
        let payload = Box::into_raw(Box::new(ThreadStart {
            task,
            routine: start,
            arg,
        }));
        let mut handle: *mut c_void = core::ptr::null_mut();
        // SAFETY: `spawn_host_thread` creates a real, non-interposed host OS
        // thread; `payload` is consumed exactly once by the trampoline.
        let rc = unsafe { spawn_host_thread(&mut handle, attr, thread_trampoline, payload.cast()) };
        if rc != 0 {
            // SAFETY: the trampoline never ran, so `payload` is still owned.
            drop(unsafe { Box::from_raw(payload) });
            fatal(&format!("host thread creation failed with code {rc}"));
        }
        state.handles.insert(handle as usize, task);
        drop(state);
        // The new thread takes over its host registrations off the baton;
        // wait for that before the guest can ask about them.
        #[cfg(target_os = "linux")]
        creation_settled().wait();
        // SAFETY: `thread_out` is non-null and writable per the pthread contract.
        unsafe { thread_out.write(handle) };
        0
    }

    /// Join a managed thread, blocking the caller until the target completes.
    ///
    /// # Safety
    /// `handle` must be a `pthread_t` from [`patina_thread_create`] and
    /// `retval_out` must be null or writable.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_thread_join(
        handle: *mut c_void,
        retval_out: *mut *mut c_void,
    ) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        let key = handle as usize;
        // A thread joining itself, the main thread before the thread runtime
        // is active too (the table below refuses a managed one): `EINVAL`
        // once it detached itself, else `EDEADLK`, glibc's order.
        // SAFETY: the real glibc `pthread_self`, resolved through the
        // host-alias table.
        #[cfg(target_os = "linux")]
        if key == unsafe { (crate::hostapi::get().host_pthread_self)() } {
            let me = current_task();
            let detached = lock_state()
                .table
                .threads
                .get(&me)
                .is_some_and(|entry| entry.detached);
            return if detached { EINVAL } else { EDEADLK };
        }
        let me = current_task();
        let mut state = lock_state();
        let Some(&target) = state.handles.get(&key) else {
            return ESRCH;
        };
        let retval = match state.begin_join(me, target) {
            Ok(JoinResolve::Ready(retval)) => {
                state.handles.remove(&key);
                // Release the state lock before the host reap below so the
                // worker's exit never contends with a lock this thread holds.
                drop(state);
                retval
            }
            Ok(JoinResolve::Blocked(Step::Switch(picked))) => {
                switch_and_park(state, picked, me);
                let mut state = lock_state();
                state.handles.remove(&key);
                state.table.take_join_result(target)
            }
            Ok(JoinResolve::Blocked(Step::Continue)) => {
                fatal("join parked without transferring the baton")
            }
            Err(error) => return error.into_posix(),
        };
        // The managed join is complete (the worker's task has exited the
        // scheduler). Now REAP the real host thread so the worker fully unwinds
        // before we return: std drops the worker's `Arc<thread::Inner>` in a
        // thread-local destructor as the host thread exits, and if that drop
        // races the joiner's own `Arc<Inner>` drop (std's `JoinInner` cleanup,
        // which runs right after this returns), whichever is the LAST reference
        // takes the acquire-fence + destructor slow path — so under
        // `--yield-points` the joiner records a host-timing-dependent number of
        // scheduling points (the op-742/12623 x86 divergence on Linux; the
        // ±2-yield main-tls record/replay divergence under load on Darwin).
        // Joining here forces the worker to drop its reference first, so the
        // joiner's drop is deterministically the last reference on every run and
        // every host thread that reaches this. The worker's own teardown runs on
        // a task-completed-silenced thread, so it records nothing; the join adds
        // no instrumented guest edges.
        // SAFETY: `handle` is the real joinable host `pthread_t` returned by
        // `patina_thread_create`; the state lock is released above so the worker's
        // exit cannot deadlock against a lock this thread holds.
        let _ = unsafe { (crate::hostapi::get().host_pthread_join)(handle, core::ptr::null_mut()) };
        if !retval_out.is_null() {
            // SAFETY: `retval_out` was checked non-null and is writable.
            unsafe { retval_out.write(retval as *mut c_void) };
        }
        0
    }

    /// Detach a managed thread so it is never joined.
    ///
    /// # Safety
    /// `handle` must be a `pthread_t` from [`patina_thread_create`].
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_thread_detach(handle: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        let key = handle as usize;
        let mut state = lock_state();
        let Some(&target) = state.handles.get(&key) else {
            return ESRCH;
        };
        match state.table.detach(target) {
            Ok(()) => {
                if !state.table.threads.contains_key(&target) {
                    state.handles.remove(&key);
                }
                drop(state);
                // Reap the host vehicle too; its pthread identity remains valid
                // until completion, exactly as the modeled detached handle does.
                let rc = unsafe { (crate::hostapi::get().host_pthread_detach)(handle) };
                if rc != 0 {
                    fatal("host pthread_detach failed");
                }
                0
            }
            Err(error) => error.into_posix(),
        }
    }

    /// `pthread_exit` is fail-closed: the deterministic runtime cannot terminate
    /// one host thread mid-body without the host's own thread destructor, and
    /// Rust threads always return from their body rather than calling it.
    ///
    /// # Safety
    /// C ABI entry point; the argument is an opaque pointer.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_thread_exit(_retval: *mut c_void) -> ! {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        fatal(
            "pthread_exit is not supported by Patina's deterministic thread runtime; \
             return from the thread body instead",
        )
    }

    /// Run the deterministic body of a mutex/cond boundary op after taking a
    /// scheduling point. The shim's own synchronization never routes here (it
    /// uses [`SpinMutex`] and the baton), so these always take the managed path.
    macro_rules! managed_op {
        ($body:block) => {{
            if let Err(errno) = sched_point() {
                return errno;
            }
            $body
        }};
    }

    /// # Safety
    /// `mutex` must reference a valid `pthread_mutex_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_mutex_init(mutex: *mut c_void, attr: *const c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        // SAFETY: a null or initialized attribute, per the pthread contract.
        let kind = unsafe { MutexKind::of_attr(attr) };
        managed_op!({
            let mut state = lock_state();
            state.table.init_mutex(mutex as usize, kind);
            0
        })
    }

    /// # Safety
    /// `mutex` must reference a valid `pthread_mutex_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_mutex_lock(mutex: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            let key = mutex as usize;
            // SAFETY: a valid `pthread_mutex_t`, per this function's contract.
            let kind = unsafe { MutexKind::of_static(mutex) };
            let me = current_task();
            let mut state = lock_state();
            match state.begin_lock(me, key, kind) {
                Ok(Step::Continue) => 0,
                Ok(Step::Switch(picked)) => {
                    switch_and_park(state, picked, me);
                    0
                }
                Err(error) => error.into_posix(),
            }
        })
    }

    /// # Safety
    /// `mutex` must reference a valid `pthread_mutex_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_mutex_trylock(mutex: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            // SAFETY: a valid `pthread_mutex_t`, per this function's contract.
            let kind = unsafe { MutexKind::of_static(mutex) };
            let me = current_task();
            let mut state = lock_state();
            state.table.trylock(me, mutex as usize, kind)
        })
    }

    /// # Safety
    /// `mutex` must reference a valid `pthread_mutex_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_mutex_unlock(mutex: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            let me = current_task();
            let mut state = lock_state();
            let mut scheduler = RealScheduler;
            match state.table.unlock(&mut scheduler, me, mutex as usize) {
                Ok(()) => 0,
                Err(error) => error.into_posix(),
            }
        })
    }

    /// # Safety
    /// `mutex` must reference a valid `pthread_mutex_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_mutex_destroy(mutex: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            let mut state = lock_state();
            match state.table.destroy_mutex(mutex as usize) {
                Ok(()) => 0,
                Err(error) => error.into_posix(),
            }
        })
    }

    /// `os_unfair_lock` (macOS) routed through the deterministic scheduler using
    /// the shared mutex table, keyed on the lock's address. `os_unfair_lock` is a
    /// bare `u32` with no init call, so the table lazily registers it on first
    /// lock/trylock (the `or_default` path) exactly as it does for a
    /// never-`pthread_mutex_init`'d word.
    ///
    /// The real primitive is non-recursive and traps on misuse: a recursive lock
    /// by the current owner (`EDEADLK` here) and an unlock by a non-owner or of a
    /// never-locked word (`EPERM`/`EINVAL` here) both abort loudly and
    /// deterministically rather than returning silently — these functions have no
    /// error channel, so a soft failure would be an invisible escape. A scheduler
    /// fault at the entry point cannot be surfaced through the `void`/`bool` ABI
    /// either, so it is ignored: the scheduling point (and any baton handoff) has
    /// already happened inside `sched_point`, and the real primitive has no such
    /// failure mode.
    ///
    /// # Safety
    /// `lock` must reference a valid `os_unfair_lock`.
    #[cfg(target_os = "macos")]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_os_unfair_lock_lock(lock: *mut c_void) {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        // Run the lock natively — never through the deterministic model — for an
        // allocator-internal `os_unfair_lock` in either of the two windows where
        // one appears: (1) the bootstrap window, where a custom global allocator's
        // own eager init takes its `malloc_mutex`; (2) reentrantly while this
        // thread already holds a shim spinlock, which happens only when the shim's
        // scheduler-path allocation re-enters the (now-initialized) allocator. Both
        // are allocator-internal, single-owner locks that must not route through
        // the scheduler (it would trip the non-recursive guard or deadlock on the
        // held spinlock). See `SHIM_BOOTSTRAP` and `SPIN_DEPTH`.
        //
        // The spinlock test comes FIRST because the window test aborts on a
        // stored init error: shim-internal reentrancy must never be the call that
        // triggers a fail-closed abort, or the shim's own diagnostic write could
        // abort from inside its allocator's deallocation.
        if super::in_shim_critical() || super::in_shim_bootstrap() {
            // SAFETY: the resolved real `os_unfair_lock_lock`; `lock` is a valid
            // `os_unfair_lock` per the caller's contract.
            unsafe { (super::hostapi::get().host_os_unfair_lock_lock)(lock) };
            return;
        }
        let _ = sched_point();
        let key = lock as usize;
        let me = current_task();
        let mut state = lock_state();
        match state.begin_lock(me, key, MutexKind::ErrorCheck) {
            Ok(Step::Continue) => {}
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Err(ThreadError::Fatal(message)) => {
                drop(state);
                fatal(&message);
            }
            Err(ThreadError::Posix(_)) => {
                drop(state);
                fatal(
                    "os_unfair_lock_lock: recursive lock of an os_unfair_lock already held by the \
                     current task",
                );
            }
        }
    }

    /// # Safety
    /// `lock` must reference a valid `os_unfair_lock`.
    #[cfg(target_os = "macos")]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_os_unfair_lock_trylock(lock: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        // Allocator-internal lock: run natively (see `patina_os_unfair_lock_lock`).
        // The real `os_unfair_lock_trylock` returns a C `bool`.
        if super::in_shim_critical() || super::in_shim_bootstrap() {
            // SAFETY: the resolved real `os_unfair_lock_trylock`; valid `lock`.
            return c_int::from(unsafe {
                (super::hostapi::get().host_os_unfair_lock_trylock)(lock)
            });
        }
        let _ = sched_point();
        let me = current_task();
        let mut state = lock_state();
        // Acquired -> 1. Held by another task (EBUSY) or already owned by this
        // task (EDEADLK) -> 0: the real single-cmpxchg trylock simply fails to
        // acquire when the word is non-zero, without trapping.
        c_int::from(
            state
                .table
                .trylock(me, lock as usize, MutexKind::ErrorCheck)
                == 0,
        )
    }

    /// # Safety
    /// `lock` must reference a valid `os_unfair_lock` the caller holds.
    #[cfg(target_os = "macos")]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_os_unfair_lock_unlock(lock: *mut c_void) {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        // Allocator-internal lock: run natively (see `patina_os_unfair_lock_lock`).
        // A lock taken natively (bootstrap, or reentrant under a held spinlock) is
        // released natively too; the allocator's lock/unlock pair is balanced
        // within the same window, so none spans a transition.
        if super::in_shim_critical() || super::in_shim_bootstrap() {
            // SAFETY: the resolved real `os_unfair_lock_unlock`; valid `lock`.
            unsafe { (super::hostapi::get().host_os_unfair_lock_unlock)(lock) };
            return;
        }
        let _ = sched_point();
        let me = current_task();
        let mut state = lock_state();
        let mut scheduler = RealScheduler;
        match state.table.unlock(&mut scheduler, me, lock as usize) {
            Ok(()) => {}
            Err(ThreadError::Fatal(message)) => {
                drop(state);
                fatal(&message);
            }
            Err(ThreadError::Posix(_)) => {
                drop(state);
                fatal(
                    "os_unfair_lock_unlock: unlock of an os_unfair_lock not owned by the current \
                     task",
                );
            }
        }
    }

    /// Deterministic `pthread_rwlock_*`. Reader/writer contention routes through
    /// the scheduler exactly like the mutex/cond interposition: the lock's kind
    /// (from its attribute or static initializer; glibc's default prefers
    /// readers) decides the grant order, writers are FIFO, and blocked readers
    /// are woken together. std's own `RwLock` does not
    /// lower to these symbols on the supported toolchains (it uses the queue-based
    /// parking `RwLock`), so this serves C guests and any std that does.
    ///
    /// # Safety
    /// `lock` must reference a valid `pthread_rwlock_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_rwlock_init(lock: *mut c_void, attr: *const c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        // SAFETY: a null or initialized attribute, per the pthread contract.
        let kind = unsafe { RwLockKind::of_attr(attr) };
        managed_op!({
            let mut state = lock_state();
            state.table.init_rwlock(lock as usize, kind);
            0
        })
    }

    /// # Safety
    /// `lock` must reference a valid `pthread_rwlock_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_rwlock_rdlock(lock: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            let key = lock as usize;
            // SAFETY: a valid `pthread_rwlock_t`, per this function's contract.
            let kind = unsafe { RwLockKind::of_static(lock) };
            let me = current_task();
            let mut state = lock_state();
            match state.begin_rdlock(me, key, kind) {
                Ok(Step::Continue) => 0,
                Ok(Step::Switch(picked)) => {
                    switch_and_park(state, picked, me);
                    0
                }
                Err(error) => error.into_posix(),
            }
        })
    }

    /// # Safety
    /// `lock` must reference a valid `pthread_rwlock_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_rwlock_wrlock(lock: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            let key = lock as usize;
            // SAFETY: a valid `pthread_rwlock_t`, per this function's contract.
            let kind = unsafe { RwLockKind::of_static(lock) };
            let me = current_task();
            let mut state = lock_state();
            match state.begin_wrlock(me, key, kind) {
                Ok(Step::Continue) => 0,
                Ok(Step::Switch(picked)) => {
                    switch_and_park(state, picked, me);
                    0
                }
                Err(error) => error.into_posix(),
            }
        })
    }

    /// # Safety
    /// `lock` must reference a valid `pthread_rwlock_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_rwlock_tryrdlock(lock: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            // SAFETY: a valid `pthread_rwlock_t`, per this function's contract.
            let kind = unsafe { RwLockKind::of_static(lock) };
            let mut state = lock_state();
            state.table.rwlock_tryrdlock(lock as usize, kind)
        })
    }

    /// # Safety
    /// `lock` must reference a valid `pthread_rwlock_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_rwlock_trywrlock(lock: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            // SAFETY: a valid `pthread_rwlock_t`, per this function's contract.
            let kind = unsafe { RwLockKind::of_static(lock) };
            let me = current_task();
            let mut state = lock_state();
            state.table.rwlock_trywrlock(me, lock as usize, kind)
        })
    }

    /// # Safety
    /// `lock` must reference a valid `pthread_rwlock_t` the caller holds.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_rwlock_unlock(lock: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            let me = current_task();
            let mut state = lock_state();
            let mut scheduler = RealScheduler;
            match state.table.rwlock_unlock(&mut scheduler, me, lock as usize) {
                Ok(()) => 0,
                Err(error) => error.into_posix(),
            }
        })
    }

    /// # Safety
    /// `lock` must reference a valid `pthread_rwlock_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_rwlock_destroy(lock: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            let mut state = lock_state();
            match state.table.destroy_rwlock(lock as usize) {
                Ok(()) => 0,
                Err(error) => error.into_posix(),
            }
        })
    }

    /// # Safety
    /// `cond` must reference a valid `pthread_cond_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_cond_init(cond: *mut c_void, attr: *const c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        // SAFETY: a null or initialized attribute, per the pthread contract.
        let clock = unsafe { CondEntry::clock_of_attr(attr) };
        managed_op!({
            let mut state = lock_state();
            state.table.init_cond(cond as usize, clock);
            0
        })
    }

    /// # Safety
    /// `cond` and `mutex` must reference valid pthread objects, and the caller
    /// must own `mutex`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_cond_wait(cond: *mut c_void, mutex: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            let me = current_task();
            let mut state = lock_state();
            match state.begin_cond_wait(me, cond as usize, mutex as usize) {
                Ok(Step::Switch(picked)) => {
                    switch_and_park(state, picked, me);
                    0
                }
                Ok(Step::Continue) => fatal("cond wait parked without transferring the baton"),
                Err(error) => error.into_posix(),
            }
        })
    }

    /// A C `struct timespec` for the supported 64-bit targets. `time_t` and
    /// `long` are both 64-bit on macOS and Linux aarch64/x86_64.
    #[repr(C)]
    struct CTimespec {
        tv_sec: i64,
        tv_nsec: i64,
    }

    /// Convert an absolute `struct timespec` deadline to nanoseconds: `EINVAL`
    /// for a `tv_nsec` outside a second, `EOVERFLOW` past `u64`. A deadline
    /// before the epoch is already past, as glibc's futex wait judges it, so
    /// it is the epoch.
    ///
    /// # Safety
    /// `ptr` must point to a valid `struct timespec`.
    unsafe fn timespec_nanos(ptr: *const c_void) -> Result<u64, c_int> {
        // SAFETY: guaranteed by this function's contract.
        let time = unsafe { &*ptr.cast::<CTimespec>() };
        if time.tv_nsec < 0 || time.tv_nsec >= 1_000_000_000 {
            return Err(EINVAL);
        }
        if time.tv_sec < 0 {
            return Ok(0);
        }
        u64::try_from(time.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|nanos| nanos.checked_add(time.tv_nsec as u64))
            .ok_or(EOVERFLOW)
    }

    /// Timed condition wait. Like [`patina_cond_wait`], but parks with the
    /// wait's absolute deadline, on the condition's clock, registered on the
    /// virtual-clock timer queue. A signal before the deadline returns 0 (the
    /// waiter owns the mutex, exactly like the untimed path); reaching the
    /// deadline re-acquires the mutex and returns `ETIMEDOUT`. Whether the wake
    /// was a signal or the timer is decided by which path removed the waiter —
    /// never by comparing clocks — so it is deterministic. A deadline already
    /// reached parks nothing: the mutex is released and re-acquired, and the
    /// wait is `ETIMEDOUT` at once, however busy the other tasks are.
    ///
    /// # Safety
    /// `cond` and `mutex` must reference valid pthread objects the caller owns,
    /// and `abstime` a valid `struct timespec`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_cond_timedwait(
        cond: *mut c_void,
        mutex: *mut c_void,
        abstime: *const c_void,
    ) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        if abstime.is_null() {
            return EINVAL;
        }
        // SAFETY: `abstime` was checked non-null and is a `struct timespec`.
        let deadline = match unsafe { timespec_nanos(abstime) } {
            Ok(deadline) => deadline,
            Err(errno) => return errno,
        };
        if let Err(errno) = sched_point() {
            return errno;
        }
        let cond_key = cond as usize;
        let mutex_key = mutex as usize;
        let me = current_task();
        let mut state = lock_state();
        let mut scheduler = RealScheduler;
        let clock = state.table.cond_clock(cond_key);
        let past = with_context_raw(|context| {
            let due = context.monotonic_deadline(clock, deadline)?;
            Ok(due <= context.monotonic_now_unrecorded()?)
        });
        match past {
            Ok(false) => {}
            Ok(true) => {
                if let Err(error) = state.table.unlock(&mut scheduler, me, mutex_key) {
                    return error.into_posix();
                }
                // SAFETY: a valid `pthread_mutex_t`, per this function's contract.
                let kind = unsafe { MutexKind::of_static(mutex) };
                match state.begin_lock(me, mutex_key, kind) {
                    Ok(Step::Continue) => drop(state),
                    Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                    Err(error) => return error.into_posix(),
                }
                return ETIMEDOUT;
            }
            Err(errno) => return errno,
        }
        // Release the mutex and enqueue on the condition, exactly as cond_wait.
        if let Err(error) = state
            .table
            .cond_wait(&mut scheduler, me, cond_key, mutex_key)
        {
            return error.into_posix();
        }
        match state.block_timed(
            me,
            "cond-timedwait",
            Wait::new(BlockClass::Sync, vec![WaiterLoc::Cond(cond_key, mutex_key)]),
            clock,
            deadline,
        ) {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => return error.into_posix(),
        }
        // Resumed. A timer wake left `me` in `timed_out` and holding no mutex; a
        // signal wake removed `me` from the condition and re-granted the mutex.
        let mut state = lock_state();
        if state.timed_out.remove(&me) {
            // SAFETY: a valid `pthread_mutex_t`, per this function's contract.
            let kind = unsafe { MutexKind::of_static(mutex) };
            match state.begin_lock(me, mutex_key, kind) {
                Ok(Step::Continue) => drop(state),
                Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                Err(error) => return error.into_posix(),
            }
            ETIMEDOUT
        } else {
            drop(state);
            0
        }
    }

    /// # Safety
    /// `cond` must reference a valid `pthread_cond_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_cond_signal(cond: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            let mut state = lock_state();
            let mut scheduler = RealScheduler;
            match state.table.cond_signal(&mut scheduler, cond as usize) {
                Ok(()) => 0,
                Err(error) => error.into_posix(),
            }
        })
    }

    /// # Safety
    /// `cond` must reference a valid `pthread_cond_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_cond_broadcast(cond: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            let mut state = lock_state();
            let mut scheduler = RealScheduler;
            match state.table.cond_broadcast(&mut scheduler, cond as usize) {
                Ok(()) => 0,
                Err(error) => error.into_posix(),
            }
        })
    }

    /// # Safety
    /// `cond` must reference a valid `pthread_cond_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_cond_destroy(cond: *mut c_void) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        managed_op!({
            let mut state = lock_state();
            match state.table.destroy_cond(cond as usize) {
                Ok(()) => 0,
                Err(error) => error.into_posix(),
            }
        })
    }

    // ------------------------------------------------------------------
    // libdispatch semaphores (macOS std thread `Parker`).
    //
    // Rust `std`'s Darwin thread `Parker` blocks on a libdispatch semaphore, so
    // `thread::park`/`park_timeout` and everything layered on them — `mpsc`/
    // `mpmc` `recv`/`recv_timeout`, blocking channel and `Once` paths — reach
    // `dispatch_semaphore_wait`. The C layer interposes `dispatch_time`,
    // `dispatch_semaphore_create`/`wait`/`signal`, and `dispatch_release` and
    // forwards them here so the wait routes through `DetScheduler` and the
    // virtual clock exactly like the pthread/futex primitives. Without this the
    // Parker would block a real host thread outside the scheduler and read host
    // time — a silent determinism escape that shared the shim baton's own
    // `dispatch_semaphore_*` audit allowance.
    //
    // Deterministic tie-break (signal vs. deadline at the same virtual instant):
    // a signal is only applied by a *runnable* unparker, which the scheduler
    // runs before any clock advance; the deadline fires only through the
    // deadlock rescue, which advances virtual time solely when no task can make
    // progress. So a pending signal always wins a same-instant tie, and which
    // path removed the waiter — never a clock comparison — decides the outcome,
    // matching `patina_cond_timedwait`. Wakeup cause and order are recorded as
    // ordinary scheduler park/wake and timer-rescue operations, so replay is
    // exact.
    #[cfg(target_os = "macos")]
    const DISPATCH_TIME_NOW: u64 = 0;
    #[cfg(target_os = "macos")]
    const DISPATCH_TIME_FOREVER: u64 = u64::MAX;
    /// Non-zero sentinel returned when a timed wait reaches its deadline; std
    /// only tests `dispatch_semaphore_wait(...) != 0`.
    #[cfg(target_os = "macos")]
    const DISPATCH_TIMED_OUT: isize = -1;

    /// Reduce `dispatch_time(when, delta)` to the relative monotonic token that
    /// [`patina_dispatch_semaphore_wait`] consumes. std only ever calls it as
    /// `dispatch_time(DISPATCH_TIME_NOW, nanos)` for `park_timeout`, so a
    /// `NOW`-relative non-negative nanosecond delta is returned verbatim (the
    /// wait resolves it against the virtual monotonic clock); `FOREVER` and a
    /// non-positive delta pass through as their sentinels.
    ///
    /// # Safety
    /// C ABI entry point; no pointers are dereferenced.
    #[cfg(target_os = "macos")]
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_dispatch_time(when: u64, delta: i64) -> u64 {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        if when == DISPATCH_TIME_FOREVER {
            return DISPATCH_TIME_FOREVER;
        }
        if delta <= 0 {
            return DISPATCH_TIME_NOW;
        }
        // Clamp away from the `FOREVER` sentinel so a real deadline is never
        // mistaken for an infinite wait.
        (delta as u64).min(DISPATCH_TIME_FOREVER - 1)
    }

    /// Allocate a modeled dispatch semaphore and return its opaque handle. Pure
    /// local allocation — no scheduling point, mirroring the non-blocking
    /// `dispatch_semaphore_create`.
    ///
    /// # Safety
    /// C ABI entry point; the returned pointer is an opaque token, never
    /// dereferenced by the shim or by std.
    #[cfg(target_os = "macos")]
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_dispatch_semaphore_create(value: isize) -> *mut c_void {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        let mut state = lock_state();
        let handle = state.next_dispatch_handle;
        state.next_dispatch_handle = handle.wrapping_add(1).max(1);
        state.dispatch.insert(
            handle,
            DispatchSem {
                count: value,
                waiters: VecDeque::new(),
            },
        );
        handle as *mut c_void
    }

    /// Release a modeled dispatch semaphore (its `Parker`'s `Drop`). Handles are
    /// never reused, so simply dropping the table entry is safe.
    ///
    /// # Safety
    /// C ABI entry point; `object` is an opaque handle from
    /// [`patina_dispatch_semaphore_create`].
    #[cfg(target_os = "macos")]
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_dispatch_release(object: *mut c_void) {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        lock_state().dispatch.remove(&(object as usize));
    }

    /// Wait on a modeled dispatch semaphore, routing any block through the
    /// deterministic scheduler and virtual clock. Returns `0` when acquired (or
    /// signalled) and a non-zero sentinel when a timed wait reaches its
    /// deadline.
    ///
    /// # Safety
    /// C ABI entry point; `sem` is an opaque handle from
    /// [`patina_dispatch_semaphore_create`].
    #[cfg(target_os = "macos")]
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_dispatch_semaphore_wait(sem: *mut c_void, timeout: u64) -> isize {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        let key = sem as usize;
        if sched_point().is_err() {
            fatal("scheduler error entering dispatch_semaphore_wait");
        }
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            fatal(&format!("activating the thread runtime failed: {error:?}"));
        }
        // `ensure_active` may have just registered this host thread as the main
        // managed task, so read the current task after it.
        let me = current_task();
        let count_after = {
            let entry = state.dispatch.entry(key).or_default();
            entry.count -= 1;
            entry.count
        };
        if count_after >= 0 {
            // The token was available; no block.
            return 0;
        }
        if timeout == DISPATCH_TIME_NOW {
            // Non-blocking poll: undo the decrement and report timed out.
            if let Some(entry) = state.dispatch.get_mut(&key) {
                entry.count += 1;
            }
            return DISPATCH_TIMED_OUT;
        }
        state
            .dispatch
            .get_mut(&key)
            .expect("semaphore was just decremented")
            .waiters
            .push_back(me);
        if timeout == DISPATCH_TIME_FOREVER {
            match state.block(me, "dispatch-sem-wait", Wait::new(BlockClass::Sync, vec![])) {
                Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                Ok(Step::Continue) => {
                    fatal("dispatch semaphore wait parked without transferring the baton")
                }
                Err(ThreadError::Fatal(message)) => fatal(&message),
                Err(ThreadError::Posix(errno)) => fatal(&format!(
                    "dispatch semaphore wait failed with errno {errno}"
                )),
            }
            // Resumed only by a signal, which removed us from the waiters.
            0
        } else {
            let now = match with_context_raw(|context| context.now(ClockKind::Monotonic)) {
                Ok(now) => now,
                Err(_) => fatal("dispatch semaphore timed wait could not read the virtual clock"),
            };
            let deadline = now.saturating_add(timeout);
            match state.block_timed(
                me,
                "dispatch-sem-timedwait",
                Wait::new(BlockClass::Sync, vec![]),
                ClockKind::Monotonic,
                deadline,
            ) {
                Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                Ok(Step::Continue) => drop(state),
                Err(ThreadError::Fatal(message)) => fatal(&message),
                Err(ThreadError::Posix(errno)) => fatal(&format!(
                    "dispatch semaphore timed wait failed with errno {errno}"
                )),
            }
            // A timer wake left us in `timed_out` (and restored the count); a
            // signal wake removed us from the waiters and kept the decrement.
            if lock_state().timed_out.remove(&me) {
                DISPATCH_TIMED_OUT
            } else {
                0
            }
        }
    }

    /// Signal a modeled dispatch semaphore, waking one waiter if the increment
    /// leaves a non-positive count (i.e. a task was blocked). Returns `1` when a
    /// task was woken, `0` otherwise; std ignores the value.
    ///
    /// # Safety
    /// C ABI entry point; `sem` is an opaque handle from
    /// [`patina_dispatch_semaphore_create`].
    #[cfg(target_os = "macos")]
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_dispatch_semaphore_signal(sem: *mut c_void) -> isize {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        let key = sem as usize;
        if sched_point().is_err() {
            fatal("scheduler error entering dispatch_semaphore_signal");
        }
        let mut state = lock_state();
        let woke = {
            let entry = state.dispatch.entry(key).or_default();
            entry.count += 1;
            if entry.count <= 0 {
                entry.waiters.pop_front()
            } else {
                None
            }
        };
        match woke {
            Some(task) => {
                if let Err(message) = RealScheduler.wake(task) {
                    fatal(&message);
                }
                1
            }
            None => 0,
        }
    }

    // ------------------------------------------------------------------
    // The descriptor classes the thread runtime owns beside the sockets
    // (`net`): pipes and FIFOs, eventfds, and the readiness reactors.

    struct NetState {
        /// Every socket and the socket families' namespaces (`net`).
        sockets: net::Sockets,
        // In-process pipe channels. Endpoints are keyed by class handle
        // (`next_handle`, shared with the sockets, so a handle is a socket
        // XOR a pipe end); the descriptor table maps guest numbers onto them and
        // says which kind a number names. `pipe_channels` are the directed byte
        // buffers each endpoint reads from / writes to; see the "in-process
        // pipe" section.
        pipe_ends: BTreeMap<c_int, PipeEnd>,
        pipe_channels: BTreeMap<u64, PipeChannel>,
        /// The channel currently backing each open FIFO, keyed by the
        /// deterministic filesystem INODE of the FIFO entry — the identity two
        /// openers of the same named pipe must agree on. A name would be the
        /// wrong key: renaming the FIFO must not split its openers, and a fresh
        /// FIFO created at a vacated name must not inherit them. The binding
        /// exists only while some descriptor is open on the FIFO.
        fifo_channels: BTreeMap<u64, u64>,
        next_channel: u64,
        /// The pipefs and sockfs nodes behind anonymous pipes and sockets
        /// ([`PipeInode`]), keyed by their inode number.
        pipe_inodes: BTreeMap<u64, PipeInode>,
        next_pipe_ino: u64,
        // Virtual kqueue readiness reactors, keyed by registry id. The
        // descriptor table holds the description (a `dup`/`F_DUPFD` of a kqueue
        // fd — tokio's IO driver clones its selector this way — is a second
        // number on the same description), so the registry outlives any one
        // number and drops only when the last closes. macOS-only: kqueue/kevent
        // have no Linux counterpart.
        #[cfg(target_os = "macos")]
        kqueues: BTreeMap<u64, KqueueSlot>,
        #[cfg(target_os = "macos")]
        next_kq: u64,
        // Virtual epoll readiness reactors — the Linux mirror of the kqueue
        // table above, keyed by registry id the same way (mio clones its
        // selector through `F_DUPFD_CLOEXEC` on Linux exactly as on macOS: a
        // second number on one description in the descriptor table).
        #[cfg(target_os = "linux")]
        epolls: BTreeMap<u64, EpollSlot>,
        #[cfg(target_os = "linux")]
        next_epoll: u64,
        // Deterministic in-process eventfd counters (Linux; mio's `Waker`
        // vehicle, the EVFILT_USER analogue), keyed by class handle.
        #[cfg(target_os = "linux")]
        eventfds: BTreeMap<c_int, EventFd>,
        /// The class-handle allocator shared by `sockets`, `pipe_ends` and
        /// `eventfds`: an internal identity the descriptor table maps guest
        /// numbers onto, never a number the guest sees (see `next_handle`).
        next_handle: c_int,
    }

    impl NetState {
        fn new() -> Self {
            Self {
                sockets: net::Sockets::default(),
                pipe_ends: BTreeMap::new(),
                pipe_channels: BTreeMap::new(),
                fifo_channels: BTreeMap::new(),
                next_channel: 0,
                pipe_inodes: BTreeMap::new(),
                next_pipe_ino: 1,
                #[cfg(target_os = "macos")]
                kqueues: BTreeMap::new(),
                #[cfg(target_os = "macos")]
                next_kq: 0,
                #[cfg(target_os = "linux")]
                epolls: BTreeMap::new(),
                #[cfg(target_os = "linux")]
                next_epoll: 0,
                #[cfg(target_os = "linux")]
                eventfds: BTreeMap::new(),
                next_handle: 0,
            }
        }
    }

    /// A dotted-quad `IP:PORT` as a host-order address and port.
    fn parse_addr(addr: &str) -> Option<(u32, u16)> {
        let (host, port) = addr.rsplit_once(':')?;
        let port: u16 = port.parse().ok()?;
        let ip: std::net::Ipv4Addr = host.parse().ok()?;
        Some((u32::from(ip), port))
    }

    fn wake_all(waiters: Vec<TaskId>) {
        let mut scheduler = RealScheduler;
        for task in waiters {
            #[cfg(target_os = "linux")]
            lock_state().remove_signal_wait(task);
            if let Err(message) = scheduler.wake(task) {
                fatal(&message);
            }
        }
    }

    /// Resolve a host name through the run's deterministic DNS host table.
    ///
    /// Writes the resolved address as a host-byte-order `u32` and returns 0; on
    /// failure returns -1 with errno set. Resolution is a recorded boundary
    /// operation, so an injected failure or latency reproduces on replay.
    ///
    /// # Safety
    /// C ABI entry point: `name` must be a NUL-terminated string and `ip` must
    /// point at a writable `uint32_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_dns_resolve(name: *const c_char, ip: *mut u32) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        if let Err(errno) = sched_point() {
            return super::fail(errno);
        }
        if name.is_null() || ip.is_null() {
            return super::fail(EINVAL);
        }
        let Ok(name) = (unsafe { std::ffi::CStr::from_ptr(name) }).to_str() else {
            return super::fail(EINVAL);
        };
        let resolved = match with_context_raw(|context| context.dns_resolve(name)) {
            Ok(address) => address,
            Err(errno) => return super::fail(errno),
        };
        // The runtime's resolutions are dotted quads by construction (the host
        // table validates every entry at configuration time), so a malformed one
        // here means the runtime and this shim disagree — fail loudly rather
        // than hand the guest a wrong address.
        let Some((address, _)) = parse_addr(&format!("{resolved}:0")) else {
            fatal("DNS resolution returned a malformed address");
        };
        unsafe { ip.write(address) };
        super::set_errno(0);
        0
    }

    // ------------------------------------------------------------------
    // In-process pipe. Both endpoints of a `pipe`/`pipe2` (or of a FIFO) live
    // inside this one guest process (the common case: an async
    // runtime's IO-driver / signal self-pipe wakeup), so there is no cross-
    // address-space escape — they are modeled as deterministic in-memory byte
    // channels whose reads/writes are scheduler-visible, reusing the SAME baton /
    // waiter machinery the virtual sockets use (block / switch_and_park / wake).
    // Being pure in-process memory that only ever mutates while the acting task
    // holds the baton, the transfer is deterministic GIVEN the schedule — exactly
    // like the futex / mutex words — so it carries NO trace events of its own: the
    // recorded scheduler steps already pin every interleaving, so record and
    // flag-free replay converge on that. No host call is ever made.

    /// A bounded, directed byte channel: writer endpoints feed it, reader
    /// endpoints drain it. A `pipe` (or a FIFO) is a single channel.
    struct PipeChannel {
        buffer: VecDeque<u8>,
        capacity: usize,
        /// Number of live fds referencing the READ side (one per reader endpoint,
        /// plus one per `dup`/`F_DUPFD` of one). The reader side is "closed" —
        /// `read_closed`, further writes get `EPIPE` — only when this hits 0.
        read_refs: usize,
        /// Number of live fds referencing the WRITE side. The writer side is
        /// "closed" — `write_closed`, drained reads return EOF — only at 0.
        write_refs: usize,
        /// Tasks parked in a blocking read, waiting for bytes to arrive.
        recv_waiters: VecDeque<TaskId>,
        /// Tasks parked in a blocking write, waiting for buffer space.
        send_waiters: VecDeque<TaskId>,
        /// Tasks parked in a blocking FIFO `open`, waiting for the opposite-end
        /// opener to arrive. One queue for both directions, as the kernel keeps
        /// one wait queue per pipe: a woken task re-checks its own condition.
        /// Always empty for an anonymous pipe, whose two ends exist at birth.
        open_waiters: VecDeque<TaskId>,
        /// How many times this channel has been opened for reading / for
        /// writing — Linux's `r_counter`/`w_counter`. A blocking open waits for
        /// the PARTNER COUNTER to move, not for the partner to still be there,
        /// so a writer that opens and closes again still releases a reader
        /// parked in `open(O_RDONLY)`.
        read_opens: u64,
        write_opens: u64,
        /// The deterministic-filesystem inode this channel belongs to when it
        /// backs a FIFO, so the last close can drop the inode → channel binding
        /// (a later `open` of the same FIFO then starts from an empty pipe,
        /// exactly as it does on a kernel that frees the pipe with its last fd).
        /// `None` for an anonymous `pipe` channel.
        fifo_ino: Option<u64>,
        /// Read-direction arrival sequence: bumped on every event that could
        /// newly satisfy a reader (bytes written, writer close). The epoll
        /// frontend's EPOLLET latch compares sequences so an edge re-fires per
        /// arrival — the kernel's semantics — even when readiness never dropped
        /// (a partially drained buffer). Linux-only: the kqueue frontend's
        /// EV_CLEAR latch re-arms only on a readiness drop.
        #[cfg(target_os = "linux")]
        read_events: u64,
        /// Write-direction sequence: bumped on space creation / reader close.
        #[cfg(target_os = "linux")]
        write_events: u64,
    }

    /// Real pipes carry a fixed-capacity kernel buffer (Linux's default is 64 KiB);
    /// match it so a writer that outruns its reader parks on a full buffer exactly
    /// as it would on the host, rather than buffering without bound.
    const PIPE_CAPACITY: usize = 64 * 1024;
    /// `PIPE_BUF`: the largest write a pipe takes whole or not at all.
    #[cfg(target_os = "linux")]
    const PIPE_BUF: usize = 4096;
    #[cfg(target_os = "macos")]
    const PIPE_BUF: usize = 512;

    #[derive(Debug, PartialEq, Eq)]
    enum PipeRead {
        Read(usize),
        Eof,
        WouldBlock,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum PipeWrite {
        Wrote(usize),
        BrokenPipe,
        WouldBlock,
    }

    impl PipeChannel {
        fn new(capacity: usize) -> Self {
            Self {
                buffer: VecDeque::new(),
                capacity,
                // Every channel is created with exactly one reader endpoint and
                // one writer endpoint; `dup` raises the matching side later.
                read_refs: 1,
                write_refs: 1,
                recv_waiters: VecDeque::new(),
                send_waiters: VecDeque::new(),
                open_waiters: VecDeque::new(),
                read_opens: 1,
                write_opens: 1,
                fifo_ino: None,
                #[cfg(target_os = "linux")]
                read_events: 0,
                #[cfg(target_os = "linux")]
                write_events: 0,
            }
        }

        /// The channel behind a FIFO inode. Unlike an anonymous pipe it is born
        /// with NO ends: every `open` of the FIFO adds one, and the rendezvous
        /// rules below decide when an open may proceed.
        fn new_fifo(capacity: usize, ino: u64) -> Self {
            Self {
                read_refs: 0,
                write_refs: 0,
                read_opens: 0,
                write_opens: 0,
                fifo_ino: Some(ino),
                ..Self::new(capacity)
            }
        }

        /// Every reader fd of this channel has closed: further writes get
        /// `EPIPE`. Derived from the reference count rather than latched,
        /// because a FIFO's reader side comes BACK when it is opened again.
        fn read_closed(&self) -> bool {
            self.read_refs == 0
        }

        /// Every writer fd has closed: drained reads return EOF. Derived for the
        /// same reason.
        fn write_closed(&self) -> bool {
            self.write_refs == 0
        }

        /// Pull up to `dst.len()` bytes. `WouldBlock` only when the buffer is empty
        /// and the writer is still open; drained + writer-closed is `Eof`.
        fn try_read(&mut self, dst: &mut [u8]) -> PipeRead {
            if !self.buffer.is_empty() {
                let count = dst.len().min(self.buffer.len());
                for (slot, byte) in dst[..count].iter_mut().zip(self.buffer.drain(..count)) {
                    *slot = byte;
                }
                #[cfg(target_os = "linux")]
                {
                    self.write_events = self.write_events.wrapping_add(1);
                }
                PipeRead::Read(count)
            } else if self.write_closed() {
                PipeRead::Eof
            } else {
                PipeRead::WouldBlock
            }
        }

        /// Push as many of `src`'s bytes as fit — all of them or none when
        /// there are at most `PIPE_BUF` (`pipe_write`'s atomic write).
        /// `WouldBlock` when they do not fit and the reader is open (the caller
        /// parks); a closed reader is `BrokenPipe` (the caller generates SIGPIPE
        /// before returning EPIPE).
        fn try_write(&mut self, src: &[u8]) -> PipeWrite {
            if self.read_closed() {
                return PipeWrite::BrokenPipe;
            }
            let space = self.capacity - self.buffer.len();
            if space == 0 || (src.len() <= PIPE_BUF && space < src.len()) {
                return PipeWrite::WouldBlock;
            }
            let count = src.len().min(space);
            self.buffer.extend(&src[..count]);
            #[cfg(target_os = "linux")]
            {
                self.read_events = self.read_events.wrapping_add(1);
            }
            PipeWrite::Wrote(count)
        }
    }

    /// One end of a pipe or FIFO. `read_channel`/`write_channel` name the
    /// directed [`PipeChannel`]s this endpoint may drain / feed: a pipe end
    /// holds one of them, a FIFO opened read-write both sides of its one.
    struct PipeEnd {
        read_channel: Option<u64>,
        write_channel: Option<u64>,
        /// Set when this endpoint came from opening a FIFO rather than from
        /// `pipe`: the NODE it is open on. It is all the descriptor
        /// needs, because `fstat` asks the filesystem about that node — the
        /// node's own reference (taken at the first open, dropped with the last
        /// endpoint) is what keeps it answerable even after the last name for it
        /// is unlinked.
        fifo_ino: Option<u64>,
        /// The pipefs node an anonymous pipe end is on
        /// (`net.pipe_inodes`); `None` for a FIFO end, whose node is
        /// `fifo_ino`'s.
        inode: Option<u64>,
    }

    /// The node behind an anonymous pipe (both ends share one, on pipefs) or a
    /// socket (each its own, on sockfs): what `fstat` reports, what
    /// `fchmod` changes, and what the filesystem-level answers (`fstatfs`,
    /// `syncfs`) are about. It holds no bytes — those are the channel's.
    struct PipeInode {
        socket: bool,
        /// Permission bits: `0o600` for a pipe, `0o777` for a socket, as the
        /// kernel creates them; `fchmod` changes them.
        mode: u32,
        atime_nanos: u64,
        mtime_nanos: u64,
        ctime_nanos: u64,
        /// Endpoints naming this node; it is freed with the last.
        ends: usize,
    }

    /// Mint a pipefs/sockfs node stamped with the filesystem clock's now.
    fn mint_pipe_inode(state: &mut ThreadRuntime, socket: bool, now: u64, ends: usize) -> u64 {
        let ino = state.net.next_pipe_ino;
        state.net.next_pipe_ino = ino.wrapping_add(1);
        state.net.pipe_inodes.insert(
            ino,
            PipeInode {
                socket,
                mode: if socket { 0o777 } else { 0o600 },
                atime_nanos: now,
                mtime_nanos: now,
                ctime_nanos: now,
                ends,
            },
        );
        ino
    }

    /// The instant a new pipefs/sockfs node is stamped with: the time the
    /// deterministic filesystem stamps its own entries with (0 before a runtime
    /// is installed, which only a unit test reaches).
    fn pipe_inode_time() -> u64 {
        super::fs_time_unrecorded()
    }

    /// The pipefs/sockfs node behind `fd` when it is an anonymous pipe end
    /// or a socket.
    fn anon_inode(state: &ThreadRuntime, fd: c_int) -> Option<u64> {
        let resolved = class_entry(fd).ok()?;
        let handle = resolved.handle as c_int;
        match resolved.kind {
            FdKind::Pipe => state.net.pipe_ends.get(&handle)?.inode,
            FdKind::Socket => state
                .net
                .sockets
                .table
                .get(&handle)
                .map(|socket| socket.inode),
            _ => None,
        }
    }

    /// The pipefs/sockfs node behind `fd`, if it is an anonymous pipe end or
    /// a socket: its metadata as `fstat` reports it.
    pub(crate) fn pipe_inode_metadata(fd: c_int) -> Option<super::PatinaMetadata> {
        let state = lock_state();
        let ino = anon_inode(&state, fd)?;
        let inode = state.net.pipe_inodes.get(&ino)?;
        Some(super::PatinaMetadata {
            kind: if inode.socket {
                super::PATINA_ENTRY_SOCKET
            } else {
                super::PATINA_ENTRY_FIFO
            },
            mode: inode.mode,
            nlink: 1,
            fs: if inode.socket {
                super::PATINA_FS_SOCKFS
            } else {
                super::PATINA_FS_PIPEFS
            },
            length: 0,
            ino,
            atime_nanos: inode.atime_nanos,
            mtime_nanos: inode.mtime_nanos,
            ctime_nanos: inode.ctime_nanos,
            btime_nanos: 0,
        })
    }

    /// `fchmod` on an anonymous pipe end or a socket: the node's permission
    /// bits change and its `ctime` moves. `None` for any other descriptor.
    pub(crate) fn pipe_inode_set_mode(fd: c_int, mode: u32) -> Option<()> {
        let now = pipe_inode_time();
        let mut state = lock_state();
        let ino = anon_inode(&state, fd)?;
        let inode = state.net.pipe_inodes.get_mut(&ino)?;
        inode.mode = mode & 0o7777;
        inode.ctime_nanos = now;
        Some(())
    }

    /// Which filesystem a pipe-kind descriptor is on: a FIFO end is on the
    /// deterministic volume, an anonymous pipe on pipefs. `None` for a number
    /// that is not a pipe end.
    #[cfg(target_os = "linux")]
    pub(crate) fn pipe_filesystem(fd: c_int) -> Option<u32> {
        let (end, _) = pipe_entry(fd).ok()?;
        let state = lock_state();
        let end = state.net.pipe_ends.get(&end)?;
        Some(match end.inode {
            None => super::PATINA_FS_VOLUME,
            Some(_) => super::PATINA_FS_PIPEFS,
        })
    }

    fn drain_channel_recv_waiters(state: &mut ThreadRuntime, channel: u64) -> Vec<TaskId> {
        state
            .net
            .pipe_channels
            .get_mut(&channel)
            .map(|channel| channel.recv_waiters.drain(..).collect())
            .unwrap_or_default()
    }

    fn drain_channel_send_waiters(state: &mut ThreadRuntime, channel: u64) -> Vec<TaskId> {
        state
            .net
            .pipe_channels
            .get_mut(&channel)
            .map(|channel| channel.send_waiters.drain(..).collect())
            .unwrap_or_default()
    }

    /// Create a simplex pipe: `read_fd_out` is the read end, `write_fd_out` the
    /// write end, both non-blocking when `nonblocking != 0` and close-on-exec
    /// when `cloexec != 0`. The ends and the backing channel come from the class
    /// handle / channel counters and the two guest numbers from the descriptor
    /// table, so their numbering is a pure function of the schedule. Activates
    /// the thread subsystem so a later blocking read/write can park via the baton.
    ///
    /// # Safety
    /// `read_fd_out`/`write_fd_out` must be writable.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_pipe(
        read_fd_out: *mut c_int,
        write_fd_out: *mut c_int,
        nonblocking: c_int,
        cloexec: c_int,
    ) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        if read_fd_out.is_null() || write_fd_out.is_null() {
            return super::fail(EINVAL);
        }
        let now = pipe_inode_time();
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return super::fail(error.into_posix());
        }
        let inode = mint_pipe_inode(&mut state, false, now, 2);
        let channel = state.net.next_channel;
        state.net.next_channel = state.net.next_channel.wrapping_add(1);
        state
            .net
            .pipe_channels
            .insert(channel, PipeChannel::new(PIPE_CAPACITY));
        let read_end = next_handle(&mut state);
        let write_end = next_handle(&mut state);
        state.net.pipe_ends.insert(
            read_end,
            PipeEnd {
                read_channel: Some(channel),
                write_channel: None,
                fifo_ino: None,
                inode: Some(inode),
            },
        );
        state.net.pipe_ends.insert(
            write_end,
            PipeEnd {
                read_channel: None,
                write_channel: Some(channel),
                fifo_ino: None,
                inode: Some(inode),
            },
        );
        let nonblock = if nonblocking != 0 { O_NONBLOCK } else { 0 };
        // SAFETY: the out-pointers were checked non-null above.
        unsafe {
            bind_pipe_pair(
                &mut state,
                (read_end, O_READ | nonblock),
                (write_end, O_WRITE | nonblock),
                cloexec != 0,
                read_fd_out,
                write_fd_out,
            )
        }
    }

    /// Bind two freshly minted pipe ends to guest numbers, atomically. A full
    /// table (`EMFILE`) releases both ends — through the ordinary close path,
    /// so the channel is reclaimed — and creates nothing.
    ///
    /// # Safety
    /// `first_out`/`second_out` must be writable.
    unsafe fn bind_pipe_pair(
        state: &mut ThreadRuntime,
        first: (c_int, u32),
        second: (c_int, u32),
        cloexec: bool,
        first_out: *mut c_int,
        second_out: *mut c_int,
    ) -> c_int {
        let bound = super::fd_table().lock().install_pair(
            FdKind::Pipe,
            (first.0 as u64, first.1),
            (second.0 as u64, second.1),
            cloexec,
        );
        match bound {
            Ok((a, b)) => {
                // SAFETY: per this function's contract.
                unsafe {
                    first_out.write(a);
                    second_out.write(b);
                }
                super::set_errno(0);
                0
            }
            Err(errno) => {
                let _ = state;
                // The ends are unreachable from any guest number, so their
                // release wakes nobody; drop them through the shared path.
                let _ = pipe_close_locked(first.0 as u64);
                let _ = pipe_close_locked(second.0 as u64);
                super::fail(errno)
            }
        }
    }

    // ------------------------------------------------------------------
    // Named pipes (FIFOs). A FIFO is a filesystem NAME (created by `mkfifo`,
    // stat-able, renameable, unlinkable — all of that is deterministic
    // filesystem state) whose BYTES are not filesystem state at all: they live
    // in a pipe, exactly like an anonymous one's. So the entry lives in the
    // driver and the transfer reuses the machinery above — one `PipeChannel`
    // per open FIFO inode, the same waiter deques, the same `try_read`/
    // `try_write`, the same EOF/`EPIPE` rules — instead of a second pipe model.
    //
    // What a FIFO adds is the rendezvous at OPEN, and it is modeled the way the
    // kernel models it (`fs/pipe.c:fifo_open`): an open registers its end and
    // bumps that side's open counter, wakes anything parked on the pipe, and
    // then — unless it is `O_NONBLOCK` or `O_RDWR` — waits for the PARTNER
    // counter to move. Waiting on the counter rather than on "a partner is
    // currently there" is what makes a writer that opens and closes again still
    // release a reader parked in `open(O_RDONLY)`.

    /// Open the FIFO whose deterministic-filesystem inode is `ino`, returning a
    /// virtual pipe-endpoint fd or -1 with `patina_errno` set.
    ///
    /// The caller has already asked the filesystem about the entry, so
    /// existence, path resolution, and the permission decision are settled
    /// before this runs.
    ///
    /// The first open of a FIFO takes a REFERENCE on its node, and the last
    /// close of the channel drops it. That reference is the whole of the FIFO's
    /// inode lifetime: a kernel keeps an inode alive while any descriptor holds
    /// it, and these descriptors are the ones the filesystem itself has no
    /// handle for — so without it, unlinking the last name would pull the node
    /// out from under a perfectly live endpoint and `fstat` would answer for a
    /// node nobody can name.
    ///
    /// Blocking is a deterministic park through the same baton the pipe reads
    /// and writes use, so under the cooperative scheduler another task's
    /// `open(O_WRONLY)` is what wakes a reader parked here — and a FIFO nobody
    /// ever opens for writing surfaces as the runtime's deadlock report rather
    /// than a hung process.
    pub(crate) fn fifo_open(
        ino: u64,
        read: bool,
        write: bool,
        nonblocking: bool,
        status: u32,
        cloexec: bool,
    ) -> c_int {
        let me = current_task();
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return super::fail(error.into_posix());
        }
        let existing = state.net.fifo_channels.get(&ino).copied();
        // `O_WRONLY|O_NONBLOCK` with no reader is `ENXIO`, and it is decided
        // BEFORE any bookkeeping: the call never becomes a writer, so it must
        // not leave a channel or an open count behind. No channel at all is the
        // same answer as a channel with no readers.
        if write && !read && nonblocking {
            let has_reader = existing
                .and_then(|channel| state.net.pipe_channels.get(&channel))
                .is_some_and(|channel| channel.read_refs > 0);
            if !has_reader {
                return super::fail(super::ENXIO);
            }
        }
        let opened_channel = existing.is_none();
        let channel_id = match existing {
            Some(channel) => channel,
            None => {
                let channel = state.net.next_channel;
                state.net.next_channel = state.net.next_channel.wrapping_add(1);
                state
                    .net
                    .pipe_channels
                    .insert(channel, PipeChannel::new_fifo(PIPE_CAPACITY, ino));
                state.net.fifo_channels.insert(ino, channel);
                channel
            }
        };
        let channel = state
            .net
            .pipe_channels
            .get_mut(&channel_id)
            .expect("the channel was just resolved or created");
        if read {
            channel.read_refs += 1;
            channel.read_opens = channel.read_opens.wrapping_add(1);
        }
        if write {
            channel.write_refs += 1;
            channel.write_opens = channel.write_opens.wrapping_add(1);
        }
        // `O_RDWR` on a FIFO is its own partner, so it never waits — Linux
        // leaves this undefined and implements it exactly this way.
        let wait = if read && write {
            None
        } else if read {
            (channel.write_refs == 0 && !nonblocking).then_some((true, channel.write_opens))
        } else {
            // The non-blocking case already returned `ENXIO` above.
            (channel.read_refs == 0).then_some((false, channel.read_opens))
        };
        let woken: Vec<TaskId> = channel.open_waiters.drain(..).collect();
        let end = next_handle(&mut state);
        state.net.pipe_ends.insert(
            end,
            PipeEnd {
                read_channel: read.then_some(channel_id),
                write_channel: write.then_some(channel_id),
                fifo_ino: Some(ino),
                inode: None,
            },
        );
        // The guest number is reserved BEFORE the rendezvous, as the kernel's
        // `do_sys_openat2` takes its slot before the blocking `fifo_open` — so a
        // second open on another thread while this one waits numbers after it.
        let fd = match super::install_fd(FdKind::Pipe, end as u64, status, cloexec) {
            Ok(fd) => fd,
            Err(errno) => {
                drop(state);
                let _ = pipe_close_locked(end as u64);
                wake_all(woken);
                return super::fail(errno);
            }
        };
        drop(state);
        // The channel is the node's one reference: taken when it comes into
        // existence, dropped when it is reclaimed. Outside the state lock, like
        // every other runtime call from this module.
        if opened_channel {
            if let Err(errno) = super::with_context(|context| context.fs_retain_inode(ino)) {
                super::patina_close(fd);
                wake_all(woken);
                return super::fail(errno);
            }
        }
        wake_all(woken);

        if let Some((for_writer, seen)) = wait {
            loop {
                let mut state = lock_state();
                let Some(channel) = state.net.pipe_channels.get_mut(&channel_id) else {
                    // Unreachable: this open holds a reference on the channel.
                    break;
                };
                let satisfied = if for_writer {
                    channel.write_refs > 0 || channel.write_opens != seen
                } else {
                    channel.read_refs > 0 || channel.read_opens != seen
                };
                if satisfied {
                    break;
                }
                channel.open_waiters.push_back(me);
                let reason = if for_writer {
                    "fifo-open-read"
                } else {
                    "fifo-open-write"
                };
                let step = state.block(
                    me,
                    reason,
                    Wait::new(BlockClass::Io, vec![WaiterLoc::PipeOpen(channel_id)]),
                );
                match step {
                    Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                    Ok(Step::Continue) => drop(state),
                    Err(error) => {
                        let errno = error.into_posix();
                        drop(state);
                        // The descriptor never came into existence, so release
                        // the number and the end this open registered — through
                        // the ordinary close path, so the partner's EOF/`EPIPE`
                        // bookkeeping and the channel reclamation are the usual
                        // ones.
                        super::patina_close(fd);
                        return super::fail(errno);
                    }
                }
                lock_state().timed_out.remove(&me);
                #[cfg(target_os = "linux")]
                if signals::resume() == signals::Resumed::Eintr {
                    super::patina_close(fd);
                    return super::fail(super::EINTR);
                }
            }
        }
        super::set_errno(0);
        fd
    }

    /// The bytes a pipe end's `FIONREAD` reports: what is queued
    /// in the channel it reads (a pipe's write end, the pipe's one channel).
    pub(crate) fn pipe_queued(handle: u64) -> Option<usize> {
        let state = lock_state();
        let end = state.net.pipe_ends.get(&(handle as c_int))?;
        let channel = end.read_channel.or(end.write_channel)?;
        state
            .net
            .pipe_channels
            .get(&channel)
            .map(|channel| channel.buffer.len())
    }

    /// What `fstat` should report for `fd` when it is a FIFO descriptor.
    pub(crate) fn fifo_ino(fd: c_int) -> Option<u64> {
        let (end, _) = pipe_entry(fd).ok()?;
        lock_state()
            .net
            .pipe_ends
            .get(&end)
            .and_then(|end| end.fifo_ino)
    }

    /// # Safety
    /// `buf` must be writable for `len` bytes when nonzero.
    pub(crate) unsafe fn pipe_read(
        handle: u64,
        nonblocking: bool,
        buf: *mut c_void,
        len: usize,
    ) -> isize {
        let fd = handle as c_int;
        if let Err(errno) = sched_point() {
            return super::fail(errno) as isize;
        }
        if len != 0 && buf.is_null() {
            return super::fail(EINVAL) as isize;
        }
        if len == 0 {
            return 0;
        }
        let me = current_task();
        loop {
            let mut state = lock_state();
            let channel = match state.net.pipe_ends.get(&fd) {
                // A read on the write-only end of a simplex pipe is EBADF (the end
                // is O_WRONLY), matching the kernel.
                Some(end) => match end.read_channel {
                    Some(channel) => channel,
                    None => return super::fail(super::EBADF) as isize,
                },
                None => return super::fail(super::EBADF) as isize,
            };
            // Reborrowed each iteration; only one `&mut` to the caller's buffer is
            // ever live (the previous is dropped when the iteration ends).
            let dst = unsafe { std::slice::from_raw_parts_mut(buf.cast::<u8>(), len) };
            let outcome = state
                .net
                .pipe_channels
                .get_mut(&channel)
                .map(|channel| channel.try_read(dst))
                // A live endpoint always references a live channel.
                .unwrap_or(PipeRead::Eof);
            match outcome {
                PipeRead::Read(count) => {
                    let waiters = drain_channel_send_waiters(&mut state, channel);
                    drop(state);
                    wake_all(waiters);
                    return isize::try_from(count).unwrap_or(isize::MAX);
                }
                PipeRead::Eof => return 0,
                PipeRead::WouldBlock => {
                    if nonblocking {
                        return super::fail(EWOULDBLOCK) as isize;
                    }
                    if let Some(channel) = state.net.pipe_channels.get_mut(&channel) {
                        channel.recv_waiters.push_back(me);
                    }
                    let step = state.block(
                        me,
                        "pipe-read",
                        Wait::new(BlockClass::Io, vec![WaiterLoc::PipeRecv(channel)]),
                    );
                    match step {
                        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                        Ok(Step::Continue) => drop(state),
                        Err(error) => return super::fail(error.into_posix()) as isize,
                    }
                    lock_state().timed_out.remove(&me);
                    #[cfg(target_os = "linux")]
                    if signals::resume() == signals::Resumed::Eintr {
                        return super::fail(super::EINTR) as isize;
                    }
                }
            }
        }
    }

    /// # Safety
    /// `buf` must be readable for `len` bytes when nonzero.
    pub(crate) unsafe fn pipe_write(
        handle: u64,
        nonblocking: bool,
        buf: *const c_void,
        len: usize,
        nosignal: bool,
    ) -> isize {
        let fd = handle as c_int;
        if let Err(errno) = sched_point() {
            return super::fail(errno) as isize;
        }
        if len != 0 && buf.is_null() {
            return super::fail(EINVAL) as isize;
        }
        if len == 0 {
            return 0;
        }
        let src = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len) };
        let me = current_task();
        // A blocking write returns once every byte is in (a signal or a
        // vanished reader ends it early with what went in); a nonblocking one
        // returns what fit.
        let mut written = 0;
        loop {
            let mut state = lock_state();
            let channel = match state.net.pipe_ends.get(&fd) {
                // A write on the read-only end of a simplex pipe is EBADF.
                Some(end) => match end.write_channel {
                    Some(channel) => channel,
                    None => return super::fail(super::EBADF) as isize,
                },
                None => return super::fail(super::EBADF) as isize,
            };
            let outcome = state
                .net
                .pipe_channels
                .get_mut(&channel)
                .map(|channel| channel.try_write(&src[written..]))
                .unwrap_or(PipeWrite::BrokenPipe);
            match outcome {
                PipeWrite::Wrote(count) => {
                    written += count;
                    let waiters = drain_channel_recv_waiters(&mut state, channel);
                    drop(state);
                    wake_all(waiters);
                    if written == len || nonblocking {
                        return isize::try_from(written).unwrap_or(isize::MAX);
                    }
                }
                PipeWrite::BrokenPipe => {
                    drop(state);
                    if !nosignal {
                        broken_pipe_signal();
                    }
                    if written > 0 {
                        return isize::try_from(written).unwrap_or(isize::MAX);
                    }
                    return super::fail(super::EPIPE) as isize;
                }
                PipeWrite::WouldBlock => {
                    if nonblocking {
                        return super::fail(EWOULDBLOCK) as isize;
                    }
                    if let Some(channel) = state.net.pipe_channels.get_mut(&channel) {
                        channel.send_waiters.push_back(me);
                    }
                    let step = state.block(
                        me,
                        "pipe-write",
                        Wait::new(BlockClass::Io, vec![WaiterLoc::PipeSend(channel)]),
                    );
                    match step {
                        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                        Ok(Step::Continue) => drop(state),
                        Err(error) => return super::fail(error.into_posix()) as isize,
                    }
                    lock_state().timed_out.remove(&me);
                    #[cfg(target_os = "linux")]
                    if signals::resume() == signals::Resumed::Eintr {
                        if written > 0 {
                            return isize::try_from(written).unwrap_or(isize::MAX);
                        }
                        return super::fail(super::EINTR) as isize;
                    }
                }
            }
        }
    }

    fn broken_pipe_signal() {
        #[cfg(target_os = "linux")]
        {
            // The channel lock must be released before the shared generation entry.
            let rc = unsafe {
                signals::generate_signal(
                    signals::GenerationTarget::Thread {
                        tgid: Some(crate::registry::IDENTITY_PID as i32),
                        tid: tid_of(current_task()),
                    },
                    signals::SIGPIPE,
                    signals::GenerationInfo::User,
                )
            };
            if rc != 0 {
                fatal("SIGPIPE generation failed");
            }
            signals::deliver();
        }
    }

    // ------------------------------------------------------------------
    // Splicing (`splice`, `tee`, `vmsplice`, and `sendfile`/`copy` into a
    // pipe): the kernel moves bytes between a pipe and a file, or between two
    // pipes, without a user copy. Here they are the SAME channel buffers the
    // reads and writes above use, under the same baton park, so a splice is
    // observable exactly as the equivalent read and write would be.

    /// The pipe an endpoint belongs to — the one channel of an anonymous pipe
    /// or a FIFO.
    #[cfg(target_os = "linux")]
    pub(crate) fn splice_pipe(handle: u64) -> Option<u64> {
        let state = lock_state();
        let end = state.net.pipe_ends.get(&(handle as c_int))?;
        end.read_channel.or(end.write_channel)
    }

    /// What a splice waits for on one pipe.
    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy)]
    enum PipeWant {
        /// Bytes to read, or the last writer gone.
        Data(u64),
        /// Room to write, or the last reader gone.
        Space(u64),
    }

    /// Park until every `want` is met — the ordinary pipe park, on each
    /// channel's queue — or answer at once under `nonblocking` (`EAGAIN`).
    /// A write side whose readers are all gone is `EPIPE`, raised as `SIGPIPE`
    /// first. `Ok(false)` when a read side is empty with no writer left: there
    /// is nothing to wait for.
    #[cfg(target_os = "linux")]
    fn pipe_await(wants: &[PipeWant], nonblocking: bool) -> Result<bool, c_int> {
        let me = current_task();
        loop {
            let mut state = lock_state();
            let mut locs = Vec::new();
            for want in wants {
                match *want {
                    PipeWant::Data(channel) => {
                        let Some(ch) = state.net.pipe_channels.get(&channel) else {
                            return Ok(false);
                        };
                        if ch.buffer.is_empty() {
                            if ch.write_closed() {
                                return Ok(false);
                            }
                            locs.push(WaiterLoc::PipeRecv(channel));
                        }
                    }
                    PipeWant::Space(channel) => {
                        let Some(ch) = state.net.pipe_channels.get(&channel) else {
                            return Err(super::EPIPE);
                        };
                        if ch.read_closed() {
                            drop(state);
                            broken_pipe_signal();
                            return Err(super::EPIPE);
                        }
                        if ch.buffer.len() >= ch.capacity {
                            locs.push(WaiterLoc::PipeSend(channel));
                        }
                    }
                }
            }
            if locs.is_empty() {
                return Ok(true);
            }
            if nonblocking {
                return Err(EWOULDBLOCK);
            }
            for loc in &locs {
                match *loc {
                    WaiterLoc::PipeRecv(channel) => {
                        if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
                            ch.recv_waiters.push_back(me);
                        }
                    }
                    WaiterLoc::PipeSend(channel) => {
                        if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
                            ch.send_waiters.push_back(me);
                        }
                    }
                    _ => {}
                }
            }
            let step = state.block(me, "pipe-splice", Wait::new(BlockClass::Io, locs.clone()));
            match step {
                Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                Ok(Step::Continue) => drop(state),
                Err(error) => return Err(error.into_posix()),
            }
            let mut state = lock_state();
            state.timed_out.remove(&me);
            unregister_waiters(&mut state, me, &locs);
            drop(state);
            #[cfg(target_os = "linux")]
            if signals::resume() == signals::Resumed::Eintr {
                return Err(super::EINTR);
            }
        }
    }

    /// Wait until the pipe `handle` reads from has bytes (`Ok(0)`: none will
    /// come, its last writer is gone).
    #[cfg(target_os = "linux")]
    pub(crate) fn pipe_await_data(handle: u64, nonblocking: bool) -> Result<usize, c_int> {
        sched_point()?;
        let channel = splice_pipe(handle).ok_or(super::EINVAL)?;
        if !pipe_await(&[PipeWant::Data(channel)], nonblocking)? {
            return Ok(0);
        }
        Ok(lock_state()
            .net
            .pipe_channels
            .get(&channel)
            .map_or(0, |channel| channel.buffer.len()))
    }

    /// Wait until the pipe `handle` writes to has room: the free bytes.
    #[cfg(target_os = "linux")]
    pub(crate) fn pipe_await_space(handle: u64, nonblocking: bool) -> Result<usize, c_int> {
        sched_point()?;
        let channel = splice_pipe(handle).ok_or(super::EINVAL)?;
        pipe_await(&[PipeWant::Space(channel)], nonblocking)?;
        Ok(lock_state()
            .net
            .pipe_channels
            .get(&channel)
            .map_or(0, |channel| {
                channel.capacity.saturating_sub(channel.buffer.len())
            }))
    }

    /// Drain up to `max` bytes from the pipe `handle` belongs to, waking its
    /// writers. Never waits.
    #[cfg(target_os = "linux")]
    pub(crate) fn pipe_take(handle: u64, max: usize) -> Vec<u8> {
        let Some(channel) = splice_pipe(handle) else {
            return Vec::new();
        };
        let mut state = lock_state();
        let Some(ch) = state.net.pipe_channels.get_mut(&channel) else {
            return Vec::new();
        };
        let count = max.min(ch.buffer.len());
        let bytes: Vec<u8> = ch.buffer.drain(..count).collect();
        if !bytes.is_empty() {
            #[cfg(target_os = "linux")]
            {
                ch.write_events = ch.write_events.wrapping_add(1);
            }
        }
        let waiters = drain_channel_send_waiters(&mut state, channel);
        drop(state);
        wake_all(waiters);
        bytes
    }

    /// Put bytes a splice took back at the head of the pipe, ahead of anything
    /// written since: the part of a transfer its destination did not accept.
    #[cfg(target_os = "linux")]
    pub(crate) fn pipe_untake(handle: u64, bytes: &[u8]) {
        let Some(channel) = splice_pipe(handle) else {
            return;
        };
        let mut state = lock_state();
        if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
            for byte in bytes.iter().rev() {
                ch.buffer.push_front(*byte);
            }
        }
    }

    /// Push as many of `bytes` as fit into the pipe `handle` belongs to,
    /// waking its readers. Never waits.
    #[cfg(target_os = "linux")]
    pub(crate) fn pipe_put(handle: u64, bytes: &[u8]) -> usize {
        let Some(channel) = splice_pipe(handle) else {
            return 0;
        };
        let mut state = lock_state();
        let written = match state
            .net
            .pipe_channels
            .get_mut(&channel)
            .map(|ch| ch.try_write(bytes))
        {
            Some(PipeWrite::Wrote(count)) => count,
            _ => 0,
        };
        let waiters = drain_channel_recv_waiters(&mut state, channel);
        drop(state);
        wake_all(waiters);
        written
    }

    /// `splice` between two pipes (`consume`) or `tee` (`!consume`): wait for
    /// input and for room, then move — or copy — up to `len` bytes in one step.
    /// `Ok(0)` when the input is empty with no writer left.
    #[cfg(target_os = "linux")]
    pub(crate) fn pipe_to_pipe(
        input: u64,
        output: u64,
        len: usize,
        nonblocking: bool,
        consume: bool,
    ) -> Result<usize, c_int> {
        sched_point()?;
        let (Some(from), Some(to)) = (splice_pipe(input), splice_pipe(output)) else {
            return Err(super::EINVAL);
        };
        if !pipe_await(&[PipeWant::Data(from), PipeWant::Space(to)], nonblocking)? {
            return Ok(0);
        }
        let mut state = lock_state();
        let available = state
            .net
            .pipe_channels
            .get(&from)
            .map_or(0, |ch| ch.buffer.len());
        let room = state
            .net
            .pipe_channels
            .get(&to)
            .map_or(0, |ch| ch.capacity.saturating_sub(ch.buffer.len()));
        let count = len.min(available).min(room);
        let bytes: Vec<u8> = match state.net.pipe_channels.get_mut(&from) {
            Some(ch) if consume => {
                #[cfg(target_os = "linux")]
                {
                    ch.write_events = ch.write_events.wrapping_add(1);
                }
                ch.buffer.drain(..count).collect()
            }
            Some(ch) => ch.buffer.iter().take(count).copied().collect(),
            None => Vec::new(),
        };
        if let Some(ch) = state.net.pipe_channels.get_mut(&to) {
            ch.try_write(&bytes);
        }
        let mut waiters = drain_channel_recv_waiters(&mut state, to);
        if consume {
            waiters.extend(drain_channel_send_waiters(&mut state, from));
        }
        drop(state);
        wake_all(waiters);
        Ok(count)
    }

    /// Free a pipe endpoint whose description's last reference went
    /// (the universal `patina_close` path). A channel SIDE closes — waking the
    /// peer with EPIPE (readers gone) or EOF (writers gone) — only on the LAST
    /// endpoint of that side; a dup'd number never reaches here until it is the
    /// last one.
    pub(crate) fn pipe_close(handle: u64) -> Result<(), c_int> {
        pipe_close_locked(handle)
    }

    fn pipe_close_locked(handle: u64) -> Result<(), c_int> {
        let fd = handle as c_int;
        let mut state = lock_state();
        let Some(end) = state.net.pipe_ends.remove(&fd) else {
            return Err(super::EBADF);
        };
        if let Some(ino) = end.inode {
            if let Some(inode) = state.net.pipe_inodes.get_mut(&ino) {
                inode.ends -= 1;
                if inode.ends == 0 {
                    state.net.pipe_inodes.remove(&ino);
                }
            }
        }
        let mut waiters = Vec::new();
        let mut released_ino = None;
        // Dropping a READER reference: writers get EPIPE only once the last one
        // goes, and only then are blocked writers woken to observe it.
        if let Some(channel) = end.read_channel {
            if let Some(channel) = state.net.pipe_channels.get_mut(&channel) {
                channel.read_refs -= 1;
                if channel.read_refs == 0 {
                    #[cfg(target_os = "linux")]
                    {
                        channel.write_events = channel.write_events.wrapping_add(1);
                    }
                    waiters.extend(channel.send_waiters.drain(..));
                }
            }
        }
        // Dropping a WRITER reference: readers see EOF (once drained) only after
        // the last writer closes, and only then are blocked readers woken.
        if let Some(channel) = end.write_channel {
            if let Some(channel) = state.net.pipe_channels.get_mut(&channel) {
                channel.write_refs -= 1;
                if channel.write_refs == 0 {
                    #[cfg(target_os = "linux")]
                    {
                        channel.read_events = channel.read_events.wrapping_add(1);
                    }
                    waiters.extend(channel.recv_waiters.drain(..));
                }
            }
        }
        // Reclaim any channel with no references left on either side. Channel ids
        // come from a monotonic counter and are never reused, so no stale entry
        // can survive.
        for channel in [end.read_channel, end.write_channel].into_iter().flatten() {
            let drained = state
                .net
                .pipe_channels
                .get(&channel)
                .is_some_and(|channel| channel.read_refs == 0 && channel.write_refs == 0);
            if drained {
                let reclaimed = state.net.pipe_channels.remove(&channel);
                // A FIFO channel is the pipe BEHIND a name, not the name: with
                // its last fd gone the buffered bytes go too, and the next
                // `open` of the same FIFO mints a fresh empty channel. Exactly
                // what a kernel does when a pipe's last reference drops.
                if let Some(ino) = reclaimed.and_then(|channel| channel.fifo_ino) {
                    state.net.fifo_channels.remove(&ino);
                    released_ino = Some(ino);
                }
            }
        }
        drop(state);
        // The last endpoint on a FIFO's channel drops the node's reference; if
        // its last name went first, that is where the node is finally freed.
        if let Some(ino) = released_ino {
            if let Err(errno) = super::with_context(|context| context.fs_release_inode(ino)) {
                wake_all(waiters);
                return Err(errno);
            }
        }
        wake_all(waiters);
        Ok(())
    }

    /// The largest pipe buffer an unprivileged `F_SETPIPE_SZ` may ask for
    /// (`fs.pipe-max-size`).
    const PIPE_MAX_SIZE: usize = crate::registry::KERNEL_CONFIG.pipe_max_size as usize;
    const PIPE_PAGE: usize = 4096;

    /// The channel a pipe endpoint's `F_GETPIPE_SZ`/`F_SETPIPE_SZ` act on: the
    /// pipe's one channel.
    fn pipe_size_channel(state: &ThreadRuntime, fd: c_int) -> Option<u64> {
        let end = state.net.pipe_ends.get(&fd)?;
        end.write_channel.or(end.read_channel)
    }

    /// `fcntl(F_GETPIPE_SZ)`: the endpoint's buffer capacity; `EINVAL` for a
    /// description that is not a pipe end.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_pipe_size(guest_fd: c_int) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        let end = match class_entry(guest_fd) {
            Ok(resolved) if resolved.kind == FdKind::Pipe => resolved.handle as c_int,
            Ok(_) => return super::fail(EINVAL),
            Err(errno) => return super::fail(errno),
        };
        let state = lock_state();
        let capacity = pipe_size_channel(&state, end)
            .and_then(|channel| state.net.pipe_channels.get(&channel))
            .map(|channel| channel.capacity);
        match capacity {
            Some(capacity) => {
                super::set_errno(0);
                c_int::try_from(capacity).unwrap_or_else(|_| super::fail(super::EOVERFLOW))
            }
            None => super::fail(super::EBADF),
        }
    }

    /// `fcntl(F_SETPIPE_SZ)`: resize the buffer the way `fs/pipe.c:round_pipe_size`
    /// does — at least one page, rounded up to a power of two, at most the
    /// unprivileged maximum (`EPERM` above it) — and refuse (`EBUSY`) to shrink
    /// below the bytes currently buffered. Returns the new capacity.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_pipe_set_size(guest_fd: c_int, size: c_int) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        let end = match class_entry(guest_fd) {
            Ok(resolved) if resolved.kind == FdKind::Pipe => resolved.handle as c_int,
            Ok(_) => return super::fail(EINVAL),
            Err(errno) => return super::fail(errno),
        };
        let Ok(requested) = usize::try_from(size) else {
            return super::fail(EINVAL);
        };
        if requested == 0 {
            return super::fail(EINVAL);
        }
        let rounded = requested.max(PIPE_PAGE).next_power_of_two();
        if rounded > PIPE_MAX_SIZE {
            return super::fail(EPERM);
        }
        let mut state = lock_state();
        let Some(channel) = pipe_size_channel(&state, end)
            .and_then(|channel| state.net.pipe_channels.get_mut(&channel))
        else {
            return super::fail(super::EBADF);
        };
        if channel.buffer.len() > rounded {
            return super::fail(EBUSY);
        }
        channel.capacity = rounded;
        super::set_errno(0);
        c_int::try_from(rounded).unwrap_or_else(|_| super::fail(super::EOVERFLOW))
    }

    // ------------------------------------------------------------------
    // eventfd (Linux). A deterministic in-process model of the kernel's 64-bit
    // event counter — mio's `Waker` vehicle on Linux, the EVFILT_USER analogue.
    // The counter is keyed by class handle; the descriptor table maps the guest
    // number onto it and the universal read/write/close route here by kind.
    // Like the pipe channels, the counter is
    // deterministic given the recorded schedule and carries NO trace events;
    // only the scheduler parks/wakes are recorded.

    /// A virtual eventfd: the counter, its creation-flag semantics, and the
    /// tasks parked on readability (blocking reads of a zero counter, and
    /// `epoll_wait` callers watching it through the shared fan-in core).
    #[cfg(target_os = "linux")]
    struct EventFd {
        value: u64,
        /// EFD_SEMAPHORE: reads return 1 and decrement, instead of
        /// return-and-reset.
        semaphore: bool,
        /// Arrival sequence, bumped once per value-adding write so the epoll
        /// EPOLLET latch re-fires per wake even when the counter never drains —
        /// mio's `Waker` writes without reading back, relying on the kernel's
        /// per-arrival edge semantics.
        write_events: u64,
        read_waiters: VecDeque<TaskId>,
    }

    /// eventfd(2) / eventfd2. Syscall-shaped (`eventfd2(initval, flags)`) so a
    /// future syscall-user-dispatch SIGSYS dispatcher can call it with raw
    /// register arguments; the C interposer is thin marshaling over this.
    /// EFD_CLOEXEC is accepted as a no-op (no exec under the runtime); unknown
    /// flags are `EINVAL`. Activates the thread subsystem so a later blocking
    /// read or epoll park can reach the baton.
    #[cfg(target_os = "linux")]
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_eventfd(initval: u32, flags: c_int) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        const EFD_SEMAPHORE: c_int = 0o1;
        const EFD_CLOEXEC: c_int = 0o2000000;
        const EFD_NONBLOCK: c_int = 0o4000;
        if flags & !(EFD_SEMAPHORE | EFD_CLOEXEC | EFD_NONBLOCK) != 0 {
            return super::fail(EINVAL);
        }
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return super::fail(error.into_posix());
        }
        let handle = next_handle(&mut state);
        state.net.eventfds.insert(
            handle,
            EventFd {
                value: u64::from(initval),
                semaphore: flags & EFD_SEMAPHORE != 0,
                write_events: 0,
                read_waiters: VecDeque::new(),
            },
        );
        let nonblock = if flags & EFD_NONBLOCK != 0 {
            O_NONBLOCK
        } else {
            0
        };
        match super::install_fd(
            FdKind::EventFd,
            handle as u64,
            O_READ | O_WRITE | nonblock,
            flags & EFD_CLOEXEC != 0,
        ) {
            Ok(fd) => {
                super::set_errno(0);
                fd
            }
            Err(errno) => {
                state.net.eventfds.remove(&handle);
                super::fail(errno)
            }
        }
    }

    /// Read a virtual eventfd: 8 bytes, returns-and-resets the counter (or
    /// returns 1 and decrements under EFD_SEMAPHORE). A zero counter is
    /// `EWOULDBLOCK` under `O_NONBLOCK`, otherwise the caller parks until a
    /// write arrives.
    ///
    /// # Safety
    /// `buf` must be writable for `len` bytes.
    #[cfg(target_os = "linux")]
    pub(crate) unsafe fn eventfd_read(
        handle: u64,
        nonblocking: bool,
        buf: *mut c_void,
        len: usize,
    ) -> isize {
        let fd = handle as c_int;
        if let Err(errno) = sched_point() {
            return super::fail(errno) as isize;
        }
        if buf.is_null() || len < 8 {
            return super::fail(EINVAL) as isize;
        }
        let me = current_task();
        loop {
            let mut state = lock_state();
            let Some(efd) = state.net.eventfds.get_mut(&fd) else {
                return super::fail(super::EBADF) as isize;
            };
            if efd.value != 0 {
                let taken = if efd.semaphore {
                    efd.value -= 1;
                    1u64
                } else {
                    std::mem::replace(&mut efd.value, 0)
                };
                // SAFETY: `buf` is writable for >= 8 bytes per this function's
                // contract (checked above).
                unsafe {
                    buf.cast::<u8>()
                        .copy_from_nonoverlapping(taken.to_ne_bytes().as_ptr(), 8)
                };
                return 8;
            }
            if nonblocking {
                return super::fail(EWOULDBLOCK) as isize;
            }
            efd.read_waiters.push_back(me);
            let step = state.block(
                me,
                "eventfd-read",
                Wait::new(BlockClass::Io, vec![WaiterLoc::EventFdRecv(fd)]),
            );
            match step {
                Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                Ok(Step::Continue) => drop(state),
                Err(error) => return super::fail(error.into_posix()) as isize,
            }
            lock_state().timed_out.remove(&me);
            #[cfg(target_os = "linux")]
            if signals::resume() == signals::Resumed::Eintr {
                return super::fail(super::EINTR) as isize;
            }
        }
    }

    /// Write a virtual eventfd: 8 bytes adding to the counter, waking parked
    /// readers and epoll watchers. The kernel parks a writer whose addition
    /// would exceed `u64::MAX - 1`; no supported caller writes near the bound
    /// (mio's `Waker` adds 1 per wake), so that fails closed loudly instead of
    /// modeling a blocked-writer queue.
    ///
    /// # Safety
    /// `buf` must be readable for `len` bytes.
    #[cfg(target_os = "linux")]
    pub(crate) unsafe fn eventfd_write(handle: u64, buf: *const c_void, len: usize) -> isize {
        let fd = handle as c_int;
        if let Err(errno) = sched_point() {
            return super::fail(errno) as isize;
        }
        if buf.is_null() || len < 8 {
            return super::fail(EINVAL) as isize;
        }
        let mut add = [0u8; 8];
        // SAFETY: `buf` is readable for >= 8 bytes per this function's contract.
        unsafe {
            add.as_mut_ptr()
                .copy_from_nonoverlapping(buf.cast::<u8>(), 8)
        };
        let add = u64::from_ne_bytes(add);
        if add == u64::MAX {
            return super::fail(EINVAL) as isize;
        }
        let mut state = lock_state();
        let Some(efd) = state.net.eventfds.get_mut(&fd) else {
            return super::fail(super::EBADF) as isize;
        };
        let Some(sum) = efd.value.checked_add(add).filter(|sum| *sum < u64::MAX) else {
            fatal(&format!(
                "eventfd write overflows the counter ({} + {add}): blocking eventfd \
                 writers are not modeled; failing closed",
                efd.value
            ));
        };
        if add == 0 {
            // Adding zero changes no readiness; the kernel reports success
            // without waking anyone.
            return 8;
        }
        efd.value = sum;
        efd.write_events = efd.write_events.wrapping_add(1);
        let waiters: Vec<TaskId> = efd.read_waiters.drain(..).collect();
        drop(state);
        wake_all(waiters);
        8
    }

    /// Free an eventfd whose description's last reference went, waking any
    /// parked readers (they observe EBADF — loud, deterministic — rather than
    /// parking forever on a dead counter).
    #[cfg(target_os = "linux")]
    pub(crate) fn eventfd_close(handle: u64) {
        let mut state = lock_state();
        let Some(efd) = state.net.eventfds.remove(&(handle as c_int)) else {
            return;
        };
        let waiters: Vec<TaskId> = efd.read_waiters.into_iter().collect();
        drop(state);
        wake_all(waiters);
    }

    // ------------------------------------------------------------------
    // kqueue / kevent readiness reactor (macOS). A deterministic in-process
    // model of the BSD readiness multiplexer that mio (and therefore tokio)
    // builds its IO driver on. A `kqueue` is a description in the descriptor
    // table; `kevent`/`kevent64` register EVFILT_READ/WRITE interest over the
    // virtual pipe and socket fds, an EVFILT_USER self-wakeup
    // (mio's `Waker`), and EVFILT_TIMER against the virtual clock, then gather
    // ready events — parking on the scheduler baton with multi-fd fan-in when
    // nothing is ready. Readiness for a pipe fd is pure in-shim channel state;
    // readiness for a SimNet socket fd is the runtime's UNRECORDED
    // `net_readiness` (a deterministic function of the recorded send/recv history
    // and the virtual clock). Like the mutex words and the pipe channels, the
    // registry itself is deterministic GIVEN the recorded schedule, so it carries
    // NO trace events of its own; only the scheduler parks/wakes are recorded.
    //
    // Event delivery is edge-triggered (mio always registers with EV_CLEAR): a
    // READ/WRITE knote fires on the not-ready -> ready transition and re-arms once
    // readiness drops, so a level condition (e.g. a peer-closed EV_EOF that stays
    // set) fires exactly once rather than busy-looping the reactor. Returned
    // events are ordered by `(ident, filter)` — the `BTreeMap` key order — so the
    // gathered slice is a pure function of the registry and the schedule.
    /// The C-facing kqueue event, matching `struct patina_kevent` in the header
    /// (a platform-neutral projection of the macOS `struct kevent` the C layer
    /// marshals to and from). Field order and padding match the header exactly.
    #[cfg(target_os = "macos")]
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(crate) struct PatinaKevent {
        ident: u64,
        filter: i16,
        flags: u16,
        fflags: u32,
        data: i64,
        udata: usize,
    }

    /// A descriptor's kernel poll mask (`EPOLL*` bits, [`net::abi`]'s
    /// `POLL*`) and its per-direction arrival sequences, for the readiness
    /// reactors: what the object's poll function answers now, computed
    /// without consuming anything or recording a boundary op. `desc`, when
    /// given, is the description an interest was registered against, which is
    /// what is polled even if the number now names another one (the kernel's
    /// `(fd, struct file)` interest key). `None` for a number that names
    /// nothing.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn fd_poll(
        state: &ThreadRuntime,
        fd: c_int,
        desc: Option<DescId>,
    ) -> Option<(u32, (u64, u64))> {
        let (kind, handle) = match desc {
            Some(desc) => {
                let table = super::fd_table().lock();
                let description = table.description(desc)?;
                (description.kind, description.handle)
            }
            None => {
                let resolved = super::fd_table().lock().resolve(fd)?;
                (resolved.kind, resolved.handle)
            }
        };
        Some(poll_description(state, kind, handle))
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn poll_description(state: &ThreadRuntime, kind: FdKind, handle: u64) -> (u32, (u64, u64)) {
        use net::abi::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
        match kind {
            FdKind::Pipe => pipe_poll(state, handle as c_int),
            FdKind::Socket => {
                net::socket_poll(state, handle).unwrap_or((POLLERR | POLLHUP, (0, 0)))
            }
            #[cfg(target_os = "linux")]
            FdKind::SignalFd => {
                let readable = signals::fd::readable(state, handle, current_task());
                let arrivals = state
                    .signals
                    .signalfds
                    .get(&handle)
                    .map_or(0, |fd| fd.arrivals);
                (
                    if readable { POLLIN | POLLRDNORM } else { 0 },
                    (arrivals, 0),
                )
            }
            // `eventfd_poll`: readable while the count is nonzero; a write
            // that would overflow fails closed instead of parking, so it is
            // always writable.
            #[cfg(target_os = "linux")]
            FdKind::EventFd => state.net.eventfds.get(&(handle as c_int)).map_or(
                (POLLERR | POLLHUP, (0, 0)),
                |efd| {
                    let readable = if efd.value > 0 {
                        POLLIN | POLLRDNORM
                    } else {
                        0
                    };
                    (readable | POLLOUT | POLLWRNORM, (efd.write_events, 0))
                },
            ),
            // Standard input is at end of file.
            FdKind::Stdin => (POLLIN | POLLRDNORM | POLLHUP, (0, 0)),
            // The captured streams always accept bytes.
            FdKind::Stdout | FdKind::Stderr => (POLLOUT | POLLWRNORM, (0, 0)),
            // `DEFAULT_POLLMASK`: files and devices are always ready (and
            // cannot be registered with epoll at all: `EPERM` at
            // `epoll_ctl`).
            FdKind::File | FdKind::Dir | FdKind::OPath | FdKind::Urandom => {
                (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM, (0, 0))
            }
            // `timerfd_poll`: readable while an expiration is unread; every
            // firing is an arrival.
            #[cfg(target_os = "linux")]
            FdKind::TimerFd => {
                let (readable, fires) = timers::timerfd_poll(state, handle);
                (if readable { POLLIN | POLLRDNORM } else { 0 }, (fires, 0))
            }
            #[cfg(target_os = "linux")]
            FdKind::Epoll => (0, (0, 0)),
            #[cfg(target_os = "linux")]
            FdKind::MessageQueue => {
                let (readable, writable) = ipc::mq_readiness(state, handle);
                let mut mask = 0;
                if readable {
                    mask |= POLLIN | POLLRDNORM;
                }
                if writable {
                    mask |= POLLOUT | POLLWRNORM;
                }
                (mask, ipc::mq_event_seqs(state, handle))
            }
            #[cfg(target_os = "macos")]
            FdKind::Kqueue => (0, (0, 0)),
        }
    }

    /// `pipe_poll`: the read side is readable while bytes are queued and hung
    /// up once no writer is left; the write side is writable while there is
    /// room and in error once no reader is left.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn pipe_poll(state: &ThreadRuntime, fd: c_int) -> (u32, (u64, u64)) {
        use net::abi::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
        let Some(end) = state.net.pipe_ends.get(&fd) else {
            return (POLLERR | POLLHUP, (0, 0));
        };
        let read = end
            .read_channel
            .and_then(|id| state.net.pipe_channels.get(&id));
        let write = end
            .write_channel
            .and_then(|id| state.net.pipe_channels.get(&id));
        let mut mask = 0;
        if let Some(channel) = read {
            if !channel.buffer.is_empty() {
                mask |= POLLIN | POLLRDNORM;
            }
            if channel.write_closed() {
                mask |= POLLHUP;
            }
        }
        if let Some(channel) = write {
            if channel.buffer.len() < channel.capacity {
                mask |= POLLOUT | POLLWRNORM;
            }
            if channel.read_closed() {
                mask |= POLLERR;
            }
        }
        #[cfg(target_os = "linux")]
        let seqs = (
            read.map_or(0, |channel| channel.read_events),
            write.map_or(0, |channel| channel.write_events),
        );
        #[cfg(target_os = "macos")]
        let seqs = (0, 0);
        (mask, seqs)
    }

    /// A readiness direction to watch on a virtual descriptor. Deliberately
    /// reactor-neutral (not an `EVFILT_*`/`EPOLL*` value): the OS-agnostic fan-in
    /// core below is shared by the kqueue (macOS) and epoll (Linux) frontends.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ReadyDir {
        Read,
        Write,
    }

    /// Where a task parked on a readiness fan-in enqueued itself, so it can be
    /// unlinked on resume regardless of which source woke it. Reactor-neutral: a
    /// kqueue or epoll frontend both watch the same virtual pipe/socket queues.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[derive(Clone, Copy)]
    enum WaiterLoc {
        PipeOpen(u64),
        Futex(usize),
        Mutex(usize),
        RwRead(usize),
        RwWrite(usize),
        Cond(usize, usize),
        Join(TaskId),
        PipeRecv(u64),
        PipeSend(u64),
        SockRecv(c_int),
        SockSend(c_int),
        /// Linux: parked on an eventfd's readable queue (an eventfd is always
        /// writable, so there is no write-direction queue).
        #[cfg(target_os = "linux")]
        EventFdRecv(c_int),
        #[cfg(target_os = "linux")]
        SignalFdRecv(u64),
        /// Linux: parked on a System V IPC object's wait queue.
        #[cfg(target_os = "linux")]
        Ipc(ipc::IpcWait),
        /// Linux: parked on a timer descriptor's readers.
        #[cfg(target_os = "linux")]
        TimerFdRecv(u64),
    }

    /// Register `me` on the waiter queue of every watched `(direction, fd)`
    /// source, returning the locations to unlink on resume. This is the reusable
    /// multi-fd fan-in primitive a readiness reactor parks on: the frontend
    /// supplies the watched set (guest numbers) from its OWN registry, so no
    /// reactor-specific keying (kqueue `(ident, filter)`, epoll interest masks)
    /// leaks into the shared core. The readiness sources — pipe channels and
    /// SimNet socket queues — and the readiness predicate [`fd_readiness`] are
    /// equally neutral. A number that names nothing waitable (closed, or a
    /// kind that is always ready) registers no waiter: its readiness is
    /// already decided.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn register_readiness_waiters(
        state: &mut ThreadRuntime,
        me: TaskId,
        watched: &[(ReadyDir, c_int)],
    ) -> Vec<WaiterLoc> {
        let mut locs = Vec::new();
        for &(dir, guest_fd) in watched {
            let Some(resolved) = super::fd_table().lock().resolve(guest_fd) else {
                continue;
            };
            let fd = resolved.handle as c_int;
            // Eventfd (Linux): only the readable direction has a queue; a write
            // watch needs no waiter because an eventfd is always writable.
            #[cfg(target_os = "linux")]
            if resolved.kind == FdKind::SignalFd {
                if dir == ReadyDir::Read {
                    if let Some(fd) = state.signals.signalfds.get_mut(&resolved.handle) {
                        fd.waiters.push_back(me);
                        locs.push(WaiterLoc::SignalFdRecv(resolved.handle));
                    }
                }
                continue;
            }
            #[cfg(target_os = "linux")]
            if resolved.kind == FdKind::MessageQueue {
                if let Some(loc) = ipc::mq_watch(state, resolved.handle, me, dir == ReadyDir::Read)
                {
                    locs.push(loc);
                }
                continue;
            }
            #[cfg(target_os = "linux")]
            if resolved.kind == FdKind::TimerFd {
                if dir == ReadyDir::Read {
                    locs.extend(timers::timerfd_watch(state, resolved.handle, me));
                }
                continue;
            }
            #[cfg(target_os = "linux")]
            if resolved.kind == FdKind::EventFd {
                if dir == ReadyDir::Read {
                    if let Some(efd) = state.net.eventfds.get_mut(&fd) {
                        efd.read_waiters.push_back(me);
                        locs.push(WaiterLoc::EventFdRecv(fd));
                    }
                }
                continue;
            }
            if resolved.kind == FdKind::Pipe {
                let Some(end) = state.net.pipe_ends.get(&fd) else {
                    continue;
                };
                let channel = match dir {
                    ReadyDir::Read => end.read_channel,
                    ReadyDir::Write => end.write_channel,
                };
                if let Some(channel) = channel {
                    if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
                        match dir {
                            ReadyDir::Read => {
                                ch.recv_waiters.push_back(me);
                                locs.push(WaiterLoc::PipeRecv(channel));
                            }
                            ReadyDir::Write => {
                                ch.send_waiters.push_back(me);
                                locs.push(WaiterLoc::PipeSend(channel));
                            }
                        }
                    }
                }
            } else if resolved.kind == FdKind::Socket {
                let Some(socket) = state.net.sockets.table.get_mut(&fd) else {
                    continue;
                };
                match dir {
                    ReadyDir::Read => {
                        socket.recv_waiters.push_back(me);
                        locs.push(WaiterLoc::SockRecv(fd));
                    }
                    ReadyDir::Write => {
                        socket.send_waiters.push_back(me);
                        locs.push(WaiterLoc::SockSend(fd));
                    }
                }
            }
        }
        locs
    }

    /// Unlink `me` from every queue [`register_readiness_waiters`] enqueued it on,
    /// so a later wake of that queue never targets an already-resumed task.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn unregister_waiters(state: &mut ThreadRuntime, me: TaskId, locs: &[WaiterLoc]) {
        let remove = |queue: &mut VecDeque<TaskId>| {
            if let Some(index) = queue.iter().position(|task| *task == me) {
                queue.remove(index);
            }
        };
        for loc in locs {
            match *loc {
                WaiterLoc::PipeOpen(channel) => {
                    if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
                        remove(&mut ch.open_waiters);
                    }
                }
                WaiterLoc::Futex(address) => {
                    if let Some(queue) = state.futexes.get_mut(&address) {
                        remove(queue);
                    }
                }
                WaiterLoc::Mutex(key) => {
                    if let Some(entry) = state.table.mutexes.get_mut(&key) {
                        if let Some(index) = entry.waiters.iter().position(|task| *task == me) {
                            entry.waiters.remove(index);
                        }
                    }
                }
                WaiterLoc::RwRead(key) | WaiterLoc::RwWrite(key) => {
                    if let Some(entry) = state.table.rwlocks.get_mut(&key) {
                        let queue = if matches!(loc, WaiterLoc::RwRead(_)) {
                            &mut entry.read_waiters
                        } else {
                            &mut entry.write_waiters
                        };
                        if let Some(index) = queue.iter().position(|task| *task == me) {
                            queue.remove(index);
                        }
                    }
                }
                WaiterLoc::Cond(cond, mutex) => {
                    if let Some(entry) = state.table.conds.get_mut(&cond) {
                        if let Some(index) = entry.waiters.iter().position(|(task, _)| *task == me)
                        {
                            entry.waiters.remove(index);
                        }
                    }
                    unregister_waiters(state, me, &[WaiterLoc::Mutex(mutex)]);
                }
                WaiterLoc::Join(target) => {
                    if let Some(entry) = state.table.threads.get_mut(&target) {
                        if entry.joiner == Some(me) {
                            entry.joiner = None;
                        }
                    }
                }
                WaiterLoc::PipeRecv(channel) => {
                    if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
                        remove(&mut ch.recv_waiters);
                    }
                }
                WaiterLoc::PipeSend(channel) => {
                    if let Some(ch) = state.net.pipe_channels.get_mut(&channel) {
                        remove(&mut ch.send_waiters);
                    }
                }
                WaiterLoc::SockRecv(fd) => {
                    if let Some(socket) = state.net.sockets.table.get_mut(&fd) {
                        remove(&mut socket.recv_waiters);
                    }
                }
                WaiterLoc::SockSend(fd) => {
                    if let Some(socket) = state.net.sockets.table.get_mut(&fd) {
                        remove(&mut socket.send_waiters);
                    }
                }
                #[cfg(target_os = "linux")]
                WaiterLoc::SignalFdRecv(handle) => {
                    if let Some(fd) = state.signals.signalfds.get_mut(&handle) {
                        remove(&mut fd.waiters);
                    }
                }
                #[cfg(target_os = "linux")]
                WaiterLoc::EventFdRecv(fd) => {
                    if let Some(efd) = state.net.eventfds.get_mut(&fd) {
                        remove(&mut efd.read_waiters);
                    }
                }
                #[cfg(target_os = "linux")]
                WaiterLoc::Ipc(wait) => state.ipc.unwait(wait, me),
                #[cfg(target_os = "linux")]
                WaiterLoc::TimerFdRecv(handle) => timers::timerfd_unwatch(state, handle, me),
            }
        }
    }

    #[cfg(target_os = "macos")]
    use kqueue::KqueueSlot;
    #[cfg(target_os = "macos")]
    pub(crate) use kqueue::{kqueue_close, kqueue_forget_number};

    #[cfg(target_os = "macos")]
    mod kqueue {
        use std::collections::{BTreeMap, VecDeque};
        use std::ffi::{c_int, c_void};

        use patina_dst_abi::ClockKind;

        use super::{
            BlockClass, FdKind, O_READ, O_WRITE, PatinaKevent, ReadyDir, Step, TaskId,
            ThreadRuntime, Wait, current_task, fatal, fd_poll, lock_state,
            register_readiness_waiters, sched_point, switch_and_park, unregister_waiters, wake_all,
            with_context_raw,
        };
        use crate::thread::net::abi::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP};

        // macOS <sys/event.h> filter identifiers (the reactor is macOS-only).
        pub(super) const EVFILT_READ: i16 = -1;
        pub(super) const EVFILT_WRITE: i16 = -2;
        pub(super) const EVFILT_TIMER: i16 = -7;
        pub(super) const EVFILT_USER: i16 = -10;

        // <sys/event.h> flags (the u16 `flags` field). EV_RECEIPT/EV_ERROR are
        // handled entirely in the C marshalling layer.
        const EV_ADD: u16 = 0x0001;
        const EV_DELETE: u16 = 0x0002;
        const EV_ENABLE: u16 = 0x0004;
        const EV_DISABLE: u16 = 0x0008;
        const EV_ONESHOT: u16 = 0x0010;
        pub(super) const EV_EOF: u16 = 0x8000;

        // EVFILT_USER / EVFILT_TIMER fflags.
        const NOTE_TRIGGER: u32 = 0x0100_0000;
        const NOTE_SECONDS: u32 = 0x0000_0001;
        const NOTE_USECONDS: u32 = 0x0000_0002;
        const NOTE_NSECONDS: u32 = 0x0000_0004;
        const NOTE_ABSOLUTE: u32 = 0x0000_0008;

        // Gather blocking modes handed down from the C `timeout` argument.
        const MODE_POLL: c_int = 0; // zero timespec: non-blocking poll
        const MODE_FOREVER: c_int = 1; // NULL timeout: block until ready
        const MODE_TIMEOUT: c_int = 2; // non-zero timespec: relative deadline

        /// One registered `(ident, filter)` knote.
        pub(super) struct KFilterState {
            udata: usize,
            enabled: bool,
            oneshot: bool,
            /// EVFILT_USER: pending NOTE_TRIGGER, cleared on delivery (edge).
            user_triggered: bool,
            /// EVFILT_TIMER: next fire time in absolute virtual nanoseconds.
            timer_deadline: u64,
            /// EVFILT_TIMER: repeat interval in nanoseconds; 0 = one-shot.
            timer_interval: u64,
            /// EVFILT_READ/WRITE edge latch: readiness already delivered, awaiting
            /// a not-ready observation before it may fire again (models EV_CLEAR).
            delivered: bool,
        }

        /// A registered knote sorts by `(ident, filter)`, giving deterministic
        /// gather order straight from the `BTreeMap`.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub(super) struct FilterKey {
            ident: u64,
            filter: i16,
        }

        /// A virtual kqueue: its registered knotes plus the tasks parked in
        /// `kevent` on it (woken by an EVFILT_USER NOTE_TRIGGER from any thread).
        #[derive(Default)]
        struct Kqueue {
            filters: BTreeMap<FilterKey, KFilterState>,
            waiters: VecDeque<TaskId>,
        }

        /// A kqueue registry. The descriptor table refcounts the description
        /// (one per `kqueue()`, shared by every `dup`/`F_DUPFD` of it) and frees
        /// the registry through [`kqueue_close`] when the last number closes.
        pub(super) struct KqueueSlot {
            kq: Kqueue,
        }

        /// Resolve a guest number to its kqueue registry id, or `None` if it is
        /// not a live kqueue descriptor.
        fn kq_id(_state: &ThreadRuntime, fd: c_int) -> Option<u64> {
            match super::super::fd_table().lock().resolve(fd) {
                Some(resolved) if resolved.kind == FdKind::Kqueue => Some(resolved.handle),
                _ => None,
            }
        }

        fn fatal_filter(filter: i16, fd: c_int, direction: &str) -> ! {
            fatal(&format!(
                "kevent EVFILT_{direction} registered on non-virtual descriptor {fd} \
                 (filter {filter}): readiness for real host descriptors is not modeled; \
                 failing closed"
            ));
        }

        /// Allocate a virtual kqueue. Activates the thread subsystem so a later
        /// blocking `kevent` gather can park through the baton.
        ///
        /// # Safety
        /// C ABI entry point.
        #[unsafe(no_mangle)]
        pub extern "C" fn patina_kqueue() -> c_int {
            let _panic_scope = crate::panic_boundary::PanicScope::enter();
            let mut state = lock_state();
            if let Err(error) = state.ensure_active() {
                return super::super::fail(error.into_posix());
            }
            let id = state.net.next_kq;
            state.net.next_kq = state.net.next_kq.wrapping_add(1);
            state.net.kqueues.insert(
                id,
                KqueueSlot {
                    kq: Kqueue::default(),
                },
            );
            // A kqueue descriptor is close-on-exec from birth (xnu sets
            // FD_CLOEXEC on it) and reports O_RDWR.
            match super::super::install_fd(FdKind::Kqueue, id, O_READ | O_WRITE, true) {
                Ok(fd) => {
                    super::super::set_errno(0);
                    fd
                }
                Err(errno) => {
                    state.net.kqueues.remove(&id);
                    super::super::fail(errno)
                }
            }
        }

        /// Free a kqueue registry whose description's last reference went,
        /// waking any task parked in `kevent` on it.
        pub(crate) fn kqueue_close(handle: u64) {
            let mut state = lock_state();
            let Some(slot) = state.net.kqueues.remove(&handle) else {
                return;
            };
            let waiters: Vec<TaskId> = slot.kq.waiters.into_iter().collect();
            drop(state);
            wake_all(waiters);
        }

        /// BSD drops the knotes registered on a NUMBER when that number closes
        /// (`knote_fdclose`), whatever other references the file keeps — so a
        /// reused number can never observe a stale knote.
        pub(crate) fn kqueue_forget_number(fd: c_int) {
            let ident = fd as u64;
            let mut state = lock_state();
            for slot in state.net.kqueues.values_mut() {
                slot.kq.filters.retain(|key, _| {
                    !(key.ident == ident && matches!(key.filter, EVFILT_READ | EVFILT_WRITE))
                });
            }
        }

        /// Apply one changelist entry to a kqueue. Returns 0 on success or a
        /// positive errno the C layer places in an EV_ERROR receipt. Registry
        /// mutation only — no scheduling point, no trace event — except an
        /// EVFILT_USER NOTE_TRIGGER, which wakes the kq's parked `kevent` callers
        /// (like a condvar signal).
        ///
        /// # Safety
        /// C ABI entry point; `ident` for EVFILT_READ/WRITE is a descriptor.
        #[unsafe(no_mangle)]
        pub extern "C" fn patina_kqueue_apply(
            kq_fd: c_int,
            ident: u64,
            filter: i16,
            flags: u16,
            fflags: u32,
            data: i64,
            udata: usize,
        ) -> c_int {
            let _panic_scope = crate::panic_boundary::PanicScope::enter();
            let me_wake: Vec<TaskId>;
            {
                let mut state = lock_state();
                let Some(id) = kq_id(&state, kq_fd) else {
                    return super::super::EBADF;
                };
                // Fail closed LOUDLY on filters the reactor does not model: a
                // silent ENOSYS/EINVAL that tokio swallowed would be an invisible
                // escape (a real host kqueue would then service them off-model).
                if !matches!(
                    filter,
                    EVFILT_READ | EVFILT_WRITE | EVFILT_USER | EVFILT_TIMER
                ) {
                    fatal(&format!(
                        "kevent filter {filter} is not modeled (only EVFILT_READ/WRITE/USER/TIMER \
                         are supported); failing closed"
                    ));
                }
                let key = FilterKey { ident, filter };

                if flags & EV_DELETE != 0 {
                    // Removal validates nothing about the fd: the descriptor may
                    // already be closed (mio deregisters around close).
                    if state
                        .net
                        .kqueues
                        .get_mut(&id)
                        .expect("kqueue was checked")
                        .kq
                        .filters
                        .remove(&key)
                        .is_none()
                    {
                        return super::super::ENOENT;
                    }
                    return 0;
                }

                if flags & EV_ADD != 0 {
                    // Registration-time fd validation: EVFILT_READ/WRITE readiness
                    // is defined only over virtual pipe and socket
                    // descriptors. A real file, stdio, or otherwise unknown
                    // descriptor fails closed loudly here.
                    if matches!(filter, EVFILT_READ | EVFILT_WRITE) {
                        let fd = c_int::try_from(ident).unwrap_or(-1);
                        let known = matches!(
                            super::super::fd_table().lock().kind(fd),
                            Some(FdKind::Pipe | FdKind::Socket)
                        );
                        if !known {
                            let direction = if filter == EVFILT_READ {
                                "READ"
                            } else {
                                "WRITE"
                            };
                            fatal_filter(filter, fd, direction);
                        }
                    }
                    let now = match with_context_raw(|c| c.monotonic_now_unrecorded()) {
                        Ok(now) => now,
                        Err(errno) => return errno,
                    };
                    let (timer_deadline, timer_interval) = if filter == EVFILT_TIMER {
                        let period = timer_nanos(data, fflags);
                        let deadline = if fflags & NOTE_ABSOLUTE != 0 {
                            data.max(0) as u64
                        } else {
                            now.saturating_add(period)
                        };
                        let interval = if flags & EV_ONESHOT != 0 { 0 } else { period };
                        (deadline, interval)
                    } else {
                        (0, 0)
                    };
                    let kq = &mut state
                        .net
                        .kqueues
                        .get_mut(&id)
                        .expect("kqueue was checked")
                        .kq;
                    let entry = kq.filters.entry(key).or_insert(KFilterState {
                        udata,
                        enabled: true,
                        oneshot: false,
                        user_triggered: false,
                        timer_deadline,
                        timer_interval,
                        delivered: false,
                    });
                    entry.udata = udata;
                    entry.enabled = flags & EV_DISABLE == 0;
                    entry.oneshot = flags & EV_ONESHOT != 0;
                    if filter == EVFILT_TIMER {
                        // Re-adding a timer restarts it from now.
                        entry.timer_deadline = timer_deadline;
                        entry.timer_interval = timer_interval;
                        entry.delivered = false;
                    }
                } else if flags & (EV_ENABLE | EV_DISABLE) != 0 {
                    let Some(entry) = state
                        .net
                        .kqueues
                        .get_mut(&id)
                        .expect("kqueue was checked")
                        .kq
                        .filters
                        .get_mut(&key)
                    else {
                        return super::super::ENOENT;
                    };
                    if flags & EV_ENABLE != 0 {
                        entry.enabled = true;
                    }
                    if flags & EV_DISABLE != 0 {
                        entry.enabled = false;
                    }
                }

                // EVFILT_USER NOTE_TRIGGER: latch the trigger and wake every task
                // parked in `kevent` on this kq. mio's `Waker::wake` sends exactly
                // this (EV_ADD | NOTE_TRIGGER) from another thread.
                if filter == EVFILT_USER && fflags & NOTE_TRIGGER != 0 {
                    let kq = &mut state
                        .net
                        .kqueues
                        .get_mut(&id)
                        .expect("kqueue was checked")
                        .kq;
                    if let Some(entry) = kq.filters.get_mut(&key) {
                        entry.user_triggered = true;
                    }
                    me_wake = kq.waiters.drain(..).collect();
                } else {
                    me_wake = Vec::new();
                }
            }
            wake_all(me_wake);
            0
        }

        /// EVFILT_TIMER period in nanoseconds from `data` and the unit fflags.
        /// The macOS default (no unit flag) is milliseconds.
        fn timer_nanos(data: i64, fflags: u32) -> u64 {
            let magnitude = data.max(0) as u64;
            if fflags & NOTE_NSECONDS != 0 {
                magnitude
            } else if fflags & NOTE_USECONDS != 0 {
                magnitude.saturating_mul(1_000)
            } else if fflags & NOTE_SECONDS != 0 {
                magnitude.saturating_mul(1_000_000_000)
            } else {
                magnitude.saturating_mul(1_000_000)
            }
        }

        /// A knote ready to deliver, plus the registry edits its delivery entails.
        struct ReadyEvent {
            event: PatinaKevent,
            key: FilterKey,
            /// Latch EV_CLEAR edge state after delivering a READ/WRITE event.
            set_delivered: bool,
            /// Clear the EVFILT_USER trigger after delivery.
            clear_user: bool,
            /// One-shot: remove the knote after delivery.
            remove: bool,
            /// EVFILT_TIMER re-arm to this absolute deadline (0 = no re-arm).
            rearm_timer: u64,
        }

        /// Scan the kq's enabled knotes at virtual time `now`, collecting the
        /// events ready to deliver (in `(ident, filter)` order) and the re-arm
        /// edits for knotes observed not-ready. `earliest_timer` returns the
        /// soonest enabled timer deadline so a blocking gather can bound its park.
        fn scan(
            state: &ThreadRuntime,
            id: u64,
            now: u64,
        ) -> (Vec<ReadyEvent>, Vec<FilterKey>, Option<u64>) {
            let kq = &state.net.kqueues.get(&id).expect("kqueue exists").kq;
            let mut ready = Vec::new();
            let mut rearm_not_ready = Vec::new();
            let mut earliest_timer = None;
            for (key, st) in &kq.filters {
                if !st.enabled {
                    continue;
                }
                match key.filter {
                    EVFILT_READ | EVFILT_WRITE => {
                        let fd = c_int::try_from(key.ident).unwrap_or(-1);
                        // The filters read the poll mask: a number that names
                        // nothing any more is ready with EOF, so the reactor
                        // wakes and the next operation surfaces the error.
                        let mask =
                            fd_poll(state, fd, None).map_or(POLLERR | POLLHUP, |(mask, _)| mask);
                        let (ready_now, eof) = if key.filter == EVFILT_READ {
                            (
                                mask & (POLLIN | POLLRDHUP | POLLHUP | POLLERR) != 0,
                                mask & (POLLRDHUP | POLLHUP) != 0,
                            )
                        } else {
                            (
                                mask & (POLLOUT | POLLHUP | POLLERR) != 0,
                                mask & (POLLHUP | POLLERR) != 0,
                            )
                        };
                        if ready_now && !st.delivered {
                            let mut flags = 0u16;
                            if eof {
                                flags |= EV_EOF;
                            }
                            ready.push(ReadyEvent {
                                event: PatinaKevent {
                                    ident: key.ident,
                                    filter: key.filter,
                                    flags,
                                    fflags: 0,
                                    data: 0,
                                    udata: st.udata,
                                },
                                key: *key,
                                set_delivered: true,
                                clear_user: false,
                                remove: st.oneshot,
                                rearm_timer: 0,
                            });
                        } else if !ready_now && st.delivered {
                            // Readiness dropped: re-arm the EV_CLEAR edge latch so
                            // the next rising edge fires again.
                            rearm_not_ready.push(*key);
                        }
                    }
                    EVFILT_USER => {
                        if st.user_triggered {
                            ready.push(ReadyEvent {
                                event: PatinaKevent {
                                    ident: key.ident,
                                    filter: key.filter,
                                    flags: 0,
                                    fflags: 0,
                                    data: 0,
                                    udata: st.udata,
                                },
                                key: *key,
                                set_delivered: false,
                                clear_user: true,
                                remove: st.oneshot,
                                rearm_timer: 0,
                            });
                        }
                    }
                    EVFILT_TIMER => {
                        if now >= st.timer_deadline {
                            let rearm = if st.oneshot || st.timer_interval == 0 {
                                0
                            } else {
                                // Advance past `now` so a long-overdue periodic
                                // timer fires once and re-arms to the future.
                                let mut next = st.timer_deadline.saturating_add(st.timer_interval);
                                while next <= now {
                                    next = next.saturating_add(st.timer_interval);
                                }
                                next
                            };
                            ready.push(ReadyEvent {
                                event: PatinaKevent {
                                    ident: key.ident,
                                    filter: key.filter,
                                    flags: 0,
                                    fflags: 0,
                                    data: 1,
                                    udata: st.udata,
                                },
                                key: *key,
                                set_delivered: false,
                                clear_user: false,
                                remove: st.oneshot || st.timer_interval == 0,
                                rearm_timer: rearm,
                            });
                        } else {
                            earliest_timer = Some(
                                earliest_timer
                                    .map_or(st.timer_deadline, |e: u64| e.min(st.timer_deadline)),
                            );
                        }
                    }
                    _ => {}
                }
            }
            (ready, rearm_not_ready, earliest_timer)
        }

        /// The enabled EVFILT_READ/WRITE knotes as reactor-neutral `(direction,
        /// fd)` pairs the shared fan-in primitive parks on, plus whether an
        /// enabled EVFILT_USER knote is present (its wakeup is the kq's own
        /// waiter list, a kqueue-specific source with no descriptor).
        fn watched_sources(state: &ThreadRuntime, id: u64) -> (Vec<(ReadyDir, c_int)>, bool) {
            let kq = &state.net.kqueues.get(&id).expect("kqueue exists").kq;
            let mut has_user = false;
            let watched = kq
                .filters
                .iter()
                .filter(|(_, st)| st.enabled)
                .filter_map(|(key, _)| match key.filter {
                    EVFILT_READ => Some((ReadyDir::Read, c_int::try_from(key.ident).unwrap_or(-1))),
                    EVFILT_WRITE => {
                        Some((ReadyDir::Write, c_int::try_from(key.ident).unwrap_or(-1)))
                    }
                    EVFILT_USER => {
                        has_user = true;
                        None
                    }
                    _ => None,
                })
                .collect();
            (watched, has_user)
        }

        /// Apply the registry edits for the events actually delivered this gather:
        /// latch EV_CLEAR edges, clear EVFILT_USER triggers, remove one-shots, and
        /// re-arm periodic timers.
        fn commit_delivered(state: &mut ThreadRuntime, id: u64, delivered: &[ReadyEvent]) {
            let kq = &mut state.net.kqueues.get_mut(&id).expect("kqueue exists").kq;
            for event in delivered {
                if event.remove {
                    kq.filters.remove(&event.key);
                    continue;
                }
                if let Some(st) = kq.filters.get_mut(&event.key) {
                    if event.set_delivered {
                        st.delivered = true;
                    }
                    if event.clear_user {
                        st.user_triggered = false;
                    }
                    if event.rearm_timer != 0 {
                        st.timer_deadline = event.rearm_timer;
                    }
                }
            }
        }

        /// Apply the readiness "not-ready" re-arms to the EV_CLEAR edge latches.
        fn commit_rearm(state: &mut ThreadRuntime, id: u64, keys: &[FilterKey]) {
            let kq = &mut state.net.kqueues.get_mut(&id).expect("kqueue exists").kq;
            for key in keys {
                if let Some(st) = kq.filters.get_mut(key) {
                    st.delivered = false;
                }
            }
        }

        /// Gather up to `nevents` ready events into `out`, blocking per `mode`.
        /// Applies the changelist beforehand from C via [`patina_kqueue_apply`];
        /// this call is only the readiness gather + deterministic park.
        ///
        /// # Safety
        /// `out` must be writable for `nevents` [`PatinaKevent`]s.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn patina_kevent_gather(
            kq_fd: c_int,
            out: *mut c_void,
            nevents: c_int,
            mode: c_int,
            timeout_nanos: u64,
        ) -> c_int {
            let _panic_scope = crate::panic_boundary::PanicScope::enter();
            if let Err(errno) = sched_point() {
                return super::super::fail(errno);
            }
            let capacity = nevents.max(0) as usize;
            let me = current_task();
            // Absolute deadline for a MODE_TIMEOUT gather, fixed on the first park.
            let mut timeout_deadline: Option<u64> = None;
            loop {
                let mut state = lock_state();
                let Some(id) = kq_id(&state, kq_fd) else {
                    return super::super::fail(super::super::EBADF);
                };
                let now = match with_context_raw(|c| c.monotonic_now_unrecorded()) {
                    Ok(now) => now,
                    Err(errno) => return super::super::fail(errno),
                };
                let (ready, rearm_not_ready, earliest_timer) = scan(&state, id, now);
                commit_rearm(&mut state, id, &rearm_not_ready);

                if !ready.is_empty() || capacity == 0 {
                    let count = ready.len().min(capacity);
                    let delivered = &ready[..count];
                    if !out.is_null() {
                        let slots = unsafe {
                            std::slice::from_raw_parts_mut(out.cast::<PatinaKevent>(), count)
                        };
                        for (slot, event) in slots.iter_mut().zip(delivered) {
                            *slot = event.event;
                        }
                    }
                    commit_delivered(&mut state, id, delivered);
                    return c_int::try_from(count).unwrap_or(c_int::MAX);
                }

                if mode == MODE_POLL {
                    return 0;
                }

                // A bounded gather whose deadline has passed with nothing ready
                // returns zero events — never re-parks on an elapsed deadline
                // (which would live-lock the deadlock rescue). The absolute
                // deadline is fixed on entry so it does not drift across scans.
                if mode == MODE_TIMEOUT {
                    let deadline =
                        *timeout_deadline.get_or_insert(now.saturating_add(timeout_nanos));
                    if now >= deadline {
                        return 0;
                    }
                }

                // Nothing ready: park with multi-fd fan-in, bounded by the earlier
                // of the gather timeout and the soonest EVFILT_TIMER deadline.
                let park_deadline = if mode == MODE_TIMEOUT {
                    let deadline = timeout_deadline.expect("timeout deadline fixed above");
                    Some(match earliest_timer {
                        Some(timer) => deadline.min(timer),
                        None => deadline,
                    })
                } else {
                    // MODE_FOREVER (MODE_POLL returned above): the park is bounded
                    // only by the soonest EVFILT_TIMER deadline, if any.
                    debug_assert!(mode == MODE_FOREVER, "unexpected kevent gather mode {mode}");
                    earliest_timer
                };
                // Fan-in on the reactor-neutral readiness sources (shared core),
                // plus the kqueue-specific EVFILT_USER trigger, whose wakeup is
                // the kq's own waiter list rather than a descriptor.
                let (watched, has_user) = watched_sources(&state, id);
                let locs = register_readiness_waiters(&mut state, me, &watched);
                if has_user {
                    state
                        .net
                        .kqueues
                        .get_mut(&id)
                        .expect("kqueue exists")
                        .kq
                        .waiters
                        .push_back(me);
                }
                let step = match park_deadline {
                    Some(deadline) => state.block_timed(
                        me,
                        "kevent",
                        Wait::new(BlockClass::Readiness, locs.clone()),
                        ClockKind::Monotonic,
                        deadline,
                    ),
                    None => {
                        state.block(me, "kevent", Wait::new(BlockClass::Readiness, locs.clone()))
                    }
                };
                match step {
                    Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                    Ok(Step::Continue) => drop(state),
                    Err(error) => {
                        let mut state = lock_state();
                        unregister_waiters(&mut state, me, &locs);
                        detach_user_waiter(&mut state, id, me);
                        return super::super::fail(error.into_posix());
                    }
                }
                let mut state = lock_state();
                unregister_waiters(&mut state, me, &locs);
                detach_user_waiter(&mut state, id, me);
                state.timed_out.remove(&me);
                drop(state);
            }
        }

        /// Unlink `me` from the kq's EVFILT_USER waiter list. Idempotent, so the
        /// gather resume paths call it unconditionally.
        fn detach_user_waiter(state: &mut ThreadRuntime, id: u64, me: TaskId) {
            if let Some(slot) = state.net.kqueues.get_mut(&id) {
                if let Some(index) = slot.kq.waiters.iter().position(|task| *task == me) {
                    slot.kq.waiters.remove(index);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    use epoll::EpollSlot;
    #[cfg(target_os = "linux")]
    pub(crate) use epoll::{epoll_close, forget_description};

    // ------------------------------------------------------------------
    // epoll readiness reactor (Linux) — the mirror of `mod kqueue` above over
    // the same OS-agnostic readiness core (`fd_poll`,
    // `register_readiness_waiters`). An epoll instance is a description in the
    // descriptor table; `epoll_ctl` keeps one interest per watched fd (epoll
    // semantics) over every pollable descriptor kind; `epoll_wait` gathers
    // ready events — parking on the scheduler baton with multi-fd fan-in when
    // nothing is ready, bounded by the millisecond timeout on the virtual
    // clock. mio's `Waker` analogue needs no epoll-specific wake path: it is an
    // ordinary watched eventfd whose write drains the shared read-waiter
    // queue.
    //
    // Delivery follows fs/eventpoll.c: a ready list (`ep->rdllist`) that an
    // interest joins at the tail when its source wakes it, from which
    // `epoll_wait` delivers each item's poll mask read through its events,
    // re-queuing a level-triggered item at the tail and dropping an
    // edge-triggered one until its next wakeup. The model observes wakeups
    // through each source's per-direction ARRIVAL SEQUENCES (a datagram, a
    // write, an eventfd add — every arrival is a wakeup, as `ep_poll_callback`
    // sees it) and through watched conditions rising (a hang-up, an error,
    // room to write). Everything here is deterministic GIVEN the recorded
    // schedule and carries NO trace events; only the scheduler parks/wakes are
    // recorded.
    #[cfg(target_os = "linux")]
    mod epoll {
        use super::{BlockClass, Wait};
        use std::collections::{BTreeMap, VecDeque};
        use std::ffi::{c_int, c_void};

        use patina_dst_abi::ClockKind;

        use super::{
            DescId, EPERM, FdKind, O_READ, O_WRITE, ReadyDir, Step, ThreadRuntime, current_task,
            fatal, lock_state, register_readiness_waiters, sched_point, switch_and_park,
            unregister_waiters, with_context_raw,
        };

        // <sys/epoll.h> control ops and event bits (the reactor is Linux-only).
        const EPOLL_CTL_ADD: c_int = 1;
        const EPOLL_CTL_DEL: c_int = 2;
        const EPOLL_CTL_MOD: c_int = 3;

        const EPOLLIN: u32 = 0x001;
        const EPOLLOUT: u32 = 0x004;
        const EPOLLERR: u32 = 0x008;
        const EPOLLHUP: u32 = 0x010;
        const EPOLLRDHUP: u32 = 0x2000;
        const EPOLLET: u32 = 1 << 31;
        /// One delivery, then the interest is disarmed until `EPOLL_CTL_MOD`
        /// re-arms it (the kernel keeps only the mode bits; a MOD replaces
        /// the whole mask).
        const EPOLLONESHOT: u32 = 1 << 30;
        /// Keep the system awake while the event is pending: it needs
        /// CAP_BLOCK_SUSPEND, so the kernel drops it for the guest.
        const EPOLLWAKEUP: u32 = 1 << 29;
        /// Wake one of the epoll instances waiting on the source rather than
        /// all: every instance sees the event here, which the flag's
        /// contract ("one or more") allows.
        const EPOLLEXCLUSIVE: u32 = 1 << 28;
        /// EPOLL_CLOEXEC == O_CLOEXEC: FD_CLOEXEC on the new number.
        const EPOLL_CLOEXEC: c_int = 0o2000000;

        /// The kernel's `struct epoll_event`, written directly into the guest's
        /// buffer with the kernel ABI layout: packed on x86_64 (the ABI keeps
        /// the i386 12-byte layout there), natural alignment elsewhere. Pinned
        /// against the platform definition by `_Static_assert`s in the C layer.
        #[cfg_attr(target_arch = "x86_64", repr(C, packed))]
        #[cfg_attr(not(target_arch = "x86_64"), repr(C))]
        #[derive(Clone, Copy)]
        pub(crate) struct EpollEvent {
            events: u32,
            data: u64,
        }

        /// The poll bits a read-direction wakeup carries (`EPOLLIN`, `EPOLLPRI`,
        /// `EPOLLRDNORM`, `EPOLLRDBAND`, `EPOLLMSG`, `EPOLLRDHUP`), and a
        /// write-direction one (`EPOLLOUT`, `EPOLLWRNORM`, `EPOLLWRBAND`).
        const READ_BITS: u32 = EPOLLIN | 0x002 | 0x040 | 0x080 | 0x400 | EPOLLRDHUP;
        const WRITE_BITS: u32 = EPOLLOUT | 0x100 | 0x200;
        /// `EP_PRIVATE_BITS`: the mode bits, never reported.
        const PRIVATE_BITS: u32 = EPOLLWAKEUP | EPOLLONESHOT | EPOLLET | EPOLLEXCLUSIVE;
        /// `EPOLLEXCLUSIVE_OK_BITS`: what an exclusive interest may carry.
        const EXCLUSIVE_OK_BITS: u32 =
            EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE;

        /// One watched fd's interest (epoll semantics: at most one per fd).
        struct Interest {
            /// The requested events with `EPOLLERR|EPOLLHUP` (always
            /// monitored) and the mode bits; a fired `EPOLLONESHOT` interest
            /// keeps the mode bits alone.
            events: u32,
            /// The caller's `epoll_data`, returned verbatim in delivered events.
            data: u64,
            /// The open file description the number named at registration — the
            /// kernel's `(fd, struct file)` key. The interest drops with the
            /// description's last reference.
            desc: DescId,
            /// The source's per-direction arrival sequences when last observed.
            seen: (u64, u64),
            /// What the interest's events read at the last observation.
            observed: u32,
        }

        /// A virtual epoll instance: its per-fd interest table and its ready
        /// list (`ep->rdllist`).
        #[derive(Default)]
        struct Epoll {
            interests: BTreeMap<c_int, Interest>,
            ready: VecDeque<c_int>,
        }

        impl Epoll {
            /// `ep_poll_callback`, observed after the fact: an interest whose
            /// source woke it since the last observation — an arrival in a
            /// watched direction, or a watched condition rising — joins the
            /// tail of the ready list unless it is on it (or disarmed, or
            /// not ready at all, when `ep_send_events` would drop it).
            fn observe(&mut self, fd: c_int, mask: u32, seqs: (u64, u64)) {
                let Some(interest) = self.interests.get_mut(&fd) else {
                    return;
                };
                let events = interest.events;
                let revents = mask & events;
                let woken = events & !PRIVATE_BITS != 0
                    && ((events & READ_BITS != 0 && seqs.0 != interest.seen.0)
                        || (events & WRITE_BITS != 0 && seqs.1 != interest.seen.1)
                        || revents & !interest.observed != 0);
                interest.seen = seqs;
                interest.observed = revents;
                if woken && revents != 0 && !self.ready.contains(&fd) {
                    self.ready.push_back(fd);
                }
            }

            /// `ep_send_events`: up to `max` events off the head of the ready
            /// list, each what its source's poll mask (`masks`) reads through
            /// the interest's events. An item that reads nothing leaves the
            /// list; a delivered `EPOLLONESHOT` item is disarmed, a delivered
            /// level-triggered one re-queued at the tail, an edge-triggered
            /// one dropped until its next wakeup. Items not reached stay at
            /// the head.
            #[cfg(test)]
            fn send(&mut self, masks: &BTreeMap<c_int, u32>, max: usize) -> Vec<EpollEvent> {
                let delivery = self.plan(masks, max);
                let events = delivery.events.clone();
                self.commit(delivery);
                events
            }

            /// [`Epoll::send`]'s outcome, decided without changing the
            /// instance: what a gather delivers, the ready list after it, and
            /// the one-shot interests it disarms. Only the ready list is
            /// copied, so deciding costs what the list holds, not what the
            /// instance watches.
            fn plan(&self, masks: &BTreeMap<c_int, u32>, max: usize) -> Delivery {
                let mut pending = self.ready.clone();
                let mut requeued = VecDeque::new();
                let mut events = Vec::new();
                let mut disarmed = Vec::new();
                while events.len() < max {
                    let Some(fd) = pending.pop_front() else {
                        break;
                    };
                    let Some(interest) = self.interests.get(&fd) else {
                        continue;
                    };
                    let revents = masks.get(&fd).copied().unwrap_or(0) & interest.events;
                    if revents == 0 {
                        continue;
                    }
                    events.push(EpollEvent {
                        events: revents,
                        data: interest.data,
                    });
                    if interest.events & EPOLLONESHOT != 0 {
                        disarmed.push(fd);
                    } else if interest.events & EPOLLET == 0 {
                        requeued.push_back(fd);
                    }
                }
                pending.extend(requeued);
                Delivery {
                    events,
                    ready: pending,
                    disarmed,
                }
            }

            fn commit(&mut self, delivery: Delivery) {
                self.ready = delivery.ready;
                for fd in delivery.disarmed {
                    if let Some(interest) = self.interests.get_mut(&fd) {
                        interest.events &= PRIVATE_BITS;
                    }
                }
            }

            fn forget(&mut self, fd: c_int) -> bool {
                self.ready.retain(|queued| *queued != fd);
                self.interests.remove(&fd).is_some()
            }
        }

        /// What one gather delivers and leaves behind (see [`Epoll::plan`]).
        struct Delivery {
            events: Vec<EpollEvent>,
            ready: VecDeque<c_int>,
            disarmed: Vec<c_int>,
        }

        /// An epoll registry. The descriptor table refcounts the description
        /// (one per `epoll_create1`, shared by every `dup`/`F_DUPFD` of it — mio
        /// clones its selector through `F_DUPFD_CLOEXEC`) and frees the registry
        /// through [`epoll_close`] when the last number closes.
        pub(super) struct EpollSlot {
            ep: Epoll,
        }

        /// Resolve a guest number to its epoll registry id: `EBADF` for a number
        /// that names nothing, `EINVAL` for one that is not an epoll instance.
        fn ep_id(fd: c_int) -> Result<u64, c_int> {
            match super::super::fd_table().lock().resolve(fd) {
                Some(resolved) if resolved.kind == FdKind::Epoll => Ok(resolved.handle),
                Some(_) => Err(super::EINVAL),
                None => Err(super::super::EBADF),
            }
        }

        /// Free an epoll registry whose description's last reference went. A
        /// task parked in `epoll_wait` is NOT woken — the kernel's wait holds
        /// its own file reference and keeps blocking, and mio's single-threaded
        /// driver never closes underneath a wait.
        pub(crate) fn epoll_close(handle: u64) {
            lock_state().net.epolls.remove(&handle);
        }

        /// Drop every interest registered against a description whose last
        /// reference went: the kernel's `eventpoll_release` on the file's final
        /// `fput`.
        pub(crate) fn forget_description(desc: DescId) {
            let mut state = lock_state();
            for slot in state.net.epolls.values_mut() {
                let gone: Vec<c_int> = slot
                    .ep
                    .interests
                    .iter()
                    .filter(|(_, interest)| interest.desc == desc)
                    .map(|(&fd, _)| fd)
                    .collect();
                for fd in gone {
                    slot.ep.forget(fd);
                }
            }
        }

        /// Allocate a virtual epoll instance. Syscall-shaped
        /// (`epoll_create1(flags)`) so a future syscall-user-dispatch SIGSYS
        /// dispatcher can call it with raw register arguments; the C interposer
        /// is thin marshaling over this. Activates the thread subsystem so a
        /// later blocking `epoll_wait` can park through the baton.
        ///
        /// # Safety
        /// C ABI entry point.
        #[unsafe(no_mangle)]
        pub extern "C" fn patina_epoll_create1(flags: c_int) -> c_int {
            let _panic_scope = crate::panic_boundary::PanicScope::enter();
            if flags & !EPOLL_CLOEXEC != 0 {
                return super::super::fail(super::EINVAL);
            }
            let mut state = lock_state();
            if let Err(error) = state.ensure_active() {
                return super::super::fail(error.into_posix());
            }
            let id = state.net.next_epoll;
            state.net.next_epoll = state.net.next_epoll.wrapping_add(1);
            state.net.epolls.insert(
                id,
                EpollSlot {
                    ep: Epoll::default(),
                },
            );
            // An epoll instance reports O_RDWR through F_GETFL.
            match super::super::install_fd(
                FdKind::Epoll,
                id,
                O_READ | O_WRITE,
                flags & EPOLL_CLOEXEC != 0,
            ) {
                Ok(fd) => {
                    super::super::set_errno(0);
                    fd
                }
                Err(errno) => {
                    state.net.epolls.remove(&id);
                    super::super::fail(errno)
                }
            }
        }

        /// Apply one `epoll_ctl` op. Syscall-shaped (`epoll_ctl(epfd, op, fd,
        /// event)`) for the SUD dispatcher. Registry mutation only — no
        /// scheduling point, no trace event. The kernel's `do_epoll_ctl`
        /// order: the event is copied in for every op but DEL (`EFAULT`);
        /// both numbers must name something (`EBADF`, `epfd` first); the
        /// target must be pollable (`EPERM`: a file, a directory, a device);
        /// `EPOLLWAKEUP` is dropped (it needs CAP_BLOCK_SUSPEND); `epfd` must
        /// be an epoll instance other than the target (`EINVAL`);
        /// `EPOLLEXCLUSIVE` is `EINVAL` on MOD, with bits outside
        /// `EPOLLEXCLUSIVE_OK_BITS` or on an epoll target; then ADD is
        /// `EEXIST` for a registered fd, DEL and MOD `ENOENT` for an
        /// unregistered one, MOD `EINVAL` for an exclusive interest, and an
        /// unknown op `EINVAL`. A registered interest that is ready joins the
        /// ready list.
        ///
        /// # Safety
        /// `event` is the guest's `struct epoll_event` for every op but DEL;
        /// it is copied in through `uaccess`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn patina_epoll_ctl(
            epfd: c_int,
            op: c_int,
            fd: c_int,
            event: *const EpollEvent,
        ) -> c_int {
            let _panic_scope = crate::panic_boundary::PanicScope::enter();
            let fail = super::super::fail;
            let (events, data) = if op == EPOLL_CTL_DEL {
                (0, 0)
            } else {
                match crate::uaccess::read::<EpollEvent>(event as usize) {
                    Ok(event) => (event.events & !EPOLLWAKEUP, event.data),
                    Err(errno) => return fail(errno),
                }
            };
            let mut state = lock_state();
            let id = match ep_id(epfd) {
                Err(errno) if errno == super::super::EBADF => return fail(errno),
                id => id,
            };
            let Some(target) = super::super::fd_table().lock().resolve(fd) else {
                return fail(super::super::EBADF);
            };
            if matches!(
                target.kind,
                FdKind::File | FdKind::Dir | FdKind::OPath | FdKind::Urandom
            ) {
                return fail(EPERM);
            }
            let id = match id {
                Ok(id) if fd != epfd => id,
                _ => return fail(super::EINVAL),
            };
            if op != EPOLL_CTL_DEL
                && events & EPOLLEXCLUSIVE != 0
                && (op == EPOLL_CTL_MOD
                    || (op == EPOLL_CTL_ADD
                        && (target.kind == FdKind::Epoll || events & !EXCLUSIVE_OK_BITS != 0)))
            {
                return fail(super::EINVAL);
            }
            // Readiness is defined over every pollable kind but another epoll
            // instance: nested epoll is not modeled and fails closed loudly.
            if target.kind == FdKind::Epoll {
                fatal(&format!(
                    "epoll_ctl registered epoll descriptor {fd} on another epoll instance: \
                     nested epoll is not modeled; failing closed"
                ));
            }
            let (mask, seqs) = super::fd_poll(&state, fd, Some(target.desc)).unwrap_or((0, (0, 0)));
            let ep = &mut state.net.epolls.get_mut(&id).expect("epoll was checked").ep;
            let registered = Interest {
                events: events | EPOLLERR | EPOLLHUP,
                data,
                desc: target.desc,
                seen: seqs,
                observed: 0,
            };
            match op {
                EPOLL_CTL_ADD => {
                    if ep.interests.contains_key(&fd) {
                        return fail(super::super::EEXIST);
                    }
                    ep.interests.insert(fd, registered);
                }
                EPOLL_CTL_DEL => {
                    return if ep.forget(fd) {
                        0
                    } else {
                        fail(super::super::ENOENT)
                    };
                }
                EPOLL_CTL_MOD => {
                    let Some(interest) = ep.interests.get_mut(&fd) else {
                        return fail(super::super::ENOENT);
                    };
                    if interest.events & EPOLLEXCLUSIVE != 0 {
                        return fail(super::EINVAL);
                    }
                    *interest = registered;
                }
                _ => return fail(super::EINVAL),
            }
            // `ep_insert`/`ep_modify` poll the item once and queue it if ready.
            ep.observe(fd, mask, seqs);
            0
        }

        /// Observe every interest of instance `id` (see [`Epoll::observe`]),
        /// in descriptor order — wakeups between two observations are queued
        /// in that order, the model keeping no clock across sources — and
        /// return what each source's poll mask reads now.
        fn scan(state: &mut ThreadRuntime, id: u64) -> BTreeMap<c_int, u32> {
            let polled: Vec<(c_int, u32, (u64, u64))> = state
                .net
                .epolls
                .get(&id)
                .expect("epoll exists")
                .ep
                .interests
                .iter()
                .map(|(&fd, interest)| {
                    let (mask, seqs) =
                        super::fd_poll(state, fd, Some(interest.desc)).unwrap_or((0, (0, 0)));
                    (fd, mask, seqs)
                })
                .collect();
            let ep = &mut state.net.epolls.get_mut(&id).expect("epoll exists").ep;
            let mut masks = BTreeMap::new();
            for (fd, mask, seqs) in polled {
                ep.observe(fd, mask, seqs);
                masks.insert(fd, mask);
            }
            masks
        }

        /// The watched fds as reactor-neutral `(direction, fd)` pairs for the
        /// shared fan-in park: every armed interest watches the read side
        /// (where hang-ups and errors arrive too), and the write side when it
        /// asks for it. A wake simply rescans.
        fn watched_sources(state: &ThreadRuntime, id: u64) -> Vec<(ReadyDir, c_int)> {
            let ep = &state.net.epolls.get(&id).expect("epoll exists").ep;
            let mut watched = Vec::new();
            for (&fd, interest) in &ep.interests {
                if interest.events & !PRIVATE_BITS == 0 {
                    continue;
                }
                watched.push((ReadyDir::Read, fd));
                if interest.events & WRITE_BITS != 0 {
                    watched.push((ReadyDir::Write, fd));
                }
            }
            watched
        }

        /// `EP_MAX_EVENTS`: the most events one wait may ask for.
        const MAX_EVENTS: c_int =
            (c_int::MAX as usize / std::mem::size_of::<EpollEvent>()) as c_int;

        /// Gather up to `maxevents` ready events into `events`, blocking per the
        /// millisecond `timeout_ms` (-1 = block until ready, 0 = poll, > 0 =
        /// relative virtual-clock deadline). Syscall-shaped (`epoll_wait(epfd,
        /// events, maxevents, timeout)`) for the SUD dispatcher; the C
        /// epoll_wait/epoll_pwait interposers are thin marshaling over this.
        /// `maxevents` outside `1..=EP_MAX_EVENTS` is `EINVAL`; the events are
        /// copied out through `uaccess`, and one that cannot be ends the
        /// delivery there (`EFAULT` if it was the first).
        ///
        /// # Safety
        /// C ABI entry point; `events` is the guest's buffer.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn patina_epoll_wait(
            epfd: c_int,
            events: *mut c_void,
            maxevents: c_int,
            timeout_ms: c_int,
        ) -> c_int {
            let _panic_scope = crate::panic_boundary::PanicScope::enter();
            let fail = super::super::fail;
            if let Err(errno) = sched_point() {
                return fail(errno);
            }
            if !(1..=MAX_EVENTS).contains(&maxevents) {
                return fail(super::EINVAL);
            }
            let capacity = maxevents as usize;
            let me = current_task();
            // Absolute deadline for a positive timeout, fixed on the first scan
            // so it does not drift across rescans.
            let mut timeout_deadline: Option<u64> = None;
            loop {
                let mut state = lock_state();
                let id = match ep_id(epfd) {
                    Ok(id) => id,
                    Err(errno) => return fail(errno),
                };
                let now = match with_context_raw(|c| c.monotonic_now_unrecorded()) {
                    Ok(now) => now,
                    Err(errno) => return fail(errno),
                };
                let masks = scan(&mut state, id);
                let ep = &mut state.net.epolls.get_mut(&id).expect("epoll exists").ep;
                let delivery = ep.plan(&masks, capacity);
                if !delivery.events.is_empty() {
                    let size = std::mem::size_of::<EpollEvent>();
                    let written = delivery
                        .events
                        .iter()
                        .enumerate()
                        .take_while(|(at, event)| {
                            crate::uaccess::write(events as usize + at * size, *event).is_ok()
                        })
                        .count();
                    if written == 0 {
                        return fail(super::super::EFAULT);
                    }
                    let delivery = if written < delivery.events.len() {
                        ep.plan(&masks, written)
                    } else {
                        delivery
                    };
                    ep.commit(delivery);
                    return c_int::try_from(written).unwrap_or(c_int::MAX);
                }

                if timeout_ms == 0 {
                    return 0;
                }
                // A bounded gather whose deadline has passed with nothing ready
                // returns zero events — never re-parks on an elapsed deadline
                // (which would live-lock the deadlock rescue).
                if timeout_ms > 0 {
                    let deadline = *timeout_deadline
                        .get_or_insert(now.saturating_add(timeout_ms as u64 * 1_000_000));
                    if now >= deadline {
                        return 0;
                    }
                }
                // Nothing ready: park with multi-fd fan-in on the shared core.
                let watched = watched_sources(&state, id);
                let locs = register_readiness_waiters(&mut state, me, &watched);
                let step = if timeout_ms > 0 {
                    let deadline = timeout_deadline.expect("timeout deadline fixed above");
                    state.block_timed(
                        me,
                        "epoll-wait",
                        Wait::new(BlockClass::Readiness, locs.clone()),
                        ClockKind::Monotonic,
                        deadline,
                    )
                } else {
                    state.block(
                        me,
                        "epoll-wait",
                        Wait::new(BlockClass::Readiness, locs.clone()),
                    )
                };
                match step {
                    Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                    Ok(Step::Continue) => drop(state),
                    Err(error) => {
                        let mut state = lock_state();
                        unregister_waiters(&mut state, me, &locs);
                        return super::super::fail(error.into_posix());
                    }
                }
                let mut state = lock_state();
                unregister_waiters(&mut state, me, &locs);
                state.timed_out.remove(&me);
                drop(state);
                if super::signals::resume() == super::signals::Resumed::Eintr {
                    return super::super::fail(super::super::EINTR);
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use super::{
                BTreeMap, EPOLLERR, EPOLLET, EPOLLHUP, EPOLLIN, EPOLLONESHOT, EPOLLOUT, Epoll,
                EpollEvent, Interest,
            };

            /// The Rust struct is written straight into the guest's buffer, so
            /// its layout must be the kernel ABI (also pinned from the C side
            /// by `_Static_assert`s against the platform `struct epoll_event`).
            #[test]
            fn epoll_event_layout_matches_kernel_abi() {
                assert_eq!(std::mem::offset_of!(EpollEvent, events), 0);
                if cfg!(target_arch = "x86_64") {
                    assert_eq!(std::mem::size_of::<EpollEvent>(), 12);
                    assert_eq!(std::mem::offset_of!(EpollEvent, data), 4);
                } else {
                    assert_eq!(std::mem::size_of::<EpollEvent>(), 16);
                    assert_eq!(std::mem::offset_of!(EpollEvent, data), 8);
                }
            }

            fn interest(events: u32) -> Interest {
                Interest {
                    events: events | EPOLLERR | EPOLLHUP,
                    data: 0,
                    desc: 0,
                    seen: (0, 0),
                    observed: 0,
                }
            }

            fn delivered(ep: &mut Epoll, masks: &[(i32, u32)], max: usize) -> Vec<u32> {
                let masks: BTreeMap<i32, u32> = masks.iter().copied().collect();
                ep.send(&masks, max)
                    .iter()
                    .map(|event| event.events)
                    .collect()
            }

            /// The pipe of readiness/epoll: the writer is ready first, the
            /// reader after a write; level-triggered items re-queue at the
            /// tail, so `maxevents` 1 takes the one queued first.
            #[test]
            fn ready_list_is_fifo_by_wakeup_with_level_items_requeued_at_the_tail() {
                let mut ep = Epoll::default();
                ep.interests.insert(3, interest(EPOLLIN));
                ep.interests.insert(4, interest(EPOLLOUT));
                ep.observe(3, EPOLLOUT, (0, 0));
                ep.observe(4, EPOLLOUT, (0, 0));
                assert_eq!(ep.ready, [4]);
                assert_eq!(
                    delivered(&mut ep, &[(3, EPOLLOUT), (4, EPOLLOUT)], 8),
                    [EPOLLOUT]
                );
                ep.observe(3, EPOLLIN, (1, 0));
                ep.observe(4, EPOLLOUT, (0, 0));
                assert_eq!(ep.ready, [4, 3]);
                let both = [(3, EPOLLIN), (4, EPOLLOUT)];
                assert_eq!(delivered(&mut ep, &both, 8), [EPOLLOUT, EPOLLIN]);
                assert_eq!(delivered(&mut ep, &both, 1), [EPOLLOUT]);
                assert_eq!(ep.ready, [3, 4]);
            }

            /// Edge-triggered: every arrival is a wakeup, readiness that
            /// merely persists is none; a rising condition (a hang-up) is.
            #[test]
            fn edge_items_fire_per_arrival_and_per_rising_condition() {
                let mut ep = Epoll::default();
                ep.interests.insert(5, interest(EPOLLIN | EPOLLET));
                ep.observe(5, EPOLLIN, (1, 0));
                assert_eq!(delivered(&mut ep, &[(5, EPOLLIN)], 8), [EPOLLIN]);
                ep.observe(5, EPOLLIN, (1, 0));
                assert!(ep.ready.is_empty());
                ep.observe(5, EPOLLIN, (2, 0));
                assert_eq!(delivered(&mut ep, &[(5, EPOLLIN)], 8), [EPOLLIN]);
                ep.observe(5, EPOLLIN | EPOLLHUP, (2, 0));
                assert_eq!(
                    delivered(&mut ep, &[(5, EPOLLIN | EPOLLHUP)], 8),
                    [EPOLLIN | EPOLLHUP]
                );
            }

            /// A socket's write-space arrivals: an edge-triggered EPOLLOUT item
            /// the reactor saw writable, whose writer then filled and was
            /// drained before the next wait, is queued again by the drain
            /// alone — the mask never read unwritable at a scan.
            #[test]
            fn a_write_space_arrival_requeues_an_edge_triggered_writer() {
                let mut ep = Epoll::default();
                ep.interests.insert(8, interest(EPOLLOUT | EPOLLET));
                ep.observe(8, EPOLLOUT, (0, 0));
                assert_eq!(delivered(&mut ep, &[(8, EPOLLOUT)], 8), [EPOLLOUT]);
                ep.observe(8, EPOLLOUT, (0, 0));
                assert!(ep.ready.is_empty());
                ep.observe(8, EPOLLOUT, (0, 1));
                assert_eq!(delivered(&mut ep, &[(8, EPOLLOUT)], 8), [EPOLLOUT]);
            }

            /// A delivered one-shot item is disarmed: nothing wakes it until
            /// a MOD re-arms it; an item that reads nothing leaves the list.
            #[test]
            fn oneshot_disarms_and_unready_items_leave_the_list() {
                let mut ep = Epoll::default();
                ep.interests.insert(6, interest(EPOLLIN | EPOLLONESHOT));
                ep.interests.insert(7, interest(EPOLLIN));
                ep.observe(6, EPOLLIN, (1, 0));
                ep.observe(7, EPOLLIN, (1, 0));
                assert_eq!(delivered(&mut ep, &[(6, EPOLLIN), (7, 0)], 8), [EPOLLIN]);
                assert!(ep.ready.is_empty());
                ep.observe(6, EPOLLIN, (2, 0));
                assert!(ep.ready.is_empty());
            }
        }
    }

    // ------------------------------------------------------------------
    // Linux futex routing. Rust std on Linux lowers Mutex/Condvar/thread
    // parking to raw SYS_futex through libc's `syscall` wrapper rather than the
    // pthread primitives the shim interposes, so the interposed `syscall` routes
    // FUTEX_WAIT/FUTEX_WAKE here. A wait parks the calling managed task on the
    // futex word's address through the baton (like a cond wait); a wake releases
    // up to N of them. macOS is unaffected — std uses pthread there. The address
    // is only read/parked while this task holds the baton, so the value check
    // and the park are atomic and no wakeup is lost. A timed wait parks with
    // its deadline on the virtual-clock timer queue: a FUTEX_WAKE that arrives
    // first wins, otherwise the deadlock rescue fires the deadline, purges the
    // waiter from the futex word's queue, and the wait returns ETIMEDOUT —
    // exactly the cond_timedwait discipline.

    /// FUTEX_WAIT: if the word at `addr` still equals `expected`, park the
    /// calling task on that address; otherwise return `EWOULDBLOCK` so the
    /// caller re-checks. Returns 0 when woken by a FUTEX_WAKE.
    ///
    /// # Safety
    /// `addr` must be the address of a live, aligned 4-byte futex word.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_futex_wait(addr: usize, expected: u32) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        futex_wait(addr, expected, false)
    }

    /// [`patina_futex_wait`], noting whether the wait is private
    /// (`FUTEX_PRIVATE_FLAG`): the dispatcher's `futex` row.
    pub(crate) fn futex_wait(addr: usize, expected: u32, private: bool) -> c_int {
        let mut restart = true;
        while restart {
            let mut state = lock_state();
            if let Err(error) = state.ensure_active() {
                return super::fail(error.into_posix());
            }
            let me = current_task();
            // SAFETY: `addr` is the guest's futex word per this function's contract;
            // only the baton holder runs, so this read races with nothing.
            let current = unsafe { core::ptr::read_volatile(addr as *const u32) };
            if current != expected {
                return super::fail(EWOULDBLOCK);
            }

            state.futexes.entry(addr).or_default().push_back(me);
            state.note_futex_wait(me, private);
            match state.block(
                me,
                "futex-wait",
                Wait::new(BlockClass::Futex, vec![WaiterLoc::Futex(addr)]),
            ) {
                Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                Ok(Step::Continue) => fatal("futex wait parked without transferring the baton"),
                Err(error) => return error.into_posix(),
            }
            #[cfg(target_os = "linux")]
            match signals::resume() {
                signals::Resumed::Eintr => return super::fail(super::EINTR),
                signals::Resumed::Restart => restart = true,
                signals::Resumed::Normal => restart = false,
            }
            #[cfg(not(target_os = "linux"))]
            {
                restart = false;
            }
        }
        0
    }

    /// Timed `FUTEX_WAIT`/`FUTEX_WAIT_BITSET`: like [`patina_futex_wait`] but
    /// with a deadline on the virtual-clock timer queue. `absolute` is 0 for a
    /// relative `FUTEX_WAIT` timeout (added to the current `clock` time) and
    /// nonzero for an absolute `FUTEX_WAIT_BITSET` deadline. `clock_id` is
    /// `PATINA_CLOCK_MONOTONIC` unless `FUTEX_CLOCK_REALTIME` was set. Returns 0
    /// when woken by a `FUTEX_WAKE`, `-1`/`ETIMEDOUT` when the timer fires, and
    /// `-1`/`EWOULDBLOCK` if the word no longer holds `expected`. The value
    /// check, clock read, and park all run under the baton, so the check and the
    /// park stay atomic exactly like the untimed path.
    ///
    /// # Safety
    /// `addr` must be the address of a live, aligned 4-byte futex word.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_futex_wait_timed(
        addr: usize,
        expected: u32,
        clock_id: u32,
        absolute: c_int,
        timeout_nanos: u64,
    ) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        futex_wait_timed(addr, expected, clock_id, absolute, timeout_nanos, false)
    }

    /// [`patina_futex_wait_timed`], noting whether the wait is private.
    pub(crate) fn futex_wait_timed(
        addr: usize,
        expected: u32,
        clock_id: u32,
        absolute: c_int,
        timeout_nanos: u64,
        private: bool,
    ) -> c_int {
        let clock = match clock_id {
            0 => ClockKind::Realtime,
            1 => ClockKind::Monotonic,
            _ => return super::fail(EINVAL),
        };
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return super::fail(error.into_posix());
        }
        let me = current_task();
        // SAFETY: `addr` is the guest's futex word per this function's contract;
        // only the baton holder runs, so this read races with nothing.
        let current = unsafe { core::ptr::read_volatile(addr as *const u32) };
        if current != expected {
            return super::fail(EWOULDBLOCK);
        }

        // A relative timeout is anchored to the current virtual time; both reads
        // and the subsequent park happen without releasing the baton.
        let deadline = if absolute != 0 {
            timeout_nanos
        } else {
            match with_context_raw(|context| context.now(clock)) {
                Ok(now) => now.saturating_add(timeout_nanos),
                Err(errno) => return super::fail(errno),
            }
        };
        state.futexes.entry(addr).or_default().push_back(me);
        state.note_futex_wait(me, private);
        match state.block_timed(
            me,
            "futex-wait",
            Wait::new(BlockClass::TimedFutex, vec![WaiterLoc::Futex(addr)]),
            clock,
            deadline,
        ) {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => return error.into_posix(),
        }
        #[cfg(target_os = "linux")]
        if signals::resume() == signals::Resumed::Eintr {
            return super::fail(super::EINTR);
        }
        let mut state = lock_state();
        if state.timed_out.remove(&me) {
            super::fail(ETIMEDOUT)
        } else {
            0
        }
    }

    /// FUTEX_WAKE: wake up to `count` tasks (all if `count < 0`) parked on
    /// `addr`. Returns the number woken.
    ///
    /// # Safety
    /// C ABI entry point.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_futex_wake(addr: usize, count: c_int) -> c_int {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        futex_wake(addr, count, true)
    }

    /// A kernel-side wake by the word's shared key (a dead robust owner's,
    /// `handle_futex_death`): up to `count` waiters, skipping those that wait
    /// privately, whose key it does not match.
    #[cfg(target_os = "linux")]
    pub(crate) fn futex_wake_shared(addr: usize, count: c_int) -> c_int {
        futex_wake(addr, count, false)
    }

    /// Wake up to `count` waiters on `addr` (all if negative), in queue
    /// order; private waiters too unless `private` is false.
    fn futex_wake(addr: usize, count: c_int, private: bool) -> c_int {
        let mut state = lock_state();
        let limit = usize::try_from(count).unwrap_or(usize::MAX);
        let ThreadRuntime {
            futexes,
            private_futex_waits,
            ..
        } = &mut *state;
        let to_wake: Vec<TaskId> = match futexes.get_mut(&addr) {
            Some(waiters) => {
                let mut woken = Vec::new();
                waiters.retain(|task| {
                    let take =
                        woken.len() < limit && (private || !private_futex_waits.contains(task));
                    if take {
                        woken.push(*task);
                    }
                    !take
                });
                woken
            }
            None => Vec::new(),
        };
        if state.futexes.get(&addr).is_some_and(VecDeque::is_empty) {
            state.futexes.remove(&addr);
        }
        let mut scheduler = RealScheduler;
        for task in &to_wake {
            #[cfg(target_os = "linux")]
            state.remove_signal_wait(*task);
            if let Err(message) = scheduler.wake(*task) {
                fatal(&message);
            }
        }
        c_int::try_from(to_wake.len()).unwrap_or(c_int::MAX)
    }

    #[cfg(test)]
    mod tests {
        use patina_dst_driver_api::SchedulerDriver;
        use patina_dst_sched_det::DetScheduler;

        use super::*;

        /// Drives [`ThreadTable`] against the real deterministic scheduler.
        struct DetAdapter {
            scheduler: DetScheduler,
        }

        impl DetAdapter {
            fn new(seed: u64) -> Self {
                Self {
                    scheduler: DetScheduler::new(seed),
                }
            }

            /// Spawn and immediately select a task as running.
            fn spawn_running(&mut self) -> TaskId {
                let task = SchedulerDriver::spawn(&mut self.scheduler, "task").unwrap();
                self.scheduler.select(Some(task)).unwrap();
                task
            }
        }

        impl Scheduler for DetAdapter {
            fn spawn(&mut self, label: &str) -> Result<TaskId, String> {
                SchedulerDriver::spawn(&mut self.scheduler, label).map_err(|error| error.message)
            }

            fn yield_task(&mut self, task: TaskId) -> Result<(), String> {
                self.scheduler
                    .yield_task(task)
                    .map_err(|error| error.message)
            }

            fn park(&mut self, task: TaskId, reason: &str) -> Result<(), String> {
                self.scheduler
                    .park(task, reason)
                    .map_err(|error| error.message)
            }

            fn park_timed(
                &mut self,
                task: TaskId,
                reason: &str,
                _clock: ClockKind,
                _deadline: u64,
            ) -> Result<(), String> {
                // The pure ThreadTable tests do not exercise the timer queue,
                // which lives in the runtime `Context`; park like the untimed op.
                self.scheduler
                    .park(task, reason)
                    .map_err(|error| error.message)
            }

            fn wake(&mut self, task: TaskId) -> Result<(), String> {
                self.scheduler.wake(task).map_err(|error| error.message)
            }

            fn complete(&mut self, task: TaskId) -> Result<(), String> {
                self.scheduler.complete(task).map_err(|error| error.message)
            }

            fn next(&mut self) -> Result<Option<TaskId>, String> {
                self.scheduler.next().map_err(|error| error.message)
            }
        }

        const MUTEX: usize = 0x1000;
        const COND: usize = 0x2000;
        const RWLOCK: usize = 0x3000;

        // The `--yield-points` teardown fix must keep "task completed" a state
        // distinct from "thread never registered": a completed thread's
        // post-finish scheduling points are silently skipped, but a foreign or
        // pre-registration thread must still fail loudly. Run on a fresh host
        // thread so the thread-locals start at their defaults.
        #[test]
        fn completed_sentinel_is_distinct_from_never_registered() {
            std::thread::spawn(|| {
                // Never-registered defaults: no task, not completed.
                assert_eq!(current_task(), UNMANAGED_TASK);
                assert!(!task_completed());
                // sched_point on a never-registered thread does NOT take the
                // completed no-op path (it would fall through to the loud
                // reschedule when the subsystem is active).
                mark_task_completed();
                // Completing marks the sentinel WITHOUT aliasing the unregistered
                // task id, so the two states remain distinguishable.
                assert!(task_completed());
                assert_eq!(current_task(), UNMANAGED_TASK);
                // A completed thread takes no scheduling point.
                assert!(sched_point().is_ok());
            })
            .join()
            .unwrap();
        }

        // The loud path the fix must preserve: rescheduling a task the scheduler
        // never registered is an error, not a silent no-op. `sched_point` reaches
        // this via `reschedule` for any non-completed thread, so a foreign thread
        // reaching a scheduling point still fails closed.
        #[test]
        fn rescheduling_an_unregistered_task_errors() {
            let mut scheduler = DetAdapter::new(1);
            assert!(scheduler.yield_task(UNMANAGED_TASK).is_err());
        }

        // The main-thread teardown fix: once the process enters its post-`main`
        // teardown window (the `exit` interposer calls `note_main_returned`), the
        // ROOT task — which never runs `thread_finish` and so has no per-thread
        // completion sentinel — takes NO scheduling point, exactly like a
        // completed worker's post-teardown, so its `--yield-points` thread-local
        // destructors record zero trailing yields. `MAIN_RETURNED` is process-wide
        // (no other test sets it, and none relies on the global `sched_point`
        // taking its reschedule path); this test restores it so the teardown state
        // never leaks into sibling tests.
        #[test]
        fn main_returned_silences_the_root_task_scheduling_point() {
            note_main_returned();
            assert!(main_returned());
            // A scheduling point in the teardown window is a no-op, on any thread —
            // never a reschedule against a torn-down scheduler.
            std::thread::spawn(|| assert!(sched_point().is_ok()))
                .join()
                .unwrap();
            MAIN_RETURNED.store(false, std::sync::atomic::Ordering::SeqCst);
            assert!(!main_returned());
        }

        // Pure pipe-channel semantics (the scheduler-integrated parking is covered
        // end-to-end by the pipe tests in cargo-patina/tests/native_abi.rs):
        // bounded capacity, partial reads, and EOF only after drain.
        #[test]
        fn pipe_channel_transfers_bytes_with_bounded_capacity_and_eof() {
            let mut channel = PipeChannel::new(4);
            let mut dst = [0u8; 8];
            // Empty + writer open → WouldBlock (the reader parks).
            assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
            // Bounded capacity: a write fills it, and the next (atomic, below
            // PIPE_BUF) waits for room for all of it.
            assert_eq!(channel.try_write(b"abcd"), PipeWrite::Wrote(4));
            assert_eq!(channel.try_write(b"ef"), PipeWrite::WouldBlock);
            // A short read frees space for the writer's remaining bytes.
            assert_eq!(channel.try_read(&mut dst[..2]), PipeRead::Read(2));
            assert_eq!(&dst[..2], b"ab");
            assert_eq!(channel.try_write(b"ef"), PipeWrite::Wrote(2));
            assert_eq!(channel.try_read(&mut dst), PipeRead::Read(4));
            assert_eq!(&dst[..4], b"cdef");
            // Drained but writer still open → WouldBlock, not EOF.
            assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
            // Buffered bytes are delivered before EOF even after the writer closes.
            channel.try_write(b"hi");
            channel.write_refs = 0;
            assert_eq!(channel.try_read(&mut dst), PipeRead::Read(2));
            assert_eq!(&dst[..2], b"hi");
            assert_eq!(channel.try_read(&mut dst), PipeRead::Eof);
        }

        // A FIFO channel is born with NO ends, and every "closed" answer is
        // derived from the reference counts rather than latched — which is what
        // lets a FIFO's reader or writer side come BACK when it is opened again.
        // RED before FIFOs were modeled: `PipeChannel` had no such constructor
        // and the two closed flags were one-way latches.
        #[test]
        fn fifo_channel_starts_endless_and_derives_closedness_from_its_refs() {
            let mut channel = PipeChannel::new_fifo(4, 7);
            assert_eq!(channel.fifo_ino, Some(7));
            assert_eq!((channel.read_refs, channel.write_refs), (0, 0));
            assert_eq!((channel.read_opens, channel.write_opens), (0, 0));
            // No writer: a read is end-of-file, not a park.
            let mut dst = [0u8; 8];
            assert!(channel.read_closed() && channel.write_closed());
            assert_eq!(channel.try_read(&mut dst), PipeRead::Eof);
            // No reader: a write is a broken pipe.
            assert_eq!(channel.try_write(b"x"), PipeWrite::BrokenPipe);

            // One opener of each side, as `fifo_open` registers them.
            channel.read_refs += 1;
            channel.write_refs += 1;
            assert!(!channel.read_closed() && !channel.write_closed());
            assert_eq!(channel.try_write(b"hi"), PipeWrite::Wrote(2));
            // Drained with a live writer is a park, not end-of-file.
            assert_eq!(channel.try_read(&mut dst), PipeRead::Read(2));
            assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
            // The last writer leaves: end-of-file. A NEW writer revives the
            // channel, which a latched flag could not express.
            channel.write_refs -= 1;
            assert_eq!(channel.try_read(&mut dst), PipeRead::Eof);
            channel.write_refs += 1;
            assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
        }

        // `pipe_write`: a write of at most PIPE_BUF bytes is atomic — it waits
        // for room for all of it rather than landing in part — while a longer
        // one takes what fits.
        #[test]
        fn pipe_channel_writes_up_to_pipe_buf_atomically() {
            let mut channel = PipeChannel::new(PIPE_BUF + 8);
            let small = [7u8; 16];
            assert_eq!(
                channel.try_write(&[0; PIPE_BUF]),
                PipeWrite::Wrote(PIPE_BUF)
            );
            assert_eq!(channel.try_write(&small), PipeWrite::WouldBlock);
            assert_eq!(channel.try_write(&small[..8]), PipeWrite::Wrote(8));
            let mut dst = [0u8; PIPE_BUF + 8];
            assert_eq!(channel.try_read(&mut dst), PipeRead::Read(PIPE_BUF + 8));
            assert_eq!(channel.try_write(&small[..8]), PipeWrite::Wrote(8));
            assert_eq!(
                channel.try_write(&[1; PIPE_BUF + 1]),
                PipeWrite::Wrote(PIPE_BUF)
            );
        }

        // Writing to a channel whose reader closed is a broken pipe surfaced as an
        // errno (EPIPE) — never a signal.
        #[test]
        fn pipe_channel_write_to_closed_reader_is_broken_pipe() {
            let mut channel = PipeChannel::new(4);
            channel.read_refs = 0;
            assert_eq!(channel.try_write(b"x"), PipeWrite::BrokenPipe);
        }

        #[test]
        fn uncontended_lock_and_unlock_round_trips() {
            let mut table = ThreadTable::default();
            let mut scheduler = DetAdapter::new(1);
            let a = TaskId(1);
            assert!(matches!(
                table.lock(a, MUTEX, MutexKind::Normal).unwrap(),
                LockStep::Acquired
            ));
            assert_eq!(table.mutexes[&MUTEX].owner, Some(a));
            table.unlock(&mut scheduler, a, MUTEX).unwrap();
            assert_eq!(table.mutexes[&MUTEX].owner, None);
        }

        #[test]
        fn an_owner_relock_follows_the_mutex_kind() {
            let mut table = ThreadTable::default();
            let mut scheduler = DetAdapter::new(1);
            let a = TaskId(1);
            let b = TaskId(2);

            table.init_mutex(MUTEX, MutexKind::ErrorCheck);
            table.lock(a, MUTEX, MutexKind::Normal).unwrap();
            assert!(matches!(
                table.lock(a, MUTEX, MutexKind::Normal),
                Err(ThreadError::Posix(EDEADLK))
            ));
            assert_eq!(table.trylock(a, MUTEX, MutexKind::Normal), EBUSY);

            // First touched here: registered with the kind the call names.
            assert!(matches!(
                table.lock(a, MUTEX + 1, MutexKind::Recursive).unwrap(),
                LockStep::Acquired
            ));
            assert!(matches!(
                table.lock(a, MUTEX + 1, MutexKind::Normal).unwrap(),
                LockStep::Acquired
            ));
            assert_eq!(table.trylock(a, MUTEX + 1, MutexKind::Normal), 0);
            for _ in 0..2 {
                table.unlock(&mut scheduler, a, MUTEX + 1).unwrap();
                assert_eq!(table.trylock(b, MUTEX + 1, MutexKind::Normal), EBUSY);
            }
            table.unlock(&mut scheduler, a, MUTEX + 1).unwrap();
            assert_eq!(table.trylock(b, MUTEX + 1, MutexKind::Normal), 0);

            // A normal mutex's owner waits behind itself.
            table.lock(a, MUTEX + 2, MutexKind::Normal).unwrap();
            assert_eq!(table.trylock(a, MUTEX + 2, MutexKind::Normal), EBUSY);
            assert!(matches!(
                table.lock(a, MUTEX + 2, MutexKind::Normal).unwrap(),
                LockStep::MustBlock
            ));
        }

        #[test]
        fn a_normal_mutex_unlock_checks_no_owner() {
            let mut table = ThreadTable::default();
            let mut scheduler = DetAdapter::new(1);
            let a = scheduler.spawn("a").unwrap();
            let b = scheduler.spawn("b").unwrap();
            for task in [a, b] {
                table.register(task);
            }

            // Another thread's unlock frees it; an unlocked one stays so.
            table.lock(a, MUTEX, MutexKind::Normal).unwrap();
            table.unlock(&mut scheduler, b, MUTEX).unwrap();
            assert_eq!(table.mutexes[&MUTEX].owner, None);
            table.unlock(&mut scheduler, a, MUTEX).unwrap();
            assert_eq!(table.trylock(b, MUTEX, MutexKind::Normal), 0);

            // The owner parked on its own relock resumes holding it once
            // another thread unlocks (a binary-semaphore hand-off).
            scheduler.scheduler.select(Some(a)).unwrap();
            table.lock(a, MUTEX + 1, MutexKind::Normal).unwrap();
            assert!(matches!(
                table.lock(a, MUTEX + 1, MutexKind::Normal).unwrap(),
                LockStep::MustBlock
            ));
            scheduler.park(a, "mutex").unwrap();
            table.unlock(&mut scheduler, b, MUTEX + 1).unwrap();
            assert_eq!(table.mutexes[&(MUTEX + 1)].owner, Some(a));
            assert_eq!(table.mutexes[&(MUTEX + 1)].count, 1);

            // Every other type checks the owner.
            for (key, kind) in [
                (MUTEX + 2, MutexKind::ErrorCheck),
                (MUTEX + 3, MutexKind::Recursive),
                (MUTEX + 4, MutexKind::NormalOwned),
            ] {
                table.lock(a, key, kind).unwrap();
                assert!(matches!(
                    table.unlock(&mut scheduler, b, key),
                    Err(ThreadError::Posix(EPERM))
                ));
                table.unlock(&mut scheduler, a, key).unwrap();
                assert!(matches!(
                    table.unlock(&mut scheduler, a, key),
                    Err(ThreadError::Posix(EPERM))
                ));
            }
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn robust_and_priority_inheriting_normal_mutexes_check_the_owner() {
            assert_eq!(MutexKind::from_glibc(0), MutexKind::Normal);
            assert_eq!(MutexKind::from_glibc(3), MutexKind::Normal);
            // Priority protection (64) and elision (256) leave it unchecked.
            assert_eq!(MutexKind::from_glibc(64 | 256), MutexKind::Normal);
            assert_eq!(MutexKind::from_glibc(16), MutexKind::NormalOwned);
            assert_eq!(MutexKind::from_glibc(32 | 3), MutexKind::NormalOwned);
            assert_eq!(MutexKind::from_glibc(16 | 1), MutexKind::Recursive);
            assert_eq!(MutexKind::from_glibc(32 | 2), MutexKind::ErrorCheck);
        }

        #[test]
        fn a_recursive_mutex_held_twice_survives_a_cond_wait() {
            let mut table = ThreadTable::default();
            let mut scheduler = DetAdapter::new(1);
            let waiter = scheduler.spawn("waiter").unwrap();
            let signaler = scheduler.spawn("signaler").unwrap();
            table.register(waiter);
            table.register(signaler);
            table.init_mutex(MUTEX, MutexKind::Recursive);
            table.init_cond(COND, ClockKind::Realtime);

            table.lock(waiter, MUTEX, MutexKind::Recursive).unwrap();
            table.lock(waiter, MUTEX, MutexKind::Recursive).unwrap();
            scheduler.scheduler.select(Some(waiter)).unwrap();
            table
                .cond_wait(&mut scheduler, waiter, COND, MUTEX)
                .unwrap();
            // One unlock of two: the waiter still holds it.
            assert_eq!(table.mutexes[&MUTEX].owner, Some(waiter));
            scheduler.scheduler.park(waiter, "cond").unwrap();

            // The signal counts the waiter's hold again and wakes it, rather
            // than queueing it behind itself.
            scheduler.scheduler.select(Some(signaler)).unwrap();
            table.cond_signal(&mut scheduler, COND).unwrap();
            let entry = &table.mutexes[&MUTEX];
            assert_eq!((entry.owner, entry.count), (Some(waiter), 2));
            assert!(entry.waiters.is_empty());
        }

        #[test]
        fn contended_mutex_wakes_waiters_in_fifo_order() {
            let mut table = ThreadTable::default();
            let mut scheduler = DetAdapter::new(1);
            let a = scheduler.spawn("a").unwrap();
            let b = scheduler.spawn("b").unwrap();
            let c = scheduler.spawn("c").unwrap();
            for task in [a, b, c] {
                table.register(task);
            }

            // a takes the mutex; b then c arrive and block behind it, each
            // parking after selection so the scheduler transitions stay valid.
            scheduler.scheduler.select(Some(a)).unwrap();
            assert!(matches!(
                table.lock(a, MUTEX, MutexKind::Normal).unwrap(),
                LockStep::Acquired
            ));
            scheduler.yield_task(a).unwrap();

            scheduler.scheduler.select(Some(b)).unwrap();
            assert!(matches!(
                table.lock(b, MUTEX, MutexKind::Normal).unwrap(),
                LockStep::MustBlock
            ));
            scheduler.park(b, "mutex").unwrap();

            scheduler.scheduler.select(Some(c)).unwrap();
            assert!(matches!(
                table.lock(c, MUTEX, MutexKind::Normal).unwrap(),
                LockStep::MustBlock
            ));
            scheduler.park(c, "mutex").unwrap();

            // Unlocking hands ownership to the head of the FIFO queue and wakes
            // exactly that waiter.
            table.unlock(&mut scheduler, a, MUTEX).unwrap();
            assert_eq!(table.mutexes[&MUTEX].owner, Some(b));
            table.unlock(&mut scheduler, b, MUTEX).unwrap();
            assert_eq!(table.mutexes[&MUTEX].owner, Some(c));
            table.unlock(&mut scheduler, c, MUTEX).unwrap();
            assert_eq!(table.mutexes[&MUTEX].owner, None);
        }

        #[test]
        fn rwlock_trylock_and_deadlock_reporting() {
            let mut table = ThreadTable::default();
            let mut scheduler = DetAdapter::new(1);
            let a = TaskId(1);
            let b = TaskId(2);

            let kind = RwLockKind::PreferReader;

            // A write hold excludes both a reader and another writer; the
            // holder's blocking re-acquire is a deadlock, its tries are busy.
            assert!(matches!(
                table.rwlock_wrlock(a, RWLOCK, kind).unwrap(),
                LockStep::Acquired
            ));
            assert_eq!(table.rwlock_trywrlock(b, RWLOCK, kind), EBUSY);
            assert_eq!(table.rwlock_tryrdlock(RWLOCK, kind), EBUSY);
            assert_eq!(table.rwlock_trywrlock(a, RWLOCK, kind), EBUSY);
            assert!(matches!(
                table.rwlock_rdlock(a, RWLOCK, kind),
                Err(ThreadError::Posix(EDEADLK))
            ));
            assert!(matches!(
                table.rwlock_wrlock(a, RWLOCK, kind),
                Err(ThreadError::Posix(EDEADLK))
            ));

            // Releasing lets multiple readers share, but a writer is then busy.
            table.rwlock_unlock(&mut scheduler, a, RWLOCK).unwrap();
            assert_eq!(table.rwlock_tryrdlock(RWLOCK, kind), 0);
            assert_eq!(table.rwlock_tryrdlock(RWLOCK, kind), 0);
            assert_eq!(table.rwlocks[&RWLOCK].readers, 2);
            assert_eq!(table.rwlock_trywrlock(a, RWLOCK, kind), EBUSY);

            // A held rwlock cannot be destroyed; an idle one can.
            assert!(matches!(
                table.destroy_rwlock(RWLOCK),
                Err(ThreadError::Posix(EBUSY))
            ));
            table.rwlock_unlock(&mut scheduler, a, RWLOCK).unwrap();
            table.rwlock_unlock(&mut scheduler, b, RWLOCK).unwrap();
            assert!(table.destroy_rwlock(RWLOCK).is_ok());
        }

        /// Two readers hold the lock, a writer waits behind them, and a third
        /// reader arrives: the lock's kind decides whether it barges past the
        /// writer and who is granted the lock when the writer releases.
        fn rwlock_preference(kind: RwLockKind) {
            let mut table = ThreadTable::default();
            let mut scheduler = DetAdapter::new(1);
            let r1 = scheduler.spawn("r1").unwrap();
            let r2 = scheduler.spawn("r2").unwrap();
            let w1 = scheduler.spawn("w1").unwrap();
            let r3 = scheduler.spawn("r3").unwrap();
            let w2 = scheduler.spawn("w2").unwrap();
            let r4 = scheduler.spawn("r4").unwrap();
            for task in [r1, r2, w1, r3, w2, r4] {
                table.register(task);
            }
            table.init_rwlock(RWLOCK, kind);
            let readers_barge = kind != RwLockKind::PreferWriterNonrecursive;
            let writer_first = kind != RwLockKind::PreferReader;

            // Two readers share the lock.
            for reader in [r1, r2] {
                scheduler.scheduler.select(Some(reader)).unwrap();
                assert!(matches!(
                    table.rwlock_rdlock(reader, RWLOCK, kind).unwrap(),
                    LockStep::Acquired
                ));
                scheduler.yield_task(reader).unwrap();
            }
            assert_eq!(table.rwlocks[&RWLOCK].readers, 2);

            // A writer arrives and blocks behind the active readers.
            scheduler.scheduler.select(Some(w1)).unwrap();
            assert!(matches!(
                table.rwlock_wrlock(w1, RWLOCK, kind).unwrap(),
                LockStep::MustBlock
            ));
            scheduler.park(w1, "rwlock-write").unwrap();

            // A new reader barges past the waiting writer only when readers
            // are preferred.
            scheduler.scheduler.select(Some(r3)).unwrap();
            let step = table.rwlock_rdlock(r3, RWLOCK, kind).unwrap();
            if readers_barge {
                assert!(matches!(step, LockStep::Acquired));
                scheduler.yield_task(r3).unwrap();
                table.rwlock_unlock(&mut scheduler, r3, RWLOCK).unwrap();
            } else {
                assert!(matches!(step, LockStep::MustBlock));
                scheduler.park(r3, "rwlock-read").unwrap();
            }

            // First reader releases: one reader remains, nothing is granted.
            table.rwlock_unlock(&mut scheduler, r1, RWLOCK).unwrap();
            assert_eq!(table.rwlocks[&RWLOCK].readers, 1);
            assert_eq!(table.rwlocks[&RWLOCK].writer, None);

            // Last reader releases: the waiting writer is granted.
            table.rwlock_unlock(&mut scheduler, r2, RWLOCK).unwrap();
            assert_eq!(table.rwlocks[&RWLOCK].writer, Some(w1));
            assert_eq!(table.rwlocks[&RWLOCK].readers, 0);

            // With the writer holding it, a reader and a second writer wait.
            scheduler.scheduler.select(Some(r4)).unwrap();
            assert!(matches!(
                table.rwlock_rdlock(r4, RWLOCK, kind).unwrap(),
                LockStep::MustBlock
            ));
            scheduler.park(r4, "rwlock-read").unwrap();
            scheduler.scheduler.select(Some(w2)).unwrap();
            assert!(matches!(
                table.rwlock_wrlock(w2, RWLOCK, kind).unwrap(),
                LockStep::MustBlock
            ));
            scheduler.park(w2, "rwlock-write").unwrap();

            // The writer releases to the preferred side: every blocked reader
            // at once, or the next writer.
            table.rwlock_unlock(&mut scheduler, w1, RWLOCK).unwrap();
            let entry = &table.rwlocks[&RWLOCK];
            if writer_first {
                assert_eq!(entry.writer, Some(w2));
                let waiting = if readers_barge { 1 } else { 2 };
                assert_eq!(entry.read_waiters.len(), waiting);
            } else {
                assert_eq!(entry.writer, None);
                assert_eq!(entry.readers, 1);
                assert!(entry.read_waiters.is_empty());
            }
        }

        #[test]
        fn rwlock_prefers_readers_by_default() {
            rwlock_preference(RwLockKind::default());
        }

        #[test]
        fn rwlock_can_hand_writer_to_writer() {
            rwlock_preference(RwLockKind::PreferWriter);
        }

        #[test]
        fn rwlock_can_prefer_writers_over_new_readers() {
            rwlock_preference(RwLockKind::PreferWriterNonrecursive);
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn rwlock_kinds_decode_as_glibc_compares_them() {
            assert_eq!(RwLockKind::from_glibc(0), RwLockKind::PreferReader);
            assert_eq!(RwLockKind::from_glibc(1), RwLockKind::PreferWriter);
            assert_eq!(
                RwLockKind::from_glibc(2),
                RwLockKind::PreferWriterNonrecursive
            );
        }

        #[test]
        fn a_join_that_could_never_end_is_edeadlk() {
            let mut table = ThreadTable::default();
            let (a, b) = (TaskId(1), TaskId(2));
            table.register(a);
            table.register(b);
            assert!(matches!(
                table.begin_join(a, a),
                Err(ThreadError::Posix(EDEADLK))
            ));
            assert!(matches!(
                table.begin_join(a, b).unwrap(),
                JoinStep::MustBlock
            ));
            // b joining a, which waits to join b.
            assert!(matches!(
                table.begin_join(b, a),
                Err(ThreadError::Posix(EDEADLK))
            ));
            // A detached thread joining itself: not joinable, before the
            // deadlock.
            let c = TaskId(3);
            table.register(c);
            table.detach(c).unwrap();
            assert!(matches!(
                table.begin_join(c, c),
                Err(ThreadError::Posix(EINVAL))
            ));
        }

        #[test]
        fn join_delivers_exit_value_after_target_finishes() {
            let mut table = ThreadTable::default();
            let mut scheduler = DetAdapter::new(1);
            let main = scheduler.spawn_running();
            let worker = SchedulerDriver::spawn(&mut scheduler.scheduler, "worker").unwrap();
            table.register(worker);

            assert!(matches!(
                table.begin_join(main, worker).unwrap(),
                JoinStep::MustBlock
            ));
            // The joiner parks; hand the baton to the worker.
            scheduler.park(main, "join").unwrap();
            scheduler.scheduler.select(Some(worker)).unwrap();

            table.exit(&mut scheduler, worker, 42).unwrap();
            // The worker's exit re-runs the joiner.
            assert_eq!(scheduler.next().unwrap(), Some(main));
            assert_eq!(table.take_join_result(worker), 42);
        }

        #[test]
        fn cond_wait_reacquires_mutex_on_signal_without_spurious_wakeups() {
            let mut table = ThreadTable::default();
            let mut scheduler = DetAdapter::new(1);
            let waiter = scheduler.spawn("waiter").unwrap();
            let signaler = scheduler.spawn("signaler").unwrap();
            table.register(waiter);
            table.register(signaler);
            table.init_mutex(MUTEX, MutexKind::Normal);
            table.init_cond(COND, ClockKind::Realtime);

            // The waiter owns the mutex, then waits on the condition.
            assert!(matches!(
                table.lock(waiter, MUTEX, MutexKind::Normal).unwrap(),
                LockStep::Acquired
            ));
            scheduler.scheduler.select(Some(waiter)).unwrap();
            table
                .cond_wait(&mut scheduler, waiter, COND, MUTEX)
                .unwrap();
            assert_eq!(table.mutexes[&MUTEX].owner, None);
            scheduler.scheduler.park(waiter, "cond").unwrap();

            // A signal with the mutex free grants it back to the waiter.
            scheduler.scheduler.select(Some(signaler)).unwrap();
            table.cond_signal(&mut scheduler, COND).unwrap();
            assert_eq!(table.mutexes[&MUTEX].owner, Some(waiter));
            assert!(table.conds[&COND].waiters.is_empty());

            // A second signal with no waiter is a no-op (no spurious wakeup).
            table.cond_signal(&mut scheduler, COND).unwrap();
        }

        #[test]
        fn all_threads_parked_is_an_explicit_deadlock() {
            // Two managed tasks that each block waiting on the other deadlock;
            // the scheduler reports it rather than hanging.
            let mut scheduler = DetAdapter::new(1);
            let a = scheduler.spawn_running();
            let b = SchedulerDriver::spawn(&mut scheduler.scheduler, "b").unwrap();
            scheduler.park(a, "wait-b").unwrap();
            assert_eq!(scheduler.next().unwrap(), Some(b));
            scheduler.park(b, "wait-a").unwrap();
            assert!(scheduler.next().is_err());
        }
    }
}

/// The recorder-budget exception to patina's fail-closed shutdown: a run that
/// outgrew its trace budget keeps its own verdict and says so in one greppable
/// line, while every other finalization failure still aborts.
#[cfg(test)]
mod over_budget_trace_tests {
    use super::*;

    /// The refusal `Context::finish` returns when the serialized bundle is over
    /// budget, verbatim in shape (see `enforce_trace_byte_limit`).
    fn over_budget() -> TraceError {
        TraceError::ResourceLimit {
            message: format!(
                "serialized trace is {} bytes; limit is {MAX_TRACE_BYTES}; reduce recorded event \
                 count or payload volume, or split the run",
                MAX_TRACE_BYTES + 1
            ),
            bytes: Some((MAX_TRACE_BYTES + 1, MAX_TRACE_BYTES)),
        }
    }

    #[test]
    fn an_over_budget_trace_is_classified_and_reported_with_its_figures() {
        let error = over_budget();
        assert!(
            error.is_resource_limit(),
            "the shutdown downgrade keys off this predicate; got {error}"
        );
        let (bytes, limit) = error.resource_limit_bytes().expect("a byte budget");
        assert_eq!((bytes, limit), (MAX_TRACE_BYTES + 1, MAX_TRACE_BYTES));

        let diagnostic = over_budget_diagnostic(&error);
        let mut lines = diagnostic.lines();
        assert_eq!(
            lines.next().unwrap(),
            format!(
                "PATINA_INFRA trace=incomplete reason=resource-limit bytes={bytes} limit={limit}"
            )
        );
        let human = lines.next().unwrap();
        assert!(
            human.contains("verdict stands unchanged") && human.contains("unusable for replay"),
            "the human line must say the run stands and the trace does not; got {human}"
        );
        assert!(lines.next().is_none(), "the report is exactly two lines");
    }

    #[test]
    fn a_broken_recorder_is_not_downgraded() {
        // The shutdown path downgrades ONLY a budget refusal. An I/O failure —
        // the shape an unwritable `--record` path takes — must stay fatal.
        let broken = RuntimeError::Io {
            action: "write temporary trace".into(),
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        };
        assert!(
            !matches!(&broken, RuntimeError::Trace(error) if error.is_resource_limit()),
            "an I/O failure must not take the budget exception"
        );
        assert_eq!(runtime_errno(&broken), EIO);
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn coverage_summary_counts_hits_and_saturation() {
        let counters = [0u32, 2, u32::MAX];
        let ranges = [CoverageRange {
            start: counters.as_ptr() as usize,
            len: counters.len(),
        }];
        let summary = coverage_summary(&ranges);
        assert_eq!(summary.edges_total, 3);
        assert_eq!(summary.edges_covered, 2);
        assert_eq!(summary.covered_permille, 666);
        assert_eq!(summary.hits_total, u64::from(2u32) + u64::from(u32::MAX));
        assert_eq!(summary.hits_max, u32::MAX);
        assert_eq!(summary.saturated, 1);
    }

    #[test]
    fn requested_coverage_with_zero_ranges_refuses() {
        let error = prepare_coverage_output(true, &[], &[]).unwrap_err();
        eprintln!("D1_RED {error}");
        assert!(
            error.contains("requested coverage is unavailable")
                && error.contains("zero SanitizerCoverage guard ranges")
                && error.contains("cargo patina build --yield-points"),
            "D1 refusal should name the missing instrumentation; got {error}"
        );
    }

    #[test]
    fn requested_coverage_with_zero_hits_refuses() {
        let counters = [0u32, 0];
        let pcs = [
            patina_yield_point as *const () as usize,
            0usize,
            patina_yield_point as *const () as usize,
            0usize,
        ];
        let guards = [CoverageRange {
            start: counters.as_ptr() as usize,
            len: counters.len(),
        }];
        let pc_ranges = [CoverageRange {
            start: pcs.as_ptr() as usize,
            len: counters.len(),
        }];
        let error = prepare_coverage_output(true, &guards, &pc_ranges).unwrap_err();
        eprintln!("D1_EMPTY_RED {error}");
        assert!(
            error.contains("requested coverage is empty")
                && error.contains("edges_total=2")
                && error.contains("edges_covered=0"),
            "empty-coverage refusal should name the zero covered count; got {error}"
        );
    }

    #[test]
    fn coverage_count_mismatch_refuses_naming_both_counts() {
        let guards = [CoverageRange {
            start: 0x1000,
            len: 3,
        }];
        let pcs = [CoverageRange {
            start: 0x2000,
            len: 2,
        }];
        let error = prepare_coverage_output(true, &guards, &pcs).unwrap_err();
        eprintln!("D2_RED {error}");
        assert!(
            error.contains("guard/pc-table count mismatch")
                && error.contains("guards=3")
                && error.contains("pcs=2"),
            "D2 refusal should name both counts; got {error}"
        );
    }

    #[test]
    fn coverage_map_serializes_counters_and_anchor_deltas() {
        let counters = [1u32, 0, 7];
        let anchor = patina_yield_point as *const () as usize;
        let pcs = [
            anchor.wrapping_add(4),
            0usize,
            anchor.wrapping_sub(8),
            0usize,
            anchor,
            1usize,
        ];
        let guards = [CoverageRange {
            start: counters.as_ptr() as usize,
            len: counters.len(),
        }];
        let pc_ranges = [CoverageRange {
            start: pcs.as_ptr() as usize,
            len: counters.len(),
        }];
        let map = build_coverage_map(&guards, &pc_ranges).unwrap();
        assert!(map.starts_with(COVERAGE_MAGIC));
        let header_len = COVERAGE_MAGIC.len() + 4 + 8 + 8 + 32;
        assert_eq!(
            &map[header_len..header_len + 12],
            &[1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0]
        );
        let deltas = &map[header_len + 12..];
        assert_eq!(&deltas[0..8], &4i64.to_le_bytes());
        assert_eq!(&deltas[8..16], &(-8i64).to_le_bytes());
        assert_eq!(&deltas[16..24], &0i64.to_le_bytes());
    }

    #[test]
    fn coverage_map_normalizes_unhit_pc_sentinel_and_refuses_hit_sentinel() {
        let counters = [0u32];
        let pcs = [1usize, 0usize];
        let guards = [CoverageRange {
            start: counters.as_ptr() as usize,
            len: counters.len(),
        }];
        let pc_ranges = [CoverageRange {
            start: pcs.as_ptr() as usize,
            len: counters.len(),
        }];
        let map = build_coverage_map(&guards, &pc_ranges).unwrap();
        let delta_start = COVERAGE_MAGIC.len() + 4 + 8 + 8 + 32 + 4;
        assert_eq!(&map[delta_start..delta_start + 8], &0i64.to_le_bytes());

        let hit = [1u32];
        let guards = [CoverageRange {
            start: hit.as_ptr() as usize,
            len: hit.len(),
        }];
        let error = build_coverage_map(&guards, &pc_ranges).unwrap_err();
        assert!(
            error.contains("sentinel pc=1") && error.contains("covered guard"),
            "covered sentinel pc should fail loudly; got {error}"
        );
    }
}

/// Source-level enumeration gate for the shim-bootstrap window.
///
/// The window answers interposed calls WITHOUT reaching `ensure_runtime`, which
/// is exactly the shape that once swallowed a fail-closed init error: a
/// fingerprint-mismatched replay of a clock-only guest spun at 100% CPU instead
/// of aborting. The structural answer is that the window is entered through one
/// predicate that consults the stored init error, so every path is covered by
/// construction — including paths not yet written. These lints keep that true:
/// the flag may not be read anywhere else, and a new call site has to be
/// enumerated here (and given a leg in the cargo-patina e2e
/// `native_replay_init_error_reaches_every_bootstrap_window_entry_point`).
#[cfg(test)]
mod bootstrap_window_lints {
    /// Every function that answers from the shim-bootstrap window, in source
    /// order. The three `os_unfair_lock` sites forward an allocator-internal
    /// lock to the real host primitive; the rest synthesize a value for the
    /// guest.
    const BOOTSTRAP_WINDOW_SITES: &[&str] = &[
        "patina_clock_now",
        "patina_cpu_time_nanos",
        "patina_read_link",
        "patina_os_unfair_lock_lock",
        "patina_os_unfair_lock_trylock",
        "patina_os_unfair_lock_unlock",
    ];

    /// Assembled at runtime so this module's own text cannot match itself.
    fn call_needle() -> String {
        format!("in_shim_bootstrap{}", "()")
    }

    #[test]
    fn the_bootstrap_flag_is_read_only_through_the_guarded_predicate() {
        let source = include_str!("lib.rs");
        let needle = format!("SHIM_BOOTSTRAP.load{}", "(");
        assert_eq!(
            source.matches(&needle).count(),
            1,
            "the bootstrap flag must be read only by the window predicate, which is where the \
             stored init error is consulted; a second reader would answer from the window \
             without that check"
        );
    }

    #[test]
    fn every_bootstrap_window_call_site_is_enumerated() {
        let source = include_str!("lib.rs");
        // One occurrence is the definition itself; the rest are call sites.
        let sites = source.matches(&call_needle()).count() - 1;
        assert_eq!(
            sites,
            BOOTSTRAP_WINDOW_SITES.len(),
            "the shim-bootstrap window gained or lost an answer path: list it in \
             BOOTSTRAP_WINDOW_SITES and give it a leg in the cargo-patina e2e \
             native_replay_init_error_reaches_every_bootstrap_window_entry_point, so a path that \
             answers before the runtime is installed keeps proving it refuses a failed init"
        );
        for site in BOOTSTRAP_WINDOW_SITES {
            assert!(
                source.contains(&format!("fn {site}(")),
                "BOOTSTRAP_WINDOW_SITES names {site}, which this crate does not define"
            );
        }
    }
}

/// Source-level convention lint: `isize`-returning interposer paths (read/
/// write/send/recv shapes) must report errors as `fail(errno) as isize` — `-1`
/// with the errno cell set — never by returning `ThreadError::into_posix()`'s
/// positive errno directly, which a guest would read as a successful byte
/// count (a deadlock-rescue errno of 35 becomes "35 bytes transferred").
/// The positive-return form is correct only for the pthread-convention `c_int`
/// sites, which this pattern does not match.
#[cfg(test)]
mod source_lints {
    #[test]
    fn no_bare_into_posix_on_isize_paths() {
        let source = include_str!("lib.rs");
        // Assembled at runtime so this test's own text cannot match itself.
        let needle = format!(".{}() as isize", "into_posix");
        assert!(
            !source.contains(&needle),
            "an isize-returning interposer path returns a positive errno as a \
             byte count; wrap it in fail(..) so the guest sees -1 with errno"
        );
    }
}

/// Source lints over the C translation unit's shape: the umbrella
/// `c/patina_posix.c` must `#include` exactly the slices [`POSIX_C_FAMILY_SOURCES`]
/// exports, in that order, and those must be exactly the files under `c/posix/`.
/// A slice added on disk but not exported would compile in-tree (the umbrella
/// resolves the include locally) and fail only in an installed `cargo-patina`,
/// whose staged sandbox carries only the exported slices.
#[cfg(test)]
mod posix_source_lints {
    use super::{POSIX_C_FAMILY_SOURCES, POSIX_C_SOURCE};

    /// The names one X-macro list in `c/posix/dlsym.c` holds.
    #[cfg(target_os = "linux")]
    fn routed(list: &str) -> std::collections::BTreeSet<String> {
        let (_, source) = POSIX_C_FAMILY_SOURCES
            .iter()
            .find(|(relative, _)| *relative == "posix/dlsym.c")
            .expect("the dlsym slice is exported");
        let start = source
            .find(&format!("#define {list}(X)"))
            .unwrap_or_else(|| panic!("dlsym.c defines {list}"));
        source[start..]
            .lines()
            .skip(1)
            .map_while(|line| line.trim().strip_prefix("X("))
            .map(|rest| rest.split(')').next().unwrap().to_owned())
            .collect()
    }

    /// Linux's dlsym table is exactly the registry's libc definitions: every
    /// `Modeled` or `Partial` row this architecture defines (`__wrap_dlsym`
    /// answering as `dlsym`), so a name the shim defines is never NULL to a
    /// dynamic lookup and nothing else is ever routed.
    #[cfg(target_os = "linux")]
    #[test]
    fn dlsym_routes_are_the_registry_definitions() {
        use crate::registry::{Platform, SYMBOLS, SymbolStatus};
        let expected: std::collections::BTreeSet<String> = SYMBOLS
            .iter()
            .filter(|row| matches!(row.platform, Platform::Linux | Platform::Both))
            .filter(|row| matches!(row.status, SymbolStatus::Modeled | SymbolStatus::Partial))
            .map(|row| row.name)
            .filter(|name| *name != "__wrap_dlsym")
            .map(str::to_owned)
            .collect();
        let mut table = routed("PATINA_ROUTED");
        let assembly = routed("PATINA_ROUTED_ASM");
        assert!(table.is_disjoint(&assembly));
        table.extend(assembly);
        let x86 = routed("PATINA_ROUTED_X86_64");
        assert!(table.is_disjoint(&x86));
        if cfg!(target_arch = "x86_64") {
            table.extend(x86);
        }
        let missing: Vec<_> = expected.difference(&table).collect();
        let extra: Vec<_> = table.difference(&expected).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "c/posix/dlsym.c's routing lists and the registry disagree: \
             missing {missing:?}, not defined as a libc contract {extra:?}"
        );
    }

    #[test]
    fn posix_umbrella_includes_every_family_slice() {
        let included: Vec<&str> = POSIX_C_SOURCE
            .lines()
            .filter_map(|line| line.strip_prefix("#include \""))
            .map(|rest| rest.trim_end_matches('"'))
            .collect();
        let exported: Vec<&str> = POSIX_C_FAMILY_SOURCES
            .iter()
            .map(|(relative, _)| *relative)
            .collect();
        assert_eq!(
            included, exported,
            "c/patina_posix.c's #include list and POSIX_C_FAMILY_SOURCES must agree, in order"
        );
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("c/posix");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .expect("c/posix exists")
            .map(|entry| format!("posix/{}", entry.unwrap().file_name().to_string_lossy()))
            .collect();
        on_disk.sort();
        let mut exported_sorted: Vec<String> = exported.iter().map(|s| s.to_string()).collect();
        exported_sorted.sort();
        assert_eq!(
            on_disk, exported_sorted,
            "every file under c/posix/ must be exported by POSIX_C_FAMILY_SOURCES and vice versa"
        );
        for (relative, source) in POSIX_C_FAMILY_SOURCES {
            assert!(
                *relative == "posix/core.c" || !source.contains("#include <"),
                "{relative}: system headers belong in posix/core.c, which every slice shares"
            );
        }
    }
}

#[cfg(test)]
mod directory_iteration_tests {
    use super::*;

    #[test]
    fn a_listing_starts_with_dot_and_dot_dot() {
        let file = FsDirectoryEntry {
            name: "a".into(),
            kind: FsEntryKind::File,
        };
        let names = |listed: Vec<FsDirectoryEntry>| {
            ReadDirState::listing(listed)
                .entries
                .into_iter()
                .map(|entry| (entry.name, entry.kind))
                .collect::<Vec<_>>()
        };
        let dir = |name: &str| (name.to_string(), FsEntryKind::Directory);
        // An empty directory (the root included) still lists both.
        assert_eq!(names(Vec::new()), [dir("."), dir("..")]);
        assert_eq!(
            names(vec![file]),
            [dir("."), dir(".."), ("a".into(), FsEntryKind::File)]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_directory_seeks_like_tmpfs_and_never_answers_espipe() {
        use crate::sud::{release_dir_iteration, seek_dir_iteration};
        use linux_raw_sys::general::{SEEK_CUR, SEEK_DATA, SEEK_END, SEEK_SET};
        // A number no other test touches; the position table is keyed by it.
        let fd = 900;
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_CUR), Some(0));
        assert_eq!(seek_dir_iteration(fd, 3, SEEK_SET), Some(3));
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_CUR), Some(3));
        assert_eq!(seek_dir_iteration(fd, -1, SEEK_CUR), Some(2));
        assert_eq!(seek_dir_iteration(fd, -5, SEEK_CUR), None);
        assert_eq!(seek_dir_iteration(fd, -1, SEEK_SET), None);
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_END), None);
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_DATA), None);
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_CUR), Some(2));
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_SET), Some(0));
        release_dir_iteration(fd);
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_CUR), Some(0));
    }
}
