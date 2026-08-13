//! Explicit native C ABI entry points for Patina.
//!
//! Internal crate: the native interposition layer that `cargo patina build`
//! links below a guest binary. The Rust side here exposes prefixed
//! `patina_*` C ABI entry points over the deterministic runtime; the bundled C
//! interposer (`c/patina_posix.c`, exported as [`POSIX_C_SOURCE`])
//! provides the libc-compatible symbols (file, socket, clock, thread, entropy)
//! that route a guest's ordinary `std` calls into it. The prefixed Rust surface
//! deliberately does not export ambient `open`/`read`/pthread symbols, so
//! linking this crate alone cannot silently alter unrelated host operations.
//! Adopters never depend on this crate; see [ARCHITECTURE.md] for the shim
//! design and its fail-closed doctrine.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

/// The POSIX interposer C source, exposed as text so out-of-tree tooling
/// (`cargo patina build`) can reproduce the native link recipe from the
/// installed crate without the workspace source tree. It lives here — the crate
/// that owns `c/patina_posix.c` — so the shim's C and any embedded copy can
/// never drift, and so both this crate and `cargo-patina` package cleanly for
/// publish (each is self-contained; neither reaches across crate boundaries).
pub const POSIX_C_SOURCE: &str = include_str!("../c/patina_posix.c");
/// The companion C header for [`POSIX_C_SOURCE`] (`include/patina_native.h`).
pub const NATIVE_HEADER: &str = include_str!("../include/patina_native.h");

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

use std::cell::{Cell, RefCell, UnsafeCell};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io;
use std::ops::{Deref, DerefMut};
use std::slice;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use patina_dst_abi::{
    ClockKind, EffectError, ErrorCode, Fd, FsDirectoryEntry, FsEntryKind, OpenFlags, SeekWhence,
    TaskId,
};

use patina_dst_driver_api::canonicalize_path;
use patina_dst_fs_crash::CrashFs;
use patina_dst_fs_mem::{FsImage, MemFs};
use patina_dst_runtime::{
    BuggifyKind, Context, CustomOpMode, MAX_TRACE_BYTES, RuntimeBuilder, RuntimeConfig,
    RuntimeError, SiteOutcome, TraceTransport, VerdictKind,
};
pub use thread::{
    patina_cond_broadcast, patina_cond_destroy, patina_cond_init, patina_cond_signal,
    patina_cond_timedwait, patina_cond_wait, patina_futex_wait, patina_futex_wait_timed,
    patina_futex_wake, patina_mutex_destroy, patina_mutex_init, patina_mutex_lock,
    patina_mutex_trylock, patina_mutex_unlock, patina_net_accept, patina_net_bind,
    patina_net_close, patina_net_connect, patina_net_getpeername, patina_net_getsockname,
    patina_net_is_nonblocking, patina_net_kind, patina_net_listen, patina_net_recv,
    patina_net_recvfrom, patina_net_send, patina_net_sendto, patina_net_set_nonblocking,
    patina_net_set_read_timeout, patina_net_shutdown, patina_net_socket, patina_net_stream_recv,
    patina_net_stream_send, patina_net_tcp_connect, patina_rwlock_destroy, patina_rwlock_init,
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
const EIO: c_int = 5;
const EISDIR: c_int = 21;
const ENOENT: c_int = 2;
const ENOSPC: c_int = 28;
#[cfg(target_os = "macos")]
const ENOSYS: c_int = 78;
#[cfg(not(target_os = "macos"))]
const ENOSYS: c_int = 38;
const ENOTDIR: c_int = 20;
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

const EFBIG: c_int = 27;
const EMFILE: c_int = 24;
const ESPIPE: c_int = 29;
const MAX_CAPTURED_STDIO_BYTES: usize = 64 * 1024 * 1024;
const HOST_IO_CHUNK: usize = 64 * 1024;
const URANDOM_FD_BASE: c_int = 0x3fff_ff00;
const URANDOM_FD_SLOTS: usize = 64;

const O_READ: u32 = 1 << 0;
const O_WRITE: u32 = 1 << 1;
const O_CREATE: u32 = 1 << 2;
const O_TRUNCATE: u32 = 1 << 3;
const O_APPEND: u32 = 1 << 4;
const O_EXCLUSIVE: u32 = 1 << 5;
const O_ALL: u32 = O_READ | O_WRITE | O_CREATE | O_TRUNCATE | O_APPEND | O_EXCLUSIVE;

/// A minimal spinlock the shim uses instead of `std::sync::Mutex`.
///
/// The shim interposes `pthread_mutex_*`, so its own `std::sync::Mutex` would
/// recurse straight back into the deterministic layer. A spinlock built on
/// atomics never touches pthread, and every critical section here is short and
/// almost always uncontended: only the managed thread that currently holds the
/// execution baton runs shim code, so contention is limited to brief handoffs.
struct SpinMutex<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the spinlock serializes all access to the interior value, so it is
// safe to share across threads whenever the value may be sent across them.
unsafe impl<T: Send> Sync for SpinMutex<T> {}
// SAFETY: as above; ownership can move across threads.
unsafe impl<T: Send> Send for SpinMutex<T> {}

impl<T> SpinMutex<T> {
    const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    fn lock(&self) -> SpinGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                std::hint::spin_loop();
            }
        }
        // Mark that this thread now holds a shim spinlock, so a reentrant lock
        // interposer (reached only via an allocator-internal allocation on the
        // scheduler path) forwards to the real host primitive instead of
        // deadlocking on this very lock. See `SPIN_DEPTH`.
        spin_depth_inc();
        SpinGuard { mutex: self }
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
        self.mutex.locked.store(false, Ordering::Release);
        spin_depth_dec();
    }
}

static CONTEXT: OnceLock<SpinMutex<Option<Context>>> = OnceLock::new();
static STDIO: OnceLock<SpinMutex<StdioCapture>> = OnceLock::new();
static URANDOM_FDS: SpinMutex<UrandomFds> = SpinMutex::new(UrandomFds {
    open: [false; URANDOM_FD_SLOTS],
});

struct UrandomFds {
    open: [bool; URANDOM_FD_SLOTS],
}

fn urandom_open() -> Result<c_int, c_int> {
    let mut fds = URANDOM_FDS.lock();
    for (index, open) in fds.open.iter_mut().enumerate() {
        if !*open {
            *open = true;
            let index = c_int::try_from(index).expect("urandom slot index fits");
            return Ok(URANDOM_FD_BASE + index);
        }
    }
    Err(EMFILE)
}

fn urandom_index(raw_fd: c_int) -> Option<usize> {
    let relative = raw_fd.checked_sub(URANDOM_FD_BASE)?;
    let index = usize::try_from(relative).ok()?;
    (index < URANDOM_FD_SLOTS).then_some(index)
}

fn urandom_is_open(raw_fd: c_int) -> bool {
    let Some(index) = urandom_index(raw_fd) else {
        return false;
    };
    URANDOM_FDS.lock().open[index]
}

fn urandom_close(raw_fd: c_int) -> Result<(), c_int> {
    let Some(index) = urandom_index(raw_fd) else {
        return Err(EBADF);
    };
    let mut fds = URANDOM_FDS.lock();
    if !fds.open[index] {
        return Err(EBADF);
    }
    fds.open[index] = false;
    Ok(())
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
#[inline]
fn in_shim_bootstrap() -> bool {
    SHIM_BOOTSTRAP.load(Ordering::Acquire)
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
#[cfg(target_os = "macos")]
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
// `dlsym` itself; the `scripts/validate-native-shim.sh` "host-alias" section
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
            std::process::abort();
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
    // `__wrap_dlsym` (patina_posix.c), which answers only from its deterministic
    // entropy routing table; only this shim-internal path
    // reaches the real resolver. Any consumer of the shim staticlib that drives a
    // host vehicle (managed threads / trace-fd I/O / baton) must link
    // `-Wl,--wrap=dlsym`, the single wrap the shim needs (thread creation is a
    // strong-def interposer whose real vehicle this same table resolves, so it
    // needs no wrap of its own); `cargo patina native-build` always links it, and
    // the direct-`cc` validate-native-shim.sh probes pass it explicitly.
    unsafe extern "C" {
        fn __real_dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }
    core::arch::global_asm!(".weak __real_dlsym");

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
        /// The real glibc `syscall(2)` wrapper, the SUD dispatcher's pass-through
        /// vehicle for process-local memory-management rows.
        pub host_syscall: HostSyscall,
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
            std::process::abort();
        }
        ptr
    }

    fn build() -> HostApi {
        // SAFETY: each resolved pointer is transmuted to the real C ABI signature
        // of the glibc symbol it names.
        unsafe {
            HostApi {
                host_read: std::mem::transmute::<*mut c_void, HostRead>(resolve(c"read")),
                host_write: std::mem::transmute::<*mut c_void, HostWrite>(resolve(c"write")),
                host_exit: std::mem::transmute::<*mut c_void, HostExit>(resolve(c"exit")),
                sem_init: std::mem::transmute::<*mut c_void, SemInit>(resolve(c"sem_init")),
                sem_wait: std::mem::transmute::<*mut c_void, SemOp>(resolve(c"sem_wait")),
                sem_post: std::mem::transmute::<*mut c_void, SemOp>(resolve(c"sem_post")),
                host_pthread_create: std::mem::transmute::<*mut c_void, HostPthreadCreate>(
                    resolve(c"pthread_create"),
                ),
                host_pthread_join: std::mem::transmute::<*mut c_void, HostPthreadJoin>(resolve(
                    c"pthread_join",
                )),
                host_syscall: std::mem::transmute::<*mut c_void, HostSyscall>(resolve(c"syscall")),
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

        pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
            self.entries
                .as_mut_slice()
                .iter_mut()
                .map(|(_, value)| value)
        }
    }

    impl<K: Copy + PartialEq, V: Default> HostMap<K, V> {
        /// Return a mutable reference to the value for `key`, inserting a default
        /// value first if absent — the [`std::collections::btree_map::Entry`]
        /// `or_default` the sync tables relied on.
        pub fn entry_or_default(&mut self, key: K) -> &mut V {
            let index = match self.index_of(&key) {
                Some(index) => index,
                None => {
                    self.entries.push((key, V::default()));
                    self.entries.len() - 1
                }
            };
            &mut self.entries.get_mut(index).1
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
    static GUEST_ENV_CSTRING: RefCell<Option<CString>> = const { RefCell::new(None) };
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

/// The mode a descriptor holds an advisory `flock` in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FlockMode {
    Shared,
    Exclusive,
}

/// Advisory `flock` state, keyed by the guest descriptor that holds the lock and
/// recording the deterministic-fs inode the descriptor is open on. Conflicts are
/// resolved against the *inode*, so two independent opens of the same path
/// contend exactly as a real per-file-identity `flock` would (a single-opener
/// database's "already open" error), while a lone opener always acquires. Cleared on
/// `LOCK_UN` and on `close`. This is shim-side state, never a trace record: the
/// inode it keys on is read through the recorded metadata path, so the table
/// rebuilds identically under replay from the same deterministic open sequence.
static FLOCK_TABLE: OnceLock<SpinMutex<BTreeMap<c_int, (u64, FlockMode)>>> = OnceLock::new();

fn flock_table() -> &'static SpinMutex<BTreeMap<c_int, (u64, FlockMode)>> {
    FLOCK_TABLE.get_or_init(|| SpinMutex::new(BTreeMap::new()))
}

/// Release any advisory lock a descriptor holds. Called by `LOCK_UN` and on
/// `close`; a descriptor holding no lock is a no-op.
fn flock_release(raw_fd: c_int) {
    flock_table().lock().remove(&raw_fd);
}

fn set_errno(errno: c_int) {
    LAST_ERRNO.with(|value| value.set(errno));
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
#[cfg(any(target_os = "linux", test))]
pub(crate) fn trap_fatal(message: &str) -> ! {
    let text = format!("patina: {message}\n");
    let _ = host_write_all(2, text.as_bytes());
    std::process::abort();
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
/// run. `abort()` skips the atexit-driven shutdown flush, so the explicit flush
/// here is what preserves that marker; mirrors [`abort_with_init_error`] /
/// [`abort_with_buggify_marker`].
fn abort_after_flushing_output() -> ! {
    let _ = flush_captured_stdio();
    std::process::abort();
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
    std::process::abort();
}

/// Emit the runtime's own init-failure diagnostic and abort the process. The
/// `message` is the runtime's error text — a fingerprint mismatch (incl.
/// plain-vs-`--yield-points` cross-replay), a `--mount` corpus whose hash does
/// not match the recording, a replay-fault-config conflict, and so on. The write
/// goes through the host-alias descriptor I/O (never the interposed `write`);
/// captured guest stdio is flushed first so the diagnostic lands after any
/// buffered output, mirroring the process-class deny-trap path.
fn abort_with_init_error(message: &str) -> ! {
    let _ = flush_captured_stdio();
    let line = format!("patina: the deterministic runtime failed to initialize: {message}\n");
    let _ = host_write_all(2, line.as_bytes());
    std::process::abort();
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
    let _ = flush_captured_stdio();
    let message: &[u8] = b"patina: harness has not installed the runtime yet; an interposed \
effect reached the deterministic boundary before patina_dst_harness::run/run_with installed the \
runtime. Do all configuration and application effects inside the harness closure.\n";
    let _ = host_write_all(2, message);
    std::process::abort();
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
    std::process::abort();
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
    invoke(context).map_err(|error| runtime_errno(&error))
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
        let _ = host_write_all(
            2,
            b"patina native shim fatal: a managed scheduling operation reached the trace after \
`main` returned; the post-main teardown window must take no recorded scheduling points\n",
        );
        std::process::abort();
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
    // scrubbed and public getenv routes through patina_getenv; do not recurse
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

/// Read an inherited host descriptor to EOF using the non-interposed host alias,
/// mirroring `FdTraceTransport::read_bundle`. Used to slurp the filesystem image
/// the supervisor duplicated onto the child before exec.
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
    let Some(fd) = control_fs_image_fd()? else {
        return Ok(MemFs::new());
    };
    let bytes = read_host_fd_to_end(fd).map_err(|error| {
        RuntimeError::Config(format!(
            "failed to read {}: {error}",
            patina_dst_runtime::ENV_FS_IMAGE_FD
        ))
    })?;
    let image = FsImage::decode(&bytes)
        .map_err(|error| RuntimeError::Config(format!("invalid filesystem image: {error}")))?;
    image.into_memfs().map_err(|error| {
        RuntimeError::Config(format!("failed to rebuild filesystem image: {error}"))
    })
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
        *init_error().lock() = Some(error.to_string());
        return fail(runtime_errno(&error));
    }
    let mut guard = slot().lock();
    if guard.is_some() {
        return fail(EALREADY);
    }
    *guard = Some(context);
    // Publish `environ` from the freshly installed guest env map. The startup
    // constructor also publishes, but a deferred harness install (or a direct
    // C-ABI embedder) lands here first — and its `--env`/overlay values must be
    // visible to direct `environ` walkers, not just to the `getenv` interposer.
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

fn fd(value: c_int) -> Result<Fd, c_int> {
    u64::try_from(value).map(Fd).map_err(|_| EBADF)
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
    LAST_BOUNDARY_SYMBOL.store(symbol.cast_mut(), Ordering::Relaxed);
}

/// Mark that the packaged C startup constructor finished capture/init/scrub.
#[unsafe(no_mangle)]
pub extern "C" fn patina_note_startup_constructor_finished() {
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
    install(Context::from_config(RuntimeConfig::seeded(seed)))
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_init_crash(seed: u64) -> c_int {
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
        *init_error().lock() = Some(error.to_string());
    }
    install(context)
}

/// Build the runtime from the `PATINA_*` protocol. Idempotent: the packaged
/// startup path (a constructor in the POSIX layer) calls this automatically, so
/// an explicit call from application code that also wants it is a no-op rather
/// than a double-init error.
#[unsafe(no_mangle)]
pub extern "C" fn patina_init_from_env() -> c_int {
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

/// Finalize the runtime, writing any recorded trace and flushing captured
/// stdio. Idempotent: the packaged startup path registers this through `atexit`
/// so record mode finalizes on normal exit without an explicit call, and a
/// second call (for example an application that still calls it explicitly) is a
/// no-op.
#[unsafe(no_mangle)]
pub extern "C" fn patina_shutdown() -> c_int {
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
        std::process::abort();
    }
    if let Err(error) = coverage {
        let line = format!("patina: coverage finalization refused: {error}\n");
        let _ = host_write_all(2, line.as_bytes());
        std::process::abort();
    }
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

fn report_shutdown_error(message: &str) {
    let line = format!("patina: runtime shutdown failed: {message}\n");
    let _ = host_write_all(2, line.as_bytes());
}

/// Flush captured stdout/stderr to the real host descriptors WITHOUT finalizing
/// the run (unlike [`patina_shutdown`], which also finishes the trace/record).
/// The process-class deny-traps in `c/patina_posix.c` call this immediately
/// before `abort()`: `abort()` skips the atexit-driven shutdown flush, so
/// without it the guest's buffered output and the deny diagnostic would be lost.
#[unsafe(no_mangle)]
pub extern "C" fn patina_flush_captured_stdio() -> c_int {
    match flush_captured_stdio() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

fn flush_captured_stdio() -> io::Result<()> {
    let mut capture = stdio_slot().lock();
    let stdout = std::mem::take(&mut capture.stdout);
    let stderr = std::mem::take(&mut capture.stderr);
    drop(capture);
    host_write_all(1, &stdout)?;
    host_write_all(2, &stderr)
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
    if fd != 1 && fd != 2 {
        return fail(EBADF) as isize;
    }
    if length != 0 && source.is_null() {
        return fail(EINVAL) as isize;
    }
    if let Err(errno) = thread::sched_point() {
        return fail(errno) as isize;
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
    LAST_ERRNO.with(Cell::get)
}

/// Look up one deterministic guest environment value for the POSIX `getenv`
/// interposer. Before the startup constructor finishes, return NULL rather than
/// reading the host environment: Rust/libc startup code can probe environment
/// variables before Patina's constructor runs, and hiding those probes preserves
/// the historical empty ambient environment without breaking ordinary guests.
/// After startup, a standalone (non-Patina) run with no runtime keeps the same
/// empty deterministic environment and returns NULL.
///
/// # Safety
/// `name` must be a valid NUL-terminated C string when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_getenv(name: *const c_char) -> *mut c_char {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(name) => name,
        Err(_) => return std::ptr::null_mut(),
    };
    if let Some(message) = init_error().lock().clone() {
        abort_with_init_error(&message);
    }
    if !STARTUP_CONSTRUCTOR_FINISHED.load(Ordering::Acquire) {
        return std::ptr::null_mut();
    }
    let value = {
        let guard = slot().lock();
        let missing_context = guard.is_none();
        let value = guard
            .as_ref()
            .and_then(|context| context.guest_env_var(name).map(str::to_owned));
        drop(guard);
        if missing_context && missing_context_is_pre_harness_install() {
            abort_harness_before_install();
        }
        value
    };
    let Some(value) = value else {
        return std::ptr::null_mut();
    };
    let Ok(value) = CString::new(value) else {
        // RuntimeConfig validation rejects NUL bytes before build; keep this path
        // fail-closed if an embedder bypasses that invariant.
        let _ = host_write_all(
            2,
            b"patina: deterministic guest environment contained a NUL byte; failing closed\n",
        );
        std::process::abort();
    };
    GUEST_ENV_CSTRING.with(|slot| {
        let mut slot = slot.borrow_mut();
        *slot = Some(value);
        slot.as_ref()
            .map(|value| value.as_ptr().cast_mut())
            .unwrap_or(std::ptr::null_mut())
    })
}

// ---- Deterministic guest environment mutation --------------------------------
//
// `setenv`/`unsetenv`/`clearenv` mutate the installed context's guest env map,
// which is the run's single source of truth for the environment. Two readers
// must agree with it: the `getenv` interposer above, which consults the map
// directly, and the process `environ` array that `std::env::vars` and other
// direct walkers iterate. Keeping them coherent means republishing `environ`
// after every mutation.
//
// Republishing happens through a C-registered callback rather than a direct
// reference to `environ`/`_NSGetEnviron`. The dependency must point C→Rust: the
// Rust lib's own test binary links no C objects, so naming a C function here
// would leave it with an undefined symbol (the same trap documented for
// `PATINA_SUD_ARMED`). Registration also keeps `environ` storage owned by the
// one layer that already manages it.
//
// Mutations are guest-driven and therefore deterministic. They are NOT boundary
// effects: like `patina_getenv` they take no scheduling point, consume no step
// budget, and emit no trace record, so replay reproduces them by re-executing
// the guest. Only the startup `--env` map lives in the trace metadata.

/// `void (*)(char **)` installed by the POSIX layer's constructor, or null when
/// no C layer is linked (direct C-ABI embedders and the Rust lib tests). Stored
/// as a data pointer because Rust has no atomic function-pointer type.
static ENVIRON_INSTALLER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

type EnvironInstaller = unsafe extern "C" fn(*mut *mut c_char);

/// Register the callback that publishes a rebuilt `environ` array. Called once
/// from the POSIX constructor before the runtime is installed; a null pointer
/// unregisters, leaving env mutation purely map-local.
///
/// # Safety
/// `installer` must be a valid `void (*)(char **)` for the life of the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_register_environ_installer(installer: Option<EnvironInstaller>) {
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

/// Rebuild the `environ` array from `env` and hand it to the registered
/// installer. The previous array and its entry strings are deliberately leaked,
/// glibc-style: a guest may still hold a `getenv` result or an `environ` slot
/// from before the mutation, and freeing replaced storage would dangle it. The
/// leak is bounded by the guest's own mutation count and is deterministic.
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
            std::process::abort();
        };
        entries.push(entry.into_raw());
    }
    entries.push(std::ptr::null_mut());
    let array = Box::leak(entries.into_boxed_slice()).as_mut_ptr();
    // SAFETY: `array` is a live, NUL-terminated `char **` that outlives the
    // process, which is exactly what the installer stores into `environ`.
    unsafe { installer(array) };
}

/// Publish `environ` from the installed context, or from an empty map when no
/// runtime is installed. Called by the POSIX constructor after the ambient host
/// environment is scrubbed, so `environ` reflects the deterministic map (the
/// startup `--env` set, or nothing) from the guest's first instruction.
#[unsafe(no_mangle)]
pub extern "C" fn patina_publish_environ() {
    let guard = slot().lock();
    match guard.as_ref() {
        Some(context) => publish_environ(context.guest_env()),
        None => publish_environ(&BTreeMap::new()),
    }
}

/// Borrow a C string argument as UTF-8, or `None` when null or not UTF-8.
///
/// # Safety
/// `value` must be a valid NUL-terminated C string when non-null.
unsafe fn env_str<'a>(value: *const c_char) -> Option<&'a str> {
    if value.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(value) }.to_str().ok()
}

/// Mutate the installed context's guest environment and republish `environ`.
/// Both happen under one `slot()` lock so concurrent guest threads can never
/// install an `environ` array that disagrees with the map.
fn with_guest_env(apply: impl FnOnce(&mut Context) -> Result<(), RuntimeError>) -> c_int {
    if let Some(message) = init_error().lock().clone() {
        abort_with_init_error(&message);
    }
    if !STARTUP_CONSTRUCTOR_FINISHED.load(Ordering::Acquire) {
        // Unlike `getenv` — which hides pre-startup probes behind NULL and stays
        // consistent, because the deterministic environment really is empty then
        // — dropping a pre-startup WRITE would leave the guest and the runtime
        // disagreeing about the environment for the rest of the run. A
        // constructor beat Patina's; name it and fail closed.
        abort_preinit_interposed_call();
    }
    let mut guard = slot().lock();
    let Some(context) = guard.as_mut() else {
        drop(guard);
        if missing_context_is_pre_harness_install() {
            abort_harness_before_install();
        }
        // A standalone run (or one past `patina_shutdown`) has no deterministic
        // environment to mutate. `getenv` can answer NULL truthfully there; a
        // write has nowhere to land, so refuse rather than pretend it took.
        let _ = host_write_all(
            2,
            b"patina: environment mutation requires an installed deterministic runtime; failing closed\n",
        );
        return fail(ENOSYS);
    };
    // The only failure the guest-env validators raise is a malformed key or
    // value, which POSIX reports as EINVAL — a normal modeled outcome, not a
    // refusal, so it carries no diagnostic.
    if apply(context).is_err() {
        return fail(EINVAL);
    }
    publish_environ(context.guest_env());
    set_errno(0);
    0
}

/// Deterministic `setenv`.
///
/// # Safety
/// `name` and `value` must be valid NUL-terminated C strings when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_setenv(
    name: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    // SAFETY: forwarded from the `setenv` interposer's C ABI contract.
    let (Some(name), Some(value)) = (unsafe { env_str(name) }, unsafe { env_str(value) }) else {
        return fail(EINVAL);
    };
    if name.is_empty() || name.contains('=') {
        return fail(EINVAL);
    }
    with_guest_env(|context| {
        context.guest_env_set(name, value, overwrite != 0)?;
        Ok(())
    })
}

/// Deterministic `unsetenv`. Removing an absent key succeeds, per POSIX.
///
/// # Safety
/// `name` must be a valid NUL-terminated C string when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_unsetenv(name: *const c_char) -> c_int {
    // SAFETY: forwarded from the `unsetenv` interposer's C ABI contract.
    let Some(name) = (unsafe { env_str(name) }) else {
        return fail(EINVAL);
    };
    if name.is_empty() || name.contains('=') {
        return fail(EINVAL);
    }
    with_guest_env(|context| {
        context.guest_env_remove(name)?;
        Ok(())
    })
}

/// Deterministic `clearenv` (glibc/musl). Empties the map so no reader — the
/// `getenv` interposer or a direct `environ` walk — keeps a stale entry.
#[unsafe(no_mangle)]
pub extern "C" fn patina_clearenv() -> c_int {
    with_guest_env(|context| {
        context.guest_env_clear();
        Ok(())
    })
}

/// Fill caller-owned memory with deterministic bytes.
///
/// # Safety
/// `destination` must be writable for `length` bytes when `length` is nonzero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_entropy(destination: *mut c_void, length: usize) -> c_int {
    if length != 0 && destination.is_null() {
        return fail(EINVAL);
    }
    let result = with_context(|context| context.entropy_bytes(length));
    match result {
        Ok(bytes) => {
            if length != 0 {
                // SAFETY: Guaranteed by this function's C ABI contract.
                unsafe {
                    slice::from_raw_parts_mut(destination.cast::<u8>(), length)
                        .copy_from_slice(&bytes);
                }
            }
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Write a deterministic clock value to caller-owned memory.
///
/// # Safety
/// `nanos` must point to writable `uint64_t` storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_clock_now(clock_id: u32, nanos: *mut u64) -> c_int {
    if nanos.is_null() {
        return fail(EINVAL);
    }
    // Bootstrap window (see `SHIM_BOOTSTRAP`): a custom global allocator's own
    // constructor reads the clock for internal timing (tikv-jemallocator's
    // `arena_new` calls `nstime_update` -> `mach_absolute_time`) BEFORE the shim
    // has installed the runtime. That value is allocator-internal, never
    // guest-observable, so answer a fixed zero without touching the runtime — going
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
    if let Some(result) = thread::managed_sleep(clock, deadline_nanos) {
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

/// Deterministic per-process CPU-time proxy in nanoseconds, backing the libc
/// resource-accounting interposers (`getrusage`/`task_info`/`sysinfo`).
///
/// The model is elapsed virtual monotonic time. Under the deterministic
/// scheduler at most one task is runnable at a time and virtual time advances
/// only through recorded `SleepUntil`/deadlock-rescue, so the sum of every
/// thread's run-slices between two observations equals the monotonic delta — the
/// monotonic clock IS the process's summed CPU time. It is read UNRECORDED (the
/// same `monotonic_now_unrecorded` the kqueue reactor uses for deadline scans),
/// so this read emits no trace op, takes no scheduling point, and leaves every
/// existing fingerprint/replay stream byte-for-byte unchanged; the returned value
/// is nonetheless a pure function of simulation state (the guest reaches this
/// call at a deterministic virtual time on record and replay alike).
///
/// Always succeeds writing a value. Before the runtime is installed (a custom
/// allocator's bootstrap timing, or a binary run outside the supervisor) it
/// reports a deterministic 0 rather than auto-installing or aborting: a resource
/// read must never be the thing that forces runtime init, mirroring
/// [`patina_clock_now`]'s bootstrap leg.
///
/// # Safety
/// `nanos` must be non-null and writable for one `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_cpu_time_nanos(nanos: *mut u64) -> c_int {
    if nanos.is_null() {
        return fail(EINVAL);
    }
    // Bootstrap window / no runtime installed: a deterministic zero (see
    // `patina_clock_now`). Never routes through `ensure_runtime`, so an
    // accounting probe cannot trip an auto-install or abort.
    let value = if in_shim_bootstrap() {
        0
    } else {
        with_context_raw(|context| context.monotonic_now_unrecorded()).unwrap_or(0)
    };
    // SAFETY: `nanos` was checked non-null and is writable per the C ABI.
    unsafe { nanos.write(value) };
    set_errno(0);
    0
}

/// Open a path in the deterministic filesystem.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_open(path: *const c_char, flags: u32) -> c_int {
    if flags & !O_ALL != 0 {
        return fail(EINVAL);
    }
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let flags = OpenFlags {
        read: flags & O_READ != 0,
        write: flags & O_WRITE != 0,
        create: flags & O_CREATE != 0,
        truncate: flags & O_TRUNCATE != 0,
        append: flags & O_APPEND != 0,
        exclusive: flags & O_EXCLUSIVE != 0,
    };
    if path == "/dev/urandom" {
        if flags.read
            && !flags.write
            && !flags.create
            && !flags.truncate
            && !flags.append
            && !flags.exclusive
        {
            return match urandom_open() {
                Ok(fd) => {
                    set_errno(0);
                    fd
                }
                Err(errno) => fail(errno),
            };
        }
        return fail(EACCES);
    }
    match with_context(|context| context.fs_open(&path, flags)) {
        Ok(fd) => i32::try_from(fd.0).unwrap_or_else(|_| fail(EOVERFLOW)),
        Err(errno) => fail(errno),
    }
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
    if length != 0 && destination.is_null() {
        return isize::try_from(fail(EINVAL)).expect("-1 fits in isize");
    }
    if urandom_is_open(raw_fd) {
        let result = unsafe { patina_entropy(destination, length) };
        return if result == 0 {
            isize::try_from(length).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        } else {
            fail(patina_errno()) as isize
        };
    }
    let fd = match fd(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return isize::try_from(fail(errno)).expect("-1 fits in isize"),
    };
    match with_context(|context| context.fs_read(fd, length)) {
        Ok(bytes) => {
            if !bytes.is_empty() {
                // SAFETY: Guaranteed by this function's C ABI contract.
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
    if length != 0 && source.is_null() {
        return fail(EINVAL) as isize;
    }
    if urandom_is_open(raw_fd) {
        return fail(EBADF) as isize;
    }
    let fd = match fd(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno) as isize,
    };
    let bytes = if length == 0 {
        &[]
    } else {
        // SAFETY: Guaranteed by this function's C ABI contract.
        unsafe { slice::from_raw_parts(source.cast::<u8>(), length) }
    };
    match with_context(|context| context.fs_write(fd, bytes)) {
        Ok(written) => isize::try_from(written).unwrap_or_else(|_| fail(EOVERFLOW) as isize),
        Err(errno) => fail(errno) as isize,
    }
}

/// Positional read (`pread`): read at `offset` without moving the file cursor.
/// A negative offset is rejected, matching the kernel `pread` contract.
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
    if length != 0 && destination.is_null() {
        return isize::try_from(fail(EINVAL)).expect("-1 fits in isize");
    }
    if urandom_is_open(raw_fd) {
        return fail(ESPIPE) as isize;
    }
    let offset = match u64::try_from(offset) {
        Ok(offset) => offset,
        Err(_) => return isize::try_from(fail(EINVAL)).expect("-1 fits in isize"),
    };
    let fd = match fd(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return isize::try_from(fail(errno)).expect("-1 fits in isize"),
    };
    match with_context(|context| context.fs_read_at(fd, offset, length)) {
        Ok(bytes) => {
            if !bytes.is_empty() {
                // SAFETY: Guaranteed by this function's C ABI contract.
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

/// Positional write (`pwrite`): write at `offset` without moving the file
/// cursor. A negative offset is rejected, matching the kernel `pwrite` contract.
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
    if length != 0 && source.is_null() {
        return fail(EINVAL) as isize;
    }
    if urandom_is_open(raw_fd) {
        return fail(EBADF) as isize;
    }
    let offset = match u64::try_from(offset) {
        Ok(offset) => offset,
        Err(_) => return fail(EINVAL) as isize,
    };
    let fd = match fd(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno) as isize,
    };
    let bytes = if length == 0 {
        &[]
    } else {
        // SAFETY: Guaranteed by this function's C ABI contract.
        unsafe { slice::from_raw_parts(source.cast::<u8>(), length) }
    };
    match with_context(|context| context.fs_write_at(fd, offset, bytes)) {
        Ok(written) => isize::try_from(written).unwrap_or_else(|_| fail(EOVERFLOW) as isize),
        Err(errno) => fail(errno) as isize,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_close(raw_fd: c_int) -> c_int {
    if urandom_index(raw_fd).is_some() {
        return match urandom_close(raw_fd) {
            Ok(()) => {
                set_errno(0);
                0
            }
            Err(errno) => fail(errno),
        };
    }
    let fd = match fd(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno),
    };
    let result = match with_context(|context| context.fs_close(fd)) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    };
    // flock(2): a descriptor's advisory lock is released when the descriptor is
    // closed. (Deterministic fd numbers are never reused, so no later open can
    // inherit a stale entry.)
    flock_release(raw_fd);
    result
}

/// `LOCK_SH`/`LOCK_EX`/`LOCK_NB`/`LOCK_UN` from `<sys/file.h>` — identical values
/// on Linux and Darwin.
const LOCK_SH: c_int = 1;
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const LOCK_UN: c_int = 8;

/// Advisory whole-file lock over the deterministic filesystem — the interposed
/// `flock` in `c/patina_posix.c`. A single-opener database (via std
/// `File::try_lock`) takes one `LOCK_EX | LOCK_NB` on open; a lone opener always
/// acquires it.
///
/// The lock is keyed on the descriptor's deterministic-fs inode, so two
/// independent opens of the *same* path contend faithfully: a non-blocking
/// request that would collide with an incompatible lock held on another
/// descriptor reports `EWOULDBLOCK` (a single-opener database surfaces this as
/// an "already open" error). `LOCK_SH` conflicts only with a held
/// `LOCK_EX`; `LOCK_EX` conflicts with any held lock. Re-locking or upgrading on
/// the *same* descriptor is always allowed (it replaces that descriptor's entry
/// and never self-conflicts). The lock clears on `LOCK_UN` and on `close`.
///
/// Simplifications, sound for the supported surface: a *blocking* request that
/// would contend fails closed with `EDEADLK` rather than parking a real thread —
/// the single-baton scheduler does not model advisory-lock waiting, and no
/// supported guest blocks on a contended `flock` (std's `File::try_lock*` is
/// always `LOCK_NB`). Dup'd descriptors are tracked independently rather than
/// sharing one open-file-description lock, so closing one dup releases only its
/// own entry; no supported guest dups a locked descriptor.
#[unsafe(no_mangle)]
pub extern "C" fn patina_flock(raw_fd: c_int, operation: c_int) -> c_int {
    let non_blocking = operation & LOCK_NB != 0;
    let request = operation & !LOCK_NB;
    if request == LOCK_UN {
        flock_release(raw_fd);
        set_errno(0);
        return 0;
    }
    let mode = match request {
        LOCK_SH => FlockMode::Shared,
        LOCK_EX => FlockMode::Exclusive,
        _ => return fail(EINVAL),
    };
    let fd = match fd(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno),
    };
    // Resolve the descriptor's inode through the recorded metadata path so the
    // conflict decision keys on the same file identity under record and replay.
    let ino = match with_context(|context| context.fs_fd_metadata(fd)) {
        Ok(metadata) => metadata.ino,
        Err(errno) => return fail(errno),
    };
    let mut table = flock_table().lock();
    let conflict = table.iter().any(|(&holder, &(held_ino, held_mode))| {
        holder != raw_fd
            && held_ino == ino
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
    table.insert(raw_fd, (ino, mode));
    set_errno(0);
    0
}

/// Duplicate an open deterministic file descriptor; the duplicate shares the
/// open-file description (cursor, flags) per POSIX. Deterministic numbering:
/// the driver's next fd, not the lowest free number.
#[unsafe(no_mangle)]
pub extern "C" fn patina_dup(raw_fd: c_int) -> c_int {
    if urandom_is_open(raw_fd) {
        return fail(ENOSYS);
    }
    let fd = match fd(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_dup(fd)) {
        Ok(fd) => i32::try_from(fd.0).unwrap_or_else(|_| fail(EOVERFLOW)),
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_seek(raw_fd: c_int, offset: i64, whence: u32) -> i64 {
    if urandom_is_open(raw_fd) {
        return i64::from(fail(ESPIPE));
    }
    let fd = match fd(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return i64::from(fail(errno)),
    };
    let whence = match whence {
        0 => SeekWhence::Start,
        1 => SeekWhence::Current,
        2 => SeekWhence::End,
        _ => return i64::from(fail(EINVAL)),
    };
    match with_context(|context| context.fs_seek(fd, offset, whence)) {
        Ok(position) => i64::try_from(position).unwrap_or_else(|_| i64::from(fail(EOVERFLOW))),
        Err(errno) => i64::from(fail(errno)),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_fsync(raw_fd: c_int) -> c_int {
    if urandom_is_open(raw_fd) {
        return fail(EINVAL);
    }
    let fd = match fd(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_sync(fd)) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_set_len(raw_fd: c_int, length: u64) -> c_int {
    if urandom_is_open(raw_fd) {
        return fail(EBADF);
    }
    let fd = match fd(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_set_len(fd, length)) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

struct ReadDirState {
    entries: Vec<FsDirectoryEntry>,
    position: usize,
}

fn metadata_kind(kind: FsEntryKind) -> u32 {
    match kind {
        FsEntryKind::File => 1,
        FsEntryKind::Directory => 2,
        FsEntryKind::Symlink => 3,
    }
}

fn write_metadata(metadata: patina_dst_abi::FsMetadata, kind: *mut u32, length: *mut u64) -> c_int {
    if kind.is_null() || length.is_null() {
        return fail(EINVAL);
    }
    // SAFETY: Both pointers were checked and are required to be writable by
    // the C ABI contract.
    unsafe {
        kind.write(metadata_kind(metadata.kind));
        length.write(metadata.len);
    }
    0
}

fn write_metadata_full(
    metadata: patina_dst_abi::FsMetadata,
    kind: *mut u32,
    length: *mut u64,
    ino: *mut u64,
    nlink: *mut u32,
    atime_nanos: *mut u64,
    mtime_nanos: *mut u64,
) -> c_int {
    if kind.is_null()
        || length.is_null()
        || ino.is_null()
        || nlink.is_null()
        || atime_nanos.is_null()
        || mtime_nanos.is_null()
    {
        return fail(EINVAL);
    }
    // SAFETY: All pointers were checked and are required to be writable by the
    // C ABI contract.
    unsafe {
        kind.write(metadata_kind(metadata.kind));
        length.write(metadata.len);
        ino.write(metadata.ino);
        nlink.write(metadata.nlink);
        atime_nanos.write(metadata.atime_nanos);
        mtime_nanos.write(metadata.mtime_nanos);
    }
    0
}

/// Read metadata for a deterministic path.
///
/// # Safety
/// All pointers must reference valid storage of their documented types.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_metadata(
    path: *const c_char,
    kind: *mut u32,
    length: *mut u64,
) -> c_int {
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_metadata(&path)) {
        Ok(metadata) => write_metadata(metadata, kind, length),
        Err(errno) => fail(errno),
    }
}

/// Read metadata for a deterministic descriptor.
///
/// # Safety
/// `kind` and `length` must point to writable storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_fd_metadata(
    raw_fd: c_int,
    kind: *mut u32,
    length: *mut u64,
) -> c_int {
    let fd = match fd(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_fd_metadata(fd)) {
        Ok(metadata) => write_metadata(metadata, kind, length),
        Err(errno) => fail(errno),
    }
}

/// Read full metadata for a deterministic path.
///
/// # Safety
/// All pointers must reference valid storage of their documented types.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_metadata_full(
    path: *const c_char,
    kind: *mut u32,
    length: *mut u64,
    ino: *mut u64,
    nlink: *mut u32,
    atime_nanos: *mut u64,
    mtime_nanos: *mut u64,
) -> c_int {
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_metadata(&path)) {
        Ok(metadata) => {
            write_metadata_full(metadata, kind, length, ino, nlink, atime_nanos, mtime_nanos)
        }
        Err(errno) => fail(errno),
    }
}

/// Read full metadata for a deterministic descriptor.
///
/// # Safety
/// All pointers must reference valid storage of their documented types.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_fd_metadata_full(
    raw_fd: c_int,
    kind: *mut u32,
    length: *mut u64,
    ino: *mut u64,
    nlink: *mut u32,
    atime_nanos: *mut u64,
    mtime_nanos: *mut u64,
) -> c_int {
    let fd = match fd(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_fd_metadata(fd)) {
        Ok(metadata) => {
            write_metadata_full(metadata, kind, length, ino, nlink, atime_nanos, mtime_nanos)
        }
        Err(errno) => fail(errno),
    }
}

/// Capture a deterministic directory snapshot for POSIX readdir iteration.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string and `state_out`
/// must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_read_dir(
    path: *const c_char,
    state_out: *mut *mut c_void,
) -> c_int {
    if state_out.is_null() {
        return fail(EINVAL);
    }
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_read_directory(&path)) {
        Ok(entries) => {
            let state = Box::new(ReadDirState {
                entries,
                position: 0,
            });
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
        kind.write(match entry.kind {
            FsEntryKind::File => 1,
            FsEntryKind::Directory => 2,
            FsEntryKind::Symlink => 3,
        });
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
    if !state.is_null() {
        // SAFETY: Guaranteed by this function's C ABI contract.
        drop(unsafe { Box::from_raw(state.cast::<ReadDirState>()) });
    }
}

unsafe fn path_unit(
    path: *const c_char,
    invoke: impl FnOnce(&mut Context, &str) -> Result<(), RuntimeError>,
) -> c_int {
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| invoke(context, &path)) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Create a deterministic directory.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_mkdir(path: *const c_char) -> c_int {
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe { path_unit(path, Context::fs_create_directory) }
}

/// Remove a deterministic regular file.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_unlink(path: *const c_char) -> c_int {
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe { path_unit(path, Context::fs_remove_file) }
}

/// Remove an empty deterministic directory.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_rmdir(path: *const c_char) -> c_int {
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe { path_unit(path, Context::fs_remove_directory) }
}

/// Rename a deterministic filesystem entry.
///
/// # Safety
/// `from` and `to` must point to valid NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_rename(from: *const c_char, to: *const c_char) -> c_int {
    let from = match path_from_c(from) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let to = match path_from_c(to) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_rename(&from, &to)) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Create a deterministic symbolic link.
///
/// # Safety
/// `target` and `link_path` must point to valid NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_symlink(target: *const c_char, link_path: *const c_char) -> c_int {
    let target = match path_from_c(target) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let link_path = match path_from_c(link_path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_symlink(&target, &link_path)) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Create a deterministic hard link (`link`/`linkat`).
///
/// Mirrors [`patina_symlink`]: both paths route through the driver, which shares
/// one inode between `from` and `to` (or, when `from` is itself a symlink,
/// duplicates the symlink entry -- the POSIX "hard link the symlink itself"
/// behavior of `linkat` without `AT_SYMLINK_FOLLOW`). The C `linkat` interposer
/// canonicalizes `from` before calling this when `AT_SYMLINK_FOLLOW` is set, so
/// the follow/no-follow distinction is resolved above this boundary.
///
/// # Safety
/// `from` and `to` must point to valid NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_link(from: *const c_char, to: *const c_char) -> c_int {
    let from = match path_from_c(from) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let to = match path_from_c(to) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_link(&from, &to)) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Read a deterministic symbolic link's target bytes.
///
/// Returns the byte count copied, with no trailing NUL added.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string and `buf` must be
/// writable for `len` bytes when `len` is nonzero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_read_link(
    path: *const c_char,
    buf: *mut c_char,
    len: usize,
) -> isize {
    if len != 0 && buf.is_null() {
        return fail(EINVAL) as isize;
    }
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
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno) as isize,
    };
    match with_context(|context| context.fs_read_link(&path)) {
        Ok(target) => {
            let bytes = target.as_bytes();
            let copied = bytes.len().min(len);
            if copied != 0 {
                // SAFETY: The destination buffer was checked and is required to
                // be writable for `len` bytes by this function's C ABI.
                unsafe {
                    slice::from_raw_parts_mut(buf.cast::<u8>(), len)[..copied]
                        .copy_from_slice(&bytes[..copied]);
                }
            }
            set_errno(0);
            isize::try_from(copied).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        Err(errno) => fail(errno) as isize,
    }
}

/// Canonicalize a guest path to its deterministic absolute form (`realpath`).
///
/// Writes the NUL-terminated canonical path into `buf` when it fits and returns
/// the canonical length in bytes (excluding the terminator); a `-1` return sets
/// `patina_errno`. The result is produced entirely from the virtual filesystem
/// -- lexical `.`/`..`/`//` normalization (shared with the drivers via
/// [`canonicalize_path`]), an existence check through the driver, and
/// trailing-symlink resolution through the driver's `read_link` -- so it never
/// consults host state and both `realpath` calling conventions receive the same
/// bytes. Unlike [`patina_read_link`] this takes no bootstrap guard: `realpath`
/// is not part of any allocator-init probe (the guarded case is
/// tikv-jemallocator's `readlink("/etc/malloc.conf")`), so it only ever runs
/// against a live runtime, and a guard would merely mask a legitimate early call.
///
/// # Safety
/// `path` must point to a valid NUL-terminated string and `buf` must be writable
/// for `len` bytes when `len` is nonzero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_canonicalize(
    path: *const c_char,
    buf: *mut c_char,
    len: usize,
) -> isize {
    if len != 0 && buf.is_null() {
        return fail(EINVAL) as isize;
    }
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno) as isize,
    };
    // fs-mem rejects intermediate-symlink traversal, so only a genuinely
    // trailing symlink is ever resolved here; the cap fails a symlink cycle
    // closed rather than looping.
    const SYMLINK_RESOLUTION_LIMIT: usize = 40;
    let canonical = with_context(|context| {
        let mut current = canonicalize_path(&path)?;
        for _ in 0..SYMLINK_RESOLUTION_LIMIT {
            let metadata = context.fs_metadata(&current)?;
            if metadata.kind != FsEntryKind::Symlink {
                return Ok(current);
            }
            let target = context.fs_read_link(&current)?;
            let base = if target.starts_with('/') {
                target
            } else {
                let parent = current.rsplit_once('/').map_or("/", |(parent, _)| parent);
                let parent = if parent.is_empty() { "/" } else { parent };
                format!("{parent}/{target}")
            };
            current = canonicalize_path(&base)?;
        }
        Err(RuntimeError::from(EffectError::new(
            ErrorCode::InvalidInput,
            format!("too many levels of symbolic links: {path:?}"),
        )))
    });
    let canonical = match canonical {
        Ok(canonical) => canonical,
        Err(errno) => return fail(errno) as isize,
    };
    let bytes = canonical.as_bytes();
    let needed = bytes.len();
    if len != 0 && needed < len {
        // SAFETY: The destination buffer is required to be writable for `len`
        // bytes by this function's C ABI, and `needed < len` leaves room for the
        // trailing NUL.
        unsafe {
            let destination = slice::from_raw_parts_mut(buf.cast::<u8>(), len);
            destination[..needed].copy_from_slice(bytes);
            destination[needed] = 0;
        }
    }
    set_errno(0);
    isize::try_from(needed).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_thread_id() -> c_int {
    thread::deterministic_thread_id()
}

/// `sched_yield`/`thread::yield_now`: take a deterministic scheduling point
/// instead of yielding the host scheduler. std's `mpsc`/`mpmc` backoff spins
/// through `thread::yield_now` before parking, so an uninterposed `sched_yield`
/// would be a host scheduling call outside the runtime. A no-op until the
/// thread subsystem activates, so single-threaded programs are unaffected.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sched_yield() -> c_int {
    let _ = thread::sched_point();
    0
}

/// The `--yield-points` guard hook: `patina_yield.c` forwards every
/// SanitizerCoverage guard hit here with the instrumented call site, so a
/// record/replay yield divergence can name the exact guest location that took
/// the extra scheduling point. Otherwise identical to [`patina_sched_yield`].
#[unsafe(no_mangle)]
pub extern "C" fn patina_yield_point(site: *const c_void) {
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
    thread::note_main_returned();
    // SAFETY: `host_exit` is the real libc `exit` resolved once via
    // `dlsym(RTLD_NEXT, "exit")`; it does not return.
    unsafe { (hostapi::get().host_exit)(status) }
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
    thread::note_main_returned();
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
    if !thread::main_returned() {
        let _ = host_write_all(
            2,
            b"patina native shim fatal: teardown interposer did not engage -- main-return \
silencing is not active on this platform/toolchain (neither the __libc_start_main wrapper nor the \
exit interposer set the teardown flag before atexit); --yield-points teardown determinism is not \
guaranteed\n",
        );
        std::process::abort();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_crash() -> c_int {
    match with_context(Context::fs_crash) {
        Ok(()) => 0,
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
    let _ = flush_captured_stdio();
    let line = format!("{marker} label={label}\n");
    let _ = host_write_all(2, line.as_bytes());
    std::process::abort();
}

/// Flush captured guest output and abort, printing nothing of the shim's own.
///
/// The run's finding has already been reported through the verdict ABI and
/// drained into the captured stderr as a `PATINA_VERDICT` line, so a second
/// hand-formatted marker would be a duplicate channel — and the classifier reads
/// the verdict, never a marker (`docs/arcs/outcome-channel.md`).
fn abort_after_verdict() -> ! {
    let _ = flush_captured_stdio();
    std::process::abort();
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
//   1. `patina_custom_op_begin(label, key, &out_len)`
//        -> 0: record pass. Run `perform`, then call `patina_custom_op_record`.
//        -> 1: replay pass. Do NOT run `perform`; `out_len` is the recorded
//              result's length, fetched with `patina_custom_op_replay_result`.
//   2a. `patina_custom_op_record(result, result_len)` closes a record pass.
//   2b. `patina_custom_op_replay_result(out, out_cap)` closes a replay pass.
//
// Every runtime-level refusal (a replay divergence on the label or key, a nested
// or unclosed operation, a modeled effect performed inside `perform`) is fatal:
// there is no answer the guest could safely be handed, so the shim aborts loudly
// rather than returning an errno the guest could swallow and continue past. Only
// malformed arguments — a non-UTF-8 label, a null pointer with a nonzero length —
// return `EINVAL`, because those are the guest's own call being wrong.

/// Announce a custom operation; returns 0 for "record pass, run `perform`" or 1
/// for "replay pass, the answer is recorded". See the module comment above.
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
    out_len: *mut usize,
) -> c_int {
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
    match with_context(|context| context.custom_op_begin(label, key)) {
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
    with_context(|context| Ok(context.buggify_rng())).unwrap_or(0)
}

/// `patina_dst::lifecycle::setup_complete()`: mark the setup boundary and emit a marker.
#[unsafe(no_mangle)]
pub extern "C" fn patina_lifecycle_setup_complete() -> c_int {
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
    use std::cell::Cell;
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::c_char;
    use std::ffi::{c_int, c_void};
    use std::sync::{Arc, OnceLock};

    use patina_dst_abi::{ClockKind, Datagram, ShutdownHow, SocketId};

    use super::hostcoll::{HostDeque, HostMap};
    use super::{
        EBUSY, EDEADLK, EINVAL, EISCONN, ENOTCONN, EOPNOTSUPP, EOVERFLOW, EPERM, ESRCH, ETIMEDOUT,
        EWOULDBLOCK, SpinGuard, SpinMutex, TaskId, host_write_all, with_context_msg,
        with_context_raw,
    };

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

    /// The unmanaged sentinel used before the thread subsystem activates; the
    /// scheduler never issues task id 0.
    const UNMANAGED_TASK: TaskId = TaskId(0);

    fn current_task() -> TaskId {
        CURRENT_TASK.with(Cell::get).unwrap_or(UNMANAGED_TASK)
    }

    pub(crate) fn deterministic_thread_id() -> c_int {
        let task = current_task();
        if task == UNMANAGED_TASK {
            1
        } else {
            c_int::try_from(task.0).unwrap_or(i32::MAX)
        }
    }

    /// Detach the thread subsystem from the runtime at shutdown. Later boundary
    /// calls (for example `Mutex`/`Condvar` destructors as the program unwinds)
    /// then take no scheduling point and never touch the removed context.
    pub(crate) fn deactivate() {
        let mut state = lock_state();
        state.active = false;
    }

    fn fatal(message: &str) -> ! {
        let text = format!("patina native shim fatal: {message}\n");
        let _ = host_write_all(2, text.as_bytes());
        std::process::abort();
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

    #[derive(Default)]
    struct MutexEntry {
        owner: Option<TaskId>,
        waiters: HostDeque<TaskId>,
    }

    #[derive(Default)]
    struct CondEntry {
        waiters: HostDeque<(TaskId, usize)>,
    }

    /// A deterministic reader/writer lock. Writer-preferring: a new reader
    /// blocks while any writer holds or is waiting, so a stream of readers can
    /// never starve a waiting writer. Writers are granted in strict FIFO order;
    /// when a writer releases and no writer is waiting, every blocked reader is
    /// granted at once (a batch wake, like a condvar broadcast). Every wake is a
    /// recorded scheduler decision, so the wake order is reproducible.
    #[derive(Default)]
    struct RwLockEntry {
        /// Number of tasks currently holding the read lock.
        readers: usize,
        /// The task currently holding the write lock, if any.
        writer: Option<TaskId>,
        write_waiters: HostDeque<TaskId>,
        read_waiters: HostDeque<TaskId>,
    }

    struct ThreadEntry {
        finished: bool,
        retval: usize,
        joiner: Option<TaskId>,
        detached: bool,
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

    impl ThreadTable {
        fn register(&mut self, task: TaskId) {
            self.threads.insert(
                task,
                ThreadEntry {
                    finished: false,
                    retval: 0,
                    joiner: None,
                    detached: false,
                },
            );
        }

        fn init_mutex(&mut self, key: usize) {
            self.mutexes.insert(key, MutexEntry::default());
        }

        fn lock(&mut self, me: TaskId, key: usize) -> Result<LockStep, ThreadError> {
            let entry = self.mutexes.entry_or_default(key);
            match entry.owner {
                None => {
                    entry.owner = Some(me);
                    Ok(LockStep::Acquired)
                }
                Some(owner) if owner == me => Err(ThreadError::Posix(EDEADLK)),
                Some(_) => {
                    entry.waiters.push_back(me);
                    Ok(LockStep::MustBlock)
                }
            }
        }

        fn trylock(&mut self, me: TaskId, key: usize) -> c_int {
            let entry = self.mutexes.entry_or_default(key);
            match entry.owner {
                None => {
                    entry.owner = Some(me);
                    0
                }
                Some(owner) if owner == me => EDEADLK,
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
                return Err(ThreadError::Posix(EPERM));
            }
            if let Some(next) = entry.waiters.pop_front() {
                entry.owner = Some(next);
                scheduler.wake(next)?;
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

        fn init_rwlock(&mut self, key: usize) {
            self.rwlocks.insert(key, RwLockEntry::default());
        }

        /// Acquire the read lock. Writer-preferring: block while a writer holds
        /// the lock or any writer is waiting.
        fn rwlock_rdlock(&mut self, me: TaskId, key: usize) -> Result<LockStep, ThreadError> {
            let entry = self.rwlocks.entry_or_default(key);
            if entry.writer == Some(me) {
                return Err(ThreadError::Posix(EDEADLK));
            }
            if entry.writer.is_none() && entry.write_waiters.is_empty() {
                entry.readers += 1;
                Ok(LockStep::Acquired)
            } else {
                entry.read_waiters.push_back(me);
                Ok(LockStep::MustBlock)
            }
        }

        /// Acquire the write lock: exclusive, so block unless the lock is fully
        /// idle (no readers and no writer).
        fn rwlock_wrlock(&mut self, me: TaskId, key: usize) -> Result<LockStep, ThreadError> {
            let entry = self.rwlocks.entry_or_default(key);
            if entry.writer == Some(me) {
                return Err(ThreadError::Posix(EDEADLK));
            }
            if entry.writer.is_none() && entry.readers == 0 {
                entry.writer = Some(me);
                Ok(LockStep::Acquired)
            } else {
                entry.write_waiters.push_back(me);
                Ok(LockStep::MustBlock)
            }
        }

        fn rwlock_tryrdlock(&mut self, me: TaskId, key: usize) -> c_int {
            let entry = self.rwlocks.entry_or_default(key);
            if entry.writer == Some(me) {
                EDEADLK
            } else if entry.writer.is_none() && entry.write_waiters.is_empty() {
                entry.readers += 1;
                0
            } else {
                EBUSY
            }
        }

        fn rwlock_trywrlock(&mut self, me: TaskId, key: usize) -> c_int {
            let entry = self.rwlocks.entry_or_default(key);
            if entry.writer == Some(me) {
                EDEADLK
            } else if entry.writer.is_none() && entry.readers == 0 {
                entry.writer = Some(me);
                0
            } else {
                EBUSY
            }
        }

        /// Release whichever mode `me` holds, then grant the lock to the next
        /// waiter(s) deterministically: a waiting writer (FIFO) is preferred, and
        /// only when none waits is every blocked reader woken together.
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
            if let Some(next) = entry.write_waiters.pop_front() {
                entry.writer = Some(next);
                scheduler.wake(next)?;
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
                        Some(reader) => scheduler.wake(reader)?,
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

        fn init_cond(&mut self, key: usize) {
            self.conds.insert(key, CondEntry::default());
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
                        entry.owner = Some(task);
                        scheduler.wake(task)?;
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

        fn begin_join(&mut self, me: TaskId, target: TaskId) -> Result<JoinStep, ThreadError> {
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
            if entry.joiner.is_some() {
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
                scheduler.wake(joiner)?;
            }
            scheduler.complete(me)?;
            if detached && joiner.is_none() {
                self.threads.remove(&me);
            }
            Ok(())
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
    fn switch_and_park(state: SpinGuard<'_, ThreadRuntime>, picked: TaskId, me: TaskId) {
        let picked_sem = state.task_sem(picked);
        let my_sem = state.task_sem(me);
        drop(state);
        picked_sem.signal();
        my_sem.wait();
    }

    /// Baton-guarded state shared by every managed host thread. Only the current
    /// baton holder touches it, so the spinlock is essentially uncontended.
    struct ThreadRuntime {
        table: ThreadTable,
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
        fn task_sem(&self, task: TaskId) -> Arc<baton::Semaphore> {
            Arc::clone(
                self.sems
                    .get(&task)
                    .expect("every managed task has a baton semaphore"),
            )
        }

        /// Register the main thread as the first managed task and give it the
        /// baton the first time the thread subsystem is used.
        fn ensure_active(&mut self) -> Result<(), ThreadError> {
            if self.active {
                return Ok(());
            }
            let mut scheduler = RealScheduler;
            let main = scheduler.spawn("main")?;
            let selected = scheduler.next()?;
            if selected != Some(main) {
                return Err(ThreadError::Fatal(format!(
                    "scheduler selected {selected:?} instead of the main task {main:?}"
                )));
            }
            self.table.register(main);
            self.sems.insert(main, Arc::new(baton::Semaphore::new()));
            self.active = true;
            set_current_task(main);
            Ok(())
        }

        fn reschedule(&mut self, me: TaskId) -> Result<Option<TaskId>, ThreadError> {
            let mut scheduler = RealScheduler;
            scheduler.yield_task(me)?;
            Ok(scheduler.next()?)
        }

        fn begin_lock(&mut self, me: TaskId, key: usize) -> Result<Step, ThreadError> {
            match self.table.lock(me, key)? {
                LockStep::Acquired => Ok(Step::Continue),
                LockStep::MustBlock => self.block(me, "mutex-contended"),
            }
        }

        fn begin_rdlock(&mut self, me: TaskId, key: usize) -> Result<Step, ThreadError> {
            match self.table.rwlock_rdlock(me, key)? {
                LockStep::Acquired => Ok(Step::Continue),
                LockStep::MustBlock => self.block(me, "rwlock-read-contended"),
            }
        }

        fn begin_wrlock(&mut self, me: TaskId, key: usize) -> Result<Step, ThreadError> {
            match self.table.rwlock_wrlock(me, key)? {
                LockStep::Acquired => Ok(Step::Continue),
                LockStep::MustBlock => self.block(me, "rwlock-write-contended"),
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
            self.block(me, "cond-wait")
        }

        fn begin_join(&mut self, me: TaskId, target: TaskId) -> Result<JoinResolve, ThreadError> {
            match self.table.begin_join(me, target)? {
                JoinStep::Done(retval) => Ok(JoinResolve::Ready(retval)),
                JoinStep::MustBlock => Ok(JoinResolve::Blocked(self.block(me, "join")?)),
            }
        }

        fn block(&mut self, me: TaskId, reason: &str) -> Result<Step, ThreadError> {
            let mut scheduler = RealScheduler;
            scheduler.park(me, reason)?;
            let next = scheduler.next()?;
            self.settle_rescued()?;
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
            reason: &str,
            clock: ClockKind,
            deadline: u64,
        ) -> Result<Step, ThreadError> {
            let mut scheduler = RealScheduler;
            scheduler.park_timed(me, reason, clock, deadline)?;
            let next = scheduler.next()?;
            self.settle_rescued()?;
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
        /// net-recv waiter simply retries the receive (the packet is now due),
        /// and a bare timed sleep is on no queue at all.
        fn mark_timed_out(&mut self, task: TaskId) {
            for cond in self.table.conds.values_mut() {
                if let Some(index) = cond.waiters.iter().position(|(waiter, _)| *waiter == task) {
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
            for socket in self.net.sockets.values_mut() {
                if let Some(index) = socket
                    .recv_waiters
                    .iter()
                    .position(|waiter| *waiter == task)
                {
                    socket.recv_waiters.remove(index);
                    return;
                }
            }
        }
    }

    fn thread_runtime() -> &'static SpinMutex<ThreadRuntime> {
        static RUNTIME: OnceLock<SpinMutex<ThreadRuntime>> = OnceLock::new();
        RUNTIME.get_or_init(|| {
            SpinMutex::new(ThreadRuntime {
                table: ThreadTable::default(),
                handles: BTreeMap::new(),
                sems: BTreeMap::new(),
                net: NetState::new(),
                futexes: BTreeMap::new(),
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
        let mut state = lock_state();
        if !state.active {
            return Ok(());
        }
        let me = current_task();
        match state.reschedule(me) {
            Ok(Some(picked)) if picked == me => Ok(()),
            Ok(Some(picked)) => {
                switch_and_park(state, picked, me);
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
    pub(crate) fn managed_sleep(clock: ClockKind, deadline: u64) -> Option<c_int> {
        let me = current_task();
        let mut state = lock_state();
        if !state.active {
            return None;
        }
        match state.block_timed(me, "sleep", clock, deadline) {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => return Some(error.into_posix()),
        }
        // A bare sleep is on no waiter list; clear a defensive timer flag anyway.
        lock_state().timed_out.remove(&me);
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
        // Park on this task's baton semaphore until it is first scheduled.
        let sem = lock_state().task_sem(task);
        sem.wait();
        let ret = routine(arg);
        thread_finish(task, ret as usize);
        ret
    }

    fn thread_finish(task: TaskId, retval: usize) {
        let mut state = lock_state();
        let mut scheduler = RealScheduler;
        if let Err(ThreadError::Fatal(message)) = state.table.exit(&mut scheduler, task, retval) {
            fatal(&message);
        }
        // The task is gone from the scheduler; mark this host thread completed so
        // instrumented teardown (TLS destructors under `--yield-points`) takes no
        // scheduling point rather than rescheduling a task that no longer exists.
        mark_task_completed();
        let next = match scheduler.next() {
            Ok(next) => next,
            Err(message) => fatal(&message),
        };
        // Completing the last runnable task can leave only timed waiters, so the
        // `next()` above may have run the rescue; settle it before handing off.
        match state.settle_rescued() {
            Ok(()) => {}
            Err(ThreadError::Fatal(message)) => fatal(&message),
            Err(ThreadError::Posix(errno)) => fatal(&format!(
                "settling timers after task completion failed ({errno})"
            )),
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
        // The semaphore must exist before the host thread parks on it.
        state.sems.insert(task, Arc::new(baton::Semaphore::new()));
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
        let key = handle as usize;
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
        let key = handle as usize;
        let mut state = lock_state();
        let Some(&target) = state.handles.get(&key) else {
            return ESRCH;
        };
        match state.table.detach(target) {
            Ok(()) => {
                state.handles.remove(&key);
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
    pub unsafe extern "C" fn patina_mutex_init(mutex: *mut c_void, _attr: *const c_void) -> c_int {
        managed_op!({
            let mut state = lock_state();
            state.table.init_mutex(mutex as usize);
            0
        })
    }

    /// # Safety
    /// `mutex` must reference a valid `pthread_mutex_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_mutex_lock(mutex: *mut c_void) -> c_int {
        managed_op!({
            let key = mutex as usize;
            let me = current_task();
            let mut state = lock_state();
            match state.begin_lock(me, key) {
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
        managed_op!({
            let me = current_task();
            let mut state = lock_state();
            state.table.trylock(me, mutex as usize)
        })
    }

    /// # Safety
    /// `mutex` must reference a valid `pthread_mutex_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_mutex_unlock(mutex: *mut c_void) -> c_int {
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
        // Run the lock natively — never through the deterministic model — for an
        // allocator-internal `os_unfair_lock` in either of the two windows where
        // one appears: (1) the bootstrap window, where a custom global allocator's
        // own eager init takes its `malloc_mutex`; (2) reentrantly while this
        // thread already holds a shim spinlock, which happens only when the shim's
        // scheduler-path allocation re-enters the (now-initialized) allocator. Both
        // are allocator-internal, single-owner locks that must not route through
        // the scheduler (it would trip the non-recursive guard or deadlock on the
        // held spinlock). See `SHIM_BOOTSTRAP` and `SPIN_DEPTH`.
        if super::in_shim_bootstrap() || super::in_shim_critical() {
            // SAFETY: the resolved real `os_unfair_lock_lock`; `lock` is a valid
            // `os_unfair_lock` per the caller's contract.
            unsafe { (super::hostapi::get().host_os_unfair_lock_lock)(lock) };
            return;
        }
        let _ = sched_point();
        let key = lock as usize;
        let me = current_task();
        let mut state = lock_state();
        match state.begin_lock(me, key) {
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
        // Allocator-internal lock: run natively (see `patina_os_unfair_lock_lock`).
        // The real `os_unfair_lock_trylock` returns a C `bool`.
        if super::in_shim_bootstrap() || super::in_shim_critical() {
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
        c_int::from(state.table.trylock(me, lock as usize) == 0)
    }

    /// # Safety
    /// `lock` must reference a valid `os_unfair_lock` the caller holds.
    #[cfg(target_os = "macos")]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_os_unfair_lock_unlock(lock: *mut c_void) {
        // Allocator-internal lock: run natively (see `patina_os_unfair_lock_lock`).
        // A lock taken natively (bootstrap, or reentrant under a held spinlock) is
        // released natively too; the allocator's lock/unlock pair is balanced
        // within the same window, so none spans a transition.
        if super::in_shim_bootstrap() || super::in_shim_critical() {
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
    /// the scheduler exactly like the mutex/cond interposition: writer-preferring
    /// grant order, FIFO among writers, and a batch wake of all blocked readers
    /// when a writer releases with no writer waiting. std's own `RwLock` does not
    /// lower to these symbols on the supported toolchains (it uses the queue-based
    /// parking `RwLock`), so this serves C guests and any std that does.
    ///
    /// # Safety
    /// `lock` must reference a valid `pthread_rwlock_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_rwlock_init(lock: *mut c_void, _attr: *const c_void) -> c_int {
        managed_op!({
            let mut state = lock_state();
            state.table.init_rwlock(lock as usize);
            0
        })
    }

    /// # Safety
    /// `lock` must reference a valid `pthread_rwlock_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_rwlock_rdlock(lock: *mut c_void) -> c_int {
        managed_op!({
            let key = lock as usize;
            let me = current_task();
            let mut state = lock_state();
            match state.begin_rdlock(me, key) {
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
        managed_op!({
            let key = lock as usize;
            let me = current_task();
            let mut state = lock_state();
            match state.begin_wrlock(me, key) {
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
        managed_op!({
            let me = current_task();
            let mut state = lock_state();
            state.table.rwlock_tryrdlock(me, lock as usize)
        })
    }

    /// # Safety
    /// `lock` must reference a valid `pthread_rwlock_t`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_rwlock_trywrlock(lock: *mut c_void) -> c_int {
        managed_op!({
            let me = current_task();
            let mut state = lock_state();
            state.table.rwlock_trywrlock(me, lock as usize)
        })
    }

    /// # Safety
    /// `lock` must reference a valid `pthread_rwlock_t` the caller holds.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_rwlock_unlock(lock: *mut c_void) -> c_int {
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
    pub unsafe extern "C" fn patina_cond_init(cond: *mut c_void, _attr: *const c_void) -> c_int {
        managed_op!({
            let mut state = lock_state();
            state.table.init_cond(cond as usize);
            0
        })
    }

    /// # Safety
    /// `cond` and `mutex` must reference valid pthread objects, and the caller
    /// must own `mutex`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_cond_wait(cond: *mut c_void, mutex: *mut c_void) -> c_int {
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

    /// Convert an absolute `struct timespec` deadline to nanoseconds,
    /// fail-closed on a malformed field or overflow.
    ///
    /// # Safety
    /// `ptr` must point to a valid `struct timespec`.
    unsafe fn timespec_nanos(ptr: *const c_void) -> Result<u64, c_int> {
        // SAFETY: guaranteed by this function's contract.
        let time = unsafe { &*ptr.cast::<CTimespec>() };
        if time.tv_sec < 0 || time.tv_nsec < 0 || time.tv_nsec >= 1_000_000_000 {
            return Err(EINVAL);
        }
        u64::try_from(time.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|nanos| nanos.checked_add(time.tv_nsec as u64))
            .ok_or(EOVERFLOW)
    }

    /// Timed condition wait. Like [`patina_cond_wait`], but parks with the
    /// wait's absolute `CLOCK_REALTIME` deadline registered on the virtual-clock
    /// timer queue. A signal before the deadline returns 0 (the waiter owns the
    /// mutex, exactly like the untimed path); reaching the deadline re-acquires
    /// the mutex and returns `ETIMEDOUT`. Whether the wake was a signal or the
    /// timer is decided by which path removed the waiter — never by comparing
    /// clocks — so it is deterministic.
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
        // Release the mutex and enqueue on the condition, exactly as cond_wait.
        if let Err(error) = state
            .table
            .cond_wait(&mut scheduler, me, cond_key, mutex_key)
        {
            return error.into_posix();
        }
        match state.block_timed(me, "cond-timedwait", ClockKind::Realtime, deadline) {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => return error.into_posix(),
        }
        // Resumed. A timer wake left `me` in `timed_out` and holding no mutex; a
        // signal wake removed `me` from the condition and re-granted the mutex.
        let mut state = lock_state();
        if state.timed_out.remove(&me) {
            match state.begin_lock(me, mutex_key) {
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
            match state.block(me, "dispatch-sem-wait") {
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
            match state.block_timed(me, "dispatch-sem-timedwait", ClockKind::Monotonic, deadline) {
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
    // Virtual AF_INET sockets over the runtime's SimNet.
    //
    // Guest socket descriptors live in a high, non-colliding range so `close`
    // can route them here. Datagram sockets preserve the original UDP
    // semantics. Stream sockets model zero-latency TCP listen/accept/connect,
    // byte-stream reads/writes, and half-close through recorded runtime network
    // operations plus the scheduler's existing park/wake machinery. IPv6, DNS,
    // readiness multiplexing, peek, and socket timeouts stay fail-closed:
    // `TcpStream::set_read_timeout(Some(_))` fails, `TcpStream::peek` fails,
    // `TcpStream::set_nodelay` and `TcpListener::bind`'s `SO_REUSEADDR`
    // succeed as no-ops, and `connect("localhost:...")` fails via getaddrinfo.
    // TCP latency > 0 is deferred, but stream inbox delivery deadlines and
    // timed read parking mirror the UDP path so wrappers can expose segment
    // latency deterministically later. All sockets are fully virtual — no host
    // network symbols are imported.

    /// Guest socket descriptors are numbered from here so they never collide
    /// with the deterministic filesystem's small descriptors.
    pub(crate) const SOCKET_FD_BASE: c_int = 0x4000_0000;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SocketKind {
        Datagram,
        /// SOCK_STREAM before listen/connect/accept resolves its role.
        StreamUnbound,
        StreamListener,
        Stream,
    }

    struct NetSocket {
        kind: SocketKind,
        socket_id: Option<SocketId>,
        address: Option<String>,
        bound: Option<(u32, u16)>,
        peer: Option<(u32, u16)>,
        nonblocking: bool,
        /// Deterministic `SO_RCVTIMEO`: `Some(nanos)` bounds a blocking receive by
        /// this many virtual nanoseconds from entry; `None` (or a zero timeval,
        /// which POSIX treats as no timeout) blocks until data or a genuine wake.
        read_timeout_nanos: Option<u64>,
        /// The `tcp_streams` key of the connection this stream endpoint belongs
        /// to (the client's local address), for stream sockets only.
        stream_key: Option<String>,
        recv_waiters: VecDeque<TaskId>,
        send_waiters: VecDeque<TaskId>,
    }

    impl NetSocket {
        fn new(kind: SocketKind, nonblocking: bool) -> Self {
            Self {
                kind,
                socket_id: None,
                address: None,
                bound: None,
                peer: None,
                nonblocking,
                read_timeout_nanos: None,
                stream_key: None,
                recv_waiters: VecDeque::new(),
                send_waiters: VecDeque::new(),
            }
        }
    }

    /// The two guest descriptors of one virtual TCP connection.
    #[derive(Clone, Copy, Default)]
    struct TcpPair {
        client: Option<c_int>,
        server: Option<c_int>,
    }

    impl TcpPair {
        /// The descriptor on the other end from `fd`, if it is still open.
        fn other(&self, fd: c_int) -> Option<c_int> {
            match (self.client, self.server) {
                (Some(client), server) if client == fd => server,
                (client, Some(server)) if server == fd => client,
                _ => None,
            }
        }

        fn is_empty(&self) -> bool {
            self.client.is_none() && self.server.is_none()
        }
    }

    struct NetState {
        sockets: BTreeMap<c_int, NetSocket>,
        bound: BTreeMap<String, c_int>,
        tcp_listeners: BTreeMap<String, c_int>,
        /// Connected stream endpoints, keyed by the CLIENT's local address. That
        /// address is unique per connection (it carries the ephemeral port) and
        /// BOTH sides hold it — the client as its own local, the acceptor as the
        /// peer address the runtime hands back — so the two endpoints agree on
        /// one key. Keying by `(local, peer)` instead would break under a
        /// wildcard bind, where the acceptor's local is the listener's
        /// `0.0.0.0:PORT` while the client's peer is the specific IP it dialed,
        /// and neither side can derive the other's spelling.
        tcp_streams: BTreeMap<String, TcpPair>,
        // In-process pipe/socketpair channels. Endpoints share the socket
        // virtual-fd space (`next_fd`) so a virtual fd is a socket XOR a pipe
        // endpoint, never both — the C dispatch tells them apart by table
        // membership. `pipe_channels` are the directed byte buffers each endpoint
        // reads from / writes to; see the "in-process pipe / socketpair" section.
        pipe_ends: BTreeMap<c_int, PipeEnd>,
        pipe_channels: BTreeMap<u64, PipeChannel>,
        next_channel: u64,
        // Virtual kqueue readiness reactors. A kqueue fd (drawn from the shared
        // `next_fd` space, so a virtual fd is a socket XOR a pipe endpoint XOR a
        // kqueue fd) maps through `kq_fds` to a reference-counted registry in
        // `kqueues`: a `dup`/`F_DUPFD` of a kqueue fd (tokio's IO driver clones
        // its selector this way) yields a second fd sharing the SAME registry, so
        // the registry outlives any one fd and drops only when the last closes.
        // macOS-only: kqueue/kevent have no Linux counterpart.
        #[cfg(target_os = "macos")]
        kqueues: BTreeMap<u64, KqueueSlot>,
        #[cfg(target_os = "macos")]
        kq_fds: BTreeMap<c_int, u64>,
        #[cfg(target_os = "macos")]
        next_kq: u64,
        // Virtual epoll readiness reactors — the Linux mirror of the kqueue
        // tables above, with the same refcounted-dup shape (mio clones its
        // selector through `F_DUPFD_CLOEXEC` on Linux exactly as on macOS).
        #[cfg(target_os = "linux")]
        epolls: BTreeMap<u64, EpollSlot>,
        #[cfg(target_os = "linux")]
        epoll_fds: BTreeMap<c_int, u64>,
        #[cfg(target_os = "linux")]
        next_epoll: u64,
        // Deterministic in-process eventfd counters (Linux; mio's `Waker`
        // vehicle, the EVFILT_USER analogue), sharing the virtual-fd space.
        #[cfg(target_os = "linux")]
        eventfds: BTreeMap<c_int, EventFd>,
        // Directory descriptors for the openat/fdopendir/unlinkat family
        // (std's `remove_dir_all` opens each directory with `openat(...,
        // O_DIRECTORY)`, hands the fd to `fdopendir`, and removes children with
        // `unlinkat(dirfd, name, ...)`). A dir fd is an ordinary deterministic-FS
        // descriptor plus a path handle: fstat/fsync/close route through the FS,
        // while the *at interposers consult the canonical path to join child names.
        // FS fds live below the virtual socket/pipe/reactor range, so table
        // membership keeps the classes distinct.
        dir_fds: BTreeMap<c_int, String>,
        next_fd: c_int,
        next_ephemeral: u16,
    }

    impl NetState {
        fn new() -> Self {
            Self {
                sockets: BTreeMap::new(),
                bound: BTreeMap::new(),
                tcp_listeners: BTreeMap::new(),
                tcp_streams: BTreeMap::new(),
                pipe_ends: BTreeMap::new(),
                pipe_channels: BTreeMap::new(),
                next_channel: 0,
                #[cfg(target_os = "macos")]
                kqueues: BTreeMap::new(),
                #[cfg(target_os = "macos")]
                kq_fds: BTreeMap::new(),
                #[cfg(target_os = "macos")]
                next_kq: 0,
                #[cfg(target_os = "linux")]
                epolls: BTreeMap::new(),
                #[cfg(target_os = "linux")]
                epoll_fds: BTreeMap::new(),
                #[cfg(target_os = "linux")]
                next_epoll: 0,
                #[cfg(target_os = "linux")]
                eventfds: BTreeMap::new(),
                dir_fds: BTreeMap::new(),
                next_fd: SOCKET_FD_BASE,
                next_ephemeral: 49152,
            }
        }

        fn ephemeral(&mut self) -> u16 {
            let assigned = self.next_ephemeral;
            self.next_ephemeral = assigned.checked_add(1).unwrap_or(49152);
            assigned
        }
    }

    fn format_addr(ip: u32, port: u16) -> String {
        format!(
            "{}.{}.{}.{}:{}",
            (ip >> 24) & 0xff,
            (ip >> 16) & 0xff,
            (ip >> 8) & 0xff,
            ip & 0xff,
            port
        )
    }

    fn parse_addr(addr: &str) -> Option<(u32, u16)> {
        let (host, port) = addr.rsplit_once(':')?;
        let port: u16 = port.parse().ok()?;
        let mut octets = host.split('.');
        let mut ip: u32 = 0;
        for _ in 0..4 {
            let octet: u32 = octets.next()?.parse().ok()?;
            if octet > 255 {
                return None;
            }
            ip = (ip << 8) | octet;
        }
        if octets.next().is_some() {
            return None;
        }
        Some((ip, port))
    }

    fn wake_all(waiters: Vec<TaskId>) {
        let mut scheduler = RealScheduler;
        for task in waiters {
            if let Err(message) = scheduler.wake(task) {
                fatal(&message);
            }
        }
    }

    /// The address a listening socket is registered under for traffic dialed at
    /// `destination`: the exact address when something is bound there, else the
    /// wildcard key when a `0.0.0.0:PORT` listener covers it. The shim keeps its
    /// own address-keyed tables to know which task to WAKE, so it must resolve
    /// exactly as the runtime routed — a datagram the runtime delivers to a
    /// wildcard socket whose waiter the shim never wakes is a silent hang.
    fn resolve_listener_address(state: &ThreadRuntime, destination: &str) -> String {
        if state.net.tcp_listeners.contains_key(destination) {
            return destination.to_owned();
        }
        match patina_dst_driver_api::wildcard_bind_key(destination) {
            Some(wildcard) if state.net.tcp_listeners.contains_key(&wildcard) => wildcard,
            _ => destination.to_owned(),
        }
    }

    /// [`resolve_listener_address`] for the datagram table.
    fn resolve_bound_address(state: &ThreadRuntime, destination: &str) -> String {
        if state.net.bound.contains_key(destination) {
            return destination.to_owned();
        }
        match patina_dst_driver_api::wildcard_bind_key(destination) {
            Some(wildcard) if state.net.bound.contains_key(&wildcard) => wildcard,
            _ => destination.to_owned(),
        }
    }

    fn peer_fd(state: &ThreadRuntime, fd: c_int) -> Option<c_int> {
        let key = state.net.sockets.get(&fd)?.stream_key.as_ref()?;
        state.net.tcp_streams.get(key)?.other(fd)
    }

    fn drain_recv_waiters(state: &mut ThreadRuntime, fd: c_int) -> Vec<TaskId> {
        state
            .net
            .sockets
            .get_mut(&fd)
            .map(|socket| socket.recv_waiters.drain(..).collect())
            .unwrap_or_default()
    }

    fn drain_send_waiters(state: &mut ThreadRuntime, fd: c_int) -> Vec<TaskId> {
        state
            .net
            .sockets
            .get_mut(&fd)
            .map(|socket| socket.send_waiters.drain(..).collect())
            .unwrap_or_default()
    }

    /// Allocate a virtual socket. Activates the thread subsystem so a later
    /// blocking receive/accept/send can park through the baton.
    ///
    /// # Safety
    /// C ABI entry point.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_net_socket(stream: c_int, nonblocking: c_int) -> c_int {
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return super::fail(error.into_posix());
        }
        let fd = state.net.next_fd;
        state.net.next_fd = state.net.next_fd.wrapping_add(1);
        let kind = if stream != 0 {
            SocketKind::StreamUnbound
        } else {
            SocketKind::Datagram
        };
        state
            .net
            .sockets
            .insert(fd, NetSocket::new(kind, nonblocking != 0));
        fd
    }

    /// Return the managed socket kind: -1 unknown, 0 datagram, 1 unbound stream,
    /// 2 listener, 3 stream. This is C dispatch state only: no runtime op.
    ///
    /// # Safety
    /// C ABI entry point.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_net_kind(fd: c_int) -> c_int {
        let state = lock_state();
        match state.net.sockets.get(&fd).map(|socket| socket.kind) {
            Some(SocketKind::Datagram) => 0,
            Some(SocketKind::StreamUnbound) => 1,
            Some(SocketKind::StreamListener) => 2,
            Some(SocketKind::Stream) => 3,
            None => -1,
        }
    }

    /// # Safety
    /// C ABI entry point; `fd` is a socket from [`patina_net_socket`].
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_net_bind(fd: c_int, ip: u32, port: u16) -> c_int {
        if let Err(errno) = sched_point() {
            return super::fail(errno);
        }
        let mut state = lock_state();
        let kind = match state.net.sockets.get(&fd) {
            Some(socket) => socket.kind,
            None => return super::fail(super::EBADF),
        };
        match kind {
            SocketKind::Datagram => {
                if state
                    .net
                    .sockets
                    .get(&fd)
                    .is_some_and(|s| s.socket_id.is_some())
                {
                    return super::fail(EINVAL);
                }
                let port = if port == 0 {
                    state.net.ephemeral()
                } else {
                    port
                };
                let address = format_addr(ip, port);
                let socket_id = match with_context_raw(|context| context.net_bind(&address)) {
                    Ok(socket_id) => socket_id,
                    Err(errno) => return super::fail(errno),
                };
                let socket = state.net.sockets.get_mut(&fd).expect("socket was checked");
                socket.socket_id = Some(socket_id);
                socket.address = Some(address.clone());
                socket.bound = Some((ip, port));
                state.net.bound.insert(address, fd);
                0
            }
            SocketKind::StreamUnbound => {
                if state
                    .net
                    .sockets
                    .get(&fd)
                    .is_some_and(|s| s.bound.is_some())
                {
                    return super::fail(EINVAL);
                }
                let port = if port == 0 {
                    state.net.ephemeral()
                } else {
                    port
                };
                let address = format_addr(ip, port);
                let socket = state.net.sockets.get_mut(&fd).expect("socket was checked");
                socket.address = Some(address);
                socket.bound = Some((ip, port));
                0
            }
            SocketKind::StreamListener | SocketKind::Stream => super::fail(EINVAL),
        }
    }

    /// # Safety
    /// C ABI entry point; datagram connect records only the peer address locally.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_net_connect(fd: c_int, ip: u32, port: u16) -> c_int {
        if let Err(errno) = sched_point() {
            return super::fail(errno);
        }
        let mut state = lock_state();
        match state.net.sockets.get_mut(&fd) {
            Some(socket) if socket.kind == SocketKind::Datagram => {
                socket.peer = Some((ip, port));
                0
            }
            Some(_) => super::fail(EOPNOTSUPP),
            None => super::fail(super::EBADF),
        }
    }

    /// # Safety
    /// C ABI entry point.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_net_listen(fd: c_int, backlog: c_int) -> c_int {
        if let Err(errno) = sched_point() {
            return super::fail(errno);
        }
        let mut state = lock_state();
        let (address, backlog) = match state.net.sockets.get(&fd) {
            Some(socket) if socket.kind == SocketKind::Datagram => return super::fail(EOPNOTSUPP),
            Some(socket)
                if matches!(socket.kind, SocketKind::StreamListener | SocketKind::Stream) =>
            {
                return super::fail(EINVAL);
            }
            Some(socket) => {
                let Some(address) = socket.address.clone() else {
                    return super::fail(EINVAL);
                };
                (address, backlog.max(1) as usize)
            }
            None => return super::fail(super::EBADF),
        };
        let socket_id = match with_context_raw(|context| context.net_tcp_listen(&address, backlog))
        {
            Ok(socket_id) => socket_id,
            Err(errno) => return super::fail(errno),
        };
        let socket = state.net.sockets.get_mut(&fd).expect("socket was checked");
        socket.socket_id = Some(socket_id);
        socket.kind = SocketKind::StreamListener;
        state.net.tcp_listeners.insert(address, fd);
        0
    }

    /// # Safety
    /// `ip_out`/`port_out` are writable when non-null.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_net_accept(
        fd: c_int,
        ip_out: *mut u32,
        port_out: *mut u16,
    ) -> c_int {
        if let Err(errno) = sched_point() {
            return super::fail(errno);
        }
        let me = current_task();
        loop {
            let mut state = lock_state();
            let (listener_id, local, bound, nonblocking) = match state.net.sockets.get(&fd) {
                Some(socket) if socket.kind == SocketKind::StreamListener => (
                    socket.socket_id.expect("listener has runtime socket id"),
                    socket.address.clone().expect("listener has address"),
                    socket.bound.expect("listener is bound"),
                    socket.nonblocking,
                ),
                Some(socket) if socket.kind == SocketKind::Datagram => {
                    return super::fail(EOPNOTSUPP);
                }
                Some(_) => return super::fail(EINVAL),
                None => return super::fail(super::EBADF),
            };
            match with_context_raw(|context| context.net_tcp_accept(listener_id)) {
                Ok(Some(accepted)) => {
                    let Some(peer) = parse_addr(&accepted.peer) else {
                        fatal("network driver returned malformed TCP peer address");
                    };
                    let new_fd = state.net.next_fd;
                    state.net.next_fd = state.net.next_fd.wrapping_add(1);
                    state.net.sockets.insert(
                        new_fd,
                        NetSocket {
                            kind: SocketKind::Stream,
                            socket_id: Some(accepted.socket),
                            address: Some(local.clone()),
                            bound: Some(bound),
                            peer: Some(peer),
                            nonblocking: false,
                            read_timeout_nanos: None,
                            stream_key: Some(accepted.peer.clone()),
                            recv_waiters: VecDeque::new(),
                            send_waiters: VecDeque::new(),
                        },
                    );
                    state
                        .net
                        .tcp_streams
                        .entry(accepted.peer)
                        .or_default()
                        .server = Some(new_fd);
                    if !ip_out.is_null() {
                        unsafe { ip_out.write(peer.0) };
                    }
                    if !port_out.is_null() {
                        unsafe { port_out.write(peer.1) };
                    }
                    return new_fd;
                }
                Ok(None) => {
                    if nonblocking {
                        return super::fail(EWOULDBLOCK);
                    }
                    state
                        .net
                        .sockets
                        .get_mut(&fd)
                        .expect("socket was checked")
                        .recv_waiters
                        .push_back(me);
                    let step = state.block(me, "tcp-accept");
                    match step {
                        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                        Ok(Step::Continue) => drop(state),
                        Err(error) => return error.into_posix(),
                    }
                    lock_state().timed_out.remove(&me);
                }
                Err(errno) => return super::fail(errno),
            }
        }
    }

    /// # Safety
    /// C ABI entry point.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_net_tcp_connect(fd: c_int, ip: u32, port: u16) -> c_int {
        if let Err(errno) = sched_point() {
            return super::fail(errno);
        }
        let mut state = lock_state();
        let (local, bound, destination) = match state.net.sockets.get(&fd) {
            Some(socket) if socket.kind == SocketKind::Stream => return super::fail(EISCONN),
            Some(socket) if socket.kind == SocketKind::StreamListener => {
                return super::fail(EOPNOTSUPP);
            }
            Some(socket) if socket.kind == SocketKind::Datagram => return super::fail(EOPNOTSUPP),
            Some(socket) => {
                let (local, bound) = match (socket.address.clone(), socket.bound) {
                    (Some(address), Some(bound)) => (address, bound),
                    _ => {
                        let local_ip = 0x7f00_0001;
                        let local_port = state.net.ephemeral();
                        (format_addr(local_ip, local_port), (local_ip, local_port))
                    }
                };
                (local, bound, format_addr(ip, port))
            }
            None => return super::fail(super::EBADF),
        };
        let socket_id =
            match with_context_raw(|context| context.net_tcp_connect(&local, &destination)) {
                Ok(socket_id) => socket_id,
                Err(errno) => return super::fail(errno),
            };
        let socket = state.net.sockets.get_mut(&fd).expect("socket was checked");
        socket.kind = SocketKind::Stream;
        socket.socket_id = Some(socket_id);
        socket.address = Some(local.clone());
        socket.bound = Some(bound);
        socket.peer = Some((ip, port));
        socket.stream_key = Some(local.clone());
        state.net.tcp_streams.entry(local).or_default().client = Some(fd);
        // Wake whoever is blocked in `accept`, resolving the listener the same
        // exact-then-wildcard way the runtime routed the connection.
        let listener_address = resolve_listener_address(&state, &destination);
        let waiters = state
            .net
            .tcp_listeners
            .get(&listener_address)
            .copied()
            .map(|listener_fd| drain_recv_waiters(&mut state, listener_fd))
            .unwrap_or_default();
        drop(state);
        wake_all(waiters);
        0
    }

    fn net_send_to(fd: c_int, bytes: &[u8], destination: &str) -> isize {
        let mut state = lock_state();
        let socket_id = match state.net.sockets.get(&fd) {
            Some(socket) if socket.kind == SocketKind::Datagram => match socket.socket_id {
                Some(socket_id) => socket_id,
                None => return super::fail(super::EBADF) as isize,
            },
            Some(_) => return super::fail(EOPNOTSUPP) as isize,
            None => return super::fail(super::EBADF) as isize,
        };
        let report =
            match with_context_raw(|context| context.net_send(socket_id, destination, bytes)) {
                Ok(report) => report,
                Err(errno) => return super::fail(errno) as isize,
            };
        let bound_address = resolve_bound_address(&state, destination);
        let waiters = state
            .net
            .bound
            .get(&bound_address)
            .copied()
            .map(|destination_fd| drain_recv_waiters(&mut state, destination_fd))
            .unwrap_or_default();
        drop(state);
        wake_all(waiters);
        isize::try_from(report.written).unwrap_or(isize::MAX)
    }

    /// # Safety
    /// `buf` must be readable for `len` bytes when nonzero.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_net_sendto(
        fd: c_int,
        buf: *const c_void,
        len: usize,
        ip: u32,
        port: u16,
    ) -> isize {
        if let Err(errno) = sched_point() {
            return super::fail(errno) as isize;
        }
        if len != 0 && buf.is_null() {
            return super::fail(EINVAL) as isize;
        }
        let bytes = if len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len) }
        };
        net_send_to(fd, bytes, &format_addr(ip, port))
    }

    /// # Safety
    /// `buf` must be readable for `len` bytes when nonzero.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_net_send(fd: c_int, buf: *const c_void, len: usize) -> isize {
        if let Err(errno) = sched_point() {
            return super::fail(errno) as isize;
        }
        if len != 0 && buf.is_null() {
            return super::fail(EINVAL) as isize;
        }
        let peer = {
            let state = lock_state();
            match state.net.sockets.get(&fd) {
                Some(socket) if socket.kind == SocketKind::Datagram => socket.peer,
                Some(_) => return super::fail(EOPNOTSUPP) as isize,
                None => return super::fail(super::EBADF) as isize,
            }
        };
        let Some((ip, port)) = peer else {
            return super::fail(ENOTCONN) as isize;
        };
        let bytes = if len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len) }
        };
        net_send_to(fd, bytes, &format_addr(ip, port))
    }

    /// # Safety
    /// `buf` must be readable for `len` bytes when nonzero.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_net_stream_send(
        fd: c_int,
        buf: *const c_void,
        len: usize,
    ) -> isize {
        if let Err(errno) = sched_point() {
            return super::fail(errno) as isize;
        }
        if len != 0 && buf.is_null() {
            return super::fail(EINVAL) as isize;
        }
        if len == 0 {
            return 0;
        }
        let bytes = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len) };
        let me = current_task();
        loop {
            let mut state = lock_state();
            let (socket_id, nonblocking) = match state.net.sockets.get(&fd) {
                Some(socket) if socket.kind == SocketKind::Stream => (
                    socket.socket_id.expect("stream has runtime socket id"),
                    socket.nonblocking,
                ),
                Some(_) => return super::fail(ENOTCONN) as isize,
                None => return super::fail(super::EBADF) as isize,
            };
            match with_context_raw(|context| context.net_tcp_send(socket_id, bytes)) {
                Ok(written) if written > 0 => {
                    let waiters = peer_fd(&state, fd)
                        .map(|peer_fd| drain_recv_waiters(&mut state, peer_fd))
                        .unwrap_or_default();
                    drop(state);
                    wake_all(waiters);
                    return isize::try_from(written).unwrap_or(isize::MAX);
                }
                Ok(0) => {
                    if nonblocking {
                        return super::fail(EWOULDBLOCK) as isize;
                    }
                    state
                        .net
                        .sockets
                        .get_mut(&fd)
                        .expect("socket was checked")
                        .send_waiters
                        .push_back(me);
                    let step = state.block(me, "tcp-send");
                    match step {
                        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                        Ok(Step::Continue) => drop(state),
                        Err(error) => return super::fail(error.into_posix()) as isize,
                    }
                    lock_state().timed_out.remove(&me);
                }
                Ok(_) => {
                    fatal("TCP send returned more bytes than requested after zero-length check")
                }
                Err(errno) => return super::fail(errno) as isize,
            }
        }
    }

    // SAFETY: `buf`/`ip_out`/`port_out` are writable per the C ABI contract.
    unsafe fn deliver_datagram(
        datagram: &Datagram,
        buf: *mut c_void,
        len: usize,
        ip_out: *mut u32,
        port_out: *mut u16,
    ) -> isize {
        let count = datagram.bytes.len().min(len);
        if count > 0 && !buf.is_null() {
            unsafe {
                std::slice::from_raw_parts_mut(buf.cast::<u8>(), count)
                    .copy_from_slice(&datagram.bytes[..count]);
            }
        }
        if let Some((ip, port)) = parse_addr(&datagram.from) {
            if !ip_out.is_null() {
                unsafe { ip_out.write(ip) };
            }
            if !port_out.is_null() {
                unsafe { port_out.write(port) };
            }
        }
        isize::try_from(count).unwrap_or(isize::MAX)
    }

    /// Blocking datagram receive.
    ///
    /// # Safety
    /// `buf` must be writable for `len` bytes; `ip_out`/`port_out` writable or null.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_net_recvfrom(
        fd: c_int,
        buf: *mut c_void,
        len: usize,
        ip_out: *mut u32,
        port_out: *mut u16,
    ) -> isize {
        if let Err(errno) = sched_point() {
            return super::fail(errno) as isize;
        }
        let me = current_task();
        // Absolute virtual deadline for a `SO_RCVTIMEO` receive, fixed on the
        // first block from entry time so it does not drift across re-checks.
        let mut timeout_deadline: Option<u64> = None;
        loop {
            let mut state = lock_state();
            let (socket_id, nonblocking, read_timeout) = match state.net.sockets.get(&fd) {
                Some(socket) if socket.kind == SocketKind::Datagram => match socket.socket_id {
                    Some(socket_id) => (socket_id, socket.nonblocking, socket.read_timeout_nanos),
                    None => return super::fail(super::EBADF) as isize,
                },
                Some(_) => return super::fail(EOPNOTSUPP) as isize,
                None => return super::fail(super::EBADF) as isize,
            };
            match with_context_raw(|context| context.net_recv(socket_id)) {
                Ok(Some(datagram)) => {
                    drop(state);
                    return unsafe { deliver_datagram(&datagram, buf, len, ip_out, port_out) };
                }
                Ok(None) => {
                    if nonblocking {
                        return super::fail(EWOULDBLOCK) as isize;
                    }
                    // Deterministic SO_RCVTIMEO. `net_recv` above is checked
                    // first every iteration, so a datagram deliverable at exactly
                    // the timeout instant is returned rather than timing out:
                    // delivery wins ties. The deadline is captured once (relative
                    // to entry) and the park below is bounded by it.
                    if let Some(rt) = read_timeout {
                        let now = match with_context_raw(|c| c.now(ClockKind::Monotonic)) {
                            Ok(now) => now,
                            Err(errno) => return super::fail(errno) as isize,
                        };
                        let deadline = *timeout_deadline.get_or_insert(now.saturating_add(rt));
                        if now >= deadline {
                            return super::fail(EWOULDBLOCK) as isize;
                        }
                    }
                    state
                        .net
                        .sockets
                        .get_mut(&fd)
                        .expect("socket was checked")
                        .recv_waiters
                        .push_back(me);
                    let delivery = match with_context_raw(|c| c.net_next_delivery(socket_id)) {
                        Ok(delivery) => delivery,
                        Err(errno) => return super::fail(errno) as isize,
                    };
                    // Park until the earlier of the next delivery and the receive
                    // timeout; block indefinitely only when neither bounds it.
                    let park_deadline = match (delivery, timeout_deadline) {
                        (Some(delivery), Some(timeout)) => Some(delivery.min(timeout)),
                        (Some(delivery), None) => Some(delivery),
                        (None, Some(timeout)) => Some(timeout),
                        (None, None) => None,
                    };
                    let step = match park_deadline {
                        Some(deadline) => {
                            state.block_timed(me, "net-recv", ClockKind::Monotonic, deadline)
                        }
                        None => state.block(me, "net-recv"),
                    };
                    match step {
                        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                        Ok(Step::Continue) => drop(state),
                        Err(error) => return super::fail(error.into_posix()) as isize,
                    }
                    lock_state().timed_out.remove(&me);
                }
                Err(errno) => return super::fail(errno) as isize,
            }
        }
    }

    /// # Safety
    /// `buf` must be writable for `len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_net_recv(fd: c_int, buf: *mut c_void, len: usize) -> isize {
        unsafe { patina_net_recvfrom(fd, buf, len, std::ptr::null_mut(), std::ptr::null_mut()) }
    }

    /// # Safety
    /// `buf` must be writable for `len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_net_stream_recv(
        fd: c_int,
        buf: *mut c_void,
        len: usize,
    ) -> isize {
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
            let (socket_id, nonblocking) = match state.net.sockets.get(&fd) {
                Some(socket) if socket.kind == SocketKind::Stream => (
                    socket.socket_id.expect("stream has runtime socket id"),
                    socket.nonblocking,
                ),
                Some(_) => return super::fail(ENOTCONN) as isize,
                None => return super::fail(super::EBADF) as isize,
            };
            match with_context_raw(|context| context.net_tcp_recv(socket_id, len)) {
                Ok(Some(bytes)) => {
                    if bytes.len() > len {
                        fatal("network driver returned more TCP bytes than requested");
                    }
                    if !bytes.is_empty() {
                        unsafe {
                            std::slice::from_raw_parts_mut(buf.cast::<u8>(), bytes.len())
                                .copy_from_slice(&bytes);
                        }
                    }
                    let waiters = if bytes.is_empty() {
                        Vec::new()
                    } else {
                        peer_fd(&state, fd)
                            .map(|peer_fd| drain_send_waiters(&mut state, peer_fd))
                            .unwrap_or_default()
                    };
                    drop(state);
                    wake_all(waiters);
                    return isize::try_from(bytes.len()).unwrap_or(isize::MAX);
                }
                Ok(None) => {
                    if nonblocking {
                        return super::fail(EWOULDBLOCK) as isize;
                    }
                    state
                        .net
                        .sockets
                        .get_mut(&fd)
                        .expect("socket was checked")
                        .recv_waiters
                        .push_back(me);
                    let delivery = match with_context_raw(|c| c.net_next_delivery(socket_id)) {
                        Ok(delivery) => delivery,
                        Err(errno) => return super::fail(errno) as isize,
                    };
                    let step = match delivery {
                        Some(deadline) => {
                            state.block_timed(me, "tcp-recv", ClockKind::Monotonic, deadline)
                        }
                        None => state.block(me, "tcp-recv"),
                    };
                    match step {
                        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                        Ok(Step::Continue) => drop(state),
                        Err(error) => return super::fail(error.into_posix()) as isize,
                    }
                    lock_state().timed_out.remove(&me);
                }
                Err(errno) => return super::fail(errno) as isize,
            }
        }
    }

    /// # Safety
    /// C ABI entry point.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_net_shutdown(fd: c_int, how: c_int) -> c_int {
        if let Err(errno) = sched_point() {
            return super::fail(errno);
        }
        let how = match how {
            0 => ShutdownHow::Read,
            1 => ShutdownHow::Write,
            2 => ShutdownHow::Both,
            _ => return super::fail(EINVAL),
        };
        let mut state = lock_state();
        let socket_id = match state.net.sockets.get(&fd) {
            Some(socket) if socket.kind == SocketKind::Stream => {
                socket.socket_id.expect("stream has runtime socket id")
            }
            Some(socket) if socket.kind == SocketKind::StreamUnbound => {
                return super::fail(ENOTCONN);
            }
            Some(_) => return super::fail(EOPNOTSUPP),
            None => return super::fail(super::EBADF),
        };
        if let Err(errno) = with_context_raw(|context| context.net_tcp_shutdown(socket_id, how)) {
            return super::fail(errno);
        }
        let peer_fd = peer_fd(&state, fd);
        let mut waiters = Vec::new();
        if matches!(how, ShutdownHow::Write | ShutdownHow::Both) {
            if let Some(peer_fd) = peer_fd {
                waiters.extend(drain_recv_waiters(&mut state, peer_fd));
            }
        }
        if matches!(how, ShutdownHow::Read | ShutdownHow::Both) {
            if let Some(peer_fd) = peer_fd {
                waiters.extend(drain_send_waiters(&mut state, peer_fd));
            }
            waiters.extend(drain_recv_waiters(&mut state, fd));
        }
        drop(state);
        wake_all(waiters);
        0
    }

    /// # Safety
    /// `ip_out`/`port_out` must be writable.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_net_getsockname(
        fd: c_int,
        ip_out: *mut u32,
        port_out: *mut u16,
    ) -> c_int {
        if ip_out.is_null() || port_out.is_null() {
            return super::fail(EINVAL);
        }
        let state = lock_state();
        let Some(socket) = state.net.sockets.get(&fd) else {
            return super::fail(super::EBADF);
        };
        let (ip, port) = socket.bound.unwrap_or((0, 0));
        unsafe {
            ip_out.write(ip);
            port_out.write(port);
        }
        0
    }

    /// # Safety
    /// `ip_out`/`port_out` must be writable.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_net_getpeername(
        fd: c_int,
        ip_out: *mut u32,
        port_out: *mut u16,
    ) -> c_int {
        if ip_out.is_null() || port_out.is_null() {
            return super::fail(EINVAL);
        }
        let state = lock_state();
        let Some(socket) = state.net.sockets.get(&fd) else {
            return super::fail(super::EBADF);
        };
        let Some((ip, port)) = socket.peer else {
            return super::fail(ENOTCONN);
        };
        unsafe {
            ip_out.write(ip);
            port_out.write(port);
        }
        0
    }

    /// Mark a socket blocking (0) or non-blocking (nonzero).
    ///
    /// # Safety
    /// C ABI entry point.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_net_set_nonblocking(fd: c_int, nonblocking: c_int) -> c_int {
        let mut state = lock_state();
        match state.net.sockets.get_mut(&fd) {
            Some(socket) => {
                socket.nonblocking = nonblocking != 0;
                0
            }
            None => super::fail(super::EBADF),
        }
    }

    /// Set a socket's `SO_RCVTIMEO` in virtual nanoseconds. A zero clears the
    /// timeout (POSIX: block indefinitely); any nonzero value bounds a later
    /// blocking receive by that many nanoseconds of virtual time from entry.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_net_set_read_timeout(fd: c_int, nanos: u64) -> c_int {
        let mut state = lock_state();
        match state.net.sockets.get_mut(&fd) {
            Some(socket) => {
                socket.read_timeout_nanos = (nanos != 0).then_some(nanos);
                0
            }
            None => super::fail(super::EBADF),
        }
    }

    /// Report whether a socket is non-blocking (1), blocking (0), or not a
    /// managed socket (-1).
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_net_is_nonblocking(fd: c_int) -> c_int {
        let state = lock_state();
        match state.net.sockets.get(&fd) {
            Some(socket) => c_int::from(socket.nonblocking),
            None => -1,
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

    /// Close a virtual socket.
    ///
    /// # Safety
    /// C ABI entry point.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_net_close(fd: c_int) -> c_int {
        let mut state = lock_state();
        let Some(socket) = state.net.sockets.remove(&fd) else {
            return super::fail(super::EBADF);
        };
        let mut waiters = Vec::new();
        match socket.kind {
            SocketKind::Datagram => {
                if let Some(address) = &socket.address {
                    state.net.bound.remove(address);
                }
            }
            SocketKind::StreamListener => {
                if let Some(address) = &socket.address {
                    state.net.tcp_listeners.remove(address);
                }
                waiters.extend(socket.recv_waiters);
                waiters.extend(socket.send_waiters);
            }
            SocketKind::Stream => {
                // The socket is already out of the table, so take the peer from
                // the connection entry directly, then drop this side from it —
                // and the whole entry once both sides are gone.
                if let Some(key) = &socket.stream_key {
                    let peer = state
                        .net
                        .tcp_streams
                        .get(key)
                        .and_then(|pair| pair.other(fd));
                    if let Some(pair) = state.net.tcp_streams.get_mut(key) {
                        if pair.client == Some(fd) {
                            pair.client = None;
                        }
                        if pair.server == Some(fd) {
                            pair.server = None;
                        }
                        if pair.is_empty() {
                            state.net.tcp_streams.remove(key);
                        }
                    }
                    if let Some(peer_fd) = peer {
                        waiters.extend(drain_recv_waiters(&mut state, peer_fd));
                        waiters.extend(drain_send_waiters(&mut state, peer_fd));
                    }
                }
                waiters.extend(socket.recv_waiters);
                waiters.extend(socket.send_waiters);
            }
            SocketKind::StreamUnbound => {
                waiters.extend(socket.recv_waiters);
                waiters.extend(socket.send_waiters);
            }
        }
        if let Some(socket_id) = socket.socket_id {
            if let Err(errno) = with_context_raw(|context| context.net_close(socket_id)) {
                return super::fail(errno);
            }
        }
        drop(state);
        wake_all(waiters);
        0
    }

    // ------------------------------------------------------------------
    // In-process pipe / socketpair. Both endpoints of a `pipe`/`pipe2`/
    // `socketpair` live inside this one guest process (the common case: an async
    // runtime's IO-driver / signal self-pipe wakeup), so there is no cross-
    // address-space escape — they are modeled as deterministic in-memory byte
    // channels whose reads/writes are scheduler-visible, reusing the SAME baton /
    // waiter machinery the virtual sockets use (block / switch_and_park / wake).
    // Being pure in-process memory that only ever mutates while the acting task
    // holds the baton, the transfer is deterministic GIVEN the schedule — exactly
    // like the futex / mutex words — so it carries NO trace events of its own: the
    // recorded scheduler steps already pin every interleaving, so record and
    // flag-free replay converge on that. No host call is ever made.

    /// A bounded, directed byte channel: one writer endpoint feeds it, one reader
    /// endpoint drains it. A simplex `pipe` is a single channel; a duplex
    /// `socketpair` is two of them (one per direction).
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
        /// Every reader fd of this side has closed: further writes get `EPIPE`.
        read_closed: bool,
        /// Every writer fd of this side has closed: reads return EOF once drained.
        write_closed: bool,
        /// Tasks parked in a blocking read, waiting for bytes to arrive.
        recv_waiters: VecDeque<TaskId>,
        /// Tasks parked in a blocking write, waiting for buffer space.
        send_waiters: VecDeque<TaskId>,
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
                read_closed: false,
                write_closed: false,
                recv_waiters: VecDeque::new(),
                send_waiters: VecDeque::new(),
                #[cfg(target_os = "linux")]
                read_events: 0,
                #[cfg(target_os = "linux")]
                write_events: 0,
            }
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
            } else if self.write_closed {
                PipeRead::Eof
            } else {
                PipeRead::WouldBlock
            }
        }

        /// Push as many of `src`'s bytes as fit. `WouldBlock` when the buffer is
        /// full and the reader is open (the caller parks); a closed reader is
        /// `BrokenPipe` (the caller returns `EPIPE`, never a signal).
        fn try_write(&mut self, src: &[u8]) -> PipeWrite {
            if self.read_closed {
                return PipeWrite::BrokenPipe;
            }
            let space = self.capacity - self.buffer.len();
            if space == 0 {
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

    /// One end of a pipe/socketpair. `read_channel`/`write_channel` name the
    /// directed [`PipeChannel`]s this endpoint may drain / feed; a simplex pipe
    /// end holds exactly one of them, a duplex socketpair end holds both.
    struct PipeEnd {
        read_channel: Option<u64>,
        write_channel: Option<u64>,
        nonblocking: bool,
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

    /// Open a deterministic read-only directory fd bound to `path`, and register
    /// that fd as a directory handle for the `fdopendir`/`unlinkat`/`openat`
    /// interposers. The caller (the C `open/openat(..., O_DIRECTORY)` interposer)
    /// has already validated that `path` names a directory and resolved any
    /// trailing symlink. Because the returned fd is also a real filesystem fd,
    /// `fstat` reports a directory and `fsync` routes to the crash model's
    /// namespace-durability barrier.
    ///
    /// # Safety
    /// `path` must point to a valid NUL-terminated UTF-8 string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_diropen(path: *const c_char) -> c_int {
        let path = match super::path_from_c(path) {
            Ok(path) => path,
            Err(errno) => return super::fail(errno),
        };
        let fd = match super::with_context(|context| {
            context.fs_open(&path, super::OpenFlags::read_only())
        }) {
            Ok(fd) => fd,
            Err(errno) => return super::fail(errno),
        };
        let fd = match c_int::try_from(fd.0) {
            Ok(fd) => fd,
            Err(_) => return super::fail(super::EOVERFLOW),
        };
        lock_state().net.dir_fds.insert(fd, path);
        super::set_errno(0);
        fd
    }

    /// C dispatch predicate: is `fd` a virtual directory descriptor? Lets the
    /// interposed `close` (and the *at resolver) tell a dir fd apart from a
    /// socket/pipe/kqueue endpoint in the shared virtual-fd space.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_dir_is_dirfd(fd: c_int) -> c_int {
        c_int::from(lock_state().net.dir_fds.contains_key(&fd))
    }

    /// Copy the canonical path a directory descriptor is bound to into `buf`,
    /// NUL-terminated when it fits, returning the path length in bytes (excluding
    /// the terminator). A negative return sets `patina_errno` to `EBADF` for an
    /// unknown fd. Mirrors [`patina_canonicalize`]'s length/terminator contract.
    ///
    /// # Safety
    /// `buf` must be writable for `len` bytes when `len` is nonzero.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_dirpath(fd: c_int, buf: *mut c_char, len: usize) -> isize {
        if len != 0 && buf.is_null() {
            return super::fail(super::EINVAL) as isize;
        }
        let state = lock_state();
        let Some(path) = state.net.dir_fds.get(&fd) else {
            return super::fail(super::EBADF) as isize;
        };
        let bytes = path.as_bytes();
        let needed = bytes.len();
        if len != 0 && needed < len {
            // SAFETY: `buf` is writable for `len` bytes and `needed < len` leaves
            // room for the trailing NUL.
            unsafe {
                let destination = std::slice::from_raw_parts_mut(buf.cast::<u8>(), len);
                destination[..needed].copy_from_slice(bytes);
                destination[needed] = 0;
            }
        }
        super::set_errno(0);
        isize::try_from(needed).unwrap_or_else(|_| super::fail(super::EOVERFLOW) as isize)
    }

    /// Release a virtual directory descriptor (the `closedir`/`close` owner).
    /// The fd is also an open deterministic filesystem descriptor, so closing the
    /// directory handle closes the underlying filesystem handle as POSIX
    /// `closedir` requires. Returns `EBADF` for an unknown fd.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_dirclose(fd: c_int) -> c_int {
        if lock_state().net.dir_fds.remove(&fd).is_some() {
            super::patina_close(fd)
        } else {
            super::fail(super::EBADF)
        }
    }

    /// Create a simplex pipe: `read_fd_out` is the read end, `write_fd_out` the
    /// write end, both non-blocking when `nonblocking != 0`. Endpoints and the
    /// backing channel are allocated from the shared virtual-fd / channel
    /// counters, so their numbering is a pure function of the schedule. Activates
    /// the thread subsystem so a later blocking read/write can park via the baton.
    ///
    /// # Safety
    /// `read_fd_out`/`write_fd_out` must be writable.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_pipe(
        read_fd_out: *mut c_int,
        write_fd_out: *mut c_int,
        nonblocking: c_int,
    ) -> c_int {
        if read_fd_out.is_null() || write_fd_out.is_null() {
            return super::fail(EINVAL);
        }
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return super::fail(error.into_posix());
        }
        let channel = state.net.next_channel;
        state.net.next_channel = state.net.next_channel.wrapping_add(1);
        state
            .net
            .pipe_channels
            .insert(channel, PipeChannel::new(PIPE_CAPACITY));
        let read_fd = state.net.next_fd;
        state.net.next_fd = state.net.next_fd.wrapping_add(1);
        let write_fd = state.net.next_fd;
        state.net.next_fd = state.net.next_fd.wrapping_add(1);
        state.net.pipe_ends.insert(
            read_fd,
            PipeEnd {
                read_channel: Some(channel),
                write_channel: None,
                nonblocking: nonblocking != 0,
            },
        );
        state.net.pipe_ends.insert(
            write_fd,
            PipeEnd {
                read_channel: None,
                write_channel: Some(channel),
                nonblocking: nonblocking != 0,
            },
        );
        unsafe {
            read_fd_out.write(read_fd);
            write_fd_out.write(write_fd);
        }
        0
    }

    /// Create a duplex AF_UNIX/SOCK_STREAM pair: `fd0_out` and `fd1_out` are
    /// interchangeable bidirectional endpoints. Two directed channels back them
    /// (fd0 → fd1 and fd1 → fd0), so each end reads what the other writes.
    ///
    /// # Safety
    /// `fd0_out`/`fd1_out` must be writable.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_socketpair(
        fd0_out: *mut c_int,
        fd1_out: *mut c_int,
        nonblocking: c_int,
    ) -> c_int {
        if fd0_out.is_null() || fd1_out.is_null() {
            return super::fail(EINVAL);
        }
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return super::fail(error.into_posix());
        }
        let channel_0to1 = state.net.next_channel;
        let channel_1to0 = channel_0to1.wrapping_add(1);
        state.net.next_channel = channel_1to0.wrapping_add(1);
        state
            .net
            .pipe_channels
            .insert(channel_0to1, PipeChannel::new(PIPE_CAPACITY));
        state
            .net
            .pipe_channels
            .insert(channel_1to0, PipeChannel::new(PIPE_CAPACITY));
        let fd0 = state.net.next_fd;
        state.net.next_fd = state.net.next_fd.wrapping_add(1);
        let fd1 = state.net.next_fd;
        state.net.next_fd = state.net.next_fd.wrapping_add(1);
        state.net.pipe_ends.insert(
            fd0,
            PipeEnd {
                read_channel: Some(channel_1to0),
                write_channel: Some(channel_0to1),
                nonblocking: nonblocking != 0,
            },
        );
        state.net.pipe_ends.insert(
            fd1,
            PipeEnd {
                read_channel: Some(channel_0to1),
                write_channel: Some(channel_1to0),
                nonblocking: nonblocking != 0,
            },
        );
        unsafe {
            fd0_out.write(fd0);
            fd1_out.write(fd1);
        }
        0
    }

    /// C dispatch predicate: is `fd` a pipe/socketpair endpoint? Lets the
    /// interposed read/write/close/fcntl route the shared virtual-fd space to the
    /// pipe class versus the socket class.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_pipe_is_endpoint(fd: c_int) -> c_int {
        c_int::from(lock_state().net.pipe_ends.contains_key(&fd))
    }

    /// Blocking (or `O_NONBLOCK`) read from a pipe/socketpair endpoint.
    ///
    /// # Safety
    /// `buf` must be writable for `len` bytes when nonzero.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_pipe_read(fd: c_int, buf: *mut c_void, len: usize) -> isize {
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
            let (channel, nonblocking) = match state.net.pipe_ends.get(&fd) {
                // A read on the write-only end of a simplex pipe is EBADF (the end
                // is O_WRONLY), matching the kernel.
                Some(end) => match end.read_channel {
                    Some(channel) => (channel, end.nonblocking),
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
                    let step = state.block(me, "pipe-read");
                    match step {
                        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                        Ok(Step::Continue) => drop(state),
                        Err(error) => return super::fail(error.into_posix()) as isize,
                    }
                    lock_state().timed_out.remove(&me);
                }
            }
        }
    }

    /// Blocking (or `O_NONBLOCK`) write to a pipe/socketpair endpoint.
    ///
    /// # Safety
    /// `buf` must be readable for `len` bytes when nonzero.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_pipe_write(fd: c_int, buf: *const c_void, len: usize) -> isize {
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
        loop {
            let mut state = lock_state();
            let (channel, nonblocking) = match state.net.pipe_ends.get(&fd) {
                // A write on the read-only end of a simplex pipe is EBADF.
                Some(end) => match end.write_channel {
                    Some(channel) => (channel, end.nonblocking),
                    None => return super::fail(super::EBADF) as isize,
                },
                None => return super::fail(super::EBADF) as isize,
            };
            let outcome = state
                .net
                .pipe_channels
                .get_mut(&channel)
                .map(|channel| channel.try_write(src))
                .unwrap_or(PipeWrite::BrokenPipe);
            match outcome {
                PipeWrite::Wrote(count) => {
                    let waiters = drain_channel_recv_waiters(&mut state, channel);
                    drop(state);
                    wake_all(waiters);
                    return isize::try_from(count).unwrap_or(isize::MAX);
                }
                // Peer reader closed: EPIPE, and crucially NO SIGPIPE — the shim
                // delivers no signals, so a broken-pipe write is a clean errno the
                // guest handles, never a process-killing signal.
                PipeWrite::BrokenPipe => return super::fail(super::EPIPE) as isize,
                PipeWrite::WouldBlock => {
                    if nonblocking {
                        return super::fail(EWOULDBLOCK) as isize;
                    }
                    if let Some(channel) = state.net.pipe_channels.get_mut(&channel) {
                        channel.send_waiters.push_back(me);
                    }
                    let step = state.block(me, "pipe-write");
                    match step {
                        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                        Ok(Step::Continue) => drop(state),
                        Err(error) => return super::fail(error.into_posix()) as isize,
                    }
                    lock_state().timed_out.remove(&me);
                }
            }
        }
    }

    /// Duplicate a pipe/socketpair endpoint: the new fd aliases the SAME channel
    /// side(s), raising the per-side reference count so the peer sees EOF/EPIPE
    /// only once EVERY aliasing fd of that side has closed. `std`'s `try_clone`
    /// (reached via `fcntl(F_DUPFD_CLOEXEC)`) drives this — tokio's signal driver
    /// clones a socketpair endpoint at runtime build. The clone inherits the
    /// blocking flag, matching a real `F_DUPFD_CLOEXEC` (which copies the file
    /// description, so `O_NONBLOCK` is shared). Returns the new fd or -1/EBADF.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_pipe_dup(fd: c_int) -> c_int {
        let mut state = lock_state();
        let Some(&PipeEnd {
            read_channel,
            write_channel,
            nonblocking,
        }) = state.net.pipe_ends.get(&fd)
        else {
            return super::fail(super::EBADF);
        };
        if let Some(channel) = read_channel {
            state
                .net
                .pipe_channels
                .get_mut(&channel)
                .expect("live endpoint references a live channel")
                .read_refs += 1;
        }
        if let Some(channel) = write_channel {
            state
                .net
                .pipe_channels
                .get_mut(&channel)
                .expect("live endpoint references a live channel")
                .write_refs += 1;
        }
        let new_fd = state.net.next_fd;
        state.net.next_fd = state.net.next_fd.wrapping_add(1);
        state.net.pipe_ends.insert(
            new_fd,
            PipeEnd {
                read_channel,
                write_channel,
                nonblocking,
            },
        );
        new_fd
    }

    /// Close a pipe/socketpair endpoint. A channel SIDE closes — waking the peer
    /// with EPIPE (readers gone) or EOF (writers gone) — only on the LAST fd of
    /// that side; a surviving `dup` keeps it open.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_pipe_close(fd: c_int) -> c_int {
        let mut state = lock_state();
        let Some(end) = state.net.pipe_ends.remove(&fd) else {
            return super::fail(super::EBADF);
        };
        let mut waiters = Vec::new();
        // Dropping a READER reference: writers get EPIPE only once the last one
        // goes, and only then are blocked writers woken to observe it.
        if let Some(channel) = end.read_channel {
            if let Some(channel) = state.net.pipe_channels.get_mut(&channel) {
                channel.read_refs -= 1;
                if channel.read_refs == 0 {
                    channel.read_closed = true;
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
                    channel.write_closed = true;
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
                state.net.pipe_channels.remove(&channel);
            }
        }
        drop(state);
        wake_all(waiters);
        0
    }

    /// Report whether a pipe/socketpair endpoint is non-blocking (1), blocking
    /// (0), or not a pipe endpoint (-1).
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_pipe_is_nonblocking(fd: c_int) -> c_int {
        let state = lock_state();
        match state.net.pipe_ends.get(&fd) {
            Some(end) => c_int::from(end.nonblocking),
            None => -1,
        }
    }

    /// Set a pipe/socketpair endpoint blocking (0) or non-blocking (nonzero), the
    /// `fcntl(F_SETFL, O_NONBLOCK)` path.
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_pipe_set_nonblocking(fd: c_int, nonblocking: c_int) -> c_int {
        let mut state = lock_state();
        match state.net.pipe_ends.get_mut(&fd) {
            Some(end) => {
                end.nonblocking = nonblocking != 0;
                0
            }
            None => super::fail(super::EBADF),
        }
    }

    // ------------------------------------------------------------------
    // eventfd (Linux). A deterministic in-process model of the kernel's 64-bit
    // event counter — mio's `Waker` vehicle on Linux, the EVFILT_USER analogue.
    // The fd shares the virtual-fd space (a virtual fd is a socket XOR a pipe
    // endpoint XOR an eventfd XOR an epoll fd); the C read/write/close route it
    // here by table membership. Like the pipe channels, the counter is
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
        nonblocking: bool,
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
        let fd = state.net.next_fd;
        state.net.next_fd = state.net.next_fd.wrapping_add(1);
        state.net.eventfds.insert(
            fd,
            EventFd {
                value: u64::from(initval),
                semaphore: flags & EFD_SEMAPHORE != 0,
                nonblocking: flags & EFD_NONBLOCK != 0,
                write_events: 0,
                read_waiters: VecDeque::new(),
            },
        );
        fd
    }

    /// C dispatch predicate: is `fd` a virtual eventfd?
    #[cfg(target_os = "linux")]
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_eventfd_is(fd: c_int) -> c_int {
        c_int::from(lock_state().net.eventfds.contains_key(&fd))
    }

    /// Read a virtual eventfd: 8 bytes, returns-and-resets the counter (or
    /// returns 1 and decrements under EFD_SEMAPHORE). A zero counter is
    /// `EWOULDBLOCK` under EFD_NONBLOCK, otherwise the caller parks until a
    /// write arrives.
    ///
    /// # Safety
    /// `buf` must be writable for `len` bytes.
    #[cfg(target_os = "linux")]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_eventfd_read(fd: c_int, buf: *mut c_void, len: usize) -> isize {
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
            if efd.nonblocking {
                return super::fail(EWOULDBLOCK) as isize;
            }
            efd.read_waiters.push_back(me);
            let step = state.block(me, "eventfd-read");
            match step {
                Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                Ok(Step::Continue) => drop(state),
                Err(error) => return super::fail(error.into_posix()) as isize,
            }
            lock_state().timed_out.remove(&me);
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
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn patina_eventfd_write(
        fd: c_int,
        buf: *const c_void,
        len: usize,
    ) -> isize {
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

    /// Close a virtual eventfd, waking any parked readers (they observe EBADF —
    /// loud, deterministic — rather than parking forever on a dead counter).
    #[cfg(target_os = "linux")]
    #[unsafe(no_mangle)]
    pub extern "C" fn patina_eventfd_close(fd: c_int) -> c_int {
        let mut state = lock_state();
        let Some(efd) = state.net.eventfds.remove(&fd) else {
            return super::fail(super::EBADF);
        };
        let waiters: Vec<TaskId> = efd.read_waiters.into_iter().collect();
        drop(state);
        wake_all(waiters);
        0
    }

    // ------------------------------------------------------------------
    // kqueue / kevent readiness reactor (macOS). A deterministic in-process
    // model of the BSD readiness multiplexer that mio (and therefore tokio)
    // builds its IO driver on. A `kqueue` fd is drawn from the shared virtual-fd
    // space; `kevent`/`kevent64` register EVFILT_READ/WRITE interest over the
    // virtual pipe/socketpair and SimNet socket fds, an EVFILT_USER self-wakeup
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

    /// Level-triggered readiness of a virtual descriptor, for the kqueue/epoll
    /// reactors. A pipe/socketpair endpoint is read from in-shim channel state;
    /// an eventfd (Linux) from its in-shim counter; a SimNet socket from the
    /// runtime's unrecorded `net_readiness`.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[derive(Clone, Copy)]
    struct FdReadiness {
        readable: bool,
        writable: bool,
        read_eof: bool,
        write_eof: bool,
    }

    /// Compute the readiness of virtual descriptor `fd` without consuming any
    /// bytes or recording a boundary op. A descriptor that no longer exists (it
    /// was closed after registration) reports ready-with-EOF so the reactor wakes
    /// and the subsequent operation surfaces the error, and the knote drops out.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn fd_readiness(state: &ThreadRuntime, fd: c_int) -> FdReadiness {
        // Pipe/socketpair endpoint: readiness is pure in-shim channel state, so
        // it needs no runtime op and emits no trace event.
        if let Some(end) = state.net.pipe_ends.get(&fd) {
            let mut readiness = FdReadiness {
                readable: false,
                writable: false,
                read_eof: false,
                write_eof: false,
            };
            if let Some(channel) = end
                .read_channel
                .and_then(|id| state.net.pipe_channels.get(&id))
            {
                readiness.read_eof = channel.write_closed && channel.buffer.is_empty();
                readiness.readable = !channel.buffer.is_empty() || readiness.read_eof;
            }
            if let Some(channel) = end
                .write_channel
                .and_then(|id| state.net.pipe_channels.get(&id))
            {
                readiness.write_eof = channel.read_closed;
                readiness.writable = readiness.write_eof || channel.buffer.len() < channel.capacity;
            }
            return readiness;
        }
        // Virtual SimNet socket: readiness lives in the runtime network driver.
        // `net_readiness` reads it plus the virtual clock WITHOUT recording, so it
        // is deterministic given the recorded schedule and emits no trace event.
        if let Some(socket) = state.net.sockets.get(&fd) {
            let Some(socket_id) = socket.socket_id else {
                // An unbound/unconnected stream has no buffers yet: nothing ready.
                return FdReadiness {
                    readable: false,
                    writable: false,
                    read_eof: false,
                    write_eof: false,
                };
            };
            return match with_context_raw(|context| context.net_readiness(socket_id)) {
                Ok(bits) => FdReadiness {
                    readable: bits & (1 << 0) != 0,
                    writable: bits & (1 << 1) != 0,
                    read_eof: bits & (1 << 2) != 0,
                    write_eof: bits & (1 << 3) != 0,
                },
                Err(_) => FdReadiness {
                    readable: true,
                    writable: true,
                    read_eof: true,
                    write_eof: true,
                },
            };
        }
        // Deterministic eventfd counter (Linux): readable iff nonzero; always
        // writable (a write that would overflow fails closed loudly instead of
        // parking, so writability never drops).
        #[cfg(target_os = "linux")]
        if let Some(efd) = state.net.eventfds.get(&fd) {
            return FdReadiness {
                readable: efd.value > 0,
                writable: true,
                read_eof: false,
                write_eof: false,
            };
        }
        // The descriptor was closed after registration: report EV_EOF once.
        FdReadiness {
            readable: true,
            writable: true,
            read_eof: true,
            write_eof: true,
        }
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
    enum WaiterLoc {
        PipeRecv(u64),
        PipeSend(u64),
        SockRecv(c_int),
        SockSend(c_int),
        /// Linux: parked on an eventfd's readable queue (an eventfd is always
        /// writable, so there is no write-direction queue).
        #[cfg(target_os = "linux")]
        EventFdRecv(c_int),
    }

    /// Register `me` on the waiter queue of every watched `(direction, fd)`
    /// source, returning the locations to unlink on resume. This is the reusable
    /// multi-fd fan-in primitive a readiness reactor parks on: the frontend
    /// supplies the watched set from its OWN registry, so no reactor-specific
    /// keying (kqueue `(ident, filter)`, epoll interest masks) leaks into the
    /// shared core. The readiness sources — pipe channels and SimNet socket
    /// queues — and the readiness predicate [`fd_readiness`] are equally neutral.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn register_readiness_waiters(
        state: &mut ThreadRuntime,
        me: TaskId,
        watched: &[(ReadyDir, c_int)],
    ) -> Vec<WaiterLoc> {
        let mut locs = Vec::new();
        for &(dir, fd) in watched {
            // Eventfd (Linux): only the readable direction has a queue; a write
            // watch needs no waiter because an eventfd is always writable.
            #[cfg(target_os = "linux")]
            if dir == ReadyDir::Read {
                if let Some(efd) = state.net.eventfds.get_mut(&fd) {
                    efd.read_waiters.push_back(me);
                    locs.push(WaiterLoc::EventFdRecv(fd));
                    continue;
                }
            }
            if let Some(end) = state.net.pipe_ends.get(&fd) {
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
            } else if let Some(socket) = state.net.sockets.get_mut(&fd) {
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
    fn unregister_readiness_waiters(state: &mut ThreadRuntime, me: TaskId, locs: &[WaiterLoc]) {
        let remove = |queue: &mut VecDeque<TaskId>| {
            if let Some(index) = queue.iter().position(|task| *task == me) {
                queue.remove(index);
            }
        };
        for loc in locs {
            match *loc {
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
                    if let Some(socket) = state.net.sockets.get_mut(&fd) {
                        remove(&mut socket.recv_waiters);
                    }
                }
                WaiterLoc::SockSend(fd) => {
                    if let Some(socket) = state.net.sockets.get_mut(&fd) {
                        remove(&mut socket.send_waiters);
                    }
                }
                #[cfg(target_os = "linux")]
                WaiterLoc::EventFdRecv(fd) => {
                    if let Some(efd) = state.net.eventfds.get_mut(&fd) {
                        remove(&mut efd.read_waiters);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    use kqueue::KqueueSlot;

    #[cfg(target_os = "macos")]
    mod kqueue {
        use std::collections::{BTreeMap, VecDeque};
        use std::ffi::{c_int, c_void};

        use patina_dst_abi::ClockKind;

        use super::{
            PatinaKevent, ReadyDir, Step, TaskId, ThreadRuntime, current_task, fatal, fd_readiness,
            lock_state, register_readiness_waiters, sched_point, switch_and_park,
            unregister_readiness_waiters, wake_all, with_context_raw,
        };

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

        /// A reference-counted kqueue registry: `refs` is the number of live fds
        /// aliasing it (one per `kqueue()`, plus one per `dup`/`F_DUPFD`), and the
        /// registry drops when the last fd closes.
        pub(super) struct KqueueSlot {
            kq: Kqueue,
            refs: usize,
        }

        /// Resolve a kqueue fd to its registry id, or `None` if `fd` is not a live
        /// kqueue descriptor.
        fn kq_id(state: &ThreadRuntime, fd: c_int) -> Option<u64> {
            state.net.kq_fds.get(&fd).copied()
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
                    refs: 1,
                },
            );
            let fd = state.net.next_fd;
            state.net.next_fd = state.net.next_fd.wrapping_add(1);
            state.net.kq_fds.insert(fd, id);
            fd
        }

        /// C dispatch predicate: is `fd` a virtual kqueue? Lets the interposed
        /// `close`/`dup`/`fcntl` route the shared virtual-fd space to the kqueue
        /// class.
        #[unsafe(no_mangle)]
        pub extern "C" fn patina_kqueue_is_kq(fd: c_int) -> c_int {
            c_int::from(lock_state().net.kq_fds.contains_key(&fd))
        }

        /// Duplicate a kqueue fd: the new fd aliases the SAME registry (tokio's IO
        /// driver clones its selector through `F_DUPFD_CLOEXEC`). Returns the new
        /// fd or -1 with `patina_errno` EBADF if `fd` is not a live kqueue.
        #[unsafe(no_mangle)]
        pub extern "C" fn patina_kqueue_dup(fd: c_int) -> c_int {
            let mut state = lock_state();
            let Some(id) = kq_id(&state, fd) else {
                return super::super::fail(super::super::EBADF);
            };
            state
                .net
                .kqueues
                .get_mut(&id)
                .expect("kq fd maps to a live registry")
                .refs += 1;
            let new_fd = state.net.next_fd;
            state.net.next_fd = state.net.next_fd.wrapping_add(1);
            state.net.kq_fds.insert(new_fd, id);
            new_fd
        }

        /// Close a kqueue fd. The registry drops (waking any task parked in
        /// `kevent` on it) only when the last aliasing fd closes.
        #[unsafe(no_mangle)]
        pub extern "C" fn patina_kqueue_close(fd: c_int) -> c_int {
            let mut state = lock_state();
            let Some(id) = state.net.kq_fds.remove(&fd) else {
                return super::super::fail(super::super::EBADF);
            };
            let slot = state
                .net
                .kqueues
                .get_mut(&id)
                .expect("kq fd maps to a live registry");
            slot.refs -= 1;
            if slot.refs > 0 {
                return 0;
            }
            let slot = state.net.kqueues.remove(&id).expect("registry was present");
            let waiters: Vec<TaskId> = slot.kq.waiters.into_iter().collect();
            drop(state);
            wake_all(waiters);
            0
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
                    // is defined only over virtual pipe/socketpair and SimNet
                    // socket descriptors. A real file, stdio, or otherwise unknown
                    // descriptor fails closed loudly here.
                    if matches!(filter, EVFILT_READ | EVFILT_WRITE) {
                        let fd = c_int::try_from(ident).unwrap_or(-1);
                        let known = state.net.pipe_ends.contains_key(&fd)
                            || state.net.sockets.contains_key(&fd);
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
                        let r = fd_readiness(state, fd);
                        let (ready_now, eof) = if key.filter == EVFILT_READ {
                            (r.readable, r.read_eof)
                        } else {
                            (r.writable, r.write_eof)
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
                    Some(deadline) => {
                        state.block_timed(me, "kevent", ClockKind::Monotonic, deadline)
                    }
                    None => state.block(me, "kevent"),
                };
                match step {
                    Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                    Ok(Step::Continue) => drop(state),
                    Err(error) => {
                        let mut state = lock_state();
                        unregister_readiness_waiters(&mut state, me, &locs);
                        detach_user_waiter(&mut state, id, me);
                        return super::super::fail(error.into_posix());
                    }
                }
                let mut state = lock_state();
                unregister_readiness_waiters(&mut state, me, &locs);
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

    // ------------------------------------------------------------------
    // epoll readiness reactor (Linux) — the mirror of `mod kqueue` above over
    // the same OS-agnostic readiness core (`fd_readiness`,
    // `register_readiness_waiters`). An epoll fd is drawn from the shared
    // virtual-fd space; `epoll_ctl` keeps one interest per watched fd (epoll
    // semantics) over the virtual pipe/socketpair, eventfd, and SimNet socket
    // fds; `epoll_wait` gathers ready events — parking on the scheduler baton
    // with multi-fd fan-in when nothing is ready, bounded by the millisecond
    // timeout on the virtual clock. mio's `Waker` analogue needs no
    // epoll-specific wake path: it is an ordinary watched eventfd whose write
    // drains the shared read-waiter queue.
    //
    // Event delivery under EPOLLET compares per-direction ARRIVAL SEQUENCES
    // (`PipeChannel::read_events`/`write_events`, `EventFd::write_events`): an
    // edge re-fires whenever the source's sequence has advanced since the last
    // delivery, not merely after readiness dropped — the kernel fires
    // edge-triggered events per arrival, and mio's eventfd Waker depends on it
    // (it writes without draining the counter). SimNet sockets expose no
    // sequence (constant 0), so they degrade to the drop-only latch the kqueue
    // frontend uses — sound for mio, which drains to EWOULDBLOCK. Returned
    // events are ordered by the interest table's fd key order (a `BTreeMap`),
    // so the gathered slice is a pure function of the registry and the
    // schedule. Like the kqueue registry, everything here is deterministic
    // GIVEN the recorded schedule and carries NO trace events; only the
    // scheduler parks/wakes are recorded.
    #[cfg(target_os = "linux")]
    mod epoll {
        use std::collections::BTreeMap;
        use std::ffi::{c_int, c_void};

        use patina_dst_abi::ClockKind;

        use super::{
            ReadyDir, Step, ThreadRuntime, current_task, fatal, fd_readiness, lock_state,
            register_readiness_waiters, sched_point, switch_and_park, unregister_readiness_waiters,
            with_context_raw,
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
        /// EPOLL_CLOEXEC == O_CLOEXEC; accepted no-op (no exec under the runtime).
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

        /// One watched fd's interest (epoll semantics: at most one per fd).
        struct Interest {
            /// Requested EPOLLIN/EPOLLOUT/EPOLLRDHUP plus the EPOLLET mode bit.
            events: u32,
            /// The caller's `epoll_data`, returned verbatim in delivered events.
            data: u64,
            /// EPOLLET per-direction latch: `Some(seq)` after a delivery at
            /// arrival sequence `seq` — silent until readiness drops (re-arm to
            /// `None`) or the sequence advances (a new arrival re-fires).
            delivered_read: Option<u64>,
            delivered_write: Option<u64>,
        }

        /// A virtual epoll instance: its per-fd interest table, ordered by fd.
        #[derive(Default)]
        struct Epoll {
            interests: BTreeMap<c_int, Interest>,
        }

        /// A reference-counted epoll registry: `refs` is the number of live fds
        /// aliasing it (one per `epoll_create1`, plus one per `dup`/`F_DUPFD` —
        /// mio clones its selector through `F_DUPFD_CLOEXEC` on Linux exactly as
        /// it does the kqueue fd), and the registry drops when the last closes.
        pub(super) struct EpollSlot {
            ep: Epoll,
            refs: usize,
        }

        /// Resolve an epoll fd to its registry id, or `None` if `fd` is not a
        /// live epoll descriptor.
        fn ep_id(state: &ThreadRuntime, fd: c_int) -> Option<u64> {
            state.net.epoll_fds.get(&fd).copied()
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
                    refs: 1,
                },
            );
            let fd = state.net.next_fd;
            state.net.next_fd = state.net.next_fd.wrapping_add(1);
            state.net.epoll_fds.insert(fd, id);
            fd
        }

        /// C dispatch predicate: is `fd` a virtual epoll descriptor? Lets the
        /// interposed `close`/`dup`/`fcntl` route the shared virtual-fd space to
        /// the epoll class.
        #[unsafe(no_mangle)]
        pub extern "C" fn patina_epoll_is_epoll(fd: c_int) -> c_int {
            c_int::from(lock_state().net.epoll_fds.contains_key(&fd))
        }

        /// Duplicate an epoll fd: the new fd aliases the SAME registry (mio's
        /// selector clone). Returns the new fd or -1 with `patina_errno` EBADF.
        #[unsafe(no_mangle)]
        pub extern "C" fn patina_epoll_dup(fd: c_int) -> c_int {
            let mut state = lock_state();
            let Some(id) = ep_id(&state, fd) else {
                return super::super::fail(super::super::EBADF);
            };
            state
                .net
                .epolls
                .get_mut(&id)
                .expect("epoll fd maps to a live registry")
                .refs += 1;
            let new_fd = state.net.next_fd;
            state.net.next_fd = state.net.next_fd.wrapping_add(1);
            state.net.epoll_fds.insert(new_fd, id);
            new_fd
        }

        /// Close an epoll fd; the registry drops when the last aliasing fd
        /// closes. A task parked in `epoll_wait` is NOT woken — the kernel's
        /// wait holds its own file reference and keeps blocking, and mio's
        /// single-threaded driver never closes underneath a wait.
        #[unsafe(no_mangle)]
        pub extern "C" fn patina_epoll_close(fd: c_int) -> c_int {
            let mut state = lock_state();
            let Some(id) = state.net.epoll_fds.remove(&fd) else {
                return super::super::fail(super::super::EBADF);
            };
            let slot = state
                .net
                .epolls
                .get_mut(&id)
                .expect("epoll fd maps to a live registry");
            slot.refs -= 1;
            if slot.refs == 0 {
                state.net.epolls.remove(&id);
            }
            0
        }

        /// Apply one `epoll_ctl` op. Syscall-shaped (`epoll_ctl(epfd, op, fd,
        /// event)`) for the future SIGSYS dispatcher. Registry mutation only —
        /// no scheduling point, no trace event. Kernel-faithful errno: EEXIST on
        /// a double ADD, ENOENT on MOD/DEL of an unregistered fd. Unmodeled
        /// event flags and non-virtual descriptors fail closed loudly.
        ///
        /// # Safety
        /// `event` must point to a live `struct epoll_event` for ADD/MOD.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn patina_epoll_ctl(
            epfd: c_int,
            op: c_int,
            fd: c_int,
            event: *const EpollEvent,
        ) -> c_int {
            let mut state = lock_state();
            let Some(id) = ep_id(&state, epfd) else {
                return super::super::fail(super::super::EBADF);
            };
            if op == EPOLL_CTL_DEL {
                // Removal validates nothing else about `fd`: the descriptor may
                // already be closed (mio deregisters around close).
                return match state
                    .net
                    .epolls
                    .get_mut(&id)
                    .expect("epoll was checked")
                    .ep
                    .interests
                    .remove(&fd)
                {
                    Some(_) => 0,
                    None => super::super::fail(super::super::ENOENT),
                };
            }
            if !matches!(op, EPOLL_CTL_ADD | EPOLL_CTL_MOD) {
                return super::super::fail(super::EINVAL);
            }
            if event.is_null() {
                return super::super::fail(super::EINVAL);
            }
            // SAFETY: non-null `event` points to a live epoll_event per this
            // function's contract; fields are copied out by value.
            let (events, data) = unsafe { ((*event).events, (*event).data) };
            // Fail closed LOUDLY on interest flags the reactor does not model
            // (EPOLLONESHOT, EPOLLEXCLUSIVE, EPOLLWAKEUP, EPOLLPRI, ...): a
            // silent EINVAL a caller swallowed would be an invisible escape.
            // EPOLLHUP/EPOLLERR are always-monitored no-ops in a request mask,
            // accepted exactly as the kernel accepts them.
            const MODELED: u32 = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP | EPOLLET;
            if events & !MODELED != 0 {
                fatal(&format!(
                    "epoll_ctl events {events:#x} carry unmodeled flags (only EPOLLIN/EPOLLOUT/\
                     EPOLLRDHUP/EPOLLERR/EPOLLHUP/EPOLLET are modeled); failing closed"
                ));
            }
            // Registration-time fd validation: readiness is defined only over
            // virtual pipe/socketpair, eventfd, and SimNet socket descriptors.
            // A real file, stdio, another epoll instance, or an otherwise
            // unknown descriptor fails closed loudly here.
            let known = state.net.pipe_ends.contains_key(&fd)
                || state.net.sockets.contains_key(&fd)
                || state.net.eventfds.contains_key(&fd);
            if !known {
                fatal(&format!(
                    "epoll_ctl registered non-virtual descriptor {fd}: readiness for real host \
                     descriptors is not modeled; failing closed"
                ));
            }
            let interests = &mut state
                .net
                .epolls
                .get_mut(&id)
                .expect("epoll was checked")
                .ep
                .interests;
            let armed = Interest {
                events,
                data,
                delivered_read: None,
                delivered_write: None,
            };
            match op {
                EPOLL_CTL_ADD => {
                    if interests.contains_key(&fd) {
                        return super::super::fail(super::super::EEXIST);
                    }
                    interests.insert(fd, armed);
                }
                _ => {
                    // EPOLL_CTL_MOD replaces the interest and re-arms the
                    // EPOLLET latches, matching the kernel.
                    let Some(interest) = interests.get_mut(&fd) else {
                        return super::super::fail(super::super::ENOENT);
                    };
                    *interest = armed;
                }
            }
            0
        }

        /// Monotonic per-direction arrival sequences for `fd` (see the section
        /// comment). SimNet sockets and closed descriptors report constant 0.
        fn fd_event_seqs(state: &ThreadRuntime, fd: c_int) -> (u64, u64) {
            if let Some(end) = state.net.pipe_ends.get(&fd) {
                let read_seq = end
                    .read_channel
                    .and_then(|id| state.net.pipe_channels.get(&id))
                    .map_or(0, |channel| channel.read_events);
                let write_seq = end
                    .write_channel
                    .and_then(|id| state.net.pipe_channels.get(&id))
                    .map_or(0, |channel| channel.write_events);
                return (read_seq, write_seq);
            }
            if let Some(efd) = state.net.eventfds.get(&fd) {
                return (efd.write_events, 0);
            }
            (0, 0)
        }

        /// An event ready to deliver, plus the latch edits its delivery entails.
        struct ReadyEvent {
            event: EpollEvent,
            fd: c_int,
            /// Latch the EPOLLET read direction at this arrival sequence.
            latch_read: Option<u64>,
            latch_write: Option<u64>,
        }

        /// Does a watched direction fire? Level-triggered interest fires
        /// whenever ready; EPOLLET fires when ready AND the latch is armed or
        /// the arrival sequence has advanced since the last delivery.
        fn dir_fires(edge: bool, ready: bool, delivered: Option<u64>, seq: u64) -> bool {
            ready && (!edge || delivered != Some(seq))
        }

        /// Scan the instance's interests, collecting the events ready to
        /// deliver (in fd order) and the re-arm edits for directions observed
        /// not-ready.
        fn scan(state: &ThreadRuntime, id: u64) -> (Vec<ReadyEvent>, Vec<(c_int, bool, bool)>) {
            let ep = &state.net.epolls.get(&id).expect("epoll exists").ep;
            let mut ready = Vec::new();
            let mut rearms = Vec::new();
            for (&fd, interest) in &ep.interests {
                let r = fd_readiness(state, fd);
                let (read_seq, write_seq) = fd_event_seqs(state, fd);
                let watch_read = interest.events & (EPOLLIN | EPOLLRDHUP) != 0;
                let watch_write = interest.events & EPOLLOUT != 0;
                let edge = interest.events & EPOLLET != 0;

                let rearm_read = watch_read && !r.readable && interest.delivered_read.is_some();
                let rearm_write = watch_write && !r.writable && interest.delivered_write.is_some();
                if rearm_read || rearm_write {
                    rearms.push((fd, rearm_read, rearm_write));
                }

                let read_fires =
                    watch_read && dir_fires(edge, r.readable, interest.delivered_read, read_seq);
                let write_fires =
                    watch_write && dir_fires(edge, r.writable, interest.delivered_write, write_seq);
                if !(read_fires || write_fires) {
                    continue;
                }
                // The delivered mask is the full current state of the watched
                // directions (an ET edge reports everything ready, like the
                // kernel). EPOLLERR/EPOLLHUP are reported unmasked: a broken
                // write side is EPOLLERR (the pipe-write-end shape), a fully
                // hung-up descriptor EPOLLHUP.
                let mut mask = 0u32;
                if r.readable && interest.events & EPOLLIN != 0 {
                    mask |= EPOLLIN;
                }
                if r.read_eof && interest.events & EPOLLRDHUP != 0 {
                    mask |= EPOLLRDHUP;
                }
                if r.writable && interest.events & EPOLLOUT != 0 {
                    mask |= EPOLLOUT;
                }
                if r.write_eof {
                    mask |= EPOLLERR;
                }
                if r.read_eof && r.write_eof {
                    mask |= EPOLLHUP;
                }
                if mask == 0 {
                    // A watched direction rose but nothing in the request mask
                    // is reportable (e.g. an EPOLLRDHUP-only interest with data
                    // but no EOF): nothing to deliver, nothing to latch.
                    continue;
                }
                ready.push(ReadyEvent {
                    event: EpollEvent {
                        events: mask,
                        data: interest.data,
                    },
                    fd,
                    latch_read: (edge && watch_read && r.readable).then_some(read_seq),
                    latch_write: (edge && watch_write && r.writable).then_some(write_seq),
                });
            }
            (ready, rearms)
        }

        /// The watched fds as reactor-neutral `(direction, fd)` pairs for the
        /// shared fan-in park. Latched directions still register: a wake simply
        /// rescans, and an arrival that woke us has advanced its sequence.
        fn watched_sources(state: &ThreadRuntime, id: u64) -> Vec<(ReadyDir, c_int)> {
            let ep = &state.net.epolls.get(&id).expect("epoll exists").ep;
            let mut watched = Vec::new();
            for (&fd, interest) in &ep.interests {
                if interest.events & (EPOLLIN | EPOLLRDHUP) != 0 {
                    watched.push((ReadyDir::Read, fd));
                }
                if interest.events & EPOLLOUT != 0 {
                    watched.push((ReadyDir::Write, fd));
                }
            }
            watched
        }

        /// Apply the latch edits for the events actually delivered this gather.
        fn commit_delivered(state: &mut ThreadRuntime, id: u64, delivered: &[ReadyEvent]) {
            let ep = &mut state.net.epolls.get_mut(&id).expect("epoll exists").ep;
            for event in delivered {
                if let Some(interest) = ep.interests.get_mut(&event.fd) {
                    if event.latch_read.is_some() {
                        interest.delivered_read = event.latch_read;
                    }
                    if event.latch_write.is_some() {
                        interest.delivered_write = event.latch_write;
                    }
                }
            }
        }

        /// Re-arm the EPOLLET latches for directions observed not-ready.
        fn commit_rearm(state: &mut ThreadRuntime, id: u64, rearms: &[(c_int, bool, bool)]) {
            let ep = &mut state.net.epolls.get_mut(&id).expect("epoll exists").ep;
            for &(fd, rearm_read, rearm_write) in rearms {
                if let Some(interest) = ep.interests.get_mut(&fd) {
                    if rearm_read {
                        interest.delivered_read = None;
                    }
                    if rearm_write {
                        interest.delivered_write = None;
                    }
                }
            }
        }

        /// Gather up to `maxevents` ready events into `events`, blocking per the
        /// millisecond `timeout_ms` (-1 = block until ready, 0 = poll, > 0 =
        /// relative virtual-clock deadline). Syscall-shaped (`epoll_wait(epfd,
        /// events, maxevents, timeout)`) for the future SIGSYS dispatcher; the
        /// C epoll_wait/epoll_pwait interposers are thin marshaling over this.
        ///
        /// # Safety
        /// `events` must be writable for `maxevents` `struct epoll_event`s.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn patina_epoll_wait(
            epfd: c_int,
            events: *mut c_void,
            maxevents: c_int,
            timeout_ms: c_int,
        ) -> c_int {
            if let Err(errno) = sched_point() {
                return super::super::fail(errno);
            }
            if maxevents <= 0 || events.is_null() {
                return super::super::fail(super::EINVAL);
            }
            let capacity = maxevents as usize;
            let me = current_task();
            // Absolute deadline for a positive timeout, fixed on the first scan
            // so it does not drift across rescans.
            let mut timeout_deadline: Option<u64> = None;
            loop {
                let mut state = lock_state();
                let Some(id) = ep_id(&state, epfd) else {
                    return super::super::fail(super::super::EBADF);
                };
                let now = match with_context_raw(|c| c.monotonic_now_unrecorded()) {
                    Ok(now) => now,
                    Err(errno) => return super::super::fail(errno),
                };
                let (ready, rearms) = scan(&state, id);
                commit_rearm(&mut state, id, &rearms);

                if !ready.is_empty() {
                    let count = ready.len().min(capacity);
                    let delivered = &ready[..count];
                    // SAFETY: `events` is writable for `maxevents >= count`
                    // entries per this function's contract.
                    let slots = unsafe {
                        std::slice::from_raw_parts_mut(events.cast::<EpollEvent>(), count)
                    };
                    for (slot, event) in slots.iter_mut().zip(delivered) {
                        *slot = event.event;
                    }
                    commit_delivered(&mut state, id, delivered);
                    return c_int::try_from(count).unwrap_or(c_int::MAX);
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
                    state.block_timed(me, "epoll-wait", ClockKind::Monotonic, deadline)
                } else {
                    state.block(me, "epoll-wait")
                };
                match step {
                    Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                    Ok(Step::Continue) => drop(state),
                    Err(error) => {
                        let mut state = lock_state();
                        unregister_readiness_waiters(&mut state, me, &locs);
                        return super::super::fail(error.into_posix());
                    }
                }
                let mut state = lock_state();
                unregister_readiness_waiters(&mut state, me, &locs);
                state.timed_out.remove(&me);
                drop(state);
            }
        }

        #[cfg(test)]
        mod tests {
            use super::{EpollEvent, dir_fires};

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

            #[test]
            fn edge_latch_fires_per_arrival_and_stays_silent_while_latched() {
                // Armed and ready: fires.
                assert!(dir_fires(true, true, None, 5));
                // Delivered at this arrival, still ready, nothing new: silent
                // (the partial-drain case).
                assert!(!dir_fires(true, true, Some(5), 5));
                // A new arrival while still ready re-fires (the kernel's
                // per-arrival edge; mio's undrained eventfd Waker needs this).
                assert!(dir_fires(true, true, Some(5), 6));
                // Not ready never fires.
                assert!(!dir_fires(true, false, Some(5), 6));
                // Level-triggered interest ignores the latch entirely.
                assert!(dir_fires(false, true, Some(5), 5));
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
        let me = current_task();
        let mut state = lock_state();
        // SAFETY: `addr` is the guest's futex word per this function's contract;
        // only the baton holder runs, so this read races with nothing.
        let current = unsafe { core::ptr::read_volatile(addr as *const u32) };
        if current != expected {
            return super::fail(EWOULDBLOCK);
        }
        if !state.active {
            // No other managed task exists to wake a matching wait; re-check
            // rather than park an unmanaged thread with no waker.
            return super::fail(EWOULDBLOCK);
        }
        state.futexes.entry(addr).or_default().push_back(me);
        match state.block(me, "futex-wait") {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => fatal("futex wait parked without transferring the baton"),
            Err(error) => return error.into_posix(),
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
        let clock = match clock_id {
            0 => ClockKind::Realtime,
            1 => ClockKind::Monotonic,
            _ => return super::fail(EINVAL),
        };
        let me = current_task();
        let mut state = lock_state();
        // SAFETY: `addr` is the guest's futex word per this function's contract;
        // only the baton holder runs, so this read races with nothing.
        let current = unsafe { core::ptr::read_volatile(addr as *const u32) };
        if current != expected {
            return super::fail(EWOULDBLOCK);
        }
        if !state.active {
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
        match state.block_timed(me, "futex-wait", clock, deadline) {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => return error.into_posix(),
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
        let mut state = lock_state();
        let to_wake: Vec<TaskId> = match state.futexes.get_mut(&addr) {
            Some(waiters) => {
                let take = if count < 0 {
                    waiters.len()
                } else {
                    (count as usize).min(waiters.len())
                };
                waiters.drain(..take).collect()
            }
            None => Vec::new(),
        };
        if state.futexes.get(&addr).is_some_and(VecDeque::is_empty) {
            state.futexes.remove(&addr);
        }
        let mut scheduler = RealScheduler;
        for task in &to_wake {
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
        // end-to-end by the pipe/socketpair legs in validate-native-shim.sh):
        // bounded capacity, partial reads/writes, and EOF only after drain.
        #[test]
        fn pipe_channel_transfers_bytes_with_bounded_capacity_and_eof() {
            let mut channel = PipeChannel::new(4);
            let mut dst = [0u8; 8];
            // Empty + writer open → WouldBlock (the reader parks).
            assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
            // Bounded capacity: only 4 of 6 bytes fit; the writer must loop.
            assert_eq!(channel.try_write(b"abcdef"), PipeWrite::Wrote(4));
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
            channel.write_closed = true;
            assert_eq!(channel.try_read(&mut dst), PipeRead::Read(2));
            assert_eq!(&dst[..2], b"hi");
            assert_eq!(channel.try_read(&mut dst), PipeRead::Eof);
        }

        // Writing to a channel whose reader closed is a broken pipe surfaced as an
        // errno (EPIPE) — never a signal.
        #[test]
        fn pipe_channel_write_to_closed_reader_is_broken_pipe() {
            let mut channel = PipeChannel::new(4);
            channel.read_closed = true;
            assert_eq!(channel.try_write(b"x"), PipeWrite::BrokenPipe);
        }

        #[test]
        fn uncontended_lock_and_unlock_round_trips() {
            let mut table = ThreadTable::default();
            let mut scheduler = DetAdapter::new(1);
            let a = TaskId(1);
            assert!(matches!(table.lock(a, MUTEX).unwrap(), LockStep::Acquired));
            assert_eq!(table.mutexes[&MUTEX].owner, Some(a));
            table.unlock(&mut scheduler, a, MUTEX).unwrap();
            assert_eq!(table.mutexes[&MUTEX].owner, None);
        }

        #[test]
        fn recursive_lock_is_reported_as_deadlock() {
            let mut table = ThreadTable::default();
            let a = TaskId(1);
            table.lock(a, MUTEX).unwrap();
            assert!(matches!(
                table.lock(a, MUTEX),
                Err(ThreadError::Posix(EDEADLK))
            ));
            assert_eq!(table.trylock(a, MUTEX), EDEADLK);
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
            assert!(matches!(table.lock(a, MUTEX).unwrap(), LockStep::Acquired));
            scheduler.yield_task(a).unwrap();

            scheduler.scheduler.select(Some(b)).unwrap();
            assert!(matches!(table.lock(b, MUTEX).unwrap(), LockStep::MustBlock));
            scheduler.park(b, "mutex").unwrap();

            scheduler.scheduler.select(Some(c)).unwrap();
            assert!(matches!(table.lock(c, MUTEX).unwrap(), LockStep::MustBlock));
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

            // A write hold excludes both a reader and another writer, and the
            // holder re-acquiring is a deadlock.
            assert!(matches!(
                table.rwlock_wrlock(a, RWLOCK).unwrap(),
                LockStep::Acquired
            ));
            assert_eq!(table.rwlock_trywrlock(b, RWLOCK), EBUSY);
            assert_eq!(table.rwlock_tryrdlock(b, RWLOCK), EBUSY);
            assert_eq!(table.rwlock_trywrlock(a, RWLOCK), EDEADLK);
            assert!(matches!(
                table.rwlock_rdlock(a, RWLOCK),
                Err(ThreadError::Posix(EDEADLK))
            ));

            // Releasing lets multiple readers share, but a writer is then busy.
            table.rwlock_unlock(&mut scheduler, a, RWLOCK).unwrap();
            assert_eq!(table.rwlock_tryrdlock(a, RWLOCK), 0);
            assert_eq!(table.rwlock_tryrdlock(b, RWLOCK), 0);
            assert_eq!(table.rwlocks[&RWLOCK].readers, 2);
            assert_eq!(table.rwlock_trywrlock(a, RWLOCK), EBUSY);

            // A held rwlock cannot be destroyed; an idle one can.
            assert!(matches!(
                table.destroy_rwlock(RWLOCK),
                Err(ThreadError::Posix(EBUSY))
            ));
            table.rwlock_unlock(&mut scheduler, a, RWLOCK).unwrap();
            table.rwlock_unlock(&mut scheduler, b, RWLOCK).unwrap();
            assert!(table.destroy_rwlock(RWLOCK).is_ok());
        }

        #[test]
        fn rwlock_is_writer_preferring_with_fifo_writers_and_batched_readers() {
            let mut table = ThreadTable::default();
            let mut scheduler = DetAdapter::new(1);
            let r1 = scheduler.spawn("r1").unwrap();
            let r2 = scheduler.spawn("r2").unwrap();
            let w1 = scheduler.spawn("w1").unwrap();
            let r3 = scheduler.spawn("r3").unwrap();
            for task in [r1, r2, w1, r3] {
                table.register(task);
            }

            // Two readers share the lock.
            scheduler.scheduler.select(Some(r1)).unwrap();
            assert!(matches!(
                table.rwlock_rdlock(r1, RWLOCK).unwrap(),
                LockStep::Acquired
            ));
            scheduler.yield_task(r1).unwrap();
            scheduler.scheduler.select(Some(r2)).unwrap();
            assert!(matches!(
                table.rwlock_rdlock(r2, RWLOCK).unwrap(),
                LockStep::Acquired
            ));
            assert_eq!(table.rwlocks[&RWLOCK].readers, 2);
            scheduler.yield_task(r2).unwrap();

            // A writer arrives and blocks behind the active readers.
            scheduler.scheduler.select(Some(w1)).unwrap();
            assert!(matches!(
                table.rwlock_wrlock(w1, RWLOCK).unwrap(),
                LockStep::MustBlock
            ));
            scheduler.park(w1, "rwlock-write").unwrap();

            // Writer-preferring: a new reader blocks while a writer waits, even
            // though only readers currently hold the lock.
            scheduler.scheduler.select(Some(r3)).unwrap();
            assert!(matches!(
                table.rwlock_rdlock(r3, RWLOCK).unwrap(),
                LockStep::MustBlock
            ));
            scheduler.park(r3, "rwlock-read").unwrap();

            // First reader releases: one reader remains, nothing is granted.
            table.rwlock_unlock(&mut scheduler, r1, RWLOCK).unwrap();
            assert_eq!(table.rwlocks[&RWLOCK].readers, 1);
            assert_eq!(table.rwlocks[&RWLOCK].writer, None);

            // Last reader releases: the waiting writer is granted (preference).
            table.rwlock_unlock(&mut scheduler, r2, RWLOCK).unwrap();
            assert_eq!(table.rwlocks[&RWLOCK].writer, Some(w1));
            assert_eq!(table.rwlocks[&RWLOCK].readers, 0);

            // Writer releases with no writer waiting: every blocked reader is
            // granted at once.
            table.rwlock_unlock(&mut scheduler, w1, RWLOCK).unwrap();
            assert_eq!(table.rwlocks[&RWLOCK].writer, None);
            assert_eq!(table.rwlocks[&RWLOCK].readers, 1);
            assert!(table.rwlocks[&RWLOCK].read_waiters.is_empty());

            table.rwlock_unlock(&mut scheduler, r3, RWLOCK).unwrap();
            assert_eq!(table.rwlocks[&RWLOCK].readers, 0);
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
            table.init_mutex(MUTEX);
            table.init_cond(COND);

            // The waiter owns the mutex, then waits on the condition.
            assert!(matches!(
                table.lock(waiter, MUTEX).unwrap(),
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
