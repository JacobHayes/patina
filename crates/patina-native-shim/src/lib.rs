//! Explicit native C ABI entry points for Patina.
//!
//! These prefixed symbols are the verified foundation for the future libc
//! interposition layer. They deliberately do not export ambient `open`,
//! `read`, or pthread symbols yet, so linking this crate cannot silently alter
//! unrelated host operations.

use std::cell::{Cell, UnsafeCell};
use std::collections::BTreeMap;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::io;
use std::ops::{Deref, DerefMut};
use std::slice;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use patina_abi::{
    ClockKind, EffectError, ErrorCode, Fd, FsDirectoryEntry, FsEntryKind, OpenFlags, SeekWhence,
    TaskId,
};

use patina_fs_crash::CrashFs;
use patina_fs_mem::{FsImage, MemFs};
use patina_runtime::{
    Context, MAX_TRACE_BYTES, RuntimeBuilder, RuntimeConfig, RuntimeError, SiteOutcome,
    TraceTransport,
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
const EINVAL: c_int = 22;
const EIO: c_int = 5;
const EISDIR: c_int = 21;
const ENOENT: c_int = 2;
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
const MAX_CAPTURED_STDIO_BYTES: usize = 64 * 1024 * 1024;
const HOST_IO_CHUNK: usize = 64 * 1024;

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
    }
}

static CONTEXT: OnceLock<SpinMutex<Option<Context>>> = OnceLock::new();
static STDIO: OnceLock<SpinMutex<StdioCapture>> = OnceLock::new();

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
// wrinkle: the shim interposes `dlsym` itself (to neuter std's optional-symbol
// probing), and glibc's flat namespace means the shim's own strong `read`/
// `write`/`sem_*` defs would satisfy any reference the shim made to those names —
// so a plain `dlsym`-based table would hit the shim's own stub. The Linux
// primitive is instead `__real_dlsym`, the real glibc resolver reached through
// `-Wl,--wrap=dlsym` (mirroring the existing `-Wl,--wrap=pthread_create`); guest
// `dlsym` binds to the neutering `__wrap_dlsym`, and `dlsym(RTLD_NEXT, "read")`
// reaches genuine glibc, skipping the shim's strong def. So `__read`/`__write`/
// `sem_*` leave the guest import table on Linux too, and its `shim_control_plane`
// residue is `dlsym` plus the wrap-contained `pthread_create`.
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
    pub type PthreadMachThread = unsafe extern "C" fn(*mut c_void) -> MachPort;
    pub type ThreadResume = unsafe extern "C" fn(MachPort) -> c_int;
    pub type HostRead = unsafe extern "C" fn(c_int, *mut c_void, usize) -> isize;
    pub type HostWrite = unsafe extern "C" fn(c_int, *const c_void, usize) -> isize;

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
        pub pthread_mach_thread_np: PthreadMachThread,
        pub thread_resume: ThreadResume,
        /// The non-cancel-point host `read`/`write` for the trace control plane
        /// and captured-stdio flush; resolving `read$NOCANCEL`/`write$NOCANCEL`
        /// reaches libSystem's real descriptor I/O (never the interposed `read`/
        /// `write`), so trace finalization can never recurse into the FS.
        pub host_read: HostRead,
        pub host_write: HostWrite,
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
// shim made to those names, and the shim also interposes `dlsym` itself (to
// neuter std's optional-symbol probing) — so neither a named import nor a plain
// `dlsym` can reach the real host vehicles. The resolution primitive is instead
// `__real_dlsym`, the real glibc resolver reached through `-Wl,--wrap=dlsym`
// (added by `cargo patina native-build`), exactly mirroring `__real_pthread_create`.
// `dlsym(RTLD_NEXT, "read")` then returns glibc's `read`, not the shim's strong
// def (RTLD_NEXT searches images *after* the main executable), so the trace-fd
// I/O and the baton semaphore reach the genuine host functions while their public
// names never appear as undefined externals in the shim objects. The one
// escape-surface residue is `dlsym` — matching macOS — plus `pthread_create`,
// which stays wrap-contained (guest calls bind to the managed `__wrap_pthread_create`).
#[cfg(target_os = "linux")]
mod hostapi {
    use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
    use std::sync::OnceLock;

    // The real glibc resolver, reached through the `-Wl,--wrap=dlsym` alias
    // `__real_dlsym`. Guest and std `dlsym` references bind to the shim's
    // neutering `__wrap_dlsym` (patina_posix.c); only this shim-internal path
    // reaches the real resolver. Any consumer of the shim staticlib that drives a
    // host vehicle (managed threads / trace-fd I/O) must link `-Wl,--wrap=dlsym`,
    // exactly as `__real_pthread_create` requires `-Wl,--wrap=pthread_create`;
    // `cargo patina native-build` always links both, and the direct-`cc`
    // validate-native-shim.sh probes pass them explicitly.
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
    pub type SemInit = unsafe extern "C" fn(*mut c_void, c_int, c_uint) -> c_int;
    pub type SemOp = unsafe extern "C" fn(*mut c_void) -> c_int;

    /// Real host vehicles resolved once through `__real_dlsym(RTLD_NEXT, ...)`.
    /// None of these names appears as an undefined external in the shim objects.
    pub struct HostApi {
        /// The non-cancel-point-free host `read`/`write` for the trace control
        /// plane and captured-stdio flush; resolving them through `RTLD_NEXT`
        /// reaches glibc's descriptor I/O, never the shim's interposed `read`/
        /// `write`, so trace finalization can never recurse into the FS.
        pub host_read: HostRead,
        pub host_write: HostWrite,
        /// The execution-baton POSIX semaphore vehicle.
        pub sem_init: SemInit,
        pub sem_wait: SemOp,
        pub sem_post: SemOp,
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
                sem_init: std::mem::transmute::<*mut c_void, SemInit>(resolve(c"sem_init")),
                sem_wait: std::mem::transmute::<*mut c_void, SemOp>(resolve(c"sem_wait")),
                sem_post: std::mem::transmute::<*mut c_void, SemOp>(resolve(c"sem_post")),
            }
        }
    }

    /// The process-wide host-alias table, resolved on first use. Every entry
    /// point that reaches it (the baton, trace-fd I/O) runs well after the loader
    /// has mapped glibc, so lazy resolution is safe; the `OnceLock` makes the
    /// one-time resolution race-free.
    pub fn get() -> &'static HostApi {
        static API: OnceLock<HostApi> = OnceLock::new();
        API.get_or_init(build)
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
                    format!("trace descriptor exceeds {MAX_TRACE_BYTES} byte limit"),
                ));
            }
        }
    }

    fn write_bundle(&mut self, bytes: &[u8]) -> io::Result<()> {
        host_write_all(self.fd, bytes)
    }
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

/// The mode a descriptor holds an advisory `flock` in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FlockMode {
    Shared,
    Exclusive,
}

/// Advisory `flock` state, keyed by the guest descriptor that holds the lock and
/// recording the deterministic-fs inode the descriptor is open on. Conflicts are
/// resolved against the *inode*, so two independent opens of the same path
/// contend exactly as a real per-file-identity `flock` would (redb's
/// `DatabaseAlreadyOpen`), while a lone opener always acquires. Cleared on
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

fn runtime_errno(error: &RuntimeError) -> c_int {
    match error {
        RuntimeError::Effect(error) => effect_errno(error),
        RuntimeError::StepBudgetExceeded { .. } => EOVERFLOW,
        RuntimeError::Config(_)
        | RuntimeError::Io { .. }
        | RuntimeError::Trace(_)
        | RuntimeError::InvalidOutcome { .. }
        | RuntimeError::RunAndFinalize { .. } => EIO,
    }
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
    if control_env(patina_runtime::ENV_MODE).is_some() {
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

/// Run a closure against the installed [`Context`] without first taking a
/// deterministic scheduling point. The managed-thread runtime uses this to
/// perform scheduler transitions from inside the baton critical section, where
/// re-entering [`sched_point`] would recurse on the thread-runtime lock.
fn with_context_raw<T>(
    invoke: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, c_int> {
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
    ensure_runtime().map_err(|_| "Patina context is not installed".to_string())?;
    let mut guard = slot().lock();
    let context = guard
        .as_mut()
        .ok_or_else(|| "Patina context is not installed".to_string())?;
    invoke(context).map_err(|error| error.to_string())
}

/// Run a closure against the installed [`Context`] behind a deterministic
/// scheduling point. Every interposed boundary call routes through here, so
/// the seeded scheduler can transfer the execution baton between managed
/// threads at each boundary; when no managed threads exist the scheduling
/// point is a cheap no-op and the behavior is identical to a single thread.
fn with_context<T>(
    invoke: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, c_int> {
    ensure_runtime()?;
    thread::sched_point()?;
    with_context_raw(invoke)
}

fn control_env(name: &str) -> Option<String> {
    if let Some(value) = control_plane().lock().get(name).cloned() {
        return Some(value);
    }
    // Direct C-ABI users that link only the Rust static library have no POSIX
    // constructor to snapshot/scrub environ, so patina_init_from_env keeps the
    // documented PATINA_* protocol working by reading the host environment here.
    // Shim-linked POSIX binaries populate CONTROL_PLANE before init and public
    // getenv returns NULL, so guest-visible environment reads stay empty.
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

fn control_trace_fd() -> Result<Option<i32>, RuntimeError> {
    control_env(patina_runtime::ENV_TRACE_FD)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{} must be a non-negative descriptor number",
                    patina_runtime::ENV_TRACE_FD
                ))
            })
        })
        .transpose()
}

/// Parse `PATINA_FS_IMAGE_FD` from the control plane, mirroring `control_trace_fd`.
/// Present only when `native-run --mount` streamed a captured host directory.
fn control_fs_image_fd() -> Result<Option<i32>, RuntimeError> {
    control_env(patina_runtime::ENV_FS_IMAGE_FD)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{} must be a non-negative descriptor number",
                    patina_runtime::ENV_FS_IMAGE_FD
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
            patina_runtime::ENV_FS_IMAGE_FD
        ))
    })?;
    let image = FsImage::decode(&bytes)
        .map_err(|error| RuntimeError::Config(format!("invalid filesystem image: {error}")))?;
    image.into_memfs().map_err(|error| {
        RuntimeError::Config(format!("failed to rebuild filesystem image: {error}"))
    })
}

fn runtime_config_from_control_plane() -> Result<(RuntimeConfig, Option<i32>), RuntimeError> {
    let mode = control_env(patina_runtime::ENV_MODE).unwrap_or_else(|| "seeded".into());
    let seed = parse_control_u64(patina_runtime::ENV_SEED)?.unwrap_or(0);
    let trace_fd = control_trace_fd()?;
    if trace_fd.is_some()
        && control_env(patina_runtime::ENV_TRACE).is_some_and(|value| !value.is_empty())
    {
        return Err(RuntimeError::Config(format!(
            "{} and {} must not both be set",
            patina_runtime::ENV_TRACE,
            patina_runtime::ENV_TRACE_FD
        )));
    }
    let mut config = match (mode.as_str(), trace_fd) {
        ("seeded", None) => RuntimeConfig::seeded(seed),
        ("seeded", Some(_)) => {
            return Err(RuntimeError::Config(format!(
                "{} is only meaningful in record or replay mode",
                patina_runtime::ENV_TRACE_FD
            )));
        }
        ("record", None) => RuntimeConfig::record(
            seed,
            required_control_string(patina_runtime::ENV_TRACE)?,
            required_control_string(patina_runtime::ENV_FINGERPRINT)?,
        ),
        ("record", Some(_)) => RuntimeConfig::record_transport(
            seed,
            required_control_string(patina_runtime::ENV_FINGERPRINT)?,
        ),
        ("replay", None) => RuntimeConfig::replay_timeline(
            required_control_string(patina_runtime::ENV_TRACE)?,
            control_env(patina_runtime::ENV_TIMELINE).unwrap_or_else(|| "main".into()),
            required_control_string(patina_runtime::ENV_FINGERPRINT)?,
        ),
        ("replay", Some(_)) => RuntimeConfig::replay_transport_timeline(
            control_env(patina_runtime::ENV_TIMELINE).unwrap_or_else(|| "main".into()),
            required_control_string(patina_runtime::ENV_FINGERPRINT)?,
        ),
        ("branch", None) => RuntimeConfig::branch(
            required_control_string(patina_runtime::ENV_TRACE)?,
            control_env(patina_runtime::ENV_PARENT_TIMELINE).unwrap_or_else(|| "main".into()),
            parse_control_u64(patina_runtime::ENV_BRANCH_FROM)?.ok_or_else(|| {
                RuntimeError::Config(format!("{} is required", patina_runtime::ENV_BRANCH_FROM))
            })?,
            required_control_string(patina_runtime::ENV_BRANCH_ID)?,
            parse_control_u64(patina_runtime::ENV_BRANCH_SEED)?.ok_or_else(|| {
                RuntimeError::Config(format!("{} is required", patina_runtime::ENV_BRANCH_SEED))
            })?,
            required_control_string(patina_runtime::ENV_FINGERPRINT)?,
        ),
        ("branch", Some(_)) => {
            return Err(RuntimeError::Config(format!(
                "branch mode requires a {} path; {} is unsupported",
                patina_runtime::ENV_TRACE,
                patina_runtime::ENV_TRACE_FD
            )));
        }
        (value, _) => {
            return Err(RuntimeError::Config(format!(
                "{} must be seeded, record, replay, or branch; got {value:?}",
                patina_runtime::ENV_MODE
            )));
        }
    };
    if let Some(budget) = parse_control_u64(patina_runtime::ENV_STEP_BUDGET)? {
        config = config.with_step_budget(budget);
    }
    if let Some(value) = control_env(patina_runtime::ENV_PARAMS_JSON) {
        let params: BTreeMap<String, String> = serde_json::from_str(&value).map_err(|error| {
            RuntimeError::Config(format!(
                "{} is invalid: {error}",
                patina_runtime::ENV_PARAMS_JSON
            ))
        })?;
        for (key, value) in params {
            config = config.with_param(key, value)?;
        }
    }
    if let Some(latency) = parse_control_u64(patina_runtime::ENV_NET_LATENCY)? {
        config = config.with_net_latency_nanos(latency);
    }
    // Seed-driven fault knobs (crash point, sleep/net jitter, drop) are read from
    // the scrubbed constructor-time control plane by the same parser the process
    // environment path uses, so both entry points accept the identical protocol
    // and fail closed on any malformed value.
    config = config.apply_fault_env(control_env)?;
    // Cooperative-SUT (buggify) knobs come from the same control plane through
    // the shared parser, so the shim and the process-environment path agree.
    config = config.apply_buggify_env(control_env)?;
    // Guest argv (recorded into the trace metadata) travels the same control
    // plane, so record mode captures the arguments the supervisor forwarded.
    config = config.apply_guest_argv_env(control_env)?;
    Ok((config, trace_fd))
}

fn install(context: Result<Context, RuntimeError>) -> c_int {
    let context = match context {
        Ok(context) => context,
        Err(error) => return fail(runtime_errno(&error)),
    };
    let mut guard = slot().lock();
    if guard.is_some() {
        return fail(EALREADY);
    }
    *guard = Some(context);
    set_errno(0);
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
    let flushed = flush_captured_stdio();
    if setup_violation {
        let _ = host_write_all(
            2,
            b"PATINA_BUGGIFY_SETUP_NEVER_CALLED --buggify-after-setup was declared but the guest \
never called patina::lifecycle::setup_complete()\n",
        );
        std::process::abort();
    }
    match (finished, flushed) {
        (Ok(()), Ok(())) => {
            set_errno(0);
            0
        }
        (Err(error), _) => fail(runtime_errno(&error)),
        (Ok(()), Err(_)) => fail(EIO),
    }
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
/// `flock` in `c/patina_posix.c`. redb (via std `File::try_lock`) takes one
/// `LOCK_EX | LOCK_NB` on open; a lone opener always acquires it.
///
/// The lock is keyed on the descriptor's deterministic-fs inode, so two
/// independent opens of the *same* path contend faithfully: a non-blocking
/// request that would collide with an incompatible lock held on another
/// descriptor reports `EWOULDBLOCK` (redb surfaces this as
/// `DatabaseError::DatabaseAlreadyOpen`). `LOCK_SH` conflicts only with a held
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

fn write_metadata(metadata: patina_abi::FsMetadata, kind: *mut u32, length: *mut u64) -> c_int {
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
    metadata: patina_abi::FsMetadata,
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
fn abort_with_buggify_marker(marker: &str, label: &str) -> ! {
    let _ = flush_captured_stdio();
    let line = format!("{marker} label={label}\n");
    let _ = host_write_all(2, line.as_bytes());
    std::process::abort();
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
    match with_context(|context| invoke(context, label, site)) {
        Ok(SiteOutcome::Fire) => 1,
        Ok(SiteOutcome::Ok) => 0,
        Ok(SiteOutcome::AlwaysViolation) => {
            abort_with_buggify_marker("PATINA_ALWAYS_VIOLATION", label)
        }
        Ok(SiteOutcome::DuplicateLabel) => {
            abort_with_buggify_marker("PATINA_BUGGIFY_DUPLICATE_LABEL", label)
        }
        Err(errno) => fail(errno),
    }
}

/// `patina::is_simulated()`: 1 whenever the deterministic runtime is installed.
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

/// `patina::rng()`: a deterministic 64-bit draw bridged to the root seed.
#[unsafe(no_mangle)]
pub extern "C" fn patina_rng() -> u64 {
    with_context(|context| Ok(context.buggify_rng())).unwrap_or(0)
}

/// `patina::lifecycle::setup_complete()`: mark the setup boundary and emit a marker.
#[unsafe(no_mangle)]
pub extern "C" fn patina_lifecycle_setup_complete() -> c_int {
    let _ = with_context(|context| {
        context.lifecycle_setup_complete();
        Ok(())
    });
    capture_stderr_line("PATINA_LIFECYCLE setup_complete");
    0
}

/// `patina::lifecycle::event!("label")`: emit a lifecycle marker.
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
/// `Condvar`) execute under Patina's [`DetScheduler`](patina_sched_det). Real
/// host OS threads back each managed task, but a single execution baton ensures
/// exactly one runs at a time; every handoff is a seeded scheduler decision
/// recorded and replayed like any other boundary operation.
///
/// # Staying out of its own interposition
///
/// The shim interposes the guest's pthread symbols, so it must never call them
/// to implement itself, or it would recurse. Two choices keep the shim audit
/// clean with no `dlsym`:
///
/// * Shim-internal synchronization never uses `std::sync` (which lowers to the
///   interposed pthread symbols). The short state sections use an atomics
///   [`SpinMutex`], and the execution baton is a per-task host OS semaphore
///   (`dispatch_semaphore` on macOS, POSIX `sem_t` on Linux) — pure blocking
///   primitives that carry no scheduling decision. Neither touches the
///   interposed pthread layer.
/// * A real host OS thread is created through a *distinct*, non-interposed
///   symbol: `pthread_create_suspended_np` (plus a mach `thread_resume`) on
///   macOS. glibc has no such variant, so on Linux the interposer is
///   `__wrap_pthread_create` and the host vehicle is `__real_pthread_create`,
///   supplied by `-Wl,--wrap=pthread_create` from `cargo patina native-build`.
///
/// Every scheduling decision — which task runs next at each boundary — is made
/// by [`DetScheduler`](patina_sched_det) and recorded/replayed; the OS
/// primitives only provide the vehicle and the blocking.
mod thread {
    use std::cell::Cell;
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::{c_int, c_void};
    use std::sync::{Arc, OnceLock};

    use patina_abi::{ClockKind, Datagram, ShutdownHow, SocketId};

    use super::{
        EBUSY, EDEADLK, EINVAL, EISCONN, ENOTCONN, EOPNOTSUPP, EOVERFLOW, EPERM, ESRCH, ETIMEDOUT,
        EWOULDBLOCK, SpinGuard, SpinMutex, TaskId, host_write_all, with_context_msg,
        with_context_raw,
    };

    /// A guest thread body: `void *start_routine(void *arg)`.
    type StartRoutine = extern "C" fn(*mut c_void) -> *mut c_void;

    // Host thread creation without `dlsym`: the shim interposes `pthread_create`,
    // so to spawn a real OS thread it reaches the host creator through a
    // *distinct*, non-interposed symbol. On macOS that is
    // `pthread_create_suspended_np` plus a mach `thread_resume` (the created
    // thread parks on the baton immediately, so the brief suspend/resume is only
    // used to avoid the interposed name). glibc has no suspended variant, so on
    // Linux the interposer is `__wrap_pthread_create` and the real host vehicle
    // is `__real_pthread_create`, both supplied by `-Wl,--wrap=pthread_create`
    // (added by `cargo patina native-build`). The `__real_` reference is marked
    // weak so unit-test and library links succeed without the flag (it is never
    // called there); a native binary is always linked with the wrap flag.
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

    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        fn __real_pthread_create(
            thread: *mut *mut c_void,
            attr: *const c_void,
            start: StartRoutine,
            arg: *mut c_void,
        ) -> c_int;
    }

    // Mark `__real_pthread_create` weak so a library/test link without the wrap
    // flag resolves it to null instead of failing; only a native-build binary
    // (which passes `-Wl,--wrap=pthread_create`) ever calls it.
    #[cfg(target_os = "linux")]
    core::arch::global_asm!(".weak __real_pthread_create");

    /// # Safety
    /// `handle` must be writable and `start`/`arg` a valid thread entry point.
    #[cfg(target_os = "linux")]
    unsafe fn spawn_host_thread(
        handle: *mut *mut c_void,
        attr: *const c_void,
        start: StartRoutine,
        arg: *mut c_void,
    ) -> c_int {
        // SAFETY: `__real_pthread_create` is the wrap-provided real host
        // pthread_create; forwarded from this function's contract.
        unsafe { __real_pthread_create(handle, attr, start, arg) }
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
    /// [`DetScheduler`](patina_sched_det).
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
        waiters: VecDeque<TaskId>,
    }

    #[derive(Default)]
    struct CondEntry {
        waiters: VecDeque<(TaskId, usize)>,
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
        write_waiters: VecDeque<TaskId>,
        read_waiters: VecDeque<TaskId>,
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
        mutexes: BTreeMap<usize, MutexEntry>,
        conds: BTreeMap<usize, CondEntry>,
        rwlocks: BTreeMap<usize, RwLockEntry>,
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
            let entry = self.mutexes.entry(key).or_default();
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
            let entry = self.mutexes.entry(key).or_default();
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
            let entry = self.rwlocks.entry(key).or_default();
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
            let entry = self.rwlocks.entry(key).or_default();
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
            let entry = self.rwlocks.entry(key).or_default();
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
            let entry = self.rwlocks.entry(key).or_default();
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
                let readers: Vec<TaskId> = entry.read_waiters.drain(..).collect();
                entry.readers = readers.len();
                for reader in readers {
                    scheduler.wake(reader)?;
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
                .entry(cond_key)
                .or_default()
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
                let entry = self.mutexes.entry(mutex_key).or_default();
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
    /// [`DetScheduler`](patina_sched_det).
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

    /// Take a deterministic scheduling point at a boundary call. A no-op until
    /// the thread subsystem activates, so single-threaded programs are
    /// unaffected.
    pub(crate) fn sched_point() -> Result<(), c_int> {
        // A thread whose task already completed is running teardown code only; it
        // must not take a scheduling point. Checked before locking and keyed on
        // the completed sentinel alone, so a never-registered thread falls through
        // to the unchanged (loud) reschedule path below rather than being silenced.
        if task_completed() {
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

    extern "C" fn thread_trampoline(raw: *mut c_void) -> *mut c_void {
        // SAFETY: `raw` is the `Box<ThreadStart>` leaked in patina_thread_create.
        let start = unsafe { Box::from_raw(raw.cast::<ThreadStart>()) };
        let ThreadStart { task, routine, arg } = *start;
        set_current_task(task);
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
                recv_waiters: VecDeque::new(),
                send_waiters: VecDeque::new(),
            }
        }
    }

    struct NetState {
        sockets: BTreeMap<c_int, NetSocket>,
        bound: BTreeMap<String, c_int>,
        tcp_listeners: BTreeMap<String, c_int>,
        tcp_streams: BTreeMap<(String, String), c_int>,
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

    fn peer_fd(state: &ThreadRuntime, local: &str, peer: &str) -> Option<c_int> {
        state
            .net
            .tcp_streams
            .get(&(peer.to_owned(), local.to_owned()))
            .copied()
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
                            recv_waiters: VecDeque::new(),
                            send_waiters: VecDeque::new(),
                        },
                    );
                    state.net.tcp_streams.insert((local, accepted.peer), new_fd);
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
        state
            .net
            .tcp_streams
            .insert((local, destination.clone()), fd);
        let waiters = state
            .net
            .tcp_listeners
            .get(&destination)
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
        let waiters = state
            .net
            .bound
            .get(destination)
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
            let (socket_id, local, peer, nonblocking) = match state.net.sockets.get(&fd) {
                Some(socket) if socket.kind == SocketKind::Stream => (
                    socket.socket_id.expect("stream has runtime socket id"),
                    socket.address.clone().expect("stream has local address"),
                    format_addr(
                        socket.peer.expect("stream has peer").0,
                        socket.peer.expect("stream has peer").1,
                    ),
                    socket.nonblocking,
                ),
                Some(_) => return super::fail(ENOTCONN) as isize,
                None => return super::fail(super::EBADF) as isize,
            };
            match with_context_raw(|context| context.net_tcp_send(socket_id, bytes)) {
                Ok(written) if written > 0 => {
                    let waiters = peer_fd(&state, &local, &peer)
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
                        Err(error) => return error.into_posix() as isize,
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
                        Err(error) => return error.into_posix() as isize,
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
            let (socket_id, local, peer, nonblocking) = match state.net.sockets.get(&fd) {
                Some(socket) if socket.kind == SocketKind::Stream => (
                    socket.socket_id.expect("stream has runtime socket id"),
                    socket.address.clone().expect("stream has local address"),
                    format_addr(
                        socket.peer.expect("stream has peer").0,
                        socket.peer.expect("stream has peer").1,
                    ),
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
                        peer_fd(&state, &local, &peer)
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
                        Err(error) => return error.into_posix() as isize,
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
        let (socket_id, local, peer) = match state.net.sockets.get(&fd) {
            Some(socket) if socket.kind == SocketKind::Stream => (
                socket.socket_id.expect("stream has runtime socket id"),
                socket.address.clone().expect("stream has local address"),
                format_addr(
                    socket.peer.expect("stream has peer").0,
                    socket.peer.expect("stream has peer").1,
                ),
            ),
            Some(socket) if socket.kind == SocketKind::StreamUnbound => {
                return super::fail(ENOTCONN);
            }
            Some(_) => return super::fail(EOPNOTSUPP),
            None => return super::fail(super::EBADF),
        };
        if let Err(errno) = with_context_raw(|context| context.net_tcp_shutdown(socket_id, how)) {
            return super::fail(errno);
        }
        let peer_fd = peer_fd(&state, &local, &peer);
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
                if let (Some(local), Some(peer_tuple)) = (&socket.address, socket.peer) {
                    let peer = format_addr(peer_tuple.0, peer_tuple.1);
                    state.net.tcp_streams.remove(&(local.clone(), peer.clone()));
                    if let Some(peer_fd) = peer_fd(&state, local, &peer) {
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
        use patina_driver_api::SchedulerDriver;
        use patina_sched_det::DetScheduler;

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
