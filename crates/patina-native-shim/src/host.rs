//! Private host aliases, host collections, and trace transports.

use super::*;

type HostClock = unsafe extern "C" fn(libc::clockid_t, *mut libc::timespec) -> c_int;
type HostSignalAction =
    unsafe extern "C" fn(c_int, *const libc::sigaction, *mut libc::sigaction) -> c_int;
type HostSignalMask =
    unsafe extern "C" fn(c_int, *const libc::sigset_t, *mut libc::sigset_t) -> c_int;
type HostThreadSignal = unsafe extern "C" fn(libc::pthread_t, c_int) -> c_int;
type HostDlAddr = unsafe extern "C" fn(*const c_void, *mut libc::Dl_info) -> c_int;
#[cfg(target_os = "linux")]
type HostDlAddr1 =
    unsafe extern "C" fn(*const c_void, *mut libc::Dl_info, *mut *mut c_void, c_int) -> c_int;

#[cfg(target_os = "macos")]
pub(crate) mod hostapi {
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
        pub host_dispatch_time: unsafe extern "C" fn(u64, i64) -> u64,
        pub host_clock_gettime: super::HostClock,
        pub host_sigaction: super::HostSignalAction,
        pub host_pthread_sigmask: super::HostSignalMask,
        pub host_pthread_kill: super::HostThreadSignal,
        pub host_pthread_self: unsafe extern "C" fn() -> usize,
        pub host_dladdr: super::HostDlAddr,
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
        /// Fail-closed fatal fallback if the host refuses to reset SIGABRT.
        pub host_immediate_exit: HostExit,
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

    pub(crate) fn resolve(name: &CStr) -> *mut c_void {
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
                host_dispatch_time: std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn(u64, i64) -> u64,
                >(resolve(c"dispatch_time")),
                host_clock_gettime: std::mem::transmute::<*mut c_void, super::HostClock>(resolve(
                    c"clock_gettime",
                )),
                host_sigaction: std::mem::transmute::<*mut c_void, super::HostSignalAction>(
                    resolve(c"sigaction"),
                ),
                host_pthread_sigmask: std::mem::transmute::<*mut c_void, super::HostSignalMask>(
                    resolve(c"pthread_sigmask"),
                ),
                host_pthread_kill: std::mem::transmute::<*mut c_void, super::HostThreadSignal>(
                    resolve(c"pthread_kill"),
                ),
                host_pthread_self: std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn() -> usize,
                >(resolve(c"pthread_self")),
                host_dladdr: std::mem::transmute::<*mut c_void, super::HostDlAddr>(resolve(
                    c"dladdr",
                )),
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
                host_immediate_exit: std::mem::transmute::<*mut c_void, HostExit>(resolve(
                    c"_exit",
                )),
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
pub(crate) mod hostapi {
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
        /// Fail-closed fatal fallback if the host refuses to reset SIGABRT.
        pub host_immediate_exit: HostExit,
        pub host_abort: unsafe extern "C" fn() -> !,
        pub host_pthread_self: unsafe extern "C" fn() -> usize,
        pub host_clock_gettime: super::HostClock,
        pub host_sigaction: super::HostSignalAction,
        pub host_pthread_sigmask: super::HostSignalMask,
        pub host_pthread_kill: super::HostThreadSignal,
        pub host_dladdr: super::HostDlAddr,
        pub host_dladdr1: super::HostDlAddr1,
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
        /// The real glibc `pthread_exit`: the C `pthread_exit` interposer calls
        /// it (never Rust, whose frames cannot be unwound) once the model has
        /// the thread's value, so glibc's own forced unwind runs the cleanup
        /// handlers and `start_thread` the destructors.
        pub host_pthread_exit: unsafe extern "C" fn(*mut c_void) -> !,
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

    pub(crate) fn resolve(name: &CStr) -> *mut c_void {
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
                host_clock_gettime: std::mem::transmute::<*mut c_void, super::HostClock>(resolve(
                    c"clock_gettime",
                )),
                host_sigaction: std::mem::transmute::<*mut c_void, super::HostSignalAction>(
                    resolve(c"sigaction"),
                ),
                host_pthread_sigmask: std::mem::transmute::<*mut c_void, super::HostSignalMask>(
                    resolve(c"pthread_sigmask"),
                ),
                host_pthread_kill: std::mem::transmute::<*mut c_void, super::HostThreadSignal>(
                    resolve(c"pthread_kill"),
                ),
                host_dladdr: std::mem::transmute::<*mut c_void, super::HostDlAddr>(resolve(
                    c"dladdr",
                )),
                host_dladdr1: std::mem::transmute::<*mut c_void, super::HostDlAddr1>(resolve(
                    c"dladdr1",
                )),
                host_read: std::mem::transmute::<*mut c_void, HostRead>(resolve(c"read")),
                host_write: std::mem::transmute::<*mut c_void, HostWrite>(resolve(c"write")),
                host_exit: std::mem::transmute::<*mut c_void, HostExit>(resolve(c"exit")),
                host_immediate_exit: std::mem::transmute::<*mut c_void, HostExit>(resolve(
                    c"_exit",
                )),
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
                host_pthread_exit: std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn(*mut c_void) -> !,
                >(resolve(c"pthread_exit")),
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
pub(crate) mod hostcoll {
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
pub(crate) unsafe fn host_read(fd: c_int, destination: *mut c_void, length: usize) -> isize {
    // SAFETY: forwarded from the caller's contract to the resolved host `read`.
    unsafe { (hostapi::get().host_read)(fd, destination, length) }
}

#[cfg(target_os = "macos")]
unsafe fn host_write(fd: c_int, source: *const c_void, length: usize) -> isize {
    // SAFETY: forwarded from the caller's contract to the resolved host `write`.
    unsafe { (hostapi::get().host_write)(fd, source, length) }
}

#[cfg(target_os = "linux")]
pub(crate) unsafe fn host_read(fd: c_int, destination: *mut c_void, length: usize) -> isize {
    // SAFETY: forwarded from the caller's contract to the resolved host `read`.
    unsafe { (hostapi::get().host_read)(fd, destination, length) }
}

#[cfg(target_os = "linux")]
unsafe fn host_write(fd: c_int, source: *const c_void, length: usize) -> isize {
    // SAFETY: forwarded from the caller's contract to the resolved host `write`.
    unsafe { (hostapi::get().host_write)(fd, source, length) }
}

pub(crate) fn host_write_all(fd: c_int, bytes: &[u8]) -> io::Result<()> {
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
            // Also used by terminal export: keep even a zero-write error
            // inline, rather than allocating a boxed custom I/O error.
            return Err(io::ErrorKind::WriteZero.into());
        }
        offset += written as usize;
    }
    Ok(())
}

/// Run-facts channel over a supervisor-provided host descriptor
/// (`PATINA_FACTS_FD`). The guest's filesystem is fully interposed, so the
/// structured facts document must leave through the private host aliases exactly
/// like the trace bundle and the coverage map do.
pub(crate) struct FdFactsSink {
    pub(crate) fd: c_int,
}

impl patina_dst_runtime::FactsSink for FdFactsSink {
    fn write_facts(&mut self, bytes: &[u8]) -> io::Result<()> {
        host_write_all(self.fd, bytes)
    }
}

/// Trace channel over a supervisor-provided host descriptor (`PATINA_TRACE_FD`).
pub(crate) struct FdTraceTransport {
    pub(crate) fd: c_int,
}

impl TraceTransport for FdTraceTransport {
    fn write_prefix(&mut self, recorder: &patina_dst_trace::Recorder) -> io::Result<()> {
        // Fixed storage: an asynchronous stop must not call the guest allocator
        // or clone the trace while the baton holder may own allocator locks.
        struct Writer {
            fd: c_int,
            buffer: [u8; 16 * 1024],
            used: usize,
            total: u64,
        }
        impl io::Write for Writer {
            fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
                let length = bytes.len();
                self.total = self.total.saturating_add(length as u64);
                if self.total > MAX_TRACE_BYTES {
                    watchdog::report_and_abort(&RuntimeError::ComputeStopExport, None, None);
                }
                while !bytes.is_empty() {
                    let n = bytes.len().min(self.buffer.len() - self.used);
                    self.buffer[self.used..self.used + n].copy_from_slice(&bytes[..n]);
                    self.used += n;
                    bytes = &bytes[n..];
                    if self.used == self.buffer.len() {
                        self.flush()?;
                    }
                }
                Ok(length)
            }
            fn flush(&mut self) -> io::Result<()> {
                // serde_json boxes I/O errors. Terminate here instead of
                // returning one into its allocating error-construction path.
                if host_write_all(self.fd, &self.buffer[..self.used]).is_err() {
                    watchdog::report_and_abort(&RuntimeError::ComputeStopExport, None, None);
                }
                self.used = 0;
                Ok(())
            }
        }
        let mut writer = Writer {
            fd: self.fd,
            buffer: [0; 16 * 1024],
            used: 0,
            total: 0,
        };
        recorder
            .write_prefix(&mut writer)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        io::Write::flush(&mut writer)
    }

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
