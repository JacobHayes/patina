//! Global shim state, bootstrap state, and descriptor release.

use super::*;

pub(crate) static CONTEXT: OnceLock<SpinMutex<Option<Context>>> = OnceLock::new();
pub(crate) static STDIO: OnceLock<SpinMutex<StdioCapture>> = OnceLock::new();
pub(crate) static FD_TABLE: OnceLock<SpinMutex<GuestFdTable>> = OnceLock::new();

/// The guest descriptor table (see `fdtable.rs`). Lock order: the thread
/// runtime's state lock first, this lock second — `fd_readiness` and the
/// waiter registration resolve descriptors while holding the runtime state —
/// and this lock is never held across a runtime call or a scheduling point.
pub(crate) fn fd_table() -> &'static SpinMutex<GuestFdTable> {
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
/// Every `O_PATH` description is a path-only kind ([`FdKind::is_path_only`]).
pub(crate) fn fdget(raw_fd: c_int) -> Result<Resolved, c_int> {
    match resolve_fd(raw_fd)? {
        resolved if resolved.kind.is_path_only() => Err(EBADF),
        resolved => Ok(resolved),
    }
}

/// The driver handle behind a deterministic-filesystem descriptor. Any other
/// kind — and an empty slot — is `EBADF`, which is what every filesystem-only
/// entry (`fstat`, `fchmod`, `getdents`, the record locks) answers for a
/// descriptor that is not a file.
pub(crate) fn fs_handle(raw_fd: c_int) -> Result<Fd, c_int> {
    let resolved = resolve_fd(raw_fd)?;
    if resolved.kind.is_fs() {
        Ok(Fd(resolved.handle))
    } else {
        Err(EBADF)
    }
}

/// Bind a fresh description to the lowest free guest number, or `EMFILE`.
pub(crate) fn install_fd(
    kind: FdKind,
    handle: u64,
    status: u32,
    cloexec: bool,
) -> Result<c_int, c_int> {
    fd_table().lock().install(kind, handle, status, cloexec)
}

/// Free the class object a description named, once its last reference is
/// gone. Runs OUTSIDE the table lock: a driver close is a recorded boundary
/// operation, a pipe close wakes parked peers, and a readiness registry drop
/// wakes parked waiters.
pub(crate) fn release_description(release: Release) -> Result<(), c_int> {
    flock_release(release.desc);
    thread::locks::release_description_locks(release.desc);
    // An epoll interest is on the FILE (the kernel's `(fd, struct file)` key
    // drops with the file's last reference), whatever kind it was.
    #[cfg(target_os = "linux")]
    thread::forget_description(release.desc);
    match release.kind {
        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr | FdKind::Urandom => Ok(()),
        FdKind::File | FdKind::Dir | FdKind::OPath => {
            #[cfg(target_os = "linux")]
            mem::released(release.handle);
            #[cfg(target_os = "linux")]
            if release.kind != FdKind::OPath {
                fsnotify::closing(Fd(release.handle), release.status & O_WRITE != 0);
            }
            let closed = with_context(|context| context.fs_close(Fd(release.handle)));
            #[cfg(target_os = "linux")]
            fsnotify::unbound(Fd(release.handle));
            closed
        }
        FdKind::Socket => thread::net::socket_close(release.handle),
        FdKind::Pipe => {
            #[cfg(target_os = "linux")]
            fsnotify::fifo_closed(release.handle, release.status & O_WRITE != 0);
            thread::pipe_close(release.handle)
        }
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
        FdKind::Inotify => {
            thread::inotify::close(release.handle);
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
        #[cfg(target_os = "linux")]
        FdKind::Pidfd | FdKind::LandlockRuleset => Ok(()),
        #[cfg(target_os = "linux")]
        FdKind::Userfaultfd => {
            mem::userfaultfd::released(release.handle);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        FdKind::Namespace | FdKind::NamespacePath => Ok(()),
        #[cfg(target_os = "linux")]
        FdKind::PtyMaster => {
            thread::pty::release(thread::pty::Side::Master, release.handle as u32);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        FdKind::PtySlave => {
            thread::pty::release(thread::pty::Side::Slave, release.handle as u32);
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
mod bootstrap {
    use std::sync::atomic::{AtomicBool, Ordering};

    static ACTIVE: AtomicBool = AtomicBool::new(true);

    pub(super) fn finish() {
        ACTIVE.store(false, Ordering::Release);
    }

    pub(super) fn active() -> bool {
        if !ACTIVE.load(Ordering::Acquire) {
            return false;
        }
        super::abort_if_init_failed();
        true
    }
}

pub(crate) fn finish_shim_bootstrap() {
    bootstrap::finish();
}

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

pub(crate) fn declare_link_time_sites(context: &mut Context) -> Result<(), RuntimeError> {
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
/// `bootstrap::ACTIVE`). Read lock-free so the interposers can branch on it on
/// entry, before touching any shim lock or the guest allocator.
///
/// This is the ONE door into the window, and it fails closed on a failed init:
/// `bootstrap::ACTIVE` is cleared only by a SUCCESSFUL [`install`], so an
/// initialization that failed closed (a `--fingerprint` mismatch, a bad
/// `--mount` corpus, ...) leaves the window open for the rest of the process.
/// Every answer behind it — a zero clock, a zero CPU time, `ENOENT` for a
/// `read_link`, a natively-run lock — is produced WITHOUT reaching
/// [`ensure_runtime`], so without the check below the guest never learns the run
/// was refused. That is not hypothetical: a replay of a guest whose only
/// boundary operations are clock reads used to spin at 100% CPU on a fabricated
/// frozen clock instead of aborting on the fingerprint mismatch. Consulting the
/// stored init error HERE, rather than at each answer, covers the paths that
/// exist and the ones not yet written. The flag is private to the bootstrap
/// module, whose only reader performs this check.
#[inline]
pub(crate) fn in_shim_bootstrap() -> bool {
    bootstrap::active()
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
pub(crate) fn spin_depth_inc() {
    SPIN_DEPTH.with(|depth| depth.set(depth.get() + 1));
}

#[inline]
pub(crate) fn spin_depth_dec() {
    SPIN_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
}

/// Whether this thread currently holds any shim spinlock — i.e. a lock-interposer
/// call now would be allocator-internal reentrancy that must run natively rather
/// than re-acquire the held spinlock. See [`SPIN_DEPTH`].
#[inline]
pub(crate) fn in_shim_critical() -> bool {
    SPIN_DEPTH.with(Cell::get) > 0
}

/// The captured streams, stdout (0) and stderr (1). On Linux each write is
/// written through to the host's descriptor as it is made, so whatever ends
/// the run (a fault the kernel kills with no handler, a supervisor's kill)
/// finds it there already, as natively; on macOS it is held until the run
/// ends. Either way the bytes each stream took are counted against the
/// capture bound, so what a write answers the guest is the same.
#[derive(Default)]
pub(crate) struct StdioCapture {
    /// What each stream holds for the host (macOS only: empty on Linux).
    pub(crate) pending: [Vec<u8>; 2],
    /// The bytes each stream took.
    taken: [usize; 2],
    /// A host stream whose reader went away (`EPIPE`): written no more.
    #[cfg(target_os = "linux")]
    gone: [bool; 2],
}

impl StdioCapture {
    /// Take `parts` onto `stream` (0 stdout, 1 stderr), all or, past the
    /// capture bound, nothing (answering false).
    pub(crate) fn put(&mut self, stream: usize, parts: &[&[u8]]) -> bool {
        let length = parts.iter().map(|part| part.len()).sum::<usize>();
        if self.taken[stream].saturating_add(length) > MAX_CAPTURED_STDIO_BYTES {
            return false;
        }
        self.taken[stream] += length;
        for part in parts {
            #[cfg(target_os = "linux")]
            if !self.gone[stream] && !part.is_empty() {
                self.gone[stream] = !thread::signals::write_through(stream as c_int + 1, part);
            }
            #[cfg(not(target_os = "linux"))]
            self.pending[stream].extend_from_slice(part);
        }
        true
    }
}
