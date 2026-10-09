//! Control-plane parsing, runtime installation, and boundary error handling.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

static CONTROL_PLANE: OnceLock<SpinMutex<BTreeMap<String, String>>> = OnceLock::new();

pub(crate) fn control_plane() -> &'static SpinMutex<BTreeMap<String, String>> {
    CONTROL_PLANE.get_or_init(|| SpinMutex::new(BTreeMap::new()))
}

/// The runtime's own diagnostic from the most recent failed `init_from_env`,
/// captured so the fail-closed abort path can surface *why* initialization
/// failed (fingerprint mismatch, bad `--mount` corpus, replay-fault conflict, …)
/// instead of the generic "no runtime installed" line. `install` collapses the
/// [`RuntimeError`] to an errno, discarding the message; this preserves it.
static INIT_ERROR: OnceLock<SpinMutex<Option<String>>> = OnceLock::new();

pub(crate) fn init_error() -> &'static SpinMutex<Option<String>> {
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
pub(crate) fn record_init_error(message: String) {
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
pub(crate) fn abort_if_init_failed() {
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
pub(crate) enum FlockMode {
    #[cfg(any(target_os = "linux", patina_posix_exports))]
    Shared,
    #[cfg(any(target_os = "linux", patina_posix_exports))]
    Exclusive,
}

/// What an advisory lock is taken ON: the kernel keys `flock` by inode, so two
/// descriptions open on one deterministic-fs inode contend, while every other
/// kind of description is its own inode (a socket, an eventfd) — modeled as the
/// description itself. (The two ends of one anonymous pipe share an inode on
/// Linux and do not here; no supported guest locks a pipe.)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LockIdentity {
    Inode(u64),
    Description(DescId),
}

/// What a lock on `resolved` is taken on. A filesystem descriptor's inode is
/// read through the recorded, never-faulted `fs_fd_ino` lookup, so the
/// conflict decision keys on the same file identity under record and replay
/// and a lock (bookkeeping that does no I/O) cannot fail with an injected
/// error; a FIFO endpoint's is its node's.
pub(crate) fn lock_identity(resolved: &Resolved) -> Result<LockIdentity, c_int> {
    if resolved.kind.is_fs() {
        return with_context(|context| context.fs_fd_ino(Fd(resolved.handle)))
            .map(LockIdentity::Inode);
    }
    let fifo = (resolved.kind == FdKind::Pipe)
        .then(|| thread::fifo_end_ino(resolved.handle))
        .flatten();
    Ok(match fifo {
        Some(ino) => LockIdentity::Inode(ino),
        None => LockIdentity::Description(resolved.desc),
    })
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

pub(crate) fn flock_table() -> &'static SpinMutex<BTreeMap<DescId, (LockIdentity, FlockMode)>> {
    FLOCK_TABLE.get_or_init(|| SpinMutex::new(BTreeMap::new()))
}

/// Release any advisory lock a description holds. Called by `LOCK_UN` and when
/// the description is freed; a description holding no lock is a no-op.
pub(crate) fn flock_release(desc: DescId) {
    flock_table().lock().remove(&desc);
}

pub(crate) fn set_errno(errno: c_int) {
    LAST_ERRNO.with(|value| value.set(errno));
}

/// A raw-ABI error return: `-errno`.
#[cfg(target_os = "linux")]
pub(crate) fn neg_errno(errno: c_int) -> i64 {
    -i64::from(errno)
}

pub(crate) fn fail(errno: c_int) -> c_int {
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

#[unsafe(no_mangle)]
/// `fcntl(F_SETOWN)`, `F_SETOWN_EX` and `F_SETSIG`: who `SIGIO` and
/// `SIGURG` go to. Neither signal is delivered, so on an open descriptor
/// this stops by name rather than answer as if they would be; a closed or
/// `O_PATH` one is `EBADF` first.
pub extern "C" fn patina_fcntl_owner(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if let Err(errno) = fdget(raw_fd) {
        return fail(errno);
    }
    trap_fatal(
        "fcntl setting a descriptor's owner or signal (F_SETOWN, F_SETOWN_EX, F_SETSIG) is not \
         modeled: SIGIO and SIGURG are never delivered; failing closed",
    );
}

#[unsafe(no_mangle)]
/// `fcntl(F_GETOWN)`, `F_GETSIG` and, with `ex` nonzero, `F_GETOWN_EX`
/// into `owner` (the guest's `struct f_owner_ex`). Nothing ever sets a
/// descriptor's owner or signal (the setters stop by name,
/// [`patina_fcntl_owner`]), so the answers are 6.8's for a file with none:
/// 0, 0 and `{F_OWNER_TID, 0}` (`EFAULT` for memory that cannot take it).
/// A closed or `O_PATH` descriptor is `EBADF` first (`check_fcntl_cmd`).
pub extern "C" fn patina_fcntl_owner_get(raw_fd: c_int, ex: c_int, owner: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if let Err(errno) = fdget(raw_fd) {
        return fail(errno);
    }
    if ex != 0
        && let Err(errno) = uaccess::write(owner as usize, &[0i32; 2])
    {
        return fail(errno);
    }
    set_errno(0);
    0
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

pub(crate) fn runtime_errno(error: &RuntimeError) -> c_int {
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
        RuntimeError::ComputeBound { .. } => {
            watchdog::report_synchronous(error);
            abort_after_flushing_output()
        }
        RuntimeError::ComputeStopExport
        | RuntimeError::ComputeStopOverflow
        | RuntimeError::ComputeStopState => watchdog::report_and_abort(error, None, None),
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

pub(crate) fn effect_errno(error: &EffectError) -> c_int {
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
        ErrorCode::NoSuchPosition => ENXIO,
        ErrorCode::FileTooBig => EFBIG,
    }
}

/// Set once `patina_shutdown` has finalized, so a later boundary call fails
/// with `ENOSYS` instead of re-initializing a torn-down runtime.
pub(crate) static SHUTDOWN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set once any deterministic boundary effect has run against the installed
/// context (in [`with_context`]/[`with_context_raw`]). The shim-backed harness
/// (`patina-dst-harness`, USAGE-MODES.md Option B) consults this in
/// [`patina_harness_install`]: a boundary observed BEFORE the harness installs
/// means the run already produced events, so reconfiguring the context would
/// make replay semantics ambiguous — the install fails closed. The harness's own
/// `install` does not route through those functions, so it never self-trips this.
pub(crate) static BOUNDARY_SEEN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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
pub(crate) static HARNESS_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Set by the packaged C startup constructor after it has captured the control
/// plane, optionally installed the runtime, and scrubbed the live environment.
/// If an interposed boundary arrives before this flag, a guest/static constructor
/// beat Patina's constructor in the loader order and the runtime cannot be
/// installed soundly from the still-unsnapshotted control plane.
pub(crate) static STARTUP_CONSTRUCTOR_FINISHED: AtomicBool = AtomicBool::new(false);

/// Best-effort name of the public interposed symbol currently entering the Rust
/// boundary. C interposers store string-literal pointers here before calling the
/// prefixed `patina_*` ABI; early-init diagnostics read it without allocation.
pub(crate) static LAST_BOUNDARY_SYMBOL: AtomicPtr<c_char> = AtomicPtr::new(std::ptr::null_mut());

/// Guarantee a deterministic runtime is installed before a boundary call, or
/// fail closed. Ordinary programs built with `cargo patina native-build` do not
/// call `patina_init_from_env` themselves: the packaged startup path installs
/// the runtime from the supervisor protocol. This is the belt-and-suspenders
/// path — if the constructor has not run yet (static-init ordering) but the
/// protocol is present, it initializes now; if the protocol is absent the
/// binary is being run outside `cargo patina native-run`, which is a hard,
/// clearly reported error rather than a silent seeded-zero run.
pub(crate) fn ensure_runtime() -> Result<(), c_int> {
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
pub(crate) fn abort_with_init_error(message: &str) -> ! {
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
pub(crate) fn missing_context_is_pre_harness_install() -> bool {
    if HARNESS_INSTALLED.load(Ordering::Acquire) {
        return false;
    }
    control_plane()
        .lock()
        .contains_key(patina_dst_runtime::ENV_DEFER_INIT)
}

pub(crate) fn abort_harness_before_install() -> ! {
    let _ = flush_before_refusal();
    let message: &[u8] = b"patina: harness has not installed the runtime yet; an interposed \
effect reached the deterministic boundary before patina_dst_harness::run/run_with installed the \
runtime. Do all configuration and application effects inside the harness closure.\n";
    let _ = host_write_all(2, message);
    crate::host_abort();
}

pub(crate) fn abort_preinit_interposed_call() -> ! {
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
pub(crate) fn with_context_raw<T>(
    invoke: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, c_int> {
    BOUNDARY_SEEN.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut guard = slot().lock();
    let context = guard.as_mut().ok_or(ENOSYS)?;
    let result = if thread::in_state_section() {
        context.in_embedder_section(invoke)
    } else {
        invoke(context)
    };
    thread::note_expiries(context);
    match result {
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
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
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
pub(crate) fn with_context_msg<T>(
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
    let result = if thread::in_state_section() {
        context.in_embedder_section(invoke)
    } else {
        invoke(context)
    };
    thread::note_expiries(context);
    result.map_err(|error| match &error {
        // A classified yield divergence gains the one fact only the shim knows:
        // the instrumented guest site of the in-flight guard hit (if any).
        RuntimeError::ScheduleDivergence { .. } => {
            format!("{error}{}", thread::yield_site_context())
        }
        RuntimeError::ComputeBound { .. } => {
            // Baton-held refusal, unlike the observer. The registered salvage
            // only lends C stdout bytes; it takes no scheduling point/Context
            // lock (see salvage_buffered_stdout). Keep stop ownership here.
            watchdog::report_synchronous(&error);
            abort_after_flushing_output()
        }
        RuntimeError::ComputeStopExport
        | RuntimeError::ComputeStopOverflow
        | RuntimeError::ComputeStopState => watchdog::report_and_abort(&error, None, None),
        _ => error.to_string(),
    })
}

/// Run a closure against the installed [`Context`] behind a deterministic
/// scheduling point. Every interposed boundary call routes through here, so
/// the seeded scheduler can transfer the execution baton between managed
/// threads at each boundary; when no managed threads exist the scheduling
/// point is a cheap no-op and the behavior is identical to a single thread.
pub(crate) fn with_context<T>(
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
pub(crate) fn fs_time_unrecorded() -> u64 {
    slot()
        .lock()
        .as_mut()
        .and_then(|context| context.fs_time_unrecorded().ok())
        .unwrap_or(0)
}

pub(crate) fn control_env(name: &str) -> Option<String> {
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

pub(crate) fn parse_control_u64(name: &str) -> Result<Option<u64>, RuntimeError> {
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
pub(crate) fn control_facts_fd() -> Result<Option<i32>, RuntimeError> {
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

pub(crate) fn control_trace_fd() -> Result<Option<i32>, RuntimeError> {
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
pub(crate) fn fs_image_base() -> Result<MemFs, RuntimeError> {
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

pub(crate) fn runtime_config_from_control_plane()
-> Result<(RuntimeConfig, Option<i32>), RuntimeError> {
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

/// Whether startup armed syscall-user-dispatch for this run
/// (`posix::lifecycle`), exported for the native-boundary guests that check
/// it. As an `AtomicU8` it lives in a writable section.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub static PATINA_SUD_ARMED: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Whether SUD was armed for this run, shaped for [`RunMetadata::sud`]:
/// `Some(true)` iff startup armed syscall-user-dispatch, else `None`
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

/// Whether startup armed the timestamp-counter trap, exported as
/// [`PATINA_SUD_ARMED`] is.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub static PATINA_TSC_ARMED: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Whether the timestamp-counter trap was armed for this run, shaped for
/// `RunMetadata::tsc`: `Some(true)` iff startup armed it, else `None`
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

pub(crate) fn install(context: Result<Context, RuntimeError>) -> c_int {
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
    finish_shim_bootstrap();
    0
}

/// Decode a NUL-terminated C path as UTF-8.
///
/// # Safety
/// When non-null, `path` must be readable through its terminating NUL byte.
/// A null pointer is accepted and returns `EINVAL`.
pub(crate) unsafe fn path_from_c(path: *const c_char) -> Result<String, c_int> {
    if path.is_null() {
        return Err(EINVAL);
    }
    // SAFETY: The caller guarantees a readable NUL-terminated string when non-null.
    unsafe { CStr::from_ptr(path) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| EINVAL)
}

pub(crate) fn clock(value: u32) -> Result<ClockKind, c_int> {
    match value {
        0 => Ok(ClockKind::Realtime),
        1 => Ok(ClockKind::Monotonic),
        _ => Err(EINVAL),
    }
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
