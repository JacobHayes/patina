//! Run shutdown, trace finalization, and captured-stream flushing.

use super::*;

static STREAM_FLUSHER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// `size_t (*)(const void **)` registered beside the flusher: hands over the
/// bytes stdout's buffer holds and empties it, writing nothing (see
/// [`salvage_buffered_stdout`]).
static STREAM_SALVAGE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

type StreamFlusher = unsafe extern "C" fn();
type StreamSalvage = unsafe extern "C" fn(*mut *const c_void) -> usize;

#[unsafe(no_mangle)]
/// Register the POSIX layer's stdio flush, which [`patina_shutdown`] runs
/// first, and the salvage of its stdout buffer, which every refusal runs
/// ([`flush_before_refusal`]). Null pointers unregister.
///
/// # Safety
/// `flusher` must be a valid `void (*)(void)` and `salvage` a valid
/// `size_t (*)(const void **)` for the life of the process.
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

#[unsafe(no_mangle)]
/// Finalize the runtime on an exit path, writing any recorded trace and
/// flushing captured stdio. The guest's stdio buffers are written first, as
/// glibc's `exit` flushes them after the atexit handlers (`_IO_cleanup`); the
/// runtime's own abort, fatal-signal and raw `exit_group` paths call
/// [`shutdown_run`] instead, since glibc flushes on none of them. Idempotent:
/// the packaged startup path registers this through `atexit` so record mode
/// finalizes on normal exit without an explicit call, and a second call (for
/// example an application that still calls it explicitly) is a no-op.
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
pub(crate) fn over_budget_diagnostic(error: &TraceError) -> String {
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

#[unsafe(no_mangle)]
/// Record the guest's own exit status. Called from the `__libc_start_main`
/// wrapper the moment the guest's `main` returns, and from [`patina_exit`] for
/// an explicit `exit(3)`/`std::process::exit`. The FIRST recording wins: `main`
/// returning is the guest's verdict, and glibc's own later `exit()` of that same
/// code must not be mistaken for a second, independent one.
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

#[unsafe(no_mangle)]
/// Flush captured stdout/stderr to the real host descriptors WITHOUT finalizing
/// the run (unlike [`patina_shutdown`], which also finishes the trace/record),
/// salvaging what the C streams buffered ([`flush_before_refusal`]). The
/// process-class deny-traps in the staged `patina_posix.c` call this immediately
/// before `host_abort()`: `host_abort()` skips the atexit-driven shutdown flush, so
/// without it the guest's buffered output and the deny diagnostic would be lost.
pub extern "C" fn patina_flush_captured_stdio() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match flush_before_refusal() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Write what the capture holds to the host (on Linux nothing: it writes
/// through, [`StdioCapture`]), as the end of a run does. The
/// guest's own stdio buffers are not touched: [`shutdown_run`] and the
/// crash-restart `_exit` end the run the way glibc's abort, fatal signal and
/// `_exit` do, and those lose them.
pub(crate) fn flush_captured_stdio() -> io::Result<()> {
    flush_capture(false)
}

/// An off-baton terminal stop cannot deallocate captured buffers, wait for a
/// guest-held stdio lock, or call the guest's C-stream salvage callback. Emit
/// only the already captured prefix if available; leave all storage in place.
pub(crate) fn flush_observed_stdio() {
    if let Some(slot) = STDIO.get()
        && let Some(capture) = slot.try_lock()
    {
        let _ = host_write_all(1, &capture.pending[0]);
        let _ = host_write_all(2, &capture.pending[1]);
    }
}

/// The flush every path on which PATINA ends the run makes before it aborts:
/// a refusal, an internal fatal, a liveness or step-budget stop, a verdict, a
/// failed initialization. The guest did not choose to end there, so the
/// output it buffered in C `stdout` (which glibc would have written at a later
/// flush) is handed to the capture too: the lines leading up to the refusal
/// are what a user debugs it from.
pub(crate) fn flush_before_refusal() -> io::Result<()> {
    flush_capture(true)
}

fn flush_capture(salvage: bool) -> io::Result<()> {
    let mut capture = stdio_slot().lock();
    let [stdout, stderr] = std::mem::take(&mut capture.pending);
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

pub(crate) fn stdio_slot() -> &'static SpinMutex<StdioCapture> {
    STDIO.get_or_init(|| SpinMutex::new(StdioCapture::default()))
}
