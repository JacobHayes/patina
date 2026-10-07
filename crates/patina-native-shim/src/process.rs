//! Process identity, scheduling, exit, abort, and crash entry points.

use super::*;

#[unsafe(no_mangle)]
pub extern "C" fn patina_thread_id() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    thread::deterministic_thread_id()
}

#[unsafe(no_mangle)]
/// `sched_yield`/`thread::yield_now`: take a deterministic scheduling point
/// instead of yielding the host scheduler. std's `mpsc`/`mpmc` backoff spins
/// through `thread::yield_now` before parking, so an uninterposed `sched_yield`
/// would be a host scheduling call outside the runtime. A no-op until the
/// thread subsystem activates, so single-threaded programs are unaffected.
pub extern "C" fn patina_sched_yield() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let _ = thread::sched_point();
    0
}

#[unsafe(no_mangle)]
/// The `--yield-points` guard hook: `patina_yield.c` forwards every
/// SanitizerCoverage guard hit here with the instrumented call site, so a
/// record/replay yield divergence can name the exact guest location that took
/// the extra scheduling point. Otherwise identical to [`patina_sched_yield`].
pub extern "C" fn patina_yield_point(site: *const c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    thread::yield_point_from(site as usize);
}

#[unsafe(no_mangle)]
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
/// The stop is the host's default SIGABRT, never a delivery: a guest's
/// SIGABRT handler (including Linux's modeled front) does not run inside the
/// stopping shim.
pub(crate) fn host_abort() -> ! {
    let host = hostapi::get();
    let mut default: libc::sigaction = unsafe { std::mem::zeroed() };
    default.sa_sigaction = libc::SIG_DFL;
    // Use the one private host seam on BOTH platforms. Reset before abort
    // unblocks/raises SIGABRT: neither a native guest handler nor Linux's front
    // handler may run while the stopping shim holds its locks/guest allocator.
    if unsafe { (host.host_sigaction)(libc::SIGABRT, &default, std::ptr::null_mut()) } != 0 {
        let _ = host_write_all(2, b"\nPATINA_INFRA host_abort_reset_failed\n");
        // Calling abort after a failed reset would re-enter guest code. A
        // refused host action instead loses signal status, never containment.
        unsafe { (host.host_immediate_exit)(128 + libc::SIGABRT) }
    }
    // libc abort supplies the unblock + raise even for an inherited host mask.
    unsafe { (host.host_abort)() }
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

#[unsafe(no_mangle)]
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
pub extern "C" fn patina_note_main_returned() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    thread::note_main_returned();
}

#[unsafe(no_mangle)]
/// Whether the process is in its post-`main` teardown (1) or not (0). After
/// `main` returns only the root task runs, so the POSIX layer's internal locks
/// (a stream's, the environment's) have nothing left to exclude, and waiting
/// on one a parked task holds would be a scheduling operation past the end of
/// the run — the refusal in `with_context_msg`. They are not taken then.
pub extern "C" fn patina_in_teardown() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    c_int::from(thread::main_returned())
}

#[unsafe(no_mangle)]
/// Linux interposer-engagement canary. The atexit finalizer (`posix::lifecycle`)
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
    // An inotify watch names an inode of the image the crash replaces, and
    // no kernel carries a watch across a crash: a restarted process has
    // none.
    #[cfg(target_os = "linux")]
    if fsnotify::watching() {
        trap_fatal(
            "patina_crash: an in-process crash while an inotify watch exists is not modeled; \
             failing closed",
        );
    }
    match with_context(Context::fs_crash) {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            {
                mem::crashed();
                fsnotify::crashed();
            }
            0
        }
        Err(errno) => fail(errno),
    }
}
