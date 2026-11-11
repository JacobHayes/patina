//! Native constructor and runtime installation.

use super::*;

#[unsafe(no_mangle)]
pub extern "C" fn patina_note_boundary_symbol(symbol: *const c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_glue();
    LAST_BOUNDARY_SYMBOL.store(symbol.cast_mut(), Ordering::Relaxed);
}

/// Mark that the packaged C startup constructor finished capture/init/scrub.
pub fn patina_note_startup_constructor_finished() {
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
pub unsafe fn patina_control_set_entry(entry: *const c_char) {
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
                .with_filesystem(filesystem)
                .build()
        });
    install(context)
}

pub(crate) fn init_from_env() -> c_int {
    let context = runtime_config_from_control_plane().and_then(|(config, trace_fd)| {
        layout::verify()?;
        watchdog::configure()?;
        #[cfg(patina_posix_exports)]
        crate::admission::capture()?;
        #[cfg(target_os = "linux")]
        crate::machine::configure()?;
        // A child process of the machine uses the root's filesystem.
        #[cfg(target_os = "linux")]
        let builder = if crate::machine::is_child() {
            RuntimeBuilder::new(config).with_filesystem(crate::machine::fs::RemoteFs)
        } else {
            RuntimeBuilder::new(config).with_fs_image(fs_image_base()?)
        };
        #[cfg(not(target_os = "linux"))]
        let builder = RuntimeBuilder::new(config).with_fs_image(fs_image_base()?);
        let mut builder = builder;
        if let Some(fd) = trace_fd {
            builder = builder.with_trace_transport(FdTraceTransport { fd });
        }
        // The structured run-facts channel.
        if let Some(fd) = control_facts_fd()? {
            builder = builder.with_facts_sink(FdFactsSink { fd });
        }
        if let Some(fd) = control_crash_report_fd()? {
            builder = builder.with_crash_attempt_sink(FdCrashAttemptSink { fd });
        }
        builder.build()
    });
    if let Err(error) = &context {
        // Preserve the runtime's diagnostic before `install` collapses it to a
        // bare errno, so the fail-closed abort path can report *why*.
        record_init_failure(error);
    }
    install(context)
}

#[unsafe(no_mangle)]
/// Build the runtime from the `PATINA_*` protocol. Idempotent: the packaged
/// startup path (a constructor in the POSIX layer) calls this automatically, so
/// an explicit call from application code that also wants it is a no-op rather
/// than a double-init error.
pub extern "C" fn patina_init_from_env() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if slot().lock().is_some() {
        set_errno(0);
        return 0;
    }
    init_from_env()
}
