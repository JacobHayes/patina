//! Native constructor and deferred-harness runtime installation.

use super::*;

#[unsafe(no_mangle)]
pub extern "C" fn patina_note_boundary_symbol(symbol: *const c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_glue();
    LAST_BOUNDARY_SYMBOL.store(symbol.cast_mut(), Ordering::Relaxed);
}

#[unsafe(no_mangle)]
/// Install the POSIX interposer's internal-panic policy without installing a
/// runtime. Bare prefixed-C embedders have no guest abort interposer or required
/// host aliases and deliberately do not call this startup control-plane entry.
pub extern "C" fn patina_init_panic_policy() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_glue();
    crate::panic_boundary::install();
}

#[unsafe(no_mangle)]
/// Mark that the packaged C startup constructor finished capture/init/scrub.
pub extern "C" fn patina_note_startup_constructor_finished() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // The loader runs the constructor on the main thread.
    thread::claim_main_thread();
    STARTUP_CONSTRUCTOR_FINISHED.store(true, Ordering::Release);
}

#[unsafe(no_mangle)]
/// Capture one `PATINA_NAME=value` constructor-time control-plane entry for
/// later shim-internal configuration reads. Guest-visible getenv never serves
/// this map.
///
/// # Safety
/// `entry` must point to a valid NUL-terminated string for the duration of the
/// call.
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

pub(crate) fn init_from_env() -> c_int {
    let context = runtime_config_from_control_plane().and_then(|(config, trace_fd)| {
        watchdog::configure()?;
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

#[unsafe(no_mangle)]
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
