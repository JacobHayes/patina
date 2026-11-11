//! Packaged startup and finalization. An ordinary program built with `
//! patina build` needs no Patina-specific init calls: the boundary sits
//! below application code. The constructor installs the deterministic runtime
//! from the PATINA_* protocol (idempotent) and registers finalization through
//! atexit, so record mode is finalized on any normal exit path (main return or
//! exit()) without an explicit patina_shutdown. A standalone run (no
//! PATINA_RT_MODE) is left uninstalled; its first effect boundary fails closed
//! (`ensure_runtime`). The public getenv reads only the deterministic guest map
//! after startup; startup reads the PATINA_* control plane through the private
//! snapshot before scrubbing the ambient environ and publishing the guest's.
//!
//! Linux startup before the constructors (`linux`) prepares the process for
//! the C `__libc_start_main` door, which keeps the main wrapper's frame.
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod traps;

/// The program's argv[0], which dlerror names a failed lookup by.
#[cfg(target_os = "linux")]
pub(super) fn program_path() -> *const core::ffi::c_char {
    linux::patina_program_path.load(core::sync::atomic::Ordering::Relaxed)
}

unsafe extern "C" {
    /// The sealed engine's binder (`cargo-patina` `seal.rs`): fills every
    /// host binding's slot with the host's definition of its door, through
    /// `patina_host_symbol`.
    fn patina_bind_hosts();
}

// The binder's stand-in in an archive linked without the seal, which has no
// host bindings to fill: weak, so the seal's binder takes the name.
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".pushsection .text.patina_bind_hosts,\"ax\",%progbits",
    ".weak patina_bind_hosts",
    ".type patina_bind_hosts, %function",
    "patina_bind_hosts:",
    "ret",
    ".size patina_bind_hosts, .-patina_bind_hosts",
    ".popsection",
);
#[cfg(target_os = "macos")]
core::arch::global_asm!(
    ".globl _patina_bind_hosts",
    ".weak_definition _patina_bind_hosts",
    ".p2align 2",
    "_patina_bind_hosts:",
    "ret",
);

/// Bind the engine's host bindings, the first thing the process runs of the
/// shim: no engine code reaches the host through one before, and none
/// resolves anything after, so a signal handler may take any of them.
pub(super) fn bind_hosts() {
    // SAFETY: the seal links the binder into every engine; startup is single
    // threaded, and no binding is reached before this.
    unsafe { patina_bind_hosts() }
}

/// Priority 101 runs before default-priority constructors on toolchains that
/// honor constructor priorities, minimizing false early-init failures while
/// still letting deliberately earlier constructors (the e2e uses
/// `.init_array.00099` on ELF) prove the fail-closed path. The C object's
/// reference to `patina_variadic_link` extracts this archive member.
#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array.00101")]
static NATIVE_START: extern "C" fn() = native_start;
#[cfg(target_os = "macos")]
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func,mod_init_funcs")]
static NATIVE_START: extern "C" fn() = native_start;

extern "C" fn native_start() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // Darwin has no earlier entry: this constructor is the shim's first.
    #[cfg(target_os = "macos")]
    bind_hosts();
    // Idempotent on Linux; also serves platforms without __libc_start_main.
    crate::panic_boundary::install();
    // SAFETY: registers a process-lifetime function.
    unsafe { libc::atexit(finalize_atexit) };
    // SAFETY: single-threaded CRT startup.
    unsafe { crate::posix_env::capture_control_plane() };
    // Register before init: installing the runtime publishes environ from the
    // guest env map.
    unsafe {
        crate::patina_register_environ_installer(Some(crate::posix_env::patina_environ_install))
    };
    // And the stdio flush the end of the run makes on its exit paths, with
    // the stdout salvage its refusals make.
    unsafe {
        crate::patina_register_stream_flusher(
            Some(super::stdio::flush_at_exit),
            Some(super::stdio::take_pending),
        )
    };
    // SAFETY: the control plane was captured above.
    if !unsafe { crate::posix_env::control_getenv(c"PATINA_RT_MODE".as_ptr()) }.is_null() {
        crate::patina_init_from_env();
    }
    crate::patina_publish_environ();
    // SAFETY: after capture, runtime installation and Linux auxv scrubbing.
    unsafe { crate::posix_env::scrub_environ() };
    crate::patina_note_startup_constructor_finished();
    // A child process of the machine reports ready and waits for its turn
    // before any guest code runs.
    #[cfg(target_os = "linux")]
    crate::machine::child_start();
}

extern "C" fn finalize_atexit() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // Interposer-engagement canary. This hook runs after the thread-local
    // destructors on every exit-chain path that reaches it, so on Linux the
    // teardown flag must already be set (natural return via the
    // __libc_start_main wrapper, explicit exit via the `exit` interposer). If
    // not, the root task's --yield-stride teardown yields were not silenced:
    // fail loudly before finalizing the trace rather than let the miss surface
    // later as an op-count divergence. `_exit`/`_Exit`/`abort` skip atexit.
    #[cfg(target_os = "linux")]
    crate::patina_assert_teardown_engaged();
    // patina_shutdown already emitted the runtime error; atexit ignores
    // return values, so abort to make finalization failures loud.
    if crate::patina_shutdown() != 0 {
        crate::host_abort(
            crate::RunStop::new(
                patina_dst_abi::RunClass::Internal,
                "shutdown_failure",
                &[b"finalizing the run failed after the guest finished"],
            )
            .with_guest_exit(crate::guest_exit_status()),
        );
    }
}
