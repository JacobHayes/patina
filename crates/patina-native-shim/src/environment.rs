//! Captured stdio and the guest environment publication gates.

use super::*;

#[unsafe(no_mangle)]
/// Capture deterministic stdout (1) or stderr (2) bytes, mirroring the WASI
/// host's captured stdio: written through to the host on Linux, flushed at
/// `patina_shutdown` on macOS ([`StdioCapture`]).
///
/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
pub unsafe extern "C" fn patina_stdio_write(
    fd: c_int,
    source: *const c_void,
    length: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if fd != 1 && fd != 2 {
        return fail(EBADF) as isize;
    }
    if length != 0 && source.is_null() {
        return fail(EINVAL) as isize;
    }
    // Capture accepts bytes with no context installed, so — like the
    // shim-bootstrap window — it never reaches `ensure_runtime` and would
    // swallow a fail-closed init error. The buffer is flushed at
    // `patina_shutdown`, which with no context returns quietly, so a guest whose
    // only boundary effect is a `println!` used to exit 0 with its output
    // dropped and the refusal unreported. Not `ensure_runtime`: that would also
    // fire for a binary run outside the supervisor, whose diagnostic is the
    // startup path's to give.
    abort_if_init_failed();
    // Runtime diagnostics can print with Context/ThreadRuntime locked. They use
    // the same captured sink, but must not schedule or re-enter either lock.
    // Guest writes still take their ordinary scheduling point.
    if !in_shim_critical()
        && let Err(errno) = thread::sched_point()
    {
        return fail(errno) as isize;
    }
    let bytes = if length == 0 {
        &[]
    } else {
        // SAFETY: Guaranteed by this function's C ABI contract.
        unsafe { slice::from_raw_parts(source.cast::<u8>(), length) }
    };
    if !stdio_slot().lock().put(fd as usize - 1, &[bytes]) {
        return fail(EFBIG) as isize;
    }
    set_errno(0);
    isize::try_from(length).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_errno() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    LAST_ERRNO.with(Cell::get)
}

// ---- The guest environment ----------------------------------------------------
//
// The environment is the process's own `environ` array, as it is under glibc:
// the POSIX layer (`src/posix_env.rs`) runs glibc's getenv/setenv/unsetenv/putenv/
// clearenv over whatever array `environ` names, so a pointer `getenv` answers
// is the entry's own bytes, new names are appended, an array the program
// assigns is honoured and a `putenv` string stays aliased. The runtime's part
// is the array the run STARTS with — the startup `--env` map, the one piece
// the trace records, published once the ambient host environment is scrubbed
// (and again when a deferred harness installs the runtime) — and the gates
// below, which decide when the POSIX layer may answer at all.
//
// Mutations are guest-driven and therefore deterministic: nothing is recorded
// per mutation, and replay reproduces them by re-executing the guest.

/// May the POSIX `getenv` read `environ`? 1 to read it, 0 to answer NULL: before
/// the startup constructor finishes, `environ` is still the ambient host
/// environment, and Rust/libc startup code can probe it before Patina's
/// constructor runs, so those probes see the historical empty environment
/// rather than the host's. A stored init error aborts, as every entry that
/// answers without reaching `ensure_runtime` must; so does a lookup that beat
/// a deferred harness install.
#[unsafe(no_mangle)]
pub extern "C" fn patina_env_read_gate() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if let Some(message) = init_error().lock().clone() {
        abort_with_init_error(&message);
    }
    if !STARTUP_CONSTRUCTOR_FINISHED.load(Ordering::Acquire) {
        return 0;
    }
    let missing_context = slot().lock().is_none();
    if missing_context && missing_context_is_pre_harness_install() {
        abort_harness_before_install();
    }
    1
}

#[unsafe(no_mangle)]
/// May the POSIX layer mutate `environ`? 0 to go ahead, -1 (`ENOSYS`, with a
/// diagnostic) when no runtime is installed. Unlike a lookup, a pre-startup
/// WRITE would change the ambient host array the constructor is about to
/// scrub, and the guest and the run would then disagree about the
/// environment: a constructor beat Patina's, so name it and fail closed.
pub extern "C" fn patina_env_write_gate() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if let Some(message) = init_error().lock().clone() {
        abort_with_init_error(&message);
    }
    if !STARTUP_CONSTRUCTOR_FINISHED.load(Ordering::Acquire) {
        abort_preinit_interposed_call();
    }
    let missing_context = slot().lock().is_none();
    if missing_context {
        if missing_context_is_pre_harness_install() {
            abort_harness_before_install();
        }
        // A standalone run (or one past `patina_shutdown`) has no deterministic
        // environment to mutate; refuse rather than pretend the write took.
        let _ = host_write_all(
            2,
            b"patina: environment mutation requires an installed deterministic runtime; failing closed\n",
        );
        return fail(ENOSYS);
    }
    set_errno(0);
    0
}

/// `void (*)(char **)` installed by the POSIX layer's constructor, or null when
/// no C layer is linked (direct C-ABI embedders and the Rust lib tests). Stored
/// as a data pointer because Rust has no atomic function-pointer type. The
/// dependency points C→Rust: the Rust lib's own test binary links no C
/// objects, so naming `environ`'s owner here would leave it undefined.
static ENVIRON_INSTALLER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

type EnvironInstaller = unsafe extern "C" fn(*mut *mut c_char);

#[unsafe(no_mangle)]
/// Register the callback that publishes the startup `environ` array. Called
/// once from the POSIX constructor before the runtime is installed.
///
/// # Safety
/// `installer` must be a valid `void (*)(char **)` for the life of the process.
pub unsafe extern "C" fn patina_register_environ_installer(installer: Option<EnvironInstaller>) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
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

/// Build the startup `environ` array from `env` (key order) and hand it to the
/// registered installer. The array and its strings are deliberately leaked: the
/// guest owns the environment from here on, and glibc's `setenv` copies an
/// array it did not allocate before growing it.
pub(crate) fn publish_environ(env: &BTreeMap<String, String>) {
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
            crate::host_abort();
        };
        entries.push(entry.into_raw());
    }
    entries.push(std::ptr::null_mut());
    let array = Box::leak(entries.into_boxed_slice()).as_mut_ptr();
    // SAFETY: `array` is a live, NUL-terminated `char **` that outlives the
    // process, which is exactly what the installer stores into `environ`.
    unsafe { installer(array) };
}

#[unsafe(no_mangle)]
/// Publish `environ` from the installed context's startup map, or an empty
/// array when no runtime is installed. The POSIX constructor then commits
/// this map to the launcher's reserved initial-stack environment and scrubs
/// the old entries before admitting guest environment reads. A deferred
/// harness installation later replaces `environ` without rebaking the stack.
pub extern "C" fn patina_publish_environ() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let guard = slot().lock();
    match guard.as_ref() {
        Some(context) => publish_environ(context.guest_env()),
        None => publish_environ(&BTreeMap::new()),
    }
}
