//! The guest's address layout: one seed, one set of addresses.
//!
//! A native guest sees host addresses — its code, its stack, its mappings,
//! its heap — and a guest that orders, hashes or prints a pointer behaves as a
//! function of them. The supervisor therefore launches every incarnation so
//! that the kernel picks the same addresses each time:
//!
//! * address-space randomization is off for the guest's image: Linux
//!   `personality(ADDR_NO_RANDOMIZE)`, Darwin `_POSIX_SPAWN_DISABLE_ASLR`;
//! * on Linux the soft `RLIMIT_STACK` is the modeled machine's 8 MiB, the
//!   value the kernel sizes the mapping area's gap from and glibc sizes a
//!   default thread stack from;
//! * the initial stack has the same size in every mode: the strings and
//!   pointers the kernel copies onto it are padded to a total that depends
//!   only on what every mode of the run shares (its arguments and its
//!   environment map), so the control plane — mode, descriptor numbers, the
//!   path the binary was exec'd from — never moves the stack.
//!
//! A host that refuses any of this stops the run before the guest starts.
//! The shim then checks, at startup, that the layout it was promised is the
//! one it got ([`patina_dst_runtime::ENV_ADDRESS_LAYOUT`]).
//!
//! `--allow-randomized-address-layout` is the operator's explicit opt-out,
//! for hosts that forbid the persona (Docker's default seccomp profile, for
//! one): the guest keeps the host's randomization and inherited stack limit,
//! its initial stack is not padded, the run's determinism is qualified in its output, and its trace records
//! the choice so a replay must make it too.

use super::*;
#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;

/// Name prefix of the inert entries that size the initial stack. Like the
/// envp slots, the shim never exposes them to the guest.
const PAD_PREFIX: &str = "_PATINA_PAD_";
/// Environment entries the control plane and the padding share: the
/// control plane's own entries, then as many padding entries as fill it.
const RESERVED_ENTRIES: usize = 256;
/// Bytes of initial-stack strings the control plane and the padding share,
/// on top of what every mode of the run shares.
const RESERVED_BYTES: usize = 256 << 10;
/// The largest padding value, well inside Linux's `MAX_ARG_STRLEN`.
const PAD_VALUE_MAX: usize = 64 << 10;

/// Pin the address layout `command` gives its guest, or, when
/// `allow_randomized`, leave the host's randomization on, pad nothing, and
/// say so to the shim. Call it last, once every argument and environment entry is in place:
/// `invariant_prefix` names the entries every mode of the run sets identically
/// (the envp slots), and `guest_payload` is the size of the run's environment
/// map and arguments as the control plane carries them.
pub(super) fn pin(
    command: &mut Command,
    argv0: &str,
    invariant_prefix: &str,
    guest_payload: usize,
    allow_randomized: bool,
) -> Result<(), CliError> {
    if allow_randomized {
        // The padding exists only to hold a fixed layout still; a randomized
        // one has nothing to hold, and the padding would only spend the
        // argument space a small inherited stack limit leaves.
        command.env(patina_dst_runtime::ENV_ADDRESS_LAYOUT, "randomized");
        return Ok(());
    }
    command.env(patina_dst_runtime::ENV_ADDRESS_LAYOUT, "fixed");
    pad_initial_stack(command, invariant_prefix, guest_payload)?;
    disable_randomization(command, argv0)
}

/// The qualification a run with `--allow-randomized-address-layout` carries,
/// on stderr and in the result envelope.
pub(super) const RANDOMIZED_QUALIFICATION: &str = "this run keeps the host's address-space \
randomization (--allow-randomized-address-layout): the guest's code, stack, heap and mapping \
addresses are the host's, not a function of the seed, so a guest whose behaviour depends on a \
pointer can differ between runs of one seed and between a recording and its replay. This run's \
determinism is NOT guaranteed and any \"deterministic\" claim on it is qualified.";

/// Bytes a C string occupies on the initial stack.
fn c_len(text: &OsStr) -> usize {
    text.len() + 1
}

/// Size the control plane's share of the initial stack to exactly
/// [`RESERVED_ENTRIES`] entries and `guest_payload + RESERVED_BYTES` bytes.
/// The arguments and the invariant entries are the same in every mode, so
/// with the share fixed the kernel places the stack, and every pointer and
/// string on it, at the same address.
fn pad_initial_stack(
    command: &mut Command,
    invariant_prefix: &str,
    guest_payload: usize,
) -> Result<(), CliError> {
    // The kernel copies the exec'd path too (Linux `AT_EXECFN`, Darwin's
    // `executable_path`), and that path is host state.
    let mut control = c_len(command.get_program());
    let mut control_entries = 0;
    for (name, value) in command.get_envs() {
        if let Some(value) = value
            && !name.as_bytes().starts_with(invariant_prefix.as_bytes())
        {
            control += name.len() + 1 + c_len(value);
            control_entries += 1;
        }
    }
    let entries = RESERVED_ENTRIES.saturating_sub(control_entries);
    let name_bytes = PAD_PREFIX.len() + 3 + 2;
    let budget = guest_payload + RESERVED_BYTES;
    let values = budget
        .checked_sub(control + entries * name_bytes)
        .filter(|values| entries > 0 && *values <= entries * PAD_VALUE_MAX);
    let Some(mut values) = values else {
        return Err(CliError(format!(
            "cannot size the native guest's initial stack for the fixed address layout: the \
control plane takes {control_entries} environment entries and {control} bytes, against the \
{RESERVED_ENTRIES} entries and {budget} bytes reserved for it and its padding"
        )));
    };
    for index in 0..entries {
        let length = values.min(PAD_VALUE_MAX);
        values -= length;
        command.env(format!("{PAD_PREFIX}{index:03}"), "x".repeat(length));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;

    pub(super) const ADDR_NO_RANDOMIZE: u64 = 0x0040000;
    const QUERY: u64 = 0xffff_ffff;
    const RLIMIT_STACK: i32 = 3;

    #[repr(C)]
    pub(super) struct Rlimit {
        pub(super) current: u64,
        pub(super) maximum: u64,
    }

    unsafe extern "C" {
        fn personality(persona: u64) -> i32;
        fn getrlimit(resource: i32, limit: *mut Rlimit) -> i32;
        fn setrlimit(resource: i32, limit: *const Rlimit) -> i32;
    }

    fn check(rc: i32) -> io::Result<i32> {
        if rc == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    /// The calling thread's persona.
    pub(super) fn persona() -> io::Result<u64> {
        // SAFETY: the query persona changes nothing.
        check(unsafe { personality(QUERY) }).map(|persona| persona as u32 as u64)
    }

    /// Set the calling thread's persona and read it back: a persona the
    /// kernel does not take returns success and leaves the old one.
    pub(super) fn set_persona(persona: u64) -> io::Result<()> {
        // SAFETY: personality only changes this thread's execution domain.
        check(unsafe { personality(persona) })?;
        if self::persona()? == persona {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(1))
        }
    }

    pub(super) fn stack_limit() -> io::Result<Rlimit> {
        let mut limit = Rlimit {
            current: 0,
            maximum: 0,
        };
        // SAFETY: `limit` is a writable rlimit.
        check(unsafe { getrlimit(RLIMIT_STACK, &mut limit) })?;
        Ok(limit)
    }

    pub(super) fn set_stack_limit(limit: &Rlimit) -> io::Result<()> {
        // SAFETY: `limit` is a readable rlimit.
        check(unsafe { setrlimit(RLIMIT_STACK, limit) }).map(drop)
    }
}

/// Exec the guest with randomization off and the modeled stack limit. The
/// supervisor proves first, on its own thread, that the host lets it, so a
/// refusal is named here rather than surfacing as a bare spawn errno.
#[cfg(target_os = "linux")]
fn disable_randomization(command: &mut Command, _argv0: &str) -> Result<(), CliError> {
    use linux::*;
    let refused = |what: &str, error: io::Error| {
        CliError(format!(
            "cannot pin the native guest's address layout: {what} failed ({error}). Patina runs \
every native guest with address-space randomization off so the same seed gives the same \
addresses; a host or container that forbids it (a seccomp profile that refuses this \
personality, for example) cannot run native guests deterministically. Pass \
--allow-randomized-address-layout to run with the host's layout and qualified determinism"
        ))
    };
    let current = persona().map_err(|error| refused("personality query", error))?;
    // The persona is per thread and is inherited, not shared: setting and
    // restoring it here leaves the supervisor's other threads untouched.
    set_persona(current | ADDR_NO_RANDOMIZE)
        .and_then(|()| set_persona(current))
        .map_err(|error| refused("personality(ADDR_NO_RANDOMIZE)", error))?;
    let modeled = patina_dst_abi::STACK_SOFT_LIMIT;
    let limit = stack_limit().map_err(|error| refused("getrlimit(RLIMIT_STACK)", error))?;
    if limit.maximum < modeled {
        return Err(refused(
            "raising the soft RLIMIT_STACK to the modeled 8 MiB",
            io::Error::other(format!("the hard limit is {} bytes", limit.maximum)),
        ));
    }
    let pinned = Rlimit {
        current: modeled,
        maximum: limit.maximum,
    };
    // SAFETY: the hook runs in the forked child before exec and makes only
    // async-signal-safe system calls, allocating nothing.
    unsafe {
        command.pre_exec(move || {
            set_persona(persona()? | ADDR_NO_RANDOMIZE)?;
            set_stack_limit(&pinned)
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod darwin {
    use std::ffi::{c_char, c_int, c_short, c_void};

    pub(super) const POSIX_SPAWN_SETEXEC: c_short = 0x0040;
    pub(super) const POSIX_SPAWN_DISABLE_ASLR: c_short = 0x0100;

    unsafe extern "C" {
        pub(super) fn posix_spawnattr_init(attr: *mut *mut c_void) -> c_int;
        pub(super) fn posix_spawnattr_setflags(attr: *mut *mut c_void, flags: c_short) -> c_int;
        pub(super) fn posix_spawnattr_destroy(attr: *mut *mut c_void) -> c_int;
        pub(super) fn posix_spawn(
            pid: *mut c_int,
            path: *const c_char,
            actions: *const c_void,
            attr: *const *mut c_void,
            argv: *const *const c_char,
            envp: *const *const c_char,
        ) -> c_int;
    }

    /// The exec the forked child performs instead of std's: `posix_spawn`
    /// with `POSIX_SPAWN_SETEXEC` replaces the calling image like `execve`,
    /// and carries the one attribute `execve` cannot, ASLR off.
    pub(super) struct SpawnExec {
        pub(super) attr: *mut c_void,
        pub(super) path: std::ffi::CString,
        /// The argument and environment strings the pointer arrays name.
        pub(super) _strings: [Vec<std::ffi::CString>; 2],
        pub(super) argv_ptrs: Vec<*const c_char>,
        pub(super) envp_ptrs: Vec<*const c_char>,
    }

    // SAFETY: the pointers name the owned strings and spawn attributes,
    // which only the forked child reads.
    unsafe impl Send for SpawnExec {}
    // SAFETY: as above; nothing mutates them after construction.
    unsafe impl Sync for SpawnExec {}

    impl Drop for SpawnExec {
        fn drop(&mut self) {
            // SAFETY: `attr` was initialized by `posix_spawnattr_init`.
            unsafe { posix_spawnattr_destroy(&mut self.attr) };
        }
    }
}

/// Exec the guest through `posix_spawn(POSIX_SPAWN_SETEXEC |
/// _POSIX_SPAWN_DISABLE_ASLR)` from std's forked child, after std has set up
/// its descriptors. std's own exec never runs: a successful spawn replaces
/// the image, and a failed one is the spawn's error.
#[cfg(target_os = "macos")]
fn disable_randomization(command: &mut Command, argv0: &str) -> Result<(), CliError> {
    use darwin::*;
    let c_string = |text: &OsStr| {
        CString::new(text.as_bytes()).map_err(|_| {
            CliError(format!(
                "cannot exec the native guest with {text:?}: it holds a NUL"
            ))
        })
    };
    let path = c_string(command.get_program())?;
    let argv = std::iter::once(OsStr::new(argv0))
        .chain(command.get_args())
        .map(c_string)
        .collect::<Result<Vec<_>, _>>()?;
    // `env_clear` leaves exactly the entries set since, in std's own order.
    let envp = command
        .get_envs()
        .filter_map(|(name, value)| value.map(|value| (name, value)))
        .map(|(name, value)| {
            let mut entry = name.to_owned();
            entry.push("=");
            entry.push(value);
            c_string(&entry)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut attr = std::ptr::null_mut();
    // SAFETY: `attr` is a writable attribute handle, initialized before use.
    let rc = unsafe {
        match posix_spawnattr_init(&mut attr) {
            0 => {
                posix_spawnattr_setflags(&mut attr, POSIX_SPAWN_SETEXEC | POSIX_SPAWN_DISABLE_ASLR)
            }
            rc => rc,
        }
    };
    if rc != 0 {
        return Err(CliError(format!(
            "cannot pin the native guest's address layout: posix_spawnattr failed ({})",
            io::Error::from_raw_os_error(rc)
        )));
    }
    let terminated = |strings: &[CString]| {
        strings
            .iter()
            .map(|string| string.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect::<Vec<_>>()
    };
    let exec = SpawnExec {
        attr,
        argv_ptrs: terminated(&argv),
        envp_ptrs: terminated(&envp),
        path,
        _strings: [argv, envp],
    };
    // SAFETY: the hook runs in the forked child before exec; `posix_spawn`
    // is the `__posix_spawn` system call over memory prepared here.
    unsafe {
        command.pre_exec(move || {
            let rc = posix_spawn(
                std::ptr::null_mut(),
                exec.path.as_ptr(),
                std::ptr::null(),
                &exec.attr,
                exec.argv_ptrs.as_ptr(),
                exec.envp_ptrs.as_ptr(),
            );
            Err(io::Error::from_raw_os_error(rc))
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the kernel copies onto the initial stack: the bytes of the exec'd
    /// path, the arguments and the environment, and the pointers to them.
    fn initial_stack(command: &Command) -> (usize, usize) {
        let environment: Vec<_> = command
            .get_envs()
            .filter_map(|(name, value)| value.map(|value| name.len() + 1 + c_len(value)))
            .collect();
        let bytes = c_len(command.get_program())
            + command.get_args().map(c_len).sum::<usize>()
            + environment.iter().sum::<usize>();
        (bytes, command.get_args().count() + environment.len())
    }

    fn launch(program: &str, control: &[(&str, &str)]) -> Command {
        let mut command = Command::new(program);
        command.args(["guest", "arguments"]).env_clear();
        for slot in 0..3 {
            command.env(format!("{ENVP_SLOT_PREFIX}{slot}"), "");
        }
        command.envs(control.iter().copied());
        command
    }

    #[test]
    fn the_control_plane_never_resizes_the_initial_stack() {
        let mut seeded = launch(
            "/a/guest",
            &[("PATINA_MODE", "seeded"), ("PATINA_SEED", "1")],
        );
        let mut recorded = launch(
            "/a/longer/checkout/guest",
            &[
                ("PATINA_MODE", "record"),
                ("PATINA_SEED", "1"),
                ("PATINA_TRACE_FD", "11"),
                ("PATINA_FINGERPRINT", "native-boundary-v1"),
            ],
        );
        assert_ne!(initial_stack(&seeded), initial_stack(&recorded));
        for command in [&mut seeded, &mut recorded] {
            pad_initial_stack(command, ENVP_SLOT_PREFIX, 100).unwrap();
        }
        assert_eq!(initial_stack(&seeded), initial_stack(&recorded));
    }

    #[test]
    fn a_control_plane_past_the_reservation_is_refused() {
        let mut command = launch(
            "/guest",
            &[("PATINA_PARAMS_JSON", &"x".repeat(RESERVED_BYTES))],
        );
        assert!(pad_initial_stack(&mut command, ENVP_SLOT_PREFIX, 0).is_err());
    }
}
