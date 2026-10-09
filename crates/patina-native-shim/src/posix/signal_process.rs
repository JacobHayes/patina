//! Ordinary process and signal ABI adapters. Callback frames remain in init.c.
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
use crate::sud::Word;
use core::ffi::{CStr, c_char, c_int, c_short};

/// # Safety
/// Termination follows libc's process and destructor contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn exit(status: c_int) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_exit(status)
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_raise"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
extern "C" fn raise(sig: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        if crate::thread::signals::patina_signal_reserved(sig) != 0 {
            return super::error(libc::EINVAL);
        }
        // SAFETY: tgkill receives only the shim's process/thread IDs and the scalar signal number.
        unsafe {
            crate::sud::forward(
                libc::SYS_tgkill,
                &[
                    crate::patina_pid().word(),
                    crate::patina_thread_id().word(),
                    sig.word(),
                ],
            )
        }
    }
    #[cfg(target_os = "macos")]
    {
        super::model_result(crate::thread::signals::patina_raise(sig))
    }
}

fn process_trap(symbol: &CStr) -> ! {
    let prefix = b"patina: process spawn reached under patina: ";
    let suffix = b"; the process class is a deterministic-runtime non-goal; failing closed\n";
    // SAFETY: each byte slice is a live read-only buffer for the synchronous stdio writes.
    unsafe {
        crate::patina_stdio_write(2, prefix.as_ptr().cast(), prefix.len());
        crate::patina_stdio_write(2, symbol.as_ptr().cast(), symbol.count_bytes());
        crate::patina_stdio_write(2, suffix.as_ptr().cast(), suffix.len());
    }
    crate::patina_flush_captured_stdio();
    crate::host_abort()
}

#[unsafe(no_mangle)]
extern "C" fn fork() -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"fork")
}

/// # Safety
/// file and argv follow libc's execvp argument contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn execvp(_file: *const c_char, _argv: *const *mut c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"execvp")
}

/// # Safety
/// status is null or a writable wait status buffer.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_waitpid"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn waitpid(pid: libc::pid_t, status: *mut c_int, options: c_int) -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"waitpid");
    #[cfg(target_os = "linux")]
    {
        // SAFETY: the unsafe libc entry contract supplies a writable status pointer when non-null.
        unsafe {
            crate::sud::forward(
                libc::SYS_wait4,
                &[pid.word(), status.word(), options.word()],
            )
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (pid, status, options);
        super::error(libc::ECHILD)
    }
}

#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_setsid"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
extern "C" fn setsid() -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setsid has no pointer operands.
        unsafe { crate::sud::forward(libc::SYS_setsid, &[]) }
    }
    #[cfg(target_os = "macos")]
    {
        super::error(libc::EPERM)
    }
}

#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_setgid"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
extern "C" fn setgid(gid: libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setgid forwards one scalar identifier and no pointers.
        unsafe { crate::sud::forward(libc::SYS_setgid, &[gid.word()]) }
    }
    #[cfg(target_os = "macos")]
    {
        if gid == crate::patina_gid() {
            0
        } else {
            super::error(libc::EPERM)
        }
    }
}

#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_setuid"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
extern "C" fn setuid(uid: libc::uid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setuid forwards one scalar identifier and no pointers.
        unsafe { crate::sud::forward(libc::SYS_setuid, &[uid.word()]) }
    }
    #[cfg(target_os = "macos")]
    {
        if uid == crate::patina_uid() {
            0
        } else {
            super::error(libc::EPERM)
        }
    }
}

#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_setpgid"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
extern "C" fn setpgid(pid: libc::pid_t, pgid: libc::pid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setpgid forwards two scalar identifiers and no pointers.
        unsafe { crate::sud::forward(libc::SYS_setpgid, &[pid.word(), pgid.word()]) }
    }
    #[cfg(target_os = "macos")]
    {
        if pgid < 0 {
            return super::error(libc::EINVAL);
        }
        if pid != 0 && pid != crate::patina_pid() {
            return super::error(libc::ESRCH);
        }
        if pgid != 0 && pgid != crate::patina_pid() {
            return super::error(libc::EPERM);
        }
        0
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// groups follows libc's count-element input contract.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_setgroups"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn setgroups(count: usize, groups: *const libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the unsafe libc entry contract supplies `groups` for `count` elements when used.
    unsafe { crate::sud::forward(libc::SYS_setgroups, &[count.word(), groups.word()]) }
}
#[cfg(target_os = "macos")]
/// # Safety
/// groups follows libc's count-element input contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn setgroups(_count: c_int, _groups: *const libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::error(libc::EPERM)
}

/// # Safety
/// All pointers follow libc's posix_spawnp argument contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawnp(
    _pid: *mut libc::pid_t,
    _file: *const c_char,
    _file_actions: *const libc::posix_spawn_file_actions_t,
    _attrp: *const libc::posix_spawnattr_t,
    _argv: *const *mut c_char,
    _envp: *const *mut c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawnp")
}
/// # Safety
/// acts follows libc's spawn file actions contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawn_file_actions_init(
    _acts: *mut libc::posix_spawn_file_actions_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawn_file_actions_init")
}
/// # Safety
/// acts follows libc's spawn file actions contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawn_file_actions_adddup2(
    _acts: *mut libc::posix_spawn_file_actions_t,
    _fd: c_int,
    _newfd: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawn_file_actions_adddup2")
}
/// # Safety
/// acts follows libc's spawn file actions contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawn_file_actions_destroy(
    _acts: *mut libc::posix_spawn_file_actions_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawn_file_actions_destroy")
}
/// # Safety
/// attr follows libc's spawn attributes contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawnattr_init(_attr: *mut libc::posix_spawnattr_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawnattr_init")
}
/// # Safety
/// attr follows libc's spawn attributes contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawnattr_destroy(_attr: *mut libc::posix_spawnattr_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawnattr_destroy")
}
/// # Safety
/// attr follows libc's spawn attributes contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawnattr_setflags(
    _attr: *mut libc::posix_spawnattr_t,
    _flags: c_short,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawnattr_setflags")
}
/// # Safety
/// attr follows libc's spawn attributes contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawnattr_setpgroup(
    _attr: *mut libc::posix_spawnattr_t,
    _pgroup: libc::pid_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawnattr_setpgroup")
}
/// # Safety
/// attr and sigdefault follow libc's spawn attributes contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawnattr_setsigdefault(
    _attr: *mut libc::posix_spawnattr_t,
    _sigdefault: *const libc::sigset_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawnattr_setsigdefault")
}

#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_kill"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
extern "C" fn kill(pid: libc::pid_t, sig: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        // SAFETY: kill forwards only scalar process and signal numbers.
        unsafe { crate::sud::forward(libc::SYS_kill, &[pid.word(), sig.word()]) }
    }
    #[cfg(target_os = "macos")]
    {
        if !(0..=64).contains(&sig) {
            return super::error(libc::EINVAL);
        }
        if sig == 0 && (pid == crate::patina_pid() || pid == 0 || pid == -1) {
            return 0;
        }
        if pid == crate::patina_ppid() {
            return 0;
        }
        if pid != crate::patina_pid() {
            return super::error(libc::ESRCH);
        }
        super::deny(c"patina: kill(self, signal) delivery is not modeled by the deterministic runtime; failing closed\n")
    }
}

#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
extern "C" fn pause() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"pause");
    super::error(libc::ENOSYS)
}
