//! Ordinary process and signal ABI adapters. Callback frames remain in init.c.
use core::ffi::{CStr, c_char, c_int, c_short};

#[cfg(target_os = "linux")]
unsafe fn dispatch(number: libc::c_long, args: [u64; 6]) -> c_int {
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            number, args[0], args[1], args[2], args[3], args[4], args[5], 0,
        )
    })
}

/// # Safety
/// Termination follows libc's process and destructor contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn exit(status: c_int) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_exit(status)
}

#[cfg(target_os = "linux")]
mod linux;

#[unsafe(no_mangle)]
pub extern "C" fn raise(sig: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        if crate::thread::signals::patina_signal_reserved(sig) != 0 {
            return super::error(libc::EINVAL);
        }
        unsafe {
            dispatch(
                libc::SYS_tgkill,
                [
                    crate::patina_pid() as u64,
                    crate::patina_thread_id() as u64,
                    sig as u64,
                    0,
                    0,
                    0,
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
    unsafe {
        crate::patina_stdio_write(2, prefix.as_ptr().cast(), prefix.len());
        crate::patina_stdio_write(2, symbol.as_ptr().cast(), symbol.count_bytes());
        crate::patina_stdio_write(2, suffix.as_ptr().cast(), suffix.len());
    }
    crate::patina_flush_captured_stdio();
    crate::host_abort()
}

#[unsafe(no_mangle)]
pub extern "C" fn fork() -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"fork")
}

/// # Safety
/// file and argv follow libc's execvp argument contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execvp(_file: *const c_char, _argv: *const *mut c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"execvp")
}

/// # Safety
/// status is null or a writable wait status buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn waitpid(
    pid: libc::pid_t,
    status: *mut c_int,
    options: c_int,
) -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"waitpid");
    #[cfg(target_os = "linux")]
    {
        unsafe {
            dispatch(
                libc::SYS_wait4,
                [pid as u64, status as u64, options as u64, 0, 0, 0],
            )
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (pid, status, options);
        super::error(libc::ECHILD)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn setsid() -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        unsafe { dispatch(libc::SYS_setsid, [0; 6]) }
    }
    #[cfg(target_os = "macos")]
    {
        super::error(libc::EPERM)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn setgid(gid: libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        unsafe { dispatch(libc::SYS_setgid, [gid as u64, 0, 0, 0, 0, 0]) }
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

#[unsafe(no_mangle)]
pub extern "C" fn setuid(uid: libc::uid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        unsafe { dispatch(libc::SYS_setuid, [uid as u64, 0, 0, 0, 0, 0]) }
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

#[unsafe(no_mangle)]
pub extern "C" fn setpgid(pid: libc::pid_t, pgid: libc::pid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        unsafe { dispatch(libc::SYS_setpgid, [pid as u64, pgid as u64, 0, 0, 0, 0]) }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setgroups(count: usize, groups: *const libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        dispatch(
            libc::SYS_setgroups,
            [count as u64, groups as u64, 0, 0, 0, 0],
        )
    }
}
#[cfg(target_os = "macos")]
/// # Safety
/// groups follows libc's count-element input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setgroups(_count: c_int, _groups: *const libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::error(libc::EPERM)
}

/// # Safety
/// All pointers follow libc's posix_spawnp argument contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawnp(
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
pub unsafe extern "C" fn posix_spawn_file_actions_init(
    _acts: *mut libc::posix_spawn_file_actions_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawn_file_actions_init")
}
/// # Safety
/// acts follows libc's spawn file actions contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawn_file_actions_adddup2(
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
pub unsafe extern "C" fn posix_spawn_file_actions_destroy(
    _acts: *mut libc::posix_spawn_file_actions_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawn_file_actions_destroy")
}
/// # Safety
/// attr follows libc's spawn attributes contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawnattr_init(_attr: *mut libc::posix_spawnattr_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawnattr_init")
}
/// # Safety
/// attr follows libc's spawn attributes contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawnattr_destroy(_attr: *mut libc::posix_spawnattr_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawnattr_destroy")
}
/// # Safety
/// attr follows libc's spawn attributes contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawnattr_setflags(
    _attr: *mut libc::posix_spawnattr_t,
    _flags: c_short,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawnattr_setflags")
}
/// # Safety
/// attr follows libc's spawn attributes contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawnattr_setpgroup(
    _attr: *mut libc::posix_spawnattr_t,
    _pgroup: libc::pid_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawnattr_setpgroup")
}
/// # Safety
/// attr and sigdefault follow libc's spawn attributes contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawnattr_setsigdefault(
    _attr: *mut libc::posix_spawnattr_t,
    _sigdefault: *const libc::sigset_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawnattr_setsigdefault")
}

#[unsafe(no_mangle)]
pub extern "C" fn kill(pid: libc::pid_t, sig: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        unsafe { dispatch(libc::SYS_kill, [pid as u64, sig as u64, 0, 0, 0, 0]) }
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
pub extern "C" fn pause() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"pause");
    super::error(libc::ENOSYS)
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_exit",
    ".hidden patina_route_exit",
    ".set patina_route_exit, exit",
    ".globl patina_route_raise",
    ".hidden patina_route_raise",
    ".set patina_route_raise, raise",
    ".globl patina_route_fork",
    ".hidden patina_route_fork",
    ".set patina_route_fork, fork",
    ".globl patina_route_execvp",
    ".hidden patina_route_execvp",
    ".set patina_route_execvp, execvp",
    ".globl patina_route_waitpid",
    ".hidden patina_route_waitpid",
    ".set patina_route_waitpid, waitpid",
    ".globl patina_route_setsid",
    ".hidden patina_route_setsid",
    ".set patina_route_setsid, setsid",
    ".globl patina_route_setgid",
    ".hidden patina_route_setgid",
    ".set patina_route_setgid, setgid",
    ".globl patina_route_setuid",
    ".hidden patina_route_setuid",
    ".set patina_route_setuid, setuid",
    ".globl patina_route_setpgid",
    ".hidden patina_route_setpgid",
    ".set patina_route_setpgid, setpgid",
    ".globl patina_route_setgroups",
    ".hidden patina_route_setgroups",
    ".set patina_route_setgroups, setgroups",
    ".globl patina_route_posix_spawnp",
    ".hidden patina_route_posix_spawnp",
    ".set patina_route_posix_spawnp, posix_spawnp",
    ".globl patina_route_posix_spawn_file_actions_init",
    ".hidden patina_route_posix_spawn_file_actions_init",
    ".set patina_route_posix_spawn_file_actions_init, posix_spawn_file_actions_init",
    ".globl patina_route_posix_spawn_file_actions_adddup2",
    ".hidden patina_route_posix_spawn_file_actions_adddup2",
    ".set patina_route_posix_spawn_file_actions_adddup2, posix_spawn_file_actions_adddup2",
    ".globl patina_route_posix_spawn_file_actions_destroy",
    ".hidden patina_route_posix_spawn_file_actions_destroy",
    ".set patina_route_posix_spawn_file_actions_destroy, posix_spawn_file_actions_destroy",
    ".globl patina_route_posix_spawnattr_init",
    ".hidden patina_route_posix_spawnattr_init",
    ".set patina_route_posix_spawnattr_init, posix_spawnattr_init",
    ".globl patina_route_posix_spawnattr_destroy",
    ".hidden patina_route_posix_spawnattr_destroy",
    ".set patina_route_posix_spawnattr_destroy, posix_spawnattr_destroy",
    ".globl patina_route_posix_spawnattr_setflags",
    ".hidden patina_route_posix_spawnattr_setflags",
    ".set patina_route_posix_spawnattr_setflags, posix_spawnattr_setflags",
    ".globl patina_route_posix_spawnattr_setpgroup",
    ".hidden patina_route_posix_spawnattr_setpgroup",
    ".set patina_route_posix_spawnattr_setpgroup, posix_spawnattr_setpgroup",
    ".globl patina_route_posix_spawnattr_setsigdefault",
    ".hidden patina_route_posix_spawnattr_setsigdefault",
    ".set patina_route_posix_spawnattr_setsigdefault, posix_spawnattr_setsigdefault",
    ".globl patina_route_kill",
    ".hidden patina_route_kill",
    ".set patina_route_kill, kill",
);
