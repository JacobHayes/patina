//! Typed libc spellings of the privileged syscall rows.
use core::ffi::{c_char, c_int};
#[cfg(target_os = "linux")]
use core::ffi::{c_ulong, c_void};

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mount(
    source: *const c_char,
    target: *const c_char,
    kind: *const c_char,
    flags: c_ulong,
    data: *const c_void,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_mount,
            source as u64,
            target as u64,
            kind as u64,
            flags,
            data as u64,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn umount2(target: *const c_char, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_umount2,
            target as u64,
            flags as i64 as u64,
            0,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pivot_root(new_root: *const c_char, put_old: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_pivot_root,
            new_root as u64,
            put_old as u64,
            0,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn open_tree(dirfd: c_int, path: *const c_char, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_open_tree,
            dirfd as i64 as u64,
            path as u64,
            flags as u64,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn move_mount(
    from_dirfd: c_int,
    from_path: *const c_char,
    to_dirfd: c_int,
    to_path: *const c_char,
    flags: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_move_mount,
            from_dirfd as i64 as u64,
            from_path as u64,
            to_dirfd as i64 as u64,
            to_path as u64,
            flags as u64,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsopen(fs_name: *const c_char, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_fsopen,
            fs_name as u64,
            flags as u64,
            0,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsconfig(
    fd: c_int,
    cmd: u32,
    key: *const c_char,
    value: *const c_void,
    aux: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_fsconfig,
            fd as i64 as u64,
            cmd as u64,
            key as u64,
            value as u64,
            aux as i64 as u64,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsmount(fd: c_int, flags: u32, attr_flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_fsmount,
            fd as i64 as u64,
            flags as u64,
            attr_flags as u64,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fspick(dirfd: c_int, path: *const c_char, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_fspick,
            dirfd as i64 as u64,
            path as u64,
            flags as u64,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mount_setattr(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    attr: *mut c_void,
    size: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_mount_setattr,
            dirfd as i64 as u64,
            path as u64,
            flags as u64,
            attr as u64,
            size as u64,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn acct(path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(libc::SYS_acct, path as u64, 0, 0, 0, 0, 0, 0)
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vhangup() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(libc::SYS_vhangup, 0, 0, 0, 0, 0, 0, 0)
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn swapon(path: *const c_char, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_swapon,
            path as u64,
            flags as i64 as u64,
            0,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn swapoff(path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(libc::SYS_swapoff, path as u64, 0, 0, 0, 0, 0, 0)
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reboot(howto: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_reboot,
            0xfee1dead,
            672274793,
            howto as i64 as u64,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn init_module(
    image: *mut c_void,
    length: c_ulong,
    params: *const c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_init_module,
            image as u64,
            length,
            params as u64,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn delete_module(name: *const c_char, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_delete_module,
            name as u64,
            flags as u64,
            0,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quotactl(
    cmd: c_int,
    special: *const c_char,
    id: c_int,
    addr: *mut c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_quotactl,
            cmd as i64 as u64,
            special as u64,
            id as i64 as u64,
            addr as u64,
            0,
            0,
            0,
        )
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iopl(level: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(libc::SYS_iopl, level as i64 as u64, 0, 0, 0, 0, 0, 0)
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ioperm(from: c_ulong, count: c_ulong, turn_on: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_ioperm,
            from,
            count,
            turn_on as i64 as u64,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unshare(flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(libc::SYS_unshare, flags as i64 as u64, 0, 0, 0, 0, 0, 0)
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setns(fd: c_int, nstype: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_setns,
            fd as i64 as u64,
            nstype as i64 as u64,
            0,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chroot(path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(libc::SYS_chroot, path as u64, 0, 0, 0, 0, 0, 0)
    })
}

#[cfg(target_os = "macos")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chroot(path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let _ = path;
    super::error(libc::EPERM)
}
