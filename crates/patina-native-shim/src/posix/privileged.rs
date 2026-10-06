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

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_mount",
    ".hidden patina_route_mount",
    ".set patina_route_mount, mount"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_umount2",
    ".hidden patina_route_umount2",
    ".set patina_route_umount2, umount2"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_pivot_root",
    ".hidden patina_route_pivot_root",
    ".set patina_route_pivot_root, pivot_root"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_open_tree",
    ".hidden patina_route_open_tree",
    ".set patina_route_open_tree, open_tree"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_move_mount",
    ".hidden patina_route_move_mount",
    ".set patina_route_move_mount, move_mount"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_fsopen",
    ".hidden patina_route_fsopen",
    ".set patina_route_fsopen, fsopen"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_fsconfig",
    ".hidden patina_route_fsconfig",
    ".set patina_route_fsconfig, fsconfig"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_fsmount",
    ".hidden patina_route_fsmount",
    ".set patina_route_fsmount, fsmount"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_fspick",
    ".hidden patina_route_fspick",
    ".set patina_route_fspick, fspick"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_mount_setattr",
    ".hidden patina_route_mount_setattr",
    ".set patina_route_mount_setattr, mount_setattr"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_acct",
    ".hidden patina_route_acct",
    ".set patina_route_acct, acct"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_vhangup",
    ".hidden patina_route_vhangup",
    ".set patina_route_vhangup, vhangup"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_swapon",
    ".hidden patina_route_swapon",
    ".set patina_route_swapon, swapon"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_swapoff",
    ".hidden patina_route_swapoff",
    ".set patina_route_swapoff, swapoff"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_reboot",
    ".hidden patina_route_reboot",
    ".set patina_route_reboot, reboot"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_init_module",
    ".hidden patina_route_init_module",
    ".set patina_route_init_module, init_module"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_delete_module",
    ".hidden patina_route_delete_module",
    ".set patina_route_delete_module, delete_module"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_quotactl",
    ".hidden patina_route_quotactl",
    ".set patina_route_quotactl, quotactl"
);
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
core::arch::global_asm!(
    ".globl patina_route_iopl",
    ".hidden patina_route_iopl",
    ".set patina_route_iopl, iopl"
);
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
core::arch::global_asm!(
    ".globl patina_route_ioperm",
    ".hidden patina_route_ioperm",
    ".set patina_route_ioperm, ioperm"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_unshare",
    ".hidden patina_route_unshare",
    ".set patina_route_unshare, unshare"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_setns",
    ".hidden patina_route_setns",
    ".set patina_route_setns, setns"
);
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_chroot",
    ".hidden patina_route_chroot",
    ".set patina_route_chroot, chroot"
);
