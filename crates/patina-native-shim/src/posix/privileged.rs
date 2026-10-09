//! Typed libc spellings of the privileged syscall rows.
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
use crate::sud::Word;
use core::ffi::{c_char, c_int};
#[cfg(target_os = "linux")]
use core::ffi::{c_ulong, c_void};

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_mount"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn mount(
    source: *const c_char,
    target: *const c_char,
    kind: *const c_char,
    flags: c_ulong,
    data: *const c_void,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps these addresses live for the synchronous row dispatch.
    unsafe {
        crate::sud::forward(
            libc::SYS_mount,
            &[
                source.word(),
                target.word(),
                kind.word(),
                flags.word(),
                data.word(),
            ],
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_umount2"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn umount2(target: *const c_char, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps `target` live for the synchronous row dispatch.
    unsafe { crate::sud::forward(libc::SYS_umount2, &[target.word(), flags.word()]) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_pivot_root"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn pivot_root(new_root: *const c_char, put_old: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps both paths live for the synchronous row dispatch.
    unsafe { crate::sud::forward(libc::SYS_pivot_root, &[new_root.word(), put_old.word()]) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_open_tree"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn open_tree(dirfd: c_int, path: *const c_char, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps `path` live for the synchronous row dispatch.
    unsafe {
        crate::sud::forward(
            libc::SYS_open_tree,
            &[dirfd.word(), path.word(), flags.word()],
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_move_mount"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn move_mount(
    from_dirfd: c_int,
    from_path: *const c_char,
    to_dirfd: c_int,
    to_path: *const c_char,
    flags: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps both paths live for the synchronous row dispatch.
    unsafe {
        crate::sud::forward(
            libc::SYS_move_mount,
            &[
                from_dirfd.word(),
                from_path.word(),
                to_dirfd.word(),
                to_path.word(),
                flags.word(),
            ],
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_fsopen"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn fsopen(fs_name: *const c_char, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps `fs_name` live for the synchronous row dispatch.
    unsafe { crate::sud::forward(libc::SYS_fsopen, &[fs_name.word(), flags.word()]) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_fsconfig"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn fsconfig(
    fd: c_int,
    cmd: u32,
    key: *const c_char,
    value: *const c_void,
    aux: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps the pointer operands live for the synchronous row dispatch.
    unsafe {
        crate::sud::forward(
            libc::SYS_fsconfig,
            &[fd.word(), cmd.word(), key.word(), value.word(), aux.word()],
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_fsmount"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn fsmount(fd: c_int, flags: u32, attr_flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: This row has no pointer operands, so `forward`'s pointer precondition is vacuous.
    unsafe {
        crate::sud::forward(
            libc::SYS_fsmount,
            &[fd.word(), flags.word(), attr_flags.word()],
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_fspick"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn fspick(dirfd: c_int, path: *const c_char, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps `path` live for the synchronous row dispatch.
    unsafe { crate::sud::forward(libc::SYS_fspick, &[dirfd.word(), path.word(), flags.word()]) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_mount_setattr"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn mount_setattr(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    attr: *mut c_void,
    size: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps `path` and `attr` live for the synchronous row dispatch.
    unsafe {
        crate::sud::forward(
            libc::SYS_mount_setattr,
            &[
                dirfd.word(),
                path.word(),
                flags.word(),
                attr.word(),
                size.word(),
            ],
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_acct"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn acct(path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps `path` live for the synchronous row dispatch.
    unsafe { crate::sud::forward(libc::SYS_acct, &[path.word()]) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_vhangup"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn vhangup() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: This row has no pointer operands, so `forward`'s pointer precondition is vacuous.
    unsafe { crate::sud::forward(libc::SYS_vhangup, &[]) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_swapon"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn swapon(path: *const c_char, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps `path` live for the synchronous row dispatch.
    unsafe { crate::sud::forward(libc::SYS_swapon, &[path.word(), flags.word()]) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_swapoff"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn swapoff(path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps `path` live for the synchronous row dispatch.
    unsafe { crate::sud::forward(libc::SYS_swapoff, &[path.word()]) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_reboot"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn reboot(howto: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: This row has no pointer operands, so `forward`'s pointer precondition is vacuous.
    unsafe {
        crate::sud::forward(
            libc::SYS_reboot,
            &[0xfee1dead_u64, 672274793_u64, howto.word()],
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_init_module"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn init_module(
    image: *mut c_void,
    length: c_ulong,
    params: *const c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps `image` and `params` live for the synchronous row dispatch.
    unsafe {
        crate::sud::forward(
            libc::SYS_init_module,
            &[image.word(), length.word(), params.word()],
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_delete_module"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn delete_module(name: *const c_char, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps `name` live for the synchronous row dispatch.
    unsafe { crate::sud::forward(libc::SYS_delete_module, &[name.word(), flags.word()]) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_quotactl"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn quotactl(
    cmd: c_int,
    special: *const c_char,
    id: c_int,
    addr: *mut c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps `special` and `addr` live for the synchronous row dispatch.
    unsafe {
        crate::sud::forward(
            libc::SYS_quotactl,
            &[cmd.word(), special.word(), id.word(), addr.word()],
        )
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_iopl"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn iopl(level: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: This row has no pointer operands, so `forward`'s pointer precondition is vacuous.
    unsafe { crate::sud::forward(libc::SYS_iopl, &[level.word()]) }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_ioperm"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn ioperm(from: c_ulong, count: c_ulong, turn_on: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: This row has no pointer operands, so `forward`'s pointer precondition is vacuous.
    unsafe {
        crate::sud::forward(
            libc::SYS_ioperm,
            &[from.word(), count.word(), turn_on.word()],
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_unshare"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn unshare(flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: This row has no pointer operands, so `forward`'s pointer precondition is vacuous.
    unsafe { crate::sud::forward(libc::SYS_unshare, &[flags.word()]) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_setns"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn setns(fd: c_int, nstype: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: This row has no pointer operands, so `forward`'s pointer precondition is vacuous.
    unsafe { crate::sud::forward(libc::SYS_setns, &[fd.word(), nstype.word()]) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_chroot"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn chroot(path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The caller's guest-pointer contract keeps `path` live for the synchronous row dispatch.
    unsafe { crate::sud::forward(libc::SYS_chroot, &[path.word()]) }
}

#[cfg(target_os = "macos")]
/// # Safety
/// Pointer arguments are guest addresses imported by the modeled syscall.
#[unsafe(no_mangle)]
unsafe extern "C" fn chroot(path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let _ = path;
    super::error(libc::EPERM)
}
