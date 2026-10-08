//! Paths, namespace operations, fixed open and fortify entries.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
use core::ptr;

use crate::variadic::open::patina_openat_impl;

/// # Safety
/// Guest pointers obey the corresponding libc buffer/string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getcwd(destination: *mut c_char, length: usize) -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        if !destination.is_null() && length == 0 {
            error(libc::EINVAL);
            return ptr::null_mut();
        }
        let mut current = [0 as c_char; libc::PATH_MAX as usize];
        let needed = crate::patina_getcwd(current.as_mut_ptr(), current.len());
        if needed < 0 {
            error(crate::patina_errno());
            return ptr::null_mut();
        }
        let bytes = needed as usize + 1;
        if destination.is_null() {
            let allocate = if length == 0 { bytes } else { length };
            if allocate < bytes {
                error(libc::ERANGE);
                return ptr::null_mut();
            }
            let owned = libc::malloc(allocate).cast::<c_char>();
            if owned.is_null() {
                error(libc::ENOMEM);
                return ptr::null_mut();
            }
            ptr::copy_nonoverlapping(current.as_ptr(), owned, bytes);
            return owned;
        }
        if length < bytes {
            error(libc::ERANGE);
            return ptr::null_mut();
        }
        ptr::copy_nonoverlapping(current.as_ptr(), destination, bytes);
        destination
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc buffer/string contract.
// _DARWIN_C_SOURCE exports the allocating extended ABI, not the legacy name.
#[cfg_attr(target_os = "linux", unsafe(no_mangle))]
#[cfg_attr(target_os = "macos", unsafe(export_name = "realpath$DARWIN_EXTSN"))]
pub unsafe extern "C" fn realpath(path: *const c_char, destination: *mut c_char) -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        let mut resolved = [0 as c_char; libc::PATH_MAX as usize];
        let mut kind = 0;
        let length = crate::patina_resolve_path(
            AT_FDCWD,
            path,
            0,
            resolved.as_mut_ptr(),
            resolved.len(),
            &mut kind,
        );
        if length < 0 {
            error(crate::patina_errno());
            return ptr::null_mut();
        }
        if kind == 0 {
            error(libc::ENOENT);
            return ptr::null_mut();
        }
        let bytes = length as usize + 1;
        let out = if destination.is_null() {
            let owned = libc::malloc(bytes).cast::<c_char>();
            if owned.is_null() {
                error(libc::ENOMEM);
                return ptr::null_mut();
            }
            owned
        } else {
            destination
        };
        ptr::copy_nonoverlapping(resolved.as_ptr(), out, bytes);
        out
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn creat(path: *const c_char, mode: libc::mode_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"creat");
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        patina_openat_impl(
            libc::AT_FDCWD,
            path,
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            mode as libc::c_uint,
        )
    }
}

#[cfg(target_os = "linux")]
unsafe fn open_fixed(
    directory: c_int,
    path: *const c_char,
    flags: c_int,
    name: &core::ffi::CStr,
) -> c_int {
    if flags & libc::O_CREAT != 0 || flags & libc::O_TMPFILE == libc::O_TMPFILE {
        super::super::fortify_fail(name);
    }
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { patina_openat_impl(directory, path, flags, 0) }
}

/// # Safety
/// Guest pointers obey the corresponding libc string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkat(
    fromfd: c_int,
    from: *const c_char,
    tofd: c_int,
    to: *const c_char,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !libc::AT_SYMLINK_FOLLOW != 0 {
        return error(libc::EINVAL);
    }
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        model_result(crate::patina_link(
            at(fromfd),
            from,
            at(tofd),
            to,
            (flags & libc::AT_SYMLINK_FOLLOW != 0) as c_int,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlinkat(directory: c_int, path: *const c_char, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !libc::AT_REMOVEDIR != 0 {
        return error(AT_FLAG_REFUSAL);
    }
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        model_result(if flags & libc::AT_REMOVEDIR != 0 {
            crate::patina_rmdir(at(directory), path)
        } else {
            crate::patina_unlink(at(directory), path)
        })
    }
}

unsafe fn mknod_impl(
    directory: c_int,
    path: *const c_char,
    mode: libc::mode_t,
    device: libc::dev_t,
) -> c_int {
    let kernel_device = device as u32;
    if kernel_device as libc::dev_t != device {
        return error(libc::EINVAL);
    }
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        model_result(crate::patina_mknod(
            directory,
            path,
            mode as libc::c_uint,
            kernel_device,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chdir(path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { model_result(crate::patina_chdir(AT_FDCWD, path)) }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fchdir(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    model_result(crate::patina_fchdir(fd))
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn umask(mask: libc::mode_t) -> libc::mode_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_umask(mask as libc::c_uint) as libc::mode_t
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symlink(target: *const c_char, link_path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { model_result(crate::patina_symlink(target, AT_FDCWD, link_path)) }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symlinkat(
    target: *const c_char,
    directory: c_int,
    link_path: *const c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { model_result(crate::patina_symlink(target, at(directory), link_path)) }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn readlink(
    path: *const c_char,
    destination: *mut c_char,
    length: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the libc caller provides a readable path and writable buffer per
    // readlink's contract.
    crate::abi::libc_result(
        unsafe { crate::fs::read_link(AT_FDCWD, path, destination, length) },
        -1,
    )
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn readlinkat(
    directory: c_int,
    path: *const c_char,
    destination: *mut c_char,
    length: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the libc caller provides a readable path and writable buffer per
    // readlinkat's contract.
    crate::abi::libc_result(
        unsafe { crate::fs::read_link(at(directory), path, destination, length) },
        -1,
    )
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn link(from: *const c_char, to: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { model_result(crate::patina_link(AT_FDCWD, from, AT_FDCWD, to, 0)) }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mknod(
    path: *const c_char,
    mode: libc::mode_t,
    device: libc::dev_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { mknod_impl(AT_FDCWD, path, mode, device) }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mknodat(
    directory: c_int,
    path: *const c_char,
    mode: libc::mode_t,
    device: libc::dev_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { mknod_impl(at(directory), path, mode, device) }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkfifo(path: *const c_char, mode: libc::mode_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { model_result(crate::patina_mkfifo(AT_FDCWD, path, mode as libc::c_uint)) }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkfifoat(
    directory: c_int,
    path: *const c_char,
    mode: libc::mode_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        model_result(crate::patina_mkfifo(
            at(directory),
            path,
            mode as libc::c_uint,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkdir(path: *const c_char, mode: libc::mode_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        model_result(crate::patina_mkdir(
            AT_FDCWD,
            path,
            (mode & 0o7777) as libc::c_uint,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkdirat(
    directory: c_int,
    path: *const c_char,
    mode: libc::mode_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        model_result(crate::patina_mkdir(
            at(directory),
            path,
            (mode & 0o7777) as libc::c_uint,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { model_result(crate::patina_unlink(AT_FDCWD, path)) }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { model_result(crate::patina_rmdir(AT_FDCWD, path)) }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rename(from: *const c_char, to: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { model_result(crate::patina_renameat2(AT_FDCWD, from, AT_FDCWD, to, 0)) }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn renameat(
    fromfd: c_int,
    from: *const c_char,
    tofd: c_int,
    to: *const c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { model_result(crate::patina_renameat2(at(fromfd), from, at(tofd), to, 0)) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn renameat2(
    fromfd: c_int,
    from: *const c_char,
    tofd: c_int,
    to: *const c_char,
    flags: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        model_result(crate::patina_renameat2(
            at(fromfd),
            from,
            at(tofd),
            to,
            flags,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn truncate(path: *const c_char, length: libc::off_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { model_result(crate::patina_truncate(AT_FDCWD, path, length)) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn truncate64(path: *const c_char, length: libc::off64_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe { model_result(crate::patina_truncate(AT_FDCWD, path, length)) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers obey the corresponding libc string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __open_2(path: *const c_char, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"__open_2");
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        open_fixed(
            libc::AT_FDCWD,
            path,
            flags,
            c"invalid open call: O_CREAT or O_TMPFILE without mode",
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers obey the corresponding libc string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __open64_2(path: *const c_char, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"__open64_2");
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        open_fixed(
            libc::AT_FDCWD,
            path,
            flags,
            c"invalid open64 call: O_CREAT or O_TMPFILE without mode",
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers obey the corresponding libc string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __openat_2(directory: c_int, path: *const c_char, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"__openat_2");
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        open_fixed(
            directory,
            path,
            flags,
            c"invalid openat call: O_CREAT or O_TMPFILE without mode",
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers obey the corresponding libc string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __openat64_2(
    directory: c_int,
    path: *const c_char,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"__openat64_2");
    // SAFETY: The unsafe callee receives the validated operands under this libc entry’s documented contract.
    unsafe {
        open_fixed(
            directory,
            path,
            flags,
            c"invalid openat64 call: O_CREAT or O_TMPFILE without mode",
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers obey the corresponding libc string/buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __readlink_chk(
    path: *const c_char,
    destination: *mut c_char,
    length: usize,
    buflen: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if length > buflen {
        super::super::chk_fail();
    }
    // SAFETY: the libc caller provides a readable path and writable buffer per
    // readlink's contract; fortify checked the requested length above.
    crate::abi::libc_result(
        unsafe { crate::fs::read_link(AT_FDCWD, path, destination, length) },
        -1,
    )
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers obey the corresponding libc string/buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __readlinkat_chk(
    directory: c_int,
    path: *const c_char,
    destination: *mut c_char,
    length: usize,
    buflen: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if length > buflen {
        super::super::chk_fail();
    }
    // SAFETY: the libc caller provides a readable path and writable buffer per
    // readlinkat's contract; fortify checked the requested length above.
    crate::abi::libc_result(
        unsafe { crate::fs::read_link(at(directory), path, destination, length) },
        -1,
    )
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn fallocate(
    fd: c_int,
    mode: c_int,
    offset: libc::off_t,
    length: libc::off_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"fallocate");
    model_result(crate::patina_fallocate(
        fd,
        mode as libc::c_uint,
        offset,
        length,
    ))
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn fallocate64(
    fd: c_int,
    mode: c_int,
    offset: libc::off64_t,
    length: libc::off64_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"fallocate64");
    model_result(crate::patina_fallocate(
        fd,
        mode as libc::c_uint,
        offset,
        length,
    ))
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn posix_fallocate(fd: c_int, offset: libc::off_t, length: libc::off_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if crate::patina_fallocate(fd, 0, offset, length) < 0 {
        crate::patina_errno()
    } else {
        0
    }
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn posix_fallocate64(
    fd: c_int,
    offset: libc::off64_t,
    length: libc::off64_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if crate::patina_fallocate(fd, 0, offset, length) < 0 {
        crate::patina_errno()
    } else {
        0
    }
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn posix_fadvise(
    fd: c_int,
    offset: libc::off_t,
    length: libc::off_t,
    advice: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if crate::advice::patina_fadvise(fd, offset, length, advice) < 0 {
        crate::patina_errno()
    } else {
        0
    }
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn posix_fadvise64(
    fd: c_int,
    offset: libc::off64_t,
    length: libc::off64_t,
    advice: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if crate::advice::patina_fadvise(fd, offset, length, advice) < 0 {
        crate::patina_errno()
    } else {
        0
    }
}
