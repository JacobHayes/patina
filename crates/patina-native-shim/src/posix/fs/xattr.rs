//! Linux xattr adapters use the model's shared path/link/descriptor selectors.
use super::*;
use crate::xattr::{XATTR_BY_FD, XATTR_BY_LINK, XATTR_BY_PATH};
use core::{ffi::c_void, ptr};

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        model_result(crate::xattr::patina_setxattr(
            -1,
            path,
            XATTR_BY_PATH,
            name,
            value,
            size,
            flags,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lsetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        model_result(crate::xattr::patina_setxattr(
            -1,
            path,
            XATTR_BY_LINK,
            name,
            value,
            size,
            flags,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsetxattr(
    fd: c_int,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        model_result(crate::xattr::patina_setxattr(
            fd,
            ptr::null(),
            XATTR_BY_FD,
            name,
            value,
            size,
            flags,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        size_result(crate::xattr::patina_getxattr(
            -1,
            path,
            XATTR_BY_PATH,
            name,
            value,
            size,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lgetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        size_result(crate::xattr::patina_getxattr(
            -1,
            path,
            XATTR_BY_LINK,
            name,
            value,
            size,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fgetxattr(
    fd: c_int,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        size_result(crate::xattr::patina_getxattr(
            fd,
            ptr::null(),
            XATTR_BY_FD,
            name,
            value,
            size,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn listxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        size_result(crate::xattr::patina_listxattr(
            -1,
            path,
            XATTR_BY_PATH,
            list.cast(),
            size,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        size_result(crate::xattr::patina_listxattr(
            -1,
            path,
            XATTR_BY_LINK,
            list.cast(),
            size,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flistxattr(fd: c_int, list: *mut c_char, size: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        size_result(crate::xattr::patina_listxattr(
            fd,
            ptr::null(),
            XATTR_BY_FD,
            list.cast(),
            size,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn removexattr(path: *const c_char, name: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        model_result(crate::xattr::patina_removexattr(
            -1,
            path,
            XATTR_BY_PATH,
            name,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lremovexattr(path: *const c_char, name: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        model_result(crate::xattr::patina_removexattr(
            -1,
            path,
            XATTR_BY_LINK,
            name,
        ))
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fremovexattr(fd: c_int, name: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        model_result(crate::xattr::patina_removexattr(
            fd,
            ptr::null(),
            XATTR_BY_FD,
            name,
        ))
    }
}
