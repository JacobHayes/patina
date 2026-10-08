//! Linux xattr adapters use the model's shared path/link/descriptor selectors.
#![deny(clippy::undocumented_unsafe_blocks)]

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
    // SAFETY: the libc caller satisfies setxattr's pointer contract.
    crate::abi::libc_result(
        unsafe { crate::xattr::setxattr(-1, path, XATTR_BY_PATH, name, value, size, flags) },
        -1,
    )
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
    // SAFETY: the libc caller satisfies lsetxattr's pointer contract.
    crate::abi::libc_result(
        unsafe { crate::xattr::setxattr(-1, path, XATTR_BY_LINK, name, value, size, flags) },
        -1,
    )
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
    // SAFETY: the libc caller satisfies fsetxattr's name/value contract.
    crate::abi::libc_result(
        unsafe { crate::xattr::setxattr(fd, ptr::null(), XATTR_BY_FD, name, value, size, flags) },
        -1,
    )
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
    // SAFETY: the libc caller satisfies getxattr's pointer contract.
    crate::abi::libc_result(
        unsafe { crate::xattr::getxattr(-1, path, XATTR_BY_PATH, name, value, size) },
        -1,
    )
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
    // SAFETY: the libc caller satisfies lgetxattr's pointer contract.
    crate::abi::libc_result(
        unsafe { crate::xattr::getxattr(-1, path, XATTR_BY_LINK, name, value, size) },
        -1,
    )
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
    // SAFETY: the libc caller satisfies fgetxattr's name/value contract.
    crate::abi::libc_result(
        unsafe { crate::xattr::getxattr(fd, ptr::null(), XATTR_BY_FD, name, value, size) },
        -1,
    )
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn listxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the libc caller satisfies listxattr's pointer contract.
    crate::abi::libc_result(
        unsafe { crate::xattr::listxattr(-1, path, XATTR_BY_PATH, list.cast(), size) },
        -1,
    )
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the libc caller satisfies llistxattr's pointer contract.
    crate::abi::libc_result(
        unsafe { crate::xattr::listxattr(-1, path, XATTR_BY_LINK, list.cast(), size) },
        -1,
    )
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flistxattr(fd: c_int, list: *mut c_char, size: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the libc caller satisfies flistxattr's list contract.
    crate::abi::libc_result(
        unsafe { crate::xattr::listxattr(fd, ptr::null(), XATTR_BY_FD, list.cast(), size) },
        -1,
    )
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn removexattr(path: *const c_char, name: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the libc caller satisfies removexattr's string contract.
    crate::abi::libc_result(
        unsafe { crate::xattr::removexattr(-1, path, XATTR_BY_PATH, name) },
        -1,
    )
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lremovexattr(path: *const c_char, name: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the libc caller satisfies lremovexattr's string contract.
    crate::abi::libc_result(
        unsafe { crate::xattr::removexattr(-1, path, XATTR_BY_LINK, name) },
        -1,
    )
}

/// # Safety
/// Guest pointers obey the corresponding libc xattr contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fremovexattr(fd: c_int, name: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the libc caller satisfies fremovexattr's name contract.
    crate::abi::libc_result(
        unsafe { crate::xattr::removexattr(fd, ptr::null(), XATTR_BY_FD, name) },
        -1,
    )
}
