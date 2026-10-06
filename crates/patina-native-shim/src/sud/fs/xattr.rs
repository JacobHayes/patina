//! Extended-attribute syscall handling.

use super::*;

// ---- extended attributes ----

/// Which node a path row names: the path, its final symlink followed or
/// not (the `l*` rows).
fn xattr_by(follow: bool) -> c_int {
    if follow {
        crate::xattr::XATTR_BY_PATH
    } else {
        crate::xattr::XATTR_BY_LINK
    }
}

pub(in crate::sud) fn sys_getxattr(
    path: u64,
    name: u64,
    value: u64,
    size: u64,
    follow: bool,
) -> i64 {
    // SAFETY: guest pointers per the getxattr(2) contract.
    ret_isize(unsafe {
        patina_getxattr(
            -1,
            path as *const c_char,
            xattr_by(follow),
            name as *const c_char,
            value as *mut c_void,
            size as usize,
        )
    })
}

pub(in crate::sud) fn sys_fgetxattr(fd: i64, name: u64, value: u64, size: u64) -> i64 {
    // SAFETY: guest pointers per the fgetxattr(2) contract.
    ret_isize(unsafe {
        patina_getxattr(
            fd as c_int,
            std::ptr::null(),
            crate::xattr::XATTR_BY_FD,
            name as *const c_char,
            value as *mut c_void,
            size as usize,
        )
    })
}

pub(in crate::sud) fn sys_listxattr(path: u64, list: u64, size: u64, follow: bool) -> i64 {
    // SAFETY: guest pointers per the listxattr(2) contract.
    ret_isize(unsafe {
        patina_listxattr(
            -1,
            path as *const c_char,
            xattr_by(follow),
            list as *mut c_void,
            size as usize,
        )
    })
}

pub(in crate::sud) fn sys_flistxattr(fd: i64, list: u64, size: u64) -> i64 {
    // SAFETY: guest pointers per the flistxattr(2) contract.
    ret_isize(unsafe {
        patina_listxattr(
            fd as c_int,
            std::ptr::null(),
            crate::xattr::XATTR_BY_FD,
            list as *mut c_void,
            size as usize,
        )
    })
}

pub(in crate::sud) fn sys_setxattr(
    path: u64,
    name: u64,
    value: u64,
    size: u64,
    flags: u64,
    follow: bool,
) -> i64 {
    // SAFETY: guest pointers per the setxattr(2) contract.
    ret_i32(unsafe {
        patina_setxattr(
            -1,
            path as *const c_char,
            xattr_by(follow),
            name as *const c_char,
            value as *const c_void,
            size as usize,
            flags as c_int,
        )
    })
}

pub(in crate::sud) fn sys_fsetxattr(fd: i64, name: u64, value: u64, size: u64, flags: u64) -> i64 {
    // SAFETY: guest pointers per the fsetxattr(2) contract.
    ret_i32(unsafe {
        patina_setxattr(
            fd as c_int,
            std::ptr::null(),
            crate::xattr::XATTR_BY_FD,
            name as *const c_char,
            value as *const c_void,
            size as usize,
            flags as c_int,
        )
    })
}

pub(in crate::sud) fn sys_removexattr(path: u64, name: u64, follow: bool) -> i64 {
    // SAFETY: guest pointers per the removexattr(2) contract.
    ret_i32(unsafe {
        patina_removexattr(
            -1,
            path as *const c_char,
            xattr_by(follow),
            name as *const c_char,
        )
    })
}

pub(in crate::sud) fn sys_fremovexattr(fd: i64, name: u64) -> i64 {
    // SAFETY: guest pointers per the fremovexattr(2) contract.
    ret_i32(unsafe {
        patina_removexattr(
            fd as c_int,
            std::ptr::null(),
            crate::xattr::XATTR_BY_FD,
            name as *const c_char,
        )
    })
}
