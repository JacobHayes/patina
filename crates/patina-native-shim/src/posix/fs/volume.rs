//! Linux statfs/statvfs spellings, including glibc 2.39's f_type.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
use crate::volume::KernelStatfs;
use core::{
    mem::{MaybeUninit, offset_of},
    ptr,
};

// libc still names f_type as the first spare word. The actual glibc 2.39
// layout keeps the same size and places that u32 after f_namemax.
#[repr(C)]
struct Statvfs {
    f_bsize: libc::c_ulong,
    f_frsize: libc::c_ulong,
    f_blocks: libc::fsblkcnt_t,
    f_bfree: libc::fsblkcnt_t,
    f_bavail: libc::fsblkcnt_t,
    f_files: libc::fsfilcnt_t,
    f_ffree: libc::fsfilcnt_t,
    f_favail: libc::fsfilcnt_t,
    f_fsid: libc::c_ulong,
    f_flag: libc::c_ulong,
    f_namemax: libc::c_ulong,
    f_type: u32,
    spare: [c_int; 5],
}
const _: () = {
    assert!(size_of::<Statvfs>() == size_of::<libc::statvfs>());
    assert!(size_of::<Statvfs>() == size_of::<libc::statvfs64>());
    assert!(size_of::<Statvfs>() == 112);
    assert!(align_of::<Statvfs>() == align_of::<libc::statvfs>());
    assert!(offset_of!(Statvfs, f_bsize) == offset_of!(libc::statvfs, f_bsize));
    assert!(offset_of!(Statvfs, f_frsize) == offset_of!(libc::statvfs, f_frsize));
    assert!(offset_of!(Statvfs, f_blocks) == offset_of!(libc::statvfs, f_blocks));
    assert!(offset_of!(Statvfs, f_bfree) == offset_of!(libc::statvfs, f_bfree));
    assert!(offset_of!(Statvfs, f_bavail) == offset_of!(libc::statvfs, f_bavail));
    assert!(offset_of!(Statvfs, f_files) == offset_of!(libc::statvfs, f_files));
    assert!(offset_of!(Statvfs, f_ffree) == offset_of!(libc::statvfs, f_ffree));
    assert!(offset_of!(Statvfs, f_favail) == offset_of!(libc::statvfs, f_favail));
    assert!(offset_of!(Statvfs, f_fsid) == offset_of!(libc::statvfs, f_fsid));
    assert!(offset_of!(Statvfs, f_flag) == offset_of!(libc::statvfs, f_flag));
    assert!(offset_of!(Statvfs, f_namemax) == offset_of!(libc::statvfs, f_namemax));
    assert!(offset_of!(Statvfs, f_type) == 88);
    assert!(offset_of!(Statvfs, spare) == 92);
    assert!(size_of::<KernelStatfs>() == size_of::<libc::statfs>());
    assert!(size_of::<KernelStatfs>() == size_of::<libc::statfs64>());
    assert!(offset_of!(KernelStatfs, f_type) == offset_of!(libc::statfs, f_type));
    assert!(offset_of!(KernelStatfs, f_fsid) == offset_of!(libc::statfs, f_fsid));
    assert!(offset_of!(KernelStatfs, f_frsize) == offset_of!(libc::statfs, f_frsize));
};

unsafe fn convert(result: c_int, fs: *const KernelStatfs, out: *mut libc::statvfs) -> c_int {
    if result < 0 {
        return model_result(result);
    }
    // SAFETY: The filesystem path/output pointers satisfy the libc statfs-family contract, and initialized output is read only after success.
    unsafe {
        let fs = &*fs;
        let out = out.cast::<Statvfs>();
        ptr::write_bytes(out.cast::<u8>(), 0, size_of::<Statvfs>());
        (*out).f_bsize = fs.f_bsize as libc::c_ulong;
        (*out).f_frsize = if fs.f_frsize != 0 {
            fs.f_frsize
        } else {
            fs.f_bsize
        } as libc::c_ulong;
        (*out).f_blocks = fs.f_blocks;
        (*out).f_bfree = fs.f_bfree;
        (*out).f_bavail = fs.f_bavail;
        (*out).f_files = fs.f_files;
        (*out).f_ffree = fs.f_ffree;
        (*out).f_favail = fs.f_ffree;
        (*out).f_fsid =
            ((fs.f_fsid[1] as u32 as libc::c_ulong) << 32) | fs.f_fsid[0] as u32 as libc::c_ulong;
        (*out).f_flag = (fs.f_flags ^ 0x20) as libc::c_ulong;
        (*out).f_namemax = fs.f_namelen as libc::c_ulong;
        (*out).f_type = fs.f_type as u32;
        0
    }
}
unsafe fn path_vfs(path: *const c_char, out: *mut libc::statvfs) -> c_int {
    // SAFETY: The filesystem path/output pointers satisfy the libc statfs-family contract, and initialized output is read only after success.
    unsafe {
        let mut fs = MaybeUninit::<KernelStatfs>::uninit();
        match crate::volume::statfs(path, fs.as_mut_ptr()) {
            Ok(()) => convert(0, fs.as_ptr(), out),
            Err(errno) => crate::abi::libc_result(Err(errno), -1),
        }
    }
}
unsafe fn fd_vfs(fd: c_int, out: *mut libc::statvfs) -> c_int {
    // SAFETY: The filesystem path/output pointers satisfy the libc statfs-family contract, and initialized output is read only after success.
    unsafe {
        let mut fs = MaybeUninit::<KernelStatfs>::uninit();
        match crate::volume::fstatfs(fd, fs.as_mut_ptr()) {
            Ok(()) => convert(0, fs.as_ptr(), out),
            Err(errno) => crate::abi::libc_result(Err(errno), -1),
        }
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn statfs(path: *const c_char, out: *mut libc::statfs) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The filesystem path/output pointers satisfy the libc statfs-family contract, and initialized output is read only after success.
    crate::abi::libc_result(
        unsafe { crate::volume::statfs(path, out.cast()) }.map(|_| 0),
        -1,
    )
}

/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatfs(fd: c_int, out: *mut libc::statfs) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The filesystem path/output pointers satisfy the libc statfs-family contract, and initialized output is read only after success.
    crate::abi::libc_result(
        unsafe { crate::volume::fstatfs(fd, out.cast()) }.map(|_| 0),
        -1,
    )
}

/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn statvfs(path: *const c_char, out: *mut libc::statvfs) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The filesystem path/output pointers satisfy the libc statfs-family contract, and initialized output is read only after success.
    unsafe { path_vfs(path, out.cast()) }
}

/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatvfs(fd: c_int, out: *mut libc::statvfs) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The filesystem path/output pointers satisfy the libc statfs-family contract, and initialized output is read only after success.
    unsafe { fd_vfs(fd, out.cast()) }
}

/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn statfs64(path: *const c_char, out: *mut libc::statfs64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The filesystem path/output pointers satisfy the libc statfs-family contract, and initialized output is read only after success.
    crate::abi::libc_result(
        unsafe { crate::volume::statfs(path, out.cast()) }.map(|_| 0),
        -1,
    )
}

/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatfs64(fd: c_int, out: *mut libc::statfs64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The filesystem path/output pointers satisfy the libc statfs-family contract, and initialized output is read only after success.
    crate::abi::libc_result(
        unsafe { crate::volume::fstatfs(fd, out.cast()) }.map(|_| 0),
        -1,
    )
}

/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn statvfs64(path: *const c_char, out: *mut libc::statvfs64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The filesystem path/output pointers satisfy the libc statfs-family contract, and initialized output is read only after success.
    unsafe { path_vfs(path, out.cast()) }
}

/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatvfs64(fd: c_int, out: *mut libc::statvfs64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The filesystem path/output pointers satisfy the libc statfs-family contract, and initialized output is read only after success.
    unsafe { fd_vfs(fd, out.cast()) }
}
