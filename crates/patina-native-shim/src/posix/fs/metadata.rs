//! Stat layouts and permission/ownership adapters.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
use crate::PatinaMetadata;
use core::{mem::MaybeUninit, ptr};

fn makedev(major: u32, minor: u32) -> libc::dev_t {
    #[cfg(target_os = "macos")]
    {
        ((major << 24) | minor) as libc::dev_t
    }
    #[cfg(target_os = "linux")]
    {
        let major = major as u64;
        let minor = minor as u64;
        (((major & 0xfffff000) << 32)
            | ((major & 0xfff) << 8)
            | ((minor & 0xffffff00) << 12)
            | (minor & 0xff)) as libc::dev_t
    }
}
unsafe fn metadata(
    directory: c_int,
    path: *const c_char,
    flags: u32,
    out: *mut PatinaMetadata,
) -> c_int {
    // SAFETY: the caller upholds the libc path contract and provides writable
    // metadata storage for this model entry.
    unsafe { model_result(crate::patina_metadata_at(directory, path, flags, out)) }
}
unsafe fn fd_metadata(fd: c_int, out: *mut PatinaMetadata) -> c_int {
    // SAFETY: the caller provides writable metadata storage for this model
    // entry, normally a local `MaybeUninit` output.
    unsafe { model_result(crate::patina_fd_metadata_full(fd, out)) }
}

#[cfg(target_os = "linux")]
const STAT_AT_FLAGS: c_int = libc::AT_SYMLINK_NOFOLLOW
    | libc::AT_EMPTY_PATH
    | libc::AT_NO_AUTOMOUNT
    | libc::AT_STATX_SYNC_TYPE;
#[cfg(target_os = "macos")]
const STAT_AT_FLAGS: c_int = libc::AT_SYMLINK_NOFOLLOW;

unsafe fn stat_at(
    directory: c_int,
    path: *const c_char,
    flags: c_int,
    values: *mut PatinaMetadata,
) -> c_int {
    // SAFETY: callers uphold the path contract; the empty-path branch checks
    // null before dereferencing, and non-null paths are valid C strings.
    unsafe {
        if flags & !STAT_AT_FLAGS != 0 {
            return error(AT_FLAG_REFUSAL);
        }
        let mut resolve_flags = 0;
        if flags & libc::AT_SYMLINK_NOFOLLOW != 0 {
            resolve_flags |= RESOLVE_NOFOLLOW;
        }
        #[cfg(target_os = "linux")]
        if flags & AT_EMPTY_PATH != 0 {
            resolve_flags |= RESOLVE_EMPTY_PATH;
            if directory != libc::AT_FDCWD && (path.is_null() || *path == 0) {
                return fd_metadata(directory, values);
            }
        }
        metadata(at(directory), path, resolve_flags, values)
    }
}

unsafe fn fill_stat(
    result: c_int,
    values: *const PatinaMetadata,
    status: *mut libc::stat,
) -> c_int {
    if result < 0 {
        return -1;
    }
    if status.is_null() {
        return error(libc::EFAULT);
    }
    // SAFETY: successful metadata initialized `values`; `status` is non-null
    // here and must be writable and aligned for the caller's libc contract.
    unsafe { write_stat(&*values, status) };
    0
}

/// Encode the libc `stat` layout, preserving its zero-first, field-by-field
/// direct-store sequence.
///
/// # Safety
/// `values` must be readable; `status` must be writable, aligned and live for
/// the duration of the call.
unsafe fn write_stat(values: &PatinaMetadata, status: *mut libc::stat) {
    // SAFETY: required by this codec's contract; the memset intentionally
    // precedes the existing field stores.
    unsafe {
        ptr::write_bytes(status.cast::<u8>(), 0, size_of::<libc::stat>());
        let (major, minor) = crate::fs::fs_device(values.fs);
        (*status).st_mode = crate::fs::stat_mode(values);
        (*status).st_dev = makedev(major, minor);
        (*status).st_rdev = makedev(values.rdev_major, values.rdev_minor);
        (*status).st_nlink = values.nlink as libc::nlink_t;
        (*status).st_ino = values.ino as libc::ino_t;
        (*status).st_size = values.length as libc::off_t;
        let (uid, gid) = crate::fs::node_owner(values.fs);
        (*status).st_uid = uid as libc::uid_t;
        (*status).st_gid = gid as libc::gid_t;
        (*status).st_blksize = crate::fs::stat_blksize(values) as libc::blksize_t;
        (*status).st_blocks = values.blocks as libc::blkcnt_t;
        (*status).st_atime = values.atime.sec as libc::time_t;
        (*status).st_atime_nsec = values.atime.nsec as libc::c_long;
        (*status).st_mtime = values.mtime.sec as libc::time_t;
        (*status).st_mtime_nsec = values.mtime.nsec as libc::c_long;
        (*status).st_ctime = values.ctime.sec as libc::time_t;
        (*status).st_ctime_nsec = values.ctime.nsec as libc::c_long;
        #[cfg(target_os = "macos")]
        {
            (*status).st_birthtime = values.btime.sec as libc::time_t;
            (*status).st_birthtime_nsec = values.btime.nsec as libc::c_long;
        }
    }
}

// Stream allocation needs both rdev-major and the target stat block size.
pub(in crate::posix) unsafe fn fd_stat(
    fd: c_int,
    values: *mut PatinaMetadata,
    status: *mut libc::stat,
) -> c_int {
    // SAFETY: `values` is writable metadata storage and `status` has the
    // caller's libc layout/alignment contract.
    unsafe { fill_stat(fd_metadata(fd, values), values, status) }
}

unsafe fn access_impl(directory: c_int, path: *const c_char, mode: c_int) -> c_int {
    // SAFETY: callers uphold the libc path contract; `values` is local output
    // storage and is read only after metadata succeeds.
    unsafe {
        let mut values = MaybeUninit::<PatinaMetadata>::uninit();
        if metadata(directory, path, 0, values.as_mut_ptr()) < 0 {
            return -1;
        }
        let answer = crate::patina_access_answer(values.as_ptr(), mode);
        if answer != 0 { error(answer) } else { 0 }
    }
}

/// # Safety
/// `path` satisfies libc's string contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `path` is valid per this export's libc string contract.
    unsafe { access_impl(AT_FDCWD, path, mode) }
}

/// # Safety
/// `path` satisfies libc's string contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn faccessat(
    directory: c_int,
    path: *const c_char,
    mode: c_int,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !(libc::AT_EACCESS | libc::AT_SYMLINK_NOFOLLOW) != 0 {
        return error(libc::EINVAL);
    }
    // SAFETY: `path` is valid per this export's libc string contract.
    unsafe { access_impl(at(directory), path, mode) }
}

/// # Safety
/// `path` satisfies libc's string contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fchmodat(
    directory: c_int,
    path: *const c_char,
    mode: libc::mode_t,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !(libc::AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return error(libc::EINVAL);
    }
    let resolve_flags = if flags & libc::AT_SYMLINK_NOFOLLOW != 0 {
        RESOLVE_NOFOLLOW
    } else {
        0
    };
    #[cfg(target_os = "linux")]
    let resolve_flags = resolve_flags
        | if flags & AT_EMPTY_PATH != 0 {
            RESOLVE_EMPTY_PATH
        } else {
            0
        };
    // SAFETY: `path` is valid per this export's libc string contract.
    unsafe {
        model_result(crate::patina_chmod(
            at(directory),
            path,
            mode as libc::c_uint,
            resolve_flags,
        ))
    }
}

/// # Safety
/// `path` satisfies libc's string contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fchownat(
    directory: c_int,
    path: *const c_char,
    owner: libc::uid_t,
    group: libc::gid_t,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !(libc::AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return error(libc::EINVAL);
    }
    let mut resolve_flags = 0;
    if flags & libc::AT_SYMLINK_NOFOLLOW != 0 {
        resolve_flags |= RESOLVE_NOFOLLOW;
    }
    #[cfg(target_os = "linux")]
    if flags & AT_EMPTY_PATH != 0 {
        resolve_flags |= RESOLVE_EMPTY_PATH;
    }
    // SAFETY: `path` is valid per this export's libc string contract.
    unsafe {
        model_result(crate::patina_chown(
            at(directory),
            path,
            resolve_flags,
            owner,
            group,
        ))
    }
}

#[cfg(target_os = "linux")]
const _: () = {
    assert!(size_of::<libc::stat>() == size_of::<libc::stat64>());
    assert!(align_of::<libc::stat>() == align_of::<libc::stat64>());
    assert!(
        core::mem::offset_of!(libc::stat, st_dev) == core::mem::offset_of!(libc::stat64, st_dev)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_ino) == core::mem::offset_of!(libc::stat64, st_ino)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_mode) == core::mem::offset_of!(libc::stat64, st_mode)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_nlink)
            == core::mem::offset_of!(libc::stat64, st_nlink)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_uid) == core::mem::offset_of!(libc::stat64, st_uid)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_gid) == core::mem::offset_of!(libc::stat64, st_gid)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_rdev) == core::mem::offset_of!(libc::stat64, st_rdev)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_size) == core::mem::offset_of!(libc::stat64, st_size)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_blksize)
            == core::mem::offset_of!(libc::stat64, st_blksize)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_blocks)
            == core::mem::offset_of!(libc::stat64, st_blocks)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_atime)
            == core::mem::offset_of!(libc::stat64, st_atime)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_atime_nsec)
            == core::mem::offset_of!(libc::stat64, st_atime_nsec)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_mtime)
            == core::mem::offset_of!(libc::stat64, st_mtime)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_mtime_nsec)
            == core::mem::offset_of!(libc::stat64, st_mtime_nsec)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_ctime)
            == core::mem::offset_of!(libc::stat64, st_ctime)
    );
    assert!(
        core::mem::offset_of!(libc::stat, st_ctime_nsec)
            == core::mem::offset_of!(libc::stat64, st_ctime_nsec)
    );
};

#[cfg(target_os = "linux")]
/// Encode the libc `statx` layout with its existing zero-first store order.
///
/// # Safety
/// `values` must be readable; `status` must satisfy this door's existing
/// direct-store contract and be writable, aligned and live for the call.
unsafe fn write_statx(values: &PatinaMetadata, mask: u32, status: *mut libc::statx) {
    // SAFETY: required by this codec's contract; this direct write is
    // intentionally unchecked and follows the metadata lookup.
    unsafe {
        ptr::write_bytes(status.cast::<u8>(), 0, size_of::<libc::statx>());
        let mut mount_id = 0;
        (*status).stx_mask = libc::STATX_BASIC_STATS
            | crate::volume::patina_statx_extra(values.fs, mask, &mut mount_id);
        (*status).stx_blksize = crate::fs::stat_blksize(values) as u32;
        (*status).stx_mode = crate::fs::stat_mode(values) as u16;
        (*status).stx_nlink = values.nlink;
        let (uid, gid) = crate::fs::node_owner(values.fs);
        (*status).stx_uid = uid;
        (*status).stx_gid = gid;
        (*status).stx_ino = values.ino;
        (*status).stx_size = values.length;
        (*status).stx_blocks = values.blocks;
        (*status).stx_atime.tv_sec = values.atime.sec;
        (*status).stx_atime.tv_nsec = values.atime.nsec as u32;
        (*status).stx_mtime.tv_sec = values.mtime.sec;
        (*status).stx_mtime.tv_nsec = values.mtime.nsec as u32;
        (*status).stx_ctime.tv_sec = values.ctime.sec;
        (*status).stx_ctime.tv_nsec = values.ctime.nsec as u32;
        if (*status).stx_mask & libc::STATX_BTIME != 0 {
            (*status).stx_btime.tv_sec = values.btime.sec;
            (*status).stx_btime.tv_nsec = values.btime.nsec as u32;
        }
        (*status).stx_mnt_id = mount_id;
        let (major, minor) = crate::fs::fs_device(values.fs);
        (*status).stx_dev_major = major;
        (*status).stx_dev_minor = minor;
        (*status).stx_rdev_major = values.rdev_major;
        (*status).stx_rdev_minor = values.rdev_minor;
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// The guest string and output buffer satisfy libc statx's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn statx(
    directory: c_int,
    path: *const c_char,
    flags: c_int,
    mask: u32,
    status: *mut libc::statx,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & libc::AT_STATX_SYNC_TYPE == libc::AT_STATX_SYNC_TYPE || mask & 0x80000000 != 0 {
        return error(libc::EINVAL);
    }
    // SAFETY: the exported entry's contract covers `path`; metadata uses
    // local output storage, and the codec preserves this door's direct-store
    // access to `status` (including its existing null/fault policy).
    unsafe {
        let mut values = MaybeUninit::<PatinaMetadata>::uninit();
        if stat_at(directory, path, flags, values.as_mut_ptr()) < 0 {
            return -1;
        }
        let values = values.assume_init();
        write_statx(&values, mask, status);
        0
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn chmod(path: *const c_char, mode: libc::mode_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `path` is valid per this export's libc string contract.
    unsafe { model_result(crate::patina_chmod(AT_FDCWD, path, mode as libc::c_uint, 0)) }
}

#[unsafe(no_mangle)]
extern "C" fn fchmod(fd: c_int, mode: libc::mode_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    model_result(crate::patina_fchmod(fd, mode as libc::c_uint))
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn chown(path: *const c_char, owner: libc::uid_t, group: libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `path` is valid per this export's libc string contract.
    unsafe { model_result(crate::patina_chown(AT_FDCWD, path, 0, owner, group)) }
}

/// # Safety
/// Guest pointers obey the corresponding libc contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn lchown(path: *const c_char, owner: libc::uid_t, group: libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `path` is valid per this export's libc string contract.
    unsafe {
        model_result(crate::patina_chown(
            AT_FDCWD,
            path,
            RESOLVE_NOFOLLOW,
            owner,
            group,
        ))
    }
}

#[unsafe(no_mangle)]
extern "C" fn fchown(fd: c_int, owner: libc::uid_t, group: libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    model_result(crate::patina_fchown(fd, owner, group))
}

/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn stat(path: *const c_char, status: *mut libc::stat) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `path` and `status` satisfy this export's libc metadata
    // contract; the local metadata is read only after a successful result.
    unsafe {
        let mut values = MaybeUninit::<PatinaMetadata>::uninit();
        let result = metadata(AT_FDCWD, path, 0, values.as_mut_ptr());
        fill_stat(result, values.as_ptr(), status.cast())
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn lstat(path: *const c_char, status: *mut libc::stat) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `path` and `status` satisfy this export's libc metadata
    // contract; the local metadata is read only after a successful result.
    unsafe {
        let mut values = MaybeUninit::<PatinaMetadata>::uninit();
        let result = metadata(AT_FDCWD, path, RESOLVE_NOFOLLOW, values.as_mut_ptr());
        fill_stat(result, values.as_ptr(), status.cast())
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fstat(fd: c_int, status: *mut libc::stat) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `status` satisfies this export's libc metadata contract; local
    // metadata is read only after a successful result.
    unsafe {
        let mut values = MaybeUninit::<PatinaMetadata>::uninit();
        let result = fd_metadata(fd, values.as_mut_ptr());
        fill_stat(result, values.as_ptr(), status.cast())
    }
}

/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fstatat(
    directory: c_int,
    path: *const c_char,
    status: *mut libc::stat,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `path` and `status` satisfy this export's libc metadata
    // contract; the local metadata is read only after a successful result.
    unsafe {
        let mut values = MaybeUninit::<PatinaMetadata>::uninit();
        let result = stat_at(directory, path, flags, values.as_mut_ptr());
        fill_stat(result, values.as_ptr(), status.cast())
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn stat64(path: *const c_char, status: *mut libc::stat64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `path` and `status` satisfy this export's libc metadata
    // contract; the local metadata is read only after a successful result.
    unsafe {
        let mut values = MaybeUninit::<PatinaMetadata>::uninit();
        let result = metadata(AT_FDCWD, path, 0, values.as_mut_ptr());
        fill_stat(result, values.as_ptr(), status.cast())
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn lstat64(path: *const c_char, status: *mut libc::stat64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `path` and `status` satisfy this export's libc metadata
    // contract; the local metadata is read only after a successful result.
    unsafe {
        let mut values = MaybeUninit::<PatinaMetadata>::uninit();
        let result = metadata(AT_FDCWD, path, RESOLVE_NOFOLLOW, values.as_mut_ptr());
        fill_stat(result, values.as_ptr(), status.cast())
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fstat64(fd: c_int, status: *mut libc::stat64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `status` satisfies this export's libc metadata contract; local
    // metadata is read only after a successful result.
    unsafe {
        let mut values = MaybeUninit::<PatinaMetadata>::uninit();
        let result = fd_metadata(fd, values.as_mut_ptr());
        fill_stat(result, values.as_ptr(), status.cast())
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers obey the corresponding libc metadata contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fstatat64(
    directory: c_int,
    path: *const c_char,
    status: *mut libc::stat64,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `path` and `status` satisfy this export's libc metadata
    // contract; the local metadata is read only after a successful result.
    unsafe {
        let mut values = MaybeUninit::<PatinaMetadata>::uninit();
        let result = stat_at(directory, path, flags, values.as_mut_ptr());
        fill_stat(result, values.as_ptr(), status.cast())
    }
}
