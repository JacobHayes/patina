//! Darwin `statfs(2)`/`fstatfs(2)`: the one deterministic volume, described
//! as macOS describes a local, writable, case-sensitive APFS volume mounted at
//! `/`.
//!
//! The volume is the shared [`crate::fs::VOLUME`] geometry, the same one the
//! Linux description reports. What is Darwin's own is the vocabulary: APFS's
//! type name and number, the mount flags of a local journaled volume, the
//! case-sensitive subtype (the virtual filesystem compares names byte for
//! byte), and an `f_fsid` that is the volume's `st_dev` beside its type number,
//! as XNU's `vfs_statfs` fills it. `f_flags` carries `MNT_LOCAL` and never
//! `MNT_RDONLY`: a reader that picks its locking or its write path from them
//! (SQLite's `unixOpen` and `autolockIoFinderImpl`) treats the volume as the
//! local, writable disk it is.
//!
//! A path resolves through the one resolver, exactly as `stat` does; a
//! descriptor answers by its kind, as XNU's `file_vnode` decides: a file,
//! directory or FIFO is a vnode on the volume, and every other kind (a pipe, a
//! socket, a kqueue) is `EINVAL`. The captured standard streams have no node,
//! and answer `EBADF` as `fstat` does. The entropy device stops by name, as its
//! `stat` does.

#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::{c_char, c_int};
use core::mem::offset_of;

use crate::abi::{SysResult, failed};
use crate::fdtable::FdKind;
use crate::fs::VOLUME;
use crate::paths;

/// Darwin's 64-bit-inode `struct statfs` (`<sys/mount.h>`), the layout every
/// arm64 caller passes.
#[repr(C)]
#[derive(Clone, Copy)]
struct DarwinStatfs {
    f_bsize: u32,
    f_iosize: i32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [i32; 2],
    f_owner: u32,
    f_type: u32,
    f_flags: u32,
    f_fssubtype: u32,
    f_fstypename: [u8; 16],
    f_mntonname: [u8; 1024],
    f_mntfromname: [u8; 1024],
    f_flags_ext: u32,
    f_reserved: [u32; 7],
}

mod plain_impls {
    #![deny(clippy::undocumented_unsafe_blocks)]

    crate::plain!(super::DarwinStatfs {
        f_bsize: u32,
        f_iosize: i32,
        f_blocks: u64,
        f_bfree: u64,
        f_bavail: u64,
        f_files: u64,
        f_ffree: u64,
        f_fsid: [i32; 2],
        f_owner: u32,
        f_type: u32,
        f_flags: u32,
        f_fssubtype: u32,
        f_fstypename: [u8; 16],
        f_mntonname: [u8; 1024],
        f_mntfromname: [u8; 1024],
        f_flags_ext: u32,
        f_reserved: [u32; 7],
    });
}

const _: () = {
    assert!(size_of::<DarwinStatfs>() == size_of::<libc::statfs>());
    assert!(align_of::<DarwinStatfs>() == align_of::<libc::statfs>());
    assert!(offset_of!(DarwinStatfs, f_ffree) == offset_of!(libc::statfs, f_ffree));
    assert!(offset_of!(DarwinStatfs, f_fsid) == offset_of!(libc::statfs, f_fsid));
    assert!(offset_of!(DarwinStatfs, f_owner) == offset_of!(libc::statfs, f_owner));
    assert!(offset_of!(DarwinStatfs, f_flags) == offset_of!(libc::statfs, f_flags));
    assert!(offset_of!(DarwinStatfs, f_fstypename) == offset_of!(libc::statfs, f_fstypename));
    assert!(offset_of!(DarwinStatfs, f_mntonname) == offset_of!(libc::statfs, f_mntonname));
    assert!(offset_of!(DarwinStatfs, f_mntfromname) == offset_of!(libc::statfs, f_mntfromname));
    assert!(offset_of!(DarwinStatfs, f_flags_ext) == offset_of!(libc::statfs, f_flags_ext));
};

/// The number XNU hands APFS when it registers (`vfc_typenum`), which every
/// APFS volume reports as `f_type` and in `f_fsid`'s second word: macOS 26's,
/// a constant here.
const APFS_TYPE: u32 = 0x1a;
/// APFS's `f_fssubtype` for a case-sensitive volume (1 is case-insensitive),
/// as macOS 26 reports volumes of each kind.
const APFS_CASE_SENSITIVE: u32 = 0;
/// APFS's preferred transfer size, `f_iosize`.
const APFS_IOSIZE: i32 = 1 << 20;
/// A local journaled volume that supports volfs paths and is the root
/// filesystem; neither read-only nor any host's content-protection or
/// sandbox labels.
const VOLUME_FLAGS: u32 =
    (libc::MNT_LOCAL | libc::MNT_JOURNALED | libc::MNT_DOVOLFS | libc::MNT_ROOTFS) as u32;

/// A NUL-padded fixed-size name field.
const fn name<const N: usize>(value: &str) -> [u8; N] {
    let bytes = value.as_bytes();
    assert!(bytes.len() < N);
    let mut field = [0; N];
    let mut i = 0;
    while i < bytes.len() {
        field[i] = bytes[i];
        i += 1;
    }
    field
}

/// The volume, as Darwin describes it.
fn describe() -> DarwinStatfs {
    let (major, minor) = crate::fs::fs_device(crate::PATINA_FS_VOLUME);
    DarwinStatfs {
        f_bsize: VOLUME.block_size,
        f_iosize: APFS_IOSIZE,
        f_blocks: VOLUME.blocks,
        f_bfree: VOLUME.free_blocks,
        f_bavail: VOLUME.free_blocks,
        f_files: VOLUME.files,
        f_ffree: VOLUME.free_files,
        f_fsid: [super::metadata::makedev(major, minor), APFS_TYPE as i32],
        // The volume's owner, root, as `/` is owned on every Mac.
        f_owner: 0,
        f_type: APFS_TYPE,
        f_flags: VOLUME_FLAGS,
        f_fssubtype: APFS_CASE_SENSITIVE,
        f_fstypename: name("apfs"),
        f_mntonname: name("/"),
        f_mntfromname: name("/dev/disk1s1"),
        f_flags_ext: 0,
        f_reserved: [0; 7],
    }
}

/// Copy the description out, last, as `statfs64`'s `copyout` does: a buffer
/// the guest cannot write (NULL or unmapped) is `EFAULT` after the path or
/// descriptor has been judged.
fn copy_out(out: *mut DarwinStatfs) -> SysResult<()> {
    crate::uaccess::write(out as usize, &describe()).map_err(failed)
}

/// The volume `path` (a trailing symlink followed) is on.
///
/// # Safety
/// `path` is a readable C string or NULL; `out` may be any address.
unsafe fn path_statfs(path: *const c_char, out: *mut DarwinStatfs) -> SysResult<()> {
    // SAFETY: the libc contract makes `path` a readable C string or NULL,
    // which `path_from_c` refuses.
    let path = unsafe { crate::path_from_c(path) }.map_err(failed)?;
    match paths::resolve(paths::AT_FDCWD, &path, 0).map_err(failed)? {
        paths::Resolution::Volume(resolved) if resolved.metadata.is_some() => copy_out(out),
        paths::Resolution::Volume(_) => Err(failed(libc::ENOENT)),
        paths::Resolution::Virtual(entry) => entry.unmodeled("the filesystem statistics"),
    }
}

/// The volume a descriptor's vnode is on.
fn descriptor_statfs(fd: c_int, out: *mut DarwinStatfs) -> SysResult<()> {
    let resolved = crate::resolve_fd(fd).map_err(failed)?;
    match resolved.kind {
        FdKind::File | FdKind::Dir | FdKind::OPath => copy_out(out),
        FdKind::Pipe if crate::thread::fifo_ino(fd).is_some() => copy_out(out),
        FdKind::Pipe | FdKind::Socket | FdKind::Kqueue => Err(failed(libc::EINVAL)),
        FdKind::MemDevice => {
            paths::Virtual::MemDevice(crate::memdev::MemDevice::of_handle(resolved.handle))
                .unmodeled("the filesystem statistics")
        }
        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => Err(failed(libc::EBADF)),
    }
}

/// # Safety
/// `path` obeys the libc `statfs` contract; `out` is copied out through uaccess.
#[unsafe(no_mangle)]
unsafe extern "C" fn statfs(path: *const c_char, out: *mut libc::statfs) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller's libc contract covers `path`.
    crate::abi::libc_result(unsafe { path_statfs(path, out.cast()) }.map(|_| 0), -1)
}

#[unsafe(no_mangle)]
extern "C" fn fstatfs(fd: c_int, out: *mut libc::statfs) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_result(descriptor_statfs(fd, out.cast()).map(|_| 0), -1)
}
